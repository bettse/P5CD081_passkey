package test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * The platform half of CTAP2 clientPIN protocol 1.
 *
 * Everything here is what a browser does: agree an ECDH shared secret with the
 * authenticator, hash it to get the AES key, encrypt with AES-256-CBC under a
 * zero IV, and authenticate with HMAC-SHA-256 truncated to its left 16 bytes.
 *
 * It exists so the card's side can be tested against an independent
 * implementation rather than against itself.
 */
public class ClientPin {

    public static final byte SUB_GET_RETRIES = 0x01;
    public static final byte SUB_GET_KEY_AGREEMENT = 0x02;
    public static final byte SUB_SET_PIN = 0x03;
    public static final byte SUB_CHANGE_PIN = 0x04;
    public static final byte SUB_GET_PIN_TOKEN = 0x05;

    private final KeyPair platformKey;

    /** Protocol 2 keeps two keys, HMAC then AES; protocol 1 uses one for both. */
    private byte[] hmacKey;
    private byte[] aesKey;

    private final int protocol;

    public ClientPin() throws Exception {
        this(1);
    }

    public ClientPin(int protocol) throws Exception {
        this.protocol = protocol;
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        platformKey = gen.generateKeyPair();
    }

    /** HKDF-SHA-256, single block, which is all protocol 2 ever needs. */
    private static byte[] hkdf(byte[] ikm, String info) throws Exception {
        Mac extract = Mac.getInstance("HmacSHA256");
        extract.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = extract.doFinal(ikm);

        Mac expand = Mac.getInstance("HmacSHA256");
        expand.init(new SecretKeySpec(prk, "HmacSHA256"));
        expand.update(info.getBytes(StandardCharsets.UTF_8));
        expand.update((byte) 0x01);
        return expand.doFinal();
    }

    /** The platform's public key as the COSE_Key the card expects. */
    public byte[] coseKey() {
        ECPublicKey pub = (ECPublicKey) platformKey.getPublic();
        byte[] x = fixed32(pub.getW().getAffineX());
        byte[] y = fixed32(pub.getW().getAffineY());

        // {1: 2 (EC2), 3: -25, -1: 1 (P-256), -2: x, -3: y}
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeInt(2),
            Cbor.encodeInt(3), Cbor.encodeInt(-25),
            Cbor.encodeInt(-1), Cbor.encodeInt(1),
            Cbor.encodeInt(-2), Cbor.encodeBytes(x),
            Cbor.encodeInt(-3), Cbor.encodeBytes(y));
    }

    /**
     * Derive the shared secret from the card's key agreement COSE_Key.
     * Protocol 1 defines it as SHA-256 of the ECDH x-coordinate.
     */
    public void agree(byte[] authenticatorCoseKey) throws Exception {
        Cbor c = new Cbor(authenticatorCoseKey);
        int entries = c.expect(Cbor.MAP);
        byte[] x = null;
        byte[] y = null;
        for (int i = 0; i < entries; i++) {
            long label = c.readInt();
            if (label == -2) {
                x = c.readBytes();
            } else if (label == -3) {
                y = c.readBytes();
            } else {
                c.readInt();
            }
        }
        if (x == null || y == null) {
            throw new IllegalArgumentException("key agreement response has no coordinates");
        }

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);

        PublicKey cardKey = KeyFactory.getInstance("EC").generatePublic(
            new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), spec));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(platformKey.getPrivate());
        ka.doPhase(cardKey, true);
        byte[] z = ka.generateSecret();

        if (protocol == 2) {
            hmacKey = hkdf(z, "CTAP2 HMAC key");
            aesKey = hkdf(z, "CTAP2 AES key");
        } else {
            hmacKey = MessageDigest.getInstance("SHA-256").digest(z);
            aesKey = hmacKey;
        }
    }

    public byte[] sharedSecret() {
        return hmacKey;
    }

    /** LEFT(SHA-256(pin), 16), what CTAP2 calls the pinHash. */
    public static byte[] pinHash(String pin) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest(pin.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOfRange(digest, 0, 16);
    }

    /** The PIN zero-padded to 64 bytes, then encrypted. */
    public byte[] encryptPin(String pin) throws Exception {
        byte[] padded = new byte[64];
        byte[] raw = pin.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(raw, 0, padded, 0, raw.length);
        return encrypt(padded);
    }

    /** Protocol 2 prefixes a random IV; protocol 1 uses an all-zero one. */
    public byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] iv = new byte[16];
        if (protocol == 2) {
            new java.security.SecureRandom().nextBytes(iv);
        }
        Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        byte[] ct = aes.doFinal(plaintext);
        return protocol == 2 ? Cbor.concat(iv, ct) : ct;
    }

    public byte[] decrypt(byte[] ciphertext) throws Exception {
        byte[] iv = new byte[16];
        byte[] body = ciphertext;
        if (protocol == 2) {
            iv = Arrays.copyOfRange(ciphertext, 0, 16);
            body = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);
        }
        Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
        return aes.doFinal(body);
    }

    /** pinUvAuthParam over the shared secret. */
    public byte[] authenticate(byte[]... parts) throws Exception {
        return truncate(authenticateFull(hmacKey, parts), protocol);
    }

    /** pinUvAuthParam over a pinToken, which is what requests are signed with. */
    public static byte[] authenticateWith(byte[] key, byte[]... parts) throws Exception {
        return truncate(authenticateFull(key, parts), 1);
    }

    public static byte[] authenticateWith(int protocol, byte[] key, byte[]... parts)
            throws Exception {
        return truncate(authenticateFull(key, parts), protocol);
    }

    private static byte[] authenticateFull(byte[] key, byte[]... parts) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] part : parts) {
            mac.update(part);
        }
        return mac.doFinal();
    }

    /** Protocol 1 truncates to 16 bytes; protocol 2 sends the whole hash. */
    private static byte[] truncate(byte[] mac, int protocol) {
        return protocol == 2 ? mac : Arrays.copyOfRange(mac, 0, 16);
    }

    // ---- request builders ----

    public static byte[] getRetries() {
        return getRetries(1);
    }

    public static byte[] getRetries(int protocol) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 2),
            Cbor.encodeInt(1), Cbor.encodeInt(protocol),
            Cbor.encodeInt(2), Cbor.encodeInt(SUB_GET_RETRIES));
    }

    public static byte[] getKeyAgreement() {
        return getKeyAgreement(1);
    }

    public static byte[] getKeyAgreement(int protocol) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 2),
            Cbor.encodeInt(1), Cbor.encodeInt(protocol),
            Cbor.encodeInt(2), Cbor.encodeInt(SUB_GET_KEY_AGREEMENT));
    }

    public byte[] setPin(String newPin) throws Exception {
        byte[] newPinEnc = encryptPin(newPin);
        byte[] pinAuth = authenticate(newPinEnc);
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeInt(protocol),
            Cbor.encodeInt(2), Cbor.encodeInt(SUB_SET_PIN),
            Cbor.encodeInt(3), coseKey(),
            Cbor.encodeInt(4), Cbor.encodeBytes(pinAuth),
            Cbor.encodeInt(5), Cbor.encodeBytes(newPinEnc));
    }

    public byte[] changePin(String oldPin, String newPin) throws Exception {
        byte[] newPinEnc = encryptPin(newPin);
        byte[] pinHashEnc = encrypt(pinHash(oldPin));
        byte[] pinAuth = authenticate(newPinEnc, pinHashEnc);
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 6),
            Cbor.encodeInt(1), Cbor.encodeInt(protocol),
            Cbor.encodeInt(2), Cbor.encodeInt(SUB_CHANGE_PIN),
            Cbor.encodeInt(3), coseKey(),
            Cbor.encodeInt(4), Cbor.encodeBytes(pinAuth),
            Cbor.encodeInt(5), Cbor.encodeBytes(newPinEnc),
            Cbor.encodeInt(6), Cbor.encodeBytes(pinHashEnc));
    }

    public byte[] getPinToken(String pin) throws Exception {
        byte[] pinHashEnc = encrypt(pinHash(pin));
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 4),
            Cbor.encodeInt(1), Cbor.encodeInt(protocol),
            Cbor.encodeInt(2), Cbor.encodeInt(SUB_GET_PIN_TOKEN),
            Cbor.encodeInt(3), coseKey(),
            Cbor.encodeInt(6), Cbor.encodeBytes(pinHashEnc));
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }
}
