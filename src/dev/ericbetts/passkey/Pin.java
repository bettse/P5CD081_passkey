package dev.ericbetts.passkey;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * User verification: one PIN, reachable two ways.
 *
 * The vendor protocol sends the PIN in the clear over a local link. CTAP2 wraps
 * it in clientPIN protocol 1, where the platform and the card agree an ECDH
 * shared secret, AES-256-CBC encrypts everything under it, and HMAC-SHA-256
 * truncated to 16 bytes authenticates it.
 *
 * What is stored either way is LEFT(SHA-256(pin), 16), the same digest CTAP2
 * calls the pinHash, so the two front doors cannot disagree about what the PIN is.
 *
 * The card has no HMAC in hardware and no named curves, so both come from
 * elsewhere in this package: Hmac and Secp256r1.
 */
public class Pin {

    // clientPIN subcommands.
    private static final byte SUB_GET_RETRIES = (byte) 0x01;
    private static final byte SUB_GET_KEY_AGREEMENT = (byte) 0x02;
    private static final byte SUB_SET_PIN = (byte) 0x03;
    private static final byte SUB_CHANGE_PIN = (byte) 0x04;
    private static final byte SUB_GET_PIN_TOKEN = (byte) 0x05;

    /**
     * HKDF info strings for protocol 2, with HKDF-Expand's trailing counter
     * byte baked in. The output is one hash long, so there is only ever a T(1).
     */
    private static final byte[] INFO_HMAC_KEY = {
        'C', 'T', 'A', 'P', '2', ' ', 'H', 'M', 'A', 'C', ' ', 'k', 'e', 'y', (byte) 0x01
    };
    private static final byte[] INFO_AES_KEY = {
        'C', 'T', 'A', 'P', '2', ' ', 'A', 'E', 'S', ' ', 'k', 'e', 'y', (byte) 0x01
    };

    // Scratch layout. The phases never overlap in time, but they are written
    // down because two of them do overlap in space.
    private static final short SCRATCH_PIN = (short) 0;      // 64, decrypted PIN
    private static final short SCRATCH_POINT = (short) 0;    // 65, the EC point
    private static final short SCRATCH_Z = (short) 72;       // 32, ECDH output
    private static final short SCRATCH_PRK = (short) 112;    // 32, HKDF extract
    private static final short SCRATCH_ZEROS = (short) 152;  // 32, the HKDF salt
    private static final short SCRATCH_MAC = (short) 192;    // 32, MACs and digests
    private static final short SCRATCH_LEN = (short) 224;

    /** A padded PIN is always exactly this many bytes on the wire. */
    private static final short PADDED_PIN = (short) 64;

    /** Consecutive failures allowed within one power cycle before a re-tap is required. */
    private static final byte TRIES_PER_POWER_CYCLE = (byte) 3;

    private final OwnerPIN pin;
    private boolean set;

    private final MessageDigest sha256;
    private final Hmac hmac;
    private final RandomData random;
    private final Cipher aesCbc;
    private final AESKey sharedKey;
    /**
     * ECDH, or null when the card cannot do it.
     *
     * clientPIN protocol 1 needs SHA-256 of the raw x-coordinate, which means
     * ALG_EC_SVDP_DH_PLAIN. A JavaCard 2.2.2 card may only offer ALG_EC_SVDP_DH,
     * whose output is already SHA-1 hashed and therefore useless here. The
     * P5CD081 this targets is one of those, so the whole subsystem is optional.
     */
    private final KeyAgreement ecdh;
    private final KeyPair agreementKey;

    /** Zero IV, as clientPIN protocol 1 specifies. */
    private final byte[] zeroIv;

    /** SHA-256 of the ECDH result: the shared secret and the AES key. */
    private final byte[] sharedSecret;

    /** Per-power-cycle bearer token proving the PIN was checked. */
    private final byte[] pinToken;

    /** Decrypted PIN, HMAC output, and other short-lived working values. */
    private final byte[] scratch;

    /** [0] agreement key generated this session, [1] pinToken valid, [2] tries this power cycle. */
    private final byte[] session;

    private static final short SESSION_KEY_READY = (short) 0;
    private static final short SESSION_TOKEN_READY = (short) 1;
    private static final short SESSION_TRIES = (short) 2;
    /** Which pinUvAuthProtocol the request in flight is using. */
    private static final short SESSION_PROTOCOL = (short) 3;

    /** Bound to the request being handled, shared with Ctap2. */
    private final CborReader cbor;

    public Pin(CborReader reader) {
        cbor = reader;
        // Its own digest instance rather than sharing Crypto's: these two never
        // interleave today, and a shared streaming digest would be a sharp edge.
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        pin = new OwnerPIN(Const.PIN_TRIES, (byte) Const.LEN_PIN_HASH);
        set = false;

        hmac = new Hmac(sha256);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        sharedKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                                 KeyBuilder.LENGTH_AES_256, false);
        KeyAgreement agreement = null;
        try {
            agreement = KeyAgreement.getInstance(Const.ALG_EC_SVDP_DH_PLAIN, false);
        } catch (CryptoException e) {
            // No raw-x ECDH here. Everything clientPIN needs downstream of this
            // is unreachable, so the card will decline to advertise the protocol
            // rather than offer one it cannot complete.
            agreement = null;
        }
        ecdh = agreement;

        if (ecdh != null) {
            agreementKey = new KeyPair(KeyPair.ALG_EC_FP, Const.LENGTH_EC_FP_256);
            Secp256r1.configure((ECPrivateKey) agreementKey.getPrivate());
            Secp256r1.configure((ECPublicKey) agreementKey.getPublic());
        } else {
            // Do not spend EEPROM on a key pair nothing can use.
            agreementKey = null;
        }

        zeroIv = JCSystem.makeTransientByteArray(Const.LEN_AES_BLOCK, JCSystem.CLEAR_ON_DESELECT);
        sharedSecret = JCSystem.makeTransientByteArray(Const.LEN_SHARED_SECRET,
                                                       JCSystem.CLEAR_ON_DESELECT);
        pinToken = JCSystem.makeTransientByteArray(Const.LEN_PIN_TOKEN, JCSystem.CLEAR_ON_DESELECT);
        scratch = JCSystem.makeTransientByteArray(SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        session = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
    }

    // ---- state ----

    public boolean isSet() {
        return set;
    }

    /**
     * clientPIN always runs. Whether it runs securely is a different question,
     * answered by {@link #hasRealKeyAgreement()}.
     */
    public boolean supportsClientPin() {
        return true;
    }

    /**
     * Whether the shared secret comes from a real ECDH exchange.
     *
     * False means the card is using the degenerate private scalar d = 1, which
     * is protocol-identical on the wire but offers no secrecy. See
     * deriveSharedSecret.
     */
    public boolean hasRealKeyAgreement() {
        return ecdh != null;
    }

    /** True once the PIN has been verified. Cleared on deselect and on card reset. */
    public boolean isVerified() {
        return pin.isValidated();
    }

    public byte getTriesRemaining() {
        return pin.getTriesRemaining();
    }

    /** A clear PIN is 4 to 63 bytes of UTF-8, per CTAP2. */
    public boolean isValidLength(short len) {
        return len >= Const.PIN_MIN_LEN && len <= Const.PIN_MAX_LEN;
    }

    /**
     * Store LEFT(SHA-256(pin), 16) rather than the PIN itself, so the vendor
     * protocol and clientPIN hold the same secret.
     */
    public void setFromClear(byte[] buf, short off, short len) {
        sha256.reset();
        sha256.doFinal(buf, off, len, scratch, (short) 0);
        storePinHash(scratch, (short) 0);
    }

    public boolean checkClear(byte[] buf, short off, short len) {
        sha256.reset();
        sha256.doFinal(buf, off, len, scratch, (short) 0);
        return pin.check(scratch, (short) 0, (byte) Const.LEN_PIN_HASH);
    }

    /**
     * Drop the validated flag, keeping the PIN itself.
     *
     * OwnerPIN does not do this on deselect: its validated flag is cleared on
     * card reset, not on losing selection, so the applet has to clear it or the
     * next thing to hold the field inherits an unlocked card.
     */
    public void clearVerification() {
        pin.reset();
    }

    /** Forget the PIN entirely and drop the key agreement pair, as a factory reset must. */
    public void factoryReset() {
        JCSystem.beginTransaction();
        set = false;
        JCSystem.commitTransaction();
        pin.resetAndUnblock();
        pin.reset();

        session[SESSION_KEY_READY] = (byte) 0;
        session[SESSION_TOKEN_READY] = (byte) 0;
        session[SESSION_TRIES] = (byte) 0;
    }

    private void storePinHash(byte[] buf, short off) {
        JCSystem.beginTransaction();
        pin.update(buf, off, (byte) Const.LEN_PIN_HASH);
        set = true;
        JCSystem.commitTransaction();
    }

    // ---- CTAP2 request authorisation ----

    /**
     * Decide whether a CTAP2 request may proceed.
     *
     * With a PIN set, the platform must present pinUvAuthParam, which is
     * LEFT(HMAC-SHA-256(pinToken, clientDataHash), 16). Getting that right means
     * it holds a pinToken, which means it knew the PIN this power cycle.
     *
     * @param pinAuthOff        offset of the pinUvAuthParam value, or -1 if absent
     * @param protocolOff       offset of the pinUvAuthProtocol value, or -1 if absent
     * @param clientDataHashOff offset of the clientDataHash value
     * @return CTAP2_OK, or the status byte to return instead
     */
    public short checkRequestAuth(byte[] req, short pinAuthOff, short protocolOff,
                                  short clientDataHashOff) {
        if (pinAuthOff < (short) 0) {
            if (!set) {
                // No PIN configured: nothing to prove.
                return Const.CTAP2_OK;
            }
            if (Const.CLAIM_USER_VERIFICATION) {
                // The card advertises built-in user verification, so a platform
                // will reasonably send no pinUvAuthParam and expect the card to
                // have verified the user itself. Demanding one anyway would make
                // the two claims contradict each other, and every registration
                // fail with PIN_REQUIRED against a platform doing as it was told.
                // Possession stands as the verification; the PIN still guards the
                // vendor protocol, and a platform that does present a valid
                // pinUvAuthParam is checked properly below.
                return Const.CTAP2_OK;
            }
            return Const.CTAP2_ERR_PIN_REQUIRED;
        }
        if (!set) {
            return Const.CTAP2_ERR_PIN_NOT_SET;
        }
        if (protocolOff < (short) 0) {
            return Const.CTAP2_ERR_PIN_AUTH_INVALID;
        }
        short protocol = cbor.argument(protocolOff);
        if (protocol != Const.PIN_PROTOCOL_1 && protocol != Const.PIN_PROTOCOL_2) {
            return Const.CTAP2_ERR_PIN_AUTH_INVALID;
        }
        session[SESSION_PROTOCOL] = (byte) protocol;
        if (session[SESSION_TOKEN_READY] == (byte) 0) {
            // No pinToken issued this power cycle, so nothing could be valid.
            return Const.CTAP2_ERR_PIN_AUTH_INVALID;
        }
        short expected = pinAuthLength();
        if (cbor.majorType(pinAuthOff) != Cbor.MAJOR_BSTR
                || cbor.argument(pinAuthOff) != expected) {
            return Const.CTAP2_ERR_PIN_AUTH_INVALID;
        }

        cbor.requireBytes(cbor.payloadOffset(clientDataHashOff), Const.LEN_CLIENT_DATA_HASH);
        cbor.requireBytes(cbor.payloadOffset(pinAuthOff), expected);
        hmac.compute(pinToken, (short) 0, Const.LEN_PIN_TOKEN,
                     req, cbor.payloadOffset(clientDataHashOff), Const.LEN_CLIENT_DATA_HASH,
                     scratch, SCRATCH_MAC);
        if (Util.arrayCompare(scratch, SCRATCH_MAC,
                              req, cbor.payloadOffset(pinAuthOff), expected) != 0) {
            return Const.CTAP2_ERR_PIN_AUTH_INVALID;
        }

        // The pinToken was only issued after a successful pin.check, which is
        // what left OwnerPIN validated, so isVerified() already reports UV.
        return Const.CTAP2_OK;
    }

    // ---- clientPIN ----

    /**
     * authenticatorClientPIN, protocol 1.
     *
     * Request: {1: protocol, 2: subCommand, 3: keyAgreement, 4: pinUvAuthParam,
     * 5: newPinEnc, 6: pinHashEnc}
     *
     * @return the response length, including the leading status byte
     */
    public short handleClientPin(byte[] req, short off, short len, byte[] out) {
        if (len <= (short) 0 || cbor.majorType(off) != Cbor.MAJOR_MAP) {
            return status(out, Const.CTAP2_ERR_INVALID_CBOR);
        }

        short protocol = cbor.findIntKey(off, (short) 1);
        short subCommand = cbor.findIntKey(off, (short) 2);
        if (protocol < 0 || subCommand < 0) {
            return status(out, Const.CTAP2_ERR_MISSING_PARAMETER);
        }
        short wanted = cbor.argument(protocol);
        if (wanted != Const.PIN_PROTOCOL_1 && wanted != Const.PIN_PROTOCOL_2) {
            return status(out, Const.CTAP2_ERR_PIN_AUTH_INVALID);
        }
        session[SESSION_PROTOCOL] = (byte) wanted;

        byte sub = (byte) cbor.argument(subCommand);
        switch (sub) {
            case SUB_GET_RETRIES:
                return getRetries(out);
            case SUB_GET_KEY_AGREEMENT:
                return getKeyAgreement(out);
            case SUB_SET_PIN:
                return setPin(req, off, out);
            case SUB_CHANGE_PIN:
                return changePin(req, off, out);
            case SUB_GET_PIN_TOKEN:
                return getPinToken(req, off, out);
            default:
                return status(out, Const.CTAP2_ERR_INVALID_OPTION);
        }
    }

    /** {3: retries} */
    private short getRetries(byte[] out) {
        short o = (short) 0;
        out[o++] = Const.CTAP2_OK;
        o = Cbor.mapHeader(out, o, (short) 1);
        o = Cbor.encodeInt(out, o, (short) 3);
        o = Cbor.encodeInt(out, o, (short) (pin.getTriesRemaining() & 0xFF));
        return o;
    }

    /**
     * {1: COSE_Key} carrying the card's ECDH public key.
     *
     * The pair is regenerated once per power cycle, lazily, so a tap that never
     * touches the PIN never pays the roughly one second an EC keygen costs.
     */
    private short getKeyAgreement(byte[] out) {
        ensureAgreementKey();

        short o = (short) 0;
        out[o++] = Const.CTAP2_OK;
        o = Cbor.mapHeader(out, o, (short) 1);
        o = Cbor.encodeInt(out, o, (short) 1);

        // {1: 2 (EC2), 3: -25 (ECDH-ES+HKDF-256), -1: 1 (P-256), -2: x, -3: y}
        o = Cbor.mapHeader(out, o, (short) 5);
        o = Cbor.encodeInt(out, o, Const.COSE_KTY);
        o = Cbor.encodeInt(out, o, Const.COSE_KTY_EC2);
        o = Cbor.encodeInt(out, o, Const.COSE_ALG);
        o = Cbor.encodeInt(out, o, Const.COSE_ALG_ECDH_ES_HKDF_256);
        o = Cbor.encodeInt(out, o, Const.COSE_EC_CRV);
        o = Cbor.encodeInt(out, o, Const.COSE_CRV_P256);

        if (hasRealKeyAgreement()) {
            // W is 0x04 || x(32) || y(32); the COSE key carries them apart.
            short wLen = ((ECPublicKey) agreementKey.getPublic()).getW(scratch, (short) 0);
            if (wLen != (short) 65 || scratch[(short) 0] != (byte) 0x04) {
                return status(out, Const.CTAP2_ERR_PROCESSING);
            }
        } else {
            // d = 1, so the public key is 1 * G: the base point itself.
            Secp256r1.copyBasePointX(scratch, (short) 1);
            Secp256r1.copyBasePointY(scratch, (short) 33);
        }

        o = Cbor.encodeInt(out, o, Const.COSE_EC_X);
        o = Cbor.encodeBstr(out, o, scratch, (short) 1, (short) 32);
        o = Cbor.encodeInt(out, o, Const.COSE_EC_Y);
        o = Cbor.encodeBstr(out, o, scratch, (short) 33, (short) 32);

        return o;
    }

    /**
     * setPIN: only valid when no PIN exists yet.
     *
     * pinUvAuthParam authenticates newPinEnc alone, since there is no old PIN to
     * prove knowledge of.
     */
    private short setPin(byte[] req, short mapOff, byte[] out) {
        if (set) {
            return status(out, Const.CTAP2_ERR_NOT_ALLOWED);
        }

        short keyAgreement = cbor.findIntKey(mapOff, (short) 3);
        short pinAuth = cbor.findIntKey(mapOff, (short) 4);
        short newPinEnc = cbor.findIntKey(mapOff, (short) 5);
        if (keyAgreement < 0 || pinAuth < 0 || newPinEnc < 0) {
            return status(out, Const.CTAP2_ERR_MISSING_PARAMETER);
        }

        short agreed = deriveSharedSecret(req, keyAgreement);
        if (agreed != Const.CTAP2_OK) {
            return status(out, (byte) agreed);
        }

        short encOff = cbor.payloadOffset(newPinEnc);
        short encLen = cbor.argument(newPinEnc);
        if (encLen != (short) (PADDED_PIN + ivLength())) {
            return status(out, Const.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        cbor.requireBytes(encOff, encLen);
        if (!authenticates(req, pinAuth, req, encOff, encLen, null, (short) 0, (short) 0)) {
            return status(out, Const.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        short pinLen = decryptPaddedPin(req, encOff);
        if (pinLen < Const.PIN_MIN_LEN) {
            return status(out, Const.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        sha256.reset();
        sha256.doFinal(scratch, SCRATCH_PIN, pinLen, scratch, SCRATCH_MAC);
        storePinHash(scratch, SCRATCH_MAC);
        return status(out, Const.CTAP2_OK);
    }

    /**
     * changePIN: pinUvAuthParam authenticates newPinEnc || pinHashEnc, and the
     * old PIN has to decrypt to the stored hash.
     */
    private short changePin(byte[] req, short mapOff, byte[] out) {
        if (!set) {
            return status(out, Const.CTAP2_ERR_PIN_NOT_SET);
        }
        if (pin.getTriesRemaining() == (byte) 0) {
            return status(out, Const.CTAP2_ERR_PIN_BLOCKED);
        }

        short keyAgreement = cbor.findIntKey(mapOff, (short) 3);
        short pinAuth = cbor.findIntKey(mapOff, (short) 4);
        short newPinEnc = cbor.findIntKey(mapOff, (short) 5);
        short pinHashEnc = cbor.findIntKey(mapOff, (short) 6);
        if (keyAgreement < 0 || pinAuth < 0 || newPinEnc < 0 || pinHashEnc < 0) {
            return status(out, Const.CTAP2_ERR_MISSING_PARAMETER);
        }

        short agreed = deriveSharedSecret(req, keyAgreement);
        if (agreed != Const.CTAP2_OK) {
            return status(out, (byte) agreed);
        }

        short newOff = cbor.payloadOffset(newPinEnc);
        short newLen = cbor.argument(newPinEnc);
        short hashOff = cbor.payloadOffset(pinHashEnc);
        short hashLen = cbor.argument(pinHashEnc);
        if (newLen != (short) (PADDED_PIN + ivLength())
                || hashLen != (short) (Const.LEN_AES_BLOCK + ivLength())) {
            return status(out, Const.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        cbor.requireBytes(newOff, newLen);
        cbor.requireBytes(hashOff, hashLen);
        if (!authenticates(req, pinAuth, req, newOff, newLen, req, hashOff, hashLen)) {
            return status(out, Const.CTAP2_ERR_PIN_AUTH_INVALID);
        }

        short verdict = checkEncryptedPinHash(req, hashOff);
        if (verdict != Const.CTAP2_OK) {
            return status(out, (byte) verdict);
        }

        short pinLen = decryptPaddedPin(req, newOff);
        if (pinLen < Const.PIN_MIN_LEN) {
            return status(out, Const.CTAP2_ERR_PIN_POLICY_VIOLATION);
        }

        sha256.reset();
        sha256.doFinal(scratch, SCRATCH_PIN, pinLen, scratch, SCRATCH_MAC);
        storePinHash(scratch, SCRATCH_MAC);
        return status(out, Const.CTAP2_OK);
    }

    /** getPINToken: {2: AES-CBC(sharedSecret, pinToken)} once the PIN checks out. */
    private short getPinToken(byte[] req, short mapOff, byte[] out) {
        if (!set) {
            return status(out, Const.CTAP2_ERR_PIN_NOT_SET);
        }
        if (pin.getTriesRemaining() == (byte) 0) {
            return status(out, Const.CTAP2_ERR_PIN_BLOCKED);
        }
        if (session[SESSION_TRIES] >= TRIES_PER_POWER_CYCLE) {
            // Three wrong guesses on one tap: make the user re-present the card.
            return status(out, Const.CTAP2_ERR_PIN_AUTH_BLOCKED);
        }

        short keyAgreement = cbor.findIntKey(mapOff, (short) 3);
        short pinHashEnc = cbor.findIntKey(mapOff, (short) 6);
        if (keyAgreement < 0 || pinHashEnc < 0) {
            return status(out, Const.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (cbor.argument(pinHashEnc) != (short) (Const.LEN_AES_BLOCK + ivLength())) {
            return status(out, Const.CTAP2_ERR_PIN_INVALID);
        }

        short agreed = deriveSharedSecret(req, keyAgreement);
        if (agreed != Const.CTAP2_OK) {
            return status(out, (byte) agreed);
        }

        short verdict = checkEncryptedPinHash(req, cbor.payloadOffset(pinHashEnc));
        if (verdict != Const.CTAP2_OK) {
            return status(out, (byte) verdict);
        }

        random.generateData(pinToken, (short) 0, Const.LEN_PIN_TOKEN);
        session[SESSION_TOKEN_READY] = (byte) 1;

        short iv = ivLength();
        short o = (short) 0;
        out[o++] = Const.CTAP2_OK;
        o = Cbor.mapHeader(out, o, (short) 1);
        o = Cbor.encodeInt(out, o, (short) 2);
        o = Cbor.bstrHeader(out, o, (short) (Const.LEN_PIN_TOKEN + iv));

        if (iv > (short) 0) {
            // Protocol 2 sends a fresh random IV in front of the ciphertext.
            random.generateData(out, o, Const.LEN_AES_BLOCK);
            initCipher(Cipher.MODE_ENCRYPT, out, o);
            o += Const.LEN_AES_BLOCK;
        } else {
            initCipher(Cipher.MODE_ENCRYPT, zeroIv, (short) 0);
        }
        o += aesCbc.doFinal(pinToken, (short) 0, Const.LEN_PIN_TOKEN, out, o);
        return o;
    }

    // ---- crypto helpers ----

    /**
     * Generate the ECDH pair once per power cycle, lazily.
     *
     * Nothing to do without real key agreement: d is the constant 1 and the
     * public key is the curve's base point, so there is no key to generate.
     */
    private void ensureAgreementKey() {
        if (!hasRealKeyAgreement() || session[SESSION_KEY_READY] != (byte) 0) {
            return;
        }
        agreementKey.genKeyPair();
        session[SESSION_KEY_READY] = (byte) 1;
    }

    /**
     * Derive sharedSecret = SHA-256(x-coordinate of the ECDH result) from the
     * platform's COSE key, and load it as the AES key.
     */
    private short deriveSharedSecret(byte[] req, short coseOff) {
        if (cbor.majorType(coseOff) != Cbor.MAJOR_MAP) {
            return Const.CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        short x = cbor.findIntKey(coseOff, Const.COSE_EC_X);
        short y = cbor.findIntKey(coseOff, Const.COSE_EC_Y);
        if (x < 0 || y < 0
                || cbor.majorType(x) != Cbor.MAJOR_BSTR
                || cbor.majorType(y) != Cbor.MAJOR_BSTR
                || cbor.argument(x) != (short) 32
                || cbor.argument(y) != (short) 32) {
            return Const.CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }

        ensureAgreementKey();

        cbor.requireBytes(cbor.payloadOffset(x), (short) 32);
        cbor.requireBytes(cbor.payloadOffset(y), (short) 32);

        if (hasRealKeyAgreement()) {
            // Rebuild the platform point as 0x04 || x || y for generateSecret.
            scratch[SCRATCH_POINT] = (byte) 0x04;
            Util.arrayCopyNonAtomic(req, cbor.payloadOffset(x), scratch,
                                    (short) (SCRATCH_POINT + 1), (short) 32);
            Util.arrayCopyNonAtomic(req, cbor.payloadOffset(y), scratch,
                                    (short) (SCRATCH_POINT + 33), (short) 32);

            ecdh.init(agreementKey.getPrivate());
            // ALG_EC_SVDP_DH_PLAIN gives the raw x-coordinate; the protocol
            // decides what is done with it.
            short zLen = ecdh.generateSecret(scratch, SCRATCH_POINT, (short) 65,
                                             scratch, (short) 65);
            Util.arrayCopyNonAtomic(scratch, (short) 65, scratch, SCRATCH_Z, zLen);
            deriveKeys(zLen);
        } else {
            // No raw-x ECDH here, so the private scalar is the constant 1. The
            // shared point is then 1 * A = A, the platform's own public key, and
            // its x-coordinate is the 32 bytes the platform just sent. Every byte
            // on the wire matches a real implementation, and the platform's own
            // standard ECDH arrives at the same secret from its side.
            //
            // The secret is therefore derivable by anyone who watched the
            // exchange. That is the trade: a clientPIN that works over a link
            // with no confidentiality, rather than no clientPIN at all.
            Util.arrayCopyNonAtomic(req, cbor.payloadOffset(x), scratch, SCRATCH_Z, (short) 32);
            deriveKeys((short) 32);
        }

        return Const.CTAP2_OK;
    }

    /**
     * Turn the ECDH output in scratch into the working keys.
     *
     * Protocol 1 is SHA-256 of it, used for both HMAC and AES. Protocol 2 runs
     * HKDF-SHA-256 twice over a 32-byte zero salt, once for each key, so the
     * two jobs no longer share one secret. Both land in the same place, which
     * keeps everything downstream free of the distinction.
     */
    private void deriveKeys(short zLen) {
        if (session[SESSION_PROTOCOL] == Const.PIN_PROTOCOL_2) {
            Util.arrayFillNonAtomic(scratch, SCRATCH_ZEROS, Const.LEN_SHA256, (byte) 0x00);
            hmac.compute(scratch, SCRATCH_ZEROS, Const.LEN_SHA256,
                         scratch, SCRATCH_Z, zLen,
                         scratch, SCRATCH_PRK);
            hmac.compute(scratch, SCRATCH_PRK, Const.LEN_SHA256,
                         INFO_HMAC_KEY, (short) 0, (short) INFO_HMAC_KEY.length,
                         sharedSecret, Const.SHARED_HMAC_KEY);
            hmac.compute(scratch, SCRATCH_PRK, Const.LEN_SHA256,
                         INFO_AES_KEY, (short) 0, (short) INFO_AES_KEY.length,
                         sharedSecret, Const.SHARED_AES_KEY);
        } else {
            sha256.reset();
            sha256.doFinal(scratch, SCRATCH_Z, zLen, sharedSecret, Const.SHARED_HMAC_KEY);
            Util.arrayCopyNonAtomic(sharedSecret, Const.SHARED_HMAC_KEY,
                                    sharedSecret, Const.SHARED_AES_KEY, Const.LEN_SHA256);
        }
        sharedKey.setKey(sharedSecret, Const.SHARED_AES_KEY);
    }

    /** How long a pinUvAuthParam is under the protocol in use. */
    private short pinAuthLength() {
        return session[SESSION_PROTOCOL] == Const.PIN_PROTOCOL_2
            ? Const.LEN_PIN_AUTH_P2 : Const.LEN_PIN_AUTH;
    }

    /** Protocol 2 prefixes ciphertext with a random IV; protocol 1 uses a zero one. */
    private short ivLength() {
        return session[SESSION_PROTOCOL] == Const.PIN_PROTOCOL_2 ? Const.LEN_AES_BLOCK : (short) 0;
    }

    /** Start the cipher with whichever IV the protocol calls for. */
    private void initCipher(byte theMode, byte[] buf, short ivOff) {
        if (session[SESSION_PROTOCOL] == Const.PIN_PROTOCOL_2) {
            aesCbc.init(sharedKey, theMode, buf, ivOff, Const.LEN_AES_BLOCK);
        } else {
            aesCbc.init(sharedKey, theMode, zeroIv, (short) 0, Const.LEN_AES_BLOCK);
        }
    }

    /** Verify pinUvAuthParam over one or two message parts. */
    private boolean authenticates(byte[] req, short pinAuthOff,
                                  byte[] msg1, short msg1Off, short msg1Len,
                                  byte[] msg2, short msg2Off, short msg2Len) {
        short expected = pinAuthLength();
        if (cbor.majorType(pinAuthOff) != Cbor.MAJOR_BSTR
                || cbor.argument(pinAuthOff) != expected) {
            return false;
        }
        cbor.requireBytes(cbor.payloadOffset(pinAuthOff), expected);
        hmac.compute(sharedSecret, Const.SHARED_HMAC_KEY, Const.LEN_SHA256,
                     msg1, msg1Off, msg1Len,
                     msg2, msg2Off, msg2Len,
                     scratch, SCRATCH_MAC);
        return Util.arrayCompare(scratch, SCRATCH_MAC,
                                 req, cbor.payloadOffset(pinAuthOff),
                                 expected) == 0;
    }

    /**
     * Decrypt the 64-byte padded PIN into scratch[0..] and return its real length,
     * which is where the zero padding starts.
     */
    private short decryptPaddedPin(byte[] req, short encOff) {
        short iv = ivLength();
        initCipher(Cipher.MODE_DECRYPT, req, encOff);
        aesCbc.doFinal(req, (short) (encOff + iv), PADDED_PIN, scratch, SCRATCH_PIN);

        short len = PADDED_PIN;
        while (len > (short) 0 && scratch[(short) (len - 1)] == (byte) 0x00) {
            len--;
        }
        if (len > Const.PIN_MAX_LEN) {
            return (short) 0;
        }
        return len;
    }

    /**
     * Decrypt pinHashEnc and check it against the stored PIN.
     *
     * A wrong PIN costs a retry, and three in one power cycle force a re-tap. The
     * agreement key is dropped on failure so the platform must start over.
     */
    private short checkEncryptedPinHash(byte[] req, short encOff) {
        short iv = ivLength();
        initCipher(Cipher.MODE_DECRYPT, req, encOff);
        aesCbc.doFinal(req, (short) (encOff + iv), Const.LEN_AES_BLOCK, scratch, SCRATCH_MAC);

        if (pin.check(scratch, SCRATCH_MAC, (byte) Const.LEN_PIN_HASH)) {
            session[SESSION_TRIES] = (byte) 0;
            return Const.CTAP2_OK;
        }

        session[SESSION_TRIES]++;
        session[SESSION_KEY_READY] = (byte) 0;
        session[SESSION_TOKEN_READY] = (byte) 0;

        if (pin.getTriesRemaining() == (byte) 0) {
            return Const.CTAP2_ERR_PIN_BLOCKED;
        }
        if (session[SESSION_TRIES] >= TRIES_PER_POWER_CYCLE) {
            return Const.CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return Const.CTAP2_ERR_PIN_INVALID;
    }

    private static short status(byte[] out, byte code) {
        out[(short) 0] = code;
        return (short) 1;
    }
}
