package dev.ericbetts.ecprobe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 * Asks a P5CD081 the three questions that decide whether ES256 can be built
 * on it without ALG_ECDSA_SHA_256:
 *
 *   1. Does ECPrivateKey.getS() hand back the scalar of a freshly generated key?
 *   2. Does the RSA engine accept a 512-bit modulus that is not an RSA modulus?
 *   3. Does it accept a 256-bit exponent?
 *
 * Failures come back as status words so the host can tell which call refused:
 *   66 sr   CryptoException, s = stage, r = reason
 *   65 s0   any other exception at stage s
 */
public class EcProbe extends Applet {

    private static final byte INS_STATUS = (byte) 0x00;
    private static final byte INS_EC_KEYGEN = (byte) 0x01;
    private static final byte INS_MODEXP = (byte) 0x02;

    private static final short MOD_LEN = (short) 64;

    private static final byte[] P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };
    private static final byte[] A = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
    };
    private static final byte[] B = {
        (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
        (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
        (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
        (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
    };
    private static final byte[] G = {
        (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42,
        (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40,
        (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33,
        (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2,
        (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
        (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E,
        (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E,
        (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51,
        (byte) 0xF5
    };
    private static final byte[] N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
    };

    private KeyPair ecPair;
    private ECPublicKey ecPub;
    private ECPrivateKey ecPriv;
    private RSAPublicKey rsaPub;
    private RSAPrivateKey rsaPriv;
    private Cipher rsa;

    /** One status per object built at install: 0 = ok, else 0x66/0x65 style. */
    private final short[] initStatus = new short[4];

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EcProbe().register();
    }

    private EcProbe() {
        try {
            ecPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false);
            ecPriv = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
            ecPub.setFieldFP(P, (short) 0, (short) P.length);
            ecPub.setA(A, (short) 0, (short) A.length);
            ecPub.setB(B, (short) 0, (short) B.length);
            ecPub.setG(G, (short) 0, (short) G.length);
            ecPub.setR(N, (short) 0, (short) N.length);
            ecPub.setK((short) 1);
            ecPriv.setFieldFP(P, (short) 0, (short) P.length);
            ecPriv.setA(A, (short) 0, (short) A.length);
            ecPriv.setB(B, (short) 0, (short) B.length);
            ecPriv.setG(G, (short) 0, (short) G.length);
            ecPriv.setR(N, (short) 0, (short) N.length);
            ecPriv.setK((short) 1);
            ecPair = new KeyPair(ecPub, ecPriv);
        } catch (CryptoException e) {
            initStatus[0] = (short) (0x6600 | e.getReason());
        } catch (RuntimeException e) {
            initStatus[0] = (short) 0x6500;
        }
        try {
            rsaPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        } catch (CryptoException e) {
            initStatus[1] = (short) (0x6600 | e.getReason());
        } catch (RuntimeException e) {
            initStatus[1] = (short) 0x6500;
        }
        try {
            rsaPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        } catch (CryptoException e) {
            initStatus[2] = (short) (0x6600 | e.getReason());
        } catch (RuntimeException e) {
            initStatus[2] = (short) 0x6500;
        }
        try {
            rsa = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        } catch (CryptoException e) {
            initStatus[3] = (short) (0x6600 | e.getReason());
        } catch (RuntimeException e) {
            initStatus[3] = (short) 0x6500;
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_STATUS:
                for (short i = 0; i < (short) 4; i++) {
                    Util.setShort(buf, (short) (i * 2), initStatus[i]);
                }
                apdu.setOutgoingAndSend((short) 0, (short) 8);
                return;
            case INS_EC_KEYGEN:
                ecKeygen(apdu, buf);
                return;
            case INS_MODEXP:
                modexp(apdu, buf);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /** Out: W (65 bytes, uncompressed) || S (whatever length getS returns). */
    private void ecKeygen(APDU apdu, byte[] buf) {
        byte stage = 1;
        short len = 0;
        try {
            ecPair.genKeyPair();
            stage = 2;
            len = ecPub.getW(buf, (short) 0);
            stage = 3;
            len += ecPriv.getS(buf, len);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6600 | (stage << 4) | e.getReason()));
        } catch (RuntimeException e) {
            ISOException.throwIt((short) (0x6500 | (stage << 4)));
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * In:  modulus(64) || exponent(P2 bytes) || base(64)
     * P1:  0 = RSAPublicKey + MODE_ENCRYPT, 1 = RSAPrivateKey + MODE_DECRYPT
     * Out: base ^ exponent mod modulus, 64 bytes
     */
    private void modexp(APDU apdu, byte[] buf) {
        short lc = apdu.setIncomingAndReceive();
        short expLen = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        if (lc != (short) (MOD_LEN + expLen + MOD_LEN)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short modOff = ISO7816.OFFSET_CDATA;
        short expOff = (short) (modOff + MOD_LEN);
        short baseOff = (short) (expOff + expLen);
        boolean priv = buf[ISO7816.OFFSET_P1] == (byte) 1;
        byte stage = 1;
        short len = 0;
        try {
            if (priv) {
                rsaPriv.setModulus(buf, modOff, MOD_LEN);
                stage = 2;
                rsaPriv.setExponent(buf, expOff, expLen);
                stage = 3;
                rsa.init(rsaPriv, Cipher.MODE_DECRYPT);
            } else {
                rsaPub.setModulus(buf, modOff, MOD_LEN);
                stage = 2;
                rsaPub.setExponent(buf, expOff, expLen);
                stage = 3;
                rsa.init(rsaPub, Cipher.MODE_ENCRYPT);
            }
            stage = 4;
            // Output lands at 0..63; the base starts at 69 or later, so no overlap.
            len = rsa.doFinal(buf, baseOff, MOD_LEN, buf, (short) 0);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6600 | (stage << 4) | e.getReason()));
        } catch (RuntimeException e) {
            ISOException.throwIt((short) (0x6500 | (stage << 4)));
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }
}
