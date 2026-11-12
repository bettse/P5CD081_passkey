package dev.ericbetts.passkey;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 * ES256 (ECDSA over P-256 with SHA-256, COSE algorithm -7) on a card that has
 * no ALG_ECDSA_SHA_256.
 *
 * JCOP 2.4.1 can hash with SHA-256 and can sign with ECDSA, but only ECDSA over
 * SHA-1, and it has no raw ECDH to build a scalar multiplication from. What it
 * does have is enough to assemble the signature by hand:
 *
 *   r = x(k * G) mod n
 *   s = k^-1 * (h + r * d) mod n
 *
 * k * G     On-card EC key generation is a fixed-base scalar multiplication
 *           with a fresh random scalar, which is exactly what the nonce needs.
 *           The card hands back both the scalar (getS) and the point (getW).
 *
 * k^-1      x^(n-2) mod n, by Fermat. The RSA engine does the exponentiation.
 *           It will not take a 256-bit modulus, and it crashes the card if
 *           given n zero-padded to 512 bits, but it accepts n^2: a result
 *           mod n^2 is still correct mod n.
 *
 * a * b     ((a+b)^2 - a^2 - b^2) / 2, with each square done by the RSA engine
 *           as x^2 mod n^2. For a, b below n the product is below n^2, so this
 *           is the exact product.
 *
 * mod n     One software reduction of a 512-bit value at the very end.
 *
 * Every step was first checked on a real P5CD081, see probe/.
 *
 * None of the software arithmetic is constant time. The nonce is as good as the
 * card's key generator and is never reused, which is the property ECDSA cannot
 * survive without; timing side channels are outside what this card defends.
 */
public class Crypto {

    /** N squared, the modulus the RSA engine is asked to work under. */
    private static final byte[] N_SQUARED = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x79, (byte) 0xCD, (byte) 0xF5, (byte) 0x5B, (byte) 0xD4, (byte) 0x61, (byte) 0x47, (byte) 0xAE,
        (byte) 0x13, (byte) 0x12, (byte) 0x4D, (byte) 0xD7, (byte) 0x5F, (byte) 0x81, (byte) 0xF2, (byte) 0x26,
        (byte) 0x00, (byte) 0x43, (byte) 0x66, (byte) 0x1F, (byte) 0x1D, (byte) 0x81, (byte) 0x9D, (byte) 0x01,
        (byte) 0x9A, (byte) 0x02, (byte) 0xFC, (byte) 0xD8, (byte) 0x5D, (byte) 0x72, (byte) 0x4A, (byte) 0xA1,
        (byte) 0x32, (byte) 0xAD, (byte) 0x5E, (byte) 0x5D, (byte) 0xE4, (byte) 0x69, (byte) 0xC2, (byte) 0x7B,
        (byte) 0xAB, (byte) 0x0D, (byte) 0xBA, (byte) 0xA1, (byte) 0x5A, (byte) 0x16, (byte) 0x83, (byte) 0xA1
    };

    /** N - 2: by Fermat, x^(N-2) is the inverse of x mod N. */
    private static final byte[] N_MINUS_2 = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
        (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x4F
    };

    /** 2^256 - N, so that 2^256 is congruent to C mod N. The top four bytes are zero. */
    private static final byte[] C = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x43, (byte) 0x19, (byte) 0x05, (byte) 0x52, (byte) 0x58, (byte) 0xE8, (byte) 0x61, (byte) 0x7B,
        (byte) 0x0C, (byte) 0x46, (byte) 0x35, (byte) 0x3D, (byte) 0x03, (byte) 0x9C, (byte) 0xDA, (byte) 0xAF
    };

    private static final short LEN_WIDE = (short) 64;
    private static final short LEN_SCALAR = (short) 32;

    // Layout of the scratch array: four 64-byte numbers and r.
    private static final short Y = (short) 0;
    private static final short Z = (short) 64;
    private static final short T1 = (short) 128;
    private static final short T2 = (short) 192;
    private static final short R = (short) 256;
    private static final short LEN_SCRATCH = (short) 288;

    private final MessageDigest sha256;

    private static final byte[] TWO = {(byte) 0x02};

    /** x -> x^2 mod n^2 */
    private final Cipher squarer;
    private final Key squareKey;
    private final byte squareMode;
    /** x -> x^(n-2) mod n^2 */
    private final Cipher inverter;
    private final RSAPrivateKey inverseKey;

    /** A throwaway key pair per signature: its scalar is k, its point is k * G. */
    private final KeyPair nonce;
    private final ECPublicKey noncePoint;
    private final ECPrivateKey nonceScalar;

    /** Holds k and intermediate products, so transient and wiped after use. */
    private final byte[] w;

    public Crypto() {
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        squarer = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        inverter = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        // Squaring wants a public key: on the P5CD081 a public-key operation
        // runs three to four times faster than a private-key one, and there are
        // six squarings in a signature. But an exponent of 2 is not a legal RSA
        // public exponent, and although the card does not mind, the simulator's
        // BouncyCastle does. Private keys are not held to that rule, so fall
        // back to one where the public key is refused.
        RSAPublicKey pub = (RSAPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
        Key chosen = pub;
        byte mode = Cipher.MODE_ENCRYPT;
        try {
            pub.setModulus(N_SQUARED, (short) 0, LEN_WIDE);
            pub.setExponent(TWO, (short) 0, (short) TWO.length);
            squarer.init(pub, Cipher.MODE_ENCRYPT);
        } catch (RuntimeException e) {
            RSAPrivateKey priv = (RSAPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
            priv.setModulus(N_SQUARED, (short) 0, LEN_WIDE);
            priv.setExponent(TWO, (short) 0, (short) TWO.length);
            chosen = priv;
            mode = Cipher.MODE_DECRYPT;
        }
        squareKey = chosen;
        squareMode = mode;

        // A private key only because that is the key type the card accepted a
        // 256-bit exponent on quickly; nothing about n - 2 is secret.
        inverseKey = (RSAPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        inverseKey.setModulus(N_SQUARED, (short) 0, LEN_WIDE);
        inverseKey.setExponent(N_MINUS_2, (short) 0, LEN_SCALAR);

        noncePoint = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, Const.LENGTH_EC_FP_256, false);
        nonceScalar = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, Const.LENGTH_EC_FP_256, false);
        Secp256r1.configure(noncePoint);
        Secp256r1.configure(nonceScalar);
        nonce = new KeyPair(noncePoint, nonceScalar);

        w = JCSystem.makeTransientByteArray(LEN_SCRATCH, JCSystem.CLEAR_ON_DESELECT);
    }

    public short digest(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        sha256.reset();
        return sha256.doFinal(in, inOff, inLen, out, outOff);
    }

    /**
     * Sign one or two message parts as though they were concatenated, writing a
     * DER ECDSA signature. Pass null for in2 when there is only one part.
     *
     * Attestation signs authData || clientDataHash, and those live in different
     * buffers. Streaming both through the digest avoids copying either.
     *
     * There is deliberately no one-part overload, and the RSA calls below are
     * not wrapped in a helper. The JCVM stack on this card is nearly full by
     * the time CTAP2 gets here: one extra frame under getAssertion was enough
     * to turn every signature into 6F00.
     *
     * The message is hashed before anything is written to out, so the signature
     * may be written into the same buffer as long as it lands past the message.
     *
     * @return the number of signature bytes written, at most 72
     */
    public short signEs256(ECPrivateKey key,
                           byte[] in1, short in1Off, short in1Len,
                           byte[] in2, short in2Off, short in2Len,
                           byte[] out, short outOff) {
        // A cipher's initialised state does not survive a card reset.
        squarer.init(squareKey, squareMode);
        inverter.init(inverseKey, Cipher.MODE_DECRYPT);

        // r = x(k * G) mod n. The point is 65 bytes, so it borrows T1 and T2.
        nonce.genKeyPair();
        if (noncePoint.getW(w, T1) != (short) 65) {
            ISOException.throwIt(Const.SW_INTERNAL);
        }
        Util.arrayCopyNonAtomic(w, (short) (T1 + 1), w, R, LEN_SCALAR);
        if (compare(w, R, Secp256r1.N, (short) 0, LEN_SCALAR) >= (short) 0) {
            subtract(w, R, Secp256r1.N, (short) 0, LEN_SCALAR);
        }
        requireNonZero(R);

        // Y = r * d
        Util.arrayFillNonAtomic(w, Y, LEN_SCALAR, (byte) 0);
        Util.arrayCopyNonAtomic(w, R, w, (short) (Y + LEN_SCALAR), LEN_SCALAR);
        loadScalar(key, Z);
        multiply(Y, Z, T1, T2);

        // Y = h + r * d
        Util.arrayFillNonAtomic(w, Z, LEN_SCALAR, (byte) 0);
        sha256.reset();
        if (in2 == null) {
            sha256.doFinal(in1, in1Off, in1Len, w, (short) (Z + LEN_SCALAR));
        } else {
            sha256.update(in1, in1Off, in1Len);
            sha256.doFinal(in2, in2Off, in2Len, w, (short) (Z + LEN_SCALAR));
        }
        // Y = Y + Z mod n^2
        if (add(w, Y, w, Z, LEN_WIDE) != (short) 0
                || compare(w, Y, N_SQUARED, (short) 0, LEN_WIDE) >= (short) 0) {
            subtract(w, Y, N_SQUARED, (short) 0, LEN_WIDE);
        }

        // T1 = k^-1, correct mod n though not reduced
        loadScalar(nonceScalar, Z);
        short len = inverter.doFinal(w, Z, LEN_WIDE, w, T1);
        if (len < LEN_WIDE) {
            rightAlign(T1, len);
        }

        // Y = k^-1 * (h + r * d), then down to 32 bytes
        multiply(Y, T1, Z, T2);
        reduce(Y);
        requireNonZero((short) (Y + LEN_SCALAR));

        len = encodeDer(out, outOff);
        Util.arrayFillNonAtomic(w, (short) 0, LEN_SCRATCH, (byte) 0);
        return len;
    }

    /** Right-align a private scalar in a zeroed 64-byte slot. */
    private void loadScalar(ECPrivateKey key, short slot) {
        Util.arrayFillNonAtomic(w, slot, LEN_WIDE, (byte) 0);
        short at = (short) (slot + LEN_SCALAR);
        short len = key.getS(w, at);
        if (len < LEN_SCALAR) {
            short gap = (short) (LEN_SCALAR - len);
            Util.arrayCopyNonAtomic(w, at, w, (short) (at + gap), len);
            Util.arrayFillNonAtomic(w, at, gap, (byte) 0);
        }
    }

    private void requireNonZero(short off) {
        for (short i = (short) 0; i < LEN_SCALAR; i++) {
            if (w[(short) (off + i)] != (byte) 0) {
                return;
            }
        }
        // One chance in 2^256. Failing is simpler than retrying and as likely.
        ISOException.throwIt(Const.SW_INTERNAL);
    }

    /**
     * a = a * b mod n^2, with t1 and t2 as scratch. All four are 64-byte slots
     * in w, and a and b must already be below n^2.
     */
    private void multiply(short a, short b, short t1, short t2) {
        Util.arrayCopyNonAtomic(w, a, w, t1, LEN_WIDE);
        // t1 = a + b mod n^2. Written out rather than called, like the
        // subtractions below, to keep the stack one frame shallower.
        if (add(w, t1, w, b, LEN_WIDE) != (short) 0
                || compare(w, t1, N_SQUARED, (short) 0, LEN_WIDE) >= (short) 0) {
            subtract(w, t1, N_SQUARED, (short) 0, LEN_WIDE);
        }
        short len = squarer.doFinal(w, t1, LEN_WIDE, w, t2);      // (a+b)^2
        if (len < LEN_WIDE) {
            rightAlign(t2, len);
        }
        len = squarer.doFinal(w, a, LEN_WIDE, w, t1);             // a^2
        if (len < LEN_WIDE) {
            rightAlign(t1, len);
        }
        // t2 = t2 - t1 mod n^2
        if (subtract(w, t2, w, t1, LEN_WIDE) != (short) 0) {
            add(w, t2, N_SQUARED, (short) 0, LEN_WIDE);
        }
        len = squarer.doFinal(w, b, LEN_WIDE, w, t1);             // b^2
        if (len < LEN_WIDE) {
            rightAlign(t1, len);
        }
        // t2 = t2 - t1 mod n^2
        if (subtract(w, t2, w, t1, LEN_WIDE) != (short) 0) {
            add(w, t2, N_SQUARED, (short) 0, LEN_WIDE);
        }

        // Halve mod n^2: an odd value becomes even by adding the odd modulus,
        // and the carry out of that addition is the bit shifted in at the top.
        short top = (short) 0;
        if ((w[(short) (t2 + LEN_WIDE - 1)] & 0x01) != 0) {
            top = add(w, t2, N_SQUARED, (short) 0, LEN_WIDE);
        }
        for (short i = (short) 0; i < LEN_WIDE; i++) {
            short at = (short) (t2 + i);
            short v = (short) (w[at] & 0xFF);
            w[at] = (byte) ((short) (v >> 1) | (short) (top << 7));
            top = (short) (v & 0x01);
        }
        Util.arrayCopyNonAtomic(w, t2, w, a, LEN_WIDE);
    }

    /**
     * The card's RSA engine always returns 64 bytes. An implementation that
     * drops leading zeros returns fewer, left-aligned; put them back.
     */
    private void rightAlign(short slot, short len) {
        short gap = (short) (LEN_WIDE - len);
        Util.arrayCopyNonAtomic(w, slot, w, (short) (slot + gap), len);
        Util.arrayFillNonAtomic(w, slot, gap, (byte) 0);
    }

    /**
     * Reduce the 64-byte number at off modulo n, leaving the result in its low
     * 32 bytes.
     *
     * n is 2^256 - C with C under 2^224, so 2^256 is congruent to C. Working
     * down from the most significant byte, each byte q above the low 256 bits
     * is removed and q * C added back in 32 bytes lower. That can carry a 1
     * back into the byte just cleared, hence the inner loop.
     */
    private void reduce(short off) {
        for (short i = (short) 0; i < LEN_SCALAR; i++) {
            short top = (short) (off + i);
            while (w[top] != (byte) 0) {
                short q = (short) (w[top] & 0xFF);
                w[top] = (byte) 0;
                short carry = (short) 0;
                for (short j = (short) (LEN_SCALAR - 1); j >= (short) 0; j--) {
                    short at = (short) (top + 1 + j);
                    // At most 255 + 255 * 255 + 255 = 65535: it wraps a signed
                    // short, but all sixteen bits are still the right ones.
                    short v = (short) ((short) (w[at] & 0xFF)
                                       + (short) (q * (short) (C[j] & 0xFF))
                                       + carry);
                    w[at] = (byte) v;
                    carry = (short) ((short) (v >> 8) & 0xFF);
                }
                w[top] = (byte) carry;
            }
        }
        short low = (short) (off + LEN_SCALAR);
        if (compare(w, low, Secp256r1.N, (short) 0, LEN_SCALAR) >= (short) 0) {
            subtract(w, low, Secp256r1.N, (short) 0, LEN_SCALAR);
        }
    }

    /** a += b over len bytes, big-endian. Returns the carry out. */
    private static short add(byte[] a, short aOff, byte[] b, short bOff, short len) {
        short carry = (short) 0;
        for (short i = (short) (len - 1); i >= (short) 0; i--) {
            short at = (short) (aOff + i);
            short v = (short) ((short) (a[at] & 0xFF) + (short) (b[(short) (bOff + i)] & 0xFF) + carry);
            a[at] = (byte) v;
            carry = (short) ((short) (v >> 8) & 0x01);
        }
        return carry;
    }

    /** a -= b over len bytes, big-endian. Returns the borrow out. */
    private static short subtract(byte[] a, short aOff, byte[] b, short bOff, short len) {
        short borrow = (short) 0;
        for (short i = (short) (len - 1); i >= (short) 0; i--) {
            short at = (short) (aOff + i);
            short v = (short) ((short) (a[at] & 0xFF) - (short) (b[(short) (bOff + i)] & 0xFF) - borrow);
            a[at] = (byte) v;
            borrow = (short) ((short) (v >> 8) & 0x01);
        }
        return borrow;
    }

    /** Unsigned big-endian comparison: negative, zero or positive. */
    private static short compare(byte[] a, short aOff, byte[] b, short bOff, short len) {
        for (short i = (short) 0; i < len; i++) {
            short x = (short) (a[(short) (aOff + i)] & 0xFF);
            short y = (short) (b[(short) (bOff + i)] & 0xFF);
            if (x != y) {
                return (short) (x - y);
            }
        }
        return (short) 0;
    }

    /** SEQUENCE { INTEGER r, INTEGER s }, from r at R and s in the low half of Y. */
    private short encodeDer(byte[] out, short outOff) {
        short o = (short) (outOff + 2);
        o = encodeDerInteger(R, out, o);
        o = encodeDerInteger((short) (Y + LEN_SCALAR), out, o);
        out[outOff] = (byte) 0x30;
        out[(short) (outOff + 1)] = (byte) (o - outOff - 2);
        return (short) (o - outOff);
    }

    private short encodeDerInteger(short src, byte[] out, short o) {
        short skip = (short) 0;
        while (skip < (short) (LEN_SCALAR - 1) && w[(short) (src + skip)] == (byte) 0) {
            skip++;
        }
        short len = (short) (LEN_SCALAR - skip);
        // DER integers are signed, so a set top bit needs a zero in front of it.
        boolean pad = (w[(short) (src + skip)] & 0x80) != 0;
        out[o++] = (byte) 0x02;
        out[o++] = (byte) (pad ? (short) (len + 1) : len);
        if (pad) {
            out[o++] = (byte) 0x00;
        }
        Util.arrayCopyNonAtomic(w, (short) (src + skip), out, o, len);
        return (short) (o + len);
    }
}
