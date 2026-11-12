package dev.ericbetts.passkey;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * HMAC-SHA-256 in software, because the P5CD081 has no ALG_HMAC_SHA_256.
 *
 * It is the plain RFC 2104 construction over the card's hardware SHA-256:
 * SHA256((K ^ opad) || SHA256((K ^ ipad) || message)). The message is streamed
 * through update(), so nothing has to hold it in a buffer.
 *
 * Keys longer than the 64-byte block would need hashing first; clientPIN only
 * ever uses 32-byte keys, so that case is rejected rather than silently handled.
 */
public class Hmac {

    private static final short BLOCK = (short) 64;
    private static final byte IPAD = (byte) 0x36;
    private static final byte OPAD = (byte) 0x5C;

    private final MessageDigest sha256;
    private final byte[] pad;
    private final byte[] inner;

    public Hmac(MessageDigest sha256) {
        this.sha256 = sha256;
        pad = JCSystem.makeTransientByteArray(BLOCK, JCSystem.CLEAR_ON_DESELECT);
        inner = JCSystem.makeTransientByteArray(Const.LEN_SHA256, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * HMAC over one message.
     *
     * @return the number of bytes written, always 32
     */
    public short compute(byte[] key, short keyOff, short keyLen,
                         byte[] msg, short msgOff, short msgLen,
                         byte[] out, short outOff) {
        return compute(key, keyOff, keyLen, msg, msgOff, msgLen, null, (short) 0, (short) 0,
                       out, outOff);
    }

    /**
     * HMAC over two message parts, which changePIN needs: it authenticates
     * newPinEnc || pinHashEnc, and those are not contiguous in the request.
     *
     * @return the number of bytes written, always 32
     */
    public short compute(byte[] key, short keyOff, short keyLen,
                         byte[] msg1, short msg1Off, short msg1Len,
                         byte[] msg2, short msg2Off, short msg2Len,
                         byte[] out, short outOff) {
        if (keyLen > BLOCK) {
            // Not reachable from clientPIN, and silently hashing would hide a bug.
            javacard.framework.ISOException.throwIt(Const.SW_INTERNAL);
        }

        buildPad(key, keyOff, keyLen, IPAD);
        sha256.reset();
        sha256.update(pad, (short) 0, BLOCK);
        if (msg2 == null) {
            sha256.doFinal(msg1, msg1Off, msg1Len, inner, (short) 0);
        } else {
            sha256.update(msg1, msg1Off, msg1Len);
            sha256.doFinal(msg2, msg2Off, msg2Len, inner, (short) 0);
        }

        buildPad(key, keyOff, keyLen, OPAD);
        sha256.reset();
        sha256.update(pad, (short) 0, BLOCK);
        sha256.doFinal(inner, (short) 0, Const.LEN_SHA256, out, outOff);

        return Const.LEN_SHA256;
    }

    /**
     * Compare the left 16 bytes of an HMAC against a candidate, which is the
     * truncation clientPIN protocol 1 uses everywhere.
     */
    public boolean verifyTruncated(byte[] key, short keyOff, short keyLen,
                                   byte[] msg, short msgOff, short msgLen,
                                   byte[] candidate, short candidateOff,
                                   byte[] scratch, short scratchOff) {
        compute(key, keyOff, keyLen, msg, msgOff, msgLen, scratch, scratchOff);
        return Util.arrayCompare(scratch, scratchOff, candidate, candidateOff,
                                 Const.LEN_PIN_AUTH) == 0;
    }

    private void buildPad(byte[] key, short keyOff, short keyLen, byte constant) {
        Util.arrayFillNonAtomic(pad, (short) 0, BLOCK, constant);
        for (short i = (short) 0; i < keyLen; i++) {
            pad[i] = (byte) (key[(short) (keyOff + i)] ^ constant);
        }
    }
}
