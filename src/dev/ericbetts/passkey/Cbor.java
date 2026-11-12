package dev.ericbetts.passkey;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Just enough CBOR (RFC 8949) for CTAP2: the encoder, and the major-type
 * constants the decoder shares.
 *
 * CTAP2 mandates canonical encoding: shortest possible argument, map keys sorted
 * by encoded length then bytewise. The encoder always picks the shortest
 * argument; key ordering is the caller's job, since the callers write fixed maps.
 *
 * Decoding lives in {@link CborReader}, which has to be bounded by the request
 * it is reading and so cannot be static.
 */
public final class Cbor {

    private Cbor() {
    }

    public static final byte MAJOR_UINT = (byte) 0x00;
    public static final byte MAJOR_NEGINT = (byte) 0x20;
    public static final byte MAJOR_BSTR = (byte) 0x40;
    public static final byte MAJOR_TSTR = (byte) 0x60;
    public static final byte MAJOR_ARRAY = (byte) 0x80;
    public static final byte MAJOR_MAP = (byte) 0xA0;
    public static final byte MAJOR_SIMPLE = (byte) 0xE0;

    public static final byte TRUE = (byte) 0xF5;
    public static final byte FALSE = (byte) 0xF4;

    // ---- encoding ----

    /**
     * Write a major type with its argument, using the shortest encoding.
     * len is treated as unsigned, so 0x8000..0xFFFF work despite being negative shorts.
     */
    public static short header(byte[] buf, short off, byte major, short len) {
        if (len >= (short) 0 && len < (short) 24) {
            buf[off++] = (byte) (major | len);
        } else if (len >= (short) 0 && len < (short) 256) {
            buf[off++] = (byte) (major | 24);
            buf[off++] = (byte) len;
        } else {
            buf[off++] = (byte) (major | 25);
            Util.setShort(buf, off, len);
            off += 2;
        }
        return off;
    }

    public static short mapHeader(byte[] buf, short off, short entries) {
        return header(buf, off, MAJOR_MAP, entries);
    }

    public static short arrayHeader(byte[] buf, short off, short items) {
        return header(buf, off, MAJOR_ARRAY, items);
    }

    public static short bstrHeader(byte[] buf, short off, short len) {
        return header(buf, off, MAJOR_BSTR, len);
    }

    /** Encode a signed integer. Negative n encodes as major type 1 with argument -1-n. */
    public static short encodeInt(byte[] buf, short off, short value) {
        if (value >= (short) 0) {
            return header(buf, off, MAJOR_UINT, value);
        }
        return header(buf, off, MAJOR_NEGINT, (short) (-1 - value));
    }

    public static short encodeBstr(byte[] buf, short off, byte[] src, short srcOff, short len) {
        off = bstrHeader(buf, off, len);
        Util.arrayCopyNonAtomic(src, srcOff, buf, off, len);
        return (short) (off + len);
    }

    /** Encode a text string held as raw bytes. Callers pass ASCII literals. */
    public static short encodeTstr(byte[] buf, short off, byte[] src, short srcOff, short len) {
        off = header(buf, off, MAJOR_TSTR, len);
        Util.arrayCopyNonAtomic(src, srcOff, buf, off, len);
        return (short) (off + len);
    }

    /**
     * Reserve room for a byte-string header whose length is not known yet.
     * Pair with {@link #fillReservedBstrHeader}: the payload must be written at
     * off + reserve, and reserve must match the header size the final length needs.
     */
    public static short reserveBstrHeader(short len) {
        if (len < (short) 24) {
            return (short) 1;
        }
        if (len < (short) 256) {
            return (short) 2;
        }
        return (short) 3;
    }

    public static void fillReservedBstrHeader(byte[] buf, short off, short len, short reserved) {
        short written = (short) (bstrHeader(buf, off, len) - off);
        if (written != reserved) {
            // The caller guessed the header size wrong and the payload is misplaced.
            ISOException.throwIt(Const.SW_INTERNAL);
        }
    }
}
