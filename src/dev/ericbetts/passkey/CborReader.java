package dev.ericbetts.passkey;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * The CBOR decoder, bound to one request.
 *
 * Decoding reads a buffer a hostile host filled in, so every read is checked
 * against the end of the request rather than the end of the array. Binding the
 * bound to the reader instead of passing it to each method means a call site
 * cannot forget it, which is how the first version of this got it wrong: it
 * took no length at all, and a byte-string header claiming 64 bytes at the tail
 * of a short request would happily copy 64 bytes of whatever the previous
 * request left behind.
 *
 * Encoding lives in {@link Cbor} and stays static: it writes into buffers this
 * applet owns and sizes itself.
 *
 * Malformed input raises {@link Const#SW_CBOR_UNSUPPORTED}, which Ctap2 catches
 * and turns into a CTAP status byte.
 */
public class CborReader {

    private byte[] buf;
    private short start;
    private short end;

    /** Point the reader at a request. Everything after this is bounded by it. */
    public void bind(byte[] buffer, short off, short len) {
        buf = buffer;
        start = off;
        end = (short) (off + len);
    }

    // ---- bounds ----

    /** Every read goes through here. */
    private void require(short off, short len) {
        if (off < start || len < (short) 0 || (short) (off + len) > end) {
            ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
        }
    }

    /** Read a byte, checked. Used for the true/false simple values. */
    public byte byteAt(short off) {
        require(off, (short) 1);
        return buf[off];
    }

    public byte majorType(short off) {
        return (byte) (byteAt(off) & 0xE0);
    }

    /**
     * The argument of the item at off.
     *
     * Rejects anything that will not fit in a positive short. A 2-byte argument
     * of 0x8000 or more would come back as a negative length and sail past the
     * "is it too big" checks downstream, which compare with a signed >.
     */
    public short argument(short off) {
        short ai = (short) (byteAt(off) & 0x1F);
        if (ai < (short) 24) {
            return ai;
        }
        switch (ai) {
            case 24: {
                require((short) (off + 1), (short) 1);
                return (short) (buf[(short) (off + 1)] & 0xFF);
            }
            case 25: {
                require((short) (off + 1), (short) 2);
                short value = Util.getShort(buf, (short) (off + 1));
                if (value < (short) 0) {
                    // 0x8000 and up: legitimate CBOR, but larger than any request
                    // this card accepts, and unrepresentable as a positive short.
                    ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
                }
                return value;
            }
            default:
                // 26 and 27 are 4- and 8-byte arguments; 28..30 are reserved; 31
                // is the indefinite-length form, which CTAP2 canonical CBOR bans.
                ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
                return (short) 0;
        }
    }

    /** Offset of the payload that follows the header at off. */
    public short payloadOffset(short off) {
        short ai = (short) (byteAt(off) & 0x1F);
        if (ai < (short) 24) {
            return (short) (off + 1);
        }
        switch (ai) {
            case 24:
                return (short) (off + 2);
            case 25:
                return (short) (off + 3);
            default:
                ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
                return (short) 0;
        }
    }

    /**
     * Advance past the complete item at off, including everything inside it.
     *
     * Iterative, not recursive. CBOR lays containers out in prefix order, so
     * skipping one is just consuming its contents in sequence: a counter of how
     * many items are still owed does the same job as a call stack, in constant
     * space.
     *
     * That matters more here than it looks. This card raises SystemException
     * NO_RESOURCE when the JCVM stack runs out, and the margin is roughly one
     * frame: a recursive skip put registration over the edge, and it presented
     * as a mysterious 6F00 during parsing rather than anything resembling a
     * stack error. It also removes the denial-of-service in the recursive
     * version, where a few hundred nested array headers exhausted the stack.
     *
     * @return the offset of the next item
     */
    public short skip(short off) {
        short owed = (short) 1;

        while (owed > (short) 0) {
            byte major = majorType(off);
            short arg = argument(off);
            off = payloadOffset(off);
            owed--;

            switch (major) {
                case Cbor.MAJOR_UINT:
                case Cbor.MAJOR_NEGINT:
                case Cbor.MAJOR_SIMPLE:
                    break;
                case Cbor.MAJOR_BSTR:
                case Cbor.MAJOR_TSTR:
                    require(off, arg);
                    off += arg;
                    break;
                case Cbor.MAJOR_ARRAY:
                    owed = add(owed, arg);
                    break;
                case Cbor.MAJOR_MAP:
                    // A map owes a key and a value for every entry.
                    owed = add(owed, add(arg, arg));
                    break;
                default:
                    ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
            }
        }
        return off;
    }

    /**
     * Add to the outstanding-item count, refusing anything a request this size
     * could not honestly contain. Every item costs at least one byte, so a
     * request cannot owe more items than MAX_REQUEST, and this also keeps the
     * sum well clear of overflowing a short.
     */
    private static short add(short owed, short more) {
        if (more < (short) 0 || (short) (owed + more) > Const.MAX_REQUEST) {
            ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
        }
        return (short) (owed + more);
    }

    /**
     * Find a value in a map keyed by small integers, the shape every CTAP2
     * request uses.
     *
     * @return offset of the value, or -1 if the key is absent
     */
    public short findIntKey(short mapOff, short key) {
        if (majorType(mapOff) != Cbor.MAJOR_MAP) {
            ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
        }
        short entries = argument(mapOff);
        short off = payloadOffset(mapOff);

        for (short i = (short) 0; i < entries; i++) {
            byte keyMajor = majorType(off);
            boolean match = false;
            if (keyMajor == Cbor.MAJOR_UINT && key >= (short) 0) {
                match = argument(off) == key;
            } else if (keyMajor == Cbor.MAJOR_NEGINT && key < (short) 0) {
                match = argument(off) == (short) (-1 - key);
            }
            off = skip(off);
            if (match) {
                return off;
            }
            off = skip(off);
        }
        return (short) -1;
    }

    /**
     * Find a value in a map keyed by text strings, used for the rp and user maps.
     *
     * @return offset of the value, or -1 if the key is absent
     */
    public short findTextKey(short mapOff, byte[] key, short keyOff, short keyLen) {
        if (majorType(mapOff) != Cbor.MAJOR_MAP) {
            ISOException.throwIt(Const.SW_CBOR_UNSUPPORTED);
        }
        short entries = argument(mapOff);
        short off = payloadOffset(mapOff);

        for (short i = (short) 0; i < entries; i++) {
            boolean match = false;
            if (majorType(off) == Cbor.MAJOR_TSTR && argument(off) == keyLen) {
                short payload = payloadOffset(off);
                require(payload, keyLen);
                match = Util.arrayCompare(buf, payload, key, keyOff, keyLen) == 0;
            }
            off = skip(off);
            if (match) {
                return off;
            }
            off = skip(off);
        }
        return (short) -1;
    }

    /**
     * Check that a byte string at off really carries len bytes.
     *
     * Callers that copy a decoder-supplied length have to say so explicitly, so
     * that a truncated request fails here rather than reading stale buffer.
     */
    public void requireBytes(short off, short len) {
        require(off, len);
    }
}
