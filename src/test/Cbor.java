package test;

import java.util.Arrays;

/**
 * A minimal CBOR reader for the test side, enough to check what the card emits.
 *
 * Deliberately strict: it rejects non-canonical arguments, because CTAP2 requires
 * canonical encoding and a card that drifts from it should fail a test, not pass.
 */
public class Cbor {

    public static final int UINT = 0x00;
    public static final int NEGINT = 0x20;
    public static final int BSTR = 0x40;
    public static final int TSTR = 0x60;
    public static final int ARRAY = 0x80;
    public static final int MAP = 0xA0;
    public static final int SIMPLE = 0xE0;

    private final byte[] data;
    private int pos;

    public Cbor(byte[] data) {
        this.data = data;
        this.pos = 0;
    }

    public int remaining() {
        return data.length - pos;
    }

    public int position() {
        return pos;
    }

    public int peekMajor() {
        return data[pos] & 0xE0;
    }

    /** Read the header at the cursor, assert its major type, and return the argument. */
    public int expect(int major) {
        if (peekMajor() != major) {
            throw new IllegalArgumentException(String.format(
                "at %d: expected major 0x%02X, got 0x%02X", pos, major, peekMajor()));
        }
        return (int) readArgument();
    }

    /** Read an integer item, signed: major 0 as-is, major 1 as -1-argument. */
    public long readInt() {
        int major = peekMajor();
        long arg = readArgument();
        switch (major) {
            case UINT:
                return arg;
            case NEGINT:
                return -1 - arg;
            default:
                throw new IllegalArgumentException(String.format(
                    "at %d: expected an integer, got major 0x%02X", pos, major));
        }
    }

    public byte[] readBytes() {
        int len = expect(BSTR);
        byte[] out = Arrays.copyOfRange(data, pos, pos + len);
        pos += len;
        return out;
    }

    public String readText() {
        int len = expect(TSTR);
        String out = new String(data, pos, len, java.nio.charset.StandardCharsets.UTF_8);
        pos += len;
        return out;
    }

    public boolean readBool() {
        int b = data[pos++] & 0xFF;
        if (b == 0xF5) {
            return true;
        }
        if (b == 0xF4) {
            return false;
        }
        throw new IllegalArgumentException(String.format("at %d: not a boolean: 0x%02X", pos - 1, b));
    }

    private long readArgument() {
        int b = data[pos++] & 0xFF;
        int ai = b & 0x1F;
        if (ai < 24) {
            return ai;
        }
        switch (ai) {
            case 24: {
                long v = data[pos++] & 0xFFL;
                if (v < 24) {
                    throw new IllegalArgumentException("non-canonical: " + v + " in a 1-byte argument");
                }
                return v;
            }
            case 25: {
                long v = ((data[pos] & 0xFFL) << 8) | (data[pos + 1] & 0xFFL);
                pos += 2;
                if (v < 256) {
                    throw new IllegalArgumentException("non-canonical: " + v + " in a 2-byte argument");
                }
                return v;
            }
            default:
                throw new IllegalArgumentException("unsupported additional info " + ai);
        }
    }

    // ---- encoding, for building CTAP2 requests in tests ----

    public static byte[] header(int major, long len) {
        if (len < 24) {
            return new byte[]{(byte) (major | len)};
        }
        if (len < 256) {
            return new byte[]{(byte) (major | 24), (byte) len};
        }
        return new byte[]{(byte) (major | 25), (byte) (len >> 8), (byte) len};
    }

    public static byte[] encodeInt(long value) {
        if (value >= 0) {
            return header(UINT, value);
        }
        return header(NEGINT, -1 - value);
    }

    public static byte[] encodeBytes(byte[] value) {
        return concat(header(BSTR, value.length), value);
    }

    public static byte[] encodeText(String value) {
        byte[] raw = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return concat(header(TSTR, raw.length), raw);
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
