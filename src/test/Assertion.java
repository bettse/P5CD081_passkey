package test;

/**
 * The CTAP2 authenticatorGetAssertion response:
 * {1: {"id":..., "type":...}, 2: authData, 3: signature}
 */
public class Assertion {

    public final byte[] credentialId;
    public final String credentialType;
    public final byte[] authData;
    public final byte[] signature;

    /** user.id, present only for a discoverable credential. */
    public final byte[] userId;

    /** Key 5, sent only when more assertions follow. Zero when absent. */
    public final int numberOfCredentials;

    private Assertion(byte[] credentialId, String credentialType, byte[] authData,
                      byte[] signature, byte[] userId, int numberOfCredentials) {
        this.credentialId = credentialId;
        this.credentialType = credentialType;
        this.authData = authData;
        this.signature = signature;
        this.userId = userId;
        this.numberOfCredentials = numberOfCredentials;
    }

    public long signCount() {
        return ((authData[33] & 0xFFL) << 24) | ((authData[34] & 0xFFL) << 16)
             | ((authData[35] & 0xFFL) << 8) | (authData[36] & 0xFFL);
    }

    public byte flags() {
        return authData[32];
    }

    public boolean userVerified() {
        return (flags() & 0x04) != 0;
    }

    public static Assertion parse(byte[] data) {
        Cbor c = new Cbor(data);
        int entries = c.expect(Cbor.MAP);
        if (entries < 3 || entries > 5) {
            throw new IllegalArgumentException("assertion has " + entries + " entries");
        }

        byte[] credentialId = null;
        String credentialType = null;
        byte[] authData = null;
        byte[] signature = null;
        byte[] userId = null;
        int numberOfCredentials = 0;

        for (int i = 0; i < entries; i++) {
            int key = (int) c.readInt();
            switch (key) {
                case 1: {
                    int fields = c.expect(Cbor.MAP);
                    for (int j = 0; j < fields; j++) {
                        String name = c.readText();
                        if (name.equals("id")) {
                            credentialId = c.readBytes();
                        } else if (name.equals("type")) {
                            credentialType = c.readText();
                        } else {
                            throw new IllegalArgumentException("unexpected credential field " + name);
                        }
                    }
                    break;
                }
                case 2:
                    authData = c.readBytes();
                    break;
                case 3:
                    signature = c.readBytes();
                    break;
                case 4: {
                    int fields = c.expect(Cbor.MAP);
                    for (int j = 0; j < fields; j++) {
                        String name = c.readText();
                        if (name.equals("id")) {
                            userId = c.readBytes();
                        } else {
                            throw new IllegalArgumentException("unexpected user field " + name);
                        }
                    }
                    break;
                }
                case 5:
                    numberOfCredentials = (int) c.readInt();
                    break;
                default:
                    throw new IllegalArgumentException("unexpected key " + key);
            }
        }
        if (c.remaining() != 0) {
            throw new IllegalArgumentException(c.remaining() + " trailing bytes");
        }
        if (credentialId == null || authData == null || signature == null) {
            throw new IllegalArgumentException("assertion is missing a field");
        }
        return new Assertion(credentialId, credentialType, authData, signature,
                             userId, numberOfCredentials);
    }
}
