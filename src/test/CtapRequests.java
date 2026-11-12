package test;

/** Builders for the CTAP2 requests a platform would send. */
public final class CtapRequests {

    public static final byte CMD_MAKE_CREDENTIAL = 0x01;
    public static final byte CMD_GET_ASSERTION = 0x02;
    public static final byte CMD_GET_INFO = 0x04;
    public static final byte CMD_CLIENT_PIN = 0x06;
    public static final byte CMD_RESET = 0x07;
    public static final byte CMD_GET_NEXT_ASSERTION = 0x08;

    public static final int ALG_ES256 = -7;
    public static final int ALG_RS256 = -257;

    private CtapRequests() {
    }

    /** {1: clientDataHash, 2: rp, 3: user, 4: pubKeyCredParams} */
    public static byte[] makeCredential(byte[] clientDataHash, String rpId, int... algs) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 4),
            Cbor.encodeInt(1), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(2), rp(rpId),
            Cbor.encodeInt(3), user(),
            Cbor.encodeInt(4), pubKeyCredParams(algs));
    }

    /** As above with an options map, for exercising rk and uv. */
    public static byte[] makeCredentialWithOptions(byte[] clientDataHash, String rpId,
                                                   String option, boolean value) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(2), rp(rpId),
            Cbor.encodeInt(3), user(),
            Cbor.encodeInt(4), pubKeyCredParams(ALG_ES256),
            Cbor.encodeInt(7), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText(option), new byte[]{value ? (byte) 0xF5 : (byte) 0xF4}));
    }

    /** {1: clientDataHash, 2: rp, 3: user, 4: pubKeyCredParams, 8: pinUvAuthParam, 9: protocol} */
    public static byte[] makeCredentialWithPinAuth(byte[] clientDataHash, String rpId,
                                                   byte[] pinUvAuthParam) {
        return makeCredentialWithPinAuth(clientDataHash, rpId, pinUvAuthParam, 1);
    }

    public static byte[] makeCredentialWithPinAuth(byte[] clientDataHash, String rpId,
                                                   byte[] pinUvAuthParam, int protocol) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 6),
            Cbor.encodeInt(1), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(2), rp(rpId),
            Cbor.encodeInt(3), user(),
            Cbor.encodeInt(4), pubKeyCredParams(ALG_ES256),
            Cbor.encodeInt(8), Cbor.encodeBytes(pinUvAuthParam),
            Cbor.encodeInt(9), Cbor.encodeInt(protocol));
    }

    /** {1: rpId, 2: clientDataHash, 6: pinUvAuthParam, 7: 1} */
    public static byte[] getAssertionWithPinAuth(String rpId, byte[] clientDataHash,
                                                 byte[] pinUvAuthParam) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 4),
            Cbor.encodeInt(1), Cbor.encodeText(rpId),
            Cbor.encodeInt(2), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(6), Cbor.encodeBytes(pinUvAuthParam),
            Cbor.encodeInt(7), Cbor.encodeInt(1));
    }

    /** A discoverable credential: options.rk true, and user.id is kept by the card. */
    public static byte[] makeCredentialResident(byte[] clientDataHash, String rpId, byte[] userId) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(2), rp(rpId),
            Cbor.encodeInt(3), user(userId),
            Cbor.encodeInt(4), pubKeyCredParams(ALG_ES256),
            Cbor.encodeInt(7), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("rk"), new byte[]{(byte) 0xF5}));
    }

    /** {..., 5: excludeList} */
    public static byte[] makeCredentialWithExcludeList(byte[] clientDataHash, String rpId,
                                                       byte[]... credentialIds) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(2), rp(rpId),
            Cbor.encodeInt(3), user(),
            Cbor.encodeInt(4), pubKeyCredParams(ALG_ES256),
            Cbor.encodeInt(5), credentialList(credentialIds));
    }

    /** {1: rpId, 2: clientDataHash} */
    public static byte[] getAssertion(String rpId, byte[] clientDataHash) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 2),
            Cbor.encodeInt(1), Cbor.encodeText(rpId),
            Cbor.encodeInt(2), Cbor.encodeBytes(clientDataHash));
    }

    /** {1: rpId, 2: clientDataHash, 3: allowList} */
    public static byte[] getAssertionWithAllowList(String rpId, byte[] clientDataHash,
                                                   byte[]... credentialIds) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 3),
            Cbor.encodeInt(1), Cbor.encodeText(rpId),
            Cbor.encodeInt(2), Cbor.encodeBytes(clientDataHash),
            Cbor.encodeInt(3), credentialList(credentialIds));
    }

    /** An array of PublicKeyCredentialDescriptor, used by both allow and exclude lists. */
    private static byte[] credentialList(byte[]... credentialIds) {
        byte[] list = Cbor.header(Cbor.ARRAY, credentialIds.length);
        for (byte[] id : credentialIds) {
            list = Cbor.concat(list,
                Cbor.header(Cbor.MAP, 2),
                Cbor.encodeText("id"), Cbor.encodeBytes(id),
                Cbor.encodeText("type"), Cbor.encodeText("public-key"));
        }
        return list;
    }

    /** Canonical text-key order is by length, so "id" comes before "name". */
    private static byte[] rp(String rpId) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 2),
            Cbor.encodeText("id"), Cbor.encodeText(rpId),
            Cbor.encodeText("name"), Cbor.encodeText("Example RP"));
    }

    private static byte[] user() {
        return user(new byte[]{1, 2, 3, 4});
    }

    private static byte[] user(byte[] userId) {
        return Cbor.concat(
            Cbor.header(Cbor.MAP, 3),
            Cbor.encodeText("id"), Cbor.encodeBytes(userId),
            Cbor.encodeText("name"), Cbor.encodeText("alice"),
            Cbor.encodeText("displayName"), Cbor.encodeText("Alice"));
    }

    private static byte[] pubKeyCredParams(int... algs) {
        byte[] out = Cbor.header(Cbor.ARRAY, algs.length);
        for (int alg : algs) {
            out = Cbor.concat(out,
                Cbor.header(Cbor.MAP, 2),
                Cbor.encodeText("alg"), Cbor.encodeInt(alg),
                Cbor.encodeText("type"), Cbor.encodeText("public-key"));
        }
        return out;
    }
}
