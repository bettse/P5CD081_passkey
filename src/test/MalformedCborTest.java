package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The decoder reads a buffer the host filled in, so it is the part of the card
 * most exposed to a hostile peer. These are the shapes that used to get through.
 */
public class MalformedCborTest extends BaseTest {

    private static final byte CTAP2_OK = 0x00;
    private static final byte CTAP2_ERR_INVALID_CBOR = 0x12;
    private static final byte CTAP1_ERR_INVALID_PARAMETER = 0x02;
    private static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14;

    private static final String RP_ID = "example.com";

    /** A well-formed registration, truncated after `keep` bytes. */
    private byte[] truncatedRegistration(int keep) {
        byte[] full = CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256);
        return Arrays.copyOfRange(full, 0, keep);
    }

    @Test
    @DisplayName("a request truncated anywhere is an error, never a crash")
    public void truncationIsAlwaysHandled() {
        byte[] full = CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256);

        // Every prefix. The card must answer a CTAP status for each, and must not
        // register anything off the back of a half a request.
        for (int keep = 1; keep < full.length; keep++) {
            CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, truncatedRegistration(keep));
            assertNotEquals(CTAP2_OK, r.status,
                "a truncated request must not succeed, cut at " + keep);
        }
        assertEquals(0, send(INS_GET_INFO, null)[4], "nothing was registered");
    }

    @Test
    @DisplayName("a byte string claiming more than the request holds is rejected")
    public void lyingLengthIsRejected() {
        // user.id says 64 bytes and then the request stops. Before the reader was
        // bounded, those 64 bytes came from whatever the previous request left in
        // the assembly buffer, and came back out later inside an assertion.
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeBytes(hash(9)),
            Cbor.encodeInt(2), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("id"), Cbor.encodeText(RP_ID)),
            Cbor.encodeInt(3), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("id"), Cbor.header(Cbor.BSTR, 64)),   // header, no payload
            Cbor.encodeInt(4), Cbor.concat(
                Cbor.header(Cbor.ARRAY, 1),
                Cbor.header(Cbor.MAP, 2),
                Cbor.encodeText("alg"), Cbor.encodeInt(-7),
                Cbor.encodeText("type"), Cbor.encodeText("public-key")),
            Cbor.encodeInt(7), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("rk"), new byte[]{(byte) 0xF5}));

        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, request);
        assertNotEquals(CTAP2_OK, r.status, "must not register on a lying length");
        assertEquals(0, send(INS_GET_INFO, null)[4]);
    }

    @Test
    @DisplayName("stale buffer contents cannot leak into a credential")
    public void noStaleBufferLeak() {
        // Fill the assembly buffer with a recognisable pattern, then send a
        // request whose user.id header over-claims. Nothing of the first request
        // may survive into a credential.
        byte[] marker = new byte[200];
        Arrays.fill(marker, (byte) 0xA5);
        ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            Cbor.concat(Cbor.header(Cbor.MAP, 1), Cbor.encodeInt(99), Cbor.encodeBytes(marker)));

        lyingLengthIsRejected();
    }

    @Test
    @DisplayName("a 16-bit length of 0x8000 or more is rejected, not read as negative")
    public void oversizedLengthIsRejected() {
        // 0x59 0x80 0x00 is a byte string of 32768. Read into a signed short that
        // is -32768, which slips straight past a "> MAX_USER_ID" check.
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeBytes(hash(9)),
            Cbor.encodeInt(2), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("id"), Cbor.encodeText(RP_ID)),
            Cbor.encodeInt(3), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("id"), new byte[]{(byte) 0x59, (byte) 0x80, (byte) 0x00}),
            Cbor.encodeInt(4), Cbor.concat(
                Cbor.header(Cbor.ARRAY, 1),
                Cbor.header(Cbor.MAP, 2),
                Cbor.encodeText("alg"), Cbor.encodeInt(-7),
                Cbor.encodeText("type"), Cbor.encodeText("public-key")),
            Cbor.encodeInt(7), Cbor.concat(
                Cbor.header(Cbor.MAP, 1),
                Cbor.encodeText("rk"), new byte[]{(byte) 0xF5}));

        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, request);
        assertTrue(r.status == CTAP2_ERR_INVALID_CBOR || r.status == CTAP1_ERR_INVALID_PARAMETER,
            "expected a length rejection, got 0x" + Integer.toHexString(r.status & 0xFF));
        assertEquals(0, send(INS_GET_INFO, null)[4]);
    }

    @Test
    @DisplayName("deeply nested CBOR is refused instead of exhausting the stack")
    public void deepNestingIsBounded() {
        // A map, then a few hundred nested one-element arrays. Skipping this
        // recursed once per level until the JCVM stack gave out.
        byte[] nest = new byte[400];
        Arrays.fill(nest, (byte) 0x81);
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 1),
            Cbor.encodeInt(1), nest, Cbor.encodeInt(0));

        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, request);
        assertNotEquals(CTAP2_OK, r.status);
    }

    @Test
    @DisplayName("indefinite-length CBOR is a protocol error, not a transport failure")
    public void indefiniteLengthIsACtapError() {
        // 0xBF is an indefinite-length map. CTAP2 canonical CBOR bans it, but a
        // generic encoder may still emit it, and the answer should be a CTAP
        // status rather than an APDU-level failure that looks like a dead card.
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, new byte[]{(byte) 0xBF});
        assertEquals(CTAP2_ERR_INVALID_CBOR, r.status);
    }

    @Test
    @DisplayName("an empty request body is an error, and the card stays usable")
    public void emptyBody() {
        assertEquals(CTAP2_ERR_INVALID_CBOR,
            ctap(CtapRequests.CMD_MAKE_CREDENTIAL, new byte[0]).status);

        // Still alive afterwards.
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_GET_INFO, null).status);
    }

    @Test
    @DisplayName("garbage where a map belongs is reported, not swallowed")
    public void wrongTopLevelType() {
        for (byte b : new byte[]{0x00, 0x20, 0x40, 0x60, (byte) 0x80, (byte) 0xF6}) {
            CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, new byte[]{b});
            assertNotEquals(CTAP2_OK, r.status, "major type 0x" + Integer.toHexString(b & 0xFF));
        }
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_GET_INFO, null).status, "still alive");
    }

    @Test
    @DisplayName("a truncated getAssertion cannot produce a signature")
    public void truncatedAssertion() {
        ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));

        byte[] full = CtapRequests.getAssertion(RP_ID, hash(11));
        for (int keep = 1; keep < full.length; keep++) {
            CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION, Arrays.copyOfRange(full, 0, keep));
            assertNotEquals(CTAP2_OK, r.status, "cut at " + keep);
        }

        // And the real thing still works afterwards.
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, hash(11))).status);
    }

    @Test
    @DisplayName("a clientPIN request with a truncated key agreement is refused")
    public void truncatedClientPin() {
        // setPIN, not getKeyAgreement: getKeyAgreement never reads the platform
        // key, so a malformed one there would prove nothing. The keyAgreement
        // entry comes last so the truncation is genuinely at the end of the
        // request, and its x coordinate claims 32 bytes it does not have.
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeInt(1),
            Cbor.encodeInt(2), Cbor.encodeInt(ClientPin.SUB_SET_PIN),
            Cbor.encodeInt(4), Cbor.encodeBytes(new byte[16]),
            Cbor.encodeInt(5), Cbor.encodeBytes(new byte[64]),
            Cbor.encodeInt(3), Cbor.concat(
                Cbor.header(Cbor.MAP, 5),
                Cbor.encodeInt(1), Cbor.encodeInt(2),
                Cbor.encodeInt(3), Cbor.encodeInt(-25),
                Cbor.encodeInt(-1), Cbor.encodeInt(1),
                Cbor.encodeInt(-3), Cbor.encodeBytes(new byte[32]),
                Cbor.encodeInt(-2), Cbor.header(Cbor.BSTR, 32)));   // header, no payload

        assertNotEquals(CTAP2_OK, ctap(CtapRequests.CMD_CLIENT_PIN, request).status);
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_GET_INFO, null).status, "still alive");
    }

    @Test
    @DisplayName("a missing parameter is still distinguished from malformed input")
    public void missingIsNotMalformed() {
        // Well-formed CBOR, just short of what makeCredential needs. This has to
        // stay a different answer from garbage, or a host cannot tell why it failed.
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 1),
            Cbor.encodeInt(1), Cbor.encodeBytes(hash(9)));
        assertEquals(CTAP2_ERR_MISSING_PARAMETER,
            ctap(CtapRequests.CMD_MAKE_CREDENTIAL, request).status);
    }
}
