package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CTAP2 as a platform speaks it: CBOR in, CBOR out, over the NFC binding.
 *
 * These tests use a card with no PIN set, which is the only state where CTAP2
 * operations are permitted until clientPIN lands.
 */
public class Ctap2Test extends BaseTest {

    private static final byte CTAP2_OK = 0x00;
    private static final byte CTAP1_ERR_INVALID_COMMAND = 0x01;
    private static final byte CTAP2_ERR_MISSING_PARAMETER = 0x14;
    private static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26;
    private static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2F;
    private static final byte CTAP2_ERR_NOT_ALLOWED = 0x31;
    private static final byte CTAP2_ERR_PIN_REQUIRED = 0x37;

    private static final String RP_ID = "example.com";

    @Test
    @DisplayName("SELECT answers FIDO_2_0 so a platform knows what it found")
    public void selectAnswersVersion() {
        byte[] response = session.transmitCommand(
            com.licel.jcardsim.utils.AIDUtil.select(
                com.licel.jcardsim.utils.AIDUtil.create(APPLET_AID)));

        assertEquals(SW_OK, sw(response));
        byte[] body = Arrays.copyOfRange(response, 0, response.length - 2);
        String version = new String(body, StandardCharsets.UTF_8);

        // The NFC binding wants "U2F_V2" from an authenticator that speaks CTAP1
        // and "FIDO_2_0" from one that does not. See Const.ANSWER_SELECT_AS_U2F
        // for why this card may say the former while only doing the latter.
        assertEquals(dev.ericbetts.passkey.Const.ANSWER_SELECT_AS_U2F ? "U2F_V2" : "FIDO_2_0",
            version);

        // Whatever SELECT says, getInfo tells the truth about what is supported.
        assertEquals(1, ctapInfo().versions.size());
        assertEquals("FIDO_2_0", ctapInfo().versions.get(0));
    }

    @Test
    @DisplayName("getInfo advertises FIDO_2_0 and ES256")
    public void getInfo() {
        CtapInfo info = ctapInfo();

        assertEquals(1, info.versions.size());
        assertEquals("FIDO_2_0", info.versions.get(0));
        assertEquals(16, info.aaguid.length, "aaguid");
        assertEquals(1024, info.maxMsgSize, "the CTAP2.1 minimum");
        assertEquals(1, info.algorithms.size());
        assertEquals(-7L, info.algorithms.get(0), "ES256 and nothing else");

        assertEquals(1, info.transports.size());
        assertEquals("nfc", info.transports.get(0), "a contactless card, and nothing else");
        assertEquals(1, info.maxCredentialCountInList, "one slot, so one entry is all it can use");
        assertEquals(16, info.maxCredentialIdLength);

        assertTrue(info.isTrue("rk"), "discoverable credentials are supported");
        assertTrue(info.isTrue("up"), "presenting the card is the gesture");
        assertTrue(info.has("plat"));
        assertFalse(info.isTrue("plat"), "a card is not a platform authenticator");
    }

    @Test
    @DisplayName("uv is claimed as true, never sent as false")
    public void uvIsTrueOrAbsent() {
        CtapInfo info = ctapInfo();

        // "uv": false would claim a built-in verification method that is merely
        // not enrolled, and invite the platform to walk the user through
        // enrolling one it does not have. Only true or absent are honest here.
        if (info.has("uv")) {
            assertTrue(info.isTrue("uv"), "uv must be true, never false");
        }
    }

    @Test
    @DisplayName("possession counts as verification, so registrations carry UV")
    public void possessionIsVerification() {
        // The card has no sensor and no keypad. Const.CLAIM_USER_VERIFICATION
        // says that holding it to a reader is the verification, which is the
        // whole authentication story for a card kept in a safe.
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        assertEquals(CTAP2_OK, r.status);

        AttestationObject att = AttestationObject.parse(r.cbor);
        assertTrue(att.userPresent());
        assertEquals(ctapInfo().isTrue("uv"), att.userVerified(),
            "the UV flag has to match what getInfo advertises");
    }

    @Test
    @DisplayName("clientPin is advertised only when the protocol can actually run")
    public void clientPinMatchesCapability() {
        CtapInfo fresh = ctapInfo();

        // "clientPin": false means "I take PINs, none is set yet, please set one".
        // Saying that on a card that cannot run clientPIN strands the platform at
        // a PIN prompt the card can never satisfy. The two must agree.
        assertEquals(fresh.has("clientPin"), !fresh.pinProtocols.isEmpty(),
            "clientPin and pinUvAuthProtocols have to tell the same story");

        if (fresh.has("clientPin")) {
            assertFalse(fresh.isTrue("clientPin"), "no PIN set on a fresh card");
            setPin(PIN);
            assertTrue(ctapInfo().isTrue("clientPin"), "and true once one is");
        } else {
            setPin(PIN);
            assertFalse(ctapInfo().has("clientPin"),
                "a PIN it cannot verify over CTAP2 is still not advertised");
        }
    }

    @Test
    @DisplayName("makeCredential registers and returns an attestation object")
    public void makeCredential() throws Exception {
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        assertEquals(CTAP2_OK, r.status);

        AttestationObject att = AttestationObject.parse(r.cbor);
        assertEquals("packed", att.fmt);
        assertTrue(att.hasAttestedCredentialData());
        assertArrayEquals(sha256(RP_ID), att.rpIdHash, "the card hashes rp.id itself");
        assertEquals(-7, att.coseKey.alg);

        assertTrue(att.userPresent());

        // Self attestation over authData || clientDataHash, verified with the key
        // the same response just published.
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(att.publicKey());
        v.update(att.authData);
        v.update(hash(9));
        assertTrue(v.verify(att.attStmtSig), "self attestation must verify");
    }

    @Test
    @DisplayName("makeCredential refuses a request that only offers RS256")
    public void unsupportedAlgorithm() {
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_RS256));
        assertEquals(CTAP2_ERR_UNSUPPORTED_ALGORITHM, r.status);
    }

    @Test
    @DisplayName("makeCredential accepts a list that includes ES256 among others")
    public void algorithmPreferenceList() {
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID,
                CtapRequests.ALG_RS256, CtapRequests.ALG_ES256));
        assertEquals(CTAP2_OK, r.status);
    }

    @Test
    @DisplayName("makeCredential rejects a request missing rp")
    public void missingParameter() {
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 1),
            Cbor.encodeInt(1), Cbor.encodeBytes(hash(9)));
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, request);
        assertEquals(CTAP2_ERR_MISSING_PARAMETER, r.status);
    }

    @Test
    @DisplayName("makeCredential accepts a discoverable credential")
    public void residentKeySupported() {
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithOptions(hash(9), RP_ID, "rk", true));
        assertEquals(CTAP2_OK, r.status);
    }

    @Test
    @DisplayName("getAssertion signs, and the registered key verifies it")
    public void getAssertion() throws Exception {
        CtapResponse made = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        AttestationObject att = AttestationObject.parse(made.cbor);

        byte[] cdh = hash(11);
        CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, cdh));
        assertEquals(CTAP2_OK, r.status);

        Assertion assertion = Assertion.parse(r.cbor);
        assertArrayEquals(att.credentialId, assertion.credentialId);
        assertEquals("public-key", assertion.credentialType);
        assertEquals(37, assertion.authData.length);
        assertArrayEquals(sha256(RP_ID), Arrays.copyOfRange(assertion.authData, 0, 32));
        assertEquals(1, assertion.signCount());

        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(att.publicKey());
        v.update(assertion.authData);
        v.update(cdh);
        assertTrue(v.verify(assertion.signature), "CTAP2 assertion must verify as ES256");
    }

    @Test
    @DisplayName("getAssertion for an unknown relying party finds no credential")
    public void wrongRelyingParty() {
        ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));

        CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion("other.example", hash(11)));
        assertEquals(CTAP2_ERR_NO_CREDENTIALS, r.status);
    }

    @Test
    @DisplayName("getAssertion on an empty card finds no credential")
    public void noCredential() {
        CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, hash(11)));
        assertEquals(CTAP2_ERR_NO_CREDENTIALS, r.status);
    }

    @Test
    @DisplayName("an allowList naming our credential is honoured, another is not")
    public void allowListFiltering() {
        CtapResponse made = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        byte[] credId = AttestationObject.parse(made.cbor).credentialId;

        CtapResponse ours = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertionWithAllowList(RP_ID, hash(11), credId));
        assertEquals(CTAP2_OK, ours.status);

        byte[] someoneElse = new byte[16];
        Arrays.fill(someoneElse, (byte) 0x5A);
        CtapResponse theirs = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertionWithAllowList(RP_ID, hash(11), someoneElse));
        assertEquals(CTAP2_ERR_NO_CREDENTIALS, theirs.status);
    }

    @Test
    @DisplayName("the signature counter advances across CTAP2 assertions")
    public void counterAdvances() {
        ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));

        long first = Assertion.parse(ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, hash(11))).cbor).signCount();
        long second = Assertion.parse(ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, hash(12))).cbor).signCount();

        assertEquals(first + 1, second);
    }

    @Test
    @DisplayName("reset wipes the credential and the PIN")
    public void reset() {
        setPin(PIN);

        // Reset is only accepted as the first command after selection, so a test
        // that has already talked to the card has to present it again.
        selectApplet();
        CtapResponse r = ctap(CtapRequests.CMD_RESET, null);
        assertEquals(CTAP2_OK, r.status);
        assertEquals(0, r.cbor.length, "reset returns a bare status byte");

        // The PIN is gone, so CTAP2 works again and the vendor side reports no PIN.
        byte[] info = send(INS_GET_INFO, null);
        assertEquals(0x00, info[1], "no credential, no PIN");

        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256)).status);
    }

    @Test
    @DisplayName("a card claiming built-in UV does not also demand a PIN")
    public void claimedUvDoesNotAlsoDemandAPin() {
        setPin(PIN);
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));

        if (dev.ericbetts.passkey.Const.CLAIM_USER_VERIFICATION) {
            // Advertising uv:true and then demanding a pinUvAuthParam makes the
            // two claims contradict each other, and a platform that believes the
            // first fails on the second. Possession is the verification here.
            assertEquals(CTAP2_OK, r.status);
            assertTrue(AttestationObject.parse(r.cbor).userVerified());
        } else {
            assertEquals(CTAP2_ERR_PIN_REQUIRED, r.status);
        }
    }

    @Test
    @DisplayName("reset is refused once anything else has been sent")
    public void resetOnlyOnAFreshSelection() {
        ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));

        // Wiping the card must not be one unauthenticated APDU. The spec uses a
        // ten-second window from power-up; with no clock, "first command after
        // selection" is the equivalent, and it means someone tapped it on purpose.
        assertEquals(CTAP2_ERR_NOT_ALLOWED, ctap(CtapRequests.CMD_RESET, null).status);
        assertEquals(1, send(INS_GET_INFO, null)[4], "the credential survived");

        // Even getInfo counts as having said something.
        selectApplet();
        ctap(CtapRequests.CMD_GET_INFO, null);
        assertEquals(CTAP2_ERR_NOT_ALLOWED, ctap(CtapRequests.CMD_RESET, null).status);

        // Present it again and it works.
        selectApplet();
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_RESET, null).status);
        assertEquals(0, send(INS_GET_INFO, null)[4], "and now it is gone");
    }

    @Test
    @DisplayName("a vendor command also closes the reset window")
    public void vendorTrafficClosesResetWindow() {
        selectApplet();
        send(INS_GET_INFO, null);
        assertEquals(CTAP2_ERR_NOT_ALLOWED, ctap(CtapRequests.CMD_RESET, null).status);
    }

    @Test
    @DisplayName("unknown commands are refused, as is getNextAssertion out of turn")
    public void unsupportedCommands() {
        assertEquals(CTAP1_ERR_INVALID_COMMAND, ctap((byte) 0x7F, null).status);
        assertEquals(CTAP2_ERR_NOT_ALLOWED,
            ctap(CtapRequests.CMD_GET_NEXT_ASSERTION, null).status);
    }

    @Test
    @DisplayName("an extended-length APDU gets its whole response back in one piece")
    public void extendedLengthApdu() {
        // Apple's stack, which Safari and Firefox on macOS both use, frames every
        // CTAP2 message as an extended-length APDU and does not follow 61xx. A
        // card that only understands short APDUs never gets past getInfo there.
        byte[] info = session.transmitCommand(extended(new byte[]{CtapRequests.CMD_GET_INFO}));
        assertEquals(SW_OK, sw(info), "getInfo over an extended APDU");
        assertEquals(CTAP2_OK, info[0]);

        byte[] request = Cbor.concat(new byte[]{CtapRequests.CMD_MAKE_CREDENTIAL},
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        byte[] response = session.transmitCommand(extended(request));
        assertEquals(SW_OK, sw(response), "one response, no 61xx");
        assertEquals(CTAP2_OK, response[0]);
        AttestationObject att = AttestationObject.parse(
            java.util.Arrays.copyOfRange(response, 1, response.length - 2));
        assertEquals(-7, att.coseKey.alg);
    }

    @Test
    @DisplayName("every response fits a short APDU, so short-APDU hosts never chain")
    public void shortApduResponsesFit() {
        // libfido2 and most PC/SC hosts send short APDUs. With an ES256 key the
        // largest response, a registration, is under 255 bytes.
        byte[] request = Cbor.concat(new byte[]{CtapRequests.CMD_MAKE_CREDENTIAL},
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        byte[] apdu = new byte[6 + request.length];
        apdu[0] = CLA_CTAP;
        apdu[1] = INS_NFCCTAP_MSG;
        apdu[4] = (byte) request.length;
        System.arraycopy(request, 0, apdu, 5, request.length);
        assertEquals(SW_OK, sw(session.transmitCommand(apdu)));
    }

    /** 80 10 00 00 | 00 LcHi LcLo | data | 00 00, the framing WebKit uses. */
    private static byte[] extended(byte[] message) {
        byte[] apdu = new byte[7 + message.length + 2];
        apdu[0] = CLA_CTAP;
        apdu[1] = INS_NFCCTAP_MSG;
        apdu[5] = (byte) (message.length >> 8);
        apdu[6] = (byte) message.length;
        System.arraycopy(message, 0, apdu, 7, message.length);
        return apdu;
    }

    @Test
    @DisplayName("a request longer than one APDU is reassembled from chained blocks")
    public void chainedRequest() throws Exception {
        // A long rp id pushes the request past 255 bytes, forcing APDU chaining.
        StringBuilder sb = new StringBuilder();
        while (sb.length() < 200) {
            sb.append("chained-request-");
        }
        String longRpId = sb + ".example";

        byte[] request = CtapRequests.makeCredential(hash(9), longRpId, CtapRequests.ALG_ES256);
        assertTrue(request.length + 1 > 255, "the test needs a request that actually chains");

        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL, request);
        assertEquals(CTAP2_OK, r.status);
        assertArrayEquals(sha256(longRpId), AttestationObject.parse(r.cbor).rpIdHash);
    }

    private static byte[] sha256(String value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    }
}
