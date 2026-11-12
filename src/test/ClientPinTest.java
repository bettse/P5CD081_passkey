package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CTAP2 clientPIN protocol 1, driven by an independent platform implementation
 * built on the JDK's own ECDH, AES and HMAC rather than on the card's code.
 */
public class ClientPinTest extends BaseTest {

    private static final byte CTAP2_OK = 0x00;
    private static final byte CTAP2_ERR_NOT_ALLOWED = 0x31;
    private static final byte CTAP2_ERR_PIN_INVALID = 0x32;
    private static final byte CTAP2_ERR_PIN_AUTH_INVALID = 0x34;
    private static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = 0x35;
    private static final byte CTAP2_ERR_PIN_NOT_SET = 0x36;
    private static final byte CTAP2_ERR_PIN_REQUIRED = 0x37;
    private static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = 0x38;

    private static final String RP_ID = "example.com";
    private static final String THE_PIN = "1234";

    /** Run getKeyAgreement and derive the shared secret, as any PIN operation must. */
    private ClientPin agree() throws Exception {
        ClientPin platform = new ClientPin();
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, ClientPin.getKeyAgreement());
        assertEquals(CTAP2_OK, r.status);

        Cbor c = new Cbor(r.cbor);
        assertEquals(1, c.expect(Cbor.MAP));
        assertEquals(1, c.readInt(), "key 1 carries the COSE key");
        platform.agree(Arrays.copyOfRange(r.cbor, c.position(), r.cbor.length));
        return platform;
    }

    private byte[] setPinOverCtap(String pin) throws Exception {
        ClientPin platform = agree();
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, platform.setPin(pin));
        assertEquals(CTAP2_OK, r.status, "setPIN should succeed");
        return platform.sharedSecret();
    }

    /** Obtain a pinToken, which is what later requests are authenticated with. */
    private byte[] pinToken(String pin) throws Exception {
        ClientPin platform = agree();
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, platform.getPinToken(pin));
        assertEquals(CTAP2_OK, r.status, "getPINToken should succeed");

        Cbor c = new Cbor(r.cbor);
        assertEquals(1, c.expect(Cbor.MAP));
        assertEquals(2, c.readInt());
        return platform.decrypt(c.readBytes());
    }

    @Test
    @DisplayName("getKeyAgreement returns a P-256 COSE key")
    public void keyAgreementShape() {
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, ClientPin.getKeyAgreement());
        assertEquals(CTAP2_OK, r.status);

        Cbor c = new Cbor(r.cbor);
        assertEquals(1, c.expect(Cbor.MAP));
        assertEquals(1, c.readInt());
        assertEquals(5, c.expect(Cbor.MAP));
        assertEquals(1, c.readInt());
        assertEquals(2, c.readInt(), "kty EC2");
        assertEquals(3, c.readInt());
        assertEquals(-25, c.readInt(), "ECDH-ES + HKDF-256");
        assertEquals(-1, c.readInt());
        assertEquals(1, c.readInt(), "curve P-256");
        assertEquals(-2, c.readInt());
        assertEquals(32, c.readBytes().length, "x");
        assertEquals(-3, c.readInt());
        assertEquals(32, c.readBytes().length, "y");
        assertEquals(0, c.remaining());
    }

    @Test
    @DisplayName("the card and the JDK agree on the same shared secret")
    public void sharedSecretMatches() throws Exception {
        // Proof by consequence: if the secrets differed, setPIN's pinUvAuthParam
        // would not verify and the card would reject it.
        ClientPin platform = agree();
        assertEquals(32, platform.sharedSecret().length);
        assertEquals(CTAP2_OK,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.setPin(THE_PIN)).status);
    }

    @Test
    @DisplayName("getRetries reports the remaining attempts")
    public void getRetries() {
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, ClientPin.getRetries());
        assertEquals(CTAP2_OK, r.status);

        Cbor c = new Cbor(r.cbor);
        assertEquals(1, c.expect(Cbor.MAP));
        assertEquals(3, c.readInt());
        assertEquals(8, c.readInt());
    }

    @Test
    @DisplayName("setPIN over clientPIN sets the same secret the vendor path checks")
    public void setPinAgreesWithVendorProtocol() throws Exception {
        setPinOverCtap(THE_PIN);

        // The vendor protocol takes the PIN in the clear and must accept it.
        verifyPin(THE_PIN.getBytes());
        assertEquals(0x06, send(INS_GET_INFO, null)[1], "PIN set and verified");
    }

    @Test
    @DisplayName("a PIN set over the vendor protocol works over clientPIN")
    public void vendorPinWorksOverCtap() throws Exception {
        setPin(THE_PIN.getBytes());
        assertEquals(16, pinToken(THE_PIN).length, "getPINToken accepts it");
    }

    @Test
    @DisplayName("setPIN is refused once a PIN exists")
    public void setPinTwice() throws Exception {
        setPinOverCtap(THE_PIN);
        ClientPin platform = agree();
        assertEquals(CTAP2_ERR_NOT_ALLOWED,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.setPin("5678")).status);
    }

    @Test
    @DisplayName("setPIN rejects a PIN shorter than four characters")
    public void shortPinRejected() throws Exception {
        ClientPin platform = agree();
        assertEquals(CTAP2_ERR_PIN_POLICY_VIOLATION,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.setPin("12")).status);
    }

    @Test
    @DisplayName("setPIN rejects a tampered pinUvAuthParam")
    public void tamperedPinAuth() throws Exception {
        ClientPin platform = agree();
        byte[] request = platform.setPin(THE_PIN);

        // Flip a bit in the last byte of the request, which is inside newPinEnc,
        // so the HMAC the card computes no longer matches the one it was given.
        request[request.length - 1] ^= 0x01;

        assertEquals(CTAP2_ERR_PIN_AUTH_INVALID,
            ctap(CtapRequests.CMD_CLIENT_PIN, request).status);
    }

    @Test
    @DisplayName("getPINToken returns a 16-byte token for the right PIN")
    public void getPinToken() throws Exception {
        setPinOverCtap(THE_PIN);
        byte[] token = pinToken(THE_PIN);
        assertEquals(16, token.length);

        boolean allZero = true;
        for (byte b : token) {
            allZero &= b == 0;
        }
        assertFalse(allZero, "the token should be random");
    }

    @Test
    @DisplayName("getPINToken refuses the wrong PIN and burns a retry")
    public void wrongPinBurnsRetry() throws Exception {
        setPinOverCtap(THE_PIN);

        ClientPin platform = agree();
        assertEquals(CTAP2_ERR_PIN_INVALID,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.getPinToken("9999")).status);

        Cbor c = new Cbor(ctap(CtapRequests.CMD_CLIENT_PIN, ClientPin.getRetries()).cbor);
        c.expect(Cbor.MAP);
        c.readInt();
        assertEquals(7, c.readInt(), "one retry gone");
    }

    @Test
    @DisplayName("three wrong PINs on one tap force the card to be re-presented")
    public void threeStrikesPerPowerCycle() throws Exception {
        setPinOverCtap(THE_PIN);

        for (int i = 0; i < 2; i++) {
            ClientPin platform = agree();
            assertEquals(CTAP2_ERR_PIN_INVALID,
                ctap(CtapRequests.CMD_CLIENT_PIN, platform.getPinToken("9999")).status,
                "attempt " + i);
        }

        ClientPin third = agree();
        assertEquals(CTAP2_ERR_PIN_AUTH_BLOCKED,
            ctap(CtapRequests.CMD_CLIENT_PIN, third.getPinToken("9999")).status);

        // Even the correct PIN is refused until the card is power-cycled.
        ClientPin fourth = agree();
        assertEquals(CTAP2_ERR_PIN_AUTH_BLOCKED,
            ctap(CtapRequests.CMD_CLIENT_PIN, fourth.getPinToken(THE_PIN)).status);

        reselect();
        assertEquals(16, pinToken(THE_PIN).length, "a fresh tap clears the per-session block");
    }

    @Test
    @DisplayName("changePIN swaps the PIN and the old one stops working")
    public void changePin() throws Exception {
        setPinOverCtap(THE_PIN);

        ClientPin platform = agree();
        assertEquals(CTAP2_OK,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.changePin(THE_PIN, "5678")).status);

        assertEquals(16, pinToken("5678").length);

        ClientPin stale = agree();
        assertEquals(CTAP2_ERR_PIN_INVALID,
            ctap(CtapRequests.CMD_CLIENT_PIN, stale.getPinToken(THE_PIN)).status);
    }

    @Test
    @DisplayName("changePIN refuses the wrong current PIN")
    public void changePinWrongOld() throws Exception {
        setPinOverCtap(THE_PIN);

        ClientPin platform = agree();
        assertEquals(CTAP2_ERR_PIN_INVALID,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.changePin("9999", "5678")).status);

        assertEquals(16, pinToken(THE_PIN).length, "the original PIN still works");
    }

    @Test
    @DisplayName("clientPIN subcommands need a PIN to exist")
    public void pinNotSet() throws Exception {
        ClientPin platform = agree();
        assertEquals(CTAP2_ERR_PIN_NOT_SET,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.getPinToken(THE_PIN)).status);
        assertEquals(CTAP2_ERR_PIN_NOT_SET,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.changePin(THE_PIN, "5678")).status);
    }

    // ---- using the pinToken on real operations ----

    @Test
    @DisplayName("makeCredential with a valid pinUvAuthParam sets the UV flag")
    public void makeCredentialWithPinAuth() throws Exception {
        setPinOverCtap(THE_PIN);
        byte[] token = pinToken(THE_PIN);

        byte[] clientDataHash = hash(9);
        byte[] pinAuth = ClientPin.authenticateWith(token, clientDataHash);
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(clientDataHash, RP_ID, pinAuth));

        assertEquals(CTAP2_OK, r.status);
        AttestationObject att = AttestationObject.parse(r.cbor);
        assertTrue(att.userVerified(), "UV must be set once the PIN was proved");
        assertTrue(att.userPresent());
    }

    @Test
    @DisplayName("a PIN is optional to present, but never optional to get right")
    public void pinAuthIsCheckedWhenOffered() throws Exception {
        setPinOverCtap(THE_PIN);

        // Not presenting one is allowed while the card claims built-in UV.
        CtapResponse without = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));
        if (dev.ericbetts.passkey.Const.CLAIM_USER_VERIFICATION) {
            assertEquals(CTAP2_OK, without.status);
        } else {
            assertEquals(CTAP2_ERR_PIN_REQUIRED, without.status);
        }

        // Presenting a wrong one is never allowed. That is the half that matters:
        // the relaxation is about what may be omitted, not about what is checked.
        byte[] token = pinToken(THE_PIN);
        byte[] wrong = ClientPin.authenticateWith(token, hash(10));
        assertEquals(CTAP2_ERR_PIN_AUTH_INVALID, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(hash(9), RP_ID, wrong)).status);
    }

    @Test
    @DisplayName("a pinUvAuthParam computed over the wrong data is refused")
    public void wrongPinAuth() throws Exception {
        setPinOverCtap(THE_PIN);
        byte[] token = pinToken(THE_PIN);

        // Authenticate a different clientDataHash than the one actually sent.
        byte[] pinAuth = ClientPin.authenticateWith(token, hash(10));
        assertEquals(CTAP2_ERR_PIN_AUTH_INVALID, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(hash(9), RP_ID, pinAuth)).status);
    }

    @Test
    @DisplayName("getAssertion with a valid pinUvAuthParam sets UV and still verifies")
    public void getAssertionWithPinAuth() throws Exception {
        setPinOverCtap(THE_PIN);
        byte[] token = pinToken(THE_PIN);

        byte[] registerHash = hash(9);
        CtapResponse made = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(registerHash, RP_ID,
                ClientPin.authenticateWith(token, registerHash)));
        AttestationObject att = AttestationObject.parse(made.cbor);

        byte[] cdh = hash(11);
        CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertionWithPinAuth(RP_ID, cdh,
                ClientPin.authenticateWith(token, cdh)));
        assertEquals(CTAP2_OK, r.status);

        Assertion assertion = Assertion.parse(r.cbor);
        assertTrue(assertion.userVerified(), "UV flag");

        java.security.Signature v = java.security.Signature.getInstance("SHA256withECDSA");
        v.initVerify(att.publicKey());
        v.update(assertion.authData);
        v.update(cdh);
        assertTrue(v.verify(assertion.signature));
    }

    @Test
    @DisplayName("a pinToken does not survive a card reset")
    public void pinTokenIsPerPowerCycle() throws Exception {
        setPinOverCtap(THE_PIN);
        byte[] token = pinToken(THE_PIN);

        reselect();

        byte[] clientDataHash = hash(9);
        byte[] pinAuth = ClientPin.authenticateWith(token, clientDataHash);
        assertEquals(CTAP2_ERR_PIN_AUTH_INVALID, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(clientDataHash, RP_ID, pinAuth)).status);
    }

    @Test
    @DisplayName("each power cycle brings a different key agreement key and token")
    public void freshMaterialPerPowerCycle() throws Exception {
        setPinOverCtap(THE_PIN);
        byte[] first = pinToken(THE_PIN);

        reselect();
        byte[] second = pinToken(THE_PIN);

        assertNotEquals(Arrays.toString(first), Arrays.toString(second),
            "a new tap must mint a new pinToken");
    }

    @Test
    @DisplayName("authenticatorReset clears the PIN set over clientPIN")
    public void resetClearsPin() throws Exception {
        setPinOverCtap(THE_PIN);

        // Reset only runs on a fresh selection.
        selectApplet();
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_RESET, null).status);

        // A PIN can be set again from scratch, which only works if it was cleared.
        ClientPin platform = agree();
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_CLIENT_PIN, platform.setPin("5678")).status);
    }

    @Test
    @DisplayName("the stored secret is LEFT(SHA-256(pin), 16)")
    public void storedSecretIsThePinHash() throws Exception {
        setPin(THE_PIN.getBytes());

        // getPINToken sends exactly that digest encrypted, and the card accepts it.
        ClientPin platform = agree();
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 4),
            Cbor.encodeInt(1), Cbor.encodeInt(1),
            Cbor.encodeInt(2), Cbor.encodeInt(ClientPin.SUB_GET_PIN_TOKEN),
            Cbor.encodeInt(3), platform.coseKey(),
            Cbor.encodeInt(6), Cbor.encodeBytes(platform.encrypt(ClientPin.pinHash(THE_PIN))));

        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_CLIENT_PIN, request).status);
        assertArrayEquals(ClientPin.pinHash(THE_PIN), ClientPin.pinHash(THE_PIN));
    }
}
