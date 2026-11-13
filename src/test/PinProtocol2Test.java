package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * clientPIN protocol 2, which differs from protocol 1 in three ways that all
 * have to line up at once: HKDF splits the shared secret into separate HMAC and
 * AES keys, ciphertext carries a random IV in front of it, and pinUvAuthParam is
 * the whole 32-byte HMAC rather than its left half.
 *
 * The platform side is the JDK's own HKDF, AES and HMAC, so agreement here means
 * the card matches the specification rather than matching itself.
 */
public class PinProtocol2Test extends BaseTest {

    private static final byte CTAP2_OK = 0x00;
    private static final byte CTAP2_ERR_PIN_INVALID = 0x31;
    private static final byte CTAP2_ERR_PIN_AUTH_INVALID = 0x33;
    private static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37;

    private static final String RP_ID = "example.com";
    private static final String THE_PIN = "1234";

    private ClientPin agree() throws Exception {
        ClientPin platform = new ClientPin(2);
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, ClientPin.getKeyAgreement(2));
        assertEquals(CTAP2_OK, r.status);

        Cbor c = new Cbor(r.cbor);
        assertEquals(1, c.expect(Cbor.MAP));
        assertEquals(1, c.readInt());
        platform.agree(Arrays.copyOfRange(r.cbor, c.position(), r.cbor.length));
        return platform;
    }

    private void setPin(String pin) throws Exception {
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_CLIENT_PIN, agree().setPin(pin)).status,
            "setPIN under protocol 2");
    }

    private byte[] pinToken(String pin) throws Exception {
        ClientPin platform = agree();
        CtapResponse r = ctap(CtapRequests.CMD_CLIENT_PIN, platform.getPinToken(pin));
        assertEquals(CTAP2_OK, r.status);

        Cbor c = new Cbor(r.cbor);
        assertEquals(1, c.expect(Cbor.MAP));
        assertEquals(2, c.readInt());
        return platform.decrypt(c.readBytes());
    }

    @Test
    @DisplayName("getInfo offers protocol 2 first, and does not promise a pinUvAuthToken")
    public void advertised() {
        CtapInfo info = ctapInfo();
        assertEquals(2, info.pinProtocols.size());
        assertEquals(2L, info.pinProtocols.get(0), "most preferred first");
        assertEquals(1L, info.pinProtocols.get(1));
        assertFalse(info.isTrue("pinUvAuthToken"),
            "that option promises clientPIN subcommand 0x09, which the card lacks");
    }

    @Test
    @DisplayName("the card derives the same HKDF keys the JDK does")
    public void keysAgree() throws Exception {
        // Proof by consequence: setPIN authenticates newPinEnc with the HMAC key
        // and encrypts it with the AES key. If either derivation differed, the
        // card would reject it.
        setPin(THE_PIN);
        verifyPin(THE_PIN.getBytes());
    }

    @Test
    @DisplayName("pinUvAuthParam is the full 32 bytes under protocol 2")
    public void fullLengthMac() throws Exception {
        ClientPin platform = agree();
        assertEquals(32, platform.authenticate(new byte[]{1, 2, 3}).length);

        // A protocol 1 length is the wrong shape and has to be refused.
        byte[] request = Cbor.concat(
            Cbor.header(Cbor.MAP, 5),
            Cbor.encodeInt(1), Cbor.encodeInt(2),
            Cbor.encodeInt(2), Cbor.encodeInt(ClientPin.SUB_SET_PIN),
            Cbor.encodeInt(3), platform.coseKey(),
            Cbor.encodeInt(4), Cbor.encodeBytes(new byte[16]),
            Cbor.encodeInt(5), Cbor.encodeBytes(platform.encryptPin(THE_PIN)));
        assertEquals(CTAP2_ERR_PIN_AUTH_INVALID,
            ctap(CtapRequests.CMD_CLIENT_PIN, request).status);
    }

    @Test
    @DisplayName("ciphertext carries a random IV, and it is used")
    public void randomIv() throws Exception {
        ClientPin platform = agree();
        byte[] first = platform.encryptPin(THE_PIN);
        byte[] second = platform.encryptPin(THE_PIN);

        assertEquals(80, first.length, "16 of IV plus 64 of padded PIN");
        assertNotEquals(Arrays.toString(Arrays.copyOfRange(first, 0, 16)),
            Arrays.toString(Arrays.copyOfRange(second, 0, 16)), "a fresh IV each time");
        assertNotEquals(Arrays.toString(first), Arrays.toString(second),
            "so the same PIN encrypts differently every time");

        // And the card decrypts it, which it can only do by using the IV sent.
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_CLIENT_PIN, platform.setPin(THE_PIN)).status);
    }

    @Test
    @DisplayName("getPINToken returns a token encrypted under protocol 2")
    public void getPinTokenWorks() throws Exception {
        setPin(THE_PIN);
        byte[] token = pinToken(THE_PIN);
        assertEquals(16, token.length);

        boolean allZero = true;
        for (byte b : token) {
            allZero &= b == 0;
        }
        assertFalse(allZero, "a real token, not a decryption failure");
    }

    @Test
    @DisplayName("a wrong PIN is still refused under protocol 2")
    public void wrongPin() throws Exception {
        setPin(THE_PIN);
        ClientPin platform = agree();
        assertEquals(CTAP2_ERR_PIN_INVALID,
            ctap(CtapRequests.CMD_CLIENT_PIN, platform.getPinToken("9999")).status);
    }

    @Test
    @DisplayName("a short PIN is still refused under protocol 2")
    public void shortPin() throws Exception {
        assertEquals(CTAP2_ERR_PIN_POLICY_VIOLATION,
            ctap(CtapRequests.CMD_CLIENT_PIN, agree().setPin("12")).status);
    }

    @Test
    @DisplayName("changePIN works under protocol 2")
    public void changePin() throws Exception {
        setPin(THE_PIN);
        assertEquals(CTAP2_OK,
            ctap(CtapRequests.CMD_CLIENT_PIN, agree().changePin(THE_PIN, "5678")).status);
        assertEquals(16, pinToken("5678").length);
    }

    @Test
    @DisplayName("a protocol 2 token authorises a registration and sets UV")
    public void tokenAuthorisesRegistration() throws Exception {
        setPin(THE_PIN);
        byte[] token = pinToken(THE_PIN);

        byte[] cdh = hash(9);
        byte[] pinAuth = ClientPin.authenticateWith(2, token, cdh);
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(cdh, RP_ID, pinAuth, 2));

        assertEquals(CTAP2_OK, r.status);
        assertTrue(AttestationObject.parse(r.cbor).userVerified());
    }

    @Test
    @DisplayName("a protocol 1 token cannot be replayed as a protocol 2 one")
    public void protocolsDoNotMix() throws Exception {
        setPin(THE_PIN);
        byte[] token = pinToken(THE_PIN);

        // Same token, same message, but truncated the way protocol 1 does it.
        byte[] cdh = hash(9);
        byte[] shortMac = ClientPin.authenticateWith(1, token, cdh);
        assertEquals(CTAP2_ERR_PIN_AUTH_INVALID, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithPinAuth(cdh, RP_ID, shortMac, 2)).status);
    }
}
