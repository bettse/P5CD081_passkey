package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasskeyTest extends BaseTest {

    @Test
    @DisplayName("fresh card reports no credential and no PIN")
    public void freshCardInfo() {
        byte[] info = send(INS_GET_INFO, null);

        assertEquals(5, info.length);
        assertEquals(0x01, info[0], "version");
        assertEquals(0x00, info[1], "flags: nothing set yet");
        assertEquals(8, info[2], "PIN retries");
        assertEquals(1, info[3], "slots");
        assertEquals(0, info[4], "slots used");
    }

    @Test
    @DisplayName("PIN can be set once, then only replaced after verifying")
    public void pinLifecycle() {
        setPin(PIN);
        assertSw(SW_PIN_ALREADY_SET, transmit(INS_SET_PIN, (byte) 0x00, (byte) 0x00, PIN));

        // Replacing needs the current PIN verified first.
        assertSw(SW_PIN_REQUIRED, transmit(INS_SET_PIN, (byte) 0x01, (byte) 0x00, "5678".getBytes()));
        verifyPin(PIN);
        assertSw(SW_OK, transmit(INS_SET_PIN, (byte) 0x01, (byte) 0x00, "5678".getBytes()));

        reselect();
        verifyPin("5678".getBytes());
    }

    @Test
    @DisplayName("wrong PIN burns a retry and reports the count")
    public void wrongPinDecrementsRetries() {
        setPin(PIN);

        assertSw(0x63C7, transmit(INS_VERIFY_PIN, (byte) 0x00, (byte) 0x00, "9999".getBytes()));
        assertSw(0x63C6, transmit(INS_VERIFY_PIN, (byte) 0x00, (byte) 0x00, "9999".getBytes()));

        // A correct PIN restores the counter.
        verifyPin(PIN);
        byte[] info = send(INS_GET_INFO, null);
        assertEquals(8, info[2]);
    }

    @Test
    @DisplayName("PIN verification does not survive a card reset")
    public void pinResetsOnCardReset() {
        unlock();
        assertTrue((send(INS_GET_INFO, null)[1] & 0x04) != 0, "verified flag set");

        reselect();
        assertEquals(0x02, send(INS_GET_INFO, null)[1], "PIN set, not verified");
    }

    @Test
    @DisplayName("PIN verification does not survive losing selection either")
    public void pinResetsOnDeselect() {
        unlock();
        assertTrue((send(INS_GET_INFO, null)[1] & 0x04) != 0, "verified flag set");

        // OwnerPIN's validated flag survives deselect unless the applet clears
        // it, so without deselect() this leaves the next caller an unlocked card.
        deselectAndReselect();
        assertEquals(0x02, send(INS_GET_INFO, null)[1], "PIN set, not verified");
    }

    @Test
    @DisplayName("a credential cannot be used through an inherited session")
    public void deselectRevokesAccess() {
        unlock();
        register(hash(1));
        deselectAndReselect();

        // Everything behind the PIN gate has to be shut again.
        assertSw(SW_PIN_REQUIRED, transmit(INS_GET_CREDENTIAL, (byte) 0, (byte) 0, null));
        assertSw(SW_PIN_REQUIRED,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, concat(hash(1), hash(9))));
        assertSw(SW_PIN_REQUIRED, transmit(INS_DELETE, (byte) 0, (byte) 0, null));
        assertSw(SW_PIN_REQUIRED, transmit(INS_SET_PIN, (byte) 0x01, (byte) 0, "5678".getBytes()));
    }

    @Test
    @DisplayName("credential operations refuse to run without a verified PIN")
    public void operationsRequirePin() {
        byte[] request = concat(hash(1), hash(REGISTER_CHALLENGE));
        assertSw(SW_PIN_REQUIRED, transmit(INS_MAKE_CREDENTIAL, (byte) 0, (byte) 0, request));

        setPin(PIN);
        assertSw(SW_PIN_REQUIRED, transmit(INS_MAKE_CREDENTIAL, (byte) 0, (byte) 0, request));

        verifyPin(PIN);
        register(hash(1));
    }

    @Test
    @DisplayName("make credential returns a P-256 key and a random credential id")
    public void makeCredential() {
        unlock();
        register(hash(1));
        CredentialRecord cred = readCredential();

        assertEquals(16, cred.credentialId.length);
        assertEquals(32, cred.x.length, "32-byte x coordinate");
        assertEquals(32, cred.y.length, "32-byte y coordinate");
        assertFalse(isAllZero(cred.credentialId), "credential id should be random");
        assertEquals(2, cred.kty, "COSE kty is EC2");
        assertEquals(-7, cred.alg, "COSE alg is ES256");

        byte[] info = send(INS_GET_INFO, null);
        assertEquals(0x07, info[1], "credential present, PIN set, PIN verified");
    }

    @Test
    @DisplayName("get credential returns the same key without regenerating it")
    public void getCredentialIsStable() {
        unlock();
        AttestationObject made = register(hash(1));
        CredentialRecord read = readCredential();

        assertArrayEquals(made.credentialId, read.credentialId);
        assertArrayEquals(made.coseKey.x, read.x);
    }

    @Test
    @DisplayName("the slot holds one credential; a second needs an explicit replace")
    public void singleSlot() {
        unlock();
        AttestationObject first = register(hash(1));

        assertSw(SW_CREDENTIAL_EXISTS, transmit(INS_MAKE_CREDENTIAL, (byte) 0, (byte) 0,
            concat(hash(2), hash(REGISTER_CHALLENGE))));

        AttestationObject second = replace(hash(2));
        assertFalse(java.util.Arrays.equals(first.coseKey.x, second.coseKey.x),
            "replace must generate a new key");

        // The old relying party no longer matches.
        assertSw(SW_RP_MISMATCH,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, concat(hash(1), hash(9))));
    }

    @Test
    @DisplayName("assertion requires a PIN, a credential, and the right relying party")
    public void assertionGuards() {
        // The PIN gate comes first: an unauthenticated caller learns nothing about
        // whether the card holds a credential.
        assertSw(SW_PIN_REQUIRED,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, concat(hash(1), hash(9))));

        unlock();
        assertSw(SW_NO_CREDENTIAL,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, concat(hash(1), hash(9))));

        register(hash(1));

        assertSw(SW_RP_MISMATCH,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, concat(hash(2), hash(9))));
        assertSw(SW_WRONG_LENGTH,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, hash(1)));
    }

    @Test
    @DisplayName("authenticator data has the right shape and an incrementing counter")
    public void authenticatorData() {
        unlock();
        register(hash(1));

        byte[] first = send(INS_GET_ASSERTION, concat(hash(1), hash(9)));
        assertEquals(0x30, first[37], "a DER signature follows the 37 bytes of authData");
        assertEquals(37 + 2 + first[38], first.length);

        byte[] rpIdHash = java.util.Arrays.copyOfRange(first, 0, 32);
        assertArrayEquals(hash(1), rpIdHash, "authData starts with the rpIdHash");
        assertEquals(0x05, first[32], "user present + user verified");
        assertEquals(1, counterOf(first), "first assertion");

        byte[] second = send(INS_GET_ASSERTION, concat(hash(1), hash(9)));
        assertEquals(2, counterOf(second));

        assertNotEquals(
            java.util.Arrays.toString(java.util.Arrays.copyOfRange(first, 37, first.length)),
            java.util.Arrays.toString(java.util.Arrays.copyOfRange(second, 37, second.length)),
            "counter change must change the signature");
    }

    @Test
    @DisplayName("delete clears the slot")
    public void delete() {
        unlock();
        register(hash(1));

        assertSw(SW_OK, transmit(INS_DELETE, (byte) 0, (byte) 0, null));

        byte[] info = send(INS_GET_INFO, null);
        assertEquals(0, info[1] & 0x01, "credential flag cleared");
        assertSw(SW_NO_CREDENTIAL,
            transmit(INS_GET_ASSERTION, (byte) 0, (byte) 0, concat(hash(1), hash(9))));
    }

    @Test
    @DisplayName("the credential survives a card reset")
    public void credentialIsPersistent() {
        unlock();
        AttestationObject made = register(hash(1));

        reselect();
        verifyPin(PIN);

        assertArrayEquals(made.coseKey.x, readCredential().x);
    }

    private static int counterOf(byte[] authData) {
        return ((authData[33] & 0xFF) << 24) | ((authData[34] & 0xFF) << 16)
             | ((authData[35] & 0xFF) << 8) | (authData[36] & 0xFF);
    }

    private static boolean isAllZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
