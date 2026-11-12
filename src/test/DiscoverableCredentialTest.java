package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Several credentials on one card: discoverable ones the card can offer by
 * itself, and the getNextAssertion walk a platform uses to see them all.
 */
public class DiscoverableCredentialTest extends BaseTest {

    private static final byte CTAP2_OK = 0x00;
    private static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
    private static final byte CTAP2_ERR_KEY_STORE_FULL = 0x28;
    private static final byte CTAP2_ERR_NO_CREDENTIALS = 0x2F;
    private static final byte CTAP2_ERR_NOT_ALLOWED = 0x31;

    private static final String RP_ID = "example.com";

    private AttestationObject registerResident(String rpId, byte[] userId) {
        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialResident(hash(9), rpId, userId));
        assertEquals(CTAP2_OK, r.status, "registration for user " + Arrays.toString(userId));
        return AttestationObject.parse(r.cbor);
    }

    @Test
    @DisplayName("a full card says so instead of evicting")
    public void capacity() {
        int slots = slots();

        for (int i = 0; i < slots; i++) {
            registerResident("site" + i + ".example", new byte[]{(byte) i});
        }
        assertEquals(slots, send(INS_GET_INFO, null)[4], "all used");

        CtapResponse extra = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialResident(hash(9), "overflow.example", new byte[]{99}));
        assertEquals(CTAP2_ERR_KEY_STORE_FULL, extra.status);
    }

    @Test
    @DisplayName("a full card keeps what it has when a different site asks to register")
    public void fullCardKeepsItsCredentials() throws Exception {
        int slots = slots();
        AttestationObject first = registerResident("site0.example", new byte[]{0});
        for (int i = 1; i < slots; i++) {
            registerResident("site" + i + ".example", new byte[]{(byte) i});
        }

        assertEquals(CTAP2_ERR_KEY_STORE_FULL, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialResident(hash(9), "other.example", new byte[]{99})).status);
        // A non-discoverable registration needs a slot just the same.
        assertEquals(CTAP2_ERR_KEY_STORE_FULL, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), "other.example", CtapRequests.ALG_ES256)).status);
        assertEquals(slots, send(INS_GET_INFO, null)[4], "nothing was evicted");

        // The first credential is still there and still signs.
        CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion("site0.example", hash(11)));
        assertEquals(CTAP2_OK, r.status);
        Assertion assertion = Assertion.parse(r.cbor);
        java.security.Signature v = java.security.Signature.getInstance("SHA256withECDSA");
        v.initVerify(first.publicKey());
        v.update(assertion.authData);
        v.update(hash(11));
        assertTrue(v.verify(assertion.signature));
    }

    @Test
    @DisplayName("reset is what frees a full card")
    public void resetFreesTheCard() {
        for (int i = 0; i < slots(); i++) {
            registerResident("site" + i + ".example", new byte[]{(byte) i});
        }
        reselect();
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_RESET, null).status);
        registerResident("other.example", new byte[]{99});
    }

    @Test
    @DisplayName("re-registering the same user replaces rather than duplicates")
    public void reRegistrationReplaces() {
        byte[] userId = {1, 2, 3};
        AttestationObject first = registerResident(RP_ID, userId);
        AttestationObject second = registerResident(RP_ID, userId);

        assertFalse(Arrays.equals(first.coseKey.x, second.coseKey.x),
            "a fresh key each time");
        assertEquals(1, send(INS_GET_INFO, null)[4], "still one slot used");
    }

    @Test
    @DisplayName("different users at the same site each get a slot")
    public void twoUsersOneSite() {
        assumeTrue(slots() >= 2, "needs room for two");
        registerResident(RP_ID, new byte[]{1});
        registerResident(RP_ID, new byte[]{2});

        assertEquals(2, send(INS_GET_INFO, null)[4]);
    }

    @Test
    @DisplayName("an assertion carries the user handle for a discoverable credential")
    public void assertionCarriesUser() {
        byte[] userId = {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        registerResident(RP_ID, userId);

        CtapResponse r = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, hash(11)));
        assertEquals(CTAP2_OK, r.status);

        Assertion assertion = Assertion.parse(r.cbor);
        assertArrayEquals(userId, assertion.userId, "user.id comes back");
        assertEquals(0, assertion.numberOfCredentials, "one credential, so no count");
    }

    @Test
    @DisplayName("a non-discoverable credential carries no user handle")
    public void nonResidentHasNoUser() {
        ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredential(hash(9), RP_ID, CtapRequests.ALG_ES256));

        Assertion assertion = Assertion.parse(ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, hash(11))).cbor);
        assertEquals(null, assertion.userId, "nothing to disclose");
    }

    @Test
    @DisplayName("getAssertion then getNextAssertion walks every credential for a site")
    public void walkAllCredentials() throws Exception {
        assumeTrue(slots() >= 3, "needs room for three");
        List<AttestationObject> registered = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            registered.add(registerResident(RP_ID, new byte[]{(byte) (i + 1)}));
        }

        byte[] cdh = hash(11);
        CtapResponse first = ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion(RP_ID, cdh));
        assertEquals(CTAP2_OK, first.status);

        Assertion a = Assertion.parse(first.cbor);
        assertEquals(3, a.numberOfCredentials, "the platform is told how many follow");

        List<Assertion> all = new ArrayList<>();
        all.add(a);
        for (int i = 0; i < 2; i++) {
            CtapResponse next = ctap(CtapRequests.CMD_GET_NEXT_ASSERTION, null);
            assertEquals(CTAP2_OK, next.status, "getNextAssertion " + i);
            Assertion n = Assertion.parse(next.cbor);
            assertEquals(0, n.numberOfCredentials, "the count appears only once");
            all.add(n);
        }

        // The walk is exhausted.
        assertEquals(CTAP2_ERR_NOT_ALLOWED, ctap(CtapRequests.CMD_GET_NEXT_ASSERTION, null).status);

        Set<String> seen = new HashSet<>();
        for (Assertion each : all) {
            seen.add(Arrays.toString(each.credentialId));
        }
        assertEquals(3, seen.size(), "three distinct credentials");

        // Every assertion verifies under the key registered for that credential.
        for (Assertion each : all) {
            AttestationObject match = null;
            for (AttestationObject candidate : registered) {
                if (Arrays.equals(candidate.credentialId, each.credentialId)) {
                    match = candidate;
                }
            }
            assertTrue(match != null, "assertion names a credential we registered");

            Signature v = Signature.getInstance("SHA256withECDSA");
            v.initVerify(match.publicKey());
            v.update(each.authData);
            v.update(cdh);
            assertTrue(v.verify(each.signature), "assertion verifies");
        }
    }

    @Test
    @DisplayName("any other command ends a walk in progress")
    public void otherCommandEndsWalk() {
        assumeTrue(slots() >= 2, "a walk needs something to walk");
        registerResident(RP_ID, new byte[]{1});
        registerResident(RP_ID, new byte[]{2});

        ctap(CtapRequests.CMD_GET_ASSERTION, CtapRequests.getAssertion(RP_ID, hash(11)));
        ctap(CtapRequests.CMD_GET_INFO, null);

        assertEquals(CTAP2_ERR_NOT_ALLOWED, ctap(CtapRequests.CMD_GET_NEXT_ASSERTION, null).status);
    }

    @Test
    @DisplayName("a walk does not survive the card being put down")
    public void walkEndsOnDeselect() {
        assumeTrue(slots() >= 2, "a walk needs something to walk");
        registerResident(RP_ID, new byte[]{1});
        registerResident(RP_ID, new byte[]{2});

        ctap(CtapRequests.CMD_GET_ASSERTION, CtapRequests.getAssertion(RP_ID, hash(11)));

        // CTAP2 expires a walk on a 30 second timer. With no clock, losing
        // selection is the equivalent, and on a contactless card it is stricter.
        deselectAndReselect();
        assertEquals(CTAP2_ERR_NOT_ALLOWED, ctap(CtapRequests.CMD_GET_NEXT_ASSERTION, null).status);
    }

    @Test
    @DisplayName("credentials for other sites are not offered")
    public void siteIsolation() {
        assumeTrue(slots() >= 2, "needs two sites at once");
        registerResident("a.example", new byte[]{1});
        registerResident("b.example", new byte[]{2});

        Assertion a = Assertion.parse(ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion("a.example", hash(11))).cbor);
        assertEquals(0, a.numberOfCredentials, "only one credential for a.example");
        assertArrayEquals(new byte[]{1}, a.userId);

        assertEquals(CTAP2_ERR_NO_CREDENTIALS, ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertion("c.example", hash(11))).status);
    }

    @Test
    @DisplayName("an allowList picks one credential out of several")
    public void allowListSelects() {
        assumeTrue(slots() >= 2, "needs two credentials to choose between");
        AttestationObject first = registerResident(RP_ID, new byte[]{1});
        AttestationObject second = registerResident(RP_ID, new byte[]{2});

        Assertion picked = Assertion.parse(ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertionWithAllowList(RP_ID, hash(11), second.credentialId)).cbor);
        assertArrayEquals(second.credentialId, picked.credentialId);
        assertEquals(0, picked.numberOfCredentials, "an allowList pick is a single result");

        assertFalse(Arrays.equals(first.credentialId, picked.credentialId));
    }

    @Test
    @DisplayName("an allowList naming another site's credential is refused")
    public void allowListRespectsRelyingParty() {
        assumeTrue(slots() >= 2, "needs two sites at once");
        AttestationObject other = registerResident("other.example", new byte[]{1});
        registerResident(RP_ID, new byte[]{2});

        assertEquals(CTAP2_ERR_NO_CREDENTIALS, ctap(CtapRequests.CMD_GET_ASSERTION,
            CtapRequests.getAssertionWithAllowList(RP_ID, hash(11), other.credentialId)).status);
    }

    @Test
    @DisplayName("an excludeList stops a site registering twice")
    public void excludeList() {
        assumeTrue(slots() >= 2, "the follow-up registration needs a free slot");
        AttestationObject existing = registerResident(RP_ID, new byte[]{1});

        CtapResponse r = ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithExcludeList(hash(9), RP_ID, existing.credentialId));
        assertEquals(CTAP2_ERR_CREDENTIAL_EXCLUDED, r.status);

        // An excludeList naming something else does not block anything.
        byte[] stranger = new byte[16];
        Arrays.fill(stranger, (byte) 0x5A);
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_MAKE_CREDENTIAL,
            CtapRequests.makeCredentialWithExcludeList(hash(9), RP_ID, stranger)).status);
    }

    @Test
    @DisplayName("reset clears every slot")
    public void resetClearsAll() {
        int slots = slots();
        for (int i = 0; i < slots; i++) {
            registerResident("site" + i + ".example", new byte[]{(byte) i});
        }
        assertEquals(slots, send(INS_GET_INFO, null)[4]);

        selectApplet();
        assertEquals(CTAP2_OK, ctap(CtapRequests.CMD_RESET, null).status);
        assertEquals(0, send(INS_GET_INFO, null)[4]);
    }

    @Test
    @DisplayName("the vendor protocol addresses slots by P2")
    public void vendorSlotAddressing() {
        assumeTrue(slots() >= 3, "needs slots 0 and 2 to exist");
        unlock();
        AttestationObject zero = AttestationObject.parse(send(INS_MAKE_CREDENTIAL,
            (byte) 0x00, (byte) 0x00, concat(hash(1), hash(REGISTER_CHALLENGE))));
        AttestationObject two = AttestationObject.parse(send(INS_MAKE_CREDENTIAL,
            (byte) 0x00, (byte) 0x02, concat(hash(2), hash(REGISTER_CHALLENGE))));

        assertEquals(2, send(INS_GET_INFO, null)[4]);

        CredentialRecord readZero = CredentialRecord.parse(
            send(INS_GET_CREDENTIAL, (byte) 0x00, (byte) 0x00, null));
        CredentialRecord readTwo = CredentialRecord.parse(
            send(INS_GET_CREDENTIAL, (byte) 0x00, (byte) 0x02, null));

        assertArrayEquals(zero.coseKey.x, readZero.x);
        assertArrayEquals(two.coseKey.x, readTwo.x);

        // Slot 1 was never filled.
        assertSw(SW_NO_CREDENTIAL, transmit(INS_GET_CREDENTIAL, (byte) 0x00, (byte) 0x01, null));
        // And there is no slot 9.
        assertSw(0x6A86, transmit(INS_GET_CREDENTIAL, (byte) 0x00, (byte) 0x09, null));
    }

    @Test
    @DisplayName("the vendor delete erases one slot or all of them")
    public void vendorDelete() {
        unlock();
        register(hash(1));

        assertSw(SW_OK, transmit(INS_DELETE, (byte) 0x00, (byte) 0x00, null));
        assertEquals(0, send(INS_GET_INFO, null)[4], "the slot is empty");

        register(hash(1));
        assertSw(SW_OK, transmit(INS_DELETE, (byte) 0x00, (byte) 0xFF, null));
        assertEquals(0, send(INS_GET_INFO, null)[4], "0xFF erases every slot");
    }

    @Test
    @DisplayName("there is no slot past the last one")
    public void slotBounds() {
        unlock();
        assertSw(0x6A86, transmit(INS_GET_CREDENTIAL, (byte) 0x00, (byte) slots(), null));
    }
}
