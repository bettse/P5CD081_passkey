package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Signature;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Registration returns the CTAP2 attestation object. These tests read it exactly
 * as a browser would before passing it to a relying party.
 */
public class AttestationTest extends BaseTest {

    @Test
    @DisplayName("registration returns a packed self-attestation object")
    public void shape() {
        unlock();
        AttestationObject att = register(hash(1));

        assertEquals("packed", att.fmt);
        assertEquals(2, att.attStmtEntries, "alg and sig, and no certificate");
        assertEquals(-7L, att.attStmtAlg, "the attestation alg matches the credential key");
        assertTrue(att.attStmtSig.length >= 8 && att.attStmtSig.length <= 72,
            "a DER ECDSA signature, got " + att.attStmtSig.length + " bytes");
        assertEquals(148, att.authData.length, "32 + 1 + 4 + 16 + 2 + 16 + 77");
    }

    @Test
    @DisplayName("the attestation signature verifies under the credential's own key")
    public void selfAttestationVerifies() throws Exception {
        unlock();
        AttestationObject att = register(hash(1));

        // Self attestation: signed with the credential private key over
        // authData || clientDataHash, and checked with the key it just published.
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(att.publicKey());
        v.update(att.authData);
        v.update(hash(REGISTER_CHALLENGE));
        assertTrue(v.verify(att.attStmtSig), "self attestation must verify");
    }

    @Test
    @DisplayName("the attestation signature is bound to the challenge")
    public void selfAttestationIsBoundToTheChallenge() throws Exception {
        unlock();
        AttestationObject att = register(hash(1));

        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(att.publicKey());
        v.update(att.authData);
        v.update(hash(REGISTER_CHALLENGE + 1));
        assertFalse(v.verify(att.attStmtSig), "a different challenge must not verify");
    }

    @Test
    @DisplayName("authData sets AT and carries attestedCredentialData")
    public void attestedCredentialData() {
        unlock();
        AttestationObject att = register(hash(1));

        assertTrue(att.hasAttestedCredentialData(), "AT flag");
        assertTrue(att.userPresent());
        assertTrue(att.userVerified());
        assertEquals(0x45, att.flags & 0xFF, "UP + UV + AT");

        assertArrayEquals(hash(1), att.rpIdHash);
        assertEquals(0, att.signCount, "a fresh credential starts at zero");
        assertEquals(16, att.aaguid.length);
        assertEquals(16, att.credentialId.length);
        assertEquals(2, att.coseKey.kty);
        assertEquals(-7, att.coseKey.alg);
        assertEquals(1, att.coseKey.crv);
        assertEquals(32, att.coseKey.x.length);
        assertEquals(32, att.coseKey.y.length);
    }

    @Test
    @DisplayName("the aaguid is a fixed non-zero model identifier")
    public void aaguid() {
        unlock();
        AttestationObject first = register(hash(1));
        AttestationObject second = replace(hash(2));

        assertArrayEquals(first.aaguid, second.aaguid, "same model, same aaguid");
        boolean allZero = true;
        for (byte b : first.aaguid) {
            allZero &= b == 0;
        }
        assertFalse(allZero, "a zero aaguid means 'no identity', which is not what we mean here");
    }

    @Test
    @DisplayName("the key in the attestation object verifies later assertions")
    public void keyFromAttestationVerifies() throws Exception {
        unlock();
        AttestationObject att = register(hash(1));

        byte[] cdh = hash(9);
        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), cdh));

        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(att.publicKey());
        v.update(Arrays.copyOfRange(response, 0, 37));
        v.update(cdh);
        assertTrue(v.verify(Arrays.copyOfRange(response, 37, response.length)),
            "registration and assertion must agree on the key");
    }

    @Test
    @DisplayName("credential id in the attestation object matches the read-back")
    public void credentialIdMatches() {
        unlock();
        AttestationObject att = register(hash(1));
        CredentialRecord read = readCredential();

        assertArrayEquals(att.credentialId, read.credentialId);
        assertArrayEquals(att.coseKey.x, read.x);
    }

    @Test
    @DisplayName("assertions clear AT and carry no attestedCredentialData")
    public void assertionHasNoAttestedData() {
        unlock();
        register(hash(1));

        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), hash(9)));
        assertEquals(0x30, response[37], "authData stays at 37 bytes, then the DER signature");
        assertEquals(37 + 2 + response[38], response.length);
        assertEquals(0x05, response[32] & 0xFF, "UP + UV, no AT");
    }
}
