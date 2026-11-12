package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The test that decides whether any of this is worth building: does the ECDSA
 * signature assembled from key generation and RSA-engine arithmetic actually
 * verify as ES256 against a stock JCA verifier, which is what a relying party runs?
 */
public class AssertionSignatureTest extends BaseTest {

    @Test
    @DisplayName("assertion verifies as ES256 the way a relying party checks it")
    public void assertionVerifies() throws Exception {
        unlock();
        AttestationObject cred = register(hash(1));
        PublicKey publicKey = cred.publicKey();

        byte[] clientDataHash = hash(9);
        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), clientDataHash));

        byte[] authData = Arrays.copyOfRange(response, 0, 37);
        byte[] signature = Arrays.copyOfRange(response, 37, response.length);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(authData);
        verifier.update(clientDataHash);

        assertTrue(verifier.verify(signature), "ES256 signature over authData || clientDataHash");
    }

    @Test
    @DisplayName("a signature does not verify against different client data")
    public void wrongClientDataFails() throws Exception {
        unlock();
        AttestationObject cred = register(hash(1));

        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), hash(9)));
        byte[] authData = Arrays.copyOfRange(response, 0, 37);
        byte[] signature = Arrays.copyOfRange(response, 37, response.length);

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(cred.publicKey());
        verifier.update(authData);
        verifier.update(hash(10));

        assertFalse(verifier.verify(signature), "must not verify against a different challenge");
    }

    @Test
    @DisplayName("every assertion in a session verifies, counter included")
    public void repeatedAssertionsVerify() throws Exception {
        unlock();
        AttestationObject cred = register(hash(1));
        PublicKey publicKey = cred.publicKey();

        for (int i = 0; i < 3; i++) {
            byte[] clientDataHash = hash(100 + i);
            byte[] response = send(INS_GET_ASSERTION, concat(hash(1), clientDataHash));

            byte[] authData = Arrays.copyOfRange(response, 0, 37);
            byte[] signature = Arrays.copyOfRange(response, 37, response.length);

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(authData);
            verifier.update(clientDataHash);

            assertTrue(verifier.verify(signature), "assertion " + i);
        }
    }

    @Test
    @DisplayName("two thousand signatures over random challenges and ten keys all verify")
    public void manySignaturesVerify() throws Exception {
        // The signature is built from additions, subtractions, a halving and a
        // reduction written by hand, and their carry and borrow paths are only
        // taken for some values. Volume is how those get exercised.
        unlock();
        java.util.Random random = new java.util.Random(20261112L);
        byte[] rp = hash(1);
        Signature verifier = Signature.getInstance("SHA256withECDSA");

        for (int key = 0; key < 10; key++) {
            PublicKey publicKey = (key == 0 ? register(rp) : replace(rp)).publicKey();
            for (int i = 0; i < 200; i++) {
                byte[] clientDataHash = new byte[32];
                random.nextBytes(clientDataHash);
                byte[] response = send(INS_GET_ASSERTION, concat(rp, clientDataHash));

                verifier.initVerify(publicKey);
                verifier.update(response, 0, 37);
                verifier.update(clientDataHash);
                assertTrue(verifier.verify(Arrays.copyOfRange(response, 37, response.length)),
                    "key " + key + ", signature " + i);
            }
        }
    }

    @Test
    @DisplayName("a replaced credential's key cannot verify the old one's signatures")
    public void replacedKeyDoesNotVerify() throws Exception {
        unlock();
        AttestationObject first = register(hash(1));

        byte[] clientDataHash = hash(9);
        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), clientDataHash));
        byte[] authData = Arrays.copyOfRange(response, 0, 37);
        byte[] signature = Arrays.copyOfRange(response, 37, response.length);

        AttestationObject second = replace(hash(2));
        assertFalse(Arrays.equals(first.coseKey.x, second.coseKey.x));

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(second.publicKey());
        verifier.update(authData);
        verifier.update(clientDataHash);

        assertFalse(verifier.verify(signature));
    }

    @Test
    @DisplayName("authData is exactly what WebAuthn expects to be signed")
    public void authDataLayout() {
        unlock();
        register(hash(1));

        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), hash(9)));
        byte[] authData = Arrays.copyOfRange(response, 0, 37);

        assertArrayEquals(hash(1), Arrays.copyOfRange(authData, 0, 32));
        assertArrayEquals(new byte[]{0x00, 0x00, 0x00, 0x01}, Arrays.copyOfRange(authData, 33, 37));
    }
}
