package test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The COSE_Key the card builds has to be byte-for-byte what a relying party
 * expects, because it goes into the attestation object verbatim and any drift
 * from canonical CBOR breaks verification.
 */
public class CoseKeyTest extends BaseTest {

    @Test
    @DisplayName("COSE key is a canonical 5-entry ES256 map")
    public void canonicalLayout() {
        unlock();
        register(hash(1));
        byte[] record = send(INS_GET_CREDENTIAL, null);
        byte[] cose = Arrays.copyOfRange(record, 16, record.length);

        // {1: 2, 3: -7, -1: 1, -2: bstr(32), -3: bstr(32)}
        assertArrayEquals(new byte[]{
            (byte) 0xA5,                // map of 5
            0x01, 0x02,                 // kty: EC2
            0x03, 0x26,                 // alg: -7
            0x20, 0x01,                 // crv: P-256
            0x21, 0x58, 0x20            // x: byte string of 32
        }, Arrays.copyOfRange(cose, 0, 10));
        assertArrayEquals(new byte[]{0x22, 0x58, 0x20},
            Arrays.copyOfRange(cose, 42, 45), "y: byte string of 32");
        assertEquals(77, cose.length, "the whole map");
    }

    @Test
    @DisplayName("labels come out in canonical order")
    public void canonicalOrder() {
        unlock();
        register(hash(1));
        byte[] record = send(INS_GET_CREDENTIAL, null);
        byte[] cose = Arrays.copyOfRange(record, 16, record.length);

        Cbor c = new Cbor(cose);
        assertEquals(5, c.expect(Cbor.MAP));

        // Canonical order for one-byte labels is bytewise: 0x01, 0x03, 0x20, 0x21, 0x22.
        long[] expected = {1, 3, -1, -2, -3};
        for (long label : expected) {
            assertEquals(label, c.readInt(), "label order");
            if (label >= -1) {
                c.readInt();
            } else {
                c.readBytes();
            }
        }
        assertEquals(0, c.remaining());
    }

    @Test
    @DisplayName("the public key is a point on P-256")
    public void onCurve() throws Exception {
        unlock();
        register(hash(1));
        CredentialRecord cred = readCredential();
        java.math.BigInteger p = new java.math.BigInteger(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        java.math.BigInteger b = new java.math.BigInteger(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        java.math.BigInteger x = new java.math.BigInteger(1, cred.x);
        java.math.BigInteger y = new java.math.BigInteger(1, cred.y);
        // y^2 = x^3 - 3x + b
        assertEquals(x.pow(3).subtract(x.multiply(java.math.BigInteger.valueOf(3))).add(b).mod(p),
            y.pow(2).mod(p));
    }

    @Test
    @DisplayName("the COSE key still reconstructs a working verifier")
    public void stillVerifies() throws Exception {
        unlock();
        register(hash(1));
        CredentialRecord cred = readCredential();

        byte[] cdh = hash(9);
        byte[] response = send(INS_GET_ASSERTION, concat(hash(1), cdh));

        java.security.Signature v = java.security.Signature.getInstance("SHA256withECDSA");
        v.initVerify(cred.toPublicKey());
        v.update(Arrays.copyOfRange(response, 0, 37));
        v.update(cdh);
        org.junit.jupiter.api.Assertions.assertTrue(
            v.verify(Arrays.copyOfRange(response, 37, response.length)));
    }
}
