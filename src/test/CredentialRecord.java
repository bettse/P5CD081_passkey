package test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * The MAKE_CREDENTIAL / GET_CREDENTIAL response, parsed the way a host would:
 * credId(16) || COSE_Key.
 */
public class CredentialRecord {

    public final byte[] credentialId;
    public final byte[] x;
    public final byte[] y;
    public final int kty;
    public final int alg;

    private CredentialRecord(byte[] credentialId, CoseKey key) {
        this.credentialId = credentialId;
        this.x = key.x;
        this.y = key.y;
        this.kty = key.kty;
        this.alg = key.alg;
    }

    public static CredentialRecord parse(byte[] data) {
        if (data.length < 17) {
            throw new IllegalArgumentException("record too short: " + data.length);
        }
        byte[] credId = Arrays.copyOfRange(data, 0, 16);
        return new CredentialRecord(credId, CoseKey.parse(Arrays.copyOfRange(data, 16, data.length)));
    }

    /** The public key as a relying party would reconstruct it from the COSE key. */
    public PublicKey toPublicKey() throws Exception {
        return p256(x, y);
    }

    /** Build a P-256 public key from raw affine coordinates, as a relying party would. */
    static PublicKey p256(byte[] x, byte[] y) throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, curve));
    }

    /** An ES256 COSE_Key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}. */
    public static class CoseKey {
        public int kty;
        public int alg;
        public int crv;
        public byte[] x;
        public byte[] y;

        public PublicKey toPublicKey() throws Exception {
            return p256(x, y);
        }

        public static CoseKey parse(byte[] data) {
            Cbor c = new Cbor(data);
            CoseKey key = new CoseKey();

            int entries = c.expect(Cbor.MAP);
            if (entries != 5) {
                throw new IllegalArgumentException("COSE key has " + entries + " entries, expected 5");
            }
            for (int i = 0; i < entries; i++) {
                int label = (int) c.readInt();
                switch (label) {
                    case 1:
                        key.kty = (int) c.readInt();
                        break;
                    case 3:
                        key.alg = (int) c.readInt();
                        break;
                    case -1:
                        key.crv = (int) c.readInt();
                        break;
                    case -2:
                        key.x = c.readBytes();
                        break;
                    case -3:
                        key.y = c.readBytes();
                        break;
                    default:
                        throw new IllegalArgumentException("unexpected COSE label " + label);
                }
            }
            if (c.remaining() != 0) {
                throw new IllegalArgumentException(c.remaining() + " trailing bytes after the COSE key");
            }
            return key;
        }
    }
}
