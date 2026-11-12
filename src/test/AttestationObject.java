package test;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * The CTAP2 authenticatorMakeCredential response, {1: fmt, 2: authData, 3: attStmt},
 * parsed the way a browser does before handing it to a relying party.
 */
public class AttestationObject {

    public final String fmt;
    public final byte[] authData;
    public final int attStmtEntries;

    /** Self attestation carries an alg and a signature, and no certificate. */
    public final Long attStmtAlg;
    public final byte[] attStmtSig;

    // Fields carved out of authData.
    public final byte[] rpIdHash;
    public final byte flags;
    public final long signCount;
    public final byte[] aaguid;
    public final byte[] credentialId;
    public final CredentialRecord.CoseKey coseKey;

    private AttestationObject(String fmt, byte[] authData, int attStmtEntries,
                              Long attStmtAlg, byte[] attStmtSig) {
        this.fmt = fmt;
        this.authData = authData;
        this.attStmtEntries = attStmtEntries;
        this.attStmtAlg = attStmtAlg;
        this.attStmtSig = attStmtSig;

        if (authData.length < 37) {
            throw new IllegalArgumentException("authData is " + authData.length + " bytes");
        }
        this.rpIdHash = Arrays.copyOfRange(authData, 0, 32);
        this.flags = authData[32];
        this.signCount = ((authData[33] & 0xFFL) << 24) | ((authData[34] & 0xFFL) << 16)
                       | ((authData[35] & 0xFFL) << 8) | (authData[36] & 0xFFL);

        if (!hasAttestedCredentialData()) {
            this.aaguid = null;
            this.credentialId = null;
            this.coseKey = null;
            return;
        }

        this.aaguid = Arrays.copyOfRange(authData, 37, 53);
        int credIdLen = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
        int keyStart = 55 + credIdLen;
        if (keyStart > authData.length) {
            throw new IllegalArgumentException("credential id length " + credIdLen + " overruns authData");
        }
        this.credentialId = Arrays.copyOfRange(authData, 55, keyStart);
        this.coseKey = CredentialRecord.CoseKey.parse(Arrays.copyOfRange(authData, keyStart, authData.length));
    }

    public boolean userPresent() {
        return (flags & 0x01) != 0;
    }

    public boolean userVerified() {
        return (flags & 0x04) != 0;
    }

    public boolean hasAttestedCredentialData() {
        return (flags & 0x40) != 0;
    }

    public PublicKey publicKey() throws Exception {
        return coseKey.toPublicKey();
    }

    public static AttestationObject parse(byte[] data) {
        Cbor c = new Cbor(data);
        int entries = c.expect(Cbor.MAP);
        if (entries != 3) {
            throw new IllegalArgumentException("attestation object has " + entries + " entries");
        }

        String fmt = null;
        byte[] authData = null;
        int attStmtEntries = -1;
        Long attStmtAlg = null;
        byte[] attStmtSig = null;

        for (int i = 0; i < entries; i++) {
            int key = (int) c.readInt();
            switch (key) {
                case 1:
                    fmt = c.readText();
                    break;
                case 2:
                    authData = c.readBytes();
                    break;
                case 3:
                    attStmtEntries = c.expect(Cbor.MAP);
                    for (int j = 0; j < attStmtEntries; j++) {
                        String name = c.readText();
                        if (name.equals("alg")) {
                            attStmtAlg = c.readInt();
                        } else if (name.equals("sig")) {
                            attStmtSig = c.readBytes();
                        } else {
                            throw new IllegalArgumentException("unexpected attStmt field " + name);
                        }
                    }
                    break;
                default:
                    throw new IllegalArgumentException("unexpected key " + key);
            }
        }
        if (c.remaining() != 0) {
            throw new IllegalArgumentException(c.remaining() + " trailing bytes");
        }
        if (fmt == null || authData == null || attStmtEntries < 0) {
            throw new IllegalArgumentException("attestation object is missing a field");
        }
        return new AttestationObject(fmt, authData, attStmtEntries, attStmtAlg, attStmtSig);
    }
}
