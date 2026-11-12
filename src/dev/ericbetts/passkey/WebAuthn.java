package dev.ericbetts.passkey;

import javacard.framework.Util;

/**
 * Authenticator data and the attestation object, per the WebAuthn and CTAP2 specs.
 *
 * Attestation is "packed" self attestation: the attStmt carries a signature made
 * with the credential's own private key, and no certificate. That proves the card
 * holds the private key matching the public key it just handed over, and nothing
 * about what hardware it is. An unfused development card has no provenance worth
 * claiming, and self attestation is the honest way to say so while still giving
 * relying parties and tools a signature to check.
 *
 * A relying party must not read the AAGUID of a self-attested credential as proof
 * of model: anyone can put any AAGUID in an attestation they signed themselves.
 */
public final class WebAuthn {

    private WebAuthn() {
    }

    /** Identifies this authenticator model. Not a per-card secret. */
    private static final byte[] AAGUID = {
        (byte) 0x1B, (byte) 0xB1, (byte) 0x08, (byte) 0x06,
        (byte) 0xC9, (byte) 0xE9, (byte) 0x45, (byte) 0xBD,
        (byte) 0xA2, (byte) 0x17, (byte) 0xFB, (byte) 0x35,
        (byte) 0x8F, (byte) 0xCA, (byte) 0x39, (byte) 0xA3
    };

    private static final byte[] FMT_PACKED = {'p', 'a', 'c', 'k', 'e', 'd'};
    private static final byte[] KEY_ALG = {'a', 'l', 'g'};
    private static final byte[] KEY_SIG = {'s', 'i', 'g'};

    public static short copyAaguid(byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(AAGUID, (short) 0, out, outOff, Const.LEN_AAGUID);
        return Const.LEN_AAGUID;
    }

    /**
     * Write authenticator data.
     *
     * rpIdHash(32) || flags(1) || signCount(4) [|| attestedCredentialData]
     *
     * attestedCredentialData is aaguid(16) || credIdLen(2) || credId || COSE_Key,
     * and is only present on registration, marked by the AT flag.
     *
     * @return the number of bytes written
     */
    public static short buildAuthData(Credential credential, byte[] out, short outOff,
                                      boolean attested, boolean userVerified) {
        short off = outOff;
        off += credential.copyRpIdHash(out, off);

        // UP is always set: presenting the card to the field is the gesture.
        byte flags = Const.FLAG_USER_PRESENT;
        if (userVerified) {
            flags |= Const.FLAG_USER_VERIFIED;
        }
        if (attested) {
            flags |= Const.FLAG_ATTESTED;
        }
        out[off++] = flags;

        off += credential.copySignCount(out, off);

        if (attested) {
            Util.arrayCopyNonAtomic(AAGUID, (short) 0, out, off, Const.LEN_AAGUID);
            off += Const.LEN_AAGUID;

            Util.setShort(out, off, Const.LEN_CRED_ID);
            off += 2;
            off += credential.copyCredId(out, off);

            off += credential.encodeCoseKey(out, off);
        }

        return (short) (off - outOff);
    }

    /**
     * Write the CTAP2 authenticatorMakeCredential response:
     * {1: "none", 2: authData, 3: {}}
     *
     * A browser turns this into the WebAuthn attestationObject by swapping the
     * integer keys for "fmt", "authData" and "attStmt".
     *
     * @return the number of bytes written
     */
    public static short buildAttestationObject(Credential credential, Crypto crypto,
                                               byte[] out, short outOff, boolean userVerified,
                                               byte[] clientDataHash, short clientDataHashOff) {
        short off = Cbor.mapHeader(out, outOff, (short) 3);

        off = Cbor.encodeInt(out, off, (short) 1);
        off = Cbor.encodeTstr(out, off, FMT_PACKED, (short) 0, (short) FMT_PACKED.length);

        off = Cbor.encodeInt(out, off, (short) 2);
        // Attested authData is 148 bytes with an ES256 key, so a 2-byte header.
        short headerOff = off;
        short authDataStart = (short) (off + 2);
        short authDataLen = buildAuthData(credential, out, authDataStart, true, userVerified);
        Cbor.fillReservedBstrHeader(out, headerOff, authDataLen, (short) 2);
        off = (short) (authDataStart + authDataLen);

        // attStmt: {"alg": -7, "sig": <authData || clientDataHash signed>}
        // Both keys are three bytes, so canonical order is bytewise and alg wins.
        off = Cbor.encodeInt(out, off, (short) 3);
        off = Cbor.mapHeader(out, off, (short) 2);
        off = Cbor.encodeTstr(out, off, KEY_ALG, (short) 0, (short) KEY_ALG.length);
        off = Cbor.encodeInt(out, off, Const.COSE_ALG_ES256);
        off = Cbor.encodeTstr(out, off, KEY_SIG, (short) 0, (short) KEY_SIG.length);

        // A DER ECDSA signature varies in length but always needs a 2-byte
        // header. It is written past everything it signs, so nothing aliases.
        short sigStart = (short) (off + 2);
        short sigLen = crypto.signEs256(credential.getPrivateKey(),
                                        out, authDataStart, authDataLen,
                                        clientDataHash, clientDataHashOff,
                                        Const.LEN_CLIENT_DATA_HASH,
                                        out, sigStart);
        Cbor.fillReservedBstrHeader(out, off, sigLen, (short) 2);

        return (short) (sigStart + sigLen - outOff);
    }
}
