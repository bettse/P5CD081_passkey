package dev.ericbetts.passkey;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.RandomData;

/**
 * One credential slot: a P-256 key bound to a relying party, its credential
 * id, its signature counter, and for a discoverable credential the user handle
 * that lets the card offer it without being told which one to use.
 *
 * The card generates and stores the key natively. Signing with it is the part
 * the card cannot do on its own, see Crypto.
 */
public class Credential {

    private final KeyPair keyPair;
    private final RandomData random;

    private final byte[] rpIdHash;
    private final byte[] credId;

    /** Big-endian 32-bit WebAuthn signature counter. */
    private final byte[] signCount;

    /** user.id, stored only for discoverable credentials. */
    private final byte[] userId;
    private short userIdLen;

    private boolean present;
    private boolean discoverable;

    public Credential() {
        // Allocated at install time so the EEPROM is reserved up front rather than
        // failing halfway through a genKeyPair() on a nearly full card.
        // JavaCard 2.2.2 has no named curves, so both halves get the parameters.
        ECPublicKey pub = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, Const.LENGTH_EC_FP_256, false);
        ECPrivateKey priv = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, Const.LENGTH_EC_FP_256, false);
        Secp256r1.configure(pub);
        Secp256r1.configure(priv);
        keyPair = new KeyPair(pub, priv);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rpIdHash = new byte[Const.LEN_RP_ID_HASH];
        credId = new byte[Const.LEN_CRED_ID];
        signCount = new byte[Const.LEN_SIGN_COUNT];
        userId = new byte[Const.MAX_USER_ID];
        userIdLen = (short) 0;
        present = false;
        discoverable = false;
    }

    public boolean isPresent() {
        return present;
    }

    public boolean isDiscoverable() {
        return discoverable;
    }

    /**
     * Generate a fresh key pair bound to rpIdHash.
     *
     * Not wrapped in a JCSystem transaction. Instead the credential is marked
     * absent first, so a power loss mid-generation leaves an unusable slot
     * rather than a key attributed to the wrong relying party.
     *
     * Takes about a tenth of a second on a P5CD081.
     *
     * @param userIdBuf may be null for a non-discoverable credential
     */
    public void create(byte[] rpIdHashBuf, short rpIdHashOff,
                       byte[] userIdBuf, short userIdOff, short userIdLength) {
        present = false;
        Util.arrayFillNonAtomic(signCount, (short) 0, Const.LEN_SIGN_COUNT, (byte) 0);

        keyPair.genKeyPair();
        random.generateData(credId, (short) 0, Const.LEN_CRED_ID);

        JCSystem.beginTransaction();
        Util.arrayCopy(rpIdHashBuf, rpIdHashOff, rpIdHash, (short) 0, Const.LEN_RP_ID_HASH);
        if (userIdBuf != null && userIdLength > (short) 0) {
            Util.arrayCopy(userIdBuf, userIdOff, userId, (short) 0, userIdLength);
            userIdLen = userIdLength;
            discoverable = true;
        } else {
            userIdLen = (short) 0;
            discoverable = false;
        }
        present = true;
        JCSystem.commitTransaction();
    }

    public void clear() {
        // Flip the flag atomically first: everything after this is best-effort scrubbing,
        // and an interrupted clear must never leave the slot looking usable.
        JCSystem.beginTransaction();
        present = false;
        discoverable = false;
        userIdLen = (short) 0;
        JCSystem.commitTransaction();

        Util.arrayFillNonAtomic(rpIdHash, (short) 0, Const.LEN_RP_ID_HASH, (byte) 0);
        Util.arrayFillNonAtomic(credId, (short) 0, Const.LEN_CRED_ID, (byte) 0);
        Util.arrayFillNonAtomic(signCount, (short) 0, Const.LEN_SIGN_COUNT, (byte) 0);
        Util.arrayFillNonAtomic(userId, (short) 0, Const.MAX_USER_ID, (byte) 0);
        keyPair.getPrivate().clearKey();
        keyPair.getPublic().clearKey();
        // clearKey may take the curve parameters with it, and the next
        // genKeyPair needs them back.
        Secp256r1.configure((ECPublicKey) keyPair.getPublic());
        Secp256r1.configure((ECPrivateKey) keyPair.getPrivate());
    }

    public boolean matchesCredId(byte[] buf, short off) {
        return present && Util.arrayCompare(buf, off, credId, (short) 0, Const.LEN_CRED_ID) == 0;
    }

    public boolean matchesRp(byte[] buf, short off) {
        return present
            && Util.arrayCompare(buf, off, rpIdHash, (short) 0, Const.LEN_RP_ID_HASH) == 0;
    }

    /** True when this slot already holds the same user's credential for the same site. */
    public boolean matchesUser(byte[] buf, short off, short len) {
        return present && userIdLen == len && len > (short) 0
            && Util.arrayCompare(buf, off, userId, (short) 0, len) == 0;
    }

    public ECPrivateKey getPrivateKey() {
        return (ECPrivateKey) keyPair.getPrivate();
    }

    public short copyCredId(byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(credId, (short) 0, out, outOff, Const.LEN_CRED_ID);
        return Const.LEN_CRED_ID;
    }

    public short copyRpIdHash(byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(rpIdHash, (short) 0, out, outOff, Const.LEN_RP_ID_HASH);
        return Const.LEN_RP_ID_HASH;
    }

    public short copySignCount(byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(signCount, (short) 0, out, outOff, Const.LEN_SIGN_COUNT);
        return Const.LEN_SIGN_COUNT;
    }

    public short getUserIdLength() {
        return userIdLen;
    }

    public short copyUserId(byte[] out, short outOff) {
        Util.arrayCopyNonAtomic(userId, (short) 0, out, outOff, userIdLen);
        return userIdLen;
    }

    /**
     * Write the public key as a CTAP2-canonical ES256 COSE_Key, always 77 bytes:
     * {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
     *
     * The labels encode as 0x01, 0x03, 0x20, 0x21, 0x22, so writing them in
     * this order already satisfies canonical ordering.
     */
    public short encodeCoseKey(byte[] out, short outOff) {
        // The card returns the point as 0x04 || x || y. Land it so that x is
        // already where it belongs, then move y three bytes along to make room
        // for its label and header.
        short xOff = (short) (outOff + 10);
        short yOff = (short) (xOff + 32 + 3);
        short wLen = ((ECPublicKey) keyPair.getPublic()).getW(out, (short) (xOff - 1));
        if (wLen != (short) 65 || out[(short) (xOff - 1)] != (byte) 0x04) {
            ISOException.throwIt(Const.SW_INTERNAL);
        }
        Util.arrayCopyNonAtomic(out, (short) (xOff + 32), out, yOff, (short) 32);

        short off = Cbor.mapHeader(out, outOff, (short) 5);
        off = Cbor.encodeInt(out, off, Const.COSE_KTY);
        off = Cbor.encodeInt(out, off, Const.COSE_KTY_EC2);
        off = Cbor.encodeInt(out, off, Const.COSE_ALG);
        off = Cbor.encodeInt(out, off, Const.COSE_ALG_ES256);
        off = Cbor.encodeInt(out, off, Const.COSE_EC_CRV);
        off = Cbor.encodeInt(out, off, Const.COSE_CRV_P256);
        off = Cbor.encodeInt(out, off, Const.COSE_EC_X);
        off = Cbor.bstrHeader(out, off, (short) 32);
        off = Cbor.encodeInt(out, (short) (off + 32), Const.COSE_EC_Y);
        off = Cbor.bstrHeader(out, off, (short) 32);
        return (short) (off + 32 - outOff);
    }

    /** Big-endian increment with carry, atomically. */
    public void incrementSignCount() {
        JCSystem.beginTransaction();
        for (short i = (short) (Const.LEN_SIGN_COUNT - 1); i >= (short) 0; i--) {
            signCount[i]++;
            if (signCount[i] != (byte) 0) {
                break;
            }
        }
        JCSystem.commitTransaction();
    }
}
