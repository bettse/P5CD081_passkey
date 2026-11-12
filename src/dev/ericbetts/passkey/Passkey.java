package dev.ericbetts.passkey;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * A WebAuthn authenticator holding a small bank of credentials.
 *
 * Two front doors onto the same state:
 *
 *   CLA 0x80  CTAP2 over NFC, what a platform speaks
 *   CLA 0xE0  a vendor protocol for provisioning and testing, which can do
 *             things CTAP2 deliberately cannot, like reading the stored key back
 *
 * CTAP2 owns CLA 0x80 by specification, which is why the vendor protocol moved
 * to 0xE0 rather than the other way round.
 *
 * Installed under the FIDO AID A0:00:00:06:47:2F:00:01 so a platform finds it,
 * and answers SELECT with "FIDO_2_0" so it knows what it found.
 */
public class Passkey extends Applet implements javacardx.apdu.ExtendedLength {

    private final CredentialStore store;
    private final Crypto crypto;
    private final Pin pin;
    private final Ctap2 ctap2;
    private final CborReader cbor;

    /** Assembled CTAP2 request, built up across chained APDUs. */
    private final byte[] inBuf;

    /** Staged response, drained by GET RESPONSE or NFCCTAP_GETRESPONSE. */
    private final byte[] outBuf;

    /**
     * [0] staged total, [1] staged bytes sent, [2] assembled request length,
     * [3] nothing has been sent yet since selection, [4] the current command
     * arrived as an extended-length APDU.
     */
    private final short[] state;

    private static final short STATE_TOTAL = (short) 0;
    private static final short STATE_SENT = (short) 1;
    private static final short STATE_REQUEST = (short) 2;
    private static final short STATE_FRESH = (short) 3;
    private static final short STATE_EXTENDED = (short) 4;

    /** authData || clientDataHash, the exact bytes WebAuthn signs over. */
    private final byte[] toSign;

    protected Passkey() {
        store = new CredentialStore();
        crypto = new Crypto();
        cbor = new CborReader();
        pin = new Pin(cbor);

        toSign = JCSystem.makeTransientByteArray(
            (short) (Const.LEN_AUTH_DATA + Const.LEN_CLIENT_DATA_HASH),
            JCSystem.CLEAR_ON_DESELECT);
        inBuf = JCSystem.makeTransientByteArray(Const.MAX_REQUEST, JCSystem.CLEAR_ON_DESELECT);
        outBuf = JCSystem.makeTransientByteArray(Const.MAX_RESPONSE, JCSystem.CLEAR_ON_DESELECT);
        state = JCSystem.makeTransientShortArray((short) 5, JCSystem.CLEAR_ON_DESELECT);

        ctap2 = new Ctap2(store, crypto, pin, cbor);

        register();
    }

    /**
     * Mark the session fresh, which is what lets authenticatorReset run.
     *
     * The transient arrays are cleared by the JCRE between deselect and here,
     * so this is the first thing that gets to write to them.
     */
    public boolean select() {
        state[STATE_FRESH] = (short) 1;
        return true;
    }

    /**
     * Drop the PIN's validated flag when the applet loses selection.
     *
     * The JCRE clears CLEAR_ON_DESELECT arrays for us, but OwnerPIN's validated
     * flag is not one of them: it survives until a card reset. Without this,
     * whatever holds the field next inherits an unlocked card.
     */
    public void deselect() {
        pin.clearVerification();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        try {
            new Passkey();
        } catch (javacard.framework.CardRuntimeException e) {
            ISOException.throwIt((short) (0x6C00 | (e.getReason() & 0xFF)));
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            // A platform decides what it is talking to from this string.
            byte[] selectBuf = apdu.getBuffer();
            short len = Ctap2.copyVersionString(selectBuf, (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            return;
        }

        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];

        // GET RESPONSE, on whichever class byte the host felt like using. The
        // spec-blessed continuation for CTAP2 is NFCCTAP_GETRESPONSE (80 11),
        // but libfido2 sends ISO GET RESPONSE with the CTAP class (80 C0), which
        // is a fair reading of ISO 7816. Accept that, and 00 C0, and E0 C0.
        if (ins == Const.INS_GET_RESPONSE
                && (cla == Const.CLA_ISO || cla == Const.CLA_CTAP || cla == Const.CLA_VENDOR)) {
            sendStaged(apdu);
            return;
        }

        // CTAP1/U2F GET_VERSION. A platform probing for U2F asks this before it
        // decides what it is talking to; answering it costs nothing and this
        // card can honestly say which version string it uses. The U2F register
        // and authenticate commands are not implemented.
        if (cla == Const.CLA_ISO && ins == Const.INS_U2F_VERSION) {
            byte[] versionBuf = apdu.getBuffer();
            short len = Ctap2.copyVersionString(versionBuf, (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            return;
        }

        boolean moreBlocks = (cla & Const.CLA_CHAINING_BIT) != 0;
        byte baseCla = (byte) (cla & ~Const.CLA_CHAINING_BIT);

        if (baseCla == Const.CLA_CTAP) {
            ctapApdu(apdu, ins, moreBlocks);
            return;
        }
        if (baseCla == Const.CLA_VENDOR) {
            if (moreBlocks) {
                // Vendor commands all fit in one APDU, so chaining means confusion.
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
            vendorApdu(apdu, ins);
            return;
        }
        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    // ---- CTAP2 transport ----

    /**
     * The CTAP2 NFC binding: INS 0x10 carries a message, INS 0x11 fetches more of
     * the response. Long requests arrive as chained APDUs and are assembled here
     * before the command layer sees them.
     */
    private void ctapApdu(APDU apdu, byte ins, boolean moreBlocks) {
        if (ins == Const.INS_NFCCTAP_GETRESPONSE) {
            sendStaged(apdu);
            return;
        }
        if (ins != Const.INS_NFCCTAP_MSG) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        short have = state[STATE_REQUEST];
        short added = receiveInto(apdu, inBuf, have);
        state[STATE_REQUEST] = (short) (have + added);

        if (moreBlocks) {
            // Acknowledge and wait for the rest.
            return;
        }

        short total = state[STATE_REQUEST];
        state[STATE_REQUEST] = (short) 0;

        boolean firstCommand = state[STATE_FRESH] != (short) 0;
        state[STATE_FRESH] = (short) 0;

        stage(ctap2.handle(inBuf, (short) 0, total, outBuf, firstCommand));
        sendStaged(apdu);
    }

    // ---- vendor protocol ----

    private void vendorApdu(APDU apdu, byte ins) {
        // Any vendor traffic also ends the window in which a reset is accepted.
        state[STATE_FRESH] = (short) 0;

        switch (ins) {
            case Const.INS_GET_INFO:
                getInfo(apdu);
                break;
            case Const.INS_SET_PIN:
                setPin(apdu);
                break;
            case Const.INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            case Const.INS_MAKE_CREDENTIAL:
                makeCredential(apdu);
                break;
            case Const.INS_GET_CREDENTIAL:
                requirePin();
                stageCredential(apdu);
                sendStaged(apdu);
                break;
            case Const.INS_GET_ASSERTION:
                getAssertion(apdu);
                break;
            case Const.INS_DELETE:
                requirePin();
                deleteCredential(apdu);
                break;
            case Const.INS_MEMORY:
                memory(apdu);
                break;
            case Const.INS_PROBE_ALG:
                probeAlg(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /** version(1) || flags(1) || pinRetriesLeft(1) || slots(1) || slotsUsed(1) */
    private void getInfo(APDU apdu) {
        byte flags = (byte) 0x00;
        if (!store.isEmpty()) {
            flags |= Const.INFO_HAS_CREDENTIAL;
        }
        if (pin.isSet()) {
            flags |= Const.INFO_PIN_SET;
        }
        if (pin.isVerified()) {
            flags |= Const.INFO_PIN_VERIFIED;
        }

        outBuf[(short) 0] = Const.VERSION;
        outBuf[(short) 1] = flags;
        outBuf[(short) 2] = pin.getTriesRemaining();
        outBuf[(short) 3] = (byte) store.size();
        outBuf[(short) 4] = (byte) store.used();

        stage((short) 5);
        sendStaged(apdu);
    }

    /**
     * Report free memory: persistent, transient-on-reset, transient-on-deselect.
     *
     * The transient pools are the binding constraint on this card, and JCOP 2.4.1
     * exposes them nowhere else, so this is how buffer sizes get chosen.
     */
    private void memory(APDU apdu) {
        Util.setShort(outBuf, (short) 0,
            JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
        Util.setShort(outBuf, (short) 2,
            JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        Util.setShort(outBuf, (short) 4,
            JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        stage((short) 6);
        sendStaged(apdu);
    }

    /**
     * Ask this card, in this applet, whether a KeyAgreement algorithm exists.
     *
     * JCAlgTest ran a different applet on a different card, so its answer is
     * evidence, not proof. P1 is the algorithm number; the response is 0x00 for
     * supported or the CryptoException reason.
     */
    private void probeAlg(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte alg = buf[ISO7816.OFFSET_P1];
        byte result;
        try {
            javacard.security.KeyAgreement.getInstance(alg, false);
            result = (byte) 0x00;
        } catch (javacard.framework.CardRuntimeException e) {
            result = (byte) e.getReason();
        }
        outBuf[(short) 0] = result;
        stage((short) 1);
        sendStaged(apdu);
    }

    /** P1 0x00 sets the first PIN; P1 0x01 replaces it and requires the current one verified. */
    private void setPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);

        if (!pin.isValidLength(lc)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte p1 = buf[ISO7816.OFFSET_P1];
        if (p1 == Const.P1_INITIAL) {
            if (pin.isSet()) {
                ISOException.throwIt(Const.SW_PIN_ALREADY_SET);
            }
        } else if (p1 == Const.P1_REPLACE) {
            requirePin();
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        pin.setFromClear(buf, apdu.getOffsetCdata(), lc);
    }

    private void verifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);

        if (!pin.isSet()) {
            ISOException.throwIt(Const.SW_PIN_REQUIRED);
        }
        if (!pin.isValidLength(lc)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (!pin.checkClear(buf, apdu.getOffsetCdata(), lc)) {
            // 63Cx: x attempts left, the usual smart card convention.
            ISOException.throwIt((short) (0x63C0 | (pin.getTriesRemaining() & 0x0F)));
        }
    }

    /**
     * Generate the credential. Data is rpIdHash(32) || clientDataHash(32).
     *
     * The clientDataHash is needed because self attestation signs it alongside
     * authData; there is nothing else to sign it with.
     *
     */
    private void makeCredential(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);

        requirePin();
        if (lc != (short) (Const.LEN_RP_ID_HASH + Const.LEN_CLIENT_DATA_HASH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Credential credential = store.get(slotFrom(buf));
        if (credential.isPresent() && buf[ISO7816.OFFSET_P1] != Const.P1_REPLACE) {
            ISOException.throwIt(Const.SW_CREDENTIAL_EXISTS);
        }

        // The vendor protocol makes non-discoverable credentials: there is no
        // user handle in an APDU this small, and CTAP2 is where that belongs.
        short cdata = apdu.getOffsetCdata();
        credential.create(buf, cdata, null, (short) 0, (short) 0);

        // A registration returns the attestation object, the same bytes CTAP2
        // puts on the wire. GET_CREDENTIAL is the debug read-back instead.
        stage(WebAuthn.buildAttestationObject(credential, crypto, outBuf, (short) 0, true,
                                              buf, (short) (cdata + Const.LEN_RP_ID_HASH)));
        sendStaged(apdu);
    }

    /**
     * Data is rpIdHash(32) || clientDataHash(32).
     * Response is authData(37) || DER ECDSA signature.
     */
    private void getAssertion(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = receive(apdu);

        requirePin();
        if (store.isEmpty()) {
            ISOException.throwIt(Const.SW_NO_CREDENTIAL);
        }
        if (lc != (short) (Const.LEN_RP_ID_HASH + Const.LEN_CLIENT_DATA_HASH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short cdata = apdu.getOffsetCdata();
        short slot = store.findByRp(buf, cdata, (short) 0);
        if (slot < (short) 0) {
            ISOException.throwIt(Const.SW_RP_MISMATCH);
        }
        Credential credential = store.get(slot);

        credential.incrementSignCount();

        // An assertion carries no attestedCredentialData, so the AT flag stays clear.
        short off = WebAuthn.buildAuthData(credential, toSign, (short) 0, false, true);

        // The relying party verifies over authData || clientDataHash.
        Util.arrayCopyNonAtomic(buf, (short) (cdata + Const.LEN_RP_ID_HASH),
                                toSign, off, Const.LEN_CLIENT_DATA_HASH);
        short signedLen = (short) (off + Const.LEN_CLIENT_DATA_HASH);

        Util.arrayCopyNonAtomic(toSign, (short) 0, outBuf, (short) 0, Const.LEN_AUTH_DATA);
        short sigLen = crypto.signEs256(credential.getPrivateKey(),
                                        toSign, (short) 0, signedLen,
                                        null, (short) 0, (short) 0,
                                        outBuf, Const.LEN_AUTH_DATA);

        stage((short) (Const.LEN_AUTH_DATA + sigLen));
        sendStaged(apdu);
    }

    /** credId(16) || COSE_Key for the slot in P2, a read-back that re-attests nothing */
    private void stageCredential(APDU apdu) {
        Credential credential = store.get(slotFrom(apdu.getBuffer()));
        if (!credential.isPresent()) {
            ISOException.throwIt(Const.SW_NO_CREDENTIAL);
        }
        short off = credential.copyCredId(outBuf, (short) 0);
        off += credential.encodeCoseKey(outBuf, off);
        stage(off);
    }

    /** P2 selects the slot, or 0xFF erases all of them. */
    private void deleteCredential(APDU apdu) {
        byte p2 = apdu.getBuffer()[ISO7816.OFFSET_P2];
        if (p2 == Const.P2_ALL_SLOTS) {
            store.clearAll();
            return;
        }
        store.get(slotFrom(apdu.getBuffer())).clear();
    }

    /** P2 names the slot for vendor commands, defaulting to the first. */
    private short slotFrom(byte[] buf) {
        short slot = (short) (buf[ISO7816.OFFSET_P2] & 0xFF);
        if (slot >= store.size()) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return slot;
    }

    private void requirePin() {
        if (!pin.isSet() || !pin.isVerified()) {
            ISOException.throwIt(Const.SW_PIN_REQUIRED);
        }
    }

    // ---- APDU plumbing ----

    /** Receive a command body that stays in the APDU buffer. */
    private short receive(APDU apdu) {
        apdu.setIncomingAndReceive();
        return apdu.getIncomingLength();
    }

    /**
     * Receive a command body into dest, looping because one APDU buffer may not
     * hold a whole block.
     *
     * @return the number of bytes copied
     */
    private short receiveInto(APDU apdu, byte[] dest, short destOff) {
        // setIncomingAndReceive comes first. Both getOffsetCdata and
        // getIncomingLength are illegal use before it, and the JCRE answers 6F00.
        short read = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short cdata = apdu.getOffsetCdata();
        short expected = apdu.getIncomingLength();
        short total = (short) 0;

        // An extended-length body starts at offset 7 rather than 5. That is the
        // only sign JavaCard 2.2.2 gives of which encoding the host used.
        state[STATE_EXTENDED] = cdata == ISO7816.OFFSET_EXT_CDATA ? (short) 1 : (short) 0;

        if ((short) (destOff + expected) > (short) dest.length) {
            state[STATE_REQUEST] = (short) 0;
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Loop on the expected count, not on read > 0: calling receiveBytes once
        // the body is exhausted is illegal use, not a polite zero.
        while (total < expected) {
            Util.arrayCopyNonAtomic(buf, cdata, dest, (short) (destOff + total), read);
            total += read;
            if (total < expected) {
                read = apdu.receiveBytes(cdata);
            }
        }
        return total;
    }

    private void stage(short len) {
        state[STATE_TOTAL] = len;
        state[STATE_SENT] = (short) 0;
    }

    /**
     * Send the staged response.
     *
     * To an extended-length command, all of it at once. To a short one, up to
     * 255 bytes, with 61xx telling the host what is left. With ES256 keys no
     * response is over 255 bytes, so the 61xx path is a backstop that nothing
     * currently reaches.
     */
    private void sendStaged(APDU apdu) {
        short remaining = (short) (state[STATE_TOTAL] - state[STATE_SENT]);
        if (remaining <= (short) 0) {
            return;
        }

        // A host that sent an extended-length command expects the whole answer
        // in one response. Apple's stack (Safari, and Firefox on macOS) sends
        // every CTAP2 message that way and does not follow 61xx at all, so
        // chunking the reply to it is the same as not replying.
        if (state[STATE_EXTENDED] != (short) 0) {
            state[STATE_EXTENDED] = (short) 0;
            state[STATE_SENT] = state[STATE_TOTAL];
            apdu.setOutgoing();
            apdu.setOutgoingLength(remaining);
            apdu.sendBytesLong(outBuf, (short) 0, remaining);
            return;
        }

        short toSendLen = remaining > Const.MAX_CHUNK ? Const.MAX_CHUNK : remaining;
        byte[] buf = apdu.getBuffer();
        Util.arrayCopyNonAtomic(outBuf, state[STATE_SENT], buf, (short) 0, toSendLen);
        apdu.setOutgoingAndSend((short) 0, toSendLen);
        state[STATE_SENT] += toSendLen;

        short left = (short) (state[STATE_TOTAL] - state[STATE_SENT]);
        if (left > (short) 0) {
            short next = left > Const.MAX_CHUNK ? Const.MAX_CHUNK : left;
            ISOException.throwIt((short) (0x6100 | (next & 0xFF)));
        }
    }
}
