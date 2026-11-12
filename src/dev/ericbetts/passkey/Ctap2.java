package dev.ericbetts.passkey;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.framework.Util;

/**
 * The CTAP2 command layer: parse a CBOR request, produce a CBOR response.
 *
 * Transport is somebody else's problem. This class is handed a complete request
 * (command byte followed by CBOR) and writes a complete response (status byte
 * followed by CBOR), which is exactly the payload the NFC binding carries.
 *
 * Errors are returned as CTAP status bytes, never thrown, because a CTAP2
 * response with an error code is still a successful APDU exchange.
 */
public class Ctap2 {

    // Text keys used in requests and responses.
    private static final byte[] KEY_ID = {'i', 'd'};
    private static final byte[] KEY_ALG = {'a', 'l', 'g'};
    private static final byte[] KEY_TYPE = {'t', 'y', 'p', 'e'};
    private static final byte[] KEY_RK = {'r', 'k'};
    private static final byte[] KEY_UP = {'u', 'p'};
    private static final byte[] KEY_UV = {'u', 'v'};
    private static final byte[] PUBLIC_KEY = {'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y'};
    private static final byte[] VERSION_FIDO_2_0 = {'F', 'I', 'D', 'O', '_', '2', '_', '0'};
    private static final byte[] VERSION_U2F_V2 = {'U', '2', 'F', '_', 'V', '2'};
    private static final byte[] OPT_PLAT = {'p', 'l', 'a', 't'};
    private static final byte[] OPT_CLIENT_PIN = {'c', 'l', 'i', 'e', 'n', 't', 'P', 'i', 'n'};
    private static final byte[] TRANSPORT_NFC = {'n', 'f', 'c'};

    /**
     * The answer to SELECT by AID. The CTAP2 NFC binding says an authenticator
     * that speaks CTAP2 replies with this, and a U2F-only one replies "U2F_V2".
     */
    public static short copyVersionString(byte[] out, short outOff) {
        if (Const.ANSWER_SELECT_AS_U2F) {
            Util.arrayCopyNonAtomic(VERSION_U2F_V2, (short) 0, out, outOff,
                                    (short) VERSION_U2F_V2.length);
            return (short) VERSION_U2F_V2.length;
        }
        Util.arrayCopyNonAtomic(VERSION_FIDO_2_0, (short) 0, out, outOff,
                                (short) VERSION_FIDO_2_0.length);
        return (short) VERSION_FIDO_2_0.length;
    }

    private final CredentialStore store;
    private final Crypto crypto;
    private final Pin pin;

    /** Bound to the request being handled, so every decode is length-checked. */
    private final CborReader cbor;

    /** authData || clientDataHash, the exact bytes WebAuthn signs over. */
    private final byte[] signBuf;

    /** The relying party and challenge of an assertion still being walked. */
    private final byte[] pendingRpIdHash;
    private final byte[] pendingClientDataHash;

    /**
     * [0] next slot to scan, [1] assertions still available, [2] user verified,
     * and [3..6] what a parsed registration hands to the key generation step.
     */
    private final short[] pending;

    private static final short PENDING_NEXT = (short) 0;
    private static final short PENDING_LEFT = (short) 1;
    private static final short PENDING_UV = (short) 2;
    private static final short PENDING_SLOT = (short) 3;
    private static final short PENDING_USER_OFF = (short) 4;
    private static final short PENDING_USER_LEN = (short) 5;
    private static final short PENDING_CDH_OFF = (short) 6;

    public Ctap2(CredentialStore store, Crypto crypto, Pin pin, CborReader reader) {
        this.store = store;
        this.crypto = crypto;
        this.pin = pin;
        this.cbor = reader;

        signBuf = JCSystem.makeTransientByteArray(
            (short) (Const.LEN_AUTH_DATA + Const.LEN_CLIENT_DATA_HASH),
            JCSystem.CLEAR_ON_DESELECT);
        pendingRpIdHash = JCSystem.makeTransientByteArray(Const.LEN_RP_ID_HASH,
                                                          JCSystem.CLEAR_ON_DESELECT);
        pendingClientDataHash = JCSystem.makeTransientByteArray(Const.LEN_CLIENT_DATA_HASH,
                                                                JCSystem.CLEAR_ON_DESELECT);
        pending = JCSystem.makeTransientShortArray((short) 7, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Handle one request.
     *
     * @param req    request buffer, req[reqOff] is the command byte
     * @param reqLen total length including the command byte
     * @param out    response buffer, out[0] receives the status byte
     * @return total response length including the status byte
     */
    /**
     * @param firstCommand true when nothing else has been sent since the applet
     *                     was selected, which is what gates authenticatorReset
     */
    public short handle(byte[] req, short reqOff, short reqLen, byte[] out,
                        boolean firstCommand) {
        if (reqLen < (short) 1) {
            return error(out, Const.CTAP1_ERR_INVALID_LENGTH);
        }

        byte command = req[reqOff];
        short cborOff = (short) (reqOff + 1);
        short cborLen = (short) (reqLen - 1);
        cbor.bind(req, cborOff, cborLen);

        // Any command other than getNextAssertion ends a walk in progress.
        if (command != Const.CTAP_GET_NEXT_ASSERTION) {
            pending[PENDING_LEFT] = (short) 0;
        }

        // The switch is inlined rather than delegated, and makeCredential is
        // deliberately outside the try. Both cost stack frames, and this card
        // answers 6F00 when the JCVM stack runs out, which signing comes within
        // a frame or two of doing. See Crypto.signEs256.
        if (command == Const.CTAP_MAKE_CREDENTIAL) {
            return makeCredential(req, cborOff, cborLen, out);
        }

        try {
            switch (command) {
                case Const.CTAP_GET_INFO:
                    return getInfo(out);
                case Const.CTAP_GET_ASSERTION:
                    return getAssertion(req, cborOff, cborLen, out);
                case Const.CTAP_GET_NEXT_ASSERTION:
                    return getNextAssertion(out);
                case Const.CTAP_RESET:
                    return reset(out, firstCommand);
                case Const.CTAP_CLIENT_PIN:
                    return pin.handleClientPin(req, cborOff, cborLen, out);
                default:
                    return error(out, Const.CTAP1_ERR_INVALID_COMMAND);
            }
        } catch (ISOException e) {
            // Malformed CBOR from the host. A CTAP error is the useful answer;
            // an APDU-level failure would look like a broken card instead.
            return error(out, Const.CTAP2_ERR_INVALID_CBOR);
        } catch (CryptoException e) {
            // A bad EC point in a clientPIN request lands here. Still the host's
            // fault, and still a protocol answer rather than a transport one.
            return error(out, Const.CTAP1_ERR_INVALID_PARAMETER);
        }
    }

    // ---- commands ----

    /**
     * authenticatorGetInfo: {1: versions, 3: aaguid, 4: options, 5: maxMsgSize,
     * [6: pinUvAuthProtocols,] 0x0A: algorithms}
     *
     * Keys are written in ascending order, which is canonical for small integers.
     */
    private short getInfo(byte[] out) {
        short off = (short) 0;
        out[off++] = Const.CTAP2_OK;

        // pinUvAuthProtocols is only listed when the card can actually run one.
        // 1, 3, 4, 5, [6,] 7, 8, 9, 0x0A
        off = Cbor.mapHeader(out, off, pin.supportsClientPin() ? (short) 9 : (short) 8);

        // 1: versions
        off = Cbor.encodeInt(out, off, (short) 1);
        off = Cbor.arrayHeader(out, off, (short) 1);
        off = Cbor.encodeTstr(out, off, VERSION_FIDO_2_0, (short) 0, (short) VERSION_FIDO_2_0.length);

        // 3: aaguid
        off = Cbor.encodeInt(out, off, (short) 3);
        off = Cbor.bstrHeader(out, off, Const.LEN_AAGUID);
        off += WebAuthn.copyAaguid(out, off);

        // 4: options
        //
        // Absent and false mean different things here, and getting it wrong makes
        // platforms offer the user things the card cannot do:
        //
        //   "uv" absent        -> no built-in user verification at all.
        //        false         -> has one, e.g. a fingerprint reader, not enrolled.
        //   "clientPin" absent -> cannot accept a PIN from the client.
        //             false    -> can, and none is set yet, so please set one.
        //
        // A card with no reader and no working clientPIN has to omit both, or the
        // platform prompts to enrol something and the card then refuses.
        off = Cbor.encodeInt(out, off, (short) 4);
        short options = (short) 3;
        if (pin.supportsClientPin()) {
            options++;
        }
        if (Const.CLAIM_USER_VERIFICATION) {
            options++;
        }
        off = Cbor.mapHeader(out, off, options);

        off = Cbor.encodeTstr(out, off, KEY_RK, (short) 0, (short) KEY_RK.length);
        out[off++] = Cbor.TRUE;
        off = Cbor.encodeTstr(out, off, KEY_UP, (short) 0, (short) KEY_UP.length);
        out[off++] = Cbor.TRUE;
        if (Const.CLAIM_USER_VERIFICATION) {
            // true, not false: false would mean "supported but not configured",
            // and invite the platform to walk the user through enrolling it.
            off = Cbor.encodeTstr(out, off, KEY_UV, (short) 0, (short) KEY_UV.length);
            out[off++] = Cbor.TRUE;
        }
        off = Cbor.encodeTstr(out, off, OPT_PLAT, (short) 0, (short) OPT_PLAT.length);
        out[off++] = Cbor.FALSE;
        if (pin.supportsClientPin()) {
            off = Cbor.encodeTstr(out, off, OPT_CLIENT_PIN, (short) 0, (short) OPT_CLIENT_PIN.length);
            out[off++] = pin.isSet() ? Cbor.TRUE : Cbor.FALSE;
            // No pinUvAuthToken option. In CTAP 2.1 that promises clientPIN
            // subcommand 0x09, getPinUvAuthTokenUsingPinWithPermissions, which
            // is not implemented here. Advertising it made libfido2 call it and
            // fail; without it, hosts use getPinToken (0x05), which is.
        }

        // 5: maxMsgSize
        off = Cbor.encodeInt(out, off, (short) 5);
        off = Cbor.encodeInt(out, off, Const.MAX_REQUEST);

        // 6: pinUvAuthProtocols, most preferred first.
        if (pin.supportsClientPin()) {
            off = Cbor.encodeInt(out, off, (short) 6);
            off = Cbor.arrayHeader(out, off, (short) 2);
            off = Cbor.encodeInt(out, off, Const.PIN_PROTOCOL_2);
            off = Cbor.encodeInt(out, off, Const.PIN_PROTOCOL_1);
        }

        // 7: maxCredentialCountInList, 8: maxCredentialIdLength, 9: transports.
        // A platform filtering its authenticator list on any of these would skip
        // a card that declares none of them, and all three are simply true here.
        off = Cbor.encodeInt(out, off, (short) 7);
        off = Cbor.encodeInt(out, off, Const.SLOTS);

        off = Cbor.encodeInt(out, off, (short) 8);
        off = Cbor.encodeInt(out, off, Const.LEN_CRED_ID);

        off = Cbor.encodeInt(out, off, (short) 9);
        off = Cbor.arrayHeader(out, off, (short) 1);
        off = Cbor.encodeTstr(out, off, TRANSPORT_NFC, (short) 0, (short) TRANSPORT_NFC.length);

        // 0x0A: algorithms
        off = Cbor.encodeInt(out, off, (short) 0x0A);
        off = Cbor.arrayHeader(out, off, (short) 1);
        off = Cbor.mapHeader(out, off, (short) 2);
        off = Cbor.encodeTstr(out, off, KEY_ALG, (short) 0, (short) KEY_ALG.length);
        off = Cbor.encodeInt(out, off, Const.COSE_ALG_ES256);
        off = Cbor.encodeTstr(out, off, KEY_TYPE, (short) 0, (short) KEY_TYPE.length);
        off = Cbor.encodeTstr(out, off, PUBLIC_KEY, (short) 0, (short) PUBLIC_KEY.length);

        return off;
    }

    /**
     * authenticatorMakeCredential.
     *
     * The clientDataHash is signed alongside authData to form the self
     * attestation, so it has to be a real 32-byte hash rather than merely
     * present. What else matters is rp.id, which becomes the rpIdHash, user.id,
     * which makes the credential discoverable, and pubKeyCredParams, which has
     * to offer ES256.
     */
    private short makeCredential(byte[] req, short off, short len, byte[] out) {
        // Parsing runs in its own call so its frame is gone before genKeyPair.
        byte status = parseRegistration(req, off, len);
        if (status != Const.CTAP2_OK) {
            return error(out, status);
        }

        Credential credential = store.get(pending[PENDING_SLOT]);
        short userIdLen = pending[PENDING_USER_LEN];
        credential.create(pendingRpIdHash, (short) 0,
                          userIdLen > (short) 0 ? req : null,
                          pending[PENDING_USER_OFF], userIdLen);

        out[(short) 0] = Const.CTAP2_OK;
        short written = WebAuthn.buildAttestationObject(credential, crypto, out, (short) 1,
                                                        userVerified(),
                                                        req, pending[PENDING_CDH_OFF]);
        return (short) (1 + written);
    }

    /**
     * Validate a registration request and stash what the key generation needs.
     *
     * Separate from makeCredential for two reasons. Hostile input dies in here,
     * where a malformed-CBOR exception can be turned into a CTAP status. And the
     * frame is popped before key generation and signing run: the JCVM stack
     * on this card is nearly full by then, so the parsing must not still be
     * on it.
     *
     * @return CTAP2_OK, or the status byte to answer with
     */
    private byte parseRegistration(byte[] req, short off, short len) {
        try {
            if (len <= (short) 0 || cbor.majorType(off) != Cbor.MAJOR_MAP) {
                return Const.CTAP2_ERR_INVALID_CBOR;
            }

            short clientDataHash = cbor.findIntKey(off, (short) 1);
            short rp = cbor.findIntKey(off, (short) 2);
            short user = cbor.findIntKey(off, (short) 3);
            short params = cbor.findIntKey(off, (short) 4);
            if (clientDataHash < 0 || rp < 0 || user < 0 || params < 0) {
                return Const.CTAP2_ERR_MISSING_PARAMETER;
            }
            if (cbor.majorType(clientDataHash) != Cbor.MAJOR_BSTR
                    || cbor.argument(clientDataHash) != Const.LEN_CLIENT_DATA_HASH) {
                return Const.CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            }
            short cdhOff = cbor.payloadOffset(clientDataHash);
            cbor.requireBytes(cdhOff, Const.LEN_CLIENT_DATA_HASH);

            if (!offersEs256(req, params)) {
                return Const.CTAP2_ERR_UNSUPPORTED_ALGORITHM;
            }

            // makeCredential carries pinUvAuthParam in key 8, the protocol in key 9.
            short pinStatus = pin.checkRequestAuth(req,
                cbor.findIntKey(off, (short) 8),
                cbor.findIntKey(off, (short) 9),
                clientDataHash);
            if (pinStatus != Const.CTAP2_OK) {
                return (byte) pinStatus;
            }

            // rp.id is a text string; the rpIdHash is its SHA-256.
            short rpId = cbor.findTextKey(rp, KEY_ID, (short) 0, (short) KEY_ID.length);
            if (rpId < 0 || cbor.majorType(rpId) != Cbor.MAJOR_TSTR) {
                return Const.CTAP2_ERR_MISSING_PARAMETER;
            }
            short rpIdOff = cbor.payloadOffset(rpId);
            short rpIdLen = cbor.argument(rpId);
            cbor.requireBytes(rpIdOff, rpIdLen);
            crypto.digest(req, rpIdOff, rpIdLen, pendingRpIdHash, (short) 0);

            short exclude = cbor.findIntKey(off, (short) 5);
            if (exclude >= 0 && firstKnown(req, exclude) >= (short) 0) {
                return Const.CTAP2_ERR_CREDENTIAL_EXCLUDED;
            }

            // A discoverable credential keeps the user handle, so the card can
            // offer it later without the site naming it.
            boolean resident = false;
            short options = cbor.findIntKey(off, (short) 7);
            if (options >= 0 && isOptionTrue(req, options, KEY_RK)) {
                resident = true;
            }

            short userIdOff = (short) -1;
            short userIdLen = (short) 0;
            if (resident) {
                short userId = cbor.findTextKey(user, KEY_ID, (short) 0, (short) KEY_ID.length);
                if (userId < 0 || cbor.majorType(userId) != Cbor.MAJOR_BSTR) {
                    return Const.CTAP2_ERR_MISSING_PARAMETER;
                }
                userIdLen = cbor.argument(userId);
                if (userIdLen <= (short) 0 || userIdLen > Const.MAX_USER_ID) {
                    return Const.CTAP1_ERR_INVALID_PARAMETER;
                }
                userIdOff = cbor.payloadOffset(userId);
                // The length came from the request; make sure the bytes did too,
                // or the copy later takes whatever the last request left behind.
                cbor.requireBytes(userIdOff, userIdLen);
            }

            short slot = store.slotForRegistration(pendingRpIdHash, (short) 0,
                                                   req, userIdOff, userIdLen);
            if (slot < (short) 0) {
                return Const.CTAP2_ERR_KEY_STORE_FULL;
            }

            pending[PENDING_SLOT] = slot;
            pending[PENDING_USER_OFF] = userIdOff;
            pending[PENDING_USER_LEN] = userIdLen;
            pending[PENDING_CDH_OFF] = cdhOff;
            return Const.CTAP2_OK;
        } catch (ISOException e) {
            return Const.CTAP2_ERR_INVALID_CBOR;
        }
    }

    /**
     * authenticatorGetAssertion.
     *
     * rpId arrives as a text string here, unlike makeCredential where it is nested
     * in the rp map, and unlike the vendor protocol where the host sends the hash.
     */
    private short getAssertion(byte[] req, short off, short len, byte[] out) {
        if (len <= (short) 0) {
            return error(out, Const.CTAP2_ERR_INVALID_CBOR);
        }
        if (cbor.majorType(off) != Cbor.MAJOR_MAP) {
            return error(out, Const.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        short rpId = cbor.findIntKey(off, (short) 1);
        short clientDataHash = cbor.findIntKey(off, (short) 2);
        if (rpId < 0 || clientDataHash < 0) {
            return error(out, Const.CTAP2_ERR_MISSING_PARAMETER);
        }
        if (cbor.majorType(rpId) != Cbor.MAJOR_TSTR
                || cbor.majorType(clientDataHash) != Cbor.MAJOR_BSTR
                || cbor.argument(clientDataHash) != Const.LEN_CLIENT_DATA_HASH) {
            return error(out, Const.CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        }

        if (store.isEmpty()) {
            return error(out, Const.CTAP2_ERR_NO_CREDENTIALS);
        }

        // getAssertion carries pinUvAuthParam in key 6 and the protocol in key 7.
        short pinStatus = pin.checkRequestAuth(req,
            cbor.findIntKey(off, (short) 6),
            cbor.findIntKey(off, (short) 7),
            clientDataHash);
        if (pinStatus != Const.CTAP2_OK) {
            return error(out, (byte) pinStatus);
        }

        short rpIdOff = cbor.payloadOffset(rpId);
        short rpIdLen = cbor.argument(rpId);
        cbor.requireBytes(rpIdOff, rpIdLen);
        crypto.digest(req, rpIdOff, rpIdLen, pendingRpIdHash, (short) 0);

        cbor.requireBytes(cbor.payloadOffset(clientDataHash), Const.LEN_CLIENT_DATA_HASH);
        Util.arrayCopyNonAtomic(req, cbor.payloadOffset(clientDataHash),
                                pendingClientDataHash, (short) 0, Const.LEN_CLIENT_DATA_HASH);
        pending[PENDING_UV] = userVerified() ? (short) 1 : (short) 0;

        short allowList = cbor.findIntKey(off, (short) 3);
        short slot;
        short total;

        if (allowList >= 0 && cbor.argument(allowList) > (short) 0) {
            // The site named the credentials it will accept, so pick one of those.
            slot = firstKnown(req, allowList);
            if (slot < (short) 0 || !store.get(slot).matchesRp(pendingRpIdHash, (short) 0)) {
                return error(out, Const.CTAP2_ERR_NO_CREDENTIALS);
            }
            total = (short) 1;
        } else {
            // No allowList: offer every credential this card holds for the site.
            slot = store.findByRp(pendingRpIdHash, (short) 0, (short) 0);
            if (slot < (short) 0) {
                return error(out, Const.CTAP2_ERR_NO_CREDENTIALS);
            }
            total = store.countByRp(pendingRpIdHash, (short) 0);
        }

        pending[PENDING_NEXT] = (short) (slot + 1);
        pending[PENDING_LEFT] = (short) (total - 1);
        return emitAssertion(slot, total, out);
    }

    /**
     * authenticatorGetNextAssertion: the rest of the credentials the last
     * getAssertion found, one per call.
     *
     * CTAP2 says a walk expires 30 seconds after the previous assertion. There
     * is no clock on a JavaCard, so the rule here is stricter instead of
     * approximated: any other command ends the walk, and so does losing
     * selection, since the state lives in CLEAR_ON_DESELECT memory. On a card
     * that is powered by the reader's field, putting it down ends the walk
     * immediately, which is rather less than 30 seconds.
     */
    private short getNextAssertion(byte[] out) {
        if (pending[PENDING_LEFT] <= (short) 0) {
            return error(out, Const.CTAP2_ERR_NOT_ALLOWED);
        }

        short slot = store.findByRp(pendingRpIdHash, (short) 0, pending[PENDING_NEXT]);
        if (slot < (short) 0) {
            pending[PENDING_LEFT] = (short) 0;
            return error(out, Const.CTAP2_ERR_NOT_ALLOWED);
        }

        pending[PENDING_NEXT] = (short) (slot + 1);
        pending[PENDING_LEFT]--;
        // numberOfCredentials appears on the first assertion only.
        return emitAssertion(slot, (short) 1, out);
    }

    /**
     * authenticatorReset: wipe every credential and the PIN.
     *
     * Destroying everything on the card must not be a single unauthenticated
     * APDU. CTAP2 guards it with user presence and a ten-second window from
     * power-up; JavaCard has no clock, so the equivalent here is that reset has
     * to be the very first command after the applet is selected. Presenting the
     * card is the user presence, and anything else in between means the request
     * did not come from someone who just tapped it deliberately.
     */
    private short reset(byte[] out, boolean firstCommand) {
        if (!firstCommand) {
            return error(out, Const.CTAP2_ERR_NOT_ALLOWED);
        }
        store.clearAll();
        pin.factoryReset();
        return error(out, Const.CTAP2_OK);
    }

    /**
     * Sign and encode one assertion.
     *
     * {1: {"id", "type"}, 2: authData, 3: signature [, 4: user] [, 5: count]}
     *
     * @param total how many credentials matched, which decides whether
     *              numberOfCredentials is worth sending
     */
    private short emitAssertion(short slot, short total, byte[] out) {
        Credential credential = store.get(slot);
        credential.incrementSignCount();

        boolean uv = pending[PENDING_UV] != (short) 0;
        short authDataLen = WebAuthn.buildAuthData(credential, signBuf, (short) 0, false, uv);
        Util.arrayCopyNonAtomic(pendingClientDataHash, (short) 0, signBuf, authDataLen,
                                Const.LEN_CLIENT_DATA_HASH);

        short entries = (short) 3;
        if (credential.isDiscoverable()) {
            entries++;
        }
        if (total > (short) 1) {
            entries++;
        }

        short o = (short) 0;
        out[o++] = Const.CTAP2_OK;
        o = Cbor.mapHeader(out, o, entries);

        o = Cbor.encodeInt(out, o, (short) 1);
        o = Cbor.mapHeader(out, o, (short) 2);
        // Canonical order for text keys is by length first, so "id" precedes "type".
        o = Cbor.encodeTstr(out, o, KEY_ID, (short) 0, (short) KEY_ID.length);
        o = Cbor.bstrHeader(out, o, Const.LEN_CRED_ID);
        o += credential.copyCredId(out, o);
        o = Cbor.encodeTstr(out, o, KEY_TYPE, (short) 0, (short) KEY_TYPE.length);
        o = Cbor.encodeTstr(out, o, PUBLIC_KEY, (short) 0, (short) PUBLIC_KEY.length);

        o = Cbor.encodeInt(out, o, (short) 2);
        o = Cbor.encodeBstr(out, o, signBuf, (short) 0, authDataLen);

        o = Cbor.encodeInt(out, o, (short) 3);
        // A DER ECDSA signature varies in length but always needs a 2-byte header.
        short sigStart = (short) (o + 2);
        short sigLen = crypto.signEs256(credential.getPrivateKey(),
                                        signBuf, (short) 0,
                                        (short) (authDataLen + Const.LEN_CLIENT_DATA_HASH),
                                        null, (short) 0, (short) 0,
                                        out, sigStart);
        Cbor.fillReservedBstrHeader(out, o, sigLen, (short) 2);
        o = (short) (sigStart + sigLen);

        if (credential.isDiscoverable()) {
            o = Cbor.encodeInt(out, o, (short) 4);
            o = Cbor.mapHeader(out, o, (short) 1);
            o = Cbor.encodeTstr(out, o, KEY_ID, (short) 0, (short) KEY_ID.length);
            o = Cbor.bstrHeader(out, o, credential.getUserIdLength());
            o += credential.copyUserId(out, o);
        }

        if (total > (short) 1) {
            o = Cbor.encodeInt(out, o, (short) 5);
            o = Cbor.encodeInt(out, o, total);
        }

        return o;
    }

    /**
     * Whether this operation carries user verification.
     *
     * Either the PIN was really checked this session, or the card claims
     * possession as verification. See Const.CLAIM_USER_VERIFICATION.
     */
    private boolean userVerified() {
        return Const.CLAIM_USER_VERIFICATION || pin.isVerified();
    }

    // ---- request helpers ----

    /** True if pubKeyCredParams contains an entry with alg -7. */
    private boolean offersEs256(byte[] req, short arrayOff) {
        if (cbor.majorType(arrayOff) != Cbor.MAJOR_ARRAY) {
            return false;
        }
        short count = cbor.argument(arrayOff);
        short entry = cbor.payloadOffset(arrayOff);

        for (short i = (short) 0; i < count; i++) {
            if (cbor.majorType(entry) == Cbor.MAJOR_MAP) {
                short alg = cbor.findTextKey(entry, KEY_ALG, (short) 0, (short) KEY_ALG.length);
                if (alg >= 0 && cbor.majorType(alg) == Cbor.MAJOR_NEGINT
                        && cbor.argument(alg) == (short) (-1 - Const.COSE_ALG_ES256)) {
                    return true;
                }
            }
            entry = cbor.skip(entry);
        }
        return false;
    }

    /** True if a boolean option is present and set. */
    private boolean isOptionTrue(byte[] req, short mapOff, byte[] name) {
        if (cbor.majorType(mapOff) != Cbor.MAJOR_MAP) {
            return false;
        }
        short value = cbor.findTextKey(mapOff, name, (short) 0, (short) name.length);
        return value >= 0 && cbor.byteAt(value) == Cbor.TRUE;
    }

    /**
     * The slot named by the first entry of a credential-descriptor list that this
     * card actually holds, or -1.
     *
     * Serves both allowList and excludeList: one asks which of these to use, the
     * other asks whether any of these already exist.
     */
    private short firstKnown(byte[] req, short arrayOff) {
        if (cbor.majorType(arrayOff) != Cbor.MAJOR_ARRAY) {
            return (short) -1;
        }
        short count = cbor.argument(arrayOff);
        short entry = cbor.payloadOffset(arrayOff);

        for (short i = (short) 0; i < count; i++) {
            if (cbor.majorType(entry) == Cbor.MAJOR_MAP) {
                short id = cbor.findTextKey(entry, KEY_ID, (short) 0, (short) KEY_ID.length);
                if (id >= 0 && cbor.majorType(id) == Cbor.MAJOR_BSTR
                        && cbor.argument(id) == Const.LEN_CRED_ID) {
                    short slot = store.findByCredId(req, cbor.payloadOffset(id));
                    if (slot >= (short) 0) {
                        return slot;
                    }
                }
            }
            entry = cbor.skip(entry);
        }
        return (short) -1;
    }

    private static short error(byte[] out, byte status) {
        out[(short) 0] = status;
        return (short) 1;
    }
}
