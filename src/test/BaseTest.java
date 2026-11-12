package test;

import com.licel.jcardsim.utils.AIDUtil;
import dev.ericbetts.passkey.Passkey;
import javacard.framework.AID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import pro.javacard.engine.EngineSession;
import pro.javacard.engine.JavaCardEngine;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BaseTest {

    /** The FIDO AID: this is what a platform selects. */
    protected static final String APPLET_AID = "A0000006472F0001";

    /**
     * A second instance, only so tests have something else to SELECT.
     * Deselecting is the only way to check what the applet drops when it loses
     * selection, and that is different from what a card reset drops.
     */
    protected static final String OTHER_AID = "A0000006472F0002";

    /** The vendor protocol moved to 0xE0 when CTAP2 claimed 0x80. */
    protected static final byte CLA = (byte) 0xE0;
    protected static final byte CLA_CTAP = (byte) 0x80;
    protected static final byte CLA_CTAP_CHAINED = (byte) 0x90;
    protected static final byte INS_NFCCTAP_MSG = (byte) 0x10;
    protected static final byte INS_GET_INFO = (byte) 0x01;
    protected static final byte INS_SET_PIN = (byte) 0x02;
    protected static final byte INS_VERIFY_PIN = (byte) 0x04;
    protected static final byte INS_MAKE_CREDENTIAL = (byte) 0x10;
    protected static final byte INS_GET_CREDENTIAL = (byte) 0x12;
    protected static final byte INS_GET_ASSERTION = (byte) 0x14;
    protected static final byte INS_DELETE = (byte) 0x16;

    protected static final int SW_OK = 0x9000;
    protected static final int SW_PIN_REQUIRED = 0x6982;
    protected static final int SW_PIN_ALREADY_SET = 0x6985;
    protected static final int SW_RP_MISMATCH = 0x6A82;
    protected static final int SW_NO_CREDENTIAL = 0x6A88;
    protected static final int SW_CREDENTIAL_EXISTS = 0x6A89;
    protected static final int SW_WRONG_LENGTH = 0x6700;

    protected static final byte[] PIN = "1234".getBytes();

    protected JavaCardEngine engine;
    protected EngineSession session;

    @BeforeEach
    public void setup() {
        engine = JavaCardEngine.create();
        engine.installApplet(AIDUtil.create(APPLET_AID), Passkey.class);
        engine.installApplet(AIDUtil.create(OTHER_AID), Passkey.class);
        session = engine.connect();
        selectApplet();
    }

    @AfterEach
    public void tearDown() {
        if (session != null) {
            session.close();
        }
    }

    protected void selectApplet() {
        session.transmitCommand(AIDUtil.select(AIDUtil.create(APPLET_AID)));
    }

    /**
     * Power-cycle the card, which is what every contactless tap does: it clears the
     * PIN-verified flag and all CLEAR_ON_DESELECT state, but keeps EEPROM.
     */
    protected void reselect() {
        session.close();
        engine.reset();
        session = engine.connect();
        selectApplet();
    }

    /**
     * Deselect and reselect without powering the card down.
     *
     * Distinct from {@link #reselect()}, which resets the card. A reset clears
     * far more, so a test that only ever resets cannot tell whether deselect
     * cleans up properly.
     */
    protected void deselectAndReselect() {
        session.transmitCommand(AIDUtil.select(AIDUtil.create(OTHER_AID)));
        selectApplet();
    }

    // ---- APDU plumbing ----

    /** Raw exchange, returns data || SW. */
    protected byte[] transmit(byte ins, byte p1, byte p2, byte[] data) {
        byte[] apdu;
        if (data == null || data.length == 0) {
            apdu = new byte[]{CLA, ins, p1, p2, 0x00};
        } else {
            apdu = new byte[6 + data.length];
            apdu[0] = CLA;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;
            apdu[4] = (byte) data.length;
            System.arraycopy(data, 0, apdu, 5, data.length);
            apdu[5 + data.length] = 0x00; // Le, making this a case-4 APDU
        }
        return session.transmitCommand(apdu);
    }

    protected int sw(byte[] response) {
        return ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    }

    /**
     * Send a command and drain any 61xx continuation, returning the concatenated data.
     * Asserts a final 9000.
     */
    protected byte[] send(byte ins, byte p1, byte p2, byte[] data) {
        byte[] response = transmit(ins, p1, p2, data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int status = sw(response);
        out.write(response, 0, response.length - 2);

        while ((status & 0xFF00) == 0x6100) {
            byte le = (byte) (status & 0xFF);
            response = session.transmitCommand(new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, le});
            status = sw(response);
            out.write(response, 0, response.length - 2);
        }

        assertEquals(SW_OK, status, "expected 9000, got " + Integer.toHexString(status));
        return out.toByteArray();
    }

    protected byte[] send(byte ins, byte[] data) {
        return send(ins, (byte) 0x00, (byte) 0x00, data);
    }

    protected void assertSw(int expected, byte[] response) {
        assertEquals(expected, sw(response),
            "expected " + Integer.toHexString(expected) + ", got " + Integer.toHexString(sw(response)));
    }

    // ---- protocol shorthands ----

    protected void setPin(byte[] value) {
        assertSw(SW_OK, transmit(INS_SET_PIN, (byte) 0x00, (byte) 0x00, value));
    }

    protected void verifyPin(byte[] value) {
        assertSw(SW_OK, transmit(INS_VERIFY_PIN, (byte) 0x00, (byte) 0x00, value));
    }

    protected void unlock() {
        setPin(PIN);
        verifyPin(PIN);
    }

    // ---- CTAP2 ----

    /**
     * Send a CTAP2 command and drain the response.
     *
     * Requests longer than 255 bytes go out as chained APDUs, which is how a
     * platform sends a real makeCredential over NFC.
     */
    protected CtapResponse ctap(byte command, byte[] cbor) {
        byte[] payload = Cbor.concat(new byte[]{command}, cbor == null ? new byte[0] : cbor);

        byte[] response = null;
        int off = 0;
        while (off < payload.length) {
            int chunk = Math.min(255, payload.length - off);
            boolean last = off + chunk == payload.length;

            byte[] apdu = new byte[5 + chunk + (last ? 1 : 0)];
            apdu[0] = last ? CLA_CTAP : CLA_CTAP_CHAINED;
            apdu[1] = INS_NFCCTAP_MSG;
            apdu[2] = 0x00;
            apdu[3] = 0x00;
            apdu[4] = (byte) chunk;
            System.arraycopy(payload, off, apdu, 5, chunk);
            if (last) {
                apdu[5 + chunk] = 0x00;
            }
            response = session.transmitCommand(apdu);
            off += chunk;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int status = sw(response);
        out.write(response, 0, response.length - 2);
        while ((status & 0xFF00) == 0x6100) {
            response = session.transmitCommand(
                new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, (byte) (status & 0xFF)});
            status = sw(response);
            out.write(response, 0, response.length - 2);
        }
        assertEquals(SW_OK, status, "CTAP exchange should end 9000, got " + Integer.toHexString(status));

        byte[] body = out.toByteArray();
        assertEquals(true, body.length >= 1, "a CTAP response always carries a status byte");
        byte[] cborOut = new byte[body.length - 1];
        System.arraycopy(body, 1, cborOut, 0, cborOut.length);
        return new CtapResponse(body[0], cborOut);
    }

    /** A CTAP2 status byte and the CBOR that follows it. */
    protected static class CtapResponse {
        public final byte status;
        public final byte[] cbor;

        CtapResponse(byte status, byte[] cbor) {
            this.status = status;
            this.cbor = cbor;
        }
    }

    /** authenticatorGetInfo, parsed. */
    protected CtapInfo ctapInfo() {
        return CtapInfo.parse(ctap(CtapRequests.CMD_GET_INFO, null).cbor);
    }

    /** How many credential slots the card was built with. */
    protected int slots() {
        return send(INS_GET_INFO, null)[3] & 0xFF;
    }

    /** The clientDataHash the vendor helpers register with, so tests can verify the signature. */
    protected static final int REGISTER_CHALLENGE = 77;

    /**
     * Register a credential and parse the attestation object it returns.
     *
     * The vendor protocol takes rpIdHash || clientDataHash: self attestation
     * signs the challenge, so it has to be told what the challenge is.
     */
    protected AttestationObject register(byte[] rpIdHash) {
        return AttestationObject.parse(
            send(INS_MAKE_CREDENTIAL, concat(rpIdHash, hash(REGISTER_CHALLENGE))));
    }

    /** Register over an existing credential (P1 = 0x01). */
    protected AttestationObject replace(byte[] rpIdHash) {
        return AttestationObject.parse(send(INS_MAKE_CREDENTIAL, (byte) 0x01, (byte) 0x00,
            concat(rpIdHash, hash(REGISTER_CHALLENGE))));
    }

    /** Read the stored credential back without regenerating it. */
    protected CredentialRecord readCredential() {
        return CredentialRecord.parse(send(INS_GET_CREDENTIAL, null));
    }

    /** A distinct 32-byte hash, deterministic per seed so tests stay reproducible. */
    protected byte[] hash(int seed) {
        byte[] h = new byte[32];
        for (int i = 0; i < h.length; i++) {
            h[i] = (byte) (seed * 31 + i);
        }
        return h;
    }

    protected byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
