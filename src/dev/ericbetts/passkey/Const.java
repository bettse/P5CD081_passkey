package dev.ericbetts.passkey;

/**
 * Protocol constants for the single-slot passkey applet.
 *
 * AID: A0:00:00:06:47:2E:50:41:53:53:01
 */
public final class Const {

    private Const() {
    }

    public static final byte VERSION = (byte) 0x01;

    /** CTAP2 over NFC lives on CLA 0x80, so the vendor protocol moved to 0xE0. */
    public static final byte CLA_CTAP = (byte) 0x80;
    public static final byte CLA_VENDOR = (byte) 0xE0;
    public static final byte CLA_ISO = (byte) 0x00;

    /** ISO 7816-4 command chaining: more blocks follow. */
    public static final byte CLA_CHAINING_BIT = (byte) 0x10;

    /**
     * Answer SELECT with "U2F_V2" rather than "FIDO_2_0".
     *
     * The NFC binding says an authenticator replies "U2F_V2" when it speaks
     * CTAP1/U2F and "FIDO_2_0" when it only speaks CTAP2. This card only speaks
     * CTAP2, so "FIDO_2_0" is the truthful answer. Apple's stack accepts either
     * string. The switch is left from an earlier experiment and stays false.
     */
    public static final boolean ANSWER_SELECT_AS_U2F = false;

    /** CTAP1/U2F GET_VERSION, on CLA 0x00. */
    public static final byte INS_U2F_VERSION = (byte) 0x03;

    /** CTAP2 NFC binding. */
    public static final byte INS_NFCCTAP_MSG = (byte) 0x10;
    public static final byte INS_NFCCTAP_GETRESPONSE = (byte) 0x11;

    public static final byte INS_GET_INFO = (byte) 0x01;
    public static final byte INS_SET_PIN = (byte) 0x02;
    public static final byte INS_VERIFY_PIN = (byte) 0x04;
    public static final byte INS_MAKE_CREDENTIAL = (byte) 0x10;
    public static final byte INS_GET_CREDENTIAL = (byte) 0x12;
    public static final byte INS_GET_ASSERTION = (byte) 0x14;
    public static final byte INS_DELETE = (byte) 0x16;
    public static final byte INS_PROBE_ALG = (byte) 0x1C;
    public static final byte INS_MEMORY = (byte) 0x1E;
    public static final byte INS_GET_RESPONSE = (byte) 0xC0;

    /** P1 for SET_PIN / MAKE_CREDENTIAL. */
    public static final byte P1_INITIAL = (byte) 0x00;
    public static final byte P1_REPLACE = (byte) 0x01;

    public static final short LEN_SHA256 = (short) 32;
    public static final short LEN_RP_ID_HASH = (short) 32;
    public static final short LEN_CLIENT_DATA_HASH = (short) 32;
    public static final short LEN_CRED_ID = (short) 16;
    public static final short LEN_SIGN_COUNT = (short) 4;

    /** rpIdHash(32) || flags(1) || signCount(4) */
    public static final short LEN_AUTH_DATA = (short) 37;

    public static final byte PIN_TRIES = (byte) 8;
    /** CTAP2 PIN policy: 4 to 63 bytes of UTF-8. */
    public static final byte PIN_MIN_LEN = (byte) 4;
    public static final byte PIN_MAX_LEN = (byte) 63;

    /** What is actually stored: LEFT(SHA-256(pin), 16), CTAP2's pinHash. */
    public static final short LEN_PIN_HASH = (short) 16;
    /** pinUvAuthParam under protocol 1: an HMAC-SHA-256 truncated to 16 bytes. */
    public static final short LEN_PIN_AUTH = (short) 16;
    /** Under protocol 2 it is the whole 32-byte HMAC. */
    public static final short LEN_PIN_AUTH_P2 = (short) 32;

    public static final byte PIN_PROTOCOL_1 = (byte) 1;
    public static final byte PIN_PROTOCOL_2 = (byte) 2;

    /**
     * Protocol 2's shared secret is two keys, HMAC then AES, so the buffer holds
     * both. Protocol 1 uses one key for both jobs and stores it twice, which
     * keeps every caller free of the difference.
     */
    public static final short LEN_SHARED_SECRET = (short) 64;
    public static final short SHARED_HMAC_KEY = (short) 0;
    public static final short SHARED_AES_KEY = (short) 32;
    public static final short LEN_PIN_TOKEN = (short) 16;
    public static final short LEN_AES_BLOCK = (short) 16;

    /**
     * Claim built-in user verification.
     *
     * This card has no sensor, no button and no keypad, so it cannot verify a
     * human in the way "uv" normally means. Setting this says: possession of
     * this card, presented to a reader, IS the verification.
     *
     * That is a deliberate claim about a deliberate threat model. This is a
     * break-glass card holding one credential, kept somewhere physical, and its
     * security is the safe it lives in rather than anything the chip does. A
     * relying party reading UV=1 from it learns that whoever tapped it had it,
     * which for this card is the whole of the authentication story.
     *
     * Set it to false and the card reverts to asserting only user presence,
     * which is the honest answer for a card left on a desk.
     */
    public static final boolean CLAIM_USER_VERIFICATION = true;

    /** WebAuthn authenticator data flags. */
    public static final byte FLAG_USER_PRESENT = (byte) 0x01;
    public static final byte FLAG_USER_VERIFIED = (byte) 0x04;
    /** AT: attestedCredentialData is present, set only on registration. */
    public static final byte FLAG_ATTESTED = (byte) 0x40;

    /** Vendor DELETE: erase every slot rather than one. */
    public static final byte P2_ALL_SLOTS = (byte) 0xFF;

    /** GET_INFO status byte. */
    public static final byte INFO_HAS_CREDENTIAL = (byte) 0x01;
    public static final byte INFO_PIN_SET = (byte) 0x02;
    public static final byte INFO_PIN_VERIFIED = (byte) 0x04;

    public static final short SW_PIN_REQUIRED = (short) 0x6982;
    public static final short SW_PIN_ALREADY_SET = (short) 0x6985;
    public static final short SW_CBOR_UNSUPPORTED = (short) 0x6A80;
    public static final short SW_RP_MISMATCH = (short) 0x6A82;
    public static final short SW_NO_CREDENTIAL = (short) 0x6A88;
    public static final short SW_CREDENTIAL_EXISTS = (short) 0x6A89;
    public static final short SW_INTERNAL = (short) 0x6F00;

    // ---- WebAuthn / COSE ----

    /** COSE_Key labels. */
    public static final short COSE_KTY = (short) 1;
    public static final short COSE_ALG = (short) 3;

    public static final short COSE_KTY_EC2 = (short) 2;
    public static final short COSE_ALG_ES256 = (short) -7;
    public static final short COSE_ALG_ECDH_ES_HKDF_256 = (short) -25;

    /** EC2 key labels. They reuse -1..-3, which RSA keys spend on n and e. */
    public static final short COSE_EC_CRV = (short) -1;
    public static final short COSE_EC_X = (short) -2;
    public static final short COSE_EC_Y = (short) -3;
    public static final short COSE_CRV_P256 = (short) 1;

    public static final short LEN_AAGUID = (short) 16;

    /**
     * How many credentials the card holds. One, deliberately.
     *
     * Every slot's key pair is allocated at install time, so raising this
     * trades EEPROM for capacity. Everything above this constant is written to
     * work at any value, so changing it is the only edit needed.
     */
    public static final short SLOTS = (short) 1;

    /** WebAuthn caps user.id at 64 bytes. */
    public static final short MAX_USER_ID = (short) 64;

    // ---- values the JavaCard 2.2.2 SDK is too old to name ----
    //
    // The 2.2.2 headers predate these, so they go in as literals rather than
    // constants. The P5CD081 has 256-bit EC keys. It does not have
    // ALG_EC_SVDP_DH_PLAIN, whatever JCAlgTest says: getInstance throws
    // NO_SUCH_ALGORITHM, and Pin falls back when it does.

    /** KeyAgreement.ALG_EC_SVDP_DH_PLAIN, added in JavaCard 3.0.1. */
    public static final byte ALG_EC_SVDP_DH_PLAIN = (byte) 3;

    /** KeyBuilder.LENGTH_EC_FP_256. The length constants are just bit counts. */
    public static final short LENGTH_EC_FP_256 = (short) 256;

    /** Chunk size for 61xx response chaining. Kept at 255 so the SW is always exact. */
    public static final short MAX_CHUNK = (short) 255;

    // ---- CTAP2 ----

    public static final byte CTAP_MAKE_CREDENTIAL = (byte) 0x01;
    public static final byte CTAP_GET_ASSERTION = (byte) 0x02;
    public static final byte CTAP_GET_INFO = (byte) 0x04;
    public static final byte CTAP_CLIENT_PIN = (byte) 0x06;
    public static final byte CTAP_RESET = (byte) 0x07;
    public static final byte CTAP_GET_NEXT_ASSERTION = (byte) 0x08;

    public static final byte CTAP2_OK = (byte) 0x00;
    public static final byte CTAP1_ERR_INVALID_COMMAND = (byte) 0x01;
    public static final byte CTAP1_ERR_INVALID_PARAMETER = (byte) 0x02;
    public static final byte CTAP1_ERR_INVALID_LENGTH = (byte) 0x03;
    public static final byte CTAP2_ERR_CBOR_UNEXPECTED_TYPE = (byte) 0x11;
    public static final byte CTAP2_ERR_INVALID_CBOR = (byte) 0x12;
    public static final byte CTAP2_ERR_MISSING_PARAMETER = (byte) 0x14;
    public static final byte CTAP2_ERR_LIMIT_EXCEEDED = (byte) 0x15;
    public static final byte CTAP2_ERR_CREDENTIAL_EXCLUDED = (byte) 0x19;
    public static final byte CTAP2_ERR_PROCESSING = (byte) 0x21;
    public static final byte CTAP2_ERR_UNSUPPORTED_ALGORITHM = (byte) 0x26;
    public static final byte CTAP2_ERR_OPERATION_DENIED = (byte) 0x27;
    public static final byte CTAP2_ERR_KEY_STORE_FULL = (byte) 0x28;
    public static final byte CTAP2_ERR_NO_OPERATION_PENDING = (byte) 0x2A;
    public static final byte CTAP2_ERR_UNSUPPORTED_OPTION = (byte) 0x2B;
    public static final byte CTAP2_ERR_INVALID_OPTION = (byte) 0x2C;
    public static final byte CTAP2_ERR_NO_CREDENTIALS = (byte) 0x2E;
    public static final byte CTAP2_ERR_NOT_ALLOWED = (byte) 0x30;
    public static final byte CTAP2_ERR_PIN_INVALID = (byte) 0x31;
    public static final byte CTAP2_ERR_PIN_BLOCKED = (byte) 0x32;
    public static final byte CTAP2_ERR_PIN_AUTH_INVALID = (byte) 0x33;
    public static final byte CTAP2_ERR_PIN_AUTH_BLOCKED = (byte) 0x34;
    public static final byte CTAP2_ERR_PIN_NOT_SET = (byte) 0x35;
    public static final byte CTAP2_ERR_PIN_REQUIRED = (byte) 0x36;
    public static final byte CTAP2_ERR_PIN_POLICY_VIOLATION = (byte) 0x37;
    public static final byte CTAP2_ERR_REQUEST_TOO_LARGE = (byte) 0x39;

    /**
     * Largest CTAP2 request we will assemble from chained APDUs, and what
     * getInfo reports as maxMsgSize. 1024 is the minimum CTAP2.1 requires; a
     * card claiming only FIDO_2_0 could get away with less, but real requests
     * from browsers carry long relying party and user names.
     */
    public static final short MAX_REQUEST = (short) 1024;

    /**
     * Response staging buffer. The largest response is a registration: 148 of
     * authData, up to 72 of self-attestation signature, and CBOR overhead,
     * about 246 bytes. An assertion with a 64-byte user handle is about 230.
     */
    public static final short MAX_RESPONSE = (short) 320;
}
