# passkey

A WebAuthn authenticator applet for the NXP P5CD081 (JCOP 2.4.1, JavaCard 2.2.2). It speaks CTAP2 over NFC on the FIDO AID, holds one discoverable credential, and signs ES256.

This is the second try. The first one lives in `/Volumes/Projects/javacard/P5CD081/passkey_no_workey` and is kept as it was: most of the code here started as a copy of it. That one passed libfido2 and then never worked in a browser. This one registers and signs in through Apple's WebAuthn stack, which is what Safari and Firefox on macOS use.

## Status

Checked on a real card (unfused, default keys, ACR1555):

| Check | Result |
|---|---|
| Simulator tests (`make test`) | 107 pass, 9 skipped (the skipped ones need more than one slot) |
| 2000 signatures over 10 keys in the simulator | all verify |
| 200 signatures on the card (`tools/card_stress.py 200`) | all verify, about 0.95 s each |
| libfido2 register + assert, no PIN and with a PIN | pass |
| Apple's stack via `harness/e2e.py`, no PIN and with a PIN set | pass |

Not checked: an actual browser. The harness drives the same WebKit code a browser hands the request to, but nobody has clicked through Firefox or Safari with this build yet. Also not checked: Windows, Android, iOS.

## Why the first one failed

Two things, both visible in one trace of Apple's stack talking to the old applet (`harness/run.sh create example.com`):

```
>> 00a4040008a0000006472f0001          select: fine
<< 5532465f56329000
>> 80100000000001040000                getInfo, as an extended-length APDU
<< (two bytes: an error status)        the old applet only understood short ones
```

1. WebKit frames every CTAP2 message as an extended-length APDU and does not follow `61xx` chaining at all (see `CtapCcidDriver.cpp` and `ApduCommand.cpp` in WebKit). The old applet did short APDUs and chained long responses with `61xx`. It never got past getInfo.
2. With that fixed, the next wall: I asked for `-7,-257` and WebKit sent the card `pubKeyCredParams` with ES256 only. The old applet was RS256 only and answered `0x26` (unsupported algorithm).

So it needed extended-length APDUs and ES256, and the card has no `ALG_ECDSA_SHA_256`.

## ES256 without ECDSA

`Crypto.java` has the long version. Short version:

```
r = x(k * G) mod n
s = k^-1 * (h + r * d) mod n
```

- `k * G`: on-card EC key generation is a scalar multiplication with a fresh random scalar. The card gives back both halves (`getS`, `getW`), so a throwaway key pair is the nonce and its point.
- `k^-1`: `k^(n-2)`, done by the RSA engine. It won't take a 256-bit modulus, but it takes `n^2`, and a result mod `n^2` is still right mod `n`.
- `a * b`: `((a+b)^2 - a^2 - b^2) / 2`, each square done by the RSA engine with exponent 2.
- One software reduction mod `n` at the end.

`probe/` is the applet and script that checked each of those on a card before any of this was written. One thing it found the hard way: giving the RSA engine `n` zero-padded to 512 bits as a modulus mutes the card until it is power cycled. Don't.

Costs: registration about 1.5 to 2.3 s, sign-in about 0.95 s. (The old RSA key generation was 7 to 48 s.)

## The harness

`harness/wkfido` is a small Objective-C tool that calls `_WKWebAuthenticationPanel`, the private WebKit class in front of Apple's security-key code. It runs in-process, so it goes through the real smart card discovery, APDU framing and CTAP2 logic with no browser and no UI. It prints every APDU.

```bash
make harness
harness/run.sh create example.com --rk      # one registration, with trace
harness/run.sh get example.com
python3 harness/e2e.py example.com          # register, sign in twice, verify signatures
WKFIDO_PIN=1234 python3 harness/e2e.py      # same, answering a PIN prompt
```

Two things to know:

- It needs the `com.apple.security.smartcard` entitlement, which the Makefile signs in ad hoc.
- WebKit keeps one smart card connection: the first slot with a card in it wins, and it never tries another. With a YubiKey plugged in, or a SAM in the reader, that is often not the card on the antenna. The harness hides every slot except the one matching `WKFIDO_READER` (default `CL Reader(1)`). **A real browser has no such filter**, so if Firefox or Safari ignores the card, unplug the YubiKey and try a reader without a SAM before blaming the applet. `WKFIDO_READER='*'` shows what WebKit would pick on its own.

## Building and testing

```bash
make test        # simulator tests, Java 18
make build       # build/passkey.cap, Java 8
make reinstall   # onto the card on the ACR1555, default keys
python3 tools/card_stress.py 200
tools/libfido2_check.sh          # or: tools/libfido2_check.sh 1234 to set and use a PIN
python3 harness/e2e.py
python3 tools/card_reset.py      # wipe credentials and PIN
```

`build.xml` reads `ant-javacard.jar` and the JavaCard 2.2.2 SDK from the old project's folder rather than copying them (`-Dtoolchain=...` if that moves).

## Things that are deliberate, or at least known

- **One credential, and it is not overwritten.** `Const.SLOTS` is 1. Once the slot is used, a registration for a different site (or a different user) is refused with "key store full" instead of replacing what is there. The same user at the same site re-registering does replace, as CTAP2 requires. To free the slot on purpose: `python3 tools/card_reset.py`, or `fido2-token -R`. Raising the slot count is that one constant plus a reinstall: a build with 48 installs on this card, and about 52 is the ceiling at roughly 1,190 bytes a slot.
- **The test tools wipe the card.** `card_stress.py`, `libfido2_check.sh` and `e2e.py` all reset it first, since a full card would refuse their registrations. Don't point them at a card you care about.
- **UV is claimed, not performed.** The card reports `uv: true` and sets the UV flag with no PIN asked, on the theory that this is a break-glass card whose security is where it is kept. `Const.CLAIM_USER_VERIFICATION` turns that off. Carried over from the first attempt.
- **clientPIN gives no secrecy.** The card has no raw ECDH, so its key agreement private key is 1 and anyone watching the exchange can derive the shared secret. Also carried over.
- **The stack is nearly full.** One extra call frame under getAssertion turned every signature into `6F00`. The signing path has since been flattened by three frames, but anything added under `Ctap2.emitAssertion` or `WebAuthn.buildAttestationObject` should be followed by `tools/card_stress.py`.
- **Not constant time**, and every signature writes a throwaway EC key to EEPROM.
- **Self attestation only**, so the AAGUID proves nothing.
- The Go client from the first attempt was not brought over. The vendor protocol on CLA `E0` is still in the applet.

## Layout

```
src/dev/ericbetts/passkey/   the applet. Crypto.java is the new part
src/test/                    simulator tests
harness/                     wkfido (Apple's stack from the CLI) and e2e.py
tools/                       on-card stress test, libfido2 check
probe/                       the feasibility probe that came first
```
