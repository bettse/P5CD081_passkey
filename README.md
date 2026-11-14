# passkey

> **LLM disclaimer:** most of this code, and this README, was written by an LLM (Claude) with me steering and testing on real cards. Nobody has audited it, and that includes the homemade crypto. Treat it accordingly.

A passkey applet for the NXP P5CD081 (JCOP 2.4.1, JavaCard 2.2.2). It talks CTAP2 over NFC, holds one discoverable credential, and signs ES256.

This is my second try. The first one (same card, RS256) passed libfido2 and then never worked in a browser. Most of the code here started as a copy of it. This one registers and signs in through Apple's WebAuthn stack, which is what Safari and Firefox on macOS use.

## The card

| | |
|---|---|
| Chip | NXP P5CD081, dual interface (contact and contactless), 81 KB EEPROM, roughly 6 KB RAM |
| OS | JCOP 2.4.1 R3 |
| JavaCard API | 2.2.2 (built against `jc222_kit`) |
| GlobalPlatform | 2.1.1, SCP02 |
| ATR (contactless) | `3B8880014A434F50763234315E` |

What the applet uses from the card:

- `javacardx.apdu.ExtendedLength`
- P-256 key pair generation (`KeyPair.ALG_EC_FP`, 256 bit), with the private scalar readable through `getS`
- raw RSA at 512 bits (`Cipher.ALG_RSA_NOPAD`), which is the big-number engine for the signing math
- `MessageDigest.ALG_SHA_256`
- AES-256 CBC with no padding, for the PIN protocol
- `RandomData.ALG_SECURE_RANDOM`

What the card doesn't have, and what stands in for it:

- `Signature.ALG_ECDSA_SHA_256`: no (only ECDSA with SHA-1). See "ES256 without ECDSA" below.
- HMAC-SHA-256: no. `Hmac.java` does it on top of the SHA-256 digest.
- `KeyAgreement.ALG_EC_SVDP_DH_PLAIN` (raw ECDH): no. JCAlgTest lists it as supported, but asking for it on the card throws `NO_SUCH_ALGORITHM`. The applet tries it at install and falls back to a fixed key when it's missing, which is the "PIN can be sniffed" item further down. On a card that has it, the same CAP should take the real path (the simulator does), but I haven't tried one.

It's only been run on this chip. Another JavaCard 2.2.2 card with the same pieces might work, but the stack depth and the RSA engine quirks are things I only know for this one.

## What it's for

A break-glass backup. One card holds one passkey for one service, gets a label saying which, and goes in a drawer or a safe. It comes out when the phone is lost or the everyday key is gone, and that might be years later.

It isn't trying to be a daily security key, and the design leans on that:

- **One credential per card, and it won't be overwritten.** A card labelled "GitHub" should still hold the GitHub credential when I need it, so once the slot is used, a registration from anywhere else is refused.
- **Where the card is kept is the security.** The card says the user was verified without checking anything, and the PIN exchange can be read by someone capturing the NFC traffic. Fine for a card in a safe, wrong for a card on a keyring.
- **Slow is fine.** About a second to sign in, on a path that gets used once in a long while.
- **No sync, no copy.** The key is generated on the card and never leaves it. A second backup is a second card, registered separately.

And a few things that follow from "it sits for years":

- Register it, then sign in with it once before putting it away. A backup you never tested isn't one.
- Keep another way in too (the service's recovery codes, or a second card). A single card can get lost or die like anything else.
- If you set a PIN, write it down with the card or somewhere you'll find it. Eight wrong tries blocks it, and a forgotten PIN is the likeliest way this card lets you down.
- The chip's data retention is finite, but long: NXP's short data sheet for the P5Cx081 family (Rev. 3.2) says 25 years minimum at 55 °C, and 500,000 EEPROM write cycles. Every signature writes to EEPROM, so the write count matters in principle, just not at backup-card usage.

## Status

Checked on a real card (unfused, default keys, ACR1555):

| Check | Result |
|---|---|
| Simulator tests (`make test`) | 107 pass, 9 skipped (the skipped ones need more than one slot) |
| 2000 signatures over 10 keys in the simulator | all verify |
| 200 signatures on the card (`tools/card_stress.py 200`) | all verify, about 0.95 s each |
| libfido2 register + assert, no PIN and with a PIN | pass |
| Apple's stack via `harness/e2e.py`, no PIN and with a PIN set | pass |

In an actual browser: I registered it once on a WebAuthn test site and the card ended up holding the credential. I didn't do the sign-in half, so a full browser round trip is still not checked. Also not checked: Windows, Android, iOS, and any real service.

## Why the first one failed

Two things, and both show up in one trace of Apple's stack talking to the old applet (`harness/run.sh create example.com`):

```
>> 00a4040008a0000006472f0001          select: fine
<< 5532465f56329000
>> 80100000000001040000                getInfo, as an extended-length APDU
<< (two bytes: an error status)        the old applet only understood short ones
```

1. WebKit sends every CTAP2 message as an extended-length APDU and doesn't follow `61xx` chaining at all (see `CtapCcidDriver.cpp` and `ApduCommand.cpp` in WebKit). The old applet did short APDUs and chained long responses with `61xx`, so it never got past getInfo.
2. With that fixed, the next wall: I asked for `-7,-257` and WebKit sent the card `pubKeyCredParams` with ES256 only. The old applet was RS256 only and answered `0x26` (unsupported algorithm).

So it needed extended-length APDUs and ES256, and this card has no `ALG_ECDSA_SHA_256`.

## ES256 without ECDSA

`Crypto.java` has the long version. Short version:

```
r = x(k * G) mod n
s = k^-1 * (h + r * d) mod n
```

- `k * G`: generating an EC key pair on the card is a scalar multiplication with a fresh random scalar. The card hands back both halves (`getS`, `getW`), so a throwaway key pair is the nonce and its point.
- `k^-1`: `k^(n-2)`, done by the RSA engine. It won't take a 256-bit modulus, but it takes `n^2`, and a result mod `n^2` is still right mod `n`.
- `a * b`: `((a+b)^2 - a^2 - b^2) / 2`, with each square done by the RSA engine using exponent 2.
- One software reduction mod `n` at the end.

`probe/` is the applet and script that checked each of those on a card before any of this got written. One thing it found the hard way: giving the RSA engine `n` zero-padded to 512 bits as a modulus mutes the card until it's power cycled. Don't.

Costs: registration is about 1.5 to 2.3 s, sign-in about 0.95 s. (The old RSA key generation was 7 to 48 s.)

## How it compares to a real security key

Short answer: it's not as secure as something like an HID Crescendo. The basics are the same (the key is generated on the card, never leaves it, and the chip is real secure hardware, just an older one). What I gave up:

1. **No user check.** The card tells the site "the user was verified" without asking for anything, so whoever holds the card can use it. `Const.CLAIM_USER_VERIFICATION` turns that off. Reading the code, with it off and a PIN set the card refuses to sign at all without the PIN, but I haven't run it that way on a card yet.
2. **The PIN can be sniffed.** The chip can't do the key agreement the PIN protocol wants, so the card fakes it with a fixed private key of 1: anyone capturing the NFC traffic can recover the PIN. No fix for that on this chip.
3. **Homemade signing.** The private key and the nonce pass through ordinary RAM as plain bytes, and the Java loops that add, subtract and reduce them aren't constant time. Someone with the card and lab gear (measuring power or emissions while it signs) has a better shot at the key than they would against a card's built-in ECDSA. I haven't measured how much it leaks.
4. **No attestation.** Self attestation only, so a site can't tell what kind of device it is. Anywhere that checks for certified keys (mostly enterprise stuff) will turn it away.

For a card that sits in a safe, the first three mostly come down to "don't let someone else get the card". For something on a keyring, they're real gaps.

## The harness

`harness/wkfido` is a small Objective-C tool that calls `_WKWebAuthenticationPanel`, the private WebKit class in front of Apple's security key code. It runs in-process, so it goes through the real smart card discovery, APDU framing and CTAP2 logic with no browser and no UI. It prints every APDU.

```bash
make harness
harness/run.sh create example.com --rk      # one registration, with trace
harness/run.sh get example.com
python3 harness/e2e.py example.com          # register, sign in twice, verify signatures
WKFIDO_PIN=1234 python3 harness/e2e.py      # same, answering a PIN prompt
```

Two things to know:

- It needs the `com.apple.security.smartcard` entitlement, which the Makefile signs in ad hoc.
- WebKit doesn't reliably find the card when other smart card slots are around. With five slots on my machine (the ACR1555 and its SAM, a YubiKey, an OMNIKEY, and a virtual one), two of four unfiltered runs selected the FIDO applet on the wrong slots, got `6A82`/`670A`, and timed out without ever trying the card. The harness hides every slot except the one matching `WKFIDO_READER` (default `CL Reader(1)`). **A real browser has no such filter**, so if Firefox or Safari ignores the card, unplug the YubiKey and try a reader without a SAM before blaming the applet. `WKFIDO_READER='*'` shows what WebKit would pick on its own.

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

The JavaCard SDKs are a git submodule (`ext/sdks`), so clone with `--recurse-submodules`, or run `git submodule update --init` after. `ant-javacard.jar` is in `lib/`.

You need `ant`, Java 8 for the CAP and Java 18 for the simulator tests, and [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) to install. The `Makefile` has my paths for those and my reader's name at the top, so expect to edit it. The Python tools want `pyscard`, `cbor2` and `cryptography`. The harness is macOS only.

## Things that are deliberate, or at least known

- **One credential, and it isn't overwritten.** `Const.SLOTS` is 1. Once the slot is used, a registration for a different site (or a different user) gets "key store full" instead of replacing what's there. The same user at the same site re-registering does replace, since CTAP2 requires it. To free the slot on purpose: `python3 tools/card_reset.py`, or `fido2-token -R`. More slots is that one constant plus a reinstall: a build with 48 installs on this card, and about 52 is the ceiling at roughly 1,190 bytes a slot. (I haven't tested more than one slot with ES256 beyond installing it.)
- **The test tools wipe the card.** `card_stress.py`, `libfido2_check.sh` and `e2e.py` all reset it first, since a full card would refuse their registrations. Don't point them at a card you care about.
- **The stack is nearly full.** One extra call frame under getAssertion turned every signature into `6F00`. The signing path has been flattened by three frames since, but anything added under `Ctap2.emitAssertion` or `WebAuthn.buildAttestationObject` should be followed by `tools/card_stress.py`.
- **Every signature writes a throwaway EC key to EEPROM.** That's the nonce trick above.
- **The simulator tests carry their own copies of the CTAP2 error codes.** That's how a whole block of them sat off by one without a test failing. They're checked against libfido2's `fido/err.h` now, but the copies are still copies.
- **NFC only, CTAP2 only.** No U2F, and no extensions (no hmac-secret/PRF, credProtect or largeBlob).
- The Go client from the first attempt didn't come along. The vendor protocol on CLA `E0` is still in the applet.

## Layout

```
src/dev/ericbetts/passkey/   the applet. Crypto.java is the new part
src/test/                    simulator tests
harness/                     wkfido (Apple's stack from the CLI) and e2e.py
tools/                       on-card stress test, libfido2 check, card reset
probe/                       the feasibility probe that came first
```
