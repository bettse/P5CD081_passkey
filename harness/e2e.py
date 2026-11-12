#!/usr/bin/env python3
"""Register and sign in through Apple's WebAuthn stack, and check the signatures.

Runs wkfido (see wkfido.m) for a registration and then an assertion against the
card on the reader, and verifies as a relying party would:

  - the self-attestation signature the card produced at registration, taken
    from the APDU trace because WebKit strips attestation down to "none"
  - the assertion signature, against the public key from the registration

Usage: e2e.py [rpId] [--rounds N] [--no-rk]
"""
import hashlib
import json
import os
import subprocess
import sys
import time

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
WKFIDO = os.path.join(HERE, "wkfido")


def run(*args):
    t = time.time()
    p = subprocess.run([WKFIDO, *args], capture_output=True, text=True)
    dt = time.time() - t
    lines = [line for line in p.stdout.splitlines() if line.startswith("{")]
    result = json.loads(lines[-1]) if lines else {"ok": False, "error": "no output"}
    trace = [line for line in p.stderr.splitlines() if line[:2] in (">>", "<<")]
    return result, trace, dt, p.stderr


def last_ctap_response(trace, command):
    """The card's raw reply to the last CTAP2 message with this command byte."""
    for i in range(len(trace) - 1, 0, -1):
        req = bytes.fromhex(trace[i - 1][3:]) if trace[i - 1].startswith(">>") else b""
        if trace[i].startswith("<<") and req[:2] == b"\x80\x10" and req[7:8] == bytes([command]):
            return bytes.fromhex(trace[i][3:])
    return None


def cose_to_key(cose):
    assert cose[1] == 2 and cose[3] == -7 and cose[-1] == 1, f"not an ES256 P-256 key: {cose}"
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()
    ).public_key()


def parse_auth_data(auth):
    out = {"rpIdHash": auth[:32], "flags": auth[32], "signCount": int.from_bytes(auth[33:37], "big")}
    if auth[32] & 0x40:
        n = int.from_bytes(auth[53:55], "big")
        out["aaguid"] = auth[37:53]
        out["credId"] = auth[55:55 + n]
        out["cose"] = cbor2.loads(auth[55 + n:])
    return out


def verify(key, sig, message):
    try:
        key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def one_round(rp, rk, n):
    fails = []

    def check(name, ok, detail=""):
        print(f"  {'ok  ' if ok else 'FAIL'} {name}{'  ' + detail if detail else ''}")
        if not ok:
            fails.append(name)

    print(f"round {n}: {rp}")
    args = ["create", rp] + (["--rk"] if rk else [])
    reg, trace, dt, err = run(*args)
    check("registration completes through WebKit", reg.get("ok", False),
          f"({dt:.1f} s)" if reg.get("ok") else reg.get("error", "") + "\n" + err[-600:])
    if not reg.get("ok"):
        return fails

    att = cbor2.loads(bytes.fromhex(reg["attestationObject"]))
    auth = parse_auth_data(att["authData"])
    check("rpIdHash matches", auth["rpIdHash"] == hashlib.sha256(rp.encode()).digest())
    check("flags carry UP and AT", auth["flags"] & 0x41 == 0x41, f"(0x{auth['flags']:02x})")
    check("credential id matches rawId", auth["credId"].hex() == reg["rawId"])
    key = cose_to_key(auth["cose"])
    check("public key is a valid P-256 point", True)

    raw = last_ctap_response(trace, 0x01)
    if raw and raw[0] == 0 and raw[-2:] == b"\x90\x00":
        card = cbor2.loads(raw[1:-2])
        stmt = card[3]
        signed = card[2] + bytes.fromhex(reg["clientDataHash"])
        check("card's self-attestation signature verifies (ES256)",
              card[1] == "packed" and stmt["alg"] == -7 and verify(key, stmt["sig"], signed))
    else:
        check("card's raw registration response found in trace", False)

    last_count = auth["signCount"]
    for label, extra in (("with allowList", ["--cred", reg["rawId"]]),
                         ("discoverable, no allowList", [])):
        if not extra and not rk:
            continue
        got, trace, dt, err = run("get", rp, *extra)
        check(f"assertion completes through WebKit, {label}", got.get("ok", False),
              f"({dt:.1f} s)" if got.get("ok") else got.get("error", "") + "\n" + err[-600:])
        if not got.get("ok"):
            continue
        adata = bytes.fromhex(got["authenticatorData"])
        a = parse_auth_data(adata)
        check("  assertion signature verifies (ES256)",
              verify(key, bytes.fromhex(got["signature"]), adata + bytes.fromhex(got["clientDataHash"])))
        check("  right credential", got["rawId"] == reg["rawId"])
        check("  signature counter went up", a["signCount"] > last_count,
              f"({last_count} -> {a['signCount']})")
        last_count = a["signCount"]
        if not extra:
            check("  user handle returned", len(got.get("userHandle", "")) > 0)
    return fails


def main():
    args = sys.argv[1:]
    rounds = 1
    if "--rounds" in args:
        i = args.index("--rounds")
        rounds = int(args[i + 1])
        del args[i:i + 2]
    rk = "--no-rk" not in args
    args = [a for a in args if a != "--no-rk"]
    rp = args[0] if args else "example.com"

    fails = []
    for n in range(1, rounds + 1):
        fails += one_round(rp, rk, n)
    print(f"\n{'PASS' if not fails else 'FAIL: ' + ', '.join(fails)}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
