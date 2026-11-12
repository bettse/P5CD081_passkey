#!/usr/bin/env python3
"""Host side of the ES256 feasibility probe for the P5CD081.

Asks the card three questions, then builds a real ES256 signature out of
nothing but card operations and verifies it with a stock library.
"""
import hashlib
import os
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from smartcard.System import readers

READER = sys.argv[1] if len(sys.argv) > 1 else "ACS ACR1555 1S CL Reader(1)"
AID = bytes.fromhex("F04543 50524F4245 01".replace(" ", ""))

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Q = 2**256 - 189                      # another 256-bit prime, for N*Q
results = []


def connect():
    for r in readers():
        if str(r) == READER:
            c = r.createConnection()
            c.connect()
            return c
    sys.exit(f"reader not found: {READER}")


def tx(conn, cla, ins, p1=0, p2=0, data=b""):
    apdu = [cla, ins, p1, p2]
    if data:
        apdu += [len(data)] + list(data)
    else:
        apdu += [0]
    t = time.time()
    resp, sw1, sw2 = conn.transmit(apdu)
    while sw1 == 0x61:
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        resp += more
    return bytes(resp), (sw1 << 8) | sw2, time.time() - t


def explain(sw):
    reasons = {1: "ILLEGAL_VALUE", 2: "UNINITIALIZED_KEY", 3: "NO_SUCH_ALGORITHM",
               4: "INVALID_INIT", 5: "ILLEGAL_USE"}
    if sw >> 8 == 0x66:
        return f"CryptoException {reasons.get(sw & 0xF, sw & 0xF)} at stage {(sw >> 4) & 0xF}"
    if sw >> 8 == 0x65:
        return f"other exception at stage {(sw >> 4) & 0xF}"
    return f"SW {sw:04X}"


def report(name, ok, detail=""):
    results.append(ok)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'  ' + detail if detail else ''}")


def keygen(conn):
    """Returns (private scalar, x of public point, y, seconds) or raises."""
    resp, sw, dt = tx(conn, 0x80, 0x01)
    if sw != 0x9000:
        raise RuntimeError(explain(sw))
    w, s = resp[:65], resp[65:]
    return int.from_bytes(s, "big"), int.from_bytes(w[1:33], "big"), int.from_bytes(w[33:65], "big"), dt, len(s)


def modexp(conn, mod, exp, base, priv=False, exp_len=None):
    e = exp.to_bytes(exp_len or max(1, (exp.bit_length() + 7) // 8), "big")
    data = mod.to_bytes(64, "big") + e + base.to_bytes(64, "big")
    resp, sw, dt = tx(conn, 0x80, 0x02, 1 if priv else 0, len(e), data)
    if sw != 0x9000:
        raise RuntimeError(explain(sw))
    return int.from_bytes(resp, "big"), dt


def check_modexp(conn, name, mod, exp, priv=False, exp_len=None):
    base = int.from_bytes(os.urandom(64), "big") % mod
    try:
        got, dt = modexp(conn, mod, exp, base, priv, exp_len)
    except RuntimeError as e:
        report(name, False, str(e))
        return False
    ok = got == pow(base, exp, mod)
    report(name, ok, f"({dt * 1000:.0f} ms)" if ok else "wrong answer")
    return ok


def main():
    conn = connect()
    resp, sw, _ = tx(conn, 0x00, 0xA4, 0x04, 0x00, AID)
    if sw != 0x9000:
        sys.exit(f"select failed: {sw:04X} (is the applet installed?)")

    resp, sw, _ = tx(conn, 0x80, 0x00)
    names = ["EC key pair objects", "RSAPublicKey 512", "RSAPrivateKey 512", "Cipher ALG_RSA_NOPAD"]
    print("install-time allocation")
    for i, name in enumerate(names):
        st = int.from_bytes(resp[i * 2:i * 2 + 2], "big")
        report(name, st == 0, "" if st == 0 else explain(st))

    print("\n1. does getS() return the private scalar of a generated key?")
    for i in range(3):
        try:
            s, x, y, dt, slen = keygen(conn)
        except RuntimeError as e:
            report(f"keygen {i + 1}", False, str(e))
            continue
        pub = ec.derive_private_key(s, ec.SECP256R1()).public_key().public_numbers()
        report(f"keygen {i + 1}: S*G == W", (pub.x, pub.y) == (x, y), f"({dt * 1000:.0f} ms, S is {slen} bytes)")

    # A genuine RSA modulus as a control, so a refusal of N^2 can be told apart
    # from a refusal of everything.
    real = (2**256 - 2**32 - 977) * Q     # product of two 256-bit primes

    print("\n2. does the RSA engine take a modulus that is not an RSA modulus?")
    check_modexp(conn, "control: real RSA modulus, e=65537, public key", real, 65537)
    check_modexp(conn, "N^2, e=65537, public key", N * N, 65537)
    check_modexp(conn, "N*Q, e=65537, public key", N * Q, 65537)
    check_modexp(conn, "N^2, e=2 (squaring), public key", N * N, 2)
    check_modexp(conn, "N^2, e=3, public key", N * N, 3)

    print("\n3. does it take a 256-bit exponent?")
    pub_inv = check_modexp(conn, "N^2, e=N-2, public key", N * N, N - 2)
    priv_inv = check_modexp(conn, "N^2, e=N-2, private key", N * N, N - 2, priv=True)
    check_modexp(conn, "N^2, e=N-2 padded to 64 bytes, private key", N * N, N - 2, priv=True, exp_len=64)
    check_modexp(conn, "N*Q, e=N-2, public key", N * Q, N - 2)
    check_modexp(conn, "N*Q, e=N-2, private key", N * Q, N - 2, priv=True)
    sq_pub = check_modexp(conn, "N^2, e=2, private key", N * N, 2, priv=True)

    print("\n4. an ES256 signature assembled only from card operations")
    try:
        card_time = 0.0
        ops = 0

        def cm(base, exp):
            nonlocal card_time, ops
            try:
                v, dt = modexp(conn, N * N, exp, base, priv=not pub_inv and exp != 2)
            except RuntimeError:
                v, dt = modexp(conn, N * N, exp, base, priv=True)
            card_time += dt
            ops += 1
            return v

        def mul(a, b):
            # a*b = ((a+b)^2 - a^2 - b^2) / 2, each square done by the card
            t = (cm(a + b, 2) - cm(a, 2) - cm(b, 2)) % (N * N)
            if t & 1:
                t += N * N
            return (t >> 1) % N

        d, qx, qy, dt, _ = keygen(conn)          # the credential key
        msg = b"authData || clientDataHash stand-in " + os.urandom(16)
        h = int.from_bytes(hashlib.sha256(msg).digest(), "big")

        k, rx, _, dt, _ = keygen(conn)           # the nonce and its point
        card_time += dt
        ops += 1
        r = rx % N
        kinv = cm(k, N - 2) % N
        s = mul(kinv, (h + mul(r, d)) % N)
        if s > N // 2:
            s = N - s

        pub = ec.EllipticCurvePublicNumbers(qx, qy, ec.SECP256R1()).public_key()
        try:
            pub.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
            report("signature verifies as ECDSA P-256 / SHA-256", True,
                   f"({ops} card operations, {card_time * 1000:.0f} ms on the card)")
        except InvalidSignature:
            report("signature verifies as ECDSA P-256 / SHA-256", False, "invalid signature")
    except RuntimeError as e:
        report("signature assembled", False, str(e))

    print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")


if __name__ == "__main__":
    main()
