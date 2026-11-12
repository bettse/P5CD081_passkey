#!/usr/bin/env python3
"""Register on the real card, then sign many times and verify every signature.

Talks CTAP2 straight to the card over PC/SC, using the same extended-length
APDU framing Apple's stack uses, so it is quick enough to run hundreds of
signatures. The simulator cannot stand in for this: it has a different RSA
engine and a different interpreter, and the arithmetic is the part at risk.

This wipes the card first: a full card refuses new registrations.

Usage: card_stress.py [count] [reader substring]
"""
import hashlib
import os
import statistics
import sys
import time

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from smartcard.System import readers

import card_reset

COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 100
READER = sys.argv[2] if len(sys.argv) > 2 else "CL Reader(1)"
FIDO_AID = bytes.fromhex("A0000006472F0001")
RP = "stress.example"


def connect():
    for r in readers():
        if READER in str(r):
            c = r.createConnection()
            c.connect()
            return c
    sys.exit(f"no reader matching {READER!r}")


def ctap(conn, command, body=None):
    msg = bytes([command]) + (cbor2.dumps(body, canonical=True) if body is not None else b"")
    apdu = bytes([0x80, 0x10, 0, 0, 0, len(msg) >> 8, len(msg) & 0xFF]) + msg + b"\x00\x00"
    t = time.time()
    resp, sw1, sw2 = conn.transmit(list(apdu))
    dt = time.time() - t
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"SW {sw1:02X}{sw2:02X}")
    resp = bytes(resp)
    if resp[0] != 0:
        raise RuntimeError(f"CTAP error 0x{resp[0]:02X}")
    return (cbor2.loads(resp[1:]) if len(resp) > 1 else None), dt


def main():
    card_reset.reset(READER)
    conn = connect()
    resp, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(FIDO_AID)] + list(FIDO_AID))
    print(f"select: {bytes(resp).decode(errors='replace')} {sw1:02X}{sw2:02X}")

    info, _ = ctap(conn, 0x04)
    print(f"getInfo: versions={info[1]} algorithms={[a['alg'] for a in info.get(10, [])]}")

    cdh = os.urandom(32)
    reg, dt = ctap(conn, 0x01, {
        1: cdh,
        2: {"id": RP, "name": RP},
        3: {"id": os.urandom(16), "name": "stress", "displayName": "Stress"},
        4: [{"alg": -7, "type": "public-key"}],
        7: {"rk": True},
    })
    auth = reg[2]
    n = int.from_bytes(auth[53:55], "big")
    cred_id = auth[55:55 + n]
    cose = cbor2.loads(auth[55 + n:])
    key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()).public_key()
    key.verify(reg[3]["sig"], auth + cdh, ec.ECDSA(hashes.SHA256()))
    print(f"makeCredential: {dt * 1000:.0f} ms, self-attestation verifies, response {len(cbor2.dumps(reg)) + 1} bytes")

    times, bad = [], 0
    for i in range(COUNT):
        cdh = os.urandom(32)
        try:
            got, dt = ctap(conn, 0x02, {1: RP, 2: cdh})
        except RuntimeError as e:
            print(f"  signature {i}: {e}")
            bad += 1
            continue
        times.append(dt)
        try:
            key.verify(got[3], got[2] + cdh, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            bad += 1
            print(f"  signature {i}: INVALID  authData={got[2].hex()} cdh={cdh.hex()} sig={got[3].hex()}")
    if times:
        print(f"getAssertion x{COUNT}: {COUNT - bad} verified, {bad} bad; "
              f"median {statistics.median(times) * 1000:.0f} ms, "
              f"min {min(times) * 1000:.0f}, max {max(times) * 1000:.0f}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
