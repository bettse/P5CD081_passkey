#!/usr/bin/env python3
"""Wipe the passkey applet: every credential and the PIN.

Sends authenticatorReset as the first command after selecting the applet, which
is the only moment the card accepts it. A full card refuses new registrations,
so this is how a slot gets freed.

Usage: card_reset.py [reader substring] [pin to set afterwards]
"""
import sys

from smartcard.System import readers

FIDO_AID = bytes.fromhex("A0000006472F0001")


def reset(reader="CL Reader(1)", pin=None):
    for r in readers():
        if reader in str(r):
            conn = r.createConnection()
            conn.connect()
            break
    else:
        raise RuntimeError(f"no reader matching {reader!r}")
    _, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(FIDO_AID)] + list(FIDO_AID))
    if (sw1, sw2) != (0x90, 0x00):
        raise RuntimeError(f"select failed: {sw1:02X}{sw2:02X}")
    resp, sw1, sw2 = conn.transmit([0x80, 0x10, 0x00, 0x00, 0x01, 0x07, 0x00])
    if (sw1, sw2) != (0x90, 0x00) or resp[:1] != [0x00]:
        raise RuntimeError(f"reset refused: {bytes(resp).hex()} {sw1:02X}{sw2:02X}")
    if pin:
        # Vendor SET_PIN, which takes the PIN in the clear. Fine on a desk.
        body = pin.encode()
        _, sw1, sw2 = conn.transmit([0xE0, 0x02, 0x00, 0x00, len(body)] + list(body))
        if (sw1, sw2) != (0x90, 0x00):
            raise RuntimeError(f"set PIN failed: {sw1:02X}{sw2:02X}")
    conn.disconnect()


if __name__ == "__main__":
    reset(*sys.argv[1:3])
    print("card reset: no credentials, " + ("PIN set" if len(sys.argv) > 2 else "no PIN"))
