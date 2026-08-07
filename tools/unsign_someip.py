#!/usr/bin/env python3
"""
unsign_someip.py

Does authentication survive a SOME/IP gateway?


WHAT THIS SHOWS, AND WHAT IT DOES NOT
-------------------------------------

The short version is the same as MAVLink: a SOME/IP message declares its extent
in a 32-bit Length field, a gateway parses it and re-emits it from the parsed
fields, and bytes appended past that Length are not re-emitted. The receiver
gets a well-formed command with the authenticator gone.

The longer version is what a day of measurement added, and it matters because
the simple version overstates the case in two directions.

**SOME/IP is not silent toward the sender.** Reading vsomeip 3.7.0's
`udp_server_endpoint_impl`, the receive path iterates the messages inside a
datagram: the declared message is delivered through `on_message`, then the
trailing bytes are attempted as a subsequent message, fail the length check, and
reach `on_error` -> `endpoint_manager_impl::on_error` ->
`routing_manager_impl::send_error`. That builds an `MT_ERROR` carrying
`E_MALFORMED_MESSAGE` and transmits it *back to the sender*.

We measured it rather than trusting the read. With the sender's socket held
open, a 32-byte and a 64-byte appended tag each produce exactly one `MT_ERROR`
back at the sender, and the control produces none. So the diagnostic exists; it
travels in the wrong direction relative to the trust decision. The party told is
the one that already knows what it sent. The receiving application, and anything
downstream of it, are told nothing.

**And it is going away.** After we reported this, a vsomeip developer said the
pending 3.7.5 release drops `E_MALFORMED_MESSAGE` from the unreliable-endpoint
path entirely, because the response is hard to reconcile with PRS_SOMEIP_00190
for very short malformed messages and the client endpoint never implemented it
(COVESA/vsomeip issue 1060). That reasoning is defensible and we take no
position on it. But the change does not move the diagnostic toward the
receiving application, it removes it: on 3.7.5 the bytes are dropped and neither
end is told. We could not verify the commits against public source, so this is
reported as a statement rather than a measurement, and the numbers below are
from 3.7.0.

The general lesson is worth more than the detail. The detection channel here
was never designed to catch this condition. It was a side effect of a protocol
requirement, and a maintainer is now dropping it for unrelated reasons. A
mitigation nobody built on purpose is a mitigation nobody is obliged to keep.

**A post-quantum-sized authenticator is not stripped here. It is dropped.**
Appending a 4,627-byte ML-DSA-87 signature produces a 4,651-byte datagram, and
vsomeip 3.7.0 rejects it before the application sees anything:

    Received a packet that is bigger than VSOMEIP_MAX_UDP_MESSAGE_SIZE (1416)
    bytes ... Message will be dropped

That is an availability failure, not an authentication bypass. Under SOME/IP-TP
the final segment carrying the appended signature is 6,039 bytes and meets the
same ceiling. Across three runs of each configuration we found no arrangement on
this stack where a post-quantum-sized appended authenticator is silently
stripped: below the ceiling it is stripped and the sender is told, above it the
message is lost.

The constructive half of that experiment is worth stating too. Carrying the
command and the 4,627-byte signature *together inside* the TP payload delivers
all 4,635 bytes intact through the same parse-and-reserialize gateway. The fix
this class prescribes works at ML-DSA-87 scale on a production stack.

**AUTOSAR SecOC is out of scope.** Its MAC is symmetric, truncated, and carried
inside the PDU. It does not satisfy C2 and this does not apply to it.

Usage:

  python3 unsign_someip.py              in-process model, no stack required
  python3 unsign_someip.py --hexdump    also print the wire bytes

The full three-node chain against a live vsomeip routing manager lives in
`tools/vsomeip-chain/`, with the captured runs in its RESULT.md.

Part of CleitonQ -- github.com/cleitonaugusto/CleitonQ
"""

import argparse
import struct
import sys

# Header layout, from the SOME/IP specification and confirmed against
# vsomeip 3.7.0's interface/vsomeip/defines.hpp:
#
#   VSOMEIP_SOMEIP_HEADER_SIZE = 8    Length counts from byte 8 onward
#   VSOMEIP_FULL_HEADER_SIZE   = 16
#
HEADER_FIXED = 8    # Message ID (4) + Length (4)
LENGTH_PREFIX = 8   # Request ID (4) + Protocol/Interface/Type/Return (4)

SERVICE, METHOD = 0x1234, 0x0421
MARKER = 0xA5

AUTH_SIZES = [
    ("HMAC-SHA3-256", 32),
    ("Ed25519 signature", 64),
    ("ML-DSA-87 signature", 4627),
]

# vsomeip 3.7.0, implementation/configuration/include/internal.hpp.in
MAX_UDP_MESSAGE_SIZE = 1416


def build_message(payload=None):
    """One valid SOME/IP request. Length counts Request ID through payload."""
    if payload is None:
        payload = struct.pack(">ff", 1.5, 0.0)   # a steering/throttle setpoint
    return (struct.pack(">I", (SERVICE << 16) | METHOD)
            + struct.pack(">I", LENGTH_PREFIX + len(payload))
            + struct.pack(">I", 0x00010001)
            + struct.pack(">BBBB", 0x01, 0x01, 0x00, 0x00)
            + payload)


def gateway_reserialize(wire_in):
    """A conformant SOME/IP-aware gateway.

    Reads the 32-bit Length, consumes exactly 8 + Length bytes, rebuilds the
    message from the parsed fields and re-emits that. Bytes outside the counted
    region were never part of the parsed object, so they cannot appear in the
    output. This is correct behaviour, which is the entire point.
    """
    if len(wire_in) < HEADER_FIXED:
        return b"", "datagram shorter than the fixed header"
    (length,) = struct.unpack_from(">I", wire_in, 4)
    total = HEADER_FIXED + length
    if len(wire_in) < total:
        return b"", "Length field claims more than the datagram holds"
    return wire_in[:total], None


def hexdump(label, data, limit=48):
    print("  %s (%d B)" % (label, len(data)))
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("    %04x  %-47s  %s"
              % (i, " ".join("%02x" % b for b in chunk), text))
    if len(data) > limit:
        print("    ....  (%d more bytes)" % (len(data) - limit))
    print()


def run(show_hex):
    print("  unsign someip — does authentication survive the hop?")
    print("  Cleiton Augusto Correa Bezerra · github.com/cleitonaugusto/CleitonQ")
    print("  " + "─" * 67)
    print()
    print("  Mode : in-process gateway model (no vsomeip required)")
    baseline = build_message()
    print("  Baseline SOME/IP request: %d B  (declared body %d B)"
          % (len(baseline), LENGTH_PREFIX + 8))
    print()

    print("  %-21s  %5s  %9s  %8s  %s"
          % ("Auth scheme", "Sent", "Delivered", "Lost", "Result"))
    print("  %s  %s  %s  %s  %s"
          % ("─" * 21, "─" * 5, "─" * 9, "─" * 8, "─" * 36))
    print("  %-21s  %5d  %9d  %8d  %s"
          % ("baseline, no auth", len(baseline), len(baseline), 0,
             "control passes"))
    for label, n in AUTH_SIZES:
        wire = baseline + bytes([MARKER]) * n
        out, _ = gateway_reserialize(wire)
        if len(wire) > MAX_UDP_MESSAGE_SIZE:
            # The datagram never reaches the gateway on vsomeip 3.7.0, so the
            # whole thing is lost, not just the appended bytes. Reporting the
            # appended count here would imply the command still arrived.
            print("  %-21s  %5d  %9d  %8d  %s"
                  % (label, len(wire), 0, len(wire),
                     "DROPPED whole, over the %d B ceiling" % MAX_UDP_MESSAGE_SIZE))
        else:
            print("  %-21s  %5d  %9d  %8d  %s"
                  % (label, len(wire), len(out), len(wire) - len(out),
                     "FAIL — auth gone, command delivered"))
    print()

    if show_hex:
        wire = baseline + bytes([MARKER]) * 32
        hexdump("sent: message + 32-byte HMAC appended", wire)
        hexdump("emitted by the gateway", gateway_reserialize(wire)[0])

    print("  ── What happened " + "─" * 47)
    print()
    print("  The gateway read the 32-bit Length, consumed exactly 8 + Length")
    print("  bytes, and rebuilt the message from what it parsed. The appended")
    print("  authenticator was never part of that object, so it was never")
    print("  re-emitted. No rule was broken and no error was raised toward the")
    print("  receiver, which gets a well-formed, unauthenticated command.")
    print()
    print("  ── Two things this model does not show " + "─" * 26)
    print()
    print("  Measured on vsomeip 3.7.0, not modelled here:")
    print()
    print("  1. The stack is not silent toward the SENDER. It logs")
    print("     'bad length field' and returns MT_ERROR / E_MALFORMED_MESSAGE")
    print("     to whoever sent the datagram. The diagnostic exists and travels")
    print("     away from the endpoint that has to decide whether to act.")
    print()
    print("  2. The ML-DSA-87 row above is not a strip on that stack. A")
    print("     4,651-byte datagram exceeds VSOMEIP_MAX_UDP_MESSAGE_SIZE (%d)"
          % MAX_UDP_MESSAGE_SIZE)
    print("     and is dropped outright, which is an availability failure. Under")
    print("     SOME/IP-TP the final segment meets the same ceiling. So we do")
    print("     NOT claim post-quantum sizes aggravate this class on SOME/IP.")
    print()
    print("  ── Fix " + "─" * 58)
    print()
    print("  Carry the authenticator inside the Length-counted region. Measured")
    print("  under SOME/IP-TP, a command plus a 4,627-byte ML-DSA-87 signature")
    print("  carried inside the payload arrives whole: 4,635 bytes through a")
    print("  parse-and-reserialize gateway, reproducibly.")
    print()
    print("  AUTOSAR SecOC is out of scope: symmetric, truncated, in-PDU.")
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Does authentication survive a SOME/IP gateway?")
    parser.add_argument("--hexdump", action="store_true",
                        help="print the wire bytes before and after the gateway")
    return run(parser.parse_args().hexdump)


if __name__ == "__main__":
    sys.exit(main())
