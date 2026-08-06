#!/usr/bin/env python3
"""
unsign_can.py

Does authentication survive a CAN-to-Ethernet gateway?

This adapter exists because a claim needed to be made true. The Internet-Draft
draft-bezerra-relay-auth-transparency-00 says the class is "demonstrated in
three independent protocol stacks (MAVLink v2, ROS2/DDS CDR, and CAN/AUTOSAR
SecOC)". Two of those were demonstrated with running code. The third was
reasoned from the protocol structure and never executed. This closes that gap
by measuring it, so the word can stay.

THE DEPLOYMENT SHAPE
--------------------

A diagnostic or control PDU travels over CAN, segmented by ISO-TP because it
does not fit in eight bytes. A gateway reassembles the ISO-TP sequence, parses
the application PDU out of it, and re-serialises that PDU for the Ethernet
domain (DoIP, or SOME/IP). The receiver on the far side acts on it.

There are two boundaries on that path, not one, and they fail differently:

  ISO-TP length   A FirstFrame declares the total length of the segmented
                  message. The reassembler delivers exactly that many bytes.
  PDU structure   A gateway that understands the application PDU rebuilds it
                  from the fields it parsed. Bytes past the PDU's own extent
                  were never in the parsed object.

Authentication appended past either one does not reach the far side, and the
receiver has no way to tell it was ever attached.

WHY THIS IS MEASURED AND NOT MODELLED
-------------------------------------

The ISO-TP half runs against the Linux kernel's own CAN and ISO-TP stacks over
a virtual CAN interface. Nothing here reimplements reassembly: the sender emits
hand-built raw CAN frames so it can lie about the declared length, and the
receiver is an ordinary `CAN_ISOTP` socket, which is the same code path a real
ECU or gateway uses. What it hands the application is what a real reassembler
hands a real application.

The gateway half is our own, for the same reason the vsomeip harness is: you
have to write the relay to observe what it emits. It does the ordinary thing,
which is parse and rebuild.

Usage:

  unsign can                    the PDU-boundary case, in process, no setup
  unsign can --vcan vcan0       add the ISO-TP case against the real kernel

The live mode needs a virtual CAN interface, which needs root once:

  sudo modprobe vcan can-isotp
  sudo ip link add dev vcan0 type vcan
  sudo ip link set up vcan0

Nothing is transmitted on a physical bus, and vcan is a loopback device.

Part of CleitonQ -- github.com/cleitonaugusto/CleitonQ
"""

import argparse
import socket
import struct
import sys
import threading
import time

# ISO-TP protocol control information, ISO 15765-2.
SF, FF, CF, FC = 0x00, 0x10, 0x20, 0x30

# UDS WriteDataByIdentifier: SID, then a 16-bit identifier, then the record.
UDS_SID = 0x2E
UDS_DID = 0xF190

TX_ID, RX_ID = 0x7E0, 0x7E8       # the usual diagnostic pair

# A classical ISO-TP FirstFrame carries a 12-bit length. Anything a sender
# would have to declare above this cannot be transmitted at all, which is a
# different finding from being stripped and is reported as one.
ISOTP_MAX_CLASSIC = 0xFFF          # 4095 bytes

AUTH_SIZES = [
    ("HMAC-SHA3-256", 32),
    ("Ed25519 signature", 64),
    ("ML-DSA-87 signature", 4627),
]

RECORD = bytes(range(0x40, 0x40 + 24))     # 24-byte data record
MARKER = 0xA5


# ---------------------------------------------------------------------------
# The application PDU
# ---------------------------------------------------------------------------

def build_uds_pdu(record=RECORD):
    """WriteDataByIdentifier. Its extent is defined by the service, not by a
    length field: SID + DID + the record the DID is defined to carry."""
    return bytes([UDS_SID]) + struct.pack(">H", UDS_DID) + record


def gateway_reserialize(pdu_in, record_len=len(RECORD)):
    """A CAN-to-Ethernet gateway that is not SecOC-aware.

    It knows this DID carries a record of `record_len` bytes, so it parses SID,
    DID and exactly that many bytes, and rebuilds the PDU for the Ethernet
    domain from those three fields. Anything after them was not part of what it
    parsed, so it cannot appear in what it emits. This is ordinary, correct
    gateway behaviour, which is the entire point.
    """
    fixed = 1 + 2
    if len(pdu_in) < fixed + record_len:
        return b"", "PDU shorter than the DID's defined record"
    sid = pdu_in[0]
    did = struct.unpack_from(">H", pdu_in, 1)[0]
    record = pdu_in[fixed:fixed + record_len]
    return bytes([sid]) + struct.pack(">H", did) + record, None


# ---------------------------------------------------------------------------
# ISO-TP, hand-built so the sender can declare one length and send another
# ---------------------------------------------------------------------------

def isotp_frames(payload, declared_length=None):
    """Build the raw CAN frames for one ISO-TP transmission.

    `declared_length` is what the FirstFrame announces. Leaving it None makes
    an honest transmission. Setting it below len(payload) is the whole
    experiment: the extra bytes are on the wire, inside consecutive frames,
    but outside what the FirstFrame said was coming.
    """
    total = len(payload) if declared_length is None else declared_length
    frames = []
    if len(payload) <= 7 and declared_length is None:
        data = bytes([SF | len(payload)]) + payload
        return [data.ljust(8, b"\x00")], True
    if len(payload) <= 6:
        # A FirstFrame promises ConsecutiveFrames will follow. With six or
        # fewer payload bytes there are none to send, so we would emit a
        # promise nobody keeps and the reassembler would wait forever. Refuse
        # rather than transmit an invalid sequence.
        raise ValueError("payload too short for a segmented transmission; "
                         "use at least 7 bytes to exercise the ISO-TP path")

    # FirstFrame: 4 bits PCI, 12 bits length, then six payload bytes.
    if total > 0xFFF:
        raise ValueError("this demo uses the 12-bit FirstFrame length only")
    ff = bytes([FF | (total >> 8), total & 0xFF]) + payload[:6]
    frames.append(ff.ljust(8, b"\x00"))

    seq, offset = 1, 6
    while offset < len(payload):
        chunk = payload[offset:offset + 7]
        frames.append((bytes([CF | (seq & 0x0F)]) + chunk).ljust(8, b"\x00"))
        offset += 7
        seq += 1
    return frames, False


def can_frame(can_id, data):
    """struct can_frame: id, dlc, 3 pad, 8 data."""
    return struct.pack("=IB3x8s", can_id, len(data), data.ljust(8, b"\x00"))


def send_isotp_raw(iface, payload, declared_length=None, timeout=3.0):
    """Emit one ISO-TP transmission as raw CAN frames, honouring flow control.

    Returns (frames_sent, got_flow_control).
    """
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    s.settimeout(timeout)

    frames, single = isotp_frames(payload, declared_length)
    s.send(can_frame(TX_ID, frames[0]))
    if single:
        s.close()
        return 1, False

    # The reassembler answers a FirstFrame with a FlowControl before we may
    # send the rest. Wait for it rather than assuming a timing.
    got_fc = False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = s.recv(16)
        except socket.timeout:
            break
        cid = struct.unpack_from("=I", raw, 0)[0]
        data = raw[8:8 + 8]
        if cid == RX_ID and (data[0] & 0xF0) == FC:
            block_size = data[1]
            if block_size:
                # This sender streams every ConsecutiveFrame after one
                # FlowControl, which is only correct when the receiver asked
                # for BS=0. A receiver that asks for blocks would drop what we
                # send, and the run would look like a successful strip. Refuse
                # rather than report a result we did not earn.
                s.close()
                raise RuntimeError(
                    "receiver requested BlockSize=%d; this sender only "
                    "implements BS=0 streaming, so the result would not be "
                    "trustworthy" % block_size)
            got_fc = True
            break
    if not got_fc:
        s.close()
        return 1, False

    for f in frames[1:]:
        s.send(can_frame(TX_ID, f))
        time.sleep(0.001)
    s.close()
    return len(frames), True


def isotp_receive(iface, expect_timeout=3.0, out=None):
    """An ordinary kernel ISO-TP socket. This is the reassembler under test."""
    s = socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, socket.CAN_ISOTP)
    # (interface, rx_id, tx_id). We receive what the sender transmits on TX_ID,
    # and the kernel answers flow control on RX_ID. Getting these the wrong way
    # round makes the reassembler listen to an address nobody is using, which
    # looks exactly like a successful strip -- the control run is what catches it.
    s.bind((iface, TX_ID, RX_ID))
    s.settimeout(expect_timeout)
    try:
        out.append(s.recv(8192))
    except (socket.timeout, OSError):
        out.append(None)
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def banner():
    print("  unsign can — does authentication survive the hop?")
    print("  Cleiton Augusto Correa Bezerra · github.com/cleitonaugusto/CleitonQ")
    print("  " + "─" * 67)
    print()


def run_pdu_case():
    """The gateway boundary: auth appended past the PDU the gateway parses."""
    pdu = build_uds_pdu()
    print("  Boundary 1 — the application PDU a gateway rebuilds")
    print("  UDS WriteDataByIdentifier, DID 0x%04X, %d-byte record → %d B PDU"
          % (UDS_DID, len(RECORD), len(pdu)))
    print()
    print("  %-21s  %6s  %10s  %6s  %s"
          % ("Auth scheme", "Sent", "Forwarded", "Lost", "Result"))
    print("  %s  %s  %s  %s  %s"
          % ("─" * 21, "─" * 6, "─" * 10, "─" * 6, "─" * 24))
    out, _ = gateway_reserialize(pdu)
    print("  %-21s  %6d  %10d  %6d  %s"
          % ("baseline, no auth", len(pdu), len(out), 0, "control passes"))
    for label, n in AUTH_SIZES:
        wire = pdu + bytes([MARKER]) * n
        out, _ = gateway_reserialize(wire)
        print("  %-21s  %6d  %10d  %6d  %s"
              % (label, len(wire), len(out), len(wire) - len(out),
                 "FAIL — auth gone"))
    print()


def run_isotp_case(iface):
    """The ISO-TP boundary, against the kernel's own reassembler."""
    print("  Boundary 2 — the ISO-TP declared length, on the Linux kernel")
    print("  Interface %s, raw CAN sender, CAN_ISOTP receiver" % iface)
    print()
    print("  %-21s  %8s  %10s  %8s  %s"
          % ("Case", "On wire", "Delivered", "Lost", "Result"))
    print("  %s  %s  %s  %s  %s"
          % ("─" * 21, "─" * 8, "─" * 10, "─" * 8, "─" * 26))

    pdu = build_uds_pdu()
    pdu_len = len(build_uds_pdu())
    rows = [("baseline, no auth", 0)]
    skipped = []
    for label, n in AUTH_SIZES:
        # The sender has to declare a length in the FirstFrame. What excludes a
        # case here is that declared length not fitting 12 bits -- not an
        # arbitrary size cut, which is what this used to be.
        if pdu_len + n > ISOTP_MAX_CLASSIC:
            skipped.append((label, n))
        else:
            rows.append((label, n))

    for label, n in rows:
        payload = pdu + bytes([MARKER]) * n
        declared = len(pdu) if n else None      # lie about the length when appending
        got = []
        rx = threading.Thread(target=isotp_receive, args=(iface, 3.0, got))
        rx.start()
        time.sleep(0.25)
        send_isotp_raw(iface, payload, declared)
        rx.join(timeout=5.0)
        received = got[0] if got else None
        if received is None:
            print("  %-21s  %8d  %10s  %8s  %s"
                  % (label, len(payload), "-", "-", "nothing reassembled"))
            continue
        lost = len(payload) - len(received)
        verdict = ("control passes" if n == 0 and len(received) == len(payload)
                   else "FAIL — auth gone" if lost == n
                   else "unexpected: %d B delivered" % len(received))
        print("  %-21s  %8d  %10d  %8d  %s"
              % (label, len(payload), len(received), lost, verdict))
    print()
    for label, n in skipped:
        print("  %-21s  %8d  %10s  %8s  %s"
              % (label, pdu_len + n, "n/a", "n/a",
                 "cannot be transmitted"))
    if skipped:
        print()
        print("  The cases marked n/a are not strips. A classical ISO-TP")
        print("  FirstFrame carries a 12-bit length, so %d bytes is the most a"
              % ISOTP_MAX_CLASSIC)
        print("  sender can declare, and those messages cannot be formed at all.")
        print("  Reporting them as stripped would be reporting a measurement we")
        print("  did not make.")
    print()


def explain(live):
    print("  ── What happened " + "─" * 47)
    print()
    print("  A gateway that is not SecOC-aware reassembles the ISO-TP sequence,")
    print("  parses the application PDU it understands, and rebuilds that PDU")
    print("  for the Ethernet domain. Authentication appended past the PDU was")
    print("  never in the parsed object, so it is never re-emitted.")
    print()
    if live:
        print("  And below it, the ISO-TP layer does the same thing one level")
        print("  down: the kernel reassembler delivers exactly the number of")
        print("  bytes the FirstFrame declared. Bytes present on the bus but")
        print("  outside that count never reach the application at all. That")
        print("  half was measured against the kernel, not modelled.")
        print()
    print("  Two boundaries, the same failure, and a receiver that cannot")
    print("  distinguish a command that arrived unauthenticated from one whose")
    print("  authenticator was removed on the way.")
    print()
    print("  ── Scope " + "─" * 56)
    print()
    print("  AUTOSAR SecOC done as specified is NOT this. Its MAC is symmetric,")
    print("  truncated, and carried inside the PDU, so it is inside the region")
    print("  the gateway parses and it survives. The exposure is a SecOC-unaware")
    print("  gateway on the path, or an authenticator bolted on outside the PDU")
    print("  because it no longer fits inside one.")
    print()
    print("  ── Fix " + "─" * 58)
    print()
    print("  Carry the authenticator inside the PDU definition, so the gateway")
    print("  parses it as data and re-emits it. If it does not fit, define a")
    print("  PDU that carries it rather than appending past the one you have.")
    print()
    print("    https://doi.org/10.5281/zenodo.20776349")
    print()


def main():
    p = argparse.ArgumentParser(
        description="Does authentication survive a CAN-to-Ethernet gateway?")
    p.add_argument("--vcan", metavar="IFACE",
                   help="also run the ISO-TP case against a real virtual CAN "
                        "interface (e.g. vcan0)")
    args = p.parse_args()

    banner()
    run_pdu_case()
    if args.vcan:
        try:
            run_isotp_case(args.vcan)
        except OSError as exc:
            print("  ISO-TP case skipped: %s" % exc)
            print("  Bring the interface up first:")
            print("    sudo modprobe vcan can-isotp")
            print("    sudo ip link add dev %s type vcan" % args.vcan)
            print("    sudo ip link set up %s" % args.vcan)
            print()
            return 1
    explain(bool(args.vcan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
