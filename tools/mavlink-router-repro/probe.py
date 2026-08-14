#!/usr/bin/env python3
"""Probe against a REAL mavlink-router, not a simulator.

Sends a valid MAVLink v2 COMMAND_LONG frame to the router's ingress with
authentication bytes appended after the frame, and captures what the router
re-emits on its output endpoint. If the appended bytes come back, the relay
preserved them; if only the 45-byte frame comes back, the relay stripped them.

The baseline case (no appended bytes) is the control: it must pass, or the
setup is wrong and nothing else is interpretable.

One case exists to rule out a rival explanation. mavlink-router reads each
datagram into a buffer of RX_BUF_MAX_SIZE = MAVLINK_MAX_PACKET_LEN * 4 = 1120
bytes (endpoint.cpp). A datagram larger than that is truncated by the kernel at
recvfrom, so for large appends the bytes would be lost before any MAVLink
parsing happens — a different mechanism that produces an identical table. The
1075-byte case sends exactly 1120 bytes on the wire: the whole datagram fits the
buffer, truncation is impossible, and anything missing was dropped by frame
re-emission. That is the case that carries the argument.

Exit status reports whether the measurement is INTERPRETABLE, not whether the
class was found: 0 when the control passed and every case produced a frame,
1 otherwise. "auth gone" is the expected result here, not an error.
"""
import socket, struct, sys, time

# endpoint.cpp:50 — RX_BUF_MAX_SIZE (MAVLINK_MAX_PACKET_LEN * 4), where
# MAVLINK_MAX_PACKET_LEN = 255 payload + 12 non-payload + 13 signature = 280.
RX_BUF_MAX_SIZE = 1120

CASE_TIMEOUT = 3.0

# The filler must not be a MAVLink start byte, and this is load-bearing rather
# than cosmetic. mavlink-router reads into rx_buf with the space that is left
# (`RX_BUF_MAX_SIZE - rx_buf.len`, endpoint.cpp:290) and scans for 0xFD/0xFE,
# keeping everything from the first start byte onward as a partial frame. A
# filler of 0xA5 matches neither, so the remainder is dropped and rx_buf is
# empty when the next datagram arrives — which is the only reason the 1120-byte
# case really does get a full 1120-byte read and cannot be truncated.
#
# Measured, because the property is easy to lose by accident: with a 0xFD filler
# in the preceding datagram, the residue survives and the following 1120-byte
# case is not forwarded at all, while the table would still print
# "Truncatable: no". A real ML-DSA-87 signature contains 0xFD bytes, so swapping
# the filler for realistic material is exactly the edit that would break this.
FILLER = 0xA5
assert FILLER not in (0xFD, 0xFE), (
    "filler must not be a MAVLink start byte: leftover bytes would stay in the "
    "relay's receive buffer and silently shorten the next read, which destroys "
    "the isolation the 1120-byte case exists to provide")

def crc_step(b, crc):
    tmp = b ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF

def mav_crc(data, crc_extra):
    crc = 0xFFFF
    for b in data:
        crc = crc_step(b, crc)
    return crc_step(crc_extra, crc)

def build(seq=0):
    # COMMAND_LONG (msgid 76), target system 0 = broadcast so the router,
    # which routes by target, forwards it without having seen an announcement.
    payload = struct.pack("<7fHBBB", 0, 0, 0, 0, 0, 0, 0, 400, 0, 0, 0)
    hdr = struct.pack("<BBBBBBBB", 0xFD, len(payload), 0, 0, seq, 255, 190, 76) + b"\x00\x00"
    frame = hdr[:10] + payload
    c = mav_crc(frame[1:], 152)  # 152 = CRC_EXTRA for COMMAND_LONG
    return frame + struct.pack("<H", c)

rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.bind(("127.0.0.1", 14551))
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx.bind(("127.0.0.1", 0))

cases = [("baseline, no auth", 0), ("HMAC-SHA3-256", 32),
         ("Ed25519 signature", 64), ("below read buffer", 1075),
         ("ML-DSA-87 signature", 4627)]

print("  %-21s  %6s  %8s  %6s  %-11s  %s"
      % ("Auth scheme", "Sent", "Received", "Lost", "Truncatable", "Result"))
print("  %s  %s  %s  %s  %s  %s"
      % ("-"*21, "-"*6, "-"*8, "-"*6, "-"*11, "-"*30))

unmeasurable = 0
for i, (label, n) in enumerate(cases):
    frame = build(i)
    wire = frame + bytes([FILLER]) * n
    tx.sendto(wire, ("127.0.0.1", 14550))
    time.sleep(0.4)
    # Whether the kernel could have truncated this datagram before mavlink-router
    # ever parsed it. "no" means the append fits the read buffer, so any loss is
    # frame re-emission and nothing else.
    truncable = "yes" if len(wire) > RX_BUF_MAX_SIZE else "no"
    # Match on the sequence number, not just the message id. Every frame here
    # carries a distinct seq; without checking it, a packet left in the buffer
    # from an earlier case would be read as this one's. Every forwarded frame
    # is 45 bytes, so that mistake would produce a table that looks exactly
    # right and is not.
    #
    # The deadline is computed once per case, not per recvfrom: a steady stream
    # of non-matching datagrams would otherwise refresh a per-call timeout
    # forever and hang here instead of reporting "nothing forwarded".
    got = None
    deadline = time.monotonic() + CASE_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        rx.settimeout(remaining)
        try:
            d, _ = rx.recvfrom(65535)
        except socket.timeout:
            break
        if len(d) < 12 or d[0] != 0xFD:
            continue
        msgid = d[7] | (d[8] << 8) | (d[9] << 16)
        if msgid == 76 and d[4] == (i & 0xFF):
            got = d
            break
    if got is None:
        print("  %-21s  %6d  %8s  %6s  %-11s  %s"
              % (label, len(wire), "-", "-", truncable, "nothing forwarded"))
        unmeasurable += 1
        continue
    lost = len(wire) - len(got)
    if n == 0:
        verdict = "control passes" if lost == 0 else "CONTROL FAILED - setup is wrong"
        if lost != 0:
            unmeasurable += 1
    elif lost == n:
        verdict = "auth gone"
    elif lost == 0:
        verdict = "PRESERVED - not an instance"
    else:
        # Neither the full append nor none of it came back. That is not a
        # measurement of anything, so it must gate the exit code like the other
        # unusable outcomes — leaving it out was the same defect this harness
        # was just fixed for: a value computed and then not acted on.
        verdict = "unexpected: %d B out" % len(got)
        unmeasurable += 1
    print("  %-21s  %6d  %8d  %6d  %-11s  %s"
          % (label, len(wire), len(got), lost, truncable, verdict))

if unmeasurable:
    print("\n  %d case(s) produced no usable measurement — the run is not"
          " interpretable." % unmeasurable)
    sys.exit(1)
