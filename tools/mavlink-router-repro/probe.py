#!/usr/bin/env python3
"""Probe against a REAL mavlink-router, not a simulator.

Sends a valid MAVLink v2 COMMAND_LONG frame to the router's ingress with
authentication bytes appended after the frame, and captures what the router
re-emits on its output endpoint. If the appended bytes come back, the relay
preserved them; if only the 45-byte frame comes back, the relay stripped them.

The baseline case (no appended bytes) is the control: it must pass, or the
setup is wrong and nothing else is interpretable.
"""
import socket, struct, time

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
rx.bind(("127.0.0.1", 14551)); rx.settimeout(3.0)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx.bind(("127.0.0.1", 0))

cases = [("baseline, no auth", 0), ("HMAC-SHA3-256", 32),
         ("Ed25519 signature", 64), ("ML-DSA-87 signature", 4627)]

print("  %-21s  %6s  %8s  %6s  %s" % ("Auth scheme", "Sent", "Received", "Lost", "Result"))
print("  %s  %s  %s  %s  %s" % ("-"*21, "-"*6, "-"*8, "-"*6, "-"*30))

fail = 0
for i, (label, n) in enumerate(cases):
    frame = build(i)
    wire = frame + bytes([0xA5]) * n
    tx.sendto(wire, ("127.0.0.1", 14550))
    time.sleep(0.4)
    # Match on the sequence number, not just the message id. Every frame here
    # carries a distinct seq; without checking it, a packet left in the buffer
    # from an earlier case would be read as this one's. Every forwarded frame
    # is 45 bytes, so that mistake would produce a table that looks exactly
    # right and is not.
    got = None
    try:
        while True:
            d, _ = rx.recvfrom(65535)
            if len(d) < 12 or d[0] != 0xFD:
                continue
            msgid = d[7] | (d[8] << 8) | (d[9] << 16)
            if msgid == 76 and d[4] == (i & 0xFF):
                got = d; break
    except socket.timeout:
        pass
    if got is None:
        print("  %-21s  %6d  %8s  %6s  %s" % (label, len(wire), "-", "-", "nothing forwarded"))
        fail += 1
        continue
    lost = len(wire) - len(got)
    ok = (n == 0 and lost == 0)
    verdict = "control passes" if ok else ("FAIL - auth gone" if lost == n else "unexpected: %d B out" % len(got))
    print("  %-21s  %6d  %8d  %6d  %s" % (label, len(wire), len(got), lost, verdict))
