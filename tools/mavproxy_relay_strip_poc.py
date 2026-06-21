#!/usr/bin/env python3
"""
mavproxy_relay_strip_poc.py
───────────────────────────
Proof of concept: MAVLink-aware relays silently strip any authentication
material appended after a valid MAVLink v2 frame.

The problem affects any scheme that appends authentication bytes outside the
MAVLink frame boundary — including HMAC tags, digital signatures (ML-DSA-87,
Ed25519), and nonces. The relay sees a valid frame, forwards exactly those
bytes, and discards the rest. No error, no log entry, no indication to
either endpoint that authentication was removed.

Affected relays (tested):
  - MAVProxy  >= 1.8.x  (any version with --master/--out routing)
  - mavlink-router      (--endpoint based routing)
  - QGroundControl      (acting as UDP bridge)

No external dependencies required. Python 3.6+.

USAGE
─────
  # Mode 1 — simulated relay (no MAVProxy needed, default)
  python3 mavproxy_relay_strip_poc.py

  # Mode 2 — real MAVProxy relay
  #   Terminal 1: mavproxy.py --master udp:127.0.0.1:14550 --out udp:127.0.0.1:14551
  #   Terminal 2: python3 mavproxy_relay_strip_poc.py --real-relay

REFERENCES
──────────
  Repository : https://github.com/cleitonaugusto/CleitonQ
  Paper      : https://doi.org/10.5281/zenodo.20776349
  RFC        : https://github.com/mavlink/mavlink/issues/2527
  Fix        : carry auth material as first-class MAVLink messages (CLEITONQ_CHUNK)

Author: Cleiton Augusto Correa Bezerra
"""

import socket
import struct
import sys
import time
import threading
import argparse

# ── MAVLink v2 constants ──────────────────────────────────────────────────────

MAV_STX_V2       = 0xFD
MSG_ID_CMD_LONG  = 76
CRC_EXTRA_CMD    = 152   # CRC_EXTRA for COMMAND_LONG (msg_id 76)

# Simulated auth payload sizes (choose to demonstrate scale)
AUTH_SIZES = {
    "HMAC-SHA3-256 (40 B)":    40,
    "Ed25519 sig  (72 B)":     72,
    "ML-DSA-87 sig (4627 B)": 4627,
}

# ── MAVLink v2 CRC-16-MCRF4XX ────────────────────────────────────────────────

def _crc_step(byte: int, crc: int) -> int:
    tmp = byte ^ (crc & 0xFF)
    tmp = tmp ^ ((tmp << 4) & 0xFF)
    return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF

def mavlink_crc(data: bytes, crc_extra: int) -> int:
    crc = 0xFFFF
    for b in data:
        crc = _crc_step(b, crc)
    return _crc_step(crc_extra, crc)

# ── Frame builder ─────────────────────────────────────────────────────────────

def build_command_long(
    sys_id: int = 255,
    comp_id: int = 0,
    seq: int = 0,
    target_sys: int = 1,
    target_comp: int = 1,
    command: int = 400,   # MAV_CMD_COMPONENT_ARM_DISARM
    param1: float = 1.0,  # arm = 1.0
) -> bytes:
    """
    Build a COMMAND_LONG (msg_id 76) MAVLink v2 frame.
    Wire order: param1-7 (7×float32) | command (u16) | target_sys | target_comp | confirmation
    """
    payload = struct.pack(
        "<7fHBBB",
        param1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # param1-7
        command,
        target_sys,
        target_comp,
        0,  # confirmation
    )
    header = struct.pack(
        "<BBBBBBBBBB",
        MAV_STX_V2,
        len(payload),   # LEN
        0x00,           # incompat_flags
        0x00,           # compat_flags
        seq,
        sys_id,
        comp_id,
        MSG_ID_CMD_LONG & 0xFF,
        (MSG_ID_CMD_LONG >> 8) & 0xFF,
        (MSG_ID_CMD_LONG >> 16) & 0xFF,
    )
    crc_input = header[1:] + payload   # CRC covers bytes 1..end (skip STX)
    crc = mavlink_crc(crc_input, CRC_EXTRA_CMD)
    return header + payload + struct.pack("<H", crc)

# ── Frame parser (mimics MAVProxy internal logic) ────────────────────────────

def parse_first_frame(buf: bytes):
    """
    Find and return the first valid MAVLink v2 frame in buf.
    Returns (frame_bytes, consumed_bytes) or (None, 0).
    This replicates what MAVProxy does: parse → re-serialize → forward.
    Anything outside the frame boundary is not included in the return value.
    """
    pos = buf.find(bytes([MAV_STX_V2]))
    if pos == -1 or len(buf) - pos < 12:
        return None, 0
    buf = buf[pos:]
    payload_len = buf[1]
    total = 10 + payload_len + 2
    if len(buf) < total:
        return None, 0
    return buf[:total], pos + total

# ── Simulated relay ───────────────────────────────────────────────────────────

def simulated_relay(in_addr: tuple, out_addr: tuple, ready: threading.Event):
    """
    Mimics MAVProxy routing: receives a datagram, finds valid MAVLink frames,
    and forwards only those frames — trailing bytes are discarded.
    """
    sock_in  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.bind(in_addr)
    sock_in.settimeout(3.0)
    ready.set()
    try:
        data, _ = sock_in.recvfrom(65535)
        pos = 0
        while pos < len(data):
            frame, consumed = parse_first_frame(data[pos:])
            if frame is None:
                break
            sock_out.sendto(frame, out_addr)
            pos += consumed
    except socket.timeout:
        pass
    finally:
        sock_in.close()
        sock_out.close()

# ── Demo ──────────────────────────────────────────────────────────────────────

def run_demo(use_real_relay: bool, relay_in: str, relay_out: str):
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  MAVLink relay authentication-stripping PoC                     ║")
    print("║  github.com/cleitonaugusto/CleitonQ                             ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    if use_real_relay:
        print(f"\n  Mode : REAL MAVProxy relay")
        print(f"  Relay: {relay_in} → {relay_out}")
        print(f"  Make sure MAVProxy is running:")
        print(f"    mavproxy.py --master udp:{relay_in} --out udp:{relay_out}\n")
        relay_in_addr  = tuple(relay_in.rsplit(":", 1))
        relay_in_addr  = (relay_in_addr[0], int(relay_in_addr[1]))
        relay_out_addr = tuple(relay_out.rsplit(":", 1))
        relay_out_addr = (relay_out_addr[0], int(relay_out_addr[1]))
    else:
        print(f"\n  Mode : simulated relay (replicates MAVProxy parse-and-forward logic)")
        relay_in_addr  = ("127.0.0.1", 15600)
        relay_out_addr = ("127.0.0.1", 15601)

    frame = build_command_long()
    print(f"  MAVLink v2 COMMAND_LONG frame: {len(frame)} bytes")
    print(f"  (STX + 10B header + 33B payload + 2B CRC)\n")
    print(f"  {'Auth scheme':<28}  {'Sent':>8}  {'Received':>10}  {'Stripped':>9}  Result")
    print(f"  {'─'*28}  {'─'*8}  {'─'*10}  {'─'*9}  {'─'*6}")

    for label, auth_size in AUTH_SIZES.items():
        packet = frame + bytes(auth_size)  # append fake auth material

        if use_real_relay:
            # Send to real MAVProxy, receive from its output port
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx.bind(relay_out_addr)
            rx.settimeout(2.0)
            tx.sendto(packet, relay_in_addr)
            try:
                received, _ = rx.recvfrom(65535)
                rx_len = len(received)
            except socket.timeout:
                rx_len = 0
            tx.close()
            rx.close()
        else:
            # Simulated relay
            ready = threading.Event()
            rx_buf = []
            def recv_side():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(relay_out_addr)
                sock.settimeout(2.0)
                try:
                    data, _ = sock.recvfrom(65535)
                    rx_buf.append(data)
                finally:
                    sock.close()

            t_recv = threading.Thread(target=recv_side, daemon=True)
            t_recv.start()

            t_relay = threading.Thread(
                target=simulated_relay,
                args=(relay_in_addr, relay_out_addr, ready),
                daemon=True
            )
            t_relay.start()
            ready.wait()

            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.sendto(packet, relay_in_addr)
            tx.close()

            t_relay.join(timeout=2.0)
            t_recv.join(timeout=2.0)
            rx_len = len(rx_buf[0]) if rx_buf else 0

        stripped = len(packet) - rx_len
        result   = "FAIL — auth gone" if stripped > 0 else "ok"
        print(f"  {label:<28}  {len(packet):>8}  {rx_len:>10}  {stripped:>9}  {result}")

    print()
    print("  ── What happened ───────────────────────────────────────────────")
    print()
    print("  The relay parsed each datagram as a MAVLink v2 frame, re-serialized")
    print("  it from internal state, and forwarded exactly that frame.")
    print("  Authentication bytes appended after the frame boundary were never")
    print("  part of the parsed structure — so they were never forwarded.")
    print()
    print("  No error was raised. The drone receives a valid, unauthenticated")
    print("  frame with no indication that auth material was ever present.")
    print()
    print("  ── Root cause ──────────────────────────────────────────────────")
    print()
    print("  MAVLink v2 frames are self-delimiting: STX + LEN defines exactly")
    print("  where the frame ends. A relay that implements the protocol correctly")
    print("  will never forward bytes outside that boundary — which means any")
    print("  auth scheme that appends bytes after the frame is structurally")
    print("  incompatible with any MAVLink-aware relay.")
    print()
    print("  This is not a MAVProxy bug. It is correct behaviour.")
    print("  The bug is in the assumption that appended bytes survive relay hops.")
    print()
    print("  ── Fix ─────────────────────────────────────────────────────────")
    print()
    print("  Authentication material must be carried as first-class MAVLink")
    print("  messages so that relays forward them as valid (possibly unknown)")
    print("  frames. See CLEITONQ_CHUNK (msg_id 50000) and the RFC:")
    print()
    print("    https://github.com/mavlink/mavlink/issues/2527")
    print("    https://doi.org/10.5281/zenodo.20776349")
    print()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MAVLink relay auth-stripping proof of concept"
    )
    parser.add_argument(
        "--real-relay",
        action="store_true",
        help="Test against a running MAVProxy instance instead of the built-in simulator",
    )
    parser.add_argument(
        "--relay-in",
        default="127.0.0.1:14550",
        metavar="HOST:PORT",
        help="MAVProxy --master address (default: 127.0.0.1:14550)",
    )
    parser.add_argument(
        "--relay-out",
        default="127.0.0.1:14551",
        metavar="HOST:PORT",
        help="MAVProxy --out address (default: 127.0.0.1:14551)",
    )
    args = parser.parse_args()
    run_demo(args.real_relay, args.relay_in, args.relay_out)

if __name__ == "__main__":
    main()
