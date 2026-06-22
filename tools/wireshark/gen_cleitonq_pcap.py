#!/usr/bin/env python3
"""
gen_cleitonq_pcap.py
────────────────────
Generates a .pcap file containing simulated CLEITONQ_CHUNK traffic so the
Wireshark dissector can be tested without physical hardware.

Produces two scenarios in the same capture:
  1. SESSION_INIT  — 7 chunks carrying a 1568-byte ML-KEM-1024 ciphertext
  2. SIGNED_CMD    — 20 chunks carrying a 4671-byte ML-DSA-87 signed command

No external dependencies. Python 3.6+.

USAGE
─────
  python3 gen_cleitonq_pcap.py                   # writes cleitonq_demo.pcap
  python3 gen_cleitonq_pcap.py -o my.pcap
  wireshark cleitonq_demo.pcap
"""

import argparse
import os
import random
import struct
import time

# ── MAVLink v2 constants ──────────────────────────────────────────────────────

MAV_STX_V2       = 0xFD
CLEITONQ_MSG_ID  = 50000
CRC_EXTRA        = 0xCE   # verified against mavgen output
CHUNK_DATA_BYTES = 245
MSG_PAYLOAD_LEN  = 253    # 2 + 6×1 + 245

FRAME_SIGNED_CMD    = 0
FRAME_SESSION_INIT  = 1

GCS_SYS  = 255
GCS_COMP = 0
DRONE_SYS  = 1
DRONE_COMP = 1

# ── CRC-16-MCRF4XX ───────────────────────────────────────────────────────────

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

def build_chunk_frame(
    seq: int,
    sys_id: int,
    comp_id: int,
    session_token: int,
    target_sys: int,
    target_comp: int,
    frame_type: int,
    chunk_seq: int,
    chunk_count: int,
    chunk_data: bytes,
) -> bytes:
    data_len = len(chunk_data)
    padded   = chunk_data + bytes(CHUNK_DATA_BYTES - len(chunk_data))

    # Wire order: session_token(u16), target_system, target_component,
    #             frame_type, chunk_seq, chunk_count, data_len, data[245]
    payload = struct.pack(
        "<H6B245s",
        session_token,
        target_sys,
        target_comp,
        frame_type,
        chunk_seq,
        chunk_count,
        data_len,
        padded,
    )
    assert len(payload) == MSG_PAYLOAD_LEN, len(payload)

    header = struct.pack(
        "<BBBBBBBBBB",
        MAV_STX_V2,
        MSG_PAYLOAD_LEN,
        0x00,        # incompat_flags
        0x00,        # compat_flags
        seq & 0xFF,
        sys_id,
        comp_id,
        CLEITONQ_MSG_ID & 0xFF,
        (CLEITONQ_MSG_ID >> 8) & 0xFF,
        (CLEITONQ_MSG_ID >> 16) & 0xFF,
    )
    crc_buf = header[1:] + payload
    crc     = mavlink_crc(crc_buf, CRC_EXTRA)
    return header + payload + struct.pack("<H", crc)

# ── pcap writer (no external libs) ───────────────────────────────────────────

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic
    2, 4,        # version
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # network: LINKTYPE_ETHERNET
)

ETH_HEADER  = bytes([0x00]*6 + [0xFF]*6 + [0x08, 0x00])  # src=0, dst=broadcast, IPv4
IP_PROTO_UDP = 0x11

def _ip_checksum(hdr: bytes) -> int:
    if len(hdr) % 2:
        hdr += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(hdr)//2), hdr))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_udp_packet(src_ip: bytes, dst_ip: bytes,
                     src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    # recalculate UDP checksum via pseudo-header (optional, set to 0 is valid)

    ip_len = 20 + udp_len
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,        # ver+ihl, dscp
        ip_len,
        0, 0,           # id, flags+frag
        64, IP_PROTO_UDP, 0,  # ttl, proto, checksum placeholder
        src_ip, dst_ip,
    )
    csum = _ip_checksum(ip_hdr_no_csum)
    ip_hdr = ip_hdr_no_csum[:10] + struct.pack("!H", csum) + ip_hdr_no_csum[12:]
    return ETH_HEADER + ip_hdr + udp

def pcap_record(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data

# ── Chunk splitter ────────────────────────────────────────────────────────────

def split_into_chunks(payload: bytes):
    chunks = []
    for i in range(0, len(payload), CHUNK_DATA_BYTES):
        chunks.append(payload[i:i + CHUNK_DATA_BYTES])
    return chunks

# ── Demo scenarios ────────────────────────────────────────────────────────────

def make_session_init_payload() -> bytes:
    """Simulated ML-KEM-1024 ciphertext (1568 bytes, random for demo)."""
    random.seed(42)
    return bytes([random.randint(0, 255) for _ in range(1568)])

def make_signed_cmd_payload() -> bytes:
    """Simulated ML-DSA-87 signed COMMAND_LONG (30B payload + 4641B auth)."""
    cmd_body = struct.pack("<7fHBBB",
        1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # params
        400,   # MAV_CMD_COMPONENT_ARM_DISARM
        1, 1,  # target sys/comp
        0,     # confirmation
    )
    nonce     = struct.pack("<Q", 1)
    fake_sig  = bytes([0xAA] * 4627)           # simulated ML-DSA-87 signature
    return cmd_body + nonce + fake_sig          # 4671 bytes total

# ── Main ──────────────────────────────────────────────────────────────────────

def generate(output: str):
    records = []
    seq     = 0
    base_ts = int(time.time())
    usec    = 0

    GCS_IP   = bytes([192, 168, 1, 100])
    DRONE_IP = bytes([192, 168, 1, 1])

    def emit(mavframe: bytes, ts_usec_offset: int):
        nonlocal records
        ts_s  = base_ts + ts_usec_offset // 1_000_000
        ts_us = ts_usec_offset % 1_000_000
        pkt   = build_udp_packet(GCS_IP, DRONE_IP, 14550, 14550, mavframe)
        records.append(pcap_record(ts_s, ts_us, pkt))

    # ── Scenario 1: SESSION_INIT (7 chunks × 245B ≈ 1568B KEM ciphertext) ────
    session_payload = make_session_init_payload()
    chunks          = split_into_chunks(session_payload)
    token_init      = 0x1A2B
    t               = 0

    for i, chunk in enumerate(chunks):
        frame = build_chunk_frame(
            seq=seq, sys_id=GCS_SYS, comp_id=GCS_COMP,
            session_token=token_init,
            target_sys=DRONE_SYS, target_comp=DRONE_COMP,
            frame_type=FRAME_SESSION_INIT,
            chunk_seq=i, chunk_count=len(chunks),
            chunk_data=chunk,
        )
        emit(frame, t)
        seq += 1
        t   += 2000  # 2 ms between chunks

    # small gap between scenarios
    t += 100_000  # 100 ms

    # ── Scenario 2: SIGNED_CMD (20 chunks × 245B ≈ 4671B signed command) ────
    cmd_payload = make_signed_cmd_payload()
    chunks      = split_into_chunks(cmd_payload)
    token_cmd   = 0x3C4D

    for i, chunk in enumerate(chunks):
        frame = build_chunk_frame(
            seq=seq, sys_id=GCS_SYS, comp_id=GCS_COMP,
            session_token=token_cmd,
            target_sys=DRONE_SYS, target_comp=DRONE_COMP,
            frame_type=FRAME_SIGNED_CMD,
            chunk_seq=i, chunk_count=len(chunks),
            chunk_data=chunk,
        )
        emit(frame, t)
        seq += 1
        t   += 2000

    with open(output, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for r in records:
            f.write(r)

    total_pkts = len(records)
    print(f"Written {output}")
    print(f"  {total_pkts} packets total")
    print(f"  Scenario 1: SESSION_INIT  {len(make_session_init_payload())} bytes → "
          f"{len(split_into_chunks(make_session_init_payload()))} chunks  token=0x{token_init:04x}")
    print(f"  Scenario 2: SIGNED_CMD    {len(make_signed_cmd_payload())} bytes → "
          f"{len(split_into_chunks(make_signed_cmd_payload()))} chunks  token=0x{token_cmd:04x}")
    print()
    print("Open in Wireshark:")
    print(f"  wireshark {output}")
    print()
    print("Display filters:")
    print("  cleitonq                              — all chunks")
    print("  cleitonq.frame_type == 1              — SESSION_INIT only")
    print("  cleitonq.frame_type == 0              — SIGNED_CMD only")
    print('  cleitonq.reassembly contains "COMPLETE" — completed payloads')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate CleitonQ demo pcap")
    parser.add_argument("-o", "--output", default="cleitonq_demo.pcap")
    args = parser.parse_args()
    generate(args.output)
