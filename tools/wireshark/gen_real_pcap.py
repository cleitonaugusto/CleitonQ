#!/usr/bin/env python3
"""
gen_real_pcap.py
────────────────
Generates a .pcap with REAL CleitonQ cryptographic operations:
  - Scenario 1: SESSION_INIT  — actual ML-KEM-1024 ciphertext (1568 bytes)
  - Scenario 2: SIGNED_CMD    — actual ML-DSA-87 signed command
  - Scenario 3: HMAC_TELEMETRY — actual HMAC-SHA3-256 authenticated packet

Requires the CleitonQ Python bindings (cleitonq-python/):
  cd cleitonq-python && maturin develop    # build once
  python3 tools/wireshark/gen_real_pcap.py

Or without installing:
  PYTHONPATH=cleitonq-python python3 tools/wireshark/gen_real_pcap.py

No other external dependencies. Python 3.6+.

USAGE
─────
  python3 gen_real_pcap.py                   # writes cleitonq_real.pcap
  python3 gen_real_pcap.py -o my.pcap
  wireshark cleitonq_real.pcap
"""

import argparse
import struct
import time
import math
import sys

try:
    import cleitonq
except ImportError:
    print("ERROR: cleitonq module not found.")
    print("Run from repo root:")
    print("  PYTHONPATH=cleitonq-python python3 tools/wireshark/gen_real_pcap.py")
    sys.exit(1)

# ── MAVLink v2 constants ──────────────────────────────────────────────────────

MAV_STX_V2       = 0xFD
CLEITONQ_MSG_ID  = 50000
CRC_EXTRA        = 0xCE
CHUNK_DATA_BYTES = 245
MSG_PAYLOAD_LEN  = 253

FRAME_SIGNED_CMD    = 0
FRAME_SESSION_INIT  = 1

GCS_SYS  = 255; GCS_COMP  = 0
DRONE_SYS = 1;  DRONE_COMP = 1

# ── CRC-16-MCRF4XX ────────────────────────────────────────────────────────────

def _crc_step(byte, crc):
    tmp = byte ^ (crc & 0xFF)
    tmp = tmp ^ ((tmp << 4) & 0xFF)
    return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF

def mavlink_crc(data, extra):
    crc = 0xFFFF
    for b in data:
        crc = _crc_step(b, crc)
    return _crc_step(extra, crc)

# ── Frame builder ─────────────────────────────────────────────────────────────

def build_chunk_frame(seq, sys_id, comp_id, session_token, target_sys,
                      target_comp, frame_type, chunk_seq, chunk_count, chunk_data):
    data_len = len(chunk_data)
    padded   = chunk_data + bytes(CHUNK_DATA_BYTES - len(chunk_data))
    payload  = struct.pack("<H6B245s",
        session_token, target_sys, target_comp,
        frame_type, chunk_seq, chunk_count, data_len, padded)
    assert len(payload) == MSG_PAYLOAD_LEN
    header = struct.pack("<BBBBBBBBBB",
        MAV_STX_V2, MSG_PAYLOAD_LEN, 0x00, 0x00,
        seq & 0xFF, sys_id, comp_id,
        CLEITONQ_MSG_ID & 0xFF,
        (CLEITONQ_MSG_ID >> 8) & 0xFF,
        (CLEITONQ_MSG_ID >> 16) & 0xFF)
    crc = mavlink_crc(header[1:] + payload, CRC_EXTRA)
    return header + payload + struct.pack("<H", crc)

# ── pcap writer ───────────────────────────────────────────────────────────────

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
ETH_HEADER = bytes([0x00]*6 + [0xFF]*6 + [0x08, 0x00])

def _ip_checksum(hdr):
    if len(hdr) % 2: hdr += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(hdr)//2), hdr))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    ip_len = 20 + udp_len
    ip_hdr_no_csum = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0, 64, 0x11, 0, src_ip, dst_ip)
    csum = _ip_checksum(ip_hdr_no_csum)
    ip_hdr = ip_hdr_no_csum[:10] + struct.pack("!H", csum) + ip_hdr_no_csum[12:]
    return ETH_HEADER + ip_hdr + udp

def pcap_record(ts_sec, ts_usec, data):
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data

def split_chunks(payload):
    return [payload[i:i+CHUNK_DATA_BYTES]
            for i in range(0, len(payload), CHUNK_DATA_BYTES)]

# ── Main ──────────────────────────────────────────────────────────────────────

def generate(output):
    GCS_IP   = bytes([192, 168, 1, 100])
    DRONE_IP = bytes([192, 168, 1, 1])
    base_ts  = int(time.time())
    records  = []
    seq      = 0
    t        = 0

    def emit(mavframe, t_us):
        ts_s  = base_ts + t_us // 1_000_000
        ts_us = t_us % 1_000_000
        records.append(pcap_record(ts_s, ts_us,
            build_udp_packet(GCS_IP, DRONE_IP, 14550, 14550, mavframe)))

    # ── Step 1: KEM key exchange (GCS → Drone) ────────────────────────────────
    print("Generating ML-KEM-1024 key pair ...", flush=True)
    dk_seed, ek = cleitonq.kem_keygen()

    print("Encapsulating session key ...", flush=True)
    ct, session_key_gcs = cleitonq.kem_encapsulate(ek)

    # Drone side: verify decapsulation matches
    session_key_drone = cleitonq.kem_decapsulate(dk_seed, ct)
    assert session_key_gcs == session_key_drone, "KEM session key mismatch!"

    # Scenario 1: SESSION_INIT — real ML-KEM-1024 ciphertext
    token_init = 0x1A2B
    chunks     = split_chunks(ct)
    print(f"SESSION_INIT: {len(ct)} bytes → {len(chunks)} chunks", flush=True)

    for i, chunk in enumerate(chunks):
        emit(build_chunk_frame(seq, GCS_SYS, GCS_COMP, token_init,
            DRONE_SYS, DRONE_COMP, FRAME_SESSION_INIT, i, len(chunks), chunk), t)
        seq += 1; t += 2000

    t += 100_000  # 100ms gap

    # ── Step 2: DSA signed command (GCS → Drone) ─────────────────────────────
    print("Generating ML-DSA-87 key pair ...", flush=True)
    sk_seed, vk = cleitonq.dsa_keygen()

    # Realistic COMMAND_LONG: arm/disarm (MAV_CMD=400), target sys=1 comp=1
    command_long = struct.pack("<7fHBBB",
        1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # param1-7 (arm=1.0)
        400,   # MAV_CMD_COMPONENT_ARM_DISARM
        1, 1,  # target_system, target_component
        0,     # confirmation
    )
    assert len(command_long) == 33

    print("Signing COMMAND_LONG with ML-DSA-87 ...", flush=True)
    signed_cmd = cleitonq.dsa_sign(sk_seed, command_long, nonce=1)

    # Verify on drone side
    recovered, accepted_nonce = cleitonq.dsa_verify(vk, signed_cmd, last_nonce=0)
    assert recovered == command_long, "DSA verification failed!"

    # Scenario 2: SIGNED_CMD — real ML-DSA-87 signed command
    token_cmd = 0x3C4D
    chunks    = split_chunks(signed_cmd)
    print(f"SIGNED_CMD: {len(signed_cmd)} bytes → {len(chunks)} chunks", flush=True)

    for i, chunk in enumerate(chunks):
        emit(build_chunk_frame(seq, GCS_SYS, GCS_COMP, token_cmd,
            DRONE_SYS, DRONE_COMP, FRAME_SIGNED_CMD, i, len(chunks), chunk), t)
        seq += 1; t += 2000

    t += 100_000

    # ── Step 3: HMAC-SHA3-256 telemetry packet (GCS ← Drone) ─────────────────
    print("Generating HMAC-SHA3-256 telemetry packet ...", flush=True)
    telemetry = b"alt=42.5 lat=10.001 lon=20.002 hdg=270.0 spd=15.3"
    hmac_packet = cleitonq.channel_sign(
        session_key_drone, cleitonq.DOMAIN_TELEMETRY, telemetry, nonce=1)

    # Verify on GCS side
    recovered_tel, _ = cleitonq.channel_verify(
        session_key_gcs, cleitonq.DOMAIN_TELEMETRY, hmac_packet, last_nonce=0)
    assert recovered_tel == telemetry, "HMAC verification failed!"

    # Scenario 3: single HMAC chunk (fits in one frame, data[40B+overhead] < 245B)
    token_tel = 0x5E6F
    chunks    = split_chunks(hmac_packet)
    print(f"HMAC_TELEMETRY: {len(hmac_packet)} bytes → {len(chunks)} chunk(s)", flush=True)

    for i, chunk in enumerate(chunks):
        emit(build_chunk_frame(seq, DRONE_SYS, DRONE_COMP, token_tel,
            GCS_SYS, GCS_COMP, FRAME_SIGNED_CMD, i, len(chunks), chunk), t)
        seq += 1; t += 2000

    # ── Write pcap ────────────────────────────────────────────────────────────
    with open(output, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for r in records:
            f.write(r)

    print()
    print(f"Written: {output}")
    print(f"  Packets: {len(records)}")
    print(f"  SESSION_INIT  — real ML-KEM-1024 ciphertext  ({cleitonq.KEM_CT_BYTES}B)")
    print(f"  SIGNED_CMD    — real ML-DSA-87 signature      ({cleitonq.DSA_SIG_BYTES}B + 38B overhead)")
    print(f"  HMAC_TELEMETRY — real HMAC-SHA3-256 tag       ({len(telemetry)}B payload + {cleitonq.HMAC_OVERHEAD}B overhead)")
    print()
    print("All cryptographic operations verified:")
    print("  KEM: session_key_gcs == session_key_drone")
    print("  DSA: dsa_verify(vk, signed_cmd) == original command")
    print("  HMAC: channel_verify(session_key) == original telemetry")
    print()
    print(f"Open in Wireshark:")
    print(f"  wireshark {output}")
    print()
    print("Display filters:")
    print("  cleitonq                   — all chunks")
    print("  cleitonq.frame_type == 1   — SESSION_INIT (ML-KEM ciphertext)")
    print("  cleitonq.frame_type == 0   — SIGNED_CMD / HMAC telemetry")
    print("  cleitonq.session_token == 0x1a2b  — KEM session")
    print("  cleitonq.session_token == 0x3c4d  — DSA signed command")
    print("  cleitonq.session_token == 0x5e6f  — HMAC telemetry")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate CleitonQ pcap with REAL cryptographic operations")
    parser.add_argument("-o", "--output", default="cleitonq_real.pcap")
    args = parser.parse_args()
    generate(args.output)
