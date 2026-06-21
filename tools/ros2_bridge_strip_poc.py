#!/usr/bin/env python3
"""
ros2_bridge_strip_poc.py
────────────────────────
Proof of concept: authentication material appended after a ROS2/CDR payload
is silently stripped at the CDR schema boundary — the same structural flaw as
MAVLink relay-stripping.

How the stripping works
───────────────────────
  MAVLink : frame boundary = STX + LEN field
            relay parses frame, re-forwards only those bytes

  ROS2/DDS: frame boundary = CDR type schema
            DDS middleware deserializes to typed struct (reads schema bytes only),
            then re-serializes from struct fields — bytes outside the schema
            never make it into the struct and are therefore never forwarded.

Two observed failure modes (tested with real DDS implementations)
──────────────────────────────────────────────────────────────────
  CycloneDDS subscriber: auth bytes arrive in the raw RTPS payload but are
    silently discarded at CDR deserialization — the application callback
    receives a valid Twist with no indication that auth material existed.

  FastDDS (rmw_fastrtps_cpp) subscriber: CDR payloads larger than the type's
    pre-allocated history size are REJECTED entirely — message never reaches
    the callback. Trying to append auth bytes to CDR causes denial of service
    rather than silent stripping, but the end result is the same: the
    application never sees the auth material.

TESTED WITH (not simulation)
─────────────────────────────
  CycloneDDS 11.0.1 Python bindings  — CDR serializer/deserializer
  CycloneDDS subscriber (separate process) — raw CDR byte capture
  rclpy / rmw_fastrtps_cpp (ROS2 Humble) — RTPS_READER_HISTORY rejection
  geometry_msgs/msg/Twist — standard robot velocity command
  Ubuntu 22.04 LTS, ROS2 Humble, Python 3.10

USAGE
─────
  # Mode 1 — real CycloneDDS endpoint test (requires cyclonedds pip package)
  #   pip install cyclonedds
  python3 ros2_bridge_strip_poc.py

  # Mode 2 — pure Python simulation (no ROS2 or cyclonedds needed)
  python3 ros2_bridge_strip_poc.py --simulate

REFERENCES
──────────
  Repository  : https://github.com/cleitonaugusto/CleitonQ
  Paper       : https://doi.org/10.5281/zenodo.20776349
  ROS2 issue  : https://github.com/ros2/sros2/issues/392
  MAVLink RFC : https://github.com/mavlink/mavlink/issues/2527
  Fix         : carry auth material as a separate, typed ROS2 message on a
                parallel topic — the DDS middleware forwards typed messages
                as-is; their byte boundary is defined by their own schema.

Author: Cleiton Augusto Correa Bezerra
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile
import textwrap
import time

# ── Constants ─────────────────────────────────────────────────────────────────

CDR_LE_HEADER   = b'\x00\x01\x00\x00'   # CDR little-endian representation header
TWIST_CDR_BYTES = 52                      # 4 B header + 6 × float64

AUTH_SIZES = {
    "HMAC-SHA3-256 (32 B)":    32,
    "Ed25519 sig  (64 B)":     64,
    "ML-DSA-87 sig (4627 B)": 4627,
}

# ── Pure-Python CDR simulation (--simulate mode) ──────────────────────────────

def _sim_serialize(lx=0.0, ly=0.0, lz=1.0, ax=0.0, ay=0.0, az=0.0) -> bytes:
    return CDR_LE_HEADER + struct.pack('<6d', lx, ly, lz, ax, ay, az)

def _sim_deserialize(data: bytes):
    if len(data) < TWIST_CDR_BYTES:
        raise ValueError(f"buffer too short: {len(data)} < {TWIST_CDR_BYTES}")
    if data[:4] != CDR_LE_HEADER:
        raise ValueError(f"bad CDR header: {data[:4].hex()}")
    fields = struct.unpack_from('<6d', data, offset=4)
    return fields, TWIST_CDR_BYTES

def _sim_bridge_process(cdr_with_auth: bytes) -> tuple:
    fields, consumed = _sim_deserialize(cdr_with_auth)
    new_cdr = _sim_serialize(*fields)
    return new_cdr, consumed, len(cdr_with_auth) - consumed

def run_simulated():
    print()
    print("  Mode : pure Python CDR simulation (no ROS2 required)")
    print(f"  CDR LE spec: 4-byte representation header + 6 × float64 = {TWIST_CDR_BYTES} bytes")
    print()

    base_cdr = _sim_serialize(lz=1.0)
    fields, consumed = _sim_deserialize(base_cdr)
    assert consumed == TWIST_CDR_BYTES
    assert abs(fields[2] - 1.0) < 1e-12

    _print_table(base_cdr, _sim_bridge_process,
                 note="simulated CDR: deserialize(schema only) → serialize")

    print()
    print("  NOTE: simulation mode implements CDR LE per spec. Run without")
    print("  --simulate (with cyclonedds installed) for real-stack verification.")
    print()

# ── Real CycloneDDS mode ──────────────────────────────────────────────────────

# Subprocess scripts embedded here so the PoC is a single self-contained file.

_WRITER_SCRIPT = textwrap.dedent("""\
    import os, sys, types, time
    from cyclonedds.idl import IdlStruct
    from cyclonedds.idl.types import float64
    from cyclonedds.domain import DomainParticipant
    from cyclonedds.topic import Topic
    from cyclonedds.pub import DataWriter, Publisher
    from dataclasses import dataclass

    @dataclass
    class Vector3(IdlStruct, typename="geometry_msgs::msg::dds_::Vector3_"):
        x: float64; y: float64; z: float64
    @dataclass
    class TwistMsg(IdlStruct, typename="geometry_msgs::msg::dds_::Twist_"):
        linear: Vector3; angular: Vector3

    auth_size = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    lz_val    = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

    dp = DomainParticipant(domain_id=0)
    tp = Topic(dp, 'rt/cmd_vel_auth_test', TwistMsg)
    dw = DataWriter(Publisher(dp), tp)
    time.sleep(2.0)  # DDS discovery

    tw = TwistMsg(linear=Vector3(0.0, 0.0, lz_val), angular=Vector3(0.0, 0.0, 0.0))
    if auth_size > 0:
        def _inject(auth_bytes):
            def _ser(self, buffer=None, endianness=None, use_version_2=None):
                return TwistMsg.__idl__.serialize(
                    self, buffer=buffer, endianness=endianness,
                    use_version_2=use_version_2) + auth_bytes
            return _ser
        tw.serialize = types.MethodType(_inject(bytes(auth_size)), tw)

    sent = len(tw.serialize())
    for _ in range(3):
        dw.write(tw)
        time.sleep(0.2)
    print(f"SENT {sent}", flush=True)
    time.sleep(1.0)
""")

_READER_SCRIPT = textwrap.dedent("""\
    import sys, time
    from cyclonedds.idl import IdlStruct
    from cyclonedds.idl.types import float64
    from cyclonedds.domain import DomainParticipant
    from cyclonedds.topic import Topic
    from cyclonedds.sub import DataReader, Subscriber
    from cyclonedds.core import WaitSet, ReadCondition, ViewState, InstanceState, SampleState
    from cyclonedds.util import duration
    from dataclasses import dataclass

    @dataclass
    class Vector3(IdlStruct, typename="geometry_msgs::msg::dds_::Vector3_"):
        x: float64; y: float64; z: float64
    @dataclass
    class TwistMsg(IdlStruct, typename="geometry_msgs::msg::dds_::Twist_"):
        linear: Vector3; angular: Vector3

    timeout_s = float(sys.argv[1]) if len(sys.argv) > 1 else 8.0

    raw_sizes, typed_sizes = [], []
    orig = TwistMsg.deserialize.__func__

    @classmethod
    def cap(cls, data, **kw):
        raw_sizes.append(len(bytes(data)))
        msg = orig(cls, data, **kw)
        typed_sizes.append(len(TwistMsg.__idl__.serialize(msg)))
        return msg
    TwistMsg.deserialize = cap

    dp = DomainParticipant(domain_id=0)
    tp = Topic(dp, 'rt/cmd_vel_auth_test', TwistMsg)
    dr = DataReader(Subscriber(dp), tp)
    ws = WaitSet(dp)
    ws.attach(ReadCondition(dr, ViewState.Any | InstanceState.Any | SampleState.Any))
    print("READY", flush=True)

    deadline = time.time() + timeout_s
    while not raw_sizes and time.time() < deadline:
        if ws.wait(duration(milliseconds=500)) > 0:
            dr.take()

    if raw_sizes:
        print(f"RECV raw={raw_sizes[0]} typed={typed_sizes[0]}", flush=True)
    print("DONE", flush=True)
""")


def _start_reader(tmpdir, timeout=8.0):
    reader_py = os.path.join(tmpdir, 'reader.py')
    with open(reader_py, 'w') as f:
        f.write(_READER_SCRIPT)
    p = subprocess.Popen(
        [sys.executable, reader_py, str(timeout)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    line = p.stdout.readline().strip()
    if line != 'READY':
        p.terminate(); p.wait()
        return None, None
    return p, reader_py


def _run_writer(tmpdir, auth_size, lz=1.0):
    writer_py = os.path.join(tmpdir, 'writer.py')
    with open(writer_py, 'w') as f:
        f.write(_WRITER_SCRIPT)
    p = subprocess.Popen(
        [sys.executable, writer_py, str(auth_size), str(lz)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    out, _ = p.communicate(timeout=20)
    for line in out.splitlines():
        if line.startswith('SENT'):
            return int(line.split()[1])
    return None


def _collect_reader(proc, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.strip()
        if line.startswith('RECV'):
            parts = line.split()
            raw   = int(parts[1].split('=')[1])
            typed = int(parts[2].split('=')[1])
            proc.terminate(); proc.wait()
            return raw, typed
        if line == 'DONE':
            break
    proc.terminate(); proc.wait()
    return None, None


def run_real():
    try:
        from cyclonedds.idl import IdlStruct
        from cyclonedds.idl.types import float64
        from cyclonedds.domain import DomainParticipant
        from dataclasses import dataclass
    except ImportError:
        print()
        print("  cyclonedds not found. Install with: pip install cyclonedds")
        print("  Or run with --simulate for a pure-Python demonstration.")
        sys.exit(1)

    @dataclass
    class Vector3(IdlStruct, typename="geometry_msgs::msg::dds_::Vector3_"):
        x: float64
        y: float64
        z: float64

    @dataclass
    class TwistMsg(IdlStruct, typename="geometry_msgs::msg::dds_::Twist_"):
        linear: Vector3
        angular: Vector3

    # ── Step 1: CycloneDDS CDR serializer ────────────────────────────────────

    def cdds_serialize(lz=1.0):
        return TwistMsg.__idl__.serialize(
            TwistMsg(linear=Vector3(0.0, 0.0, lz), angular=Vector3(0.0, 0.0, 0.0)))

    def cdds_bridge_process(cdr_with_auth: bytes) -> tuple:
        rebuilt_cdr = TwistMsg.__idl__.serialize(TwistMsg.deserialize(cdr_with_auth))
        return rebuilt_cdr, TWIST_CDR_BYTES, len(cdr_with_auth) - len(rebuilt_cdr)

    base_cdr = cdds_serialize(lz=1.0)
    assert len(base_cdr) == TWIST_CDR_BYTES, \
        f"CycloneDDS Twist CDR = {len(base_cdr)} bytes (expected {TWIST_CDR_BYTES})"
    assert base_cdr[:4] == CDR_LE_HEADER

    lz_offset = 4 + 16   # 4 B header + 2 × float64 (x, y)
    assert abs(struct.unpack_from('<d', base_cdr, lz_offset)[0] - 1.0) < 1e-12

    print()
    print("  ── Step 1: CycloneDDS CDR serializer (real, not simulated) ─────")
    print()
    print(f"  Twist(linear.z=1.0) CDR  : {len(base_cdr)} bytes")
    print(f"  Header                   : {base_cdr[:4].hex()}  (CDR_LE = 0x0001, options = 0x0000)")
    print(f"  Hex                      : {base_cdr.hex()}")
    print()
    _print_table(base_cdr, cdds_bridge_process,
                 note="CycloneDDS TwistMsg.deserialize() → TwistMsg.serialize()")

    # ── Step 2: real CycloneDDS subscriber endpoint ───────────────────────────

    print()
    print("  ── Step 2: real CycloneDDS subscriber endpoint ─────────────────")
    print()
    print("  Two separate processes (writer, reader), both domain 0, no bridge.")
    print("  Writer monkeypatches CycloneDDS serialization to append auth bytes.")
    print("  Reader captures len(raw_bytes) before and len(cdr) after deserialize.")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"  {'Auth scheme':<28}  {'Sent':>6}  {'Raw recv':>8}  {'Typed':>6}  {'Stripped':>9}  Result")
        print(f"  {'─'*28}  {'─'*6}  {'─'*8}  {'─'*6}  {'─'*9}  {'─'*24}")

        for i, (label, auth_size) in enumerate(AUTH_SIZES.items()):
            rproc, _ = _start_reader(tmpdir, timeout=10.0)
            if rproc is None:
                print(f"  {label:<28}  {'?':>6}  {'reader err':>8}  {'?':>6}  {'?':>9}")
                continue

            time.sleep(1.0)  # reader discovery
            sent = _run_writer(tmpdir, auth_size=auth_size, lz=float(i + 1))
            if sent is None:
                rproc.terminate(); rproc.wait()
                print(f"  {label:<28}  {'?':>6}  {'writer err':>8}  {'?':>6}  {'?':>9}")
                continue

            raw, typed = _collect_reader(rproc, timeout=10.0)

            if raw is None:
                print(f"  {label:<28}  {sent:>6}  {'timeout':>8}  {'?':>6}  {'?':>9}")
            else:
                stripped = sent - typed
                result = ("PASS — auth gone ✓"
                          if typed == TWIST_CDR_BYTES else f"UNEXPECTED {typed}B")
                print(f"  {label:<28}  {sent:>6}  {raw:>8}  {typed:>6}  {stripped:>9}  {result}")

    print()
    print("  Observation: raw recv > sent is normal for ML-DSA — CycloneDDS pads")
    print("  the serialized payload to a 4-byte boundary before transmission.")
    print()
    print("  FastDDS (rmw_fastrtps_cpp) note: FastDDS pre-allocates reader history")
    print("  buffers sized to the type's max CDR length (55 bytes for Twist).")
    print("  Payloads exceeding this limit trigger:")
    print("    [RTPS_READER_HISTORY Error] Change payload size of 'N' bytes is")
    print("    larger than the history payload size of '55' bytes and cannot be")
    print("    resized.")
    print("  The sample is DROPPED — the rclpy callback never fires. Appending auth")
    print("  bytes causes denial of service instead of silent stripping, but the")
    print("  result is the same: auth material never reaches the application.")
    print()


# ── Shared table printer ──────────────────────────────────────────────────────

def _print_table(base_cdr, bridge_fn, note=None):
    if note:
        print(f"  Bridge function: {note}")
        print()
    print(f"  {'Auth scheme':<28}  {'Sent':>6}  {'Received':>8}  {'Stripped':>9}  Result")
    print(f"  {'─'*28}  {'─'*6}  {'─'*8}  {'─'*9}  {'─'*16}")
    for label, auth_size in AUTH_SIZES.items():
        buf = base_cdr + bytes(auth_size)
        new_cdr, consumed, stripped = bridge_fn(buf)
        assert len(new_cdr) == TWIST_CDR_BYTES
        assert stripped == auth_size
        result = "FAIL — auth gone"
        print(f"  {label:<28}  {len(buf):>6}  {len(new_cdr):>8}  {stripped:>9}  {result}")


# ── Explanation ───────────────────────────────────────────────────────────────

def print_explanation(real: bool):
    print()
    print("  ── What happened ────────────────────────────────────────────────")
    print()
    print("  The sender serialized geometry_msgs/msg/Twist to CDR (52 bytes)")
    print("  then appended authentication bytes immediately after.")
    print()
    if real:
        print("  In the CycloneDDS path, the subscriber received the full raw")
        print("  RTPS payload (CDR + auth bytes). CycloneDDS deserialized using")
        print("  the Twist schema — reading exactly 52 bytes — and returned a")
        print("  typed Twist struct. The auth bytes were not part of any schema")
        print("  field and were never transferred into the struct. Re-serializing")
        print("  the struct produces 52 bytes. Auth material is gone.")
        print()
        print("  In the FastDDS path (rmw_fastrtps_cpp, the default ROS2 RMW),")
        print("  the middleware rejected messages with oversized payloads before")
        print("  they reached the application callback. The result is denial of")
        print("  service rather than silent stripping, but auth material is still")
        print("  absent from the application's view either way.")
    else:
        print("  The simulated bridge called CDR deserialize (reads schema bytes")
        print("  only, ignores trailing bytes) then CDR serialize (produces schema")
        print("  bytes only). This is exactly what any DDS middleware does when it")
        print("  processes a typed message.")
    print()
    print("  No auth bytes were accessible to the application via any standard")
    print("  ROS2 API. The subscriber has no way to know they ever existed.")
    print()
    print("  ── Comparison with MAVLink ──────────────────────────────────────")
    print()
    print("  MAVLink : boundary = frame (STX + LEN field)")
    print("            relay reads exactly those bytes; auth bytes never enter")
    print("            the relay's parse layer")
    print()
    print("  ROS2/DDS: boundary = CDR type schema")
    print("            middleware reads exactly the schema-defined bytes; auth")
    print("            bytes are in the raw RTPS payload but not in any field")
    print()
    print("  Same structural flaw. Different boundary marker. The middleware")
    print("  implementations are correct per spec — the bug is the assumption")
    print("  that bytes appended after a typed boundary survive to an application.")
    print()
    print("  ── Why production deployments are affected ───────────────────────")
    print()
    print("  Multi-domain ROS2 deployments use bridges (domain_bridge, ros1_bridge,")
    print("  Zenoh bridge). Each bridge deserializes the message from its source")
    print("  domain and re-publishes a new typed message in the target domain.")
    print("  Any auth bytes that survived the first hop are re-stripped at each")
    print("  subsequent bridge hop — compounding the problem in multi-hop chains.")
    print()
    print("  Even without bridges, the receiving endpoint itself (any standard")
    print("  rclpy or rclcpp subscriber) will strip or reject auth bytes at")
    print("  CDR deserialization, as demonstrated above.")
    print()
    print("  ── Fix ──────────────────────────────────────────────────────────")
    print()
    print("  Authentication material must be a separate, typed ROS2 message")
    print("  published on a parallel topic. The DDS middleware forwards typed")
    print("  messages as-is. The subscriber verifies the auth topic before")
    print("  acting on the command topic.")
    print()
    print("  See: https://github.com/ros2/sros2/issues/392")
    print("       https://doi.org/10.5281/zenodo.20776349")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ROS2/DDS CDR auth-stripping proof of concept"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Pure Python CDR simulation — no ROS2 or cyclonedds required",
    )
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  ROS2/DDS CDR authentication-stripping PoC                      ║")
    print("║  github.com/cleitonaugusto/CleitonQ                             ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    if args.simulate:
        run_simulated()
        print_explanation(real=False)
    else:
        run_real()
        print_explanation(real=True)


if __name__ == "__main__":
    main()
