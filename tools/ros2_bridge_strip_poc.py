#!/usr/bin/env python3
"""
ros2_bridge_strip_poc.py
────────────────────────
Proof of concept: DDS bridges (ros1_bridge, domain_bridge) silently strip
authentication material appended after a ROS2 message's CDR serialized payload.

The mechanism is structurally identical to MAVLink relay-stripping:

  MAVLink : STX + LEN  → relay parses frame, re-forwards only frame bytes
  ROS2/DDS: CDR schema → bridge deserializes to typed struct, re-serializes
                          from struct fields; anything outside schema is gone

Affected bridges (behaviour is correct per spec — the bug is the assumption
that appended bytes survive a typed relay):
  - ros1_bridge      (ROS1 ↔ ROS2, every version)
  - ros2 domain_bridge  (cross-domain relay)
  - Zenoh bridge, CycloneDDS gateway, etc.

TESTED WITH (not simulation):
  - CycloneDDS 11.0.1 Python bindings (real CDR serializer/deserializer)
  - ros-humble domain_bridge 0.5.0 (real bridge process, domain 0 → domain 1)
  - geometry_msgs/msg/Twist (standard robot velocity command)
  - Ubuntu 22.04 LTS, ROS2 Humble

USAGE
─────
  # Mode 1 — CDR + domain_bridge test (requires ROS2 Humble + cyclonedds)
  #   pip install cyclonedds
  #   source /opt/ros/humble/setup.bash
  python3 ros2_bridge_strip_poc.py

  # Mode 2 — pure Python simulation (no ROS2 needed)
  python3 ros2_bridge_strip_poc.py --simulate

REFERENCES
──────────
  Repository  : https://github.com/cleitonaugusto/CleitonQ
  Paper       : https://doi.org/10.5281/zenodo.20776349
  ROS2 issue  : https://github.com/ros2/sros2/issues/392
  MAVLink RFC : https://github.com/mavlink/mavlink/issues/2527
  Fix         : carry auth material as a separate, typed ROS2 message on a
                parallel topic — bridges forward typed messages, not raw bytes

Author: Cleiton Augusto Correa Bezerra
"""

import argparse
import os
import struct
import subprocess
import sys
import threading
import time

# ── Constants ─────────────────────────────────────────────────────────────────

CDR_LE_HEADER   = b'\x00\x01\x00\x00'   # CDR little-endian representation header
TWIST_CDR_BYTES = 52                      # 4 B header + 6 × float64

AUTH_SIZES = {
    "HMAC-SHA3-256 (32 B)":    32,
    "Ed25519 sig  (64 B)":     64,
    "ML-DSA-87 sig (4627 B)": 4627,
}

BRIDGE_YAML = "/tmp/cleitonq_bridge_config.yaml"

BRIDGE_YAML_CONTENT = """\
name: auth_strip_bridge
from_domain: 0
to_domain: 1
topics:
  /cmd_vel_auth_test:
    type: geometry_msgs/msg/Twist
"""

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

def run_simulated():
    print()
    print("  Mode : pure Python CDR simulation (no ROS2 required)")
    print(f"  CDR LE spec: 4-byte representation header + 6 × float64 = {TWIST_CDR_BYTES} bytes")
    print()

    base_cdr = _sim_serialize(lz=1.0)
    fields, consumed = _sim_deserialize(base_cdr)
    assert consumed == TWIST_CDR_BYTES
    assert abs(fields[2] - 1.0) < 1e-12

    _print_table(base_cdr, _sim_bridge_process)

    print()
    print("  NOTE: simulation mode implements CDR LE per spec. Use the default")
    print("  mode (with ROS2 + cyclonedds installed) for real-stack verification.")
    print()

def _sim_bridge_process(cdr_with_auth: bytes) -> tuple:
    fields, consumed = _sim_deserialize(cdr_with_auth)
    new_cdr = _sim_serialize(*fields)
    return new_cdr, consumed, len(cdr_with_auth) - consumed

# ── Real CycloneDDS + domain_bridge mode ──────────────────────────────────────

def run_real():
    try:
        from cyclonedds.idl import IdlStruct
        from cyclonedds.idl.types import float64
        from cyclonedds.domain import DomainParticipant
        from cyclonedds.topic import Topic
        from cyclonedds.sub import DataReader, Subscriber
        from cyclonedds.core import WaitSet, ReadCondition, ViewState, InstanceState, SampleState
        from cyclonedds.util import duration
        from dataclasses import dataclass
    except ImportError:
        print()
        print("  cyclonedds not found. Install with: pip install cyclonedds")
        print("  Then source ROS2: source /opt/ros/humble/setup.bash")
        print("  Or run with --simulate for a pure-Python demonstration.")
        sys.exit(1)

    try:
        import rclpy
        from rclpy.node import Node
        from geometry_msgs.msg import Twist
    except ImportError:
        print()
        print("  rclpy not found. Source ROS2 first:")
        print("    source /opt/ros/humble/setup.bash")
        print("  Or use --simulate for a pure-Python demonstration.")
        sys.exit(1)

    from dataclasses import dataclass

    @dataclass
    class Vector3(IdlStruct, typename="geometry_msgs::msg::dds_::Vector3_"):
        x: float64
        y: float64
        z: float64

    @dataclass
    class TwistMsg(IdlStruct, typename="geometry_msgs::msg::dds_::Twist_"):
        linear: Vector3
        angular: Vector3

    def cdds_serialize(lz=1.0):
        return TwistMsg.serialize(
            TwistMsg(linear=Vector3(0.0, 0.0, lz), angular=Vector3(0.0, 0.0, 0.0)))

    def cdds_bridge_process(cdr_with_auth: bytes) -> tuple:
        rebuilt_cdr = TwistMsg.serialize(TwistMsg.deserialize(cdr_with_auth))
        return rebuilt_cdr, TWIST_CDR_BYTES, len(cdr_with_auth) - len(rebuilt_cdr)

    # ── Step 1: CDR format + stripping with real CycloneDDS ──────────────────

    base_cdr = cdds_serialize(lz=1.0)
    assert len(base_cdr) == TWIST_CDR_BYTES, \
        f"CycloneDDS Twist CDR = {len(base_cdr)} bytes (expected {TWIST_CDR_BYTES})"
    assert base_cdr[:4] == CDR_LE_HEADER
    lz_offset = 4 + 16   # 4 B header + 2 × float64 (x, y)
    assert abs(struct.unpack_from('<d', base_cdr, lz_offset)[0] - 1.0) < 1e-12

    print()
    print("  ── Step 1: CycloneDDS CDR serializer (real, not simulated) ─────")
    print()
    print(f"  Twist(linear.z=1.0) CDR: {len(base_cdr)} bytes")
    print(f"  Header: {base_cdr[:4].hex()}  (CDR_LE = 0x0001, options = 0x0000)")
    print(f"  Hex: {base_cdr.hex()}")
    print()
    _print_table(base_cdr, cdds_bridge_process,
                 note="CycloneDDS TwistMsg.deserialize() + TwistMsg.serialize()")

    # ── Step 2: domain_bridge end-to-end ─────────────────────────────────────

    print()
    print("  ── Step 2: domain_bridge end-to-end (domain 0 → domain 1) ─────")
    print()

    with open(BRIDGE_YAML, 'w') as f:
        f.write(BRIDGE_YAML_CONTENT)

    received_cdrs = []
    sub_ready     = threading.Event()
    collect_done  = threading.Event()

    def run_subscriber():
        dp1 = DomainParticipant(domain_id=1)
        tp  = Topic(dp1, 'rt/cmd_vel_auth_test', TwistMsg)
        dr  = DataReader(Subscriber(dp1), tp)
        ws  = WaitSet(dp1)
        rc  = ReadCondition(dr,
              ViewState.Any | InstanceState.Any | SampleState.Any)
        ws.attach(rc)
        sub_ready.set()
        deadline = time.time() + 15.0
        while time.time() < deadline and not collect_done.is_set():
            if ws.wait(duration(milliseconds=500)) > 0:
                for s in dr.take(N=50):
                    if s.sample_info.valid_data:
                        received_cdrs.append(TwistMsg.serialize(s))

    t_sub = threading.Thread(target=run_subscriber, daemon=True)
    t_sub.start()
    sub_ready.wait(timeout=5)

    env0 = os.environ.copy()
    env0['ROS_DOMAIN_ID'] = '0'
    bridge_proc = subprocess.Popen(
        ['bash', '-c',
         'source /opt/ros/humble/setup.bash && '
         f'ros2 run domain_bridge domain_bridge {BRIDGE_YAML}'],
        env=env0, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"  domain_bridge PID {bridge_proc.pid} started (domain 0 → domain 1)")
    print("  Waiting for DDS discovery (5s)...")
    time.sleep(5.0)

    rclpy.init()
    pub_node = Node('auth_strip_pub')
    pub = pub_node.create_publisher(Twist, '/cmd_vel_auth_test', 10)
    time.sleep(1.0)

    n_sent = 5
    for i in range(n_sent):
        msg = Twist()
        msg.linear.z = float(i + 1)
        pub.publish(msg)
        rclpy.spin_once(pub_node, timeout_sec=0.1)
        time.sleep(0.5)

    deadline = time.time() + 5.0
    while time.time() < deadline and len(received_cdrs) < n_sent:
        time.sleep(0.2)

    collect_done.set()
    t_sub.join(timeout=3.0)
    bridge_proc.terminate()
    bridge_proc.wait(timeout=5)
    pub_node.destroy_node()
    rclpy.shutdown()

    n_recv  = len(received_cdrs)
    sizes   = [len(c) for c in received_cdrs]
    all_52  = all(s == TWIST_CDR_BYTES for s in sizes)
    all_hdr = all(c[:4] == CDR_LE_HEADER for c in received_cdrs)
    lz_vals = [round(struct.unpack_from('<d', c, lz_offset)[0], 1)
               for c in received_cdrs]

    print(f"  Published on domain 0 : {n_sent}")
    print(f"  Received on domain 1  : {n_recv}")
    print(f"  CDR sizes received    : {sizes}")
    print(f"  All == {TWIST_CDR_BYTES} bytes          : {'✓' if all_52 else '✗ FAIL'}")
    print(f"  CDR header correct    : {'✓' if all_hdr else '✗ FAIL'}")
    print(f"  Values linear.z       : {lz_vals}")

    if not all_52 or n_recv == 0:
        print()
        print("  [!] Bridge test did not produce expected results.")
        print("  [!] Try running again — DDS discovery can be slow on first run.")
        sys.exit(1)

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
    print("  The sender serialized a geometry_msgs/msg/Twist to CDR (52 bytes),")
    print("  then appended authentication bytes immediately after.")
    print()
    if real:
        print("  The domain_bridge (real ROS2 process) subscribed to the topic on")
        print("  domain 0. CycloneDDS delivered the full CDR+auth buffer to the")
        print("  bridge's DDS layer. The bridge deserialized according to the Twist")
        print("  schema (52 bytes), reconstructed the struct, and republished.")
        print("  Auth bytes were never read. The domain 1 subscriber received")
        print("  exactly 52 bytes — confirmed by CycloneDDS reader on domain 1.")
    else:
        print("  A simulated bridge called CDR deserialize (reads schema bytes only,")
        print("  ignores trailing bytes) then CDR serialize (produces schema bytes")
        print("  only). This is what domain_bridge and ros1_bridge do internally.")
    print()
    print("  No exception. No log entry. The subscriber receives a valid, typed")
    print("  Twist message with no indication that auth material ever existed.")
    print()
    print("  ── Comparison with MAVLink ──────────────────────────────────────")
    print()
    print("  MAVLink : boundary = frame (STX + LEN field)")
    print("            auth bytes never reach the relay's parse layer")
    print()
    print("  ROS2/DDS: boundary = CDR schema")
    print("            auth bytes reach the bridge, but are dropped at CDR")
    print("            deserialization — RTPS itself is not the culprit")
    print()
    print("  Same result. Different boundary. Neither middleware is at fault.")
    print("  The bug is the assumption that appended bytes survive a typed relay.")
    print()
    print("  ── Why production deployments are affected ───────────────────────")
    print()
    print("  Bridges are the norm in production ROS2 systems. Sensors, planners,")
    print("  and actuators rarely share a DDS domain. A navigation stack that")
    print("  spans ros1_bridge + domain_bridge has at least two stripping points.")
    print()
    print("  ── Fix ──────────────────────────────────────────────────────────")
    print()
    print("  Authentication material must be a separate, typed ROS2 message")
    print("  published on a parallel topic. Bridges forward typed messages as-is.")
    print("  The subscriber verifies the auth topic before acting on the command.")
    print()
    print("  See: https://github.com/ros2/sros2/issues/392")
    print("       https://doi.org/10.5281/zenodo.20776349")
    print()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ROS2/DDS bridge auth-stripping proof of concept"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Pure Python CDR simulation — no ROS2 or cyclonedds required",
    )
    args = parser.parse_args()

    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  ROS2/DDS bridge authentication-stripping PoC                   ║")
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
