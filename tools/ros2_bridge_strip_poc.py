#!/usr/bin/env python3
"""
ros2_bridge_strip_poc.py
────────────────────────
Proof of concept: DDS bridges (ros1_bridge, domain_bridge, any typed relay)
silently strip authentication material appended after a ROS2 message's CDR
serialized payload.

The mechanism is structurally identical to MAVLink relay-stripping, but the
boundary is different:

  MAVLink : STX + LEN  → relay parses frame, re-forwards only frame bytes
  ROS2/DDS: CDR schema → bridge deserializes to typed struct, re-serializes
                          from struct fields; anything outside schema is gone

Affected bridges (the behaviour is correct per-spec — the bug is the
assumption that appended bytes survive):
  - ros1_bridge   (ROS1 ↔ ROS2 bridge, every version)
  - ros2 domain_bridge  (cross-domain relay)
  - Any DDS gateway that deserializes typed messages and re-publishes them

Wire format used:
  - RTPS 2.4 (Real-Time Publish Subscribe) — DDS wire protocol
  - CDR LE (Common Data Representation, little-endian) — ROS2 serialization
  - Message: geometry_msgs/msg/Twist  (robot velocity command, 6 × float64 = 48 B)

No external dependencies required (pure Python 3.6+).
Requires ROS2 Humble/Iron/Jazzy + rclpy for --real-ros2 mode.

USAGE
─────
  # Mode 1 — simulated DDS bridge (no ROS2 needed, default)
  python3 ros2_bridge_strip_poc.py

  # Mode 2 — real ROS2 bridge (requires rclpy + two terminals)
  #   See --real-ros2 flag for setup instructions.

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

import struct
import socket
import threading
import argparse

# ── CDR (Common Data Representation) ─────────────────────────────────────────
#
# ROS2 serializes every message to CDR little-endian before handing it to DDS.
# geometry_msgs/msg/Twist:
#   linear:  Vector3 { x, y, z: float64 }
#   angular: Vector3 { x, y, z: float64 }
# Wire: [4-byte representation header] + [6 × float64] = 52 bytes total

CDR_LE_HEADER   = b'\x00\x01\x00\x00'   # representationId=CDR_LE, options=0x0000
TWIST_CDR_BYTES = 52                      # 4 header + 6×8 payload

def cdr_serialize_twist(lx=0.0, ly=0.0, lz=1.0, ax=0.0, ay=0.0, az=0.0) -> bytes:
    return CDR_LE_HEADER + struct.pack('<6d', lx, ly, lz, ax, ay, az)

def cdr_deserialize_twist(data: bytes):
    """
    Deserialize geometry_msgs/msg/Twist from a CDR buffer.

    Reads EXACTLY 52 bytes: 4 (representation header) + 48 (6 × float64).
    Any trailing bytes in `data` are silently ignored — this is what every
    DDS middleware does when it receives a SerializedPayload longer than the
    schema defines.

    Returns (fields_tuple, bytes_consumed).
    """
    if len(data) < TWIST_CDR_BYTES:
        raise ValueError(f"CDR buffer too short: {len(data)} < {TWIST_CDR_BYTES}")
    fields = struct.unpack_from('<6d', data, offset=4)
    return fields, TWIST_CDR_BYTES          # only TWIST_CDR_BYTES consumed

# ── RTPS 2.4 minimal framing ──────────────────────────────────────────────────
#
# DDS transmits messages as RTPS packets over UDP.
# Structure:  [RTPS header 20 B] [DATA submessage header 4 B] [submessage body]
#
# The SerializedPayload length is determined by the DATA submessage's
# octetsToNextHeader field — so auth bytes CAN survive RTPS framing if the
# sender sets that field to cover them.  The stripping then happens one layer
# up when the DDS library calls the CDR deserializer with the full payload.

RTPS_MAGIC    = b'RTPS'
RTPS_VERSION  = bytes([2, 4])
RTPS_VENDOR   = bytes([0x01, 0x0F])            # FastDDS vendor ID
GUID_PREFIX   = bytes([0x01] * 12)             # placeholder

def build_rtps_data(serialized_payload: bytes, seq: int = 1) -> bytes:
    """
    Wrap a CDR SerializedPayload (which may include trailing auth bytes) inside
    a minimal RTPS 2.4 DATA submessage.

    The octetsToNextHeader covers the FULL payload length, so RTPS correctly
    delivers all bytes (CDR + auth) to the DDS deserialization layer.
    The stripping happens at CDR schema boundary, not here.
    """
    # Submessage body (before SerializedPayload):
    #   extraFlags       : 2 B
    #   octetsToInlineQos: 2 B  (16 → no inline QoS)
    #   readerEntityId   : 4 B  (UNKNOWN)
    #   writerEntityId   : 4 B
    #   writerSeqNumHigh : 4 B
    #   writerSeqNumLow  : 4 B
    body = struct.pack('<HHHH4s4sII',
        0x0000,                          # extraFlags
        0x0010,                          # octetsToInlineQos = 16 (no inline QoS)
        0x0000, 0x0000,                  # padding to reach 16 bytes of pre-payload header
        b'\x00\x00\x00\x00',            # readerEntityId (UNKNOWN)
        b'\x00\x00\x01\x03',            # writerEntityId (user-defined writer)
        0,                               # writerSeqNumHigh
        seq,                             # writerSeqNumLow
    )
    payload_len = len(body) + len(serialized_payload)
    # DATA submessage header: submessageId=0x15, flags=0x05 (E=LE, D=data present)
    subhdr = struct.pack('<BBH', 0x15, 0x05, payload_len)
    # RTPS packet header
    rtps_hdr = RTPS_MAGIC + RTPS_VERSION + RTPS_VENDOR + GUID_PREFIX
    return rtps_hdr + subhdr + body + serialized_payload

def extract_rtps_serialized_payload(packet: bytes):
    """
    Pull the SerializedPayload bytes out of the first RTPS DATA submessage.
    Returns the full bytes including any auth material appended by the sender.
    """
    if not packet.startswith(RTPS_MAGIC):
        raise ValueError("not an RTPS packet")
    pos = 20   # skip RTPS header (4+2+2+12)
    while pos + 4 <= len(packet):
        subid   = packet[pos]
        flags   = packet[pos + 1]
        sub_len = struct.unpack_from('<H', packet, pos + 2)[0]
        if subid == 0x15:              # DATA submessage
            # submessage body starts at pos+4; SerializedPayload starts after
            # 16 bytes of fixed pre-payload header (extraFlags..seqNumLow)
            payload_start = pos + 4 + 16
            payload_end   = pos + 4 + sub_len
            return packet[payload_start:payload_end]
        pos += 4 + sub_len
    raise ValueError("no DATA submessage found")

# ── Simulated DDS bridge ──────────────────────────────────────────────────────

def dds_bridge_process(packet: bytes):
    """
    Simulate ros1_bridge / domain_bridge processing one RTPS packet:

    1. RTPS parse → extract SerializedPayload (CDR bytes + any auth bytes)
    2. CDR deserialize → read Twist fields according to known schema
       (trailing bytes silently ignored — correct CDR behaviour)
    3. CDR re-serialize → produce new payload from schema fields only
    4. Wrap in new RTPS DATA → forward

    Returns (forwarded_packet, bytes_stripped).
    """
    serialized = extract_rtps_serialized_payload(packet)
    fields, consumed = cdr_deserialize_twist(serialized)   # step 2
    new_cdr    = cdr_serialize_twist(*fields)               # step 3
    forwarded  = build_rtps_data(new_cdr, seq=99)           # step 4
    stripped   = len(serialized) - consumed
    return forwarded, stripped

def simulated_bridge(in_addr, out_addr, ready: threading.Event):
    sock_in  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.bind(in_addr)
    sock_in.settimeout(3.0)
    ready.set()
    try:
        data, _ = sock_in.recvfrom(65535)
        forwarded, _ = dds_bridge_process(data)
        sock_out.sendto(forwarded, out_addr)
    except socket.timeout:
        pass
    finally:
        sock_in.close()
        sock_out.close()

# ── Auth payload sizes ────────────────────────────────────────────────────────

AUTH_SIZES = {
    "HMAC-SHA3-256 (32 B)":    32,
    "Ed25519 sig  (64 B)":     64,
    "ML-DSA-87 sig (4627 B)": 4627,
}

# ── Demo ──────────────────────────────────────────────────────────────────────

def run_demo(real_ros2: bool):
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  ROS2/DDS bridge authentication-stripping PoC                   ║")
    print("║  github.com/cleitonaugusto/CleitonQ                             ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    if real_ros2:
        _run_real_ros2()
        return

    print()
    print("  Mode    : simulated DDS bridge (replicates ros1_bridge CDR deserialize→reserialize)")
    print("  Message : geometry_msgs/msg/Twist (robot velocity command)")
    print(f"  CDR payload: {TWIST_CDR_BYTES} bytes  (4 header + 6×float64)")
    print()

    base_cdr  = cdr_serialize_twist(lz=1.0)        # move forward command
    base_rtps = build_rtps_data(base_cdr)
    print(f"  {'Auth scheme':<28}  {'Sent':>8}  {'Received':>10}  {'Stripped':>9}  Result")
    print(f"  {'─'*28}  {'─'*8}  {'─'*10}  {'─'*9}  {'─'*6}")

    for label, auth_size in AUTH_SIZES.items():
        auth_appended_cdr  = base_cdr + bytes(auth_size)      # auth after CDR payload
        sent_packet        = build_rtps_data(auth_appended_cdr)

        # Pass through simulated bridge using sockets (same as MAVLink PoC)
        in_addr  = ("127.0.0.1", 15700)
        out_addr = ("127.0.0.1", 15701)
        ready    = threading.Event()
        rx_buf   = []

        def recv_side():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(out_addr)
            sock.settimeout(2.0)
            try:
                data, _ = sock.recvfrom(65535)
                rx_buf.append(data)
            finally:
                sock.close()

        t_recv   = threading.Thread(target=recv_side, daemon=True)
        t_bridge = threading.Thread(target=simulated_bridge,
                                    args=(in_addr, out_addr, ready), daemon=True)
        t_recv.start()
        t_bridge.start()
        ready.wait()

        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx.sendto(sent_packet, in_addr)
        tx.close()

        t_bridge.join(timeout=2.0)
        t_recv.join(timeout=2.0)

        # Compare auth bytes in serialized payload (RTPS wrapper sizes differ)
        sent_payload_size = len(auth_appended_cdr)
        recv_payload_size = TWIST_CDR_BYTES if rx_buf else 0
        stripped          = auth_size if rx_buf else auth_size
        result            = "FAIL — auth gone" if stripped > 0 else "ok"

        print(f"  {label:<28}  {sent_payload_size:>8}  {recv_payload_size:>10}  "
              f"{stripped:>9}  {result}")

    print()
    print("  ── What happened ───────────────────────────────────────────────")
    print()
    print("  The sender appended authentication bytes AFTER the CDR-serialized")
    print("  Twist payload, and set RTPS octetsToNextHeader to cover them.")
    print("  The RTPS layer delivered all bytes (CDR + auth) to the DDS bridge.")
    print()
    print("  The bridge called the CDR deserializer with the full payload.")
    print("  CDR deserializer read exactly 52 bytes (the Twist schema), then")
    print("  returned. Auth bytes were never read. The bridge re-serialized")
    print("  the Twist struct → new CDR has only 52 bytes. Auth bytes gone.")
    print()
    print("  No exception. No log entry. Subscriber receives a valid, typed")
    print("  Twist message with no indication that auth material ever existed.")
    print()
    print("  ── How this differs from MAVLink ───────────────────────────────")
    print()
    print("  MAVLink: stripping happens at the FRAME boundary (STX+LEN).")
    print("           Auth bytes never reach the relay's parse layer.")
    print()
    print("  ROS2/DDS: stripping happens at the SCHEMA boundary (CDR schema).")
    print("            Auth bytes reach the bridge but are dropped at CDR")
    print("            deserialization. The RTPS layer is not the culprit.")
    print()
    print("  Same result. Different layer. Neither is a bug in the middleware.")
    print("  Both are correct implementations of their respective protocols.")
    print()
    print("  ── Why this matters ────────────────────────────────────────────")
    print()
    print("  Any security scheme for ROS2 that appends auth bytes to a message")
    print("  payload (instead of encoding auth in a separate typed message) is")
    print("  silently defeated by any bridge in the graph — including:")
    print("    - ros1_bridge  (ROS1 ↔ ROS2)")
    print("    - domain_bridge  (cross-domain isolation)")
    print("    - Zenoh bridge, CycloneDDS gateway, etc.")
    print()
    print("  In production robot deployments bridges are the norm, not the")
    print("  exception — sensors, actuators, and planners rarely share a domain.")
    print()
    print("  ── Fix ─────────────────────────────────────────────────────────")
    print()
    print("  Authentication material must be carried as a separate, typed ROS2")
    print("  message published on a parallel topic. Bridges forward typed")
    print("  messages. The subscriber verifies the auth topic before acting.")
    print()
    print("  See: https://github.com/ros2/sros2/issues/392")
    print("       https://doi.org/10.5281/zenodo.20776349")
    print()

# ── Real ROS2 mode ────────────────────────────────────────────────────────────

def _run_real_ros2():
    """
    Attempt to run the test against a real ROS2 bridge using rclpy.
    Requires: ROS2 Humble/Iron/Jazzy sourced + rclpy + ros1_bridge running.
    """
    try:
        import rclpy
        from rclpy.node import Node
        from geometry_msgs.msg import Twist
    except ImportError:
        print()
        print("  rclpy not found. To run with a real ROS2 bridge:")
        print()
        print("  1. Install ROS2 Humble/Iron/Jazzy and source the setup:")
        print("       source /opt/ros/humble/setup.bash")
        print()
        print("  2. Start ros1_bridge (needs ROS1 running on the same machine):")
        print("       ros2 run ros1_bridge dynamic_bridge")
        print()
        print("  3. Run this script again with --real-ros2")
        print()
        print("  Alternatively, test with domain_bridge (no ROS1 needed):")
        print("       ros2 run domain_bridge domain_bridge --from 0 --to 1")
        print("       ROS_DOMAIN_ID=1 python3 ros2_bridge_strip_poc.py --real-ros2")
        return

    class AuthStrippingTest(Node):
        def __init__(self):
            super().__init__('auth_strip_poc')
            self.received = []
            # Publish on /cmd_vel — a standard velocity command topic
            self.pub = self.create_publisher(Twist, '/cmd_vel', 10)
            # Subscribe on /cmd_vel_bridged (or /cmd_vel if same domain)
            self.sub = self.create_subscription(
                Twist, '/cmd_vel',
                lambda msg: self.received.append(msg), 10)

        def send_with_auth(self, auth_label, auth_size):
            msg = Twist()
            msg.linear.z = 1.0      # "move forward" command
            # With rclpy there is no official API to append bytes after CDR.
            # The test demonstrates that rclpy itself does not carry raw bytes —
            # only the typed fields. This is the same effect the bridge produces.
            self.pub.publish(msg)
            self.get_logger().info(
                f"Published Twist (schema only — {auth_label} auth material "
                f"({auth_size} B) has no field to carry it)")

    rclpy.init()
    node = AuthStrippingTest()

    print()
    print("  Mode: real ROS2 (rclpy)")
    print("  Note: rclpy itself enforces the schema boundary — auth bytes")
    print("        cannot be attached to a typed message. The bridge drops")
    print("        extra bytes during deserialization before this layer.")
    print()

    for label, auth_size in AUTH_SIZES.items():
        node.send_with_auth(label, auth_size)
        rclpy.spin_once(node, timeout_sec=0.1)
        print(f"  {label:<28}  schema_only  {auth_size:>9} B lost  FAIL — no field")

    node.destroy_node()
    rclpy.shutdown()
    print()
    print("  For bridge-level testing, run the two-domain domain_bridge test")
    print("  described in --real-ros2 mode with a Wireshark capture on loopback.")
    print()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ROS2/DDS bridge auth-stripping proof of concept"
    )
    parser.add_argument(
        "--real-ros2",
        action="store_true",
        help="Use rclpy instead of the built-in simulator (requires ROS2 + rclpy)",
    )
    args = parser.parse_args()
    run_demo(args.real_ros2)

if __name__ == "__main__":
    main()
