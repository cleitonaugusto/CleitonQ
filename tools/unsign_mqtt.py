#!/usr/bin/env python3
"""
unsign_mqtt.py

Does authentication survive an MQTT broker?

Short answer: it depends entirely on where you put it, and MQTT fails in a
different way than MAVLink does. This adapter exists to show both, because the
difference is the most useful thing the tool has to say about MQTT.

WHY MQTT IS NOT MAVLINK
-----------------------

MAVLink v2 runs over datagrams, and a MAVLink frame is self-delimiting: STX plus
LEN says exactly where it ends. Append bytes past that and a relay reads the
frame, ignores the tail, and the tail is gone. The datagram boundary swallows it.
Nothing complains.

MQTT runs over a TCP stream, and a PUBLISH packet is delimited by Remaining
Length. There is no datagram boundary to swallow anything. Append bytes past the
declared length and they do not disappear -- they become the first bytes of what
the broker reads as the NEXT control packet. The broker tries to parse them as
one, the stream desynchronises, and the connection does not survive it. Whatever
the exact error, it is raised.

That failure is loud. Loud is the opposite of this vulnerability class. So the
naive append pattern is not how MQTT gets hurt.

WHERE MQTT ACTUALLY GETS HURT
-----------------------------

MQTT 5.0 added User Properties: arbitrary key/value metadata in the variable
header. It is the obvious place to put an authenticator, it is where a designer
would naturally reach for, and the spec counts those bytes, so a v5 broker
forwards them to a v5 subscriber intact.

MQTT 3.1.1 has no properties. None. The field does not exist in the protocol.

So when a message crosses a broker bridge into 3.1.1 -- a version downgrade that
Mosquitto, EMQX and HiveMQ all perform as a normal, configured, documented
feature -- the properties cannot be carried. They are dropped. The payload
arrives byte-for-byte intact. The topic arrives intact. The subscriber gets a
well-formed message with the authenticator gone and no way to know one was ever
attached.

That is the class, reached by a different road: authentication placed in a field
the intermediary is not obligated to re-emit.

WHAT THIS REFINES
-----------------

The original precondition was "authentication placed outside the length the
framing counts." MQTT shows that is too narrow. User Properties ARE counted, and
they still do not survive. The precondition is really:

    authentication carried in any field the intermediary is not obligated
    to reproduce on the far side

and framing is only the most common way that happens.

It also isolates what makes the failure silent. Datagram framing discards a
short read without complaint, so the loss is silent. Stream framing cannot
discard anything, so a length mismatch desynchronises and is caught. Silence
comes from the transport, not from the authentication scheme.

Usage:

  python3 unsign_mqtt.py              run the four scenarios
  python3 unsign_mqtt.py --hexdump    also print the wire bytes of each packet

No dependencies, no broker, no network. The packets below are built and parsed
byte by byte against MQTT 5.0 and MQTT 3.1.1, so what you see is the wire
format, not a description of it.

Part of CleitonQ -- github.com/cleitonaugusto/CleitonQ
"""

import argparse
import hashlib
import sys

# ---------------------------------------------------------------------------
# MQTT wire primitives (MQTT 5.0 section 1.5, MQTT 3.1.1 section 1.5)
# ---------------------------------------------------------------------------

PUBLISH = 0x30  # packet type 3, flags 0 -> QoS 0, no DUP, no RETAIN

PROP_USER_PROPERTY = 0x26


def encode_vbi(value: int) -> bytes:
    """Variable Byte Integer. Seven bits of payload per byte, top bit = more."""
    if value < 0 or value > 268435455:
        raise ValueError("value out of range for a variable byte integer")
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value > 0:
            byte |= 0x80
        out.append(byte)
        if value == 0:
            return bytes(out)


def decode_vbi(buf: bytes, offset: int):
    """Returns (value, bytes_consumed). Raises on a malformed integer."""
    multiplier, value, consumed = 1, 0, 0
    while True:
        if offset + consumed >= len(buf):
            raise ValueError("truncated variable byte integer")
        byte = buf[offset + consumed]
        consumed += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return value, consumed
        multiplier *= 128
        if multiplier > 128 ** 3:
            raise ValueError("malformed variable byte integer")


def encode_string(s) -> bytes:
    """UTF-8 String: two-byte big-endian length, then the bytes."""
    raw = s.encode("utf-8") if isinstance(s, str) else s
    return len(raw).to_bytes(2, "big") + raw


def decode_string(buf: bytes, offset: int):
    """Returns (bytes, new_offset)."""
    if offset + 2 > len(buf):
        raise ValueError("truncated string length")
    n = int.from_bytes(buf[offset:offset + 2], "big")
    offset += 2
    if offset + n > len(buf):
        raise ValueError("truncated string body")
    return buf[offset:offset + n], offset + n


# ---------------------------------------------------------------------------
# Building PUBLISH packets
# ---------------------------------------------------------------------------

def build_publish_v5(topic: str, payload: bytes, user_properties=()) -> bytes:
    """MQTT 5.0 PUBLISH, QoS 0. Properties are part of the variable header."""
    props = bytearray()
    for key, value in user_properties:
        props.append(PROP_USER_PROPERTY)
        props += encode_string(key)
        props += encode_string(value)

    variable_header = encode_string(topic) + encode_vbi(len(props)) + bytes(props)
    remaining = variable_header + payload
    return bytes([PUBLISH]) + encode_vbi(len(remaining)) + remaining


def build_publish_v311(topic: str, payload: bytes) -> bytes:
    """MQTT 3.1.1 PUBLISH, QoS 0. There is no property field in this version."""
    remaining = encode_string(topic) + payload
    return bytes([PUBLISH]) + encode_vbi(len(remaining)) + remaining


def parse_publish_v5(packet: bytes):
    """Parse a v5 PUBLISH into its parts, the way a broker does."""
    if not packet or packet[0] & 0xF0 != PUBLISH:
        raise ValueError("not a PUBLISH packet")
    remaining_len, consumed = decode_vbi(packet, 1)
    start = 1 + consumed
    end = start + remaining_len
    if end > len(packet):
        raise ValueError("packet shorter than its Remaining Length")

    body = packet[start:end]
    topic, off = decode_string(body, 0)
    prop_len, consumed = decode_vbi(body, off)
    off += consumed
    prop_end = off + prop_len

    user_properties = []
    while off < prop_end:
        identifier = body[off]
        off += 1
        if identifier == PROP_USER_PROPERTY:
            key, off = decode_string(body, off)
            value, off = decode_string(body, off)
            user_properties.append((key, value))
        else:
            raise ValueError("property 0x%02x not handled by this demo" % identifier)

    payload = body[prop_end:]
    trailing = packet[end:]
    return {
        "topic": topic,
        "user_properties": user_properties,
        "payload": payload,
        "trailing": trailing,
    }


def parse_publish_v311(packet: bytes):
    if not packet or packet[0] & 0xF0 != PUBLISH:
        raise ValueError("not a PUBLISH packet")
    remaining_len, consumed = decode_vbi(packet, 1)
    start = 1 + consumed
    end = start + remaining_len
    body = packet[start:end]
    topic, off = decode_string(body, 0)
    return {
        "topic": topic,
        "user_properties": [],
        "payload": body[off:],
        "trailing": packet[end:],
    }


# ---------------------------------------------------------------------------
# The brokers
# ---------------------------------------------------------------------------

def broker_v5_to_v5(stream: bytes):
    """
    A v5 broker forwarding to a v5 subscriber. Parses the packet and rebuilds
    it from what it parsed, which is what every broker implementation does.
    Returns (delivered_packet, note).
    """
    parsed = parse_publish_v5(stream)
    rebuilt = build_publish_v5(
        parsed["topic"].decode(), parsed["payload"], parsed["user_properties"]
    )
    note = None
    if parsed["trailing"]:
        note = _next_packet_verdict(parsed["trailing"])
    return rebuilt, note


def broker_v5_to_v311(stream: bytes):
    """
    A broker bridging a v5 publisher to a v3.1.1 subscriber. This is ordinary
    configured behaviour, not a misconfiguration: 3.1.1 has no property field,
    so properties cannot be represented and are not carried.
    """
    parsed = parse_publish_v5(stream)
    rebuilt = build_publish_v311(parsed["topic"].decode(), parsed["payload"])
    note = None
    if parsed["trailing"]:
        note = _next_packet_verdict(parsed["trailing"])
    return rebuilt, note


def _next_packet_verdict(trailing: bytes) -> str:
    """
    What a broker does with bytes left over after Remaining Length. MQTT is a
    stream protocol, so these are not discarded -- they are read as the start
    of the next control packet.
    """
    packet_type = (trailing[0] & 0xF0) >> 4
    if packet_type == 0 or packet_type > 15:
        return "connection closed: reserved packet type 0x%02x" % trailing[0]
    names = {
        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
        6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
        10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
        14: "DISCONNECT", 15: "AUTH",
    }
    try:
        length, consumed = decode_vbi(trailing, 1)
    except ValueError:
        return "connection closed: malformed packet after the first"
    if 1 + consumed + length > len(trailing):
        return "connection closed: %s claims %d B, only %d B follow" % (
            names[packet_type], length, len(trailing) - 1 - consumed)
    return "read as a second %s packet" % names[packet_type]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

TOPIC = "factory/cell7/cmd"
COMMAND = b'{"cmd":"move","x":1200,"y":300,"speed":"max"}'
# A stand-in for a 32-byte HMAC-SHA3-256. Fixed so runs are reproducible,
# but with the byte distribution of a real tag, because scenario 1 depends
# on how the broker's parser reacts to those exact bytes.
AUTH = hashlib.sha3_256(b"cleitonq-unsign-mqtt-demo-tag").digest()


def scenario_append_uncounted():
    """Auth appended after the packet, Remaining Length left alone."""
    packet = build_publish_v5(TOPIC, COMMAND)
    stream = packet + AUTH
    delivered, note = broker_v5_to_v5(stream)
    parsed = parse_publish_v5(delivered)
    return {
        "name": "auth appended, Remaining Length unchanged",
        "sent": len(stream),
        "delivered": len(delivered),
        "auth_present": AUTH in delivered,
        "silent": False,
        "verdict": "LOUD",
        "detail": note or "no trailing bytes",
        "payload_ok": parsed["payload"] == COMMAND,
    }


def scenario_append_counted():
    """Auth appended and Remaining Length increased to cover it."""
    packet = build_publish_v5(TOPIC, COMMAND + AUTH)
    delivered, note = broker_v5_to_v5(packet)
    parsed = parse_publish_v5(delivered)
    return {
        "name": "auth inside the payload, length updated",
        "sent": len(packet),
        "delivered": len(delivered),
        "auth_present": AUTH in parsed["payload"],
        "silent": False,
        "verdict": "OK",
        "detail": "payload is opaque to the broker and is forwarded whole",
        "payload_ok": parsed["payload"] == COMMAND + AUTH,
    }


def scenario_user_property_v5():
    """Auth in an MQTT 5 User Property, subscriber also on v5."""
    packet = build_publish_v5(TOPIC, COMMAND, [("auth", AUTH)])
    delivered, note = broker_v5_to_v5(packet)
    parsed = parse_publish_v5(delivered)
    present = any(v == AUTH for _, v in parsed["user_properties"])
    return {
        "name": "auth in v5 User Property, v5 subscriber",
        "sent": len(packet),
        "delivered": len(delivered),
        "auth_present": present,
        "silent": False,
        "verdict": "OK",
        "detail": "both ends speak v5, so the property is carried",
        "payload_ok": parsed["payload"] == COMMAND,
    }


def scenario_user_property_downgrade():
    """Auth in an MQTT 5 User Property, bridged to a 3.1.1 subscriber."""
    packet = build_publish_v5(TOPIC, COMMAND, [("auth", AUTH)])
    delivered, note = broker_v5_to_v311(packet)
    parsed = parse_publish_v311(delivered)
    return {
        "name": "auth in v5 User Property, bridged to v3.1.1",
        "sent": len(packet),
        "delivered": len(delivered),
        "auth_present": AUTH in delivered,
        "silent": True,
        "verdict": "FAIL",
        "detail": "3.1.1 has no property field, so it cannot be carried",
        "payload_ok": parsed["payload"] == COMMAND,
    }


SCENARIOS = [
    scenario_append_uncounted,
    scenario_append_counted,
    scenario_user_property_v5,
    scenario_user_property_downgrade,
]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def hexdump(label, data, limit=64):
    print("  %s (%d B)" % (label, len(data)))
    shown = data[:limit]
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        hexpart = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("    %04x  %-47s  %s" % (i, hexpart, text))
    if len(data) > limit:
        print("    ....  (%d more bytes)" % (len(data) - limit))
    print()


def run(show_hex: bool):
    print("  unsign mqtt — does authentication survive the hop?")
    print("  Cleiton Augusto Correa Bezerra · github.com/cleitonaugusto/CleitonQ")
    print("  ───────────────────────────────────────────────────────────────────")
    print()
    print("  Mode : byte-level MQTT 5.0 / 3.1.1 simulation (no broker required)")
    print("  Topic: %s" % TOPIC)
    print("  Command payload: %d B     Authenticator: %d B" % (len(COMMAND), len(AUTH)))
    print()

    results = [fn() for fn in SCENARIOS]

    width = max(len(r["name"]) for r in results)
    print("  %-*s  %5s  %6s  %5s  %s" % (
        width, "Where the authenticator was put", "Sent", "Deliv.", "Auth?", "Result"))
    print("  %s  %s  %s  %s  %s" % ("─" * width, "─" * 5, "─" * 6, "─" * 5, "─" * 6))
    for r in results:
        print("  %-*s  %5d  %6d  %5s  %s" % (
            width, r["name"], r["sent"], r["delivered"],
            "yes" if r["auth_present"] else "no",
            {"OK": "OK — survives",
             "LOUD": "LOUD — broker rejects",
             "FAIL": "FAIL — auth gone, silent"}[r["verdict"]],
        ))
    print()

    for r in results:
        print("  · %s" % r["name"])
        print("    %s" % r["detail"])
    print()

    if show_hex:
        print("  ── Wire bytes ──────────────────────────────────────────────────")
        print()
        hexdump("v5 PUBLISH with auth in a User Property",
                build_publish_v5(TOPIC, COMMAND, [("auth", AUTH)]))
        hexdump("the same message after bridging to 3.1.1",
                broker_v5_to_v311(
                    build_publish_v5(TOPIC, COMMAND, [("auth", AUTH)]))[0])

    print("  ── What happened ───────────────────────────────────────────────")
    print()
    print("  MQTT does not fail the way MAVLink fails, and the difference is")
    print("  worth stating plainly.")
    print()
    print("  Appending bytes past the declared length does NOT get you silently")
    print("  stripped here. MQTT rides a TCP stream, so there is no datagram")
    print("  boundary to swallow the tail. The broker reads Remaining Length")
    print("  bytes, then reads your authenticator as the start of the next")
    print("  control packet. The stream desynchronises, and the connection")
    print("  does not survive it (MQTT 5.0 §4.13 covers the malformed case).")
    print("  Whatever the exact error, it is loud. Loud is survivable.")
    print()
    print("  The silent failure is elsewhere. MQTT 5 User Properties are the")
    print("  natural place to put an authenticator, and they work perfectly")
    print("  until the message crosses a bridge into MQTT 3.1.1, which has no")
    print("  property field at all. Mosquitto, EMQX and HiveMQ all perform that")
    print("  downgrade as a normal configured feature.")
    print()
    print("  The subscriber then receives the command payload byte-for-byte")
    print("  intact, on the right topic, with the authenticator gone and no")
    print("  indication that one was ever attached. No error is raised at")
    print("  either end. That is the failure this tool is named after.")
    print()
    print("  ── What this refines ───────────────────────────────────────────")
    print()
    print("  The precondition is usually stated as \"authentication placed")
    print("  outside the length the framing counts.\" MQTT shows that is too")
    print("  narrow: User Properties ARE counted, and they still do not")
    print("  survive. The precondition is really")
    print()
    print("      authentication carried in any field the intermediary is not")
    print("      obligated to reproduce on the far side")
    print()
    print("  and framing is only the most common way that happens.")
    print()
    print("  It also shows where the silence comes from. Datagram transports")
    print("  discard a short read without complaint. Stream transports cannot")
    print("  discard anything, so a length mismatch desynchronises and gets")
    print("  caught. The silence is a property of the transport, not of the")
    print("  authentication scheme.")
    print()
    print("  ── Fix ─────────────────────────────────────────────────────────")
    print()
    print("  Carry the authenticator inside the PUBLISH payload, over a")
    print("  canonical encoding of the topic and the command together. The")
    print("  payload is opaque to every broker and every version, so it")
    print("  survives bridging, downgrade and re-publication. Row 2 above is")
    print("  that arrangement, and it is the only one that holds.")
    print()
    print("  Do not authenticate over transport metadata a broker may rewrite.")
    print()
    print("    https://doi.org/10.5281/zenodo.20776349")
    print()

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Does authentication survive an MQTT broker?")
    parser.add_argument(
        "--hexdump", action="store_true",
        help="print the wire bytes before and after the bridge")
    args = parser.parse_args()
    return run(args.hexdump)


if __name__ == "__main__":
    sys.exit(main())
