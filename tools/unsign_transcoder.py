#!/usr/bin/env python3
"""
unsign_transcoder.py

Does authentication survive a gRPC-JSON transcoder?


WHAT THIS SHOWS, AND WHAT IT DOES NOT
-------------------------------------

A JSON client posts a command to a gRPC service through a transcoder — Envoy's
`grpc_json_transcoder`, grpc-gateway, ConnectRPC, or Google Cloud Endpoints. The
transcoder parses the JSON into the service's protobuf schema and forwards that.
If the client attached authentication in a field the schema does not name, the
transcoder has no place to put it: the JSON mapping can only carry fields the
schema declares. The field is dropped. The service receives a well-formed,
unauthenticated command; the client receives HTTP 200. Neither is told.

This is the same class as MAVLink or SOME/IP, but the boundary is a schema
rather than a length field, and the population is different: not embedded control
buses but ordinary backend edges, where JSON meets gRPC.

**The cause is the JSON mapping, not any one product.** proto3 has preserved
unknown fields in *binary* serialisation since 3.5, on purpose, so that an
intermediary re-serialising a message does not destroy forward compatibility.
The JSON mapping has no way to represent a field the schema does not name, so
converting to JSON drops it. A binary-to-binary proxy is therefore safe by
construction; a transcoder, which crosses from JSON to binary, is not. Two
components that look interchangeable in an architecture diagram behave oppositely.

**Measured on four real stacks, three of them independent.** In its default
configuration each accepts the request (HTTP 200) and silently drops the unmapped
field:

    Envoy                1.31.10   C++/BoringSSL     no configuration rejects it
    grpc-gateway         2.30.0    Go                reject by DiscardUnknown=false
    ConnectRPC           1.20.0    Go / Buf          reject by replacing the codec
    Cloud Endpoints      ESPv2     = Envoy 1.30.7    (same engine as Envoy, not
                                                      an independent fourth)

Three codebases across two languages and two protocols agree on the silent-drop
default, which is why the cause is the proto3 JSON mapping and not the vendor. They
diverge only on the mitigation: Envoy exposes no switch for an unknown body field
at all; grpc-gateway flips one option on its built-in marshaler; ConnectRPC needs
a replacement codec. All four are unsafe by default. The two Go stacks are even
more permissive than the `protojson` library they wrap, whose own default is
strict; Envoy — and therefore Cloud Endpoints — offers no unknown-body-field
switch at all.

**Unlike SOME/IP, size does not save you.** On SOME/IP a post-quantum-sized
authenticator is dropped whole by a UDP ceiling — an availability failure, not a
strip. A transcoder has no such ceiling: it drops the unmapped field at any size,
so a 32-byte HMAC and a 4,627-byte ML-DSA-87 signature are stripped the same way,
and the command still arrives.

**What this model is.** The bytes below are the real protobuf wire format, and
`json_transcode` drops exactly the fields a schema-driven JSON mapping cannot
name — the real proto3 JSON-mapping behaviour. It is an in-process model of the
mechanism,
not a live proxy; the four stacks above were measured separately, from a clean
state, with the appended field arriving byte-identical when — and only when — the
schema named it (a positive control on every one).

Usage:

  python3 unsign_transcoder.py              in-process model, nothing required
  python3 unsign_transcoder.py --hexdump    also print the wire bytes

Part of CleitonQ -- github.com/cleitonaugusto/CleitonQ
"""

import argparse
import sys

# The service schema names two fields. Authentication is placed in field 15,
# which the schema does not name — the client's own message type has it, the
# service's does not. These are protobuf field numbers.
SCHEMA_FIELDS = (1, 2)          # action, amount
AUTH_FIELD = 15

AUTH_SIZES = [
    ("HMAC-SHA3-256", 32),
    ("Ed25519 signature", 64),
    ("ML-DSA-87 signature", 4627),
]


def _varint(n):
    """protobuf base-128 varint."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_varint(buf, i):
    shift = val = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7


def _tag(field, wire_type):
    return _varint((field << 3) | wire_type)


def encode_command(action, amount, auth=None):
    """Real proto3 wire bytes for a Command, optionally with auth in field 15."""
    w = bytearray()
    a = action.encode()
    w += _tag(1, 2) + _varint(len(a)) + a        # field 1: string action
    w += _tag(2, 0) + _varint(amount)            # field 2: varint amount
    if auth is not None:
        w += _tag(AUTH_FIELD, 2) + _varint(len(auth)) + auth   # field 15: bytes
    return bytes(w)


def walk_fields(wire):
    """Yield (field_number, wire_type, raw_bytes) for each field on the wire."""
    i, n = 0, len(wire)
    while i < n:
        start = i
        key, i = _read_varint(wire, i)
        field, wt = key >> 3, key & 7
        if wt == 0:            # varint
            _, i = _read_varint(wire, i)
        elif wt == 2:          # length-delimited
            ln, i = _read_varint(wire, i)
            i += ln
        elif wt == 5:          # 32-bit
            i += 4
        elif wt == 1:          # 64-bit
            i += 8
        else:
            raise ValueError("wire type %d not handled" % wt)
        yield field, wt, wire[start:i]


def binary_proxy(wire):
    """A binary-to-binary intermediary. proto3 preserves unknown fields on
    re-serialisation, so everything survives. Safe by construction."""
    return wire


def json_transcode(wire, known=SCHEMA_FIELDS):
    """A JSON transcoder. The JSON mapping can only carry fields the schema
    names, so re-serialising keeps only those. Any other field is dropped."""
    out = bytearray()
    for field, _wt, raw in walk_fields(wire):
        if field in known:
            out += raw
    return bytes(out)


def hexdump(label, data, limit=48):
    print("  %s (%d B)" % (label, len(data)))
    for i in range(0, min(len(data), limit), 16):
        chunk = data[i:i + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print("    %04x  %-47s  %s"
              % (i, " ".join("%02x" % b for b in chunk), text))
    if len(data) > limit:
        print("    ....  (%d more bytes)" % (len(data) - limit))
    print()


def run(show_hex):
    print("  unsign transcoder — does authentication survive the hop?")
    print("  Cleiton Augusto Correa Bezerra · github.com/cleitonaugusto/CleitonQ")
    print("  " + "─" * 67)
    print()
    print("  Mode : in-process model, real protobuf wire format (no proxy needed)")
    baseline = encode_command("transfer", 1000000)
    print("  Baseline Command: %d B  (schema names fields %s)"
          % (len(baseline), ", ".join(str(f) for f in SCHEMA_FIELDS)))
    print()

    print("  %-21s  %8s  %14s  %16s  %s"
          % ("Auth scheme", "Appended", "Binary proxy", "JSON transcoder", "Result"))
    print("  %s  %s  %s  %s  %s"
          % ("─" * 21, "─" * 8, "─" * 14, "─" * 16, "─" * 24))
    print("  %-21s  %8d  %14s  %16s  %s"
          % ("baseline, no auth", 0, "%d B" % len(baseline),
             "%d B" % len(baseline), "control passes"))
    for label, n in AUTH_SIZES:
        wire = encode_command("transfer", 1000000, auth=bytes([0xA5]) * n)
        via_binary = binary_proxy(wire)
        via_json = json_transcode(wire)
        auth_present = any(f == AUTH_FIELD for f, _w, _r in walk_fields(via_binary))
        print("  %-21s  %8d  %14s  %16s  %s"
              % (label, n,
                 "%d B%s" % (len(via_binary), " ✓" if auth_present else ""),
                 "%d B" % len(via_json),
                 "FAIL — auth stripped, command delivered"))
    print()

    if show_hex:
        wire = encode_command("transfer", 1000000, auth=bytes([0xA5]) * 32)
        hexdump("sent: command + 32-byte HMAC in field 15", wire)
        hexdump("binary proxy re-emits (auth survives)", binary_proxy(wire))
        hexdump("JSON transcoder re-emits (auth gone)", json_transcode(wire))

    print("  ── What happened " + "─" * 47)
    print()
    print("  The transcoder parsed the JSON into the service schema, which names")
    print("  only fields %s. Field %d was not in the schema, so the JSON mapping"
          % (", ".join(str(f) for f in SCHEMA_FIELDS), AUTH_FIELD))
    print("  had nowhere to carry it, and the re-serialised gRPC message the")
    print("  service receives does not contain it. The client got HTTP 200. No")
    print("  rule was broken; the transcoder is conformant.")
    print()
    print("  The binary-proxy column is the contrast that names the cause. The")
    print("  same appended bytes survive a binary-to-binary hop, because proto3")
    print("  preserves unknown fields on the wire since 3.5. Only the JSON")
    print("  mapping, which cannot name an unknown field, drops them.")
    print()
    print("  ── Measured on real software " + "─" * 36)
    print()
    print("  Default configuration, unmapped field in the JSON body:")
    print()
    print("    Envoy 1.31.10          HTTP 200, dropped   no switch rejects it")
    print("    grpc-gateway 2.30.0    HTTP 200, dropped   DiscardUnknown=false → 400")
    print("    ConnectRPC 1.20.0      HTTP 200, dropped   replace json codec  → 400")
    print("    Cloud Endpoints/ESPv2  HTTP 200, dropped   = Envoy underneath")
    print()
    print("  Three independent codebases, two languages, two protocols, one")
    print("  default: silent drop. The two Go stacks are even more permissive")
    print("  than the protojson library they wrap, whose default is strict;")
    print("  Envoy offers no unknown-body-field switch at all.")
    print()
    print("  ── Fix " + "─" * 58)
    print()
    print("  Carry the authenticator in a field the schema names, so the mapping")
    print("  is obliged to reproduce it. Measured: with the field added to the")
    print("  schema, the same request arrives with the authenticator byte-for-")
    print("  byte intact through every one of the four stacks. Where an operator")
    print("  cannot change the schema, reject unknown body fields at the")
    print("  transcoder — available on grpc-gateway and ConnectRPC, not on Envoy.")
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Does authentication survive a gRPC-JSON transcoder?")
    parser.add_argument("--hexdump", action="store_true",
                        help="print the wire bytes through each path")
    return run(parser.parse_args().hexdump)


if __name__ == "__main__":
    sys.exit(main())
