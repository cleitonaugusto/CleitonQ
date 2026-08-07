# CleitonQ Telemetry Authentication Specification

**Version:** 0.1-draft  
**Author:** Cleiton Augusto Correa Bezerra  
**Date:** 2026-07-02  
**Status:** Draft — not yet submitted to IETF

---

## Abstract

Autonomous systems generate continuous telemetry streams at rates of 10–200 Hz.
Authenticating each frame with a post-quantum digital signature (ML-DSA-87,
4627-byte output) is impractical: at 100 Hz, it would require 462 KB/s of
authentication overhead alone — exceeding the C2 link budget of most deployed
systems.

This specification defines a two-layer protocol that authenticates high-rate
telemetry streams with negligible per-packet overhead while providing full
non-repudiation and third-party auditability through periodic anchor signatures.

---

## 1. Problem Statement

### 1.1 Bandwidth constraints

| Link type | Typical uplink budget | ML-DSA-87 @ 100 Hz |
|---|---|---|
| TELEMETRY_RADIO (SiK) | 56 kbps | 3.7 Mbps ❌ |
| LONG_RANGE (RFD900) | 128 kbps | 3.7 Mbps ❌ |
| Wi-Fi (5 GHz) | 54 Mbps | 3.7 Mbps ✅ (but wasteful) |
| LTE/4G | 10–50 Mbps | 3.7 Mbps ✅ |
| IRIDIUM | 2.4 kbps | 3.7 Mbps ❌ |
| CCSDS LEO uplink | 2–8 kbps | 3.7 Mbps ❌ |

Full per-packet ML-DSA-87 is only practical on high-bandwidth links.
For the general case, a different approach is required.

### 1.2 Non-repudiation requirement

HMAC-SHA3-256 provides authentication (only the session parties can verify),
but not non-repudiation (either party could have generated any packet —
proof to a third party is impossible). For post-mission audit, legal proceeding,
or accident investigation, a third party must be able to cryptographically verify
that a specific telemetry sequence came from a specific drone.

### 1.3 The gap

No published protocol addresses authenticated high-rate telemetry with PQC
non-repudiation for autonomous systems. This specification fills that gap.

---

## 2. Protocol Overview

The Telemetry Authentication Protocol (TAP) uses two complementary layers:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Per-packet HMAC-SHA3-256                       │
│  • Overhead: 42 bytes (8 nonce + 2 len + 32 tag)         │
│  • Latency: 1.1 µs (Neoverse-N2)                        │
│  • Provides: authenticity + integrity + anti-replay      │
│  • Does NOT provide: non-repudiation                     │
└─────────────────────────────────────────────────────────┘
             │
             ▼ every W packets (default W=256)
┌─────────────────────────────────────────────────────────┐
│  Layer 2: ML-DSA-87 Window Anchor                        │
│  • Overhead: 4707 bytes (80 header/commitment + 4627 sig)│
│  • Latency: ~962 µs (Neoverse-N2, amortized = 3.75 µs/pkt) │
│  • Provides: non-repudiation + audit trail               │
│  • Signs: SHA3-256 commitment of last W packet MACs      │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Definitions

- **W**: window size (number of packets per anchor). Default: 256.
- **T**: anchor time limit (seconds). Default: 10s. An anchor is emitted at
  min(W packets elapsed, T seconds elapsed), whichever comes first.
- **SESSION_KEY**: a 32-byte key established via ML-KEM-1024 session setup.
- **HMAC_KEY**: `SHA3-256(SESSION_KEY || "cleitonq-tap-hmac-v1")` — 32 bytes.
- **ANCHOR_KEY**: the ML-DSA-87 signing key held by the ground station.
- **window_commitment**: `SHA3-256(mac_0 || mac_1 || ... || mac_{W-1})` where
  each `mac_i` is the 32-byte HMAC tag of packet `i` in the window.

---

## 4. Session Establishment

TAP reuses the CleitonQ session establishment protocol (FIPS 203 ML-KEM-1024):

1. Drone broadcasts `SESSION_INIT` containing its ML-KEM-1024 encapsulation key.
2. Ground station encapsulates to obtain `(ciphertext, SESSION_KEY)`.
3. Ground station transmits `ciphertext` to drone.
4. Drone decapsulates to recover `SESSION_KEY`.
5. Both parties derive `HMAC_KEY` from `SESSION_KEY`.

The ground station's ML-DSA-87 `ANCHOR_KEY` (verifying key) is pre-provisioned
on the drone at key ceremony time (out-of-band).

---

## 5. Per-Packet Format (Layer 1)

Each telemetry packet is authenticated as follows:

```
TELEMETRY_AUTH packet:
  nonce       : u64  (8 bytes)  — monotonically increasing, per-channel
  payload_len : u16  (2 bytes)  — length of original telemetry payload
  payload     : bytes[payload_len]
  mac         : bytes[32]       — HMAC-SHA3-256(HMAC_KEY, nonce || payload)

Total overhead: 10 bytes header + 32 bytes MAC = 42 bytes
```

**Verification:**
```
expected_mac = HMAC-SHA3-256(HMAC_KEY, nonce || payload)
assert constant_time_eq(mac, expected_mac)
assert nonce > last_verified_nonce
```

The receiver maintains `last_verified_nonce` per channel. A packet with
`nonce <= last_verified_nonce` is rejected as a replay.

---

## 6. Window Anchor Format (Layer 2)

After every W packets (or T seconds), the ground station emits an anchor:

```
TELEMETRY_ANCHOR packet:
  domain          : bytes[22]           — the ASCII string "CLEITONQ-TAP-ANCHOR-v1"
  anchor_nonce    : u64      (8 bytes)  — independent nonce sequence for anchors
  window_start    : u64      (8 bytes)  — nonce of first packet in this window
  window_end      : u64      (8 bytes)  — nonce of last packet in this window
  packet_count    : u16      (2 bytes)  — number of packets in window (≤ W)
  commitment      : bytes[32]           — SHA3-256(mac_0 || mac_1 || ... || mac_{n-1})
  anchor_signature: bytes[4627]         — ML-DSA-87(ANCHOR_KEY, domain || anchor_nonce || window_start || window_end || packet_count || commitment)

Total size: 4707 bytes (22 + 8 + 8 + 8 + 2 + 32 + 4627)
```

**A verifier MUST reject an anchor whose signed payload is not exactly 80 bytes
or does not begin with the domain string.** Both checks, not either one.

### Why the domain string is here, and why the length check matters as much

This changed on 2026-08-07, and the reasoning is worth keeping because it is the
same reasoning the rest of this project is about.

The signing routine builds what it signs by plain concatenation: the payload,
then an eight-byte nonce. There is no length prefix, no type tag and no
separator. So a signature over one structure is a valid signature over another
whenever the two byte strings happen to coincide, and the only thing standing
between the two is whether a verifier can tell them apart.

Without the domain string, the signed payload here is 58 bytes of fields with
nothing distinguishing it. Any other 58-byte structure signed by the same key
would verify as an anchor. That is only a problem if one key signs more than one
kind of thing, which this document does not forbid and which is what people
actually do when a construction is offered for reuse.

The CCSDS instantiation of the same construction was already protected, and not
by its domain string alone: its decoder requires the domain string **and** an
exact payload length, so nothing shorter, longer or differently-shaped is
accepted. That pairing is what closes the gap, and it is the same shape as a
protocol parser that refuses to proceed unless it consumed exactly what it was
handed.

The cost is a constant 22-byte prefix, which amortises to 0.09 bytes per message
at W=256. The failure it prevents is a cross-context signature substitution.

**Divergence to reconcile:** `draft-bezerra-anchors-command-provenance-01` gives
this anchor as 4685 bytes and raises the question of whether the telemetry
instantiation needs the prefix, leaving it open. This document now answers it.
The draft will be updated; until then, this specification is the current one and
the draft's figure is the pre-change size.

**Anchor computation (ground station):**
```
commitment = SHA3-256(concat(mac_i for i in window))
anchor_signature = ML-DSA-87.sign(ANCHOR_KEY,
    anchor_nonce || window_start || window_end || packet_count || commitment)
```

**Anchor verification (drone / third-party auditor):**
```
// Recompute commitment from stored MACs
commitment = SHA3-256(concat(mac_i for i in window))
ML-DSA-87.verify(ANCHOR_VERIFYING_KEY,
    anchor_nonce || window_start || window_end || packet_count || commitment,
    anchor_signature)
assert anchor_nonce > last_anchor_nonce
```

---

## 7. Bandwidth Analysis

At 100 Hz with W=256 (anchor every 2.56 seconds):

| Component | Per-packet overhead | Effective bandwidth |
|---|---|---|
| Layer 1 HMAC | 42 bytes | 33.6 kbps |
| Layer 2 anchor (amortized) | 4707 / 256 = 18.4 bytes | 14.7 kbps |
| **Total TAP overhead** | **60.4 bytes** | **48.3 kbps** |

For comparison, a 100-Hz MAVLink telemetry stream with a 100-byte average payload
consumes 80 kbps. TAP adds ~60% overhead — acceptable for Wi-Fi and LTE links,
borderline for RFD900, impractical for SiK at 56 kbps.

**For bandwidth-constrained links (SiK, IRIDIUM, CCSDS):**
- Increase W to 1024 or 4096 (anchor every 10–40 seconds)
- Layer 1 overhead remains 42 bytes regardless of W
- Amortized anchor overhead drops to 4.6 / 1.1 bytes per packet

---

## 8. CCSDS Adaptation

For CCSDS Telecommand (TC) frames with uplink budgets of 2–8 kbps:

- W = 1 contact window (all TC packets in one ground station pass)
- T = contact duration (typically 240–600s for LEO)
- One anchor per contact window (CCSDS_PQC_ANCHOR, 4719 bytes — see adapter spec)
- Layer 1 HMAC overhead: 42 bytes per TC packet (fits in 1024-byte TC Transfer Frame)

The CCSDS TC authentication extension is specified in [ccsds-pqc-adapter.md](ccsds-pqc-adapter.md).

---

## 9. Security Analysis

### 9.1 HMAC layer

HMAC-SHA3-256 with a 256-bit session key provides 128-bit post-quantum security
(Grover's algorithm halves symmetric key security). The session key is established
via ML-KEM-1024, which provides 256-bit classical / 128-bit quantum security.

### 9.2 Anchor layer

ML-DSA-87 provides 128-bit post-quantum security for signatures. The window
commitment (SHA3-256) is collision-resistant with 128-bit quantum security
(Grover on SHA3-256 requires 2^128 operations).

### 9.3 Threat model

| Threat | Mitigation |
|---|---|
| Active MitM modifying telemetry | HMAC-SHA3-256 per packet |
| Passive HNDL (harvest, decrypt later) | ML-KEM session key — quantum-resistant |
| Impersonation (forge telemetry source) | ML-DSA-87 anchor signature |
| Replay of valid telemetry window | Monotonic anchor_nonce + window_start |
| Ground station key compromise | ML-KEM forward secrecy protects past sessions |

### 9.4 Third-party audit

An auditor with access to:
- The stored MAC sequence `{mac_i}`
- The anchor packets `{TELEMETRY_ANCHOR}`
- The ground station ML-DSA-87 verifying key

can verify the authenticity of the entire telemetry archive without access to
the session key or HMAC key. This enables post-mission forensics independent
of any live system.

---

## 10. Implementation Notes

The Layer 1 HMAC authentication is implemented in `cleitonq::channel::AuthChannel`.
The Layer 2 anchor signature is implemented in `cleitonq::dsa::SigningKey` / `VerifyingKey`.

A reference implementation of the TAP window accumulator and anchor emitter
(`examples/telemetry_auth.rs`) is planned — see Open Items.

---

## 11. Open Items

- [ ] Reference implementation `examples/telemetry_auth.rs` (window accumulator + anchor emitter)
- [ ] Define CLEITONQ_TELEMETRY_ANCHOR wire format for MAVLink dialect (MSG_ID TBD)
- [ ] Specify recovery behavior when anchor is lost in transit
- [ ] Evaluate W selection heuristics for bandwidth-constrained links
- [ ] Extend IETF I-D to include TAP as Section 5
