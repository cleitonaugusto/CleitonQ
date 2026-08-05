# CleitonQ CCSDS PQC Adapter

**Version:** 0.1-draft  
**Author:** Cleiton Augusto Correa Bezerra  
**Date:** 2026-07-02  
**Status:** Draft — target: CCSDS Security Working Group submission

---

## Abstract

Spacecraft using CCSDS Telecommand (TC) and Telemetry (TM) protocols employ
key establishment and authentication based on AES-256 with RSA-2048 or ECDSA.
Satellites launched today have operational lifetimes of 10–25 years, placing
them inside the credible quantum threat window (2029–2032, per current estimates).

A 2026 systematic survey of 393 PQC publications for space systems explicitly
identified a 3–5 year standardization gap for CCSDS integration requirements
for missions launching in 2026–2028.

This document specifies how CleitonQ's post-quantum authentication primitives
(ML-KEM-1024 FIPS 203, ML-DSA-87 FIPS 204, HMAC-SHA3-256 FIPS 202) adapt
to CCSDS TC/TM constraints: uplink budgets of 2–8 kbps, TC Transfer Frames
of up to 1024 bytes, and contact windows of 3–15 minutes for LEO orbits.

---

## 1. CCSDS Protocol Context

### 1.1 Telecommand (TC) Transfer Frame structure

```
TC Transfer Frame (CCSDS 232.0-B-4):
  ┌────────────────────────────────────────────────┐
  │ Primary Header       (5 bytes)                  │
  │   Version Number (2b) | Bypass Flag (1b)         │
  │   Control Command Flag (1b) | Reserved (2b)      │
  │   Spacecraft ID (10b) | Virtual Channel ID (6b)  │
  │   Frame Length (10b) | Frame Seq Number (8b)     │
  ├────────────────────────────────────────────────┤
  │ TC Segment (variable, up to 1019 bytes)         │
  │   Sequence Flags (2b) | Multiplexer Access      │
  │   Point ID (6b) | TC Packet                     │
  ├────────────────────────────────────────────────┤
  │ Frame Error Control (2 bytes, optional CRC-16)  │
  └────────────────────────────────────────────────┘
  Maximum Frame Length: 1024 bytes
```

### 1.2 Current security (SDLS — CCSDS 355.0-B-2)

CCSDS Space Data Link Security (SDLS) provides:
- Authentication: CMAC-AES-128 or CMAC-AES-256
- Encryption: AES-256-GCM
- Key management: manual (pre-loaded symmetric keys) or asymmetric via RSA-2048 / ECDH-P256

SDLS does not provide post-quantum security.

#### 1.2.1 Relationship to SDLS (why this adapter is complementary)

This adapter does not replace SDLS. Three structural properties of SDLS
(CCSDS 355.0-B-2) define the boundary:

1. **The Security Trailer carries a fixed-length MAC** (§4.1.2.3), sized per
   Security Association for symmetric tags (16 bytes). An ML-DSA-87 signature
   (4627 bytes) exceeds an entire 1024-byte TC frame and cannot reside in a
   Security Trailer. A PQC *signature* service must therefore operate
   out-of-frame — motivating `CCSDS_PQC_CHUNK` fragmentation (§4).
2. **SDLS authentication is symmetric** (a MAC, §2.3.2.2), providing integrity
   and origin authentication to the session peer but not non-repudiation to a
   third party. The per-contact-window `CCSDS_PQC_ANCHOR` (§3.3) adds exactly
   that service.
3. **Over-the-air SA key negotiation is explicitly undefined** in SDLS
   (§2.3.1.5, "a currently undefined Application Layer function"). The
   ML-KEM-1024 session establishment of §3.1 is a concrete instantiation of
   that open function.

SDLS is not relay-strippable: its Security Header and Trailer sit inside the
Transfer Frame, and the MAC covers the frame header and security header. This
adapter adds the two services SDLS cannot structurally provide —
non-repudiation and post-quantum signatures — and fills its undefined key
establishment function.

### 1.3 Uplink budget constraints

| Orbit | Typical uplink rate | Contact window | Bytes available/pass |
|---|---|---|---|
| LEO (400–600 km) | 2–8 kbps | 3–12 min | 45 KB – 720 KB |
| MEO (GPS, 20,200 km) | 64 kbps | 4–8 hours | 115 MB |
| GEO (35,786 km) | 100+ kbps | Continuous | Unlimited |
| Deep Space | 1–256 bps | Hours–days | KB to MB/pass |

LEO is the constraining case: 45 KB minimum per pass, 2 kbps worst case.

---

## 2. Constraint Analysis for PQC Algorithms

| Algorithm | Key / Output size | Fit in 1024-byte TC frame? | Fit in LEO contact? |
|---|---|---|---|
| ML-KEM-1024 encapsulation key | 1568 bytes | ❌ spans 2 frames | ✅ 1 frame burst |
| ML-KEM-1024 ciphertext | 1568 bytes | ❌ spans 2 frames | ✅ 1 frame burst |
| ML-DSA-87 signature | 4627 bytes | ❌ spans 5 frames | ✅ (sparse use) |
| HMAC-SHA3-256 tag | 32 bytes | ✅ 32/1024 = 3% | ✅ |
| SLH-DSA-SHA2-256s signature | 29792 bytes | ❌ spans 30 frames | ✅ (1/mission, §3.4 reserved) |

**Key finding:** ML-KEM and ML-DSA outputs do not fit in a single TC frame.
CLEITONQ_CHUNK fragmentation (the same mechanism used for MAVLink relay-transparency)
applies directly to CCSDS: each CCSDS_PQC_CHUNK carries one fragment of the
key material as a native TC packet. Ground relay nodes forward chunks without
inspecting content.

---

## 3. Protocol Design

### 3.0 Conventions

**All multi-byte integers in this specification are big-endian**, consistent
with CCSDS practice, in every structure defined here — `CCSDS_PQC_CMD`,
`CCSDS_PQC_ANCHOR` and the `CCSDS_PQC_CHUNK` header alike. Field widths are
given in octets.

Known-answer test vectors pinning every byte of these formats are published
alongside this specification, so an implementation in any language can be
checked against a fixed reference. The vectors deliberately do not re-cover the
NIST primitives themselves (ML-KEM, ML-DSA, SHA3), which have their own official
vectors; they pin how this adapter composes them.

### 3.1 Session establishment (one-time per mission phase)

The ML-KEM-1024 session is established during a designated key-exchange window,
typically the first ground contact of a mission phase.

```
Ground Station → Spacecraft:
  CCSDS_PQC_SESSION_INIT chunks (ML-KEM-1024 ciphertext, 1568 bytes)
  Fragmented into 2 TC Transfer Frames (≤ 1024 bytes each)
  Total uplink cost: ~3.1 kbps for 8 seconds

Spacecraft:
  Decapsulates SESSION_KEY from ML-KEM-1024 decapsulation key
  Derives HMAC_KEY = SHA3-256(SESSION_KEY || "cleitonq-ccsds-hmac-v1")
  Confirms via CCSDS_PQC_SESSION_ACK in TM downlink
```

The ML-KEM encapsulation key is pre-loaded at the spacecraft during ground
integration (equivalent to key ceremony). It does not change during the mission
unless a rekeying event occurs.

### 3.2 Per-command authentication (continuous)

Every TC packet in normal operations is authenticated with HMAC-SHA3-256:

```
CCSDS_PQC_CMD packet (embedded in TC Segment):
  pqc_nonce      : u64     (8 bytes)  — monotonic, per virtual channel
  original_apid  : u16     (2 bytes)  — CCSDS Application Process ID
  payload_len    : u16     (2 bytes)
  payload        : bytes[payload_len] — original TC packet payload
  hmac_tag       : bytes[32]          — HMAC-SHA3-256(HMAC_KEY, pqc_nonce || original_apid || payload)

Total overhead: 44 bytes per TC command
Fits in 1024-byte TC Transfer Frame: ✅ (44/1024 = 4.3%)
```

HMAC verification on the spacecraft: 1.1 µs (Neoverse-N2); comparable or faster
on radiation-hardened processors at equivalent clock rates.

### 3.3 Contact window anchor (once per pass)

At the end of each ground contact window, the ground station transmits a
ML-DSA-87 anchor covering the entire session:

```
CCSDS_PQC_ANCHOR (fragmented across 5 TC frames):
  domain          : bytes[24]           — "CLEITONQ-CCSDS-ANCHOR-v1", domain separation
  anchor_nonce    : u64      (8 bytes)
  session_start   : u64      (8 bytes)  — first pqc_nonce in this contact
  session_end     : u64      (8 bytes)  — last pqc_nonce in this contact
  cmd_count       : u32      (4 bytes)  — number of commands authenticated
  commitment      : bytes[32]           — SHA3-256(hmac_tag_0 || ... || hmac_tag_n)
  sig_nonce       : u64      (8 bytes)  — signature-layer replay nonce
  anchor_sig      : bytes[4627]         — ML-DSA-87 over all preceding fields

Total: 4719 bytes → 5 TC Transfer Frames
Uplink cost at 2 kbps: 19.1 seconds (4779 bytes on the wire including frame and
fragmentation headers; acceptable at the end of a 3–12 min pass)
```

The anchor enables post-mission audit: any third party with the ground station's
ML-DSA-87 verifying key can verify the authenticity of the entire command sequence
for a given contact window, without access to the symmetric session key.

### 3.4 Mission-lifetime key revocation (rare) — NOT YET SPECIFIED

> **Status: reserved, not implemented.** This section states a requirement and a
> size budget. It does not yet define a wire format, and no implementation of it
> exists. `CCSDS_PQC_CHUNK` type `0x03` is reserved for it. Earlier revisions of
> this document described the mechanism as though it were defined; it is not.

If the ground segment's ML-DSA-87 signing key is compromised, a spacecraft that
has been provisioned with its verifying key must be able to learn that the key is
no longer trustworthy, and to do so without relying on that same key. The natural
instrument is a certificate signed by the long-lived SLH-DSA-SHA2-256s trust root
(FIPS 205), which rests on hash assumptions alone and is therefore independent of
the lattice path it revokes.

The parameter set is a profile decision. The reference implementation defaults to
SHA2-256s and supports the three FIPS 205 small-signature sets, so a
specification can fix one and an implementation can honour it:

| Profile | NIST category | Verifying key | Signature | TC frames | Sign | Verify |
|---|---|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 1 | 32 B | 7 856 B | 8 | 772 ms | 796 µs |
| SLH-DSA-SHA2-192s | 3 | 48 B | 16 224 B | 17 | 1.35 s | 1.26 ms |
| **SLH-DSA-SHA2-256s** (default) | **5** | 64 B | 29 792 B | 30 | 1.31 s | 1.82 ms |

Timings are from the reference implementation on x86-64, ten samples each, and
are reproducible from the published benchmark. They are given because the trade
is not the smooth one the sizes suggest: **category 3 costs as much signing time
as category 5** — the confidence intervals overlap — while offering less margin,
so its only argument is the smaller signature. A profile selection should be
made on size, not on an assumption that a lower category buys speed.

Verification is milliseconds at every profile. The cost of this scheme falls
entirely on the offline signing ceremony, never on the spacecraft, which never
verifies one of these signatures on the critical path.

We recommend category 5 for the space profile, and state the reasoning so it can
be contested: this key is the longest-lived trust root in the system, and at
category 5 it matches ML-DSA-87 rather than sitting below the operational path it
backstops. The cost — 30 frames — is paid at most once per mission, in the rarest
event the design contemplates.

The recommendation is not universal, which is why this is a profile rather than a
constant. The same certificate over a narrowband link with a 255-byte frame is
120 fragments at category 5 and 32 at category 1, and there the trade may fall
the other way. A constrained profile should be chosen deliberately and recorded,
not inherited by default.

**What is undefined, and belongs to working-group discussion rather than to this
document:** the certificate's field layout; whether revocation is permanent or
carries a successor key; how the spacecraft obtains a replacement verifying key
once the old one is repudiated; whether the spacecraft may act on a revocation
received over the very link the revoked key authenticated; and what it should do
in the interval between revocation and re-provisioning. These are protocol
questions, not encoding questions, and specifying the object without settling
them would only look complete.

The reference implementation does contain an SLH-DSA revocation certificate, but
it revokes a *peer node identifier* in a fleet registry — a different object with
different semantics, belonging to the MAVLink profile rather than to this
adapter. It is not the mechanism described here and should not be read as one.

---

## 4. CLEITONQ_CHUNK Fragmentation for CCSDS

The CLEITONQ_CHUNK mechanism (designed for MAVLink relay-transparency) maps
directly to CCSDS TC fragmentation:

```
CCSDS_PQC_CHUNK TC packet:
  chunk_type  : u8   — 0x01 = SESSION_INIT, 0x02 = ANCHOR, 0x03 = REVOCATION
  chunk_index : u8   — 0-indexed fragment number
  chunk_total : u8   — total number of fragments
  chunk_len   : u16  — length of this fragment
  chunk_data  : bytes[chunk_len]
```

A CCSDS relay node that does not implement PQC support forwards
`CCSDS_PQC_CHUNK` packets as opaque TC data — the same relay-transparent
behavior as CLEITONQ_CHUNK in MAVLink. The spacecraft reassembles fragments
before processing.

---

## 5. Compliance Mapping

| Requirement | Source | CleitonQ CCSDS Adapter |
|---|---|---|
| AES-256 for encryption | CCSDS SDLS, NSA CNSA 2.0 | ChaCha20-Poly1305 (RFC 8439, equivalent security) |
| Post-quantum key establishment | NSA CNSA 2.0 (Jan 2027 mandate) | ML-KEM-1024 (FIPS 203) ✅ |
| Post-quantum signatures | NSA CNSA 2.0 | ML-DSA-87 (FIPS 204) ✅ |
| Non-repudiation | Mission assurance requirements | ML-DSA-87 anchor per contact window ✅ |
| Authentication overhead | CCSDS link budget | 44 bytes/command (4.3% of frame) ✅ |
| Fits in TC Transfer Frame | CCSDS 232.0-B-4 (1024 bytes max) | HMAC: ✅ | KEM/DSA: fragmented ✅ |

---

## 6. Threat Model

| Threat | Applicable to CCSDS? | Mitigation |
|---|---|---|
| Ground relay stripping authentication | ✅ Relay nodes re-serialize TC packets | CCSDS_PQC_CHUNK (relay-transparent) |
| Harvest-now-decrypt-later | ✅ TM downlink interceptable from any antenna | ML-KEM forward secrecy |
| Spacecraft command injection | ✅ Uplink interception by state actors | HMAC-SHA3-256 per command |
| Replay of valid command sequence | ✅ Recorded uplink replayed next pass | Monotonic pqc_nonce per virtual channel |
| Ground station key compromise | ✅ Mission-critical threat | ML-KEM forward secrecy + SLH-DSA revocation |

---

## 7. Comparison with Existing Proposals

| Approach | Uplink overhead | Non-repudiation | Relay-transparent | PQ-secure |
|---|---|---|---|---|
| CCSDS SDLS (AES-256) | ~16 bytes/cmd | ❌ | ✅ (symmetric) | ❌ |
| Falcon-512 per-command | 666 bytes/cmd | ✅ | ❌ | ✅ |
| SPHINCS+-SHA2-128s per-cmd | 7856 bytes/cmd | ✅ | ❌ | ✅ |
| **CleitonQ CCSDS Adapter** | **44 bytes/cmd + 4719 bytes/pass** | **✅** | **✅** | **✅** |

CleitonQ's two-layer approach is the only design that satisfies all four
requirements simultaneously within LEO link budget constraints.

---

## 8. Implementation Roadmap

| Milestone | Target | Status |
|---|---|---|
| Spec v0.1 (this document) | Q3 2026 | ✅ Draft |
| Reference implementation in Rust | Q3 2026 | 🔄 In progress |
| CCSDS TC simulator (Python) | Q3 2026 | Planned |
| Benchmark on radiation-hardened processor (LEON3/GR740) | Q4 2026 | Planned |
| Submission to CCSDS Security WG | Q1 2027 | Blocked on CVE + IACR ePrint |
| INPE / ESA OSIP engagement | Q1 2027 | Planned |

---

## 9. References

1. CCSDS 232.0-B-4, *TC Space Data Link Protocol*, October 2021
2. CCSDS 355.0-B-2, *Space Data Link Security Protocol (SDLS)*, July 2022
3. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024
4. NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, August 2024
5. NSA, *Commercial National Security Algorithm Suite 2.0*, September 2022
6. H. Kim, *Post-quantum cryptography for space systems: Algorithms, implementation, and design constraints—A systematic survey*, Acta Astronautica, vol. 246, pp. 863–886, 2026. doi:10.1016/j.actaastro.2026.04.041
7. CleitonQ IETF I-D: draft-bezerra-relay-auth-transparency-00
