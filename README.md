# CleitonQ

**Post-quantum authentication for constrained embedded systems, in `no_std` Rust.**

*by Cleiton Augusto Correa Bezerra*

[![Crates.io](https://img.shields.io/crates/v/cleitonq.svg)](https://crates.io/crates/cleitonq)
[![Docs.rs](https://docs.rs/cleitonq/badge.svg)](https://docs.rs/cleitonq)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]()
[![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM--1024-blueviolet.svg)]()
[![FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20ML--DSA--87-blueviolet.svg)]()
[![FIPS 205](https://img.shields.io/badge/NIST-FIPS%20205%20SLH--DSA-blueviolet.svg)]()
[![ARM64 CI](https://github.com/cleitonaugusto/CleitonQ/actions/workflows/arm-bench.yml/badge.svg)](https://github.com/cleitonaugusto/CleitonQ/actions/workflows/arm-bench.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20776349.svg)](https://doi.org/10.5281/zenodo.20776349)
[![Blog](https://img.shields.io/badge/blog-cleitonaugusto.github.io-informational.svg)](https://cleitonaugusto.github.io)

---

CleitonQ is a post-quantum authentication library for resource-constrained embedded systems. It provides FIPS 203/204/205 session establishment, message signing, and high-rate telemetry authentication in `no_std` Rust, targeting the link protocols used in robotics and embedded control.

**Protocol coverage:** MAVLink v2 · ROS2/DDS · CAN · CCSDS Telecommand

**Target hardware:** Cortex-A76 (Jetson, RPi5), Cortex-A53, Cortex-M4F (`no_std + alloc`)

Security properties were formally verified using ProVerif and Tamarin Prover. Proof artifacts are available upon request.

---

## Why this exists now

The cryptographic threat to autonomous systems is not a future concern — it is a present-day operational reality.

**Harvest-now-decrypt-later (HNDL):** State-level adversaries record encrypted C2 traffic today to decrypt when quantum computers become available. Three independent papers published between May 2025 and March 2026 reduced the estimated cost of breaking RSA-2048 from 20 million to under 100,000 physical qubits. Median estimate for a cryptographically relevant quantum computer: **2030**. A drone designed today for a 5-year service life will operate inside that window.

**CNSA 2.0 mandate:** The NSA's Commercial National Security Algorithm Suite 2.0 transitioned from guidance to **mandatory procurement requirement** in January 2027. All new National Security System acquisitions must use ML-KEM-1024 for key establishment and ML-DSA-87 for signatures. No compliant, embedded-safe, formally verified implementation for autonomous system C2 existed before CleitonQ.

**The standardization gap:** A 2026 systematic survey of 393 publications on PQC for autonomous and space systems identified a 3–5 year gap in standardized solutions for embedded C2 protocols. CleitonQ addresses that gap.

---

## The origin case: relay-stripping in MAVLink v2

The motivation for CleitonQ is a vulnerability class discovered in MAVLink v2: **authentication bytes appended after the frame boundary are silently stripped by any compliant relay**.

Root cause: the MAVLink v2 spec defines frame length as exactly `10 + LEN + 2` bytes. A compliant parser (MAVProxy, mavlink-router, QGroundControl) reads that many bytes and stops. Appended bytes — including the optional signing field from MAVLink RFC #196 — are discarded at every relay hop. The downstream receiver gets a valid, unauthenticated frame with no indication that authentication was removed.

**This affects every authentication scheme that appends material outside the frame boundary**, regardless of algorithm. It is a structural property of the protocol, not an implementation bug.

```
PoC (no drone required):
./tools/unsign mavlink
```

IETF Internet-Draft: [draft-bezerra-relay-auth-transparency-00](https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/)

The same relay-transparency class applies to DDS bridges in ROS2 (CDR boundary stripping), CAN gateways (DLC boundary re-serialization), and CCSDS relay nodes — documented in [Section 4 of the I-D](https://www.ietf.org/archive/id/draft-bezerra-relay-auth-transparency-00.txt).

---

## The fix: relay-transparent fragmentation

`CLEITONQ_CHUNK` (MSG_ID 50000, `INCOMPAT_FLAGS=0x00`) — a first-class MAVLink dialect message carrying authentication material as fragmented native frames. Any relay forwards chunks as valid, opaque messages whether or not it knows the CleitonQ dialect. Authentication survives every relay hop.

---

## What CleitonQ provides

| Layer | Algorithm | Standard | Purpose |
|---|---|---|---|
| Session establishment | ML-KEM-1024 | FIPS 203 | Forward-secret key exchange; one-time per session |
| Command signing | ML-DSA-87 | FIPS 204 | Non-repudiation; per high-value command |
| Command encryption | ChaCha20-Poly1305 | RFC 8439 | Payload confidentiality + AEAD |
| Per-packet authentication | HMAC-SHA3-256 | FIPS 202 | High-rate telemetry; 40-byte overhead at 100+ Hz |
| Hybrid KEM | X25519 + ML-KEM-1024 | NIST SP 800-227 | Classical/PQC transition compatibility |
| Revocation certificates | SLH-DSA-SHA2-128s | FIPS 205 | Hash-only security assumption; 20-year validity |

### High-rate telemetry authentication

A full ML-DSA-87 signature (4627 bytes) per telemetry packet is impractical at 100 Hz — it would consume more bandwidth than the link budget allows.

CleitonQ solves this with a two-layer approach:

1. **Per-packet:** HMAC-SHA3-256 authentication (40-byte overhead, 1.1 µs on Neoverse-N2). Protects the data stream in real time.
2. **Periodic anchor:** ML-DSA-87 signature over a rolling commitment of the last *N* packets (configurable; default 256). Provides non-repudiation and long-term audit trail without per-packet overhead.

The session HMAC key is established once via ML-KEM-1024. The anchor signature proves the entire telemetry window to a third party, not just the immediate receiver. This is the first formally specified PQC telemetry authentication protocol for autonomous systems. Spec: [rfc/telemetry-auth-spec.md](rfc/telemetry-auth-spec.md).

### Security properties

- **Quantum resistance** — ML-KEM and ML-DSA are secure against Shor's algorithm (NIST FIPS 203/204)
- **Forward secrecy** — each ML-KEM session key is independent; past sessions are safe if the long-term key is later compromised
- **Non-repudiation** — ML-DSA-87 signatures prove a command came from the authorised ground station
- **Payload confidentiality** — ChaCha20-Poly1305 encrypts C2 commands; relays see only opaque ciphertext
- **Anti-replay** — monotonically-increasing per-packet counters, enforced in constant time
- **Domain separation** — one session key produces independent sub-keys per channel (C2, telemetry, mesh) via SHA3-256 salts
- **Defense in depth** — SLH-DSA revocation certs require only hash security; if lattice hardness is ever questioned, revocations remain valid
- **Formally verified** — session key secrecy, command authenticity, injective replay resistance, and forward secrecy verified with ProVerif and Tamarin Prover; proof artifacts available upon request

---

## Quick start

```toml
[dependencies]
cleitonq = "0.2"
```

### Session establishment + encrypted C2

```rust
use cleitonq::prelude::*;

// Drone: generate ML-KEM key pair (once, at provisioning)
let kp = kem::KemKeyPair::generate();
// share kp.ek_bytes() with the ground station; keep dk on the drone

// Ground station: establish forward-secret session
let (ciphertext, session_key) = kem::encapsulate_raw(&drone_ek)?;
// send `ciphertext` to the drone — reveals nothing about session_key

// Both sides: derive an encrypted C2 channel
let c2 = SealedChannel::new(&session_key, ChannelDomain::C2);

// Ground station: encrypt + authenticate a command
let packet = c2.seal(b"waypoint=100.0,80.0,50.0", /*counter=*/ 1);

// Drone: verify + decrypt
let mut pkt = packet;
let (plaintext, _counter) = c2.open(&mut pkt, /*last_counter=*/ 0)
    .expect("authenticated and decrypted");
```

### Command signing with non-repudiation (ML-DSA-87)

```rust
use cleitonq::dsa::{SigningKey, VerifyingKey};

// Ground station: sign a high-value command
let sk = SigningKey::generate();
let packet = sk.sign(b"arm_vehicle", seq_number);

// Drone: verify — rejects forgeries and replays
let vk = VerifyingKey::load("gs_verifying.bin")?;
let (payload, nonce) = vk.verify(&packet, last_nonce).expect("valid command");
```

### Per-packet HMAC channel (telemetry, 100+ Hz)

```rust
use cleitonq::prelude::*;

let c2_tx = AuthChannel::new(&session_key, ChannelDomain::C2);
let packet = c2_tx.sign(b"telemetry_payload", nonce);

let c2_rx = AuthChannel::new(&session_key, ChannelDomain::C2);
let (payload, _nonce) = c2_rx.verify(&packet, last_nonce).expect("authenticated");
```

### Key generation (run once before deployment)

```rust
use cleitonq::kem::KemKeyPair;
use cleitonq::dsa::SigningKey;

// Drone: generate and save ML-KEM key pair
let kp = KemKeyPair::generate();
kp.save("drone_kem_dk.bin", "drone_kem_ek.bin").unwrap();
// drone_kem_dk.bin → stays on the drone (PRIVATE)
// drone_kem_ek.bin → share with ground station (public)

// Ground station: generate ML-DSA-87 signing key
let sk = SigningKey::generate();
sk.save("gs_signing.bin").unwrap();
sk.verifying_key().save("gs_verifying.bin").unwrap();
// gs_signing.bin → stays at ground station (PRIVATE)
// gs_verifying.bin → distribute to every drone (public)
```

---

## Performance

Measured with Criterion (median of 100 samples, release build). Run `cargo bench` to reproduce.
ARM64 numbers from a native `ubuntu-24.04-arm` GitHub Actions runner (Neoverse-N2).

| Operation | x86-64 (Intel Core i5) | ARM64 (Neoverse-N2) | Notes |
|---|---|---|---|
| ML-KEM-1024 keygen | 100.2 µs | 77.1 µs | One-time at provisioning |
| ML-KEM-1024 encapsulate | 95.5 µs | 70.5 µs | One-time per session |
| ML-KEM-1024 decapsulate | 125.6 µs | 84.3 µs | One-time per session |
| ML-DSA-87 sign (30B payload) | 455.3 µs | 962.0 µs | Per high-value command |
| ML-DSA-87 verify (30B payload) | 115.9 µs | 85.3 µs | Per received command |
| ChaCha20-Poly1305 seal/open | < 1 µs | < 1 µs | Per encrypted packet |
| HMAC-SHA3-256 sign | 2.50 µs | 1.10 µs | Per packet at 100+ Hz |
| HMAC-SHA3-256 verify | 2.37 µs | 1.12 µs | Per packet at 100+ Hz |
| Full session establishment | 304.6 µs | 241.1 µs | Encap + decap + channel init |

**At 100 Hz, the per-packet authentication overhead is 110 µs/s — negligible against any realistic cycle budget.**

The two-layer telemetry approach (HMAC per-packet + ML-DSA anchor) adds a worst-case of 962 µs for anchor computation, amortized over 256 packets = 3.75 µs/packet equivalent.

### Packet overhead

| Layer | Overhead |
|---|---|
| ChaCha20-Poly1305 (SealedChannel) | 24 bytes (8 counter + 16 tag) |
| HMAC-SHA3-256 channel | 40 bytes (8 nonce + 32 tag) |
| ML-DSA-87 signed command | 4635 bytes (8 nonce + 4627 sig) |
| ML-KEM-1024 ciphertext (one-time) | 1568 bytes |

---

## Protocol coverage

### MAVLink v2

CleitonQ wraps MAVLink payloads without modifying the MAVLink framing. Authentication material travels as `CLEITONQ_CHUNK` (MSG_ID 50000) — a first-class dialect message that survives any MAVProxy / mavlink-router relay hop.

A formal MAVLink RFC was submitted in June 2026: [Issue #2527](https://github.com/mavlink/mavlink/issues/2527) and [PR #2528](https://github.com/mavlink/mavlink/pull/2528). Wire format spec and dialect XML in [rfc/](rfc/).

### ROS2 / DDS

The `cleitonq-ros2` package implements a parallel-topic authentication pattern for ROS2: authenticated commands travel on a `/cmd_pqc` topic alongside the original command topic. `./tools/unsign ros2` demonstrates the same vulnerability class in ros1_bridge and Fast DDS bridge deployments.

OMG DDS-Security PQC extension spec draft: [docs/omg/dds-security-pqc-extension-spec-v0.1.md](docs/omg/dds-security-pqc-extension-spec-v0.1.md)  
Issue submitted: [omg-dds/dds-security#22](https://github.com/omg-dds/dds-security/issues/22)

### CCSDS (satellite telecommand)

CCSDS Telecommand (TC) frames carry the same relay-transparency risk at ground station relay nodes. Uplink bandwidth constraints (2–8 kbps for LEO) make per-command ML-DSA-87 signatures impractical; CleitonQ's two-layer approach (HMAC per TC packet, ML-DSA-87 anchor once per contact window) is directly applicable. Specification in progress: [rfc/ccsds-pqc-adapter.md](rfc/ccsds-pqc-adapter.md).

---

## Embedded support (`no_std`)

CleitonQ compiles on Cortex-M4F and higher without the standard library:

```toml
[dependencies]
cleitonq = { version = "0.2", default-features = false, features = ["alloc"] }
```

The `alloc` feature enables heap allocation (required for ML-KEM/ML-DSA key material). Tested on Cortex-M4F via QEMU in CI; physical target: STM32F4, NuttX (PX4), Pixhawk 4.

---

## Technical paper

> Bezerra, C. A. C. (2026). *Post-Quantum Authentication for MAVLink v2: A Relay-Transparent Wire Format Using ML-KEM-1024 and ML-DSA-87*. Zenodo.
> [https://doi.org/10.5281/zenodo.20776349](https://doi.org/10.5281/zenodo.20776349)

IETF Internet-Draft: [draft-bezerra-relay-auth-transparency-00](https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/)  
**Blog:** [cleitonaugusto.github.io](https://cleitonaugusto.github.io)  
**dev.to:** [Nonce Design for Safety-Critical Systems](https://dev.to/cleiton_augusto_/nonce-design-for-safety-critical-systems-lessons-from-a-post-quantum-mavlink-protocol-2kmc)

---

## Tools

### `unsign` — does authentication survive the hop?

`tools/unsign` answers one question for a protocol and the relay it runs through: if the sender appends authentication to a message, does the receiver still have it? Usually not, and nothing on the path reports a problem. No attacker is involved — the relay is behaving correctly.

```
./tools/unsign            # list what can be tested
./tools/unsign mavlink    # MAVLink v2 through a MAVLink-aware relay
./tools/unsign ros2       # ROS2 / DDS through a bridge
./tools/unsign mqtt       # MQTT 5.0 through a broker bridging to 3.1.1
```

MQTT is worth running for the contrast: appending past the declared length does **not** get you silently stripped there, because MQTT rides a TCP stream and the leftover bytes desynchronise it loudly. The silent failure is elsewhere — an authenticator in an MQTT 5 User Property is dropped when a broker bridges to MQTT 3.1.1, which has no property field at all. Same class, different road, and it shows the silence is a property of the transport rather than of the authentication scheme.

`unsign mqtt --broker HOST:PORT` asks a real broker instead of the model, which is how the model's mistakes were found: MQTT 5 User Properties carry UTF-8 strings, so a raw binary tag cannot go in one at all, and whether an appended tag is rejected loudly or silently stalls the connection depends on the tag's own first bytes. Verified against mosquitto 2.1.2.

Zero dependencies, Python 3.6+, runs in about 30 seconds. Both adapters include a built-in relay simulator; `unsign mavlink --real-relay` drives a live MAVProxy instead, and `unsign ros2` uses real rclpy when it is available.

Each adapter also runs standalone: [tools/unsign_mavlink.py](tools/unsign_mavlink.py), [tools/unsign_ros2.py](tools/unsign_ros2.py), [tools/unsign_mqtt.py](tools/unsign_mqtt.py).

### Wireshark dissector

`tools/wireshark/cleitonq_chunk.lua` — Lua dissector for CLEITONQ_CHUNK (msg_id 50000). Decodes all fields, tracks chunk reassembly, and marks completed payloads with `[COMPLETE]`.

```bash
cp tools/wireshark/cleitonq_chunk.lua ~/.config/wireshark/plugins/
python3 tools/wireshark/gen_cleitonq_pcap.py
wireshark cleitonq_demo.pcap
```

Display filters: `cleitonq`, `cleitonq.frame_type == 0` (SIGNED_CMD), `cleitonq.frame_type == 1` (SESSION_INIT).

---

## Python bindings

PyO3-based bindings in `cleitonq-python/` expose all layers with a Pythonic API. Build with [maturin](https://github.com/PyO3/maturin):

```bash
cd cleitonq-python && maturin develop
python3 tests/test_basic.py   # 7 tests
```

---

## Module structure

| Module | Contents |
|---|---|
| `cleitonq::kem` | ML-KEM-1024 key generation, encapsulation, decapsulation (FIPS 203) |
| `cleitonq::dsa` | ML-DSA-87 signing key, verifying key, sign/verify (FIPS 204) |
| `cleitonq::channel` | `AuthChannel` — HMAC-SHA3-256 with domain separation (FIPS 202) |
| `cleitonq::sealed` | `SealedChannel` — ChaCha20-Poly1305 AEAD encrypt+authenticate (RFC 8439) |
| `cleitonq::fips205` | `RevocationSigner` / `RevocationVerifier` — SLH-DSA-SHA2-128s (FIPS 205) |
| `cleitonq::hybrid` | X25519 + ML-KEM-1024 hybrid key establishment (NIST SP 800-227) |
| `cleitonq::rotation` | Key rotation, `KeyRegistry`, `RotatingSigningKey` |
| `cleitonq::nonce` | Atomic and simple nonce trackers |
| `cleitonq::hsm` | PKCS#11 (SoftHSM2 / YubiHSM2) and TPM2 signing backends |
| `cleitonq::prelude` | Re-exports of the most common types |

---

## Compliance

CleitonQ is designed with the following standards in scope:

| Standard | Applicability |
|---|---|
| NIST FIPS 203/204/205 | Algorithm conformance (ML-KEM, ML-DSA, SLH-DSA) |
| NSA CNSA 2.0 | Key establishment + signing algorithm requirements |
| STANAG 4609 | UAV C2 security (NATO) |
| DO-326A / ED-202A | Avionics cybersecurity (FAA/EASA) |
| NIST SP 800-213 | IoT device cybersecurity |
| MIL-STD-882E | System safety (authentication failure modes) |

---

## Security considerations

- **Never reuse a counter.** Use an atomic `u64` counter, one per channel direction.
- **Rotate ML-KEM sessions periodically.** Forward secrecy protects past sessions, but use short lifetimes in high-threat environments.
- **The ML-DSA-87 signing key is your master secret.** Store it in a hardware security module (HSM) or at minimum a secrets manager. Never put it on the drone.
- **Domain separation is enforced cryptographically.** A key derived for the C2 channel cannot authenticate a telemetry packet. Don't bypass it.
- **SLH-DSA is slow (~10–100 ms to sign).** Use only for infrequent, long-lived operations (revocation, root CA). For per-packet work, use HMAC or ML-DSA.
- **Security properties were formally verified** using ProVerif (5 properties) and Tamarin Prover (5 lemmas, all VERIFIED). Proof artifacts available upon request.

---

## License

MIT OR Apache-2.0

---

*CleitonQ — quantum-resistant authentication for autonomous systems that will still be flying when quantum computers arrive.*
