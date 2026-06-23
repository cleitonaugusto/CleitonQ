# CleitonQ

**Post-quantum authenticated command & control for embedded and autonomous systems.**

*by Cleiton Augusto Correa Bezerra*

[![Crates.io](https://img.shields.io/crates/v/cleitonq.svg)](https://crates.io/crates/cleitonq)
[![Docs.rs](https://docs.rs/cleitonq/badge.svg)](https://docs.rs/cleitonq)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]()
[![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM--1024-blueviolet.svg)]()
[![FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20ML--DSA--87-blueviolet.svg)]()
[![ARM64 CI](https://github.com/cleitonaugusto/CleitonQ/actions/workflows/arm-bench.yml/badge.svg)](https://github.com/cleitonaugusto/CleitonQ/actions/workflows/arm-bench.yml)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20776349.svg)](https://doi.org/10.5281/zenodo.20776349)
[![Blog](https://img.shields.io/badge/blog-cleitonaugusto.github.io-informational.svg)](https://cleitonaugusto.github.io)

---

## The problem

Current drone communication protocols — MAVLink, DroneCAN, proprietary C2 links — use
classical cryptography (ECDSA, X25519, AES-GCM) that a sufficiently powerful quantum
computer breaks in polynomial time via Shor's algorithm.

NIST finalised post-quantum standards in August 2024 (FIPS 203/204). Defence agencies
are writing migration mandates for 2026–2027. **No open-source MAVLink implementation
has PQC yet.**

CleitonQ is the reference implementation.

---

## What it does

CleitonQ secures the C2 channel between a ground station and one or more autonomous
systems using three complementary mechanisms:

| Layer | Algorithm | Standard | Protects against |
|---|---|---|---|
| Session establishment | ML-KEM-1024 | FIPS 203 | Key compromise + quantum decryption |
| Command signing | ML-DSA-87 | FIPS 204 | Forged commands + quantum forgery |
| Per-packet authentication | HMAC-SHA3-256 | FIPS 202 | Replay + tampering (low overhead) |

### Security properties

- **Quantum resistance** — ML-KEM and ML-DSA are secure against Shor's algorithm
- **Forward secrecy** — each ML-KEM session is independent; past sessions are safe even if the long-term key is later compromised
- **Non-repudiation** — ML-DSA-87 signatures prove a command came from the authorised ground station
- **Anti-replay** — monotonically-increasing per-packet nonces, enforced in constant time
- **Domain separation** — one session key produces independent sub-keys per channel (C2, telemetry, mesh) via SHA3-256 salts; a mesh key cannot authenticate a C2 packet

---

## Quick start

```toml
[dependencies]
cleitonq = "0.2"
```

### Symmetric channel (ML-KEM session + HMAC)

```rust
use cleitonq::prelude::*;

// Ground station: establish a forward-secret session
let (ciphertext, session_key) = kem::encapsulate("drone_kem_ek.bin")?;
// send `ciphertext` to the drone over any channel — it reveals nothing

let c2_tx = AuthChannel::new(&session_key, ChannelDomain::C2);
let packet = c2_tx.sign(b"thrust=9.81 roll=0.0", 1);

// Drone: recover the session key and verify
let dk = kem::KemKeyPair::load_decapsulation_key("drone_kem_dk.bin")?;
let session_key = kem::decapsulate(&dk, &ciphertext)?;
let c2_rx = AuthChannel::new(&session_key, ChannelDomain::C2);
let (payload, nonce) = c2_rx.verify(&packet, 0).expect("authenticated");
```

### Command signing with non-repudiation (ML-DSA-87)

```rust
use cleitonq::dsa::{SigningKey, VerifyingKey};

// Ground station: sign a command
let sk = SigningKey::load("gs_signing.bin")?;
let packet = sk.sign(b"waypoint=100.0,80.0,50.0", seq_number);

// Drone: verify with the ground station's public key
let vk = VerifyingKey::load("gs_verifying.bin")?;
let (payload, nonce) = vk.verify(&packet, last_nonce).expect("valid command");
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

Measured with Criterion (median of 100 samples, release build). Run
`cargo bench` to reproduce. ARM64 numbers are from a native
`ubuntu-24.04-arm` GitHub Actions runner (Neoverse-N2) — a server-class
ARM core, not yet a Cortex-A-class embedded flight computer (e.g.
Raspberry Pi 5); that comparison is still open, see
[ROADMAP.md](ROADMAP.md).

| Operation | x86-64 (Intel Core i5) | ARM64 (Neoverse-N2) | Notes |
|---|---|---|---|
| ML-KEM-1024 keygen | 100.2 µs | 77.1 µs | One-time at provisioning |
| ML-KEM-1024 encapsulate | 95.5 µs | 70.5 µs | One-time per session |
| ML-KEM-1024 decapsulate | 125.6 µs | 84.3 µs | One-time per session |
| ML-DSA-87 sign (30B payload) | 455.3 µs | 962.0 µs | Per signed command — O(1) in payload size |
| ML-DSA-87 verify (30B payload) | 115.9 µs | 85.3 µs | Per received command — O(1) in payload size |
| HMAC-SHA3-256 sign | 2.50 µs | 1.10 µs | Per packet at 100 Hz |
| HMAC-SHA3-256 verify | 2.37 µs | 1.12 µs | Per packet at 100 Hz |
| Full session establishment | 304.6 µs | 241.1 µs | Encap + decap + channel init |

**At 100 Hz, the per-packet HMAC overhead is negligible (<0.03% of cycle budget) on both architectures.**
ML-DSA-87 is used for high-value commands (waypoints, arm/disarm), not every telemetry packet.

### Packet overhead

| Layer | Overhead |
|---|---|
| HMAC-SHA3-256 channel | 40 bytes (8 nonce + 32 tag) |
| ML-DSA-87 signed command | 4635 bytes (8 nonce + 4627 sig) |
| ML-KEM-1024 ciphertext (one-time) | 1568 bytes |

---

## MAVLink integration

CleitonQ is designed to wrap MAVLink payloads without modifying the MAVLink framing.
A signed COMMAND_LONG v2 frame (44 bytes: 10B header + 30B payload + 2B CRC + 2B alignment)
becomes a 4679-byte authenticated packet — large but acceptable for the infrequent
high-value commands that justify non-repudiation.

For telemetry streams (100 Hz+), use the HMAC channel with 40 bytes overhead.

A formal MAVLink RFC was submitted in June 2026 — see [Issue #2527](https://github.com/mavlink/mavlink/issues/2527) and [PR #2528](https://github.com/mavlink/mavlink/pull/2528). Wire format spec and dialect XML in [rfc/](rfc/).

---

## Technical paper

> Bezerra, C. A. C. (2026). *Post-Quantum Authentication for MAVLink v2: A Relay-Transparent Wire Format Using ML-KEM-1024 and ML-DSA-87*. Zenodo.
> [https://doi.org/10.5281/zenodo.20776349](https://doi.org/10.5281/zenodo.20776349)

The paper covers the relay-stripping problem, the CLEITONQ_CHUNK wire format design, security properties, and benchmark methodology.

**Blog:** [cleitonaugusto.github.io](https://cleitonaugusto.github.io) — technical posts on design decisions, formal verification, and protocol analysis.

---

## Tools

### Relay-stripping proof of concept

`tools/mavproxy_relay_strip_poc.py` — a zero-dependency Python 3.6+ script that demonstrates
how MAVLink-aware relays (MAVProxy, mavlink-router, QGC) silently discard authentication bytes
appended after a MAVLink frame. Includes a built-in relay simulator and optional live MAVProxy mode.

```
python3 tools/mavproxy_relay_strip_poc.py
```

### Wireshark dissector

`tools/wireshark/cleitonq_chunk.lua` — Lua dissector for CLEITONQ_CHUNK (msg_id 50000).
Decodes all fields, tracks chunk reassembly across packets, and marks completed payloads
with `[COMPLETE]` in the packet list. Install by copying to your Wireshark plugins directory:

- Linux/Mac: `~/.config/wireshark/plugins/`
- Windows: `%APPDATA%\Wireshark\plugins\`

Then reload plugins: **Analyze → Reload Lua Plugins** (Ctrl+Shift+L).

A demo `.pcap` with two reassembly scenarios can be generated without hardware:

```
python3 tools/wireshark/gen_cleitonq_pcap.py   # writes cleitonq_demo.pcap
wireshark cleitonq_demo.pcap
```

Display filters: `cleitonq`, `cleitonq.frame_type == 0` (SIGNED_CMD), `cleitonq.frame_type == 1` (SESSION_INIT).

---

## Python bindings

PyO3-based bindings are available in `cleitonq-python/`. All three layers (KEM, DSA, HMAC channel)
are exposed with a Pythonic API. Build with [maturin](https://github.com/PyO3/maturin):

```bash
cd cleitonq-python && maturin develop
python3 tests/test_basic.py   # 7 tests
```

---

## Module structure

| Module | Contents |
|---|---|
| `cleitonq::kem` | ML-KEM-1024 key generation, encapsulation, decapsulation |
| `cleitonq::dsa` | ML-DSA-87 signing key, verifying key, sign/verify |
| `cleitonq::channel` | `AuthChannel` — HMAC-SHA3-256 with domain separation |
| `cleitonq::prelude` | Re-exports of the most common types |

---

## Security considerations

- **Never reuse a nonce.** Use an atomic counter or a cryptographic sequence number.
- **Rotate ML-KEM sessions periodically.** A session key established today has forward
  secrecy, but use short session lifetimes in high-threat environments.
- **The ML-DSA-87 signing key is your master secret.** Store it in a hardware security
  module (HSM) or at minimum a secrets manager. Never put it on the drone.
- **This library does not provide confidentiality** — payloads are authenticated but not
  encrypted. Add AES-256-GCM or ChaCha20-Poly1305 if payload confidentiality is required.
  Encryption support is planned for v0.3 — see [ROADMAP.md](ROADMAP.md).

---

## License

MIT OR Apache-2.0

---

*CleitonQ — Securing autonomous systems before the quantum threat arrives.*
