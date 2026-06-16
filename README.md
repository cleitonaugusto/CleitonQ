# CleitonQ

**Post-quantum authenticated command & control for embedded and autonomous systems.**

*by Cleiton Augusto Correa Bezerra*

[![Crates.io](https://img.shields.io/crates/v/cleitonq.svg)](https://crates.io/crates/cleitonq)
[![Docs.rs](https://docs.rs/cleitonq/badge.svg)](https://docs.rs/cleitonq)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)]()
[![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM--1024-blueviolet.svg)]()
[![FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20ML--DSA--87-blueviolet.svg)]()

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
cleitonq = "0.1"
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

```bash
# Generate ML-KEM key pair for the drone
cargo run --example keygen -- --out pq_keys/

# The drone stores: pq_keys/drone_kem_dk.bin (PRIVATE)
# The ground station gets: pq_keys/drone_kem_ek.bin (public)
# The ground station stores: pq_keys/gs_signing.bin (PRIVATE)
# The drone gets: pq_keys/gs_verifying.bin (public)
```

---

## Performance

Measured on x86-64 (Intel Core i5, release build). ARM benchmarks (Raspberry Pi 5)
coming in v0.2 — see [ROADMAP.md](ROADMAP.md).

| Operation | Latency | Notes |
|---|---|---|
| ML-KEM-1024 keygen | 100.2 µs | One-time at provisioning |
| ML-KEM-1024 encapsulate | 95.5 µs | One-time per session |
| ML-KEM-1024 decapsulate | 125.6 µs | One-time per session |
| ML-DSA-87 sign (40B) | 1.23 ms | Per signed command |
| ML-DSA-87 verify (40B) | 121.5 µs | Per received command |
| ML-DSA-87 sign (256B) | 455.3 µs | Per signed command (MAVLink-sized) |
| ML-DSA-87 verify (256B) | 115.9 µs | Per received command |
| HMAC-SHA3-256 sign | 2.50 µs | Per packet at 100 Hz |
| HMAC-SHA3-256 verify | 2.37 µs | Per packet at 100 Hz |
| Full session establishment | 304.6 µs | Encap + decap + channel init |

*(Median of 100 samples, Criterion. Run `cargo bench` to reproduce.)*

**At 100 Hz, the per-packet HMAC overhead is negligible (<0.03% of cycle budget).**
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
A signed COMMAND_LONG (28 bytes) becomes a 4663-byte authenticated packet — large but
acceptable for the infrequent high-value commands that justify non-repudiation.

For telemetry streams (100 Hz+), use the HMAC channel with 40 bytes overhead.

A formal MAVLink extension proposal (RFC) is planned for Q3 2025 — see [ROADMAP.md](ROADMAP.md).

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
