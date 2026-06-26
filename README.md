# CleitonQ

**Post-quantum authenticated C2 protocol for MAVLink v2.**

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

CleitonQ is a post-quantum authenticated C2 protocol for MAVLink v2. It fixes a class of relay-stripping vulnerabilities (CVE-YYYY-NNNNN / [GHSA-f5rj-mrxh-r7vm](https://github.com/cleitonaugusto/CleitonQ/security/advisories/GHSA-f5rj-mrxh-r7vm)) that affects **every authentication scheme appended outside the MAVLink frame boundary**, and provides FIPS 203/204/205 quantum-resistant authentication suitable for BVLOS commercial and public-safety drone operations.

---

## The vulnerability

Any authentication scheme that appends bytes *after* the MAVLink v2 frame CRC is silently stripped by any compliant relay — MAVProxy, mavlink-router, QGroundControl all exhibit this behavior.

Root cause: the MAVLink v2 spec defines frame length as exactly `10 + LEN + 2` bytes. A compliant parser reads that many bytes and stops. Appended bytes are discarded. The downstream receiver gets a valid, unauthenticated frame with no indication that authentication was removed.

**This affects the MAVLink v2 optional signing field (RFC #196) in any deployment with a relay in the path**, and any "append-after-CRC" authentication scheme regardless of algorithm.

```
PoC (no drone required):
python3 tools/mavproxy_relay_strip_poc.py
```

Full advisory: [GHSA-f5rj-mrxh-r7vm](https://github.com/cleitonaugusto/CleitonQ/security/advisories/GHSA-f5rj-mrxh-r7vm)

---

## The fix

`CLEITONQ_CHUNK` (MSG_ID 50000, `INCOMPAT_FLAGS=0x00`) — a first-class MAVLink dialect message that carries authentication material as fragmented native frames. Any relay forwards chunks as valid, opaque messages whether or not it knows the CleitonQ dialect. Authentication survives every relay hop.

---

## What it provides

| Layer | Algorithm | Standard | Purpose |
|---|---|---|---|
| Session establishment | ML-KEM-1024 | FIPS 203 | Forward-secret key exchange |
| Command signing | ML-DSA-87 | FIPS 204 | Non-repudiation, quantum-resistant |
| Command encryption | ChaCha20-Poly1305 | RFC 8439 | Payload confidentiality + AEAD |
| Per-packet authentication | HMAC-SHA3-256 | FIPS 202 | 100 Hz telemetry, 40-byte overhead |
| Revocation certificates | SLH-DSA-SHA2-128s | FIPS 205 | Hash-only assumptions, 20-year validity |

### Security properties

- **Quantum resistance** — ML-KEM and ML-DSA are secure against Shor's algorithm
- **Forward secrecy** — each ML-KEM session is independent; past sessions are safe if the long-term key is later compromised
- **Non-repudiation** — ML-DSA-87 signatures prove a command came from the authorised ground station
- **Payload confidentiality** — ChaCha20-Poly1305 encrypts C2 commands; relays see only opaque ciphertext
- **Anti-replay** — monotonically-increasing per-packet counters, enforced in constant time
- **Domain separation** — one session key produces independent sub-keys per channel (C2, telemetry, mesh) via SHA3-256 salts; a mesh key cannot authenticate a C2 packet
- **Defense in depth** — SLH-DSA revocation certs require only hash security; if lattice hardness is ever questioned, revocations remain valid

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

### Per-packet HMAC channel (telemetry, 100 Hz)

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
| HMAC-SHA3-256 sign | 2.50 µs | 1.10 µs | Per packet at 100 Hz |
| HMAC-SHA3-256 verify | 2.37 µs | 1.12 µs | Per packet at 100 Hz |
| Full session establishment | 304.6 µs | 241.1 µs | Encap + decap + channel init |

**At 100 Hz, the per-packet authentication overhead is negligible (<0.03% of cycle budget) on both architectures.**
ML-DSA-87 is used for high-value commands (waypoints, arm/disarm), not every telemetry packet.

### Packet overhead

| Layer | Overhead |
|---|---|
| ChaCha20-Poly1305 (SealedChannel) | 24 bytes (8 counter + 16 tag) |
| HMAC-SHA3-256 channel | 40 bytes (8 nonce + 32 tag) |
| ML-DSA-87 signed command | 4635 bytes (8 nonce + 4627 sig) |
| ML-KEM-1024 ciphertext (one-time) | 1568 bytes |

---

## MAVLink integration

CleitonQ wraps MAVLink payloads without modifying the MAVLink framing.
Authentication material travels as `CLEITONQ_CHUNK` (MSG_ID 50000) — a first-class dialect message that survives any MAVProxy / mavlink-router relay hop.

A formal MAVLink RFC was submitted in June 2026 — see [Issue #2527](https://github.com/mavlink/mavlink/issues/2527) and [PR #2528](https://github.com/mavlink/mavlink/pull/2528). Wire format spec and dialect XML in [rfc/](rfc/).

The companion-computer proxy architecture (no firmware changes needed) enables deployment on any ArduPilot or PX4 vehicle with a Jetson or RPi4+ companion computer.

---

## Technical paper

> Bezerra, C. A. C. (2026). *Post-Quantum Authentication for MAVLink v2: A Relay-Transparent Wire Format Using ML-KEM-1024 and ML-DSA-87*. Zenodo.
> [https://doi.org/10.5281/zenodo.20776349](https://doi.org/10.5281/zenodo.20776349)

The paper covers the relay-stripping vulnerability, the CLEITONQ_CHUNK wire format design, security properties, and benchmark methodology.

**Blog:** [cleitonaugusto.github.io](https://cleitonaugusto.github.io) — technical posts on design decisions, formal verification, and protocol analysis.

**dev.to:** [Nonce Design for Safety-Critical Systems](https://dev.to/cleiton_augusto_/nonce-design-for-safety-critical-systems-lessons-from-a-post-quantum-mavlink-protocol-2kmc)

---

## Tools

### Relay-stripping proof of concept

`tools/mavproxy_relay_strip_poc.py` — zero-dependency Python 3.6+ script demonstrating how MAVLink-aware relays silently discard authentication bytes appended after a frame. Includes a built-in relay simulator and optional live MAVProxy mode.

```
python3 tools/mavproxy_relay_strip_poc.py
```

### Wireshark dissector

`tools/wireshark/cleitonq_chunk.lua` — Lua dissector for CLEITONQ_CHUNK (msg_id 50000). Decodes all fields, tracks chunk reassembly, and marks completed payloads with `[COMPLETE]`.

```
# Linux/Mac
cp tools/wireshark/cleitonq_chunk.lua ~/.config/wireshark/plugins/

# Generate demo .pcap without hardware
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
| `cleitonq::hybrid` | X25519 + ML-KEM-1024 hybrid key establishment |
| `cleitonq::rotation` | Key rotation, `KeyRegistry`, `RotatingSigningKey` |
| `cleitonq::nonce` | Atomic and simple nonce trackers |
| `cleitonq::hsm` | PKCS#11 (SoftHSM2 / YubiHSM2) and TPM2 signing backends |
| `cleitonq::prelude` | Re-exports of the most common types |

---

## Security considerations

- **Never reuse a counter.** Use an atomic `u64` counter, one per channel direction.
- **Rotate ML-KEM sessions periodically.** Forward secrecy protects past sessions, but use short lifetimes in high-threat environments.
- **The ML-DSA-87 signing key is your master secret.** Store it in a hardware security module (HSM) or at minimum a secrets manager. Never put it on the drone.
- **Domain separation is enforced cryptographically.** A key derived for the C2 channel cannot authenticate a telemetry packet — the SHA3-256 salt is different. Don't bypass it.
- **SLH-DSA is slow.** ~10-100 ms to sign. Use only for infrequent, long-lived operations (revocation, root CA). For per-packet work, use HMAC or ML-DSA.

---

## License

MIT OR Apache-2.0

---

*CleitonQ — securing autonomous systems before the quantum threat arrives.*
