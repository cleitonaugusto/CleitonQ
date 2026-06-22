# Changelog

All notable changes to CleitonQ are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-06-22

### Security fixes

- **CRITICAL** — `AtomicNonce::next()` previously used `fetch_add` which wraps
  silently at `u64::MAX`, allowing nonce rollover to 0. Replaced with a
  compare-exchange saturating increment: a saturated nonce is rejected by
  receivers as replay rather than silently accepted (`src/nonce.rs`).
- **HIGH** — `SigningKey::save()` and `KemKeyPair::save()` wrote private key
  material with default permissions (0644, world-readable on Unix). Both now
  use `OpenOptions::mode(0o600)` via a dedicated `write_secret_file()` helper
  (`src/dsa.rs`, `src/kem.rs`).

### Added

- **Wireshark dissector** (`tools/wireshark/cleitonq_chunk.lua`) — Lua plugin
  for CLEITONQ_CHUNK (msg_id 50000). Decodes all wire fields, tracks chunk
  reassembly across packets, and marks complete payloads with `[COMPLETE]`
  in the packet list. Hooks into the MAVLink plugin DissectorTable when
  present; falls back to a standalone UDP scanner on ports 14550/14551/
  14552/14580.
- **pcap generator** (`tools/wireshark/gen_cleitonq_pcap.py`) — generates a
  demo capture with two scenarios (7-chunk SESSION_INIT + 20-chunk SIGNED_CMD)
  without requiring physical hardware or a live MAVLink stack.
- **NIST API-layer determinism tests** (`src/dsa.rs`) — four tests verifying
  that the wrapper around `ml-dsa` does not permute seed bytes or corrupt
  wire format: `keygen_from_seed_is_deterministic`, `known_vk_prefix_for_fixed_seed`,
  `sign_verify_nonce_strictly_enforced`, `wire_format_length_is_predictable`.
- **MAVLink RFC** — formal RFC submitted to mavlink/mavlink (issue #2527,
  PR #2528) with dialect XML `rfc/cleitonq.xml` validated against mavgen
  for Python, C, C++11, C#, WLua, and Java targets.

### Changed

- Benchmark table corrected: ML-DSA-87 sign on ARM64 (Neoverse-N2) is
  **962 µs** for a 30-byte payload, not 509 µs (which applies to 256-byte
  payloads). All benchmark numbers are now CI-verified via the
  `ubuntu-24.04-arm` GitHub Actions runner with full Criterion artifact.
- `nonce.rs` module expanded: `SimpleNonce` and `SimpleNonceTracker` added
  for `no_std` targets without 64-bit atomic support (Cortex-M4).
- API-layer documentation updated throughout `dsa.rs` and `kem.rs` to
  clarify private key file format and seed sizes.

### Infrastructure

- ARM64 benchmark CI workflow (`.github/workflows/arm-bench.yml`) runs on
  `ubuntu-24.04-arm` (Neoverse-N2 native runner) and archives full Criterion
  output + `lscpu` as a downloadable artifact on every push.
- 35 unit/integration tests passing (up from 21 in 0.1.0).
- DoS stress tests and active-MITM tests cover: 10K malformed packets,
  16 MiB hostile payload, MITM ciphertext substitution, signature splicing,
  and cross-session replay.

---

## [0.1.1] — 2026-06-10

### Fixed

- Benchmark compile error: missing `ml_kem::Kem` import in `benches/pqc_bench.rs`.
- `kem.rs`: resolved `AsRef` ambiguity in tests and doctests.
- Test isolation: all file-I/O roundtrip tests now use process-ID-scoped
  temp paths to prevent conflicts under parallel `cargo test`.

### Added

- `KemKeyPair::dk_seed_bytes()` and `ek_bytes()` — in-memory accessors
  that avoid the temp-file pattern required by the earlier file-only API.
- `SigningKey::from_seed_bytes()` and `to_seed_bytes()` — same pattern for DSA.
- ROS2/DDS bridge auth-stripping PoC (`tools/ros2_bridge_strip_poc.py`).
- MAVLink relay auth-stripping PoC (`tools/mavproxy_relay_strip_poc.py`).
- `no_std + alloc` support: all core modules compile without `std` for
  Cortex-M4 / STM32 / Pixhawk targets.

---

## [0.1.0] — 2026-05-28

Initial public release.

### Added

- `cleitonq::kem` — ML-KEM-1024 (FIPS 203) session key establishment:
  key generation, encapsulation, decapsulation, file save/load.
- `cleitonq::dsa` — ML-DSA-87 (FIPS 204) command signing:
  key generation, sign, verify, file save/load, key rotation.
- `cleitonq::channel` — HMAC-SHA3-256 (FIPS 202) per-packet authentication
  with domain separation (C2 / telemetry / mesh).
- `cleitonq::nonce` — `AtomicNonce` and `NonceTracker` for thread-safe
  nonce management; `SimpleNonce` and `SimpleNonceTracker` for `no_std`.
- `cleitonq::rotation` — `KeyRegistry` and `RotatingSigningKey` for
  zero-downtime key rotation and revocation.
- Python bindings via PyO3 (`cleitonq-python/`): DSA, KEM, and HMAC
  channel exposed with a Pythonic API; built with maturin.
- Fuzzing targets (`fuzz/`) for DSA verify and HMAC channel verify.
- Active-MITM and DoS integration tests (`tests/`).
- GitHub Actions CI: test matrix (stable + beta Rust), ARM64 benchmarks.
