# Security

CleitonQ is pre-1.0 and has not had a third-party security audit. This
document states what has been tested, what hasn't, and what an integrator
should know before relying on it.

## What's tested

- **Functional correctness**: sign/verify roundtrips, replay rejection,
  tamper rejection, domain separation, wrong-key rejection
  (`cargo test --workspace`).
- **Fuzzing**: both verifiers (`channel::AuthChannel::verify`,
  `dsa::VerifyingKey::verify`) are fuzzed with `cargo-fuzz` against
  arbitrary attacker-controlled bytes (`fuzz/fuzz_targets/`). No crashes
  found across millions of executions as of the last run; this is not a
  one-time guarantee — re-run before any release.
- **Active MITM scenarios** (`tests/mitm_active.rs`): ciphertext
  substitution across sessions, cross-session replay, signature splicing
  across two valid packets.
- **Resource exhaustion** (`tests/dos_stress.rs`): malformed packets in
  volume, oversized packets (tens of MiB), and floods of correctly-sized
  forged ML-DSA packets — verified to reject in bounded time without
  panicking.
- **Real socket round-trip** (`examples/mavlink_udp_link.rs`): signed
  MAVLink v2 frames sent over an actual `UdpSocket` (not just in-memory
  byte arrays), including replay and tamper rejection across the socket
  boundary. This caught a real bug during development: a receive buffer
  sized at 4096 bytes silently truncated packets, since an ML-DSA-87
  signature alone is 4627 bytes — fixed by sizing the buffer against
  `dsa::OVERHEAD`. Any integration using a fixed-size UDP receive buffer
  must size it to fit `dsa::OVERHEAD` (or `channel::OVERHEAD`) plus the
  largest expected payload.

## Known architecture limitation: doesn't survive MAVLink-aware relays

Tested against MAVProxy (acting as a UDP-to-UDP relay): a MAVLink v2
frame with extra trailing bytes appended (standing in for CleitonQ's
`nonce + signature` suffix) was received intact by MAVProxy but
**re-serialized and forwarded without the trailing bytes** — MAVProxy
parses discrete MAVLink messages and forwards exactly the recognized
frame, silently dropping anything appended after it.

This means the current wire format — sign the serialized MAVLink frame,
append `nonce + signature` after it — **only works over a direct,
unrouted link** (point-to-point UDP/serial, no intermediary). It does
**not** survive any topology with a MAVLink-aware hop in between:
MAVProxy, `mavlink-router`, QGroundControl acting as a relay, or any GCS
that re-serializes messages instead of passing raw bytes through.

This is an architecture constraint, not a bug to patch — fixing it
requires a redesign of the wire format so that the authenticated payload
is treated as a first-class MAVLink construct rather than opaque trailing
bytes, allowing relay hops to forward it intact. The proposed wire format
(`CLEITONQ_SIGNED_CMD`, `CLEITONQ_SESSION_INIT`) is described in the
technical paper (preprint, June 2026 — https://doi.org/10.5281/zenodo.20776349) and will be the basis
of a formal MAVLink RFC. Most real deployments route through exactly this
kind of middleware, so this must be resolved before any standardization
effort.

## Known gaps (not yet resolved)

- **ARM benchmarks are server-class, not embedded-class.** `README.md` has
  numbers from a native ARM64 GitHub Actions runner (Neoverse-N2, via
  `.github/workflows/arm-bench.yml`) — real ARM silicon, not emulated, but
  a server/cloud core, not a flight-computer-class chip. Cortex-A76
  (Raspberry Pi 5) or STM32-class microcontroller numbers are still open.
- **No `no_std` support.** Current API requires `std` (file I/O for key
  storage, heap allocation). Microcontroller targets are not supported yet.
- **No HSM integration.** The ML-DSA-87 signing key lives in process
  memory; there's no support for keeping it in a hardware security module.
- **No formal/external audit.** Nothing here has been reviewed by anyone
  outside the author. Treat all of the above as self-reported, not
  independently verified.
- **Key compromise response is local-registry-based, not broadcast.**
  `rotation::KeyRegistry` lets a drone trust multiple signing keys and
  revoke one locally, but there's no signed revocation message — an
  operator must push the updated registry to every drone out-of-band.
  A cryptographically authenticated revocation broadcast is future work.

## Reporting a vulnerability

Open an issue or contact the author directly (see `Cargo.toml`). There is
no bug bounty at this stage.
