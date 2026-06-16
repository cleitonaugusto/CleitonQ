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

## Known gaps (not yet resolved)

- **No ARM/embedded benchmarks.** All numbers in `README.md` are x86_64
  desktop measurements. Flight-computer-class hardware (e.g. Raspberry Pi
  5 / Cortex-A76, STM32) has not been benchmarked.
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
