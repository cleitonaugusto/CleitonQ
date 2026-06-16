<!--
  RASCUNHO — não publicado ainda. Abrir manualmente em:
  https://github.com/mavlink/mavlink/issues/new
  (ou via `gh issue create --repo mavlink/mavlink` depois de revisar)

  Pendências antes de publicar:
  - [ ] números de hardware ARM real (Raspberry Pi 5 ou similar) — hoje só
        temos x86-64 desktop
  - [ ] revisão final do texto pelo Cleiton
-->

## Title

Post-quantum authenticated COMMAND_LONG / SET_POSITION_TARGET — does MAVLink have a PQC roadmap?

## Body

NIST finalized ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in August 2024. MAVLink's
current signing scheme (`MAVLink 2 message signing`, SHA-256 HMAC keyed by a
pre-shared 256-bit key) is symmetric-only — it has no asymmetric authentication
or session-establishment story, and nothing here is broken by a quantum
adversary today. But any future asymmetric extension (or any TLS/X25519-based
transport wrapper someone bolts on) would need post-quantum primitives to stay
useful past the "harvest now, decrypt later" horizon that NIST and NSA CNSA 2.0
guidance are already planning around for government/defense procurement.

I built a small reference implementation — [CleitonQ](https://github.com/cleitonaugusto/CleitonQ)
— that wraps MAVLink v2 frames (`COMMAND_LONG`, `SET_POSITION_TARGET_LOCAL_NED`,
tested against the official `mavlink` / rust-mavlink crate's real wire format)
with:

- **ML-KEM-1024** (FIPS 203) for forward-secret session key establishment
- **ML-DSA-87** (FIPS 204) for command signing / non-repudiation
- **HMAC-SHA3-256** for low-overhead per-packet auth on high-rate telemetry

Measured on x86-64 (release build, Criterion, median of 100 samples):

| Operation | Latency |
|---|---|
| ML-KEM-1024 encapsulate | 95.5 µs |
| ML-KEM-1024 decapsulate | 125.6 µs |
| ML-DSA-87 sign (256B payload) | 455.3 µs |
| ML-DSA-87 verify (256B payload) | 115.9 µs |
| Full session establishment | 304.6 µs |

Per-packet overhead is the dominant cost: an ML-DSA-87 signature adds 4627
bytes per signed command, which is fine for low-rate C2 (arm/disarm, waypoints)
but not for 50–100 Hz telemetry — that's what the HMAC-SHA3-256 layer is for
(40-byte overhead, ~2.5 µs sign/verify).

I don't have ARM benchmarks yet (no Cortex-A class hardware on hand right now),
which matters a lot here since most autopilots run on exactly that class of
chip — I'll follow up with those once I do.

Questions for the maintainers:

1. Is there any existing discussion or design doc about a PQC extension to
   MAVLink's signing scheme? I couldn't find one searching issues/discussions.
2. Would a formal proposal (extension spec + reference implementation +
   embedded-hardware benchmarks) be something this repo would want to track,
   or is this better suited as a third-party extension that dialects can
   opt into?
3. Is there interest in an asymmetric (KEM + signature) layer at all, or is
   the expectation that PQC concerns get pushed down to the transport
   (DTLS 1.3 with a PQC group, etc.) rather than the MAVLink layer itself?

Happy to write this up properly (threat model, protocol design, full
benchmark suite including ARM once I have the hardware) if there's interest.
