# CLEITONQ-RFC-001: Post-Quantum Authentication for MAVLink v2

**Author:** Cleiton Augusto Correa Bezerra  
**Status:** Draft  
**Reference implementation:** https://github.com/cleitonaugusto/CleitonQ  
**Technical paper:** Preprint June 2026 (Zenodo/TechRxiv — DOI pending upload)

---

## 1. Problem Statement

MAVLink v2 currently authenticates packets using HMAC-SHA256 with a pre-shared key
(MAVLink signing, RFC MAVLink-0001). This mechanism is broken by a sufficiently
powerful quantum computer via Grover's algorithm (halving the effective key length)
and is entirely incompatible with a post-quantum threat model that includes
harvest-now-decrypt-later (HNDL) attacks.

NIST finalised post-quantum standards in August 2024:
- FIPS 203 — ML-KEM (key encapsulation)
- FIPS 204 — ML-DSA (digital signatures)

Defence agencies and critical infrastructure operators are writing PQC migration
mandates for 2026–2027. MAVLink is used in military, government, and critical
infrastructure drone programmes that fall under these mandates.

### 1.1 The relay incompatibility problem

Any attempt to add authentication material by appending bytes after a valid MAVLink
v2 frame is silently defeated by MAVLink-aware relays (MAVProxy, mavlink-router,
QGroundControl acting as proxy). These relays parse each MAVLink frame, re-serialize
it from internal state, and forward exactly the recognized frame — any trailing bytes
are discarded without notice.

This was tested and documented in the CleitonQ reference implementation:

```
GCS → [MAVLink frame][nonce 8B][ML-DSA-87 sig 4627B]
                                        ↓ MAVProxy
Drone ← [MAVLink frame]          ← auth bytes silently stripped
```

Result: the drone receives a syntactically valid, unauthenticated frame and has no
indication that authentication material existed.

This means **no naive PQC signing scheme layered over the current wire format is
deployable in real infrastructure**, which almost universally includes at least one
MAVLink-aware relay hop (MAVProxy, QGC, mavlink-router, companion computer, etc.).

---

## 2. Proposed Solution

Encode PQC authentication material as first-class MAVLink messages so that any
relay — regardless of whether it understands CleitonQ — forwards them as valid
MAVLink frames. Authentication bytes are never appended outside the MAVLink frame
boundary.

### 2.1 New message: CLEITONQ_CHUNK (ID 50000)

A single fragment carrier handles both authentication payload types. Receivers
reassemble the complete payload using `(session_token, frame_type, chunk_seq)`.

```
CLEITONQ_CHUNK wire layout (255 bytes, all fields little-endian):
  target_system   : uint8   (1B)
  target_component: uint8   (1B)
  session_token   : uint16  (2B) — per-payload random reassembly token
  frame_type      : uint8   (1B) — 0=SIGNED_CMD, 1=SESSION_INIT
  chunk_seq       : uint8   (1B) — 0-based fragment index
  chunk_count     : uint8   (1B) — total fragments for this payload
  data_len        : uint8   (1B) — valid bytes in data[] for this chunk
  data            : uint8[245]   — fragment bytes (pad last chunk with zeros)
```

### 2.2 Payload type A: CLEITONQ_SIGNED_CMD

Carries a MAVLink command authenticated with ML-DSA-87 (FIPS 204, security level 5).

```
Reassembled CLEITONQ_SIGNED_CMD (all little-endian):
  original_msg_id  : uint16       (2B) — MAVLink message ID of the authenticated command
  target_system    : uint8        (1B)
  target_component : uint8        (1B)
  nonce            : uint64       (8B) — monotonically increasing anti-replay counter
  payload_len      : uint16       (2B) — length of original MAVLink payload
  payload          : uint8[]           — original MAVLink payload (up to 255B)
  signature        : uint8[4627]       — ML-DSA-87 signature over (payload || nonce LE)

Total: 14 + payload_len + 4627 bytes
For COMMAND_LONG (payload=40B): 4681 bytes → 20 CLEITONQ_CHUNK messages
```

**What is signed:** `SHA3-256(payload || nonce_le_bytes)` as per ML-DSA-87 (FIPS 204 §5.2).  
**Signing key:** long-term ML-DSA-87 key pair held by the authorised GCS.  
**Verification key:** pre-distributed to each drone out-of-band (key provisioning is
out of scope for this RFC).

### 2.3 Payload type B: CLEITONQ_SESSION_INIT

Establishes a forward-secret session key using ML-KEM-1024 (FIPS 203, security level 5).

```
Reassembled CLEITONQ_SESSION_INIT (all little-endian):
  initiator_system : uint8        (1B) — system_id of the initiating GCS
  timestamp        : uint64       (8B) — microseconds since epoch (handshake anti-replay)
  kem_ciphertext   : uint8[1568]        — ML-KEM-1024 ciphertext

Total: 1577 bytes → 7 CLEITONQ_CHUNK messages
```

**Session establishment flow:**
1. Drone generates ML-KEM-1024 key pair; shares public key out-of-band (pre-flight).
2. GCS runs `ML-KEM.Encapsulate(drone_pk)` → `(ciphertext, shared_secret)`.
3. GCS sends `CLEITONQ_SESSION_INIT` (7 chunks) with `kem_ciphertext`.
4. Drone runs `ML-KEM.Decapsulate(drone_sk, ciphertext)` → `shared_secret`.
5. Both derive symmetric channel keys: `SHA3-256(shared_secret || domain_label)`.
6. Subsequent commands use `CLEITONQ_SIGNED_CMD` for non-repudiation, plus
   optional HMAC-SHA3-256 per-packet authentication for high-rate telemetry.

---

## 3. Security Properties

| Property | Mechanism | Quantum-resistant |
|---|---|---|
| Command non-repudiation | ML-DSA-87 (FIPS 204) | Yes — Shor's alg does not apply |
| Forward secrecy | ML-KEM-1024 (FIPS 203) | Yes — Grover halving: 256-bit → 128-bit effective |
| Per-packet integrity | HMAC-SHA3-256 | Partial — Grover reduces to 128-bit |
| Anti-replay | Monotonic nonce (uint64) | N/A — symmetric counter |
| Relay transparency | CLEITONQ_CHUNK framing | N/A — protocol design |

### 3.1 Threat model

- Attacker can read all MAVLink traffic on the link (radio interception).
- Attacker can inject, replay, or modify frames (active MITM).
- Attacker has access to a cryptographically-relevant quantum computer
  (harvest-now-decrypt-later scenario).
- Attacker does NOT have the GCS signing key or drone decapsulation key.
- Relay infrastructure (MAVProxy, mavlink-router) is assumed honest but unmodified
  (no CleitonQ support required).

### 3.2 What this RFC does not protect

- **Confidentiality** — telemetry content is not encrypted. A separate RFC would
  add AES-256-GCM over the established session key.
- **GCS key compromise** — if the ML-DSA-87 signing key is stolen, all signed
  commands from that key are forgeable. Key rotation (`CLEITONQ_KEY_ROTATION`,
  future RFC) and HSM integration are out of scope.
- **DoS** — a jammer can prevent delivery; this RFC provides no availability
  guarantees.

---

## 4. Backward Compatibility

Relays that do not implement CleitonQ treat `CLEITONQ_CHUNK` (ID 50000) as an
unknown message type. MAVLink relay behaviour for unknown IDs:

- **MAVProxy**: forwards unknown messages if `--mavlink-version 2` is set and the
  message ID is not in the active dialect. Default behaviour varies by version.
- **mavlink-router**: forwards all messages that parse as valid MAVLink v2 frames.
- **QGroundControl**: forwards unknown messages when acting as a UDP bridge.

In all tested configurations, `CLEITONQ_CHUNK` frames are forwarded intact because
they are valid MAVLink v2 frames. This is the fundamental design property: **the
authentication material is inside the MAVLink frame boundary, not appended after it**.

Drones that do not implement CleitonQ silently discard unknown message IDs. No
existing MAVLink behaviour is changed.

---

## 5. Performance

Measured on ARM64 Neoverse-N2 (GitHub Actions `ubuntu-24.04-arm`), release build,
Criterion median of 100 samples:

| Operation | Latency | Notes |
|---|---|---|
| ML-KEM-1024 full session setup | 241 µs | One-time per flight session |
| ML-DSA-87 sign (40B payload) | 509 µs | Per critical command (arm/disarm, waypoint) |
| HMAC-SHA3-256 verify (256B) | 1.1 µs | Per telemetry packet at 100 Hz |

The signing latency (509 µs) is within the round-trip budget for low-rate critical
commands. High-rate telemetry (100 Hz) uses HMAC-SHA3-256 exclusively (1.1 µs).

---

## 6. Fragmentation and Reassembly

### 6.1 Sender behaviour

1. Serialize the complete payload (SIGNED_CMD or SESSION_INIT) to bytes.
2. Generate a random `session_token` (uint16).
3. Split into chunks of 245 bytes. Zero-pad the last chunk.
4. Send each `CLEITONQ_CHUNK` in order, with `chunk_seq` incrementing from 0.
5. For retransmission: resend the full chunk sequence with a new `session_token`.

### 6.2 Receiver behaviour

1. On each `CLEITONQ_CHUNK`, index by `(frame_type, session_token)`.
2. Store the chunk at `chunk_seq`. Discard duplicates.
3. When `chunk_count` chunks are received: reassemble in `chunk_seq` order.
4. Validate the reassembled payload:
   - SIGNED_CMD: verify ML-DSA-87 signature; reject if nonce ≤ last_accepted_nonce.
   - SESSION_INIT: run ML-KEM.Decapsulate; reject if timestamp is replayed.
5. Evict incomplete assemblies after a timeout (recommended: 5 seconds).
6. On new `session_token` for same `frame_type`: discard prior partial assembly.

### 6.3 Chunk count reference

| Payload | Total bytes | Chunks (ceil/245) |
|---|---|---|
| SIGNED_CMD (COMMAND_LONG, 40B payload) | 4681 | 20 |
| SIGNED_CMD (HEARTBEAT, 9B payload) | 4650 | 19 |
| SESSION_INIT | 1577 | 7 |

---

## 7. Implementation Notes

Reference implementation in Rust: https://github.com/cleitonaugusto/CleitonQ

Dependencies (all NIST FIPS 203/204 compliant):
- `ml-kem` crate (RustCrypto) — ML-KEM-1024
- `ml-dsa` crate (RustCrypto) — ML-DSA-87
- `hmac` + `sha3` crates (RustCrypto) — HMAC-SHA3-256

The reference implementation provides `SignedCmd` and `SessionInit` with
`serialize()`, `deserialize()`, `sign()`, and `verify()` methods.
Chunking/reassembly is a thin layer on top of these serialized payloads.

---

## 8. Open Questions for Working Group

1. **Message ID assignment** — IDs 50000–50001 are in the vendor extension range.
   What is the process for permanent WG assignment?

2. **Dialect inclusion** — Should `cleitonq.xml` be a standalone dialect or merged
   into `common.xml`? Given the size of authentication payloads and the niche use
   case, a standalone dialect seems appropriate initially.

3. **Key distribution** — This RFC assumes out-of-band key provisioning (pre-flight).
   A follow-on RFC could define `CLEITONQ_KEY_ANNOUNCE` for authenticated key
   distribution. Is there appetite for this in the working group?

4. **Hybrid mode** — Operate ML-DSA-87 alongside the existing HMAC-SHA256 signing
   during a transition period? Or is a hard cutover preferred?

5. **ARM Cortex-A embedded benchmarks** — Current numbers are from a server-class
   ARM64 core (Neoverse-N2). Cortex-A76 (Raspberry Pi 5) and STM32-class MCU
   numbers are pending. The WG may wish to see these before committing.

---

## 9. References

- NIST FIPS 203 — ML-KEM: https://doi.org/10.6028/NIST.FIPS.203
- NIST FIPS 204 — ML-DSA: https://doi.org/10.6028/NIST.FIPS.204
- MAVLink v2 Signing: https://mavlink.io/en/guide/message_signing.html
- RustCrypto ml-kem: https://github.com/RustCrypto/KEMs
- RustCrypto ml-dsa: https://github.com/RustCrypto/signatures
- CleitonQ reference implementation: https://github.com/cleitonaugusto/CleitonQ
- CleitonQ technical paper: Preprint June 2026 (DOI pending Zenodo upload)
