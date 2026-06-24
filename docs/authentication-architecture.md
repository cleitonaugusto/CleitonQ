# Authentication Architecture — When to Use What

CleitonQ provides two authentication layers. Choosing the wrong one for a
given message type wastes bandwidth or reduces security. This document is the
authoritative reference.

---

## The Two Layers

### Layer 1 — AuthChannel (HMAC-SHA3-256)

**Overhead:** 40 bytes per packet (8-byte nonce + 32-byte tag)  
**Speed:** < 0.1 ms on Cortex-A76  
**Security:** symmetric — requires pre-shared session key (from ML-KEM handshake)  
**Non-repudiation:** none — anyone with the session key can forge

**Use for:**
- All continuous telemetry (position, attitude, sensor data)
- Heartbeat / keepalive
- Any message at > 1 Hz

### Layer 2 — DsaChannel (ML-DSA-87)

**Overhead:** 4635 bytes per packet (8-byte nonce + 4627-byte signature)  
**Speed:** ~2 ms verify, ~5 ms sign on Cortex-A76  
**Bandwidth cost (see table below):** 19 CLEITONQ_CHUNK frames per command  
**Security:** asymmetric — only the holder of the signing key can sign  
**Non-repudiation:** yes — verifying key is public and independently verifiable

**Use for:**
- ARM / DISARM
- Mission start / abort
- GOTO_WAYPOINT (critical navigation changes)
- Mode changes (MANUAL ↔ AUTO ↔ RTL)
- Any irreversible command sent ≤ 1 Hz

**Do NOT use for:**
- Continuous telemetry
- Heartbeat
- Any message > 1 Hz in steady state

---

## Bandwidth Budget

```
ML-DSA-87 signature      = 4627 bytes
CLEITONQ_CHUNK data      = 245 bytes/frame
Frames per signed command = ceil(4627 / 245) = 19 frames
MAVLink frame size        = 265 bytes (10B header + 253B payload + 2B CRC)
Bytes per signed command  = 19 × 265 = 5035 bytes
```

| Link type         | Bandwidth     | Time to deliver one signed command |
|---|---|---|
| Telemetry radio   | 250 B / 500ms | ~10 seconds                        |
| WiFi (2.4 GHz)    | 1400 B / 200ms| ~720 ms                            |
| Starlink terminal | 1400 B / 2s   | ~7.2 seconds                       |
| Iridium SBD       | 340 B / 8s    | ~118 seconds (unusable)            |

**Critical rule for telemetry radio:** never use ML-DSA-87 for commands at
rates above 0.1 Hz. At 1 Hz the link is saturated with signature frames alone.

---

## Recommended Architecture: Dual-Channel

```
        ┌─────────────────────────────────────┐
        │           Ground Station            │
        │                                     │
        │  Fast channel (AuthChannel)  ──────►│──► every packet
        │  Command channel (DsaChannel)──────►│──► critical commands only
        └─────────────────────────────────────┘
                         │
                    [ relay(s) ]
                         │
        ┌─────────────────────────────────────┐
        │               Drone                 │
        │                                     │
        │  verify HMAC every packet           │
        │  verify ML-DSA-87 for ARM/DISARM/   │
        │    WAYPOINT/MODE_CHANGE             │
        └─────────────────────────────────────┘
```

Every packet gets HMAC authentication — provides replay protection and
integrity on all traffic. Critical commands additionally require ML-DSA-87
for non-repudiation and public verifiability.

---

## Command Classification Reference

| Command              | HMAC required | ML-DSA-87 required | Reason                          |
|---|---|---|---|
| HEARTBEAT            | ✓             | —                   | High frequency, no action       |
| ATTITUDE             | ✓             | —                   | Telemetry, high frequency       |
| GLOBAL_POSITION_INT  | ✓             | —                   | Telemetry, high frequency       |
| ARM_DISARM           | ✓             | ✓                   | Irreversible safety action      |
| SET_MODE             | ✓             | ✓                   | Mission-critical mode change    |
| MISSION_START        | ✓             | ✓                   | Autonomous mission trigger      |
| MISSION_ABORT        | ✓             | ✓                   | Safety-critical abort           |
| DO_GOTO_WAYPOINT     | ✓             | ✓                   | Navigation command              |
| DO_REPOSITION        | ✓             | ✓                   | Navigation command              |
| RETURN_TO_LAUNCH     | ✓             | ✓                   | Safety action                   |
| SET_HOME_POSITION    | ✓             | ✓                   | Persistent configuration change |
| PARAM_SET (flight)   | ✓             | ✓                   | Persistent configuration change |
| PARAM_SET (logging)  | ✓             | —                   | Non-critical                    |

---

## Key Ceremony Outputs

The key ceremony (see `docs/key_ceremony.md`) produces:

- `gcs_signing_key` — ML-DSA-87 signing key, stored in HSM, never leaves
- `gcs_verifying_key` — 2592 bytes, distributed to every drone at ceremony
- `per_drone_signing_key[i]` — ML-DSA-87 per-drone, stored in drone's TPM2
- `per_drone_verifying_key[i]` — distributed to GCS SwarmKeyRegistry
- `session_key` — 32 bytes, derived fresh per mission from ML-KEM-1024 handshake

Session keys rotate per mission (or on demand). Signing keys rotate via the
`KeyRegistry` rotation procedure — old key remains trusted during the
transition window, revoked once all endpoints have the new verifying key.

---

## Compliance Notes

| Standard      | Relevant requirement                          | How CleitonQ satisfies it        |
|---|---|---|
| STANAG 4609   | §3.1 message authentication                  | AuthChannel HMAC on all traffic  |
| STANAG 4609   | §3.2 non-repudiation for C2                  | DsaChannel ML-DSA-87             |
| DO-326A       | §6.2.1 algorithm selection                    | FIPS 203 (ML-KEM), 204 (ML-DSA) |
| MIL-STD-882E  | Hazard mitigation — command injection         | Dual-layer auth + anomaly detect |
| NIST SP 800-213| IoT device authentication                    | Per-device identity key pair     |
