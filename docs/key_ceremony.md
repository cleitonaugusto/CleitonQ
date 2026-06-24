# CleitonQ Key Ceremony Procedure

**Version**: 1.0  
**Date**: 2026-06-24  
**Author**: Cleiton Augusto Correa Bezerra  
**Required for**: NATO procurement, FISMA compliance, DO-326A §6.3.2, defense deployment

---

## Overview

A key ceremony is a controlled, auditable procedure for generating and distributing
ML-DSA-87 signing keys. It ensures that:

1. The signing key is generated on an air-gapped machine and never transmitted in plaintext.
2. The key seed is split using Shamir Secret Sharing (SSS) so no single person can reconstruct it.
3. The verifying key (public) is distributed to all drones/robots before deployment.
4. The signing key (private) lives only in the GCS HSM after the ceremony.

This procedure requires **3 to 5 people** (one ceremony officer + 2–4 key custodians),
one air-gapped laptop, and either a YubiHSM2 or SoftHSM2-initialized USB drive.

---

## Prerequisites

### Hardware
- [ ] Air-gapped laptop running Ubuntu 22.04 LTS (no network, no Bluetooth)
- [ ] YubiHSM2 USB key (production) or SoftHSM2 on encrypted USB (development)
- [ ] 3–5 USB drives (one per key custodian) for SSS shards
- [ ] Paper and pens for ceremony log (no cameras or phones in room)
- [ ] Secure shredder for paper waste

### Software (pre-installed on air-gapped machine)
```bash
# Install on air-gapped machine before ceremony
sudo apt-get install -y softhsm2 opensc libsecret-1-0 python3-secretsharing
cargo install cleitonq-tools  # ceremony tooling binary (future)
```

### People
- **Ceremony Officer (CO)**: runs the procedure, does not hold any shard
- **Key Custodian 1–4 (KC1–KC4)**: each holds one SSS shard
- **Witness** (optional but recommended): independent observer

A 2-of-3 scheme requires 3 custodians; 3-of-5 requires 5. Choose based on
operational requirements (higher threshold = more secure but harder to recover).

---

## Procedure

### Phase 1 — Preparation (1 day before ceremony)

**CO actions:**
```bash
# 1. Boot air-gapped machine from live USB
# 2. Verify no network interfaces are active
ip link show
# All interfaces should be DOWN or show loopback only

# 3. Verify CleitonQ tools binary hash (compare to published SHA-256 on GitHub)
sha256sum /usr/local/bin/cleitonq-ceremony
# Expected: <hash from github.com/cleitonaugusto/CleitonQ/releases>

# 4. Initialize SoftHSM2 or insert YubiHSM2
softhsm2-util --init-token --slot 0 --label "CleitonQ-GCS-Production" \
  --pin <CEREMONY_PIN> --so-pin <SO_PIN>
# Write CEREMONY_PIN and SO_PIN on paper, seal in envelope.
# These are destroyed after key import to HSM.
```

### Phase 2 — Key Generation

All custodians must be present and observing. CO speaks each action aloud.

```bash
# 1. Generate ML-DSA-87 key pair
# The seed is 32 bytes of CSPRNG output.
cleitonq-ceremony generate-keypair \
  --output-seed /tmp/mldsa87_seed.bin \
  --output-vk   /tmp/mldsa87_vk.bin

# 2. Verify the verifying key is exactly 2592 bytes
ls -la /tmp/mldsa87_vk.bin
# Expected: 2592 bytes

# 3. Display verifying key fingerprint (SHA3-256 of the verifying key)
sha3sum /tmp/mldsa87_vk.bin
# Record this fingerprint in the ceremony log (paper).
# This fingerprint will be verified on every drone after distribution.
```

**Alternative: generate seed with hardware entropy**
```bash
# Using /dev/hwrng if available (RPi5, YubiHSM2 RNG)
dd if=/dev/hwrng bs=32 count=1 2>/dev/null | \
  cleitonq-ceremony import-seed --output-vk /tmp/mldsa87_vk.bin
```

### Phase 3 — Shamir Secret Sharing (Seed Split)

```bash
# Split the 32-byte seed into N shards with threshold K.
# Default: 2-of-3 (any 2 of 3 custodians can reconstruct).
# For defense: use 3-of-5.

cleitonq-ceremony split-seed \
  --input    /tmp/mldsa87_seed.bin \
  --threshold 2 \
  --shares    3 \
  --output-prefix /tmp/shard_

# This produces:
#   /tmp/shard_1.bin  (64 bytes — shard index + data)
#   /tmp/shard_2.bin
#   /tmp/shard_3.bin

# Each custodian copies their shard to their USB drive:
cp /tmp/shard_1.bin /media/KC1_USB/cleitonq_shard.bin  # KC1
cp /tmp/shard_2.bin /media/KC2_USB/cleitonq_shard.bin  # KC2
cp /tmp/shard_3.bin /media/KC3_USB/cleitonq_shard.bin  # KC3

# Custodians verify their shard is readable:
sha3sum /media/KC1_USB/cleitonq_shard.bin  # KC1 records this hash
sha3sum /media/KC2_USB/cleitonq_shard.bin  # KC2 records this hash
sha3sum /media/KC3_USB/cleitonq_shard.bin  # KC3 records this hash
```

**Record all shard hashes in the ceremony log.**

### Phase 4 — HSM Import

```bash
# Import the seed into the GCS HSM.
# After this step, the seed file is shredded.

# Option A: SoftHSM2
cleitonq-ceremony import-to-pkcs11 \
  --seed    /tmp/mldsa87_seed.bin \
  --library /usr/lib/softhsm/libsofthsm2.so \
  --slot    0 \
  --pin     <CEREMONY_PIN> \
  --label   MLDSA87_GCS_SEED

# Option B: YubiHSM2
cleitonq-ceremony import-to-yubihsm2 \
  --seed        /tmp/mldsa87_seed.bin \
  --auth-key-id 1 \
  --password    <YUBIHSM2_PASSWORD> \
  --label       MLDSA87_GCS_SEED

# Verify the import by doing a test sign:
cleitonq-ceremony test-sign \
  --library /usr/lib/softhsm/libsofthsm2.so \
  --label   MLDSA87_GCS_SEED \
  --pin     <CEREMONY_PIN> \
  --message "ceremony-test"
# This should print: SIGNATURE VALID ✓

# Shred the seed file immediately after successful HSM import:
shred -uz /tmp/mldsa87_seed.bin
ls /tmp/mldsa87_seed.bin 2>/dev/null && echo "ERROR: seed not deleted" || echo "Seed shredded ✓"
```

### Phase 5 — Verifying Key Distribution

The verifying key (`mldsa87_vk.bin`, 2592 bytes) is public and goes to every drone/robot.

```bash
# Copy to all drones/GCS instances:
cp /tmp/mldsa87_vk.bin /media/DRONE_USB/gs_verifying.bin

# Each drone/robot verifies the fingerprint on first boot:
sha3sum /etc/cleitonq/gs_verifying.bin
# Must match the fingerprint recorded in Phase 2.

# For ROS2 deployments, distribute via:
ros2 param set /cleitonq_auth_node vk_path /etc/cleitonq/gs_verifying.bin
```

### Phase 6 — Cleanup and Log

```bash
# Shred all temporary files:
shred -uz /tmp/shard_*.bin
shred -uz /tmp/mldsa87_vk.bin  # keep only on drone USBs and signed manifest
shred -uz /tmp/ceremony_*.log  # paper log is the authoritative record

# Verify ceremony machine has no key material:
find /tmp -name "*.bin" 2>/dev/null && echo "WARNING: files remain" || echo "Clean ✓"

# Power off ceremony machine and remove storage:
sudo poweroff
```

**CO seals the paper ceremony log in a tamper-evident envelope and stores in physical safe.**

---

## Key Recovery Procedure

If the GCS HSM fails or is lost, reconstruct the seed from ≥ K custodian shards:

```bash
# Custodians assemble (≥2 of 3 required for 2-of-3 scheme)
# Each inserts their USB drive on the air-gapped machine:

cleitonq-ceremony reconstruct-seed \
  --shard /media/KC1_USB/cleitonq_shard.bin \
  --shard /media/KC2_USB/cleitonq_shard.bin \
  --output /tmp/mldsa87_seed_recovered.bin

# Verify fingerprint matches ceremony log:
sha3sum /tmp/mldsa87_seed_recovered.bin

# Re-import to new HSM (Phase 4) then shred:
shred -uz /tmp/mldsa87_seed_recovered.bin
```

---

## Key Rotation

Rotate the signing key when:
- Any custodian's shard USB is lost or compromised
- HSM firmware has a known vulnerability
- Operational policy requires periodic rotation (e.g., every 12 months)

Rotation procedure:
1. Generate new key pair (Phase 2)
2. Distribute new verifying key to all drones (Phase 5) — drones must accept both old and new vk during transition window
3. Decommission old HSM key: `pkcs11-tool --delete-object --type data --label MLDSA87_GCS_SEED`
4. After all drones updated: remove old vk from drone storage

---

## Compliance Notes

| Standard | Requirement | How this ceremony satisfies it |
|---|---|---|
| NATO STANAG 4609 | Key material generated in controlled environment with audit trail | Air-gapped machine + paper log + ceremony officer |
| FISMA (NIST SP 800-57) | Key split for sensitive keys; HSM for production keys | 2-of-3 SSS + YubiHSM2/SoftHSM2 |
| DO-326A §6.3.2 | Key management plan with documented generation and distribution | This document + ceremony log |
| MIL-STD-882E | Hazard elimination for authentication failure modes | Shred procedure prevents key reconstruction without quorum |
| UNECE WP.29 R155 | Cryptographic key management for vehicle cybersecurity | HSM storage + NV-indexed TPM2 alternative |

---

## Quick Reference Card (for ceremony participants)

```
BEFORE CEREMONY:
  ☐ Verify air-gap (no network, no Bluetooth)
  ☐ Count participants (CO + KC1..KCn + optional Witness)
  ☐ All phones/cameras out of room

DURING CEREMONY:
  ☐ Phase 2: Generate keypair → record VK fingerprint on paper
  ☐ Phase 3: Split seed into N shards → each KC copies their shard
  ☐ Phase 3: Each KC records their shard hash on paper
  ☐ Phase 4: Import seed to HSM → test sign succeeds → shred seed
  ☐ Phase 5: Distribute VK to drones → verify fingerprint

AFTER CEREMONY:
  ☐ Shred all temp files (verified)
  ☐ Ceremony log sealed in tamper-evident envelope
  ☐ Each KC takes their shard USB (stored separately)
  ☐ CO stores ceremony log in physical safe
```
