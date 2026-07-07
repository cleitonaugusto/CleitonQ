# Anchors: Quantum-Safe Command Provenance for Autonomous Machines

**Version:** 0.1-draft
**Author:** Cleiton Augusto Correa Bezerra
**Date:** 2026-07-03
**Status:** Draft — concept definition and prior art

---

## Abstract

Autonomous machines — drones, robots, spacecraft — execute commands issued by
human operators and, increasingly, by AI agents. When an incident occurs, no
independent evidence exists of who commanded what: conventional logs are
mutable by whoever operates the system, symmetric authentication (MAC) cannot
prove origin to a third party, and records signed with elliptic-curve
cryptography lose their evidentiary value once cryptographically relevant
quantum computers arrive — evidence with an expiration date.

This document defines the **Anchor**: a post-quantum signed commitment over a
window of authenticated machine traffic. An anchor is a cryptographic receipt
of what a machine was commanded to do and what it reported back, verifiable
by any third party — an insurer, a regulator, a court — without trusting the
operator, without network access, decades after the fact.

Anchors are protocol-agnostic. This document specifies the generic
construction and references two concrete instantiations already specified:
high-rate telemetry links ([telemetry-auth-spec.md](telemetry-auth-spec.md))
and CCSDS spacecraft telecommand ([ccsds-pqc-adapter.md](ccsds-pqc-adapter.md)).

---

## 1. The Accountability Gap

### 1.1 Three failures of current practice

**Mutable logs.** Flight logs and command histories are files under the
operator's control. In a liability dispute, the party that produces the log
is the party with the motive and the means to alter it.

**Authentication without non-repudiation.** Symmetric MACs (including
post-quantum-safe HMAC) prove to the *session peer* that traffic is authentic.
They prove nothing to anyone else: either party could have generated any
message. Post-incident, the operator cannot demonstrate to an insurer or
investigator that the recorded command sequence is what the machine actually
received.

**Quantum-expiring evidence.** Records signed today with ECDSA or EdDSA —
including blockchain-anchored records, which inherit the elliptic-curve
signatures of their underlying ledgers — become forgeable when a
cryptographically relevant quantum computer exists. A machine sold in 2026
operates into the 2040s; its evidence trail must outlive the quantum
transition.

### 1.2 Why this matters now

- **EU AI Act, Article 12** (Regulation (EU) 2024/1689): high-risk AI systems —
  including AI safety components of regulated machinery — must automatically
  record events over their lifetime, retain logs at least six months, and
  enable post-hoc reconstruction of individual decisions.
- **AI agents issuing physical commands.** Joint guidance from six national
  cyber security agencies (May 2026) addresses agentic AI risk; US defense
  guidance recommends digitally signed commands so that an agent cannot act
  on forged instructions. Existing agent-authorization work (OAuth/JWT token
  chains) covers software APIs only — it does not reach the physical machine,
  and none of it is post-quantum.
- **BVLOS operations and insurance.** Emerging beyond-visual-line-of-sight
  frameworks (e.g., FAA Part 108 rulemaking) presuppose that regulators and
  insurers can trust telemetry records. Trust requires third-party
  verifiability, not operator attestation.

No existing system provides post-quantum, third-party-verifiable command
provenance for physical machines. This document names that class and defines
its primitive.

---

## 2. Definition

An **Anchor** is a post-quantum digital signature over a compact commitment
to a window of authenticated traffic:

```
Given a window of n authenticated messages with MAC tags mac_0 ... mac_{n-1}:

  commitment = H(mac_0 || mac_1 || ... || mac_{n-1})
  anchor     = ( metadata, commitment,
                 Sig_sk(DOMAIN || metadata || commitment) )

where:
  H         = SHA3-256 (FIPS 202)
  Sig       = ML-DSA-87 (FIPS 204, NIST security category 5)
  DOMAIN    = a fixed domain-separation tag (e.g. "cleitonq-anchor-v1")
  metadata  = anchor sequence number, window boundaries, message count
              (exact fields are instantiation-specific)
```

The `DOMAIN` prefix is mandatory when the signing key is also used to sign
other messages (e.g. individual commands): it ensures an anchor signature can
never be reinterpreted as a valid signature for another message type under the
same ML-DSA key. A verifier MUST reject any anchor whose signed input does not
begin with the expected `DOMAIN` tag.

Window closure is governed by two parameters: **W** (maximum messages per
window) and **T** (maximum time per window); an anchor is emitted at
whichever bound is reached first.

### 2.1 Properties

| Property | Mechanism |
|---|---|
| Tamper evidence | Any alteration of any message MAC changes the commitment; the signature no longer verifies |
| Non-repudiation | ML-DSA-87 signature binds the window to the holder of the signing key |
| Third-party verifiability | Verification requires only the MAC sequence, the anchors, and the public verifying key — not the session key, not the operator's cooperation |
| Offline operation | Anchors are generated and stored locally; no network, ledger, or third-party service is required at recording time |
| Quantum durability | ML-DSA-87 and SHA3-256 remain secure against known quantum attacks; the evidence does not expire with the quantum transition |
| Constrained-link fit | One signature amortized over a window: per-message overhead stays at the MAC size (32–44 bytes), independent of window size |

### 2.2 What an Anchor is not

- Not a blockchain: no consensus, no ledger, no network dependency, no
  energy cost beyond one signature per window.
- Not encryption: anchors provide evidence, not confidentiality
  (confidentiality is a separate, composable layer).
- Not a flight recorder for software-only agents: the anchor covers the
  authenticated link to a physical machine, at the boundary where commands
  become actuation.

---

## 3. Instantiations

Two instantiations are specified in companion documents. Both use the same
construction; they differ only in metadata fields and windowing policy.

| | Telemetry (TAP) | CCSDS Telecommand |
|---|---|---|
| Specification | [telemetry-auth-spec.md](telemetry-auth-spec.md) | [ccsds-pqc-adapter.md](ccsds-pqc-adapter.md) |
| Per-message overhead | 42 bytes | 44 bytes |
| Window policy | W = 256 packets or T = 10 s | one ground contact window |
| Anchor size | 4,685 bytes | 4,687 bytes (5 TC frames) |
| Link budget fit | 48.2 kbps total at 100 Hz | 18.7 s at 2 kbps, once per pass |

The same construction applies to ROS2/DDS topics and CAN buses; the
underlying relay-transparency problem for these protocol stacks is documented
in IETF draft-bezerra-relay-auth-transparency-00.

Session keys for the MAC layer are established via ML-KEM-1024 (FIPS 203,
NIST security category 5). Signing-key revocation uses SLH-DSA-SHA2-128s
(FIPS 205) as a hash-based fallback independent of lattice assumptions.

---

## 4. Verification Model

An auditor holding:

1. the stored MAC sequence for the period in question,
2. the anchor records, and
3. the signer's ML-DSA-87 verifying key (distributed at provisioning,
   e.g., via key ceremony)

recomputes each window commitment and verifies each anchor signature.
A verified anchor chain establishes that the recorded traffic is exactly
what the signer authenticated at recording time — the operator cannot
retroactively insert, delete, or modify messages without breaking the chain.

Verification requires no live system, no session secrets, and no trust in
the party producing the archive. A runnable reference emitter and standalone
verifier — demonstrating intact-archive verification, tamper detection,
replay rejection, and wrong-signer rejection — is provided in
`examples/anchor_provenance.rs`, so that any third party can implement and
perform this check independently.

---

## 5. Security Considerations

- **Signer compromise.** An attacker holding the signing key can anchor
  forged windows *going forward*; past anchors remain valid evidence.
  Revocation is handled by SLH-DSA-signed revocation certificates
  (instantiation-specific).
- **Selective omission.** An operator may withhold entire windows. Anchor
  sequence numbers are monotonic; gaps in the anchor sequence are themselves
  evidence of omission.
- **Commitment security.** SHA3-256 provides 128-bit classical collision
  resistance; known quantum collision attacks do not reduce this below
  practical security margins.
- **Algorithm agility.** The construction is parametric in H and Sig;
  migration to future signature standards changes the anchor format version,
  not the architecture.

---

## 6. References

1. NIST FIPS 202, *SHA-3 Standard*, August 2015
2. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024
3. NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, August 2024
4. NIST FIPS 205, *Stateless Hash-Based Digital Signature Standard*, August 2024
5. Regulation (EU) 2024/1689 (AI Act), Article 12 — Record-keeping
6. NSA, *Commercial National Security Algorithm Suite 2.0*, September 2022
7. IETF draft-bezerra-relay-auth-transparency-00, June 2026
8. CleitonQ Telemetry Authentication Specification (TAP), July 2026
9. CleitonQ CCSDS PQC Adapter, July 2026
