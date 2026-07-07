//! Anchor command-provenance: reference emitter + standalone verifier.
//!
//! Demonstrates the construction specified in `rfc/anchors-command-provenance.md`
//! and IETF `draft-bezerra-anchors-command-provenance`:
//!
//!   commitment = SHA3-256(mac_0 || mac_1 || ... || mac_{n-1})
//!   anchor     = ML-DSA-87.sign( metadata || commitment )
//!
//! An anchor chain is a tamper-evident, non-repudiable, quantum-resistant record
//! of a window of authenticated machine traffic — verifiable by any third party
//! holding only the MAC sequence, the anchors, and the public verifying key.
//!
//! Run: `cargo run --example anchor_provenance`

use cleitonq::channel::AuthChannel;
use cleitonq::dsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};

const MAC_BYTES: usize = 32;

/// Domain-separation tag prefixed to every anchor signature input, so an anchor
/// signature can never be mistaken for a command signature produced by the same
/// ML-DSA-87 key (which the ground station reuses for both).
const ANCHOR_DOMAIN: &[u8] = b"cleitonq-anchor-v1";

/// Metadata bound into every anchor signature (little-endian on the wire).
struct AnchorMeta {
    anchor_nonce: u64,
    window_start: u64,
    window_end: u64,
    packet_count: u32,
}

impl AnchorMeta {
    /// `anchor_nonce || window_start || window_end || packet_count` (28 bytes LE).
    fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&self.anchor_nonce.to_le_bytes());
        b.extend_from_slice(&self.window_start.to_le_bytes());
        b.extend_from_slice(&self.window_end.to_le_bytes());
        b.extend_from_slice(&self.packet_count.to_le_bytes());
        b
    }
}

/// SHA3-256 over the ordered concatenation of window MAC tags.
fn commit_window(macs: &[[u8; MAC_BYTES]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for mac in macs {
        h.update(mac);
    }
    h.finalize().into()
}

/// EMITTER (signer side): produce an anchor over a window of MAC tags.
///
/// Returns the wire packet `[ meta || commitment | anchor_nonce_le8 | ml_dsa_sig ]`,
/// reusing the crate's verified `SigningKey::sign`.
fn emit_anchor(sk: &SigningKey, meta: &AnchorMeta, macs: &[[u8; MAC_BYTES]]) -> Vec<u8> {
    let mut signed_payload = Vec::from(ANCHOR_DOMAIN);
    signed_payload.extend_from_slice(&meta.to_bytes());
    signed_payload.extend_from_slice(&commit_window(macs));
    sk.sign(&signed_payload, meta.anchor_nonce)
}

/// VERIFIER (third-party auditor side): validate an anchor against a stored
/// MAC sequence, trusting only the public verifying key.
///
/// This is the network-effect deliverable: anyone can implement and run it
/// without the operator's cooperation and without any session secret.
fn verify_anchor(
    vk: &VerifyingKey,
    anchor: &[u8],
    macs: &[[u8; MAC_BYTES]],
    last_anchor_nonce: u64,
) -> Result<u64, &'static str> {
    // 1. Signature valid + strictly-increasing anchor nonce (anti-replay).
    let (signed_payload, anchor_nonce) = vk
        .verify(anchor, last_anchor_nonce)
        .ok_or("signature invalid, malformed, or replayed anchor nonce")?;

    // 2. Require the anchor domain tag: a command signature (which lacks it)
    //    can never be accepted here, even under the same ML-DSA key.
    if signed_payload.len() < ANCHOR_DOMAIN.len() + 32
        || &signed_payload[..ANCHOR_DOMAIN.len()] != ANCHOR_DOMAIN
    {
        return Err("not an anchor: missing domain tag");
    }

    // 3. Recompute the commitment from the locally stored MAC sequence and
    //    check it against the value the signer committed to.
    let committed = &signed_payload[signed_payload.len() - 32..];
    let recomputed = commit_window(macs);
    if committed != recomputed {
        return Err("commitment mismatch: the MAC archive was altered");
    }

    Ok(anchor_nonce)
}

fn main() {
    println!("== Anchor command-provenance reference ==\n");

    // --- Provisioning: signer holds ML-DSA-87 key; auditor holds the public half.
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();

    // --- A window of authenticated machine traffic (W = 256).
    // Each command is authenticated in real time with HMAC-SHA3-256; the anchor
    // later converts those symmetric tags into third-party-verifiable evidence.
    let channel = AuthChannel::from_raw_key([0x42; 32]);
    let window: u32 = 256;
    let mut macs: Vec<[u8; MAC_BYTES]> = Vec::with_capacity(window as usize);
    for nonce in 1..=window as u64 {
        let payload = format!("MAV_CMD #{nonce}");
        let packet = channel.sign(payload.as_bytes(), nonce);
        let mac: [u8; MAC_BYTES] = packet[packet.len() - MAC_BYTES..].try_into().unwrap();
        macs.push(mac);
    }

    let meta = AnchorMeta {
        anchor_nonce: 1,
        window_start: 1,
        window_end: window as u64,
        packet_count: window,
    };
    let anchor = emit_anchor(&sk, &meta, &macs);
    println!(
        "emitted 1 anchor covering {} commands  ({} bytes on the wire)",
        window,
        anchor.len()
    );
    println!(
        "per-command amortized overhead: {:.1} bytes\n",
        anchor.len() as f64 / window as f64
    );

    // --- Case 1: honest archive verifies.
    match verify_anchor(&vk, &anchor, &macs, 0) {
        Ok(n) => println!("[PASS] intact archive verified (anchor_nonce = {n})"),
        Err(e) => println!("[FAIL] unexpected: {e}"),
    }

    // --- Case 2: operator alters one command after the fact -> detected.
    let mut tampered = macs.clone();
    tampered[100][0] ^= 0x01; // flip a single bit in command #101's MAC
    match verify_anchor(&vk, &anchor, &tampered, 0) {
        Ok(_) => println!("[FAIL] tampering went undetected!"),
        Err(e) => println!("[PASS] tampering detected -> {e}"),
    }

    // --- Case 3: replayed anchor (nonce not advanced) -> rejected.
    match verify_anchor(&vk, &anchor, &macs, 1) {
        Ok(_) => println!("[FAIL] replay accepted!"),
        Err(e) => println!("[PASS] replay rejected -> {e}"),
    }

    // --- Case 4: wrong signer key -> rejected.
    let other = SigningKey::generate().verifying_key();
    match verify_anchor(&other, &anchor, &macs, 0) {
        Ok(_) => println!("[FAIL] forged-signer anchor accepted!"),
        Err(e) => println!("[PASS] wrong signing key rejected -> {e}"),
    }

    // --- Case 5: a command-style signature (same key, NO anchor domain tag)
    //     over the exact meta || commitment bytes must NOT pass as an anchor.
    let mut command_bytes = meta.to_bytes();
    command_bytes.extend_from_slice(&commit_window(&macs));
    let forged = sk.sign(&command_bytes, meta.anchor_nonce); // no ANCHOR_DOMAIN prefix
    match verify_anchor(&vk, &forged, &macs, 0) {
        Ok(_) => println!("[FAIL] untagged command signature accepted as anchor!"),
        Err(e) => println!("[PASS] domain separation holds -> {e}"),
    }

    println!("\nAll provenance properties hold: tamper-evidence, non-repudiation,");
    println!("third-party verifiability, replay resistance — post-quantum (ML-DSA-87 + SHA3-256).");
}
