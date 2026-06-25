// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Sealed channel — ChaCha20-Poly1305 AEAD for authenticated-encrypted payloads.
//!
//! Adds **confidentiality** to the CleitonQ stack. [`AuthChannel`] authenticates
//! commands in plaintext — a passive RF listener can read waypoints, ARM/DISARM,
//! altitude targets. [`SealedChannel`] makes every byte opaque while keeping the
//! same anti-replay and domain-separation guarantees.
//!
//! # Relationship to `AuthChannel`
//!
//! | Property | `AuthChannel` | `SealedChannel` |
//! |---|---|---|
//! | Confidentiality | ✗ plaintext | ✓ ChaCha20 |
//! | Integrity | ✓ HMAC-SHA3-256 | ✓ Poly1305 |
//! | Anti-replay | ✓ nonce > last | ✓ counter > last |
//! | Overhead | 40 B | **24 B** |
//! | `no_std + alloc` | ✓ | ✓ |
//!
//! Use `SealedChannel` for any channel where mission intelligence (coordinates,
//! timing, system IDs) must not leak to a passive adversary.
//!
//! # Wire format
//!
//! ```text
//! [ counter (8 B LE) | ciphertext (N B) | Poly1305 tag (16 B) ]
//! ```
//!
//! Total overhead: **24 bytes** per packet.
//!
//! # Nonce construction (96-bit / IETF ChaCha20-Poly1305)
//!
//! ```text
//! nonce_96 = [ domain_u32_le (4 B) | counter_u64_le (8 B) ]
//! ```
//!
//! The domain prefix prevents nonce reuse between a C2 key and a Telemetry key
//! derived from the same session secret — even if both sides independently wrap
//! their counter back to 0 after a re-key.
//!
//! # Key derivation
//!
//! ```text
//! seal_key = SHA3-256(session_key ∥ "cleitonq-seal-v1" ∥ domain_salt)
//! ```
//!
//! Independent from `AuthChannel`'s key — the same session key drives two
//! independent subkeys via distinct domain labels.
//!
//! # Example
//!
//! ```rust,no_run,ignore
//! use cleitonq::sealed::SealedChannel;
//! use cleitonq::channel::ChannelDomain;
//!
//! let session_key = [0u8; 32]; // from ML-KEM-1024
//! let tx = SealedChannel::new(&session_key, ChannelDomain::C2);
//! let rx = SealedChannel::new(&session_key, ChannelDomain::C2);
//!
//! // GCS seals a command
//! let sealed = tx.seal(b"ARM sysid=1", 1);
//!
//! // Drone opens it
//! let mut buf = sealed;
//! let (plaintext, counter) = rx.open(&mut buf, 0).expect("must succeed");
//! assert_eq!(plaintext, b"ARM sysid=1");
//! assert_eq!(counter, 1);
//! ```

use alloc::vec::Vec;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::channel::ChannelDomain;

/// Per-packet overhead: 8-byte counter + 16-byte Poly1305 tag.
pub const SEALED_OVERHEAD: usize = 24;

const TAG_SIZE: usize = 16;
const COUNTER_SIZE: usize = 8;

// ── Key derivation ────────────────────────────────────────────────────────────

fn derive_seal_key(session_key: &[u8; 32], domain: ChannelDomain) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(session_key);
    h.update(b"cleitonq-seal-v1");
    h.update(domain.salt());
    let digest = h.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    key
}

// ── Nonce construction ────────────────────────────────────────────────────────

fn domain_prefix(domain: ChannelDomain) -> u32 {
    // Unique 32-bit prefix per domain — prevents cross-domain nonce collisions.
    match domain {
        ChannelDomain::C2        => 0x434C_5132, // "CLQ2"
        ChannelDomain::Telemetry => 0x434C_5154, // "CLQT"
        ChannelDomain::Mesh      => 0x434C_514D, // "CLQM"
        ChannelDomain::Custom(_) => 0x434C_5155, // "CLQU"
    }
}

fn build_nonce(domain: ChannelDomain, counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&domain_prefix(domain).to_le_bytes());
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce)
}

// ── SealedChannel ─────────────────────────────────────────────────────────────

/// Authenticated-encryption channel backed by ChaCha20-Poly1305.
///
/// Construct one per logical direction from the shared ML-KEM session key.
/// Both GCS (sealer) and drone (opener) derive the same key independently.
///
/// **Thread safety**: not `Send + Sync` — use one instance per task/thread.
pub struct SealedChannel {
    key: Zeroizing<[u8; 32]>,
    domain: ChannelDomain,
}

impl SealedChannel {
    /// Create a sealed channel from an ML-KEM session key and channel domain.
    ///
    /// Derives an independent sealing key via domain-separated SHA3-256.
    pub fn new(session_key: &[u8; 32], domain: ChannelDomain) -> Self {
        Self {
            key: derive_seal_key(session_key, domain),
            domain,
        }
    }

    /// Create a channel directly from a pre-derived sealing key.
    ///
    /// Use only when you have already performed key derivation externally
    /// (e.g., from a hardware KDF). For normal use, prefer [`Self::new`].
    pub fn from_raw_key(key: [u8; 32], domain: ChannelDomain) -> Self {
        Self { key: Zeroizing::new(key), domain }
    }

    /// Seal `payload`: encrypt-and-authenticate, prepend counter.
    ///
    /// `counter` must be **strictly increasing** across all calls on this channel
    /// instance. Use [`crate::nonce::AtomicNonce`] or a persisted counter.
    ///
    /// Returns `[counter_8B | ciphertext_NB | tag_16B]`.
    pub fn seal(&self, payload: &[u8], counter: u64) -> Vec<u8> {
        let nonce = build_nonce(self.domain, counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));

        // Buffer: [counter(8) | payload(N)] — payload portion encrypted in-place.
        let mut buf = Vec::with_capacity(COUNTER_SIZE + payload.len() + TAG_SIZE);
        let counter_bytes = counter.to_le_bytes();
        buf.extend_from_slice(&counter_bytes);
        buf.extend_from_slice(payload);

        // AAD = counter bytes — binds the tag to this specific counter value,
        // preventing an attacker from splicing ciphertexts with a different counter.
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &counter_bytes, &mut buf[COUNTER_SIZE..])
            .expect("ChaCha20Poly1305 seal cannot fail for a valid 32-byte key");

        buf.extend_from_slice(&tag);
        buf
    }

    /// Open a sealed packet: verify tag then decrypt.
    ///
    /// `packet` is modified in-place (decrypted). On success returns a slice
    /// into `packet` containing the plaintext and the validated counter.
    ///
    /// Returns `None` without revealing the reason on any failure:
    /// - Wrong tag (authentication failure / tampering)
    /// - `counter <= last_counter` (replay)
    /// - Packet shorter than [`SEALED_OVERHEAD`]
    pub fn open<'a>(&self, packet: &'a mut [u8], last_counter: u64) -> Option<(&'a [u8], u64)> {
        if packet.len() < SEALED_OVERHEAD {
            return None;
        }

        let tag_start = packet.len() - TAG_SIZE;

        // Decode counter before authentication — we use it to build the nonce
        // and AAD, but do NOT accept it until the tag verifies.
        let counter = u64::from_le_bytes(packet[..COUNTER_SIZE].try_into().ok()?);

        // Anti-replay: reject before doing crypto work to avoid oracle.
        // Note: we check BEFORE decryption so a forged counter doesn't reach
        // the cipher. The tag still covers the counter via AAD.
        if counter <= last_counter {
            return None;
        }

        let nonce = build_nonce(self.domain, counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
        let counter_bytes = counter.to_le_bytes();

        // Extract tag — must match exactly 16 bytes.
        let tag_bytes: [u8; TAG_SIZE] = packet[tag_start..].try_into().ok()?;
        let tag = Tag::from(tag_bytes);

        // Decrypt in-place; returns Err on tag mismatch (constant-time compare).
        cipher
            .decrypt_in_place_detached(
                &nonce,
                &counter_bytes,
                &mut packet[COUNTER_SIZE..tag_start],
                &tag,
            )
            .ok()?;

        Some((&packet[COUNTER_SIZE..tag_start], counter))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn channel_pair(domain: ChannelDomain) -> (SealedChannel, SealedChannel) {
        let key = [0x42u8; 32];
        (SealedChannel::new(&key, domain), SealedChannel::new(&key, domain))
    }

    #[test]
    fn seal_open_roundtrip() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let sealed = tx.seal(b"ARM sysid=1 comp=1", 1);
        let mut buf = sealed;
        let (plain, counter) = rx.open(&mut buf, 0).expect("must succeed");
        assert_eq!(plain, b"ARM sysid=1 comp=1");
        assert_eq!(counter, 1);
    }

    #[test]
    fn seal_open_empty_payload() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let sealed = tx.seal(b"", 1);
        assert_eq!(sealed.len(), SEALED_OVERHEAD);
        let mut buf = sealed;
        let (plain, _) = rx.open(&mut buf, 0).unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn overhead_is_exactly_24_bytes() {
        let tx = SealedChannel::new(&[0u8; 32], ChannelDomain::C2);
        let payload = b"test";
        let sealed = tx.seal(payload, 1);
        assert_eq!(sealed.len(), payload.len() + SEALED_OVERHEAD);
    }

    #[test]
    fn replay_rejected() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let sealed = tx.seal(b"DISARM", 5);
        // last_counter=4 → accept
        let mut buf = sealed.clone();
        assert!(rx.open(&mut buf, 4).is_some());
        // last_counter=5 → reject (counter must be strictly greater)
        let mut buf = sealed.clone();
        assert!(rx.open(&mut buf, 5).is_none());
        // last_counter=10 → reject
        let mut buf = sealed;
        assert!(rx.open(&mut buf, 10).is_none());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let mut sealed = tx.seal(b"WAYPOINT lat=47.4", 1);
        // Flip one byte in the ciphertext body
        sealed[COUNTER_SIZE] ^= 0xFF;
        assert!(rx.open(&mut sealed, 0).is_none());
    }

    #[test]
    fn tampered_tag_rejected() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let mut sealed = tx.seal(b"TAKEOFF alt=20", 1);
        let last = sealed.last_mut().unwrap();
        *last ^= 0xFF;
        assert!(rx.open(&mut sealed, 0).is_none());
    }

    #[test]
    fn tampered_counter_rejected() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let mut sealed = tx.seal(b"RTL", 3);
        // Corrupt the counter field — tag covers counter via AAD
        sealed[0] ^= 0x01;
        assert!(rx.open(&mut sealed, 0).is_none());
    }

    #[test]
    fn wrong_key_rejected() {
        let tx = SealedChannel::new(&[0xAAu8; 32], ChannelDomain::C2);
        let rx = SealedChannel::new(&[0xBBu8; 32], ChannelDomain::C2);
        let sealed = tx.seal(b"secret command", 1);
        let mut buf = sealed;
        assert!(rx.open(&mut buf, 0).is_none());
    }

    #[test]
    fn domain_separation_c2_vs_telemetry() {
        // Same session key, different domain → different seal keys → cross-domain open fails.
        let key = [0xCCu8; 32];
        let tx_c2 = SealedChannel::new(&key, ChannelDomain::C2);
        let rx_telem = SealedChannel::new(&key, ChannelDomain::Telemetry);
        let sealed = tx_c2.seal(b"ARM", 1);
        let mut buf = sealed;
        assert!(rx_telem.open(&mut buf, 0).is_none(), "cross-domain open must fail");
    }

    #[test]
    fn domain_separation_c2_vs_mesh() {
        let key = [0xDDu8; 32];
        let tx = SealedChannel::new(&key, ChannelDomain::C2);
        let rx = SealedChannel::new(&key, ChannelDomain::Mesh);
        let sealed = tx.seal(b"FORMATION", 1);
        let mut buf = sealed;
        assert!(rx.open(&mut buf, 0).is_none());
    }

    #[test]
    fn counter_strictly_increasing() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let p1 = tx.seal(b"cmd1", 1);
        let p3 = tx.seal(b"cmd3", 3);
        // Accept p1 first
        let mut b1 = p1;
        rx.open(&mut b1, 0).expect("counter=1 must be accepted");
        // Skip counter=2 — counter=3 still accepted (monotonic, not sequential)
        let mut b3 = p3;
        rx.open(&mut b3, 1).expect("counter=3 must be accepted after counter=1");
    }

    #[test]
    fn seal_large_payload() {
        let (tx, rx) = channel_pair(ChannelDomain::Mesh);
        let payload = vec![0xABu8; 4096];
        let sealed = tx.seal(&payload, 42);
        assert_eq!(sealed.len(), 4096 + SEALED_OVERHEAD);
        let mut buf = sealed;
        let (plain, ctr) = rx.open(&mut buf, 0).unwrap();
        assert_eq!(plain, &payload[..]);
        assert_eq!(ctr, 42);
    }

    #[test]
    fn independent_from_auth_channel_key() {
        use crate::channel::AuthChannel;
        // Same session key must yield different subkeys for AuthChannel and SealedChannel.
        let session_key = [0x55u8; 32];
        let auth = AuthChannel::new(&session_key, ChannelDomain::C2);
        let sealed_ch = SealedChannel::new(&session_key, ChannelDomain::C2);

        // A packet signed by AuthChannel must NOT be openable by SealedChannel.
        let auth_packet = auth.sign(b"cmd", 1);
        let mut buf = auth_packet;
        if buf.len() >= SEALED_OVERHEAD {
            assert!(sealed_ch.open(&mut buf, 0).is_none(),
                "AuthChannel packet must not open in SealedChannel");
        }
    }
}
