// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Authenticated channel combining ML-KEM session key + HMAC-SHA3-256.
//!
//! `AuthChannel` is the high-level API for most integrations. It wraps a
//! 32-byte session key (typically from ML-KEM encapsulation) and uses it to
//! authenticate every packet with HMAC-SHA3-256 + anti-replay nonce.
//!
//! For command authentication with non-repudiation (proving the command came
//! from a specific ground station), use [`crate::dsa`] on top of this channel.
//!
//! # Key hierarchy
//!
//! A single session key produces distinct sub-keys per channel via domain
//! separation salts, preventing cross-channel key reuse:
//!
//! ```text
//! session_key (32 bytes, from ML-KEM)
//!     │
//!     ├─ SHA3-256(session_key || "cleitonq-c2-v1")      → C2 inbound key
//!     ├─ SHA3-256(session_key || "cleitonq-telemetry-v1") → telemetry key
//!     └─ SHA3-256(session_key || "cleitonq-mesh-v1")    → mesh key
//! ```
//!
//! # Wire format
//!
//! ```text
//! [ payload (N bytes) | nonce (8 bytes LE) | HMAC-SHA3-256 tag (32 bytes) ]
//! ```
//!
//! # Example
//!
//! ```no_run
//! use cleitonq::channel::{AuthChannel, ChannelDomain};
//!
//! let session_key = [0u8; 32]; // from ML-KEM in production
//! let tx = AuthChannel::new(&session_key, ChannelDomain::C2);
//! let rx = AuthChannel::new(&session_key, ChannelDomain::C2);
//!
//! let packet = tx.sign(b"roll=0.0 pitch=0.0 thrust=9.81", 1);
//! let (payload, nonce) = rx.verify(&packet, 0).expect("must succeed");
//! ```

use hmac::{Hmac, Mac};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

type HmacSha3256 = Hmac<Sha3_256>;

/// Per-packet overhead: 8-byte nonce + 32-byte HMAC tag.
pub const OVERHEAD: usize = 40;

/// Domain separation label for each logical channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDomain {
    /// Inbound command & control (ground station → drone).
    C2,
    /// Outbound telemetry (drone → ground station).
    Telemetry,
    /// Inter-drone mesh (drone ↔ drone).
    Mesh,
    /// Custom domain — provide your own salt.
    Custom(&'static [u8]),
}

impl ChannelDomain {
    fn salt(self) -> &'static [u8] {
        match self {
            Self::C2        => b"cleitonq-c2-v1",
            Self::Telemetry => b"cleitonq-telemetry-v1",
            Self::Mesh      => b"cleitonq-mesh-v1",
            Self::Custom(s) => s,
        }
    }
}

/// An authenticated channel backed by a session key and HMAC-SHA3-256.
///
/// Construct one per logical channel (C2, telemetry, mesh) from the same
/// session key — domain separation ensures the derived keys are independent.
pub struct AuthChannel {
    key: Zeroizing<[u8; 32]>,
}

impl AuthChannel {
    /// Creates an authenticated channel from a session key and domain label.
    ///
    /// Derives a channel-specific key via `SHA3-256(session_key || domain_salt)`.
    pub fn new(session_key: &[u8; 32], domain: ChannelDomain) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(session_key);
        hasher.update(domain.salt());
        let digest = hasher.finalize();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&digest);
        Self { key }
    }

    /// Creates a channel directly from a pre-derived key (e.g. env var PSK).
    pub fn from_raw_key(key: [u8; 32]) -> Self {
        Self { key: Zeroizing::new(key) }
    }

    /// Signs `payload` with `nonce` and returns the full wire packet.
    ///
    /// The nonce must be strictly increasing across calls. Use an atomic
    /// counter or a monotonic clock in production.
    pub fn sign(&self, payload: &[u8], nonce: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(payload.len() + OVERHEAD);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&nonce.to_le_bytes());

        let mut mac = HmacSha3256::new_from_slice(self.key.as_ref())
            .expect("32-byte key is always valid for HMAC");
        mac.update(&buf);
        buf.extend_from_slice(&mac.finalize().into_bytes());
        buf
    }

    /// Verifies a packet and extracts `(payload, nonce)`.
    ///
    /// Returns `None` on any failure without revealing the reason.
    pub fn verify<'a>(&self, packet: &'a [u8], last_nonce: u64) -> Option<(&'a [u8], u64)> {
        if packet.len() < OVERHEAD {
            return None;
        }

        let tag_start   = packet.len() - 32;
        let nonce_start = tag_start - 8;

        let nonce = u64::from_le_bytes(packet[nonce_start..tag_start].try_into().ok()?);
        if nonce <= last_nonce {
            return None;
        }

        let mut mac = HmacSha3256::new_from_slice(self.key.as_ref())
            .expect("32-byte key is always valid for HMAC");
        mac.update(&packet[..tag_start]);
        mac.verify_slice(&packet[tag_start..]).ok()?;

        Some((&packet[..nonce_start], nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel_pair(domain: ChannelDomain) -> (AuthChannel, AuthChannel) {
        let key = [0x42u8; 32];
        (AuthChannel::new(&key, domain), AuthChannel::new(&key, domain))
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let payload = b"roll=1.5 pitch=0.0 yaw=-0.3 thrust=9.81";
        let packet = tx.sign(payload, 1);
        assert_eq!(packet.len(), payload.len() + OVERHEAD);
        let (data, nonce) = rx.verify(&packet, 0).expect("must succeed");
        assert_eq!(data, payload.as_ref());
        assert_eq!(nonce, 1);
    }

    #[test]
    fn test_replay_rejected() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let packet = tx.sign(b"critical_cmd", 10);
        assert!(rx.verify(&packet, 9).is_some());
        assert!(rx.verify(&packet, 10).is_none());
        assert!(rx.verify(&packet, 11).is_none());
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let (tx, rx) = channel_pair(ChannelDomain::Telemetry);
        let mut packet = tx.sign(b"altitude=50.0", 1);
        packet[0] ^= 0xFF;
        assert!(rx.verify(&packet, 0).is_none());
    }

    #[test]
    fn test_domain_separation() {
        let key = [0xABu8; 32];
        let c2   = AuthChannel::new(&key, ChannelDomain::C2);
        let mesh = AuthChannel::new(&key, ChannelDomain::Mesh);
        // A C2-signed packet must NOT verify on the mesh channel
        let packet = c2.sign(b"cmd", 1);
        assert!(mesh.verify(&packet, 0).is_none(), "cross-domain must fail");
    }

    #[test]
    fn test_empty_payload() {
        let (tx, rx) = channel_pair(ChannelDomain::C2);
        let packet = tx.sign(b"", 1);
        let (data, _) = rx.verify(&packet, 0).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_short_packet_rejected() {
        let (_, rx) = channel_pair(ChannelDomain::C2);
        assert!(rx.verify(&vec![0u8; OVERHEAD - 1], 0).is_none());
        assert!(rx.verify(&[], 0).is_none());
    }
}
