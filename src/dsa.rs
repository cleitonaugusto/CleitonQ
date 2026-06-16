// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! ML-DSA-87 command signing and verification (NIST FIPS 204).
//!
//! Provides unforgeable, quantum-resistant signatures for C2 commands and
//! waypoints. The ground station holds the private signing key; every drone
//! holds only the public verifying key. A valid signature proves the command
//! came from an authorised ground station — even against an adversary with a
//! quantum computer.
//!
//! Anti-replay is enforced via a monotonically-increasing `u64` nonce embedded
//! in every signed packet. The receiver rejects any packet whose nonce is not
//! strictly greater than the last accepted nonce.
//!
//! # Packet wire format
//!
//! ```text
//! [ payload (N bytes) | nonce (8 bytes LE) | ML-DSA-87 signature (4627 bytes) ]
//! ```
//!
//! # Example
//!
//! ```no_run
//! use cleitonq::dsa::{SigningKey, VerifyingKey};
//!
//! // Key generation (ground station, run once)
//! let sk = SigningKey::generate();
//! sk.save("gs_signing.bin").unwrap();
//! sk.verifying_key().save("gs_verifying.bin").unwrap();
//!
//! // Ground station: sign a command
//! let packet = sk.sign(b"thrust=9.81 roll=0.0", 1);
//!
//! // Drone: verify
//! let vk = VerifyingKey::load("gs_verifying.bin").unwrap();
//! let (payload, nonce) = vk.verify(&packet, 0).expect("invalid signature");
//! assert_eq!(payload, b"thrust=9.81 roll=0.0");
//! assert_eq!(nonce, 1);
//! ```

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey,
    Generate, Keypair, MlDsa87, Signer, Verifier,
};

/// Size of an ML-DSA-87 signature in bytes (FIPS 204, Table 1).
pub const SIG_BYTES: usize = 4627;
/// Size of the ML-DSA-87 verifying key in bytes.
pub const VK_BYTES: usize = 2592;
/// Size of the ML-DSA-87 signing key seed stored on disk.
pub const SK_SEED_BYTES: usize = 32;
/// Per-packet overhead: 8-byte nonce + ML-DSA-87 signature.
pub const OVERHEAD: usize = 8 + SIG_BYTES;

/// ML-DSA-87 signing key (ground station side — keep private).
pub struct SigningKey(ml_dsa::SigningKey<MlDsa87>);

impl SigningKey {
    /// Generates a fresh ML-DSA-87 signing key using the OS CSPRNG.
    pub fn generate() -> Self {
        Self(ml_dsa::SigningKey::<MlDsa87>::generate())
    }

    /// Loads a signing key from a 32-byte seed file.
    pub fn load(path: &str) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        let seed = ml_dsa::Seed::try_from(bytes.as_slice())
            .map_err(|_| Error::InvalidKey(format!(
                "{path}: expected {SK_SEED_BYTES} bytes, got {}", bytes.len()
            )))?;
        Ok(Self(ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed)))
    }

    /// Saves the signing key seed to disk.
    pub fn save(&self, path: &str) -> Result<(), Error> {
        let seed = self.0.to_seed();
        std::fs::write(path, &seed[..]).map_err(Error::Io)
    }

    /// Returns the corresponding verifying key (safe to distribute to drones).
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Signs `payload` with `nonce` and returns the full wire packet:
    /// `[payload | nonce_le8 | ml_dsa_sig]`.
    pub fn sign(&self, payload: &[u8], nonce: u64) -> Vec<u8> {
        let mut to_sign: Vec<u8> = Vec::with_capacity(payload.len() + 8);
        to_sign.extend_from_slice(payload);
        to_sign.extend_from_slice(&nonce.to_le_bytes());

        let sig: ml_dsa::Signature<MlDsa87> = self.0.sign(&to_sign);
        let encoded: EncodedSignature<MlDsa87> = sig.encode();

        let mut packet = to_sign;
        packet.extend_from_slice(encoded.as_ref());
        packet
    }
}

/// ML-DSA-87 verifying key (drone side — public, distribute freely).
pub struct VerifyingKey(ml_dsa::VerifyingKey<MlDsa87>);

impl VerifyingKey {
    /// Loads a verifying key from a 2592-byte file.
    pub fn load(path: &str) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(bytes.as_slice())
            .map_err(|_| Error::InvalidKey(format!(
                "{path}: expected {VK_BYTES} bytes, got {}", bytes.len()
            )))?;
        Ok(Self(ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded)))
    }

    /// Saves the verifying key to a file.
    pub fn save(&self, path: &str) -> Result<(), Error> {
        let encoded = self.0.encode();
        let bytes: &[u8] = encoded.as_ref();
        std::fs::write(path, bytes).map_err(Error::Io)
    }

    /// Verifies a signed packet and extracts `(payload, nonce)`.
    ///
    /// Returns `None` on any failure without revealing the reason (timing-safe).
    /// Only returns `Some` when:
    /// - The packet is long enough to contain a signature and nonce.
    /// - The ML-DSA-87 signature is valid over `[payload | nonce]`.
    /// - `nonce > last_nonce` (strict anti-replay).
    pub fn verify<'a>(&self, packet: &'a [u8], last_nonce: u64) -> Option<(&'a [u8], u64)> {
        if packet.len() < OVERHEAD {
            return None;
        }

        let sig_start   = packet.len() - SIG_BYTES;
        let nonce_start = sig_start - 8;

        let signed_data = &packet[..sig_start];
        let sig_bytes   = &packet[sig_start..];

        let encoded = EncodedSignature::<MlDsa87>::try_from(sig_bytes).ok()?;
        let sig = ml_dsa::Signature::<MlDsa87>::decode(&encoded)?;
        self.0.verify(signed_data, &sig).ok()?;

        let nonce = u64::from_le_bytes(packet[nonce_start..sig_start].try_into().ok()?);
        if nonce <= last_nonce {
            return None;
        }

        Some((&packet[..nonce_start], nonce))
    }
}

/// Errors from DSA operations.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidKey(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidKey(s) => write!(f, "invalid key: {s}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, vk) = keypair();
        let payload = b"thrust=9.81 roll=0.0 pitch=0.0 yaw=0.0";
        let packet = sk.sign(payload, 1);
        assert_eq!(packet.len(), payload.len() + OVERHEAD);
        let (recovered, nonce) = vk.verify(&packet, 0).expect("valid signature must pass");
        assert_eq!(recovered, payload.as_ref());
        assert_eq!(nonce, 1);
    }

    #[test]
    fn test_replay_rejected() {
        let (sk, vk) = keypair();
        let packet = sk.sign(b"cmd", 5);
        assert!(vk.verify(&packet, 4).is_some(), "nonce 5 > 4: must accept");
        assert!(vk.verify(&packet, 5).is_none(), "nonce 5 == 5: replay");
        assert!(vk.verify(&packet, 6).is_none(), "nonce 5 < 6: replay");
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let (sk, vk) = keypair();
        let mut packet = sk.sign(b"thrust=0.0", 1);
        packet[0] ^= 0xFF;
        assert!(vk.verify(&packet, 0).is_none());
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (sk, vk) = keypair();
        let mut packet = sk.sign(b"waypoint=100,80,50", 1);
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        assert!(vk.verify(&packet, 0).is_none());
    }

    #[test]
    fn test_short_packet_rejected() {
        let (_, vk) = keypair();
        assert!(vk.verify(&vec![0u8; OVERHEAD - 1], 0).is_none());
        assert!(vk.verify(&[], 0).is_none());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (sk, _) = keypair();
        let (_, vk_other) = keypair();
        let packet = sk.sign(b"cmd", 1);
        assert!(vk_other.verify(&packet, 0).is_none());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let sk = SigningKey::generate();
        let sk_path = "/tmp/cleitonq_test_sk.bin";
        let vk_path = "/tmp/cleitonq_test_vk.bin";
        sk.save(sk_path).unwrap();
        sk.verifying_key().save(vk_path).unwrap();

        let sk2 = SigningKey::load(sk_path).unwrap();
        let vk2 = VerifyingKey::load(vk_path).unwrap();

        let packet = sk2.sign(b"hello", 1);
        assert!(vk2.verify(&packet, 0).is_some());

        std::fs::remove_file(sk_path).ok();
        std::fs::remove_file(vk_path).ok();
    }
}
