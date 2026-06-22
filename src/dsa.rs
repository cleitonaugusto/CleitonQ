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

use alloc::vec::Vec;
use core::fmt;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey,
    Generate, Keypair, MlDsa87, Signer, Verifier,
};

/// Write secret key material to disk with owner-only permissions (0600).
#[cfg(feature = "std")]
fn write_secret_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

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
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        Self(ml_dsa::SigningKey::<MlDsa87>::generate())
    }

    /// Generates a fresh ML-DSA-87 signing key using the provided CSPRNG.
    ///
    /// Use this on embedded targets that provide their own hardware RNG.
    pub fn generate_from_rng<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng,
    {
        Self(ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(rng))
    }

    /// Constructs a signing key from a 32-byte seed (C API / in-memory use).
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self, Error> {
        let s = ml_dsa::Seed::try_from(seed)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self(ml_dsa::SigningKey::<MlDsa87>::from_seed(&s)))
    }

    /// Returns the 32-byte seed that can reconstruct this signing key.
    pub fn to_seed_bytes(&self) -> [u8; SK_SEED_BYTES] {
        let seed = self.0.to_seed();
        let mut out = [0u8; SK_SEED_BYTES];
        out.copy_from_slice(&seed[..]);
        out
    }

    /// Loads a signing key from a 32-byte seed file.
    #[cfg(feature = "std")]
    pub fn load(path: &str) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        let seed = ml_dsa::Seed::try_from(bytes.as_slice())
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self(ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed)))
    }

    /// Saves the signing key seed to disk with owner-only permissions (0600).
    #[cfg(feature = "std")]
    pub fn save(&self, path: &str) -> Result<(), Error> {
        let seed = self.0.to_seed();
        write_secret_file(path, &seed[..]).map_err(Error::Io)
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
    /// Constructs a verifying key from raw 2592-byte encoding (C API / in-memory use).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(bytes)
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self(ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded)))
    }

    /// Returns the raw 2592-byte verifying key encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let encoded: EncodedVerifyingKey<MlDsa87> = self.0.encode();
        let bytes: &[u8] = encoded.as_ref();
        bytes.to_vec()
    }

    /// Loads a verifying key from a 2592-byte file.
    #[cfg(feature = "std")]
    pub fn load(path: &str) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(bytes.as_slice())
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self(ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded)))
    }

    /// Saves the verifying key to a file.
    #[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
    Io(std::io::Error),
    InvalidKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidKey => write!(f, "invalid key"),
        }
    }
}

#[cfg(feature = "std")]
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
        assert!(vk.verify(&alloc::vec![0u8; OVERHEAD - 1], 0).is_none());
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
    fn test_from_seed_bytes_roundtrip() {
        let sk = SigningKey::generate();
        let seed = sk.to_seed_bytes();
        let sk2 = SigningKey::from_seed_bytes(&seed).unwrap();
        let vk = sk2.verifying_key();
        let packet = sk2.sign(b"hello", 1);
        assert!(vk.verify(&packet, 0).is_some());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_save_load_roundtrip() {
        let pid = std::process::id();
        let sk_path = format!("/tmp/cleitonq_test_sk_{pid}.bin");
        let vk_path = format!("/tmp/cleitonq_test_vk_{pid}.bin");

        let sk = SigningKey::generate();
        sk.save(&sk_path).unwrap();
        sk.verifying_key().save(&vk_path).unwrap();

        let sk2 = SigningKey::load(&sk_path).unwrap();
        let vk2 = VerifyingKey::load(&vk_path).unwrap();

        let packet = sk2.sign(b"hello", 1);
        assert!(vk2.verify(&packet, 0).is_some());

        std::fs::remove_file(&sk_path).ok();
        std::fs::remove_file(&vk_path).ok();
    }

    // ── NIST API-layer determinism tests ──────────────────────────────────
    //
    // The underlying ml-dsa crate is tested against the official NIST FIPS 204
    // Known Answer Tests (KATs) in its own CI. These tests verify that our API
    // layer (seed round-trip, nonce enforcement, wire format) does not corrupt
    // the cryptographic operations.

    #[test]
    fn keygen_from_seed_is_deterministic() {
        let seed = [0x42u8; SK_SEED_BYTES];
        let sk1 = SigningKey::from_seed_bytes(&seed).unwrap();
        let sk2 = SigningKey::from_seed_bytes(&seed).unwrap();
        assert_eq!(sk1.verifying_key().to_bytes(), sk2.verifying_key().to_bytes());
    }

    #[test]
    fn known_vk_prefix_for_fixed_seed() {
        // Fixed seed → deterministic verifying key. Verifies our from_seed_bytes
        // wrapper does not permute or truncate bytes before passing to ml-dsa.
        let seed = [0x42u8; SK_SEED_BYTES];
        let sk = SigningKey::from_seed_bytes(&seed).unwrap();
        let vk = sk.verifying_key().to_bytes();
        // First 16 bytes of vk for seed=[0x42;32] — regenerate with gen_kat if ml-dsa is updated.
        let expected_prefix = [
            0x8a, 0x9d, 0x3f, 0x21, 0xd2, 0xe9, 0xcb, 0xbd,
            0xc7, 0x5e, 0xf8, 0xf9, 0x3f, 0xbd, 0x6f, 0xf4,
        ];
        assert_eq!(&vk[..16], &expected_prefix);
        assert_eq!(vk.len(), VK_BYTES);
    }

    #[test]
    fn sign_verify_nonce_strictly_enforced() {
        let seed = [0x11u8; SK_SEED_BYTES];
        let sk = SigningKey::from_seed_bytes(&seed).unwrap();
        let vk = sk.verifying_key();
        let payload = b"waypoint lat=10.0 lon=20.0 alt=100.0";

        let p1 = sk.sign(payload, 1);
        let p5 = sk.sign(payload, 5);

        assert!(vk.verify(&p1, 0).is_some());
        assert!(vk.verify(&p5, 1).is_some());
        assert!(vk.verify(&p1, 1).is_none());
        assert!(vk.verify(&p5, 5).is_none());
    }

    #[test]
    fn wire_format_length_is_predictable() {
        let seed = [0x22u8; SK_SEED_BYTES];
        let sk = SigningKey::from_seed_bytes(&seed).unwrap();
        let payload = b"arm drone-alpha";
        let packet = sk.sign(payload, 1);
        assert_eq!(packet.len(), payload.len() + 8 + SIG_BYTES);
    }
}
