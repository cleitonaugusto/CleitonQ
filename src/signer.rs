//! Signing backend abstraction for ML-DSA-87.
//!
//! The `Signer` trait decouples signing callers from the key storage backend.
//! Production firmware selects the backend at build time:
//!
//! | Backend | Use case |
//! |---|---|
//! | `InMemorySigner` | Development, embedded, keys in Zeroizing RAM |
//! | `Pkcs11Signer` | HSM-backed key storage (requires `pkcs11` feature) |
//! | `Tpm2Signer` | TPM2 key storage on Cortex-A76 / RPi5 (future) |
//!
//! All backends produce the same wire format as `SigningKey::sign()`.

use alloc::vec::Vec;
use crate::dsa::{SigningKey, VerifyingKey};

/// Error returned by signing operations.
///
/// `InMemorySigner::sign()` always returns `Ok`. Error variants are
/// reserved for HSM/TPM2 backends where the key lives outside the process.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignerError {
    /// HSM returned an error (PKCS#11 or TPM2). Contains a human-readable message.
    Hsm(alloc::string::String),
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Hsm(msg) => write!(f, "HSM error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignerError {}

/// ML-DSA-87 signing backend.
///
/// Implementors must be `Send + Sync` — typical flight software authenticates
/// commands from a single thread, but the bound allows safe multi-threaded use.
pub trait Signer: Send + Sync {
    /// Signs `payload` with `nonce` and returns the full wire packet.
    ///
    /// Wire format: `[ payload | nonce_le8 | ml_dsa_sig_4627 ]`
    ///
    /// The nonce must be strictly increasing. Use `AtomicNonce` or
    /// `SimpleNonce` from `cleitonq::nonce` to generate nonces.
    fn sign(&self, payload: &[u8], nonce: u64) -> Result<Vec<u8>, SignerError>;

    /// Returns the verifying key corresponding to this signer.
    ///
    /// Used by the drone to pre-register the GCS public key.
    fn verifying_key(&self) -> VerifyingKey;
}

/// In-memory signing backend.
///
/// The ML-DSA-87 signing key lives in a `Zeroizing`-wrapped buffer and is
/// overwritten when this struct is dropped. Suitable for:
///
/// - Embedded companion computers where key is loaded from HSM at boot
/// - Development environments
/// - Environments without PKCS#11/TPM2 support
pub struct InMemorySigner {
    key: SigningKey,
}

impl InMemorySigner {
    /// Wraps an existing signing key.
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// Constructs from a 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, crate::dsa::Error> {
        Ok(Self { key: SigningKey::from_seed_bytes(seed)? })
    }

    /// Returns a reference to the underlying `SigningKey` for cases where
    /// direct access is required (e.g., key rotation, ceremony tooling).
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

impl Signer for InMemorySigner {
    fn sign(&self, payload: &[u8], nonce: u64) -> Result<Vec<u8>, SignerError> {
        Ok(self.key.sign(payload, nonce))
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::VerifyingKey;

    #[test]
    fn test_in_memory_signer_roundtrip() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let signer = InMemorySigner::new(sk);

        let packet = signer.sign(b"ARM 1", 42).unwrap();
        let (payload, nonce) = vk.verify(&packet, 0).expect("valid signature");
        assert_eq!(payload, b"ARM 1");
        assert_eq!(nonce, 42);
    }

    #[test]
    fn test_in_memory_signer_from_seed() {
        let seed = [0x42u8; 32];
        let s1 = InMemorySigner::from_seed(&seed).unwrap();
        let s2 = InMemorySigner::from_seed(&seed).unwrap();

        let vk: VerifyingKey = s1.verifying_key();
        let packet = s2.sign(b"HOLD", 1).unwrap();
        assert!(vk.verify(&packet, 0).is_some());
    }

    #[test]
    fn test_signer_replay_rejected() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let signer = InMemorySigner::new(sk);

        let packet = signer.sign(b"DISARM", 10).unwrap();
        assert!(vk.verify(&packet, 10).is_none()); // nonce 10 not > last_accepted 10
        assert!(vk.verify(&packet, 9).is_some());  // 10 > 9 — accepted
    }

    #[test]
    fn test_signer_trait_object() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let signer: Box<dyn Signer> = Box::new(InMemorySigner::new(sk));

        let packet = signer.sign(b"WAYPOINT", 5).unwrap();
        assert!(vk.verify(&packet, 0).is_some());
    }
}
