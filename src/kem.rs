// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! ML-KEM-1024 session key establishment (NIST FIPS 203).
//!
//! Provides forward-secret session keys for authenticating C2 channels.
//! The ground station encapsulates a 32-byte session key using the drone's
//! public encapsulation key; the drone decapsulates it. Both sides then use
//! the shared secret to derive per-channel HMAC keys.
//!
//! # Key storage
//!
//! | File | Who holds it | Content |
//! |---|---|---|
//! | `drone_kem_ek.bin` | Drone + GS copy | 1568-byte public encapsulation key |
//! | `drone_kem_dk.bin` | Drone only (PRIVATE) | 32-byte seed for decapsulation key |
//!
//! # Example
//!
//! ```no_run
//! use cleitonq::kem::{KemKeyPair, encapsulate, decapsulate};
//!
//! // --- Key generation (run once before deployment) ---
//! let keypair = KemKeyPair::generate();
//! keypair.save("drone_kem_dk.bin", "drone_kem_ek.bin").unwrap();
//!
//! // --- Ground station: establish session ---
//! let (ciphertext, session_key) = encapsulate("drone_kem_ek.bin").unwrap();
//!
//! // --- Drone: recover session key ---
//! let dk = KemKeyPair::load_decapsulation_key("drone_kem_dk.bin").unwrap();
//! let session_key = decapsulate(&dk, &ciphertext).unwrap();
//! ```

use ml_kem::{
    kem::{Encapsulate, TryDecapsulate},
    DecapsulationKey, EncapsulationKey, Kem, KeyExport, MlKem1024,
};
use zeroize::Zeroizing;

/// Size of the ML-KEM-1024 public encapsulation key in bytes.
pub const EK_BYTES: usize = 1568;
/// Size of the decapsulation key seed stored on disk (derives the full key).
pub const DK_SEED_BYTES: usize = 32;
/// Size of the established shared secret (session key).
pub const SESSION_KEY_BYTES: usize = 32;

/// A zeroized 32-byte session key derived from ML-KEM encapsulation.
pub type SessionKey = Zeroizing<[u8; SESSION_KEY_BYTES]>;

/// An ML-KEM-1024 key pair.
pub struct KemKeyPair {
    dk: DecapsulationKey<MlKem1024>,
    ek: EncapsulationKey<MlKem1024>,
}

impl KemKeyPair {
    /// Generates a fresh ML-KEM-1024 key pair using the OS CSPRNG.
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate_keypair();
        Self { dk, ek }
    }

    /// Saves the key pair to disk.
    ///
    /// `dk_path` — private seed (32 bytes). Keep on the drone only.
    /// `ek_path` — public encapsulation key (1568 bytes). Share with ground station.
    pub fn save(&self, dk_path: &str, ek_path: &str) -> Result<(), Error> {
        let seed = self.dk.to_seed().ok_or(Error::KeyExport)?;
        std::fs::write(dk_path, &seed[..]).map_err(Error::Io)?;
        let ek_bytes = self.ek.to_bytes();
        std::fs::write(ek_path, &ek_bytes[..]).map_err(Error::Io)?;
        Ok(())
    }

    /// Loads the decapsulation key from a 32-byte seed file.
    pub fn load_decapsulation_key(dk_path: &str) -> Result<DecapsulationKey<MlKem1024>, Error> {
        let bytes = std::fs::read(dk_path).map_err(Error::Io)?;
        let seed = ml_kem::array::Array::try_from(bytes.as_slice())
            .map_err(|_| Error::InvalidKey(format!(
                "{dk_path}: expected {DK_SEED_BYTES} bytes, got {}", bytes.len()
            )))?;
        Ok(DecapsulationKey::<MlKem1024>::from_seed(seed))
    }

    /// Loads the encapsulation key from a 1568-byte file.
    pub fn load_encapsulation_key(ek_path: &str) -> Result<EncapsulationKey<MlKem1024>, Error> {
        let bytes = std::fs::read(ek_path).map_err(Error::Io)?;
        let arr: ml_kem::kem::Key<EncapsulationKey<MlKem1024>> =
            ml_kem::array::Array::try_from(bytes.as_slice())
                .map_err(|_| Error::InvalidKey(format!(
                    "{ek_path}: expected {EK_BYTES} bytes, got {}", bytes.len()
                )))?;
        EncapsulationKey::<MlKem1024>::new(&arr)
            .map_err(|e| Error::InvalidKey(format!("invalid encapsulation key: {e}")))
    }
}

/// Ground station: encapsulate a fresh session key using the drone's public key.
///
/// Returns `(ciphertext, session_key)`. Send `ciphertext` to the drone over any
/// channel (it reveals nothing about `session_key`). Zeroize `session_key` after
/// passing it to [`crate::channel::AuthChannel`].
pub fn encapsulate(ek_path: &str) -> Result<(Vec<u8>, SessionKey), Error> {
    let ek = KemKeyPair::load_encapsulation_key(ek_path)?;
    let (ct, ss) = ek.encapsulate();
    let mut key = Zeroizing::new([0u8; SESSION_KEY_BYTES]);
    key.copy_from_slice(ss.as_ref());
    Ok((ct[..].to_vec(), key))
}

/// Drone: decapsulate the session key from the ground station's ciphertext.
pub fn decapsulate(
    dk: &DecapsulationKey<MlKem1024>,
    ciphertext: &[u8],
) -> Result<SessionKey, Error> {
    use ml_kem::Ciphertext;
    let ct = Ciphertext::<MlKem1024>::try_from(ciphertext)
        .map_err(|e| Error::Decapsulation(format!("{e}")))?;
    let ss = dk.try_decapsulate(&ct)
        .map_err(|e| Error::Decapsulation(format!("{e}")))?;
    let mut key = Zeroizing::new([0u8; SESSION_KEY_BYTES]);
    key.copy_from_slice(ss.as_ref());
    Ok(key)
}

/// Errors from KEM operations.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidKey(String),
    KeyExport,
    Decapsulation(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidKey(s) => write!(f, "invalid key: {s}"),
            Self::KeyExport => write!(f, "failed to export decapsulation key seed"),
            Self::Decapsulation(s) => write!(f, "decapsulation failed: {s}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn ss_bytes(ss: &impl AsRef<[u8]>) -> Vec<u8> {
        ss.as_ref().to_vec()
    }

    #[test]
    fn test_encap_decap_shared_secret_matches() {
        let (dk, ek) = MlKem1024::generate_keypair();
        let (ct, k_gs) = ek.encapsulate();
        let k_drone = dk.try_decapsulate(&ct).expect("decapsulation must succeed");
        assert_eq!(ss_bytes(&k_gs), ss_bytes(&k_drone), "shared secrets must match");
    }

    #[test]
    fn test_wrong_ciphertext_produces_different_key() {
        let (dk, ek) = MlKem1024::generate_keypair();
        let (mut ct, k_real) = ek.encapsulate();
        ct[0] ^= 0xFF;
        // ML-KEM is implicitly rejection-sampled — wrong CT yields a different
        // (but still valid-looking) key, not an error. This is by design (IND-CCA2).
        let k_wrong = dk.try_decapsulate(&ct).unwrap();
        assert_ne!(ss_bytes(&k_real), ss_bytes(&k_wrong));
    }

    #[test]
    fn test_keypair_save_load_roundtrip() {
        use std::fs;
        let keypair = KemKeyPair::generate();
        let dk_path = "/tmp/cleitonq_test_dk.bin";
        let ek_path = "/tmp/cleitonq_test_ek.bin";
        keypair.save(dk_path, ek_path).unwrap();

        let dk = KemKeyPair::load_decapsulation_key(dk_path).unwrap();
        let ek = KemKeyPair::load_encapsulation_key(ek_path).unwrap();

        let (ct, k_gs) = ek.encapsulate();
        let k_drone = dk.try_decapsulate(&ct).unwrap();
        assert_eq!(ss_bytes(&k_gs), ss_bytes(&k_drone));

        fs::remove_file(dk_path).ok();
        fs::remove_file(ek_path).ok();
    }
}
