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
//! | `drone_kem_dk.bin` | Drone only (PRIVATE) | 64-byte seed for decapsulation key |
//!
//! # Example (std)
//!
//! ```no_run
//! use cleitonq::kem::{KemKeyPair, encapsulate, decapsulate};
//!
//! let keypair = KemKeyPair::generate();
//! keypair.save("drone_kem_dk.bin", "drone_kem_ek.bin").unwrap();
//!
//! let (ciphertext, session_key) = encapsulate("drone_kem_ek.bin").unwrap();
//!
//! let dk = KemKeyPair::load_decapsulation_key("drone_kem_dk.bin").unwrap();
//! let session_key = decapsulate(&dk, &ciphertext).unwrap();
//! ```
//!
//! # Example (no_std + alloc)
//!
//! ```ignore
//! use cleitonq::kem::{KemKeyPair, encapsulate_raw_with_rng, decapsulate_from_seed};
//!
//! // Key generation uses hardware RNG on embedded
//! let mut hw_rng = /* your CryptoRng impl */;
//! let keypair = KemKeyPair::generate_from_rng(&mut hw_rng);
//! let dk_seed = keypair.dk_seed_bytes().unwrap();
//! let ek_bytes = keypair.ek_bytes();
//!
//! // Session establishment
//! let (ciphertext, session_key) = encapsulate_raw_with_rng(&ek_bytes, &mut hw_rng).unwrap();
//! let session_key = decapsulate_from_seed(&dk_seed, &ciphertext).unwrap();
//! ```

use alloc::vec::Vec;
use core::fmt;
use ml_kem::{
    kem::{Encapsulate, TryDecapsulate},
    DecapsulationKey, EncapsulationKey, Kem, KeyExport, MlKem1024,
};
use zeroize::Zeroizing;

/// Size of the ML-KEM-1024 public encapsulation key in bytes.
pub const EK_BYTES: usize = 1568;
/// Size of the decapsulation key seed stored on disk (FIPS 203: d || z, two 32-byte values).
pub const DK_SEED_BYTES: usize = 64;
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
    #[cfg(feature = "std")]
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate_keypair();
        Self { dk, ek }
    }

    /// Generates a fresh ML-KEM-1024 key pair using the provided CSPRNG.
    ///
    /// Use this on embedded targets that provide their own hardware RNG.
    pub fn generate_from_rng<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng,
    {
        let (dk, ek) = MlKem1024::generate_keypair_from_rng(rng);
        Self { dk, ek }
    }

    /// Returns the DK seed bytes (64 bytes: d‖z) without writing to disk.
    pub fn dk_seed_bytes(&self) -> Result<[u8; DK_SEED_BYTES], Error> {
        let seed = self.dk.to_seed().ok_or(Error::KeyExport)?;
        let mut out = [0u8; DK_SEED_BYTES];
        out.copy_from_slice(&seed[..]);
        Ok(out)
    }

    /// Returns the encapsulation key bytes (1568 bytes).
    pub fn ek_bytes(&self) -> Vec<u8> {
        self.ek.to_bytes()[..].to_vec()
    }

    /// Saves the key pair to disk.
    #[cfg(feature = "std")]
    pub fn save(&self, dk_path: &str, ek_path: &str) -> Result<(), Error> {
        let seed = self.dk.to_seed().ok_or(Error::KeyExport)?;
        std::fs::write(dk_path, &seed[..]).map_err(Error::Io)?;
        let ek_bytes = self.ek.to_bytes();
        std::fs::write(ek_path, &ek_bytes[..]).map_err(Error::Io)?;
        Ok(())
    }

    /// Loads the decapsulation key from a 64-byte seed file.
    #[cfg(feature = "std")]
    pub fn load_decapsulation_key(dk_path: &str) -> Result<DecapsulationKey<MlKem1024>, Error> {
        let bytes = std::fs::read(dk_path).map_err(Error::Io)?;
        let seed = ml_kem::array::Array::try_from(bytes.as_slice())
            .map_err(|_| Error::InvalidKey)?;
        Ok(DecapsulationKey::<MlKem1024>::from_seed(seed))
    }

    /// Loads the encapsulation key from a 1568-byte file.
    #[cfg(feature = "std")]
    pub fn load_encapsulation_key(ek_path: &str) -> Result<EncapsulationKey<MlKem1024>, Error> {
        let bytes = std::fs::read(ek_path).map_err(Error::Io)?;
        let arr: ml_kem::kem::Key<EncapsulationKey<MlKem1024>> =
            ml_kem::array::Array::try_from(bytes.as_slice())
                .map_err(|_| Error::InvalidKey)?;
        EncapsulationKey::<MlKem1024>::new(&arr)
            .map_err(|_| Error::InvalidKey)
    }
}

/// Ground station: encapsulate a fresh session key using the drone's public key from a file.
///
/// Returns `(ciphertext, session_key)`.
#[cfg(feature = "std")]
pub fn encapsulate(ek_path: &str) -> Result<(Vec<u8>, SessionKey), Error> {
    let ek = KemKeyPair::load_encapsulation_key(ek_path)?;
    let (ct, ss) = ek.encapsulate();
    let mut key = Zeroizing::new([0u8; SESSION_KEY_BYTES]);
    key.copy_from_slice(ss.as_ref());
    Ok((ct[..].to_vec(), key))
}

/// Encapsulate using raw EK bytes and OS CSPRNG (no file I/O).
#[cfg(feature = "std")]
pub fn encapsulate_raw(ek_bytes: &[u8]) -> Result<(Vec<u8>, SessionKey), Error> {
    let arr = ml_kem::array::Array::try_from(ek_bytes)
        .map_err(|_| Error::InvalidKey)?;
    let ek = EncapsulationKey::<MlKem1024>::new(&arr)
        .map_err(|_| Error::InvalidKey)?;
    let (ct, ss) = ek.encapsulate();
    let mut key = Zeroizing::new([0u8; SESSION_KEY_BYTES]);
    key.copy_from_slice(ss.as_ref());
    Ok((ct[..].to_vec(), key))
}

/// Encapsulate using raw EK bytes and a caller-provided CSPRNG.
///
/// Available in `no_std + alloc` contexts. Pass a hardware RNG on embedded.
pub fn encapsulate_raw_with_rng<R>(
    ek_bytes: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, SessionKey), Error>
where
    R: rand_core::CryptoRng + ?Sized,
{
    let arr = ml_kem::array::Array::try_from(ek_bytes)
        .map_err(|_| Error::InvalidKey)?;
    let ek = EncapsulationKey::<MlKem1024>::new(&arr)
        .map_err(|_| Error::InvalidKey)?;
    let (ct, ss) = ek.encapsulate_with_rng(rng);
    let mut key = Zeroizing::new([0u8; SESSION_KEY_BYTES]);
    key.copy_from_slice(ss.as_ref());
    Ok((ct[..].to_vec(), key))
}

/// Decapsulate using raw DK seed bytes (no file I/O).
pub fn decapsulate_from_seed(dk_seed: &[u8], ciphertext: &[u8]) -> Result<SessionKey, Error> {
    let seed = ml_kem::array::Array::try_from(dk_seed)
        .map_err(|_| Error::InvalidKey)?;
    let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
    decapsulate(&dk, ciphertext)
}

/// Drone: decapsulate the session key from the ground station's ciphertext.
pub fn decapsulate(
    dk: &DecapsulationKey<MlKem1024>,
    ciphertext: &[u8],
) -> Result<SessionKey, Error> {
    use ml_kem::Ciphertext;
    let ct = Ciphertext::<MlKem1024>::try_from(ciphertext)
        .map_err(|_| Error::Decapsulation)?;
    let ss = dk.try_decapsulate(&ct)
        .map_err(|_| Error::Decapsulation)?;
    let mut key = Zeroizing::new([0u8; SESSION_KEY_BYTES]);
    key.copy_from_slice(ss.as_ref());
    Ok(key)
}

/// Errors from KEM operations.
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "std")]
    Io(std::io::Error),
    InvalidKey,
    KeyExport,
    Decapsulation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::KeyExport => write!(f, "failed to export decapsulation key seed"),
            Self::Decapsulation => write!(f, "decapsulation failed"),
        }
    }
}

#[cfg(feature = "std")]
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
        let k_wrong = dk.try_decapsulate(&ct).unwrap();
        assert_ne!(ss_bytes(&k_real), ss_bytes(&k_wrong));
    }

    #[cfg(feature = "std")]
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
