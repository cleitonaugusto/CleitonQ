//! Hybrid Classical/PQC key establishment — Phase 5.
//!
//! Combines X25519 (classical) with ML-KEM-1024 (post-quantum) so an attacker
//! must break BOTH algorithms to compromise a session. Follows NIST SP 800-227
//! (concatenation combiner for hybrid key encapsulation).
//!
//! # Protocol (static X25519 + ephemeral ML-KEM)
//!
//! Both parties have static X25519 key pairs provisioned before the mission.
//! ML-KEM is ephemeral per session (provides PQ forward secrecy).
//!
//! ```text
//! GCS:   x25519_ss = X25519(gcs_sk, drone_x25519_pk)
//! GCS:   (ct, ml_kem_ss) = ML-KEM-1024.Encapsulate(drone_ml_kem_ek)
//! GCS:   session_key = KDF(x25519_ss ∥ ml_kem_ss)   → send ct
//!
//! Drone: x25519_ss = X25519(drone_sk, gcs_x25519_pk)
//! Drone: ml_kem_ss = ML-KEM-1024.Decapsulate(ct, drone_dk)
//! Drone: session_key = KDF(x25519_ss ∥ ml_kem_ss)   → same key
//! ```
//!
//! No extra round-trips versus PQ-only (ML-KEM ciphertext already required).
//!
//! # Security properties
//!
//! | Property | PQ-only | Hybrid |
//! |---|---|---|
//! | Quantum-safe session key | ✓ | ✓ |
//! | Classical hardness (X25519) | — | ✓ |
//! | PQ forward secrecy (ML-KEM ephemeral) | ✓ | ✓ |
//! | Classical forward secrecy | — | only if X25519 is ephemeral |
//!
//! Static X25519 does NOT provide classical forward secrecy — if the GCS
//! X25519 static key is compromised, past sessions are exposed to a classical
//! attacker. ML-KEM provides PQ forward secrecy regardless.
//! For deployments requiring classical forward secrecy, rotate X25519 keys
//! per-mission (treat them as medium-term rather than static).

use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// Type alias for clarity — a 32-byte session key in Zeroizing storage.
pub type SessionKey = Zeroizing<[u8; 32]>;

/// Domain separation label for the hybrid KDF (NIST SP 800-227 §4.3.1).
const HYBRID_DOMAIN: &[u8] = b"cleitonq-hybrid-v1";

// ── Key establishment mode ────────────────────────────────────────────────────

/// Key establishment algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HybridMode {
    /// ML-KEM-1024 only. Default; use when X25519 infrastructure not deployed.
    PqOnly = 0,
    /// X25519 + ML-KEM-1024. Recommended during classical-to-PQ transition.
    Hybrid = 1,
    /// X25519 only. Emergency fallback if a PQ algorithm is found broken.
    ClassicOnly = 2,
}

impl core::fmt::Display for HybridMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PqOnly      => f.write_str("pq-only"),
            Self::Hybrid      => f.write_str("hybrid"),
            Self::ClassicOnly => f.write_str("classic-only"),
        }
    }
}

// ── KeyEstablishment trait ────────────────────────────────────────────────────

/// Abstraction over session key establishment backends.
///
/// Implementations: `MlKemEstablishment` (current), `HybridEstablishment`
/// (X25519 + ML-KEM), `QkdEstablishment` (ETSI QKD), `PskEstablishment`
/// (pre-shared key emergency fallback).
pub trait KeyEstablishment {
    type Error: core::fmt::Debug + core::fmt::Display;
    type Ciphertext;

    /// Initiator (GCS) side: produce a ciphertext and session key.
    fn encapsulate(&self) -> Result<(Self::Ciphertext, SessionKey), Self::Error>;

    /// Responder (drone) side: recover the session key from the ciphertext.
    fn decapsulate(&self, ct: &Self::Ciphertext) -> Result<SessionKey, Self::Error>;

    /// The mode this implementation operates in.
    fn mode(&self) -> HybridMode;
}

// ── KDF ───────────────────────────────────────────────────────────────────────

/// Derive hybrid session key from X25519 and ML-KEM shared secrets.
///
/// `SHA3-256(x25519_ss ∥ ml_kem_ss ∥ "cleitonq-hybrid-v1")`
///
/// This is the NIST SP 800-227 concatenation combiner. Secure as long as
/// EITHER component (x25519_ss OR ml_kem_ss) is pseudo-random.
pub fn derive_hybrid_session_key(x25519_ss: &[u8; 32], ml_kem_ss: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(x25519_ss);
    h.update(ml_kem_ss);
    h.update(HYBRID_DOMAIN);
    h.finalize().into()
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum HybridError {
    InvalidPublicKey,
    InvalidCiphertext,
    Encapsulation,
    Decapsulation,
}

impl core::fmt::Display for HybridError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKey  => f.write_str("invalid X25519 public key"),
            Self::InvalidCiphertext => f.write_str("invalid ML-KEM ciphertext"),
            Self::Encapsulation     => f.write_str("ML-KEM encapsulation failed"),
            Self::Decapsulation     => f.write_str("ML-KEM decapsulation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HybridError {}

// ── Hybrid encapsulator (GCS side, requires `hybrid` feature) ─────────────────

#[cfg(feature = "hybrid")]
/// GCS-side hybrid key establishment (X25519 static + ML-KEM-1024 ephemeral).
pub struct HybridEncapsulator {
    x25519_sk: x25519_dalek::StaticSecret,
    peer_x25519_pk: x25519_dalek::PublicKey,
    peer_ml_kem_ek: Vec<u8>,
}

#[cfg(feature = "hybrid")]
impl HybridEncapsulator {
    /// Construct the GCS encapsulator.
    ///
    /// - `x25519_sk_bytes`: GCS static X25519 secret key (32 bytes)
    /// - `drone_x25519_pk_bytes`: drone static X25519 public key (32 bytes)
    /// - `drone_ml_kem_ek`: drone ML-KEM-1024 encapsulation key (1568 bytes)
    pub fn new(
        x25519_sk_bytes: [u8; 32],
        drone_x25519_pk_bytes: [u8; 32],
        drone_ml_kem_ek: Vec<u8>,
    ) -> Self {
        Self {
            x25519_sk: x25519_dalek::StaticSecret::from(x25519_sk_bytes),
            peer_x25519_pk: x25519_dalek::PublicKey::from(drone_x25519_pk_bytes),
            peer_ml_kem_ek: drone_ml_kem_ek,
        }
    }

    /// Encapsulate: returns `(ml_kem_ciphertext, hybrid_session_key)`.
    ///
    /// Send the ciphertext to the drone; keep the session key local.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), HybridError> {
        let x25519_ss = Zeroizing::new(*self.x25519_sk
            .diffie_hellman(&self.peer_x25519_pk)
            .as_bytes());

        let (ct, ml_kem_ss) = crate::kem::encapsulate_raw(&self.peer_ml_kem_ek)
            .map_err(|_| HybridError::Encapsulation)?;

        let session_key = derive_hybrid_session_key(&x25519_ss, &ml_kem_ss);
        Ok((ct, Zeroizing::new(session_key)))
    }
}

// ── Hybrid decapsulator (drone side, requires `hybrid` feature) ───────────────

#[cfg(feature = "hybrid")]
/// Drone-side hybrid key establishment.
pub struct HybridDecapsulator {
    x25519_sk: x25519_dalek::StaticSecret,
    peer_x25519_pk: x25519_dalek::PublicKey,
    ml_kem_dk_seed: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "hybrid")]
impl HybridDecapsulator {
    /// Construct the drone decapsulator.
    ///
    /// - `x25519_sk_bytes`: drone static X25519 secret key (32 bytes)
    /// - `gcs_x25519_pk_bytes`: GCS static X25519 public key (32 bytes)
    /// - `ml_kem_dk_seed`: drone ML-KEM-1024 decapsulation key seed (32 bytes)
    pub fn new(
        x25519_sk_bytes: [u8; 32],
        gcs_x25519_pk_bytes: [u8; 32],
        ml_kem_dk_seed: Vec<u8>,
    ) -> Self {
        Self {
            x25519_sk: x25519_dalek::StaticSecret::from(x25519_sk_bytes),
            peer_x25519_pk: x25519_dalek::PublicKey::from(gcs_x25519_pk_bytes),
            ml_kem_dk_seed: Zeroizing::new(ml_kem_dk_seed),
        }
    }

    /// Decapsulate the ciphertext and recover the hybrid session key.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, HybridError> {
        let x25519_ss = Zeroizing::new(*self.x25519_sk
            .diffie_hellman(&self.peer_x25519_pk)
            .as_bytes());

        let ml_kem_ss = crate::kem::decapsulate_from_seed(&self.ml_kem_dk_seed, ct)
            .map_err(|_| HybridError::Decapsulation)?;

        let session_key = derive_hybrid_session_key(&x25519_ss, &ml_kem_ss);
        Ok(Zeroizing::new(session_key))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_is_deterministic() {
        let x25519_ss = [0x11_u8; 32];
        let ml_kem_ss = [0x22_u8; 32];
        let k1 = derive_hybrid_session_key(&x25519_ss, &ml_kem_ss);
        let k2 = derive_hybrid_session_key(&x25519_ss, &ml_kem_ss);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_kdf_differs_from_pq_component_alone() {
        let x25519_ss = [0x11_u8; 32];
        let ml_kem_ss = [0x22_u8; 32];
        let hybrid = derive_hybrid_session_key(&x25519_ss, &ml_kem_ss);
        // Hybrid key must not equal either component
        assert_ne!(hybrid, x25519_ss);
        assert_ne!(hybrid, ml_kem_ss);
    }

    #[test]
    fn test_kdf_order_matters() {
        let a = [0x11_u8; 32];
        let b = [0x22_u8; 32];
        let k1 = derive_hybrid_session_key(&a, &b);
        let k2 = derive_hybrid_session_key(&b, &a); // swapped
        assert_ne!(k1, k2, "KDF must not be commutative");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_hybrid_mode_display() {
        assert_eq!(HybridMode::PqOnly.to_string(), "pq-only");
        assert_eq!(HybridMode::Hybrid.to_string(), "hybrid");
        assert_eq!(HybridMode::ClassicOnly.to_string(), "classic-only");
    }

    /// Full roundtrip: GCS encapsulates, drone decapsulates, both get same key.
    #[test]
    #[cfg(feature = "hybrid")]
    fn test_hybrid_encapsulate_decapsulate_roundtrip() {
        use crate::kem::KemKeyPair;

        // Pre-provisioned X25519 key pairs (GCS + drone)
        let gcs_x25519_sk = [0xAA_u8; 32];
        let drone_x25519_sk = [0xBB_u8; 32];
        let gcs_x25519_pk: [u8; 32] = *x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(gcs_x25519_sk)
        ).as_bytes();
        let drone_x25519_pk: [u8; 32] = *x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(drone_x25519_sk)
        ).as_bytes();

        // Drone ML-KEM key pair
        let drone_kem = KemKeyPair::generate();
        let drone_ek = drone_kem.ek_bytes();
        let drone_dk_seed = drone_kem.dk_seed_bytes().unwrap();

        // GCS encapsulates
        let enc = HybridEncapsulator::new(gcs_x25519_sk, drone_x25519_pk, drone_ek.to_vec());
        let (ct, gcs_key) = enc.encapsulate().unwrap();

        // Drone decapsulates
        let dec = HybridDecapsulator::new(drone_x25519_sk, gcs_x25519_pk, drone_dk_seed.to_vec());
        let drone_key = dec.decapsulate(&ct).unwrap();

        assert_eq!(*gcs_key, *drone_key, "GCS and drone must derive the same session key");
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_wrong_x25519_key_produces_different_session_key() {
        use crate::kem::KemKeyPair;

        let gcs_x25519_sk = [0xAA_u8; 32];
        let drone_x25519_sk = [0xBB_u8; 32];
        let wrong_drone_x25519_sk = [0xCC_u8; 32]; // impersonator

        let drone_x25519_pk: [u8; 32] = *x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(drone_x25519_sk)
        ).as_bytes();
        let gcs_x25519_pk: [u8; 32] = *x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(gcs_x25519_sk)
        ).as_bytes();

        let drone_kem = KemKeyPair::generate();
        let drone_ek = drone_kem.ek_bytes();
        let drone_dk_seed = drone_kem.dk_seed_bytes().unwrap();

        let enc = HybridEncapsulator::new(gcs_x25519_sk, drone_x25519_pk, drone_ek.to_vec());
        let (ct, gcs_key) = enc.encapsulate().unwrap();

        // Drone with wrong X25519 key
        let dec_wrong = HybridDecapsulator::new(
            wrong_drone_x25519_sk, gcs_x25519_pk, drone_dk_seed.to_vec()
        );
        let wrong_key = dec_wrong.decapsulate(&ct).unwrap();

        assert_ne!(*gcs_key, *wrong_key, "wrong X25519 key must yield different session key");
    }
}
