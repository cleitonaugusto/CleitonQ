// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! SLH-DSA (FIPS 205) stateless hash-based signatures for long-lived certificates.
//!
//! Uses the SHA2-256s parameter set: 64-byte verifying key, 29792-byte signature.
//! Unlike ML-DSA (lattice-based), SLH-DSA requires only hash security assumptions.
//! This provides defense-in-depth: if lattice hardness is ever questioned,
//! SLH-DSA revocation certificates remain secure.
//!
//! # Why SHA2-256s and not a smaller parameter set
//!
//! This key is the **longest-lived key in the system** — a trust root that must
//! still be verifiable after the operational keys it revokes are long gone. It
//! therefore must be at least as strong as the operational path it backstops.
//!
//! The operational signature is ML-DSA-87, which is NIST security category 5.
//! SLH-DSA-SHA2-256s is also category 5, so the trust root and the fast path sit
//! at the same level. An earlier revision of this module used SHA2-128s
//! (category 1), which inverted that relationship: the key with the longest
//! horizon was the weakest link, undercutting the very conservatism the
//! hash-based scheme is here to provide.
//!
//! The cost of the choice is signature size — 29792 bytes against 7856 — and
//! slower signing. Both are acceptable here precisely because this scheme is
//! never on a per-packet path: signing happens offline (see below), rarely, and
//! the signature is not transmitted at line rate.
//!
//! # Intended use
//!
//! SLH-DSA is 10-100× slower to sign than ML-DSA-87 and produces larger signatures.
//! Use it only for **infrequent, long-lived signatures** such as:
//! - Drone key revocation certificates (verified in 15+ years)
//! - Root CA certificates in a SwarmKeyRegistry
//! - Operator credential attestations with multi-year validity
//!
//! For per-packet or per-command signing, use [`crate::dsa`] (ML-DSA-87, FIPS 204).

use alloc::vec::Vec;

use slh_dsa::{
    Sha2_256s,
    signature::{Signer as _, Verifier as _, Keypair as _},
};

/// Size of the SLH-DSA-SHA2-256s signing key in bytes.
pub const SLH_SK_BYTES: usize = 128;
/// Size of the SLH-DSA-SHA2-256s verifying key in bytes.
pub const SLH_VK_BYTES: usize = 64;
/// Size of an SLH-DSA-SHA2-256s signature in bytes.
pub const SLH_SIG_BYTES: usize = 29792;

/// SLH-DSA-SHA2-256s signing key for long-lived revocation certificates.
pub struct RevocationSigner(slh_dsa::SigningKey<Sha2_256s>);

/// SLH-DSA-SHA2-256s verifying key (distribute to all validators).
pub struct RevocationVerifier(slh_dsa::VerifyingKey<Sha2_256s>);

impl RevocationSigner {
    /// Generates a fresh SLH-DSA-SHA2-256s signing key using the OS CSPRNG.
    #[cfg(feature = "fips205")]
    pub fn generate() -> Self {
        use rand_core::UnwrapErr;
        let mut rng = UnwrapErr(getrandom::SysRng);
        Self(slh_dsa::SigningKey::<Sha2_256s>::new(&mut rng))
    }

    /// Generates a signing key from the provided CSPRNG (embedded targets).
    pub fn generate_from_rng<R: rand_core::CryptoRng>(rng: &mut R) -> Self {
        Self(slh_dsa::SigningKey::<Sha2_256s>::new(rng))
    }

    /// Reconstructs a signing key from its 128-byte serialized form.
    pub fn from_bytes(bytes: &[u8; SLH_SK_BYTES]) -> Option<Self> {
        slh_dsa::SigningKey::<Sha2_256s>::try_from(bytes.as_ref()).ok().map(Self)
    }

    /// Serializes the signing key to 128 bytes. **Keep secret.**
    pub fn to_bytes(&self) -> [u8; SLH_SK_BYTES] {
        let arr = self.0.to_bytes();
        let mut out = [0u8; SLH_SK_BYTES];
        out.copy_from_slice(arr.as_ref());
        out
    }

    /// Returns the corresponding verifying key.
    pub fn verifying_key(&self) -> RevocationVerifier {
        RevocationVerifier(self.0.verifying_key().clone())
    }

    /// Signs `message` and returns the 29792-byte SLH-DSA signature.
    ///
    /// Deterministic (pure) signing variant — safe for revocation certs where
    /// the message already contains sufficient context (drone ID, timestamp).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: slh_dsa::Signature<Sha2_256s> = self.0.sign(message);
        sig.to_vec()
    }
}

impl RevocationVerifier {
    /// Reconstructs a verifying key from its 64-byte serialized form.
    pub fn from_bytes(bytes: &[u8; SLH_VK_BYTES]) -> Option<Self> {
        slh_dsa::VerifyingKey::<Sha2_256s>::try_from(bytes.as_ref()).ok().map(Self)
    }

    /// Serializes the verifying key to 64 bytes.
    pub fn to_bytes(&self) -> [u8; SLH_VK_BYTES] {
        let arr = self.0.to_bytes();
        let mut out = [0u8; SLH_VK_BYTES];
        out.copy_from_slice(arr.as_ref());
        out
    }

    /// Verifies an SLH-DSA signature. Returns `true` if valid.
    pub fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        let Ok(parsed) = slh_dsa::Signature::<Sha2_256s>::try_from(sig) else {
            return false;
        };
        self.0.verify(message, &parsed).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let signer = RevocationSigner::generate();
        let verifier = signer.verifying_key();

        let msg = b"revoke drone_id=CLQD-4F2A timestamp=2026-06-25T00:00:00Z";
        let sig = signer.sign(msg);

        assert_eq!(sig.len(), SLH_SIG_BYTES);
        assert!(verifier.verify(msg, &sig));
    }

    #[test]
    fn wrong_message_rejected() {
        let signer = RevocationSigner::generate();
        let verifier = signer.verifying_key();

        let sig = signer.sign(b"revoke drone=A");
        assert!(!verifier.verify(b"revoke drone=B", &sig));
    }

    #[test]
    fn wrong_key_rejected() {
        let signer_a = RevocationSigner::generate();
        let signer_b = RevocationSigner::generate();
        let verifier_b = signer_b.verifying_key();

        let sig = signer_a.sign(b"revoke drone=A");
        assert!(!verifier_b.verify(b"revoke drone=A", &sig));
    }

    #[test]
    fn truncated_sig_rejected() {
        let signer = RevocationSigner::generate();
        let verifier = signer.verifying_key();

        let msg = b"revoke drone=X";
        let sig = signer.sign(msg);
        let truncated = &sig[..100];
        assert!(!verifier.verify(msg, truncated));
    }

    #[test]
    fn key_serialization_roundtrip() {
        let signer = RevocationSigner::generate();
        let sk_bytes = signer.to_bytes();
        let vk_bytes = signer.verifying_key().to_bytes();

        let restored = RevocationSigner::from_bytes(&sk_bytes).expect("valid");
        let restored_vk = RevocationVerifier::from_bytes(&vk_bytes).expect("valid");

        let msg = b"revoke drone=test";
        let sig = restored.sign(msg);
        assert!(restored_vk.verify(msg, &sig));
    }

    #[test]
    fn key_sizes() {
        let signer = RevocationSigner::generate();
        assert_eq!(signer.to_bytes().len(), SLH_SK_BYTES);
        assert_eq!(signer.verifying_key().to_bytes().len(), SLH_VK_BYTES);
        assert_eq!(signer.sign(b"test").len(), SLH_SIG_BYTES);
    }
}
