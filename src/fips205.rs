// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! SLH-DSA (FIPS 205) stateless hash-based signatures for long-lived certificates.
//!
//! Unlike ML-DSA (lattice-based), SLH-DSA requires only hash security assumptions.
//! This provides defense-in-depth: if lattice hardness is ever questioned,
//! SLH-DSA revocation certificates remain secure.
//!
//! # Profiles
//!
//! The parameter set is a deployment decision, not an implementation detail, so
//! the scheme is generic over [`RevocationProfile`] and ships the three
//! "small signature" sets as named profiles:
//!
//! | Profile | NIST category | Verifying key | Signature |
//! |---|---|---|---|
//! | `Sha2_128s` | 1 | 32 B | 7 856 B |
//! | `Sha2_192s` | 3 | 48 B | 16 224 B |
//! | [`DefaultProfile`] (`Sha2_256s`) | 5 | 64 B | 29 792 B |
//!
//! `RevocationSigner` with no type argument means [`DefaultProfile`]. A
//! constrained link may fix a lower profile deliberately — a 29 792-byte
//! signature is 120 fragments over a 255-byte radio frame — but that choice
//! should be made and written down, not inherited.
//!
//! The declared sizes are asserted against what the implementation produces, so
//! a specification quoting this table cannot silently drift from the code.
//!
//! # Why the default is SHA2-256s and not a smaller parameter set
//!
//! This key is the **longest-lived key in the system** — a trust root that must
//! still be verifiable after the operational keys it revokes are long gone. It
//! therefore must be at least as strong as the operational path it backstops.
//!
//! The operational signature is ML-DSA-87, which is NIST security category 5.
//! SLH-DSA-SHA2-256s is also category 5, so the trust root and the fast path sit
//! at the same level. An earlier revision of this module fixed SHA2-128s
//! (category 1) as the only option, which inverted that relationship: the key
//! with the longest horizon was the weakest link, undercutting the very
//! conservatism the hash-based scheme is here to provide. A deployment may still
//! choose a lower profile for a constrained link, but it now does so explicitly.
//!
//! The cost of the choice is signature size — 29792 bytes against 7856 — and
//! slower signing. Both are acceptable here precisely because this scheme is
//! never on a per-packet path: signing happens offline (see below), rarely, and
//! the signature is not transmitted at line rate.
//!
//! # Cost
//!
//! Signing is roughly three to four thousand times slower than ML-DSA-87.
//! Measured by `benches/pqc_bench.rs` on an x86-64 development machine, release
//! build, ten samples per figure; reproduce with
//! `cargo bench --features fips205 --bench pqc_bench -- SLH-DSA`.
//!
//! | Profile | Key generation | Sign | Verify |
//! |---|---|---|---|
//! | SHA2-128s (cat 1) | 103 ms | 772 ms | 796 µs |
//! | SHA2-192s (cat 3) | 147 ms | 1.35 s | 1.26 ms |
//! | SHA2-256s (cat 5) | 111 ms | 1.31 s | 1.82 ms |
//! | *ML-DSA-87, for scale* | *0.6 ms* | *0.3 ms* | — |
//!
//! **Category 3 is a poor trade on this implementation.** Signing at 192s costs
//! as much as at 256s — the confidence intervals overlap — and its key
//! generation is measurably slower, while offering less margin. The only reason
//! to prefer it is signature size, 16 224 bytes against 29 792. The size trade
//! across profiles is smooth; the time trade is not.
//!
//! Verification stays cheap at every profile, which is the property that
//! matters: signing happens once, on an offline machine, and every later check
//! of that signature is milliseconds. Budget for the signing cost in any
//! ceremony that produces one of these, and expect a test suite that generates
//! them to be slow.
//!
//! These are one implementation on one architecture. The ordering between 192s
//! and 256s in particular may not hold elsewhere, and is worth re-measuring
//! before it is relied on.
//!
//! # Intended use
//!
//! Use this only for **infrequent, long-lived signatures** such as:
//! - Drone key revocation certificates (verified in 15+ years)
//! - Root CA certificates in a SwarmKeyRegistry
//! - Operator credential attestations with multi-year validity
//!
//! For per-packet or per-command signing, use [`crate::dsa`] (ML-DSA-87, FIPS 204).

use alloc::vec::Vec;

use slh_dsa::{
    ParameterSet,
    signature::{Keypair as _, Signer as _, Verifier as _},
};

// The profile types are part of this module's public surface: a caller choosing
// a profile should not have to depend on the slh-dsa crate to name one.
pub use slh_dsa::{Sha2_128s, Sha2_192s, Sha2_256s};

/// A revocation profile: a FIPS 205 parameter set together with the sizes it
/// produces and the NIST category it reaches.
///
/// The parameter set is a deployment decision, not an implementation detail. A
/// trust root guarding a spacecraft for twenty-five years and one carried over a
/// 255-byte radio frame face the same trade — signature size against security
/// margin — and land in different places. Rather than hard-code one answer, the
/// scheme is generic over this trait and ships the three "small signature"
/// parameter sets as named profiles, so a specification can fix a profile and an
/// implementation can honour it.
///
/// `slh_dsa::ParameterSet` is deliberately closed to outside implementation, so
/// this trait is implemented here for the three sets we expose rather than being
/// open-ended. Adding a fourth is a one-line impl plus its size constants.
pub trait RevocationProfile: ParameterSet {
    /// NIST security category reached by this parameter set.
    const NIST_CATEGORY: u8;
    /// Serialized signing-key length in bytes.
    const SK_BYTES: usize;
    /// Serialized verifying-key length in bytes.
    const VK_BYTES: usize;
    /// Signature length in bytes.
    const SIG_BYTES: usize;
}

impl RevocationProfile for Sha2_256s {
    const NIST_CATEGORY: u8 = 5;
    const SK_BYTES: usize = 128;
    const VK_BYTES: usize = 64;
    const SIG_BYTES: usize = 29792;
}

impl RevocationProfile for Sha2_192s {
    const NIST_CATEGORY: u8 = 3;
    const SK_BYTES: usize = 96;
    const VK_BYTES: usize = 48;
    const SIG_BYTES: usize = 16224;
}

impl RevocationProfile for Sha2_128s {
    const NIST_CATEGORY: u8 = 1;
    const SK_BYTES: usize = 64;
    const VK_BYTES: usize = 32;
    const SIG_BYTES: usize = 7856;
}

// Signature size must increase with the security category. This is a property of
// the profiles as declared, so it is checked when the crate builds rather than
// when a test runs: getting it wrong means a size constant is transcribed
// incorrectly, and that should never reach a specification quoting this table.
const _: () = {
    assert!(Sha2_128s::SIG_BYTES < Sha2_192s::SIG_BYTES);
    assert!(Sha2_192s::SIG_BYTES < Sha2_256s::SIG_BYTES);
    assert!(Sha2_128s::VK_BYTES < Sha2_192s::VK_BYTES);
    assert!(Sha2_192s::VK_BYTES < Sha2_256s::VK_BYTES);
};

/// The default profile: SLH-DSA-SHA2-256s, NIST category 5.
///
/// Chosen so the trust root is no weaker than the ML-DSA-87 operational path it
/// backstops. See the module documentation for why the inverse would undermine
/// the argument for having a hash-based fallback at all.
pub type DefaultProfile = Sha2_256s;

/// Size of the default profile's signing key in bytes.
pub const SLH_SK_BYTES: usize = <DefaultProfile as RevocationProfile>::SK_BYTES;
/// Size of the default profile's verifying key in bytes.
pub const SLH_VK_BYTES: usize = <DefaultProfile as RevocationProfile>::VK_BYTES;
/// Size of a default-profile signature in bytes.
pub const SLH_SIG_BYTES: usize = <DefaultProfile as RevocationProfile>::SIG_BYTES;

/// SLH-DSA signing key for long-lived revocation certificates.
///
/// Defaults to [`DefaultProfile`], so `RevocationSigner` alone means category 5.
pub struct RevocationSigner<P: RevocationProfile = DefaultProfile>(slh_dsa::SigningKey<P>);

/// SLH-DSA verifying key (distribute to all validators).
pub struct RevocationVerifier<P: RevocationProfile = DefaultProfile>(slh_dsa::VerifyingKey<P>);

impl<P: RevocationProfile> RevocationSigner<P> {
    /// Generates a fresh signing key using the OS CSPRNG.
    #[cfg(feature = "fips205")]
    pub fn generate() -> Self {
        use rand_core::UnwrapErr;
        let mut rng = UnwrapErr(getrandom::SysRng);
        Self(slh_dsa::SigningKey::<P>::new(&mut rng))
    }

    /// Generates a signing key from the provided CSPRNG (embedded targets).
    pub fn generate_from_rng<R: rand_core::CryptoRng>(rng: &mut R) -> Self {
        Self(slh_dsa::SigningKey::<P>::new(rng))
    }

    /// Reconstructs a signing key from its serialized form.
    ///
    /// Returns `None` if the length does not match this profile, which also
    /// rejects a key serialized under a different parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != P::SK_BYTES {
            return None;
        }
        slh_dsa::SigningKey::<P>::try_from(bytes).ok().map(Self)
    }

    /// Serializes the signing key. **Keep secret.**
    pub fn to_bytes(&self) -> Vec<u8> {
        let arr = self.0.to_bytes();
        arr[..].to_vec()
    }

    /// Returns the corresponding verifying key.
    pub fn verifying_key(&self) -> RevocationVerifier<P> {
        RevocationVerifier(self.0.verifying_key().clone())
    }

    /// Signs `message` and returns the signature.
    ///
    /// Deterministic (pure) signing variant — safe for revocation certs where
    /// the message already contains sufficient context (subject ID, timestamp).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: slh_dsa::Signature<P> = self.0.sign(message);
        sig.to_vec()
    }
}

impl<P: RevocationProfile> RevocationVerifier<P> {
    /// Reconstructs a verifying key from its serialized form.
    ///
    /// Returns `None` if the length does not match this profile.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != P::VK_BYTES {
            return None;
        }
        slh_dsa::VerifyingKey::<P>::try_from(bytes).ok().map(Self)
    }

    /// Serializes the verifying key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let arr = self.0.to_bytes();
        arr[..].to_vec()
    }

    /// Verifies a signature. Returns `true` if valid under this profile.
    pub fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        let Ok(parsed) = slh_dsa::Signature::<P>::try_from(sig) else {
            return false;
        };
        self.0.verify(message, &parsed).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises one profile end to end. Every profile must satisfy the same
    /// contract, so the body is written once and instantiated per parameter set.
    fn profile_roundtrip<P: RevocationProfile>() {
        let signer = RevocationSigner::<P>::generate();
        let verifier = signer.verifying_key();

        let msg = b"revoke subject=CLQD-4F2A timestamp=2026-06-25T00:00:00Z";
        let sig = signer.sign(msg);

        assert_eq!(sig.len(), P::SIG_BYTES, "signature length must match the profile");
        assert_eq!(signer.to_bytes().len(), P::SK_BYTES);
        assert_eq!(verifier.to_bytes().len(), P::VK_BYTES);
        assert!(verifier.verify(msg, &sig));

        // Wrong message, truncated signature, and a signature from another key
        // must all fail under every profile.
        assert!(!verifier.verify(b"revoke subject=OTHER", &sig));
        assert!(!verifier.verify(msg, &sig[..sig.len() - 1]));
        let other = RevocationSigner::<P>::generate();
        assert!(!other.verifying_key().verify(msg, &sig));

        // Serialization round-trips.
        let sk = RevocationSigner::<P>::from_bytes(&signer.to_bytes()).expect("valid sk");
        let vk = RevocationVerifier::<P>::from_bytes(&verifier.to_bytes()).expect("valid vk");
        assert!(vk.verify(msg, &sk.sign(msg)));
    }

    #[test]
    fn category5_sha2_256s() {
        profile_roundtrip::<Sha2_256s>();
    }

    /// The lower profiles are exercised too, and are far cheaper to run, which is
    /// why they carry the size and cross-profile checks that would otherwise make
    /// the category-5 test slower still.
    #[test]
    fn category3_sha2_192s() {
        profile_roundtrip::<Sha2_192s>();
    }

    #[test]
    fn category1_sha2_128s() {
        profile_roundtrip::<Sha2_128s>();
    }

    /// The size constants are asserted against what the implementation actually
    /// produces, so a wrong constant cannot ship: it fails here rather than
    /// silently mis-describing a profile in a specification.
    #[test]
    fn declared_sizes_match_reality() {
        fn check<P: RevocationProfile>() {
            let s = RevocationSigner::<P>::generate();
            assert_eq!(s.to_bytes().len(), P::SK_BYTES, "SK_BYTES wrong for {}", P::NAME);
            assert_eq!(s.verifying_key().to_bytes().len(), P::VK_BYTES, "VK_BYTES wrong for {}", P::NAME);
            assert_eq!(s.sign(b"x").len(), P::SIG_BYTES, "SIG_BYTES wrong for {}", P::NAME);
        }
        check::<Sha2_128s>();
        check::<Sha2_192s>();
        // Category 5 is covered by category5_sha2_256s; generating another
        // 256s key here would add a second ~1.2 s signing operation for nothing.
    }

    /// Categories must be ordered as the profiles claim, and the default must be
    /// the one that matches the ML-DSA-87 operational path.
    #[test]
    fn profile_ordering_and_default() {
        assert_eq!(Sha2_128s::NIST_CATEGORY, 1);
        assert_eq!(Sha2_192s::NIST_CATEGORY, 3);
        assert_eq!(Sha2_256s::NIST_CATEGORY, 5);
        // The default profile is category 5, and the compatibility constants
        // describe it. A change to the default that forgot these would fail here.
        assert_eq!(<DefaultProfile as RevocationProfile>::NIST_CATEGORY, 5);
        assert_eq!(SLH_SK_BYTES, <DefaultProfile as RevocationProfile>::SK_BYTES);
        assert_eq!(SLH_VK_BYTES, <DefaultProfile as RevocationProfile>::VK_BYTES);
        assert_eq!(SLH_SIG_BYTES, <DefaultProfile as RevocationProfile>::SIG_BYTES);
    }

    /// A key or signature from one profile must not be accepted by another.
    /// Uses the two cheap profiles so the check costs little.
    #[test]
    fn profiles_do_not_interoperate() {
        let a = RevocationSigner::<Sha2_128s>::generate();
        let msg = b"revoke subject=X";
        let sig_a = a.sign(msg);

        // A 128s signature is the wrong length for a 192s verifier.
        let b = RevocationSigner::<Sha2_192s>::generate();
        assert!(!b.verifying_key().verify(msg, &sig_a));

        // And key material does not cross profiles either.
        assert!(RevocationVerifier::<Sha2_192s>::from_bytes(&a.verifying_key().to_bytes()).is_none());
        assert!(RevocationSigner::<Sha2_192s>::from_bytes(&a.to_bytes()).is_none());
    }

    #[test]
    fn malformed_key_material_is_rejected() {
        assert!(RevocationSigner::<Sha2_128s>::from_bytes(&[]).is_none());
        assert!(RevocationVerifier::<Sha2_128s>::from_bytes(&[0u8; 31]).is_none());
        assert!(RevocationVerifier::<Sha2_128s>::from_bytes(&[0u8; 33]).is_none());
    }
}
