// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Key rotation and revocation for ML-DSA-87 signing keys.
//!
//! [`crate::dsa::SigningKey`] is a single static key pair with no notion of
//! identity or revocation — a deployment that uses it directly has no answer
//! to "the ground station's signing key may be compromised, now what?"
//! beyond manually redistributing a new verifying key out-of-band and
//! trusting every drone to update before the old key is misused.
//!
//! This module adds that missing layer without changing [`crate::dsa`]'s
//! wire format: every signed packet is prefixed with a 4-byte key ID, and a
//! [`KeyRegistry`] on the verifying side holds every currently-trusted key
//! plus a revocation set. Revoking a key is a local registry update (no
//! cryptographic operation, no need to reach the compromised key holder).
//!
//! # Wire format
//!
//! ```text
//! [ key_id (4 bytes LE) | dsa::SigningKey packet (payload | nonce | sig) ]
//! ```
//!
//! # Rotation procedure
//!
//! 1. Generate a new [`RotatingSigningKey`] with a fresh, never-reused `KeyId`.
//! 2. Distribute its verifying key to every drone's [`KeyRegistry`]
//!    (`register`) — out-of-band, same trust channel used for initial
//!    provisioning. This module does not bootstrap trust; it only manages
//!    keys once they're trusted.
//! 3. Start signing with the new key. Drones accept both old and new while
//!    the fleet catches up — `KeyRegistry` holds multiple active keys.
//! 4. Once the suspected-compromised key is confirmed retired fleet-wide,
//!    call `revoke` on its ID. A revoked ID is rejected even if the
//!    signature is cryptographically valid, with no expiry needed.
//!
//! # What this does not solve
//!
//! There is no signed revocation message in this version — `revoke` is a
//! local call the integration must trigger via its own out-of-band channel
//! (e.g. ground control pushes an updated registry snapshot). A
//! cryptographically-authenticated revocation broadcast is future work
//! ([`crate::rotation`] tracks the wire format; a v2 could add a signed
//! `RevocationNotice` chained from a higher-trust root key).

use crate::dsa::{SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};

/// Identifies a signing key across rotations. Must never be reused once
/// assigned — reusing an ID after revocation would let a registry that
/// hasn't seen the revocation re-trust the old (compromised) key material
/// if it's ever recovered by an attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub u32);

/// Per-packet overhead added on top of `dsa::OVERHEAD`: the 4-byte key ID.
pub const ID_OVERHEAD: usize = 4;

/// A signing key bound to a [`KeyId`] for rotation-aware deployments.
pub struct RotatingSigningKey {
    id: KeyId,
    inner: SigningKey,
}

impl RotatingSigningKey {
    /// Generates a fresh key bound to `id`. The caller is responsible for
    /// ensuring `id` has never been used (and is not currently revoked) in
    /// the target [`KeyRegistry`].
    pub fn generate(id: KeyId) -> Self {
        Self { id, inner: SigningKey::generate() }
    }

    pub fn id(&self) -> KeyId {
        self.id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    /// Signs `payload` with `nonce`, prefixing the wire packet with this
    /// key's ID so the verifier can look up the right key (and check
    /// revocation) without trying every registered key.
    pub fn sign(&self, payload: &[u8], nonce: u64) -> Vec<u8> {
        let mut packet = Vec::with_capacity(ID_OVERHEAD + payload.len() + crate::dsa::OVERHEAD);
        packet.extend_from_slice(&self.id.0.to_le_bytes());
        packet.extend_from_slice(&self.inner.sign(payload, nonce));
        packet
    }
}

/// The drone-side set of currently-trusted verifying keys, plus revocations.
#[derive(Default)]
pub struct KeyRegistry {
    keys: HashMap<u32, VerifyingKey>,
    revoked: HashSet<u32>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or replaces) the verifying key for `id`. Registering a
    /// revoked ID does not un-revoke it — revocation is permanent for that
    /// ID by design (see module docs: IDs must never be reused).
    pub fn register(&mut self, id: KeyId, key: VerifyingKey) {
        self.keys.insert(id.0, key);
    }

    /// Marks `id` as revoked. Future `verify` calls reject packets signed
    /// under this ID even with a cryptographically valid signature.
    pub fn revoke(&mut self, id: KeyId) {
        self.revoked.insert(id.0);
    }

    pub fn is_revoked(&self, id: KeyId) -> bool {
        self.revoked.contains(&id.0)
    }

    /// Verifies a `RotatingSigningKey`-produced packet: extracts the key
    /// ID, rejects it if revoked or unknown, then delegates to the
    /// corresponding [`VerifyingKey`]. Returns `(payload, nonce, key_id)`.
    pub fn verify<'a>(
        &self,
        packet: &'a [u8],
        last_nonce: u64,
    ) -> Option<(&'a [u8], u64, KeyId)> {
        if packet.len() < ID_OVERHEAD {
            return None;
        }
        let id = u32::from_le_bytes(packet[..ID_OVERHEAD].try_into().ok()?);
        if self.revoked.contains(&id) {
            return None;
        }
        let key = self.keys.get(&id)?;
        let (payload, nonce) = key.verify(&packet[ID_OVERHEAD..], last_nonce)?;
        Some((payload, nonce, KeyId(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_roundtrip() {
        let signer = RotatingSigningKey::generate(KeyId(1));
        let mut registry = KeyRegistry::new();
        registry.register(signer.id(), signer.verifying_key());

        let packet = signer.sign(b"thrust=9.81", 1);
        let (payload, nonce, id) = registry.verify(&packet, 0).expect("must verify");
        assert_eq!(payload, b"thrust=9.81");
        assert_eq!(nonce, 1);
        assert_eq!(id, KeyId(1));
    }

    #[test]
    fn revoked_key_rejected_even_with_valid_signature() {
        let signer = RotatingSigningKey::generate(KeyId(7));
        let mut registry = KeyRegistry::new();
        registry.register(signer.id(), signer.verifying_key());

        let packet = signer.sign(b"land=true", 1);
        assert!(registry.verify(&packet, 0).is_some(), "valid before revocation");

        registry.revoke(KeyId(7));
        assert!(
            registry.verify(&packet, 0).is_none(),
            "revoked key must be rejected even though the signature is still valid"
        );
    }

    #[test]
    fn unknown_key_id_rejected() {
        let signer = RotatingSigningKey::generate(KeyId(99));
        let registry = KeyRegistry::new(); // never registered
        let packet = signer.sign(b"cmd", 1);
        assert!(registry.verify(&packet, 0).is_none());
    }

    #[test]
    fn multiple_active_keys_during_rotation_window() {
        let old_signer = RotatingSigningKey::generate(KeyId(1));
        let new_signer = RotatingSigningKey::generate(KeyId(2));
        let mut registry = KeyRegistry::new();
        registry.register(old_signer.id(), old_signer.verifying_key());
        registry.register(new_signer.id(), new_signer.verifying_key());

        let old_packet = old_signer.sign(b"cmd_old", 1);
        let new_packet = new_signer.sign(b"cmd_new", 1);
        assert!(registry.verify(&old_packet, 0).is_some(), "old key still trusted mid-rotation");
        assert!(registry.verify(&new_packet, 0).is_some(), "new key trusted immediately");

        registry.revoke(old_signer.id());
        assert!(registry.verify(&old_packet, 0).is_none(), "old key revoked after rotation completes");
        assert!(registry.verify(&new_packet, 0).is_some(), "new key unaffected by old key's revocation");
    }

    #[test]
    fn short_packet_rejected() {
        let registry = KeyRegistry::new();
        assert!(registry.verify(&[0u8; ID_OVERHEAD - 1], 0).is_none());
        assert!(registry.verify(&[], 0).is_none());
    }

    #[test]
    fn reregistering_revoked_id_does_not_restore_trust() {
        let signer = RotatingSigningKey::generate(KeyId(3));
        let mut registry = KeyRegistry::new();
        registry.register(signer.id(), signer.verifying_key());
        registry.revoke(KeyId(3));

        // Re-registering (e.g. a stale config push) must not un-revoke.
        registry.register(signer.id(), signer.verifying_key());
        let packet = signer.sign(b"cmd", 1);
        assert!(
            registry.verify(&packet, 0).is_none(),
            "revocation must survive re-registration of the same ID"
        );
    }
}
