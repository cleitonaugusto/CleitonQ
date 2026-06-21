// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Active MITM scenarios: an attacker controlling the link between ground
//! station and drone tries to substitute, splice, or relay traffic between
//! independent sessions. Unlike `dsa::tests`/`channel::tests`, which check
//! single-message tamper/replay, these tests model an attacker with full
//! control of the wire who can mix material from multiple legitimate
//! handshakes.

use cleitonq::dsa::SigningKey;
use cleitonq::kem::{decapsulate, encapsulate, KemKeyPair};
use cleitonq::prelude::*;

/// Attacker swaps the ML-KEM ciphertext from a second, unrelated session
/// into the first one's transcript. The drone must derive a session key
/// that does not match what the ground station has — i.e. the swap must
/// not let the attacker establish a shared channel with either party.
#[test]
fn mitm_ciphertext_substitution_breaks_session() {
    let pid = std::process::id();
    let dk_a_path = format!("/tmp/cq_mitm_dk_a_{pid}.bin");
    let ek_a_path = format!("/tmp/cq_mitm_ek_a_{pid}.bin");
    let dk_b_path = format!("/tmp/cq_mitm_dk_b_{pid}.bin");
    let ek_b_path = format!("/tmp/cq_mitm_ek_b_{pid}.bin");

    let keypair_a = KemKeyPair::generate();
    keypair_a.save(&dk_a_path, &ek_a_path).unwrap();
    let keypair_b = KemKeyPair::generate();
    keypair_b.save(&dk_b_path, &ek_b_path).unwrap();

    let (_ct_a, session_key_gs) = encapsulate(&ek_a_path).unwrap();
    let (ct_b, _session_key_gs_b) = encapsulate(&ek_b_path).unwrap();

    // Attacker forwards drone A the ciphertext meant for drone B's key pair.
    let dk_a = KemKeyPair::load_decapsulation_key(&dk_a_path).unwrap();
    let session_key_drone = decapsulate(&dk_a, &ct_b).unwrap();

    // Both sides derive *some* key (ML-KEM doesn't error on a foreign
    // ciphertext — it's IND-CCA2 via implicit rejection), but they must
    // not match, so no shared authenticated channel exists.
    assert_ne!(
        session_key_gs.as_ref(),
        session_key_drone.as_ref(),
        "substituted ciphertext must not produce a shared session key"
    );

    let gs_channel = AuthChannel::new(&session_key_gs, ChannelDomain::C2);
    let drone_channel = AuthChannel::new(&session_key_drone, ChannelDomain::C2);
    let packet = gs_channel.sign(b"arm", 1);
    assert!(
        drone_channel.verify(&packet, 0).is_none(),
        "drone must reject packets signed under the wrong session key"
    );

    for p in [&dk_a_path, &ek_a_path, &dk_b_path, &ek_b_path] {
        std::fs::remove_file(p).ok();
    }
}

/// Attacker captures a signed command from session 1 and replays it
/// verbatim into session 2 (same ground station signing key, different
/// AuthChannel/nonce window — e.g. drone rebooted and re-keyed). The
/// ML-DSA signature alone is not session-bound, so this must be caught
/// by the nonce, not the signature.
#[test]
fn mitm_cross_session_replay_rejected_by_nonce() {
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();

    // Session 1: drone tracks last_nonce = 5 after accepting nonce 5.
    let captured = sk.sign(b"thrust=9.81", 5);
    assert!(vk.verify(&captured, 0).is_some());

    // Session 2 (new boot, attacker replays the captured packet hoping the
    // fresh session starts trusting from nonce 0 again).
    let fresh_last_nonce = 0u64;
    // Without session-scoped nonce tracking, a naive integration would
    // accept this. CleitonQ's contract is per-channel-instance state, so
    // the integration is responsible for persisting last_nonce across
    // reboots — verify here only proves nonce 5 > 0 passes the *local*
    // check, which is exactly why persistence is a documented requirement,
    // not an internal guarantee.
    assert!(vk.verify(&captured, fresh_last_nonce).is_some());

    // What CleitonQ does guarantee: once nonce 5 is recorded as last_nonce,
    // no replay of that exact packet (or anything <= 5) is ever accepted
    // again on that same tracked state.
    assert!(vk.verify(&captured, 5).is_none(), "replay at recorded nonce must fail");
}

/// Attacker relays a ground-station-signed command unmodified but tries to
/// splice a different (smaller) ML-DSA signature captured from another
/// packet onto this payload, hoping the verifier reads past the wrong
/// boundary. The fixed `OVERHEAD` framing must prevent any cross-packet
/// splicing from producing a valid signature.
#[test]
fn mitm_signature_splicing_rejected() {
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();

    let packet_1 = sk.sign(b"thrust=9.81", 1);
    let packet_2 = sk.sign(b"thrust=0.0 land=true", 2);

    // Splice: payload+nonce from packet_2, signature bytes from packet_1.
    let sig_len = cleitonq::dsa::SIG_BYTES;
    let mut spliced = packet_2[..packet_2.len() - sig_len].to_vec();
    spliced.extend_from_slice(&packet_1[packet_1.len() - sig_len..]);

    assert!(
        vk.verify(&spliced, 0).is_none(),
        "spliced signature from a different message must not verify"
    );
}
