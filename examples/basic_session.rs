// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Basic CleitonQ session example.
//!
//! Demonstrates a full ML-KEM session establishment + HMAC-authenticated
//! command exchange between a simulated ground station and drone.
//!
//! Run with:
//!   cargo run --example basic_session

use cleitonq::channel::{AuthChannel, ChannelDomain};

fn main() {
    println!("CleitonQ — Basic Session Example");
    println!("by Cleiton Augusto Correa Bezerra\n");

    // ---- Key generation (done once before deployment) -------------------------
    let keypair = cleitonq::kem::KemKeyPair::generate();
    keypair.save("/tmp/cq_dk.bin", "/tmp/cq_ek.bin").unwrap();
    println!("[keygen] ML-KEM-1024 key pair saved to /tmp/cq_{{dk,ek}}.bin");

    // ---- Ground station: establish forward-secret session ---------------------
    let (ciphertext, gs_session_key) = cleitonq::kem::encapsulate("/tmp/cq_ek.bin").unwrap();
    println!("[gs]     ML-KEM encapsulation: {} bytes ciphertext", ciphertext.len());

    let c2_tx = AuthChannel::new(&gs_session_key, ChannelDomain::C2);

    // ---- Drone: recover session key -------------------------------------------
    let dk = cleitonq::kem::KemKeyPair::load_decapsulation_key("/tmp/cq_dk.bin").unwrap();
    let drone_session_key = cleitonq::kem::decapsulate(&dk, &ciphertext).unwrap();
    println!("[drone]  ML-KEM decapsulation: session key recovered");

    assert_eq!(gs_session_key.as_ref(), drone_session_key.as_ref(),
        "BUG: session keys must match");

    let c2_rx = AuthChannel::new(&drone_session_key, ChannelDomain::C2);

    // ---- Command exchange -----------------------------------------------------
    let commands = [
        (b"thrust=9.81 roll=0.0 pitch=0.0 yaw=0.0".as_ref(), 1u64),
        (b"thrust=10.5 roll=0.1 pitch=-0.05 yaw=0.0".as_ref(), 2u64),
        (b"waypoint=100.0,80.0,50.0".as_ref(), 3u64),
    ];

    let mut last_nonce = 0u64;
    for (payload, nonce) in commands {
        let packet = c2_tx.sign(payload, nonce);
        let (recovered, recv_nonce) = c2_rx.verify(&packet, last_nonce)
            .expect("authentication failed");

        assert_eq!(recovered, payload);
        assert_eq!(recv_nonce, nonce);
        last_nonce = recv_nonce;

        println!("[cmd]    nonce={nonce} payload=\"{}\" overhead={}B",
            std::str::from_utf8(payload).unwrap(),
            packet.len() - payload.len());
    }

    // ---- Domain separation: telemetry channel ---------------------------------
    let telem_tx = AuthChannel::new(&gs_session_key, ChannelDomain::Telemetry);
    let telem_rx = AuthChannel::new(&drone_session_key, ChannelDomain::Telemetry);

    let telem_data = b"alt=50.1 vx=1.2 vy=0.3 vz=0.0 bat=87%";
    let telem_packet = telem_tx.sign(telem_data, 1);
    let (telem_recv, _) = telem_rx.verify(&telem_packet, 0).unwrap();
    assert_eq!(telem_recv, telem_data);
    println!("[telem]  telemetry authenticated on separate channel key");

    // ---- Cross-domain attack demo ---------------------------------------------
    let cross = c2_rx.verify(&telem_packet, 0);
    assert!(cross.is_none(), "cross-domain attack must fail");
    println!("[sec]    cross-domain replay: REJECTED (domain separation works)");

    println!("\nAll checks passed.");
}
