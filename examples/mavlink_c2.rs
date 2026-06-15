//! CleitonQ MAVLink C2 integration example.
//!
//! Shows how to wrap MAVLink command packets with CleitonQ ML-DSA-87
//! signatures — the same pattern used in the Laminar drone project.
//!
//! This example does NOT require a real MAVLink connection: it simulates
//! the packet structure to demonstrate the signing and verification flow.
//!
//! Run with:
//!   cargo run --example mavlink_c2

use cleitonq::dsa::{SigningKey, OVERHEAD};

/// Simulated MAVLink COMMAND_LONG payload (28 bytes in real MAVLink v2).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct CommandLong {
    target_system:    u8,
    target_component: u8,
    command:          u16,
    confirmation:     u8,
    param1:           f32, // thrust
    param2:           f32, // roll
    param3:           f32, // pitch
    param4:           f32, // yaw
    _pad:             [u8; 10],
}

impl CommandLong {
    fn hover() -> Self {
        Self {
            target_system: 1,
            target_component: 1,
            command: 400, // MAV_CMD_COMPONENT_ARM_DISARM placeholder
            confirmation: 0,
            param1: 9.81,
            param2: 0.0,
            param3: 0.0,
            param4: 0.0,
            _pad: [0; 10],
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>(),
            )
        }
    }
}

fn main() {
    println!("CleitonQ — MAVLink C2 Integration Example");
    println!("by Cleiton Augusto Correa Bezerra\n");

    // ---- Key generation (ground station, one-time setup) ----------------------
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();
    println!("[keygen] ML-DSA-87 key pair generated");

    // ---- Ground station: sign a MAVLink command --------------------------------
    let cmd = CommandLong::hover();
    let payload = cmd.as_bytes();

    let nonce: u64 = 1_000_001; // monotonic sequence number
    let signed_packet = sk.sign(payload, nonce);

    println!("[gs]     signed COMMAND_LONG:");
    println!("         payload_size = {} bytes", payload.len());
    println!("         sig_overhead = {} bytes (nonce + ML-DSA-87)", OVERHEAD);
    println!("         total_packet = {} bytes", signed_packet.len());

    // ---- Network transport (untrusted UDP) ------------------------------------
    println!("[net]    packet transmitted over UDP (untrusted channel)");

    // ---- Drone: verify and execute --------------------------------------------
    let mut last_nonce: u64 = 1_000_000;

    match vk.verify(&signed_packet, last_nonce) {
        Some((verified_payload, recv_nonce)) => {
            assert_eq!(verified_payload, payload, "payload must be intact");
            last_nonce = recv_nonce;
            println!("[drone]  ACCEPTED nonce={recv_nonce}");
            println!("         command authenticated — executing hover");
        }
        None => panic!("verification failed"),
    }

    // ---- Replay attack --------------------------------------------------------
    let replay_result = vk.verify(&signed_packet, last_nonce);
    assert!(replay_result.is_none(), "replay must be rejected");
    println!("[sec]    REPLAY ATTACK: REJECTED (nonce={nonce} <= last={last_nonce})");

    // ---- Tampered packet -------------------------------------------------------
    let mut tampered = signed_packet.clone();
    tampered[3] ^= 0xFF; // flip a bit in the command field
    let tampered_result = vk.verify(&tampered, 0);
    assert!(tampered_result.is_none(), "tampered packet must be rejected");
    println!("[sec]    TAMPERED PACKET: REJECTED (ML-DSA-87 signature invalid)");

    // ---- Wrong key attack ------------------------------------------------------
    let attacker_sk = SigningKey::generate();
    let fake_packet = attacker_sk.sign(payload, nonce + 1);
    let fake_result = vk.verify(&fake_packet, last_nonce);
    assert!(fake_result.is_none(), "wrong key must be rejected");
    println!("[sec]    FORGED COMMAND (wrong key): REJECTED");

    println!("\nMAVLink C2 security demo complete.");
    println!("All attacks blocked by CleitonQ ML-DSA-87 authentication.");
}
