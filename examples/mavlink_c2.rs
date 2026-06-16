// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! CleitonQ MAVLink v2 integration example.
//!
//! Uses the official `mavlink` crate (github.com/mavlink/rust-mavlink) to build
//! real MAVLink v2 wire-format messages — `COMMAND_LONG` and
//! `SET_POSITION_TARGET_LOCAL_NED` — then wraps them with CleitonQ ML-DSA-87
//! signatures for authenticated ground-station-to-vehicle command delivery.
//!
//! This does not require a live link: it serializes real MAVLink v2 frames
//! (header, payload, CRC) exactly as `mavlink::write_v2_msg` would send them
//! over UDP/serial, then signs/verifies the resulting bytes.
//!
//! Run with:
//!   cargo run --example mavlink_c2

use cleitonq::dsa::{SigningKey, OVERHEAD};
use mavlink::dialects::common::{
    MavCmd, MavFrame as MavPositionFrame, MavMessage, COMMAND_LONG_DATA,
    SET_POSITION_TARGET_LOCAL_NED_DATA, PositionTargetTypemask,
};
use mavlink::peek_reader::PeekReader;
use mavlink::{MavHeader, MavlinkVersion};

/// Serializes a `MavMessage` to its real MAVLink v2 wire bytes
/// (header + payload + checksum), the same bytes that go on the wire.
fn to_v2_bytes(header: MavHeader, msg: &MavMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    mavlink::write_v2_msg(&mut buf, header, msg).expect("encode must succeed");
    buf
}

fn arm_command() -> MavMessage {
    MavMessage::COMMAND_LONG(COMMAND_LONG_DATA {
        param1: 1.0, // arm
        param2: 0.0,
        param3: 0.0,
        param4: 0.0,
        param5: 0.0,
        param6: 0.0,
        param7: 0.0,
        command: MavCmd::MAV_CMD_COMPONENT_ARM_DISARM,
        target_system: 1,
        target_component: 1,
        confirmation: 0,
    })
}

fn position_target() -> MavMessage {
    MavMessage::SET_POSITION_TARGET_LOCAL_NED(SET_POSITION_TARGET_LOCAL_NED_DATA {
        time_boot_ms: 0,
        x: 10.0,
        y: 5.0,
        z: -2.0,
        vx: 0.0,
        vy: 0.0,
        vz: 0.0,
        afx: 0.0,
        afy: 0.0,
        afz: 0.0,
        yaw: 0.0,
        yaw_rate: 0.0,
        type_mask: PositionTargetTypemask::POSITION_TARGET_TYPEMASK_VX_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_VY_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_VZ_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE,
        target_system: 1,
        target_component: 1,
        coordinate_frame: MavPositionFrame::MAV_FRAME_LOCAL_NED,
    })
}

fn main() {
    println!("CleitonQ — Real MAVLink v2 Integration Example");
    println!("by Cleiton Augusto Correa Bezerra\n");

    let header = MavHeader {
        system_id: 255,
        component_id: 0,
        sequence: 1,
    };

    // ---- Key generation (ground station, one-time setup) ----------------------
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();
    println!("[keygen] ML-DSA-87 key pair generated");
    println!("[proto]  MAVLink {:?}\n", MavlinkVersion::V2);

    // ---- Ground station: encode + sign real MAVLink v2 frames ------------------
    for (label, msg) in [
        ("COMMAND_LONG (arm)", arm_command()),
        ("SET_POSITION_TARGET_LOCAL_NED", position_target()),
    ] {
        let wire_bytes = to_v2_bytes(header, &msg);
        let nonce: u64 = 1_000_001;
        let signed_packet = sk.sign(&wire_bytes, nonce);

        println!("[gs]     {label}");
        println!("         mavlink_v2_frame = {} bytes", wire_bytes.len());
        println!("         sig_overhead     = {OVERHEAD} bytes (nonce + ML-DSA-87)");
        println!("         total_packet     = {} bytes", signed_packet.len());

        // ---- Drone: verify and decode -------------------------------------------
        let (verified_bytes, recv_nonce) =
            vk.verify(&signed_packet, 0).expect("valid signature must verify");
        assert_eq!(verified_bytes, wire_bytes, "wire bytes must survive roundtrip");

        let mut reader = PeekReader::<_, 280>::new(verified_bytes);
        let (_decoded_header, decoded_msg) =
            mavlink::read_v2_msg::<MavMessage, _>(&mut reader).expect("must decode");
        assert_eq!(
            format!("{decoded_msg:?}").split('(').next(),
            format!("{msg:?}").split('(').next(),
            "decoded message type must match"
        );

        println!("[drone]  ACCEPTED nonce={recv_nonce} — decoded and authenticated\n");
    }

    // ---- Replay attack -----------------------------------------------------------
    let wire_bytes = to_v2_bytes(header, &arm_command());
    let packet = sk.sign(&wire_bytes, 42);
    assert!(vk.verify(&packet, 42).is_none(), "replay must be rejected");
    println!("[sec]    REPLAY ATTACK: REJECTED");

    // ---- Tampered frame ------------------------------------------------------------
    let mut tampered = packet.clone();
    tampered[3] ^= 0xFF;
    assert!(vk.verify(&tampered, 0).is_none(), "tampered frame must be rejected");
    println!("[sec]    TAMPERED MAVLINK FRAME: REJECTED (ML-DSA-87 signature invalid)");

    // ---- Forged command (wrong key) -------------------------------------------------
    let attacker_sk = SigningKey::generate();
    let forged = attacker_sk.sign(&wire_bytes, 43);
    assert!(vk.verify(&forged, 0).is_none(), "forged command must be rejected");
    println!("[sec]    FORGED COMMAND (wrong key): REJECTED");

    println!("\nMAVLink v2 + CleitonQ ML-DSA-87 integration demo complete.");
    println!("Real wire-format frames signed, verified, and decoded successfully.");
}
