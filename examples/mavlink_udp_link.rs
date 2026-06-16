// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Ground-station/drone link over a real OS UDP socket (loopback).
//!
//! `examples/mavlink_c2.rs` builds and verifies signed MAVLink v2 frames
//! entirely in memory — useful to prove the wire format and signature
//! logic are correct, but it never touches the network stack. This example
//! sends the same signed frames over an actual `UdpSocket`, so the bytes
//! cross a real send/recv boundary (syscalls, kernel buffers, socket
//! framing) instead of being passed as a `Vec<u8>` between functions.
//!
//! Run with:
//!   cargo run --example mavlink_udp_link

use cleitonq::dsa::SigningKey;
use cleitonq::nonce::AtomicNonce;
use mavlink::dialects::common::{MavCmd, MavMessage, COMMAND_LONG_DATA};
use mavlink::MavHeader;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn to_v2_bytes(header: MavHeader, msg: &MavMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    mavlink::write_v2_msg(&mut buf, header, msg).expect("encode must succeed");
    buf
}

fn arm_command() -> MavMessage {
    MavMessage::COMMAND_LONG(COMMAND_LONG_DATA {
        param1: 1.0,
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

fn main() {
    println!("CleitonQ — Ground station <-> drone over a real UDP socket\n");

    let sk = SigningKey::generate();
    let vk = sk.verifying_key();

    let drone_socket = UdpSocket::bind("127.0.0.1:0").expect("bind drone socket");
    let drone_addr = drone_socket.local_addr().unwrap();
    println!("[drone]  listening on {drone_addr}");

    let drone = thread::spawn(move || {
        // Must exceed dsa::OVERHEAD (8 + ML-DSA-87's 4627-byte signature) —
        // a smaller buffer silently truncates the UDP datagram on recv.
        let mut buf = [0u8; 8192];
        let mut last_nonce = 0u64;
        let mut accepted = 0u32;
        let mut rejected = 0u32;

        // Expect: 5 legitimate signed packets, then 1 replay (must reject),
        // then 1 tampered packet (must reject) — matches what main() sends.
        for _ in 0..7 {
            let (len, src) = drone_socket.recv_from(&mut buf).expect("recv");
            let packet = &buf[..len];
            match vk.verify(packet, last_nonce) {
                Some((payload, nonce)) => {
                    last_nonce = nonce;
                    accepted += 1;
                    println!(
                        "[drone]  ACCEPTED from {src}: nonce={nonce} mavlink_bytes={}",
                        payload.len()
                    );
                }
                None => {
                    rejected += 1;
                    println!("[drone]  REJECTED packet from {src} ({len} bytes on the wire)");
                }
            }
        }

        (accepted, rejected)
    });

    // Give the drone socket a moment to start listening.
    thread::sleep(Duration::from_millis(50));

    let gs_socket = UdpSocket::bind("127.0.0.1:0").expect("bind ground station socket");
    let header = MavHeader { system_id: 255, component_id: 0, sequence: 1 };
    let wire_bytes = to_v2_bytes(header, &arm_command());
    let nonce_gen = AtomicNonce::new(1);

    // 5 legitimate commands, each with a fresh nonce.
    let mut last_sent = Vec::new();
    for _ in 0..5 {
        let packet = sk.sign(&wire_bytes, nonce_gen.next());
        gs_socket.send_to(&packet, drone_addr).expect("send");
        last_sent = packet;
        thread::sleep(Duration::from_millis(20));
    }

    // Replay: resend the exact same bytes captured off the wire — drone must reject.
    gs_socket.send_to(&last_sent, drone_addr).expect("send replay");
    thread::sleep(Duration::from_millis(20));

    // Tamper: flip a bit in a freshly-signed packet before sending.
    let mut tampered = sk.sign(&wire_bytes, nonce_gen.next());
    let last_byte = tampered.len() - 1;
    tampered[last_byte] ^= 0xFF;
    gs_socket.send_to(&tampered, drone_addr).expect("send tampered");

    let (accepted, rejected) = drone.join().expect("drone thread");
    println!("\n[result] accepted={accepted} rejected={rejected} (expected 5 accepted, 2 rejected)");
    assert_eq!(accepted, 5, "all 5 legitimate packets must be accepted over the real socket");
    assert_eq!(rejected, 2, "replay and tampered packet must both be rejected");
    println!("UDP link test passed: signed MAVLink v2 frames survive a real socket round-trip.");
}
