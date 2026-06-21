// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Resource-exhaustion checks for both verifiers. A drone's radio link is
//! attacker-reachable; these tests assert the verifier rejects hostile
//! input in bounded time and memory instead of allocating, looping, or
//! panicking on attacker-controlled length/content.

use cleitonq::channel::AuthChannel;
use cleitonq::dsa::{SigningKey, VerifyingKey};
use std::time::{Duration, Instant};

// Debug builds run unoptimized HMAC/SHA3/ML-DSA and are routinely 50-100x
// slower than release — these budgets exist to catch quadratic/exponential
// blowups (a real DoS finding), not to benchmark absolute speed (that's
// `benches/pqc_bench.rs`, release-only). Scale generously for debug so the
// budget doesn't fire on profile alone.
fn budget(release_secs: u64) -> Duration {
    let factor = if cfg!(debug_assertions) { 100 } else { 1 };
    Duration::from_secs(release_secs * factor)
}

#[test]
fn channel_verify_rejects_malformed_packets_in_volume() {
    let ch = AuthChannel::from_raw_key([0x99u8; 32]);
    let start = Instant::now();
    let mut accepted = 0u64;

    // Truncated/garbage packets across a range of lengths, repeated with
    // varying content — none should verify, and none should make the loop
    // take anywhere near the budget (a quadratic verify() would blow this
    // up immediately even at this modest volume).
    for round in 0..5u8 {
        for len in 0..2048usize {
            let packet: Vec<u8> = (0..len).map(|i| (i as u8) ^ round).collect();
            if ch.verify(&packet, 0).is_some() {
                accepted += 1;
            }
        }
    }

    assert_eq!(accepted, 0, "no garbage packet should ever verify");
    assert!(
        start.elapsed() < budget(2),
        "verify() must stay fast under hostile volume, took {:?}",
        start.elapsed()
    );
}

#[test]
fn channel_verify_rejects_huge_packet_without_excessive_cost() {
    let ch = AuthChannel::from_raw_key([0x77u8; 32]);
    // 16 MiB of attacker-controlled bytes — must not be quadratic, must
    // not panic, must reject (HMAC over garbage will not match).
    let huge = vec![0xAAu8; 16 * 1024 * 1024];
    let start = Instant::now();
    assert!(ch.verify(&huge, 0).is_none());
    assert!(
        start.elapsed() < budget(2),
        "verify() on a 16MiB packet took {:?}, expected linear-time rejection",
        start.elapsed()
    );
}

#[test]
fn dsa_verify_rejects_malformed_packets_without_panicking() {
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();
    let sig_bytes = cleitonq::dsa::SIG_BYTES;

    // Lengths around the real signature size are the interesting boundary —
    // off-by-one above/below the expected size, where slice arithmetic in
    // `verify()` could panic if not carefully bounds-checked.
    for delta in -3i64..=3 {
        let len = (sig_bytes as i64 + 8 + delta).max(0) as usize;
        let packet = vec![0x5Au8; len];
        assert!(vk.verify(&packet, 0).is_none());
    }

    // Zero-length and single-byte edge cases.
    assert!(vk.verify(&[], 0).is_none());
    assert!(vk.verify(&[0u8], 0).is_none());
}

#[test]
fn dsa_verify_rejects_oversized_packet_in_bounded_time() {
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();

    // A flood of packets the right *length* to pass the size check and
    // reach full ML-DSA signature decode/verify — this is the expensive
    // path (~120us each per the benches), so this also bounds worst-case
    // CPU cost of a flood of correctly-sized-but-forged packets.
    let start = Instant::now();
    let forged_count = 200;
    for i in 0..forged_count {
        let mut packet = vec![0u8; 8 + cleitonq::dsa::SIG_BYTES];
        packet[0] = i as u8;
        assert!(vk.verify(&packet, 0).is_none());
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < budget(2),
        "{forged_count} forged-but-correctly-sized packets took {elapsed:?}; \
         a flood of these is the realistic DoS vector against ML-DSA verify"
    );
}

#[test]
fn verifying_key_load_rejects_malformed_files_without_panicking() {
    let path = format!("/tmp/cq_dos_bad_vk_{}.bin", std::process::id());
    for len in [0usize, 1, 100, cleitonq::dsa::VK_BYTES - 1, cleitonq::dsa::VK_BYTES + 1, 10_000] {
        std::fs::write(&path, vec![0x11u8; len]).unwrap();
        assert!(VerifyingKey::load(&path).is_err());
    }
    std::fs::remove_file(&path).ok();
}
