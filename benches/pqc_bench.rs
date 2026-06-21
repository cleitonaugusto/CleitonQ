// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! CleitonQ performance benchmarks.
//!
//! Measures the latency of ML-KEM-1024, ML-DSA-87, and HMAC-SHA3-256
//! operations to validate suitability for embedded/real-time C2 systems.
//!
//! Run with:
//!   cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cleitonq::{
    channel::{AuthChannel, ChannelDomain},
    dsa::SigningKey,
    kem::{self, KemKeyPair},
};
use ml_kem::{kem::Encapsulate, Kem, MlKem1024};

fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024");

    // Keygen
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _ = black_box(MlKem1024::generate_keypair());
        });
    });

    // Encapsulation
    let (_, ek) = MlKem1024::generate_keypair();
    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let _ = black_box(ek.encapsulate());
        });
    });

    // Decapsulation
    let (dk, ek) = MlKem1024::generate_keypair();
    let (ct, _) = ek.encapsulate();
    group.bench_function("decapsulate", |b| {
        use ml_kem::kem::TryDecapsulate;
        b.iter(|| {
            let _ = black_box(dk.try_decapsulate(&ct));
        });
    });

    group.finish();
}

fn bench_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA-87");

    let sk = SigningKey::generate();
    let vk = sk.verifying_key();
    let payload = b"thrust=9.81 roll=0.0 pitch=0.0 yaw=0.0";

    // Signing
    group.bench_function("sign/40B", |b| {
        b.iter(|| {
            let _ = black_box(sk.sign(payload, 1));
        });
    });

    // Verification
    let packet = sk.sign(payload, 1);
    group.bench_function("verify/40B", |b| {
        b.iter(|| {
            let _ = black_box(vk.verify(&packet, 0));
        });
    });

    // Larger payload (MAVLink-sized ~256 bytes)
    let large_payload = vec![0xABu8; 256];
    group.bench_function("sign/256B", |b| {
        b.iter(|| {
            let _ = black_box(sk.sign(&large_payload, 1));
        });
    });

    let large_packet = sk.sign(&large_payload, 1);
    group.bench_function("verify/256B", |b| {
        b.iter(|| {
            let _ = black_box(vk.verify(&large_packet, 0));
        });
    });

    group.finish();
}

fn bench_channel(c: &mut Criterion) {
    let mut group = c.benchmark_group("HMAC-SHA3-256 channel");

    let key = [0x42u8; 32];
    let ch = AuthChannel::from_raw_key(key);
    let payload = b"altitude=50.1 vx=1.2 vy=0.3 bat=87%";

    group.bench_function("sign/38B", |b| {
        b.iter(|| {
            let _ = black_box(ch.sign(payload, 1));
        });
    });

    let packet = ch.sign(payload, 1);
    group.bench_function("verify/38B", |b| {
        b.iter(|| {
            let _ = black_box(ch.verify(&packet, 0));
        });
    });

    group.finish();
}

fn bench_full_handshake(c: &mut Criterion) {
    // Measures the complete session establishment (KEM encap + decap + channel init).
    // This is the one-time cost paid at connection setup.
    c.bench_function("full_session_establishment", |b| {
        let pid = std::process::id();
        let dk_path = format!("/tmp/cq_bench_dk_{pid}.bin");
        let ek_path = format!("/tmp/cq_bench_ek_{pid}.bin");
        let keypair = KemKeyPair::generate();
        keypair.save(&dk_path, &ek_path).unwrap();

        b.iter(|| {
            let (ct, sk) = black_box(kem::encapsulate(&ek_path).unwrap());
            let dk = KemKeyPair::load_decapsulation_key(&dk_path).unwrap();
            let rk = black_box(kem::decapsulate(&dk, &ct).unwrap());
            let _ = black_box(AuthChannel::new(&rk, ChannelDomain::C2));
            let _ = black_box(AuthChannel::new(&sk, ChannelDomain::C2));
        });

        std::fs::remove_file(&dk_path).ok();
        std::fs::remove_file(&ek_path).ok();
    });
}

criterion_group!(benches, bench_kem, bench_dsa, bench_channel, bench_full_handshake);
criterion_main!(benches);
