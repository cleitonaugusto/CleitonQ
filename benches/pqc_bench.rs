// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! CleitonQ performance benchmarks.
//!
//! Measures the latency of ML-KEM-1024, ML-DSA-87, and HMAC-SHA3-256
//! operations to validate suitability for embedded/real-time C2 systems.
//!
//! Run with:
//!   cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "fips205")]
use std::time::Duration;
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

/// SLH-DSA (FIPS 205) across the three published profiles.
///
/// These numbers are quoted in the `fips205` module documentation and in the
/// CCSDS adapter specification. They live here so the quote is reproducible on
/// demand and tracked by the benchmark workflows, rather than resting on a
/// one-off measurement nobody can repeat.
///
/// Signing dominates and is slow by construction — the "s" parameter sets trade
/// signing time for signature size — so the signing groups run few samples.
/// Verification is cheap, which is the property that matters operationally: the
/// cost falls on an offline ceremony, and every later check is milliseconds.
///
/// Run with: `cargo bench --features fips205 --bench pqc_bench -- SLH-DSA`
#[cfg(feature = "fips205")]
fn bench_slh_dsa(c: &mut Criterion) {
    use cleitonq::fips205::{
        RevocationProfile, RevocationSigner, Sha2_128s, Sha2_192s, Sha2_256s,
    };

    const MSG: &[u8] = b"revoke subject=CLQD-4F2A reason=key-compromise";

    fn bench_profile<P: RevocationProfile>(c: &mut Criterion, name: &str) {
        let mut group = c.benchmark_group(format!("SLH-DSA/{name}"));
        // Signing a single 256s signature takes on the order of a second, so the
        // criterion default of 100 samples would put this group in the minutes.
        group.sample_size(10).measurement_time(Duration::from_secs(20));

        group.bench_function("keygen", |b| {
            b.iter(|| black_box(RevocationSigner::<P>::generate()));
        });

        let signer = RevocationSigner::<P>::generate();
        group.bench_function("sign", |b| {
            b.iter(|| black_box(signer.sign(black_box(MSG))));
        });

        let verifier = signer.verifying_key();
        let sig = signer.sign(MSG);
        group.bench_function("verify", |b| {
            b.iter(|| black_box(verifier.verify(black_box(MSG), black_box(&sig))));
        });

        group.finish();
    }

    // Ascending security category, so the report reads as the trade it is:
    // signature size and signing cost against margin.
    bench_profile::<Sha2_128s>(c, "SHA2-128s-cat1");
    bench_profile::<Sha2_192s>(c, "SHA2-192s-cat3");
    bench_profile::<Sha2_256s>(c, "SHA2-256s-cat5");
}

#[cfg(not(feature = "fips205"))]
fn bench_slh_dsa(_c: &mut Criterion) {}

criterion_group!(
    benches,
    bench_kem,
    bench_dsa,
    bench_channel,
    bench_full_handshake,
    bench_slh_dsa
);
criterion_main!(benches);
