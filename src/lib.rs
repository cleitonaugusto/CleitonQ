//! # CleitonQ
//!
//! **Post-quantum authenticated command & control for embedded and autonomous systems.**
//!
//! Created by Cleiton Augusto Correa Bezerra.
//!
//! CleitonQ secures the communication layer between ground stations and
//! autonomous systems (drones, robots, vehicles) against both classical and
//! quantum adversaries, using NIST-standardised post-quantum algorithms:
//!
//! | Algorithm | Standard | Purpose |
//! |---|---|---|
//! | ML-KEM-1024 | FIPS 203 | Session key establishment (forward secrecy) |
//! | ML-DSA-87   | FIPS 204 | Command signing (non-repudiation) |
//! | HMAC-SHA3-256 | FIPS 202 | Per-packet authentication (low overhead) |
//!
//! ## Quick start
//!
//! ### Symmetric channel (session key from ML-KEM)
//!
//! ```no_run
//! use cleitonq::prelude::*;
//!
//! // Ground station: establish a forward-secret session
//! let (ciphertext, session_key) = kem::encapsulate("drone_kem_ek.bin").unwrap();
//! // send `ciphertext` to the drone over any channel
//!
//! let c2_tx = AuthChannel::new(&session_key, ChannelDomain::C2);
//! let packet = c2_tx.sign(b"thrust=9.81", 1);
//!
//! // Drone: recover the session key and verify
//! let dk = kem::KemKeyPair::load_decapsulation_key("drone_kem_dk.bin").unwrap();
//! let session_key = kem::decapsulate(&dk, &ciphertext).unwrap();
//! let c2_rx = AuthChannel::new(&session_key, ChannelDomain::C2);
//! let (payload, _nonce) = c2_rx.verify(&packet, 0).expect("authenticated");
//! ```
//!
//! ### Command signing with non-repudiation (ML-DSA-87)
//!
//! ```no_run
//! use cleitonq::prelude::*;
//!
//! // Ground station
//! let sk = dsa::SigningKey::generate();
//! let packet = sk.sign(b"waypoint=100,80,50", 1);
//!
//! // Drone
//! let vk = sk.verifying_key();
//! let (payload, nonce) = vk.verify(&packet, 0).expect("valid command");
//! ```
//!
//! ## Security properties
//!
//! - **Quantum resistance** — ML-KEM and ML-DSA are secure against Shor's algorithm.
//! - **Forward secrecy** — each ML-KEM session produces an independent key; compromising
//!   the drone's long-term key does not expose past sessions.
//! - **Anti-replay** — every packet carries a monotonically-increasing nonce;
//!   replayed packets are rejected without revealing why.
//! - **Domain separation** — a single session key produces independent sub-keys per
//!   channel (C2, telemetry, mesh) via distinct SHA3-256 salts.
//! - **Timing-safe verification** — all `verify` operations return `None` on failure
//!   without revealing which check failed.

pub mod channel;
pub mod dsa;
pub mod kem;

/// Convenience re-exports for the most common types.
pub mod prelude {
    pub use crate::channel::{AuthChannel, ChannelDomain};
    pub use crate::dsa::{SigningKey, VerifyingKey};
    pub use crate::kem;
}

/// CleitonQ crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// CleitonQ crate author.
pub const AUTHOR: &str = "Cleiton Augusto Correa Bezerra";
