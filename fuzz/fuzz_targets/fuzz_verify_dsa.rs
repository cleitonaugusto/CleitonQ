#![no_main]

use cleitonq::dsa::{SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

// Keygen + signing dominate at ~1ms each; doing them per-iteration would limit
// the fuzzer to ~1000 exec/s and mostly measure ML-DSA itself, not the parser.
// A fixed key generated once keeps focus on `VerifyingKey::verify`'s packet
// parsing (length checks, slice arithmetic, encode/decode of attacker bytes).
static VK: Lazy<VerifyingKey> = Lazy::new(|| SigningKey::generate().verifying_key());

fuzz_target!(|data: &[u8]| {
    let _ = VK.verify(data, 0);
});
