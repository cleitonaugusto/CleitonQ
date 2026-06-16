#![no_main]

use cleitonq::channel::AuthChannel;
use libfuzzer_sys::fuzz_target;

// Fixed key: the fuzzer's job is to find inputs that break parsing/verification
// logic, not to search the key space. A fixed key keeps every run deterministic
// and reproducible from a saved corpus entry.
fuzz_target!(|data: &[u8]| {
    let ch = AuthChannel::from_raw_key([0x42u8; 32]);
    let _ = ch.verify(data, 0);
});
