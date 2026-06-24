// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.
//
// CleitonQ C API — post-quantum authentication for autonomous systems.
//
// Memory model: all opaque handles are heap-allocated Rust values wrapped in
// Box<T> and returned as raw pointers. The caller owns the pointer after
// creation and must free it with the corresponding _free() function.
// No function retains a pointer passed by the caller.

use cleitonq::channel::{AuthChannel, ChannelDomain};
use cleitonq::dsa::{SigningKey, VerifyingKey};
use cleitonq::kem::{KemKeyPair, decapsulate_from_seed, encapsulate_raw};
use std::slice;

// ── Error codes ──────────────────────────────────────────────────────────────

/// Success.
pub const CLEITONQ_OK: i32 = 0;
/// A required pointer argument was null.
pub const CLEITONQ_ERR_NULL: i32 = -1;
/// Authentication or signature verification failed.
pub const CLEITONQ_ERR_VERIFY: i32 = -2;
/// Output buffer too small.
pub const CLEITONQ_ERR_BUFFER: i32 = -3;
/// Invalid key, seed, or argument value.
pub const CLEITONQ_ERR_INVALID: i32 = -4;

// ── Version ──────────────────────────────────────────────────────────────────

/// Returns a null-terminated ASCII string: "0.2.0\0".
/// The returned pointer is valid for the lifetime of the process.
#[no_mangle]
pub extern "C" fn cleitonq_version() -> *const std::os::raw::c_char {
    static VERSION: &[u8] = b"0.2.0\0";
    VERSION.as_ptr() as *const std::os::raw::c_char
}

// ── AuthChannel ───────────────────────────────────────────────────────────────
//
// Authenticated channel: HMAC-SHA3-256 with a 32-byte session key.
// Wire format: [payload (N bytes) | nonce LE64 (8 bytes) | HMAC-SHA3-256 (32 bytes)]
// Overhead: 40 bytes per packet.

/// Domain labels for key derivation. Pass as `domain` to cleitonq_channel_new().
#[repr(C)]
pub enum CleitonqDomain {
    /// Inbound C2 (ground station → drone).
    C2 = 0,
    /// Outbound telemetry (drone → ground station).
    Telemetry = 1,
    /// Inter-drone mesh.
    Mesh = 2,
}

/// Creates an AuthChannel from a 32-byte session key and domain label.
///
/// Returns null on invalid input. The caller must free with cleitonq_channel_free().
///
/// # Parameters
/// - `session_key` — pointer to exactly 32 bytes (e.g. from cleitonq_kem_decapsulate).
/// - `domain`      — CLEITONQ_DOMAIN_C2 (0), TELEMETRY (1), or MESH (2).
#[no_mangle]
pub unsafe extern "C" fn cleitonq_channel_new(
    session_key: *const u8,
    domain: i32,
) -> *mut AuthChannel {
    if session_key.is_null() {
        return std::ptr::null_mut();
    }
    let key = &*(session_key as *const [u8; 32]);
    let dom = match domain {
        0 => ChannelDomain::C2,
        1 => ChannelDomain::Telemetry,
        2 => ChannelDomain::Mesh,
        _ => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(AuthChannel::new(key, dom)))
}

/// Frees a channel created by cleitonq_channel_new(). Safe to call with null.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_channel_free(ch: *mut AuthChannel) {
    if !ch.is_null() {
        drop(Box::from_raw(ch));
    }
}

/// Signs `payload` with `nonce` and writes the authenticated packet to `out`.
///
/// `out` must point to at least `payload_len + 40` bytes.
///
/// Returns the total packet length (>= 40) on success, or a negative error code.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_channel_sign(
    ch: *const AuthChannel,
    payload: *const u8,
    payload_len: usize,
    nonce: u64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if ch.is_null() || (payload_len > 0 && payload.is_null()) || out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let min_out = payload_len.saturating_add(40);
    if out_cap < min_out {
        return CLEITONQ_ERR_BUFFER;
    }
    let pl = if payload_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(payload, payload_len)
    };
    let packet = (*ch).sign(pl, nonce);
    std::ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len());
    packet.len() as i32
}

/// Verifies an authenticated packet and extracts the payload.
///
/// On success:
/// - Copies the payload to `payload_out` (if non-null, must be >= packet_len bytes).
/// - Writes the packet nonce to `nonce_out` (if non-null).
/// - Returns the payload length (>= 0).
///
/// On failure returns a negative error code. Failure reveals no timing information
/// about which check failed.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_channel_verify(
    ch: *const AuthChannel,
    packet: *const u8,
    packet_len: usize,
    last_nonce: u64,
    payload_out: *mut u8,
    payload_cap: usize,
    nonce_out: *mut u64,
) -> i32 {
    if ch.is_null() || packet.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let pkt = slice::from_raw_parts(packet, packet_len);
    match (*ch).verify(pkt, last_nonce) {
        None => CLEITONQ_ERR_VERIFY,
        Some((pl, nonce)) => {
            if !payload_out.is_null() {
                if payload_cap < pl.len() {
                    return CLEITONQ_ERR_BUFFER;
                }
                if !pl.is_empty() {
                    std::ptr::copy_nonoverlapping(pl.as_ptr(), payload_out, pl.len());
                }
            }
            if !nonce_out.is_null() {
                *nonce_out = nonce;
            }
            pl.len() as i32
        }
    }
}

// ── ML-DSA-87 signing ─────────────────────────────────────────────────────────
//
// Wire format: [payload (N bytes) | nonce LE64 (8 bytes) | ML-DSA-87 sig (4627 bytes)]
// Overhead: 4635 bytes per signed command.

/// Generates a fresh ML-DSA-87 signing key using the OS CSPRNG.
/// Returns null on allocation failure. Free with cleitonq_dsa_sk_free().
#[no_mangle]
pub extern "C" fn cleitonq_dsa_keygen() -> *mut SigningKey {
    Box::into_raw(Box::new(SigningKey::generate()))
}

/// Reconstructs a signing key from its 32-byte seed.
/// Returns null on invalid input. Free with cleitonq_dsa_sk_free().
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_sk_from_seed(seed: *const u8) -> *mut SigningKey {
    if seed.is_null() {
        return std::ptr::null_mut();
    }
    let s = slice::from_raw_parts(seed, 32);
    match SigningKey::from_seed_bytes(s) {
        Ok(sk) => Box::into_raw(Box::new(sk)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Exports the 32-byte seed of a signing key into `seed_out`.
/// `seed_out` must point to at least 32 bytes.
/// Returns CLEITONQ_OK or a negative error code.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_sk_to_seed(
    sk: *const SigningKey,
    seed_out: *mut u8,
) -> i32 {
    if sk.is_null() || seed_out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let seed = (*sk).to_seed_bytes();
    std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_out, 32);
    CLEITONQ_OK
}

/// Derives the verifying key from a signing key.
/// Returns null on allocation failure. Free with cleitonq_dsa_vk_free().
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_verifying_key(
    sk: *const SigningKey,
) -> *mut VerifyingKey {
    if sk.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new((*sk).verifying_key()))
}

/// Reconstructs a verifying key from its raw 2592-byte encoding.
/// Returns null on invalid input. Free with cleitonq_dsa_vk_free().
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_vk_from_bytes(
    vk_bytes: *const u8,
) -> *mut VerifyingKey {
    if vk_bytes.is_null() {
        return std::ptr::null_mut();
    }
    let b = slice::from_raw_parts(vk_bytes, 2592);
    match VerifyingKey::from_bytes(b) {
        Ok(vk) => Box::into_raw(Box::new(vk)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Exports the raw 2592-byte verifying key into `vk_out`.
/// `vk_out` must point to at least 2592 bytes.
/// Returns CLEITONQ_OK or a negative error code.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_vk_to_bytes(
    vk: *const VerifyingKey,
    vk_out: *mut u8,
) -> i32 {
    if vk.is_null() || vk_out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let bytes = (*vk).to_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), vk_out, bytes.len());
    CLEITONQ_OK
}

/// Frees a signing key. Safe to call with null.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_sk_free(sk: *mut SigningKey) {
    if !sk.is_null() {
        drop(Box::from_raw(sk));
    }
}

/// Frees a verifying key. Safe to call with null.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_vk_free(vk: *mut VerifyingKey) {
    if !vk.is_null() {
        drop(Box::from_raw(vk));
    }
}

/// Signs `payload` with `nonce` using ML-DSA-87 and writes the packet to `out`.
///
/// `out` must point to at least `payload_len + 4635` bytes.
/// Returns the total packet length on success, or a negative error code.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_sign(
    sk: *const SigningKey,
    payload: *const u8,
    payload_len: usize,
    nonce: u64,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if sk.is_null() || (payload_len > 0 && payload.is_null()) || out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let min_out = payload_len.saturating_add(4635);
    if out_cap < min_out {
        return CLEITONQ_ERR_BUFFER;
    }
    let pl = if payload_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(payload, payload_len)
    };
    let packet = (*sk).sign(pl, nonce);
    std::ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len());
    packet.len() as i32
}

/// Verifies an ML-DSA-87 signed packet and extracts the payload.
///
/// On success copies payload to `payload_out`, writes nonce to `nonce_out`.
/// Returns payload length (>= 0) on success, negative on failure.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_dsa_verify(
    vk: *const VerifyingKey,
    packet: *const u8,
    packet_len: usize,
    last_nonce: u64,
    payload_out: *mut u8,
    payload_cap: usize,
    nonce_out: *mut u64,
) -> i32 {
    if vk.is_null() || packet.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let pkt = slice::from_raw_parts(packet, packet_len);
    match (*vk).verify(pkt, last_nonce) {
        None => CLEITONQ_ERR_VERIFY,
        Some((pl, nonce)) => {
            if !payload_out.is_null() {
                if payload_cap < pl.len() {
                    return CLEITONQ_ERR_BUFFER;
                }
                if !pl.is_empty() {
                    std::ptr::copy_nonoverlapping(pl.as_ptr(), payload_out, pl.len());
                }
            }
            if !nonce_out.is_null() {
                *nonce_out = nonce;
            }
            pl.len() as i32
        }
    }
}

// ── ML-KEM-1024 session key establishment ────────────────────────────────────
//
// Ground station: cleitonq_kem_encapsulate() → send ciphertext to drone
// Drone:          cleitonq_kem_decapsulate() → recover shared session key
// Both sides then feed session_key into cleitonq_channel_new().

/// Generates a fresh ML-KEM-1024 key pair using the OS CSPRNG.
/// Returns null on failure. Free with cleitonq_kem_keypair_free().
#[no_mangle]
pub extern "C" fn cleitonq_kem_keygen() -> *mut KemKeyPair {
    Box::into_raw(Box::new(KemKeyPair::generate()))
}

/// Frees a KEM key pair. Safe to call with null.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_kem_keypair_free(kp: *mut KemKeyPair) {
    if !kp.is_null() {
        drop(Box::from_raw(kp));
    }
}

/// Exports the 1568-byte public encapsulation key into `ek_out`.
/// Returns CLEITONQ_OK or a negative error code.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_kem_ek_bytes(
    kp: *const KemKeyPair,
    ek_out: *mut u8,
    out_cap: usize,
) -> i32 {
    if kp.is_null() || ek_out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    if out_cap < 1568 {
        return CLEITONQ_ERR_BUFFER;
    }
    let bytes = (*kp).ek_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ek_out, bytes.len());
    CLEITONQ_OK
}

/// Exports the 64-byte decapsulation key seed into `dk_out`.
/// Store this securely — it reconstructs the private decapsulation key.
/// Returns CLEITONQ_OK or a negative error code.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_kem_dk_seed(
    kp: *const KemKeyPair,
    dk_out: *mut u8,
    out_cap: usize,
) -> i32 {
    if kp.is_null() || dk_out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    if out_cap < 64 {
        return CLEITONQ_ERR_BUFFER;
    }
    match (*kp).dk_seed_bytes() {
        Ok(seed) => {
            std::ptr::copy_nonoverlapping(seed.as_ptr(), dk_out, 64);
            CLEITONQ_OK
        }
        Err(_) => CLEITONQ_ERR_INVALID,
    }
}

/// Ground station: encapsulate a fresh session key using the drone's public key.
///
/// - `ek_bytes`   — 1568-byte encapsulation key (from drone).
/// - `ct_out`     — 1568-byte output buffer for the ciphertext (send to drone).
/// - `ss_out`     — 32-byte output buffer for the session key (keep locally).
///
/// Returns CLEITONQ_OK on success. On success, feed `ss_out` into
/// cleitonq_channel_new() to create the authenticated channel.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_kem_encapsulate(
    ek_bytes: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> i32 {
    if ek_bytes.is_null() || ct_out.is_null() || ss_out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let ek = slice::from_raw_parts(ek_bytes, 1568);
    match encapsulate_raw(ek) {
        Ok((ct, ss)) => {
            std::ptr::copy_nonoverlapping(ct.as_ptr(), ct_out, ct.len());
            std::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32);
            CLEITONQ_OK
        }
        Err(_) => CLEITONQ_ERR_INVALID,
    }
}

/// Drone: recover the session key from the ground station's ciphertext.
///
/// - `dk_seed`    — 64-byte decapsulation key seed (stored on drone).
/// - `ciphertext` — 1568-byte ciphertext received from ground station.
/// - `ss_out`     — 32-byte output buffer for the session key.
///
/// Returns CLEITONQ_OK on success. On success, feed `ss_out` into
/// cleitonq_channel_new() to create the authenticated channel.
#[no_mangle]
pub unsafe extern "C" fn cleitonq_kem_decapsulate(
    dk_seed: *const u8,
    ciphertext: *const u8,
    ss_out: *mut u8,
) -> i32 {
    if dk_seed.is_null() || ciphertext.is_null() || ss_out.is_null() {
        return CLEITONQ_ERR_NULL;
    }
    let seed = slice::from_raw_parts(dk_seed, 64);
    let ct = slice::from_raw_parts(ciphertext, 1568);
    match decapsulate_from_seed(seed, ct) {
        Ok(ss) => {
            std::ptr::copy_nonoverlapping(ss.as_ptr(), ss_out, 32);
            CLEITONQ_OK
        }
        Err(_) => CLEITONQ_ERR_INVALID,
    }
}
