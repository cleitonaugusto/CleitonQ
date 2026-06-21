use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyBytes;
use cleitonq::dsa::{SigningKey, VerifyingKey};
use cleitonq::kem::{KemKeyPair, encapsulate_raw, decapsulate_from_seed};
use cleitonq::channel::{AuthChannel, ChannelDomain};

fn domain_from_int(d: u8) -> PyResult<ChannelDomain> {
    match d {
        0 => Ok(ChannelDomain::C2),
        1 => Ok(ChannelDomain::Telemetry),
        2 => Ok(ChannelDomain::Mesh),
        _ => Err(PyValueError::new_err("domain must be 0 (C2), 1 (Telemetry), or 2 (Mesh)")),
    }
}

// ── DSA — ML-DSA-87 ──────────────────────────────────────────────────────────

/// Generate a fresh ML-DSA-87 key pair.
/// Returns (sk_seed: bytes[32], vk: bytes[2592])
#[pyfunction]
fn dsa_keygen(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let sk = SigningKey::generate();
    let seed = sk.to_seed_bytes();
    let vk = sk.verifying_key().to_bytes();
    Ok((PyBytes::new_bound(py, &seed).into(), PyBytes::new_bound(py, &vk).into()))
}

/// Sign a payload with ML-DSA-87.
/// Returns the full signed packet (payload + nonce + signature).
#[pyfunction]
fn dsa_sign(py: Python<'_>, sk_seed: &[u8], payload: &[u8], nonce: u64) -> PyResult<Py<PyBytes>> {
    let sk = SigningKey::from_seed_bytes(sk_seed)
        .map_err(|e| PyValueError::new_err(format!("invalid signing key: {e}")))?;
    Ok(PyBytes::new_bound(py, &sk.sign(payload, nonce)).into())
}

/// Verify a signed packet with ML-DSA-87.
/// Returns (payload: bytes, nonce: int) on success, or raises ValueError on failure.
/// The returned nonce must be passed as last_nonce in the next call to enforce anti-replay.
#[pyfunction]
fn dsa_verify(py: Python<'_>, vk: &[u8], packet: &[u8], last_nonce: u64) -> PyResult<(Py<PyBytes>, u64)> {
    let vk_obj = VerifyingKey::from_bytes(vk)
        .map_err(|e| PyValueError::new_err(format!("invalid verifying key: {e}")))?;
    vk_obj.verify(packet, last_nonce)
        .map(|(payload, nonce)| (PyBytes::new_bound(py, payload).into(), nonce))
        .ok_or_else(|| PyValueError::new_err("signature verification failed or nonce replay"))
}

// ── KEM — ML-KEM-1024 ────────────────────────────────────────────────────────

/// Generate a fresh ML-KEM-1024 key pair.
/// Returns (dk_seed: bytes[64], ek: bytes[1568])
#[pyfunction]
fn kem_keygen(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let kp = KemKeyPair::generate();
    let dk = kp.dk_seed_bytes()
        .map_err(|e| PyValueError::new_err(format!("keygen failed: {e}")))?;
    let ek = kp.ek_bytes();
    Ok((PyBytes::new_bound(py, &dk).into(), PyBytes::new_bound(py, &ek).into()))
}

/// Encapsulate a session key using the drone's public encapsulation key.
/// Returns (ciphertext: bytes[1568], shared_secret: bytes[32])
#[pyfunction]
fn kem_encapsulate(py: Python<'_>, ek: &[u8]) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (ct, ss) = encapsulate_raw(ek)
        .map_err(|e| PyValueError::new_err(format!("encapsulation failed: {e}")))?;
    Ok((PyBytes::new_bound(py, &ct).into(), PyBytes::new_bound(py, ss.as_ref()).into()))
}

/// Decapsulate and recover the session key.
/// Returns shared_secret: bytes[32]
#[pyfunction]
fn kem_decapsulate(py: Python<'_>, dk_seed: &[u8], ciphertext: &[u8]) -> PyResult<Py<PyBytes>> {
    let ss = decapsulate_from_seed(dk_seed, ciphertext)
        .map_err(|e| PyValueError::new_err(format!("decapsulation failed: {e}")))?;
    Ok(PyBytes::new_bound(py, ss.as_ref()).into())
}

// ── HMAC channel — HMAC-SHA3-256 ─────────────────────────────────────────────

/// Sign a packet with HMAC-SHA3-256.
/// domain: 0=C2, 1=Telemetry, 2=Mesh
/// Returns authenticated packet bytes.
#[pyfunction]
fn channel_sign(py: Python<'_>, session_key: &[u8], domain: u8, payload: &[u8], nonce: u64) -> PyResult<Py<PyBytes>> {
    if session_key.len() != 32 {
        return Err(PyValueError::new_err("session_key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(session_key);
    let ch = AuthChannel::new(&key, domain_from_int(domain)?);
    Ok(PyBytes::new_bound(py, &ch.sign(payload, nonce)).into())
}

/// Verify an HMAC-SHA3-256 authenticated packet.
/// Returns (payload: bytes, nonce: int) on success, or raises ValueError on failure.
/// The returned nonce must be passed as last_nonce in the next call to enforce anti-replay.
#[pyfunction]
fn channel_verify(py: Python<'_>, session_key: &[u8], domain: u8, packet: &[u8], last_nonce: u64) -> PyResult<(Py<PyBytes>, u64)> {
    if session_key.len() != 32 {
        return Err(PyValueError::new_err("session_key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(session_key);
    let ch = AuthChannel::new(&key, domain_from_int(domain)?);
    ch.verify(packet, last_nonce)
        .map(|(payload, nonce)| (PyBytes::new_bound(py, payload).into(), nonce))
        .ok_or_else(|| PyValueError::new_err("HMAC verification failed or nonce replay"))
}

// ── Module ────────────────────────────────────────────────────────────────────

#[pymodule]
fn _cleitonq(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // DSA
    m.add_function(wrap_pyfunction!(dsa_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(dsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(dsa_verify, m)?)?;
    // KEM
    m.add_function(wrap_pyfunction!(kem_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(kem_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(kem_decapsulate, m)?)?;
    // Channel
    m.add_function(wrap_pyfunction!(channel_sign, m)?)?;
    m.add_function(wrap_pyfunction!(channel_verify, m)?)?;
    // Constants
    m.add("DOMAIN_C2", 0u8)?;
    m.add("DOMAIN_TELEMETRY", 1u8)?;
    m.add("DOMAIN_MESH", 2u8)?;
    m.add("DSA_SK_SEED_BYTES", 32u32)?;
    m.add("DSA_VK_BYTES", 2592u32)?;
    m.add("DSA_SIG_BYTES", 4627u32)?;
    m.add("KEM_EK_BYTES", 1568u32)?;
    m.add("KEM_DK_SEED_BYTES", 64u32)?;
    m.add("KEM_CT_BYTES", 1568u32)?;
    m.add("KEM_SS_BYTES", 32u32)?;
    m.add("HMAC_OVERHEAD", 40u32)?;
    Ok(())
}
