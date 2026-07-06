//! `cleitonq-verify` — standalone anchor command-provenance tool.
//!
//! A third-party auditor uses this to verify that an archive of authenticated
//! machine traffic is exactly what the signer committed to, trusting only a
//! public ML-DSA-87 verifying key. No session secret, no live system, no
//! network, no operator cooperation.
//!
//! Construction: `rfc/anchors-command-provenance.md` /
//! IETF draft-bezerra-anchors-command-provenance.
//!
//!   commitment = SHA3-256(mac_0 || mac_1 || ... || mac_{n-1})
//!   anchor     = ML-DSA-87.sign( anchor_nonce || window_start ||
//!                                window_end || packet_count || commitment )
//!
//! Subcommands:
//!   gen-key --out <prefix>                       write <prefix>.sk / <prefix>.vk
//!   emit --sk <f> --macs <f> --out <f> \
//!        --anchor-nonce N --window-start N --window-end N
//!   verify --vk <f> --macs <f> --anchor <f> [--last-nonce N]
//!   demo                                         self-contained round-trip
//!
//! The MAC archive (`--macs`) is a raw file of concatenated 32-byte tags.

use std::collections::HashMap;
use std::process::ExitCode;

use cleitonq::channel::AuthChannel;
use cleitonq::dsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};

const MAC_BYTES: usize = 32;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    let result = match cmd {
        "gen-key" => cmd_gen_key(&flags(&args[2..])),
        "emit" => cmd_emit(&flags(&args[2..])),
        "verify" => cmd_verify(&flags(&args[2..])),
        "demo" => cmd_demo(),
        "help" | "-h" | "--help" | "" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown subcommand '{other}' (try `help`)")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Minimal `--key value` flag parser.
fn flags(rest: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < rest.len() {
        if let Some(key) = rest[i].strip_prefix("--") {
            let val = rest.get(i + 1).cloned().unwrap_or_default();
            m.insert(key.to_string(), val);
            i += 2;
        } else {
            i += 1;
        }
    }
    m
}

fn need<'a>(f: &'a HashMap<String, String>, k: &str) -> Result<&'a String, String> {
    f.get(k).ok_or_else(|| format!("missing required flag --{k}"))
}

fn parse_u64(f: &HashMap<String, String>, k: &str) -> Result<u64, String> {
    need(f, k)?.parse().map_err(|_| format!("--{k} must be a number"))
}

/// `anchor_nonce || window_start || window_end || packet_count` (28 bytes LE).
fn meta_bytes(anchor_nonce: u64, window_start: u64, window_end: u64, count: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(28);
    b.extend_from_slice(&anchor_nonce.to_le_bytes());
    b.extend_from_slice(&window_start.to_le_bytes());
    b.extend_from_slice(&window_end.to_le_bytes());
    b.extend_from_slice(&count.to_le_bytes());
    b
}

fn commit(macs: &[u8]) -> Result<[u8; 32], String> {
    if macs.is_empty() || macs.len() % MAC_BYTES != 0 {
        return Err(format!(
            "MAC archive length {} is not a positive multiple of {MAC_BYTES}",
            macs.len()
        ));
    }
    let mut h = Sha3_256::new();
    h.update(macs); // concatenation of fixed 32-byte tags == streaming update
    Ok(h.finalize().into())
}

fn cmd_gen_key(f: &HashMap<String, String>) -> Result<(), String> {
    let prefix = need(f, "out")?;
    let sk = SigningKey::generate();
    sk.save(&format!("{prefix}.sk")).map_err(|e| format!("{e:?}"))?;
    sk.verifying_key()
        .save(&format!("{prefix}.vk"))
        .map_err(|e| format!("{e:?}"))?;
    println!("wrote {prefix}.sk (signing key) and {prefix}.vk (verifying key)");
    Ok(())
}

fn cmd_emit(f: &HashMap<String, String>) -> Result<(), String> {
    let sk = SigningKey::load(need(f, "sk")?).map_err(|e| format!("load sk: {e:?}"))?;
    let macs = std::fs::read(need(f, "macs")?).map_err(|e| format!("read macs: {e}"))?;
    let count = (macs.len() / MAC_BYTES) as u32;

    let anchor_nonce = parse_u64(f, "anchor-nonce")?;
    let window_start = parse_u64(f, "window-start")?;
    let window_end = parse_u64(f, "window-end")?;

    let mut payload = meta_bytes(anchor_nonce, window_start, window_end, count);
    payload.extend_from_slice(&commit(&macs)?);
    let anchor = sk.sign(&payload, anchor_nonce);

    std::fs::write(need(f, "out")?, &anchor).map_err(|e| format!("write anchor: {e}"))?;
    println!(
        "emitted anchor over {count} commands ({} bytes) -> {}",
        anchor.len(),
        f["out"]
    );
    Ok(())
}

fn cmd_verify(f: &HashMap<String, String>) -> Result<(), String> {
    let vk = VerifyingKey::load(need(f, "vk")?).map_err(|e| format!("load vk: {e:?}"))?;
    let macs = std::fs::read(need(f, "macs")?).map_err(|e| format!("read macs: {e}"))?;
    let anchor = std::fs::read(need(f, "anchor")?).map_err(|e| format!("read anchor: {e}"))?;
    let last_nonce = f.get("last-nonce").and_then(|s| s.parse().ok()).unwrap_or(0);

    match verify(&vk, &anchor, &macs, last_nonce) {
        Ok(n) => {
            println!("VERIFIED  anchor_nonce={n}  commands={}", macs.len() / MAC_BYTES);
            println!("the archive is exactly what the signer authenticated; untampered.");
            Ok(())
        }
        Err(e) => Err(format!("REJECTED: {e}")),
    }
}

/// Core verification, shared by `verify` and `demo`.
fn verify(vk: &VerifyingKey, anchor: &[u8], macs: &[u8], last_nonce: u64) -> Result<u64, String> {
    let (payload, anchor_nonce) = vk
        .verify(anchor, last_nonce)
        .ok_or("bad signature, malformed anchor, or replayed anchor nonce")?;
    if payload.len() < 32 {
        return Err("anchor payload too short to hold a commitment".into());
    }
    let committed = &payload[payload.len() - 32..];
    if committed != commit(macs)? {
        return Err("commitment mismatch — the MAC archive was altered".into());
    }
    Ok(anchor_nonce)
}

fn cmd_demo() -> Result<(), String> {
    println!("== cleitonq-verify demo (self-contained round-trip) ==\n");
    let sk = SigningKey::generate();
    let vk = sk.verifying_key();

    // Build a window of 256 HMAC-SHA3-256 authenticated commands.
    let channel = AuthChannel::from_raw_key([0x42; 32]);
    let mut macs = Vec::new();
    for nonce in 1..=256u64 {
        let pkt = channel.sign(format!("CMD#{nonce}").as_bytes(), nonce);
        macs.extend_from_slice(&pkt[pkt.len() - MAC_BYTES..]);
    }

    let mut payload = meta_bytes(1, 1, 256, 256);
    payload.extend_from_slice(&commit(&macs)?);
    let anchor = sk.sign(&payload, 1);
    println!("anchor: {} bytes over 256 commands\n", anchor.len());

    let mut ok = true;
    let mut check = |label: &str, want_pass: bool, got: Result<u64, String>| {
        let passed = got.is_ok() == want_pass;
        ok &= passed;
        println!("[{}] {label}", if passed { "PASS" } else { "FAIL" });
    };

    check("intact archive verifies", true, verify(&vk, &anchor, &macs, 0));

    let mut bad = macs.clone();
    bad[100 * MAC_BYTES] ^= 0x01;
    check("single-bit tampering detected", false, verify(&vk, &anchor, &bad, 0));
    check("replayed anchor nonce rejected", false, verify(&vk, &anchor, &macs, 1));
    check(
        "wrong signing key rejected",
        false,
        verify(&SigningKey::generate().verifying_key(), &anchor, &macs, 0),
    );

    println!();
    if ok {
        println!("all provenance properties hold (ML-DSA-87 + SHA3-256, post-quantum).");
        Ok(())
    } else {
        Err("a provenance property failed".into())
    }
}

fn print_usage() {
    println!(
        "cleitonq-verify — standalone anchor command-provenance tool\n\n\
         USAGE:\n  \
         cleitonq-verify gen-key --out <prefix>\n  \
         cleitonq-verify emit --sk <f> --macs <f> --out <f> \\\n      \
         --anchor-nonce N --window-start N --window-end N\n  \
         cleitonq-verify verify --vk <f> --macs <f> --anchor <f> [--last-nonce N]\n  \
         cleitonq-verify demo\n\n\
         The MAC archive (--macs) is a raw file of concatenated 32-byte tags."
    );
}
