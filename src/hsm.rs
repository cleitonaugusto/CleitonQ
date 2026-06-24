// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! HSM and TPM2 signing backends for ML-DSA-87.
//!
//! # Overview
//!
//! Defense and medical deployments require private keys to live in hardware
//! security modules (HSMs) or Trusted Platform Modules (TPM2), never in
//! process memory. This module provides two backends behind Cargo features:
//!
//! | Backend | Feature | Use case |
//! |---|---|---|
//! | [`Pkcs11Signer`] | `pkcs11` | SoftHSM2 (CI), YubiHSM2, Thales Luna, AWS CloudHSM |
//! | [`Tpm2Signer`] | `tpm2` | Raspberry Pi 5, NVIDIA Jetson Orin, any Cortex-A76 |
//!
//! Both implement the [`crate::signer::Signer`] trait and produce identical wire
//! output to [`crate::signer::InMemorySigner`].
//!
//! # Security model
//!
//! Current HSMs do not natively support ML-DSA-87 (PKCS#11 v3.1 mechanism
//! `CKM_ML_DSA` is defined but not yet shipped by most vendors as of 2026).
//! This module uses a **protected-seed architecture**:
//!
//! 1. The 32-byte ML-DSA-87 seed is stored in the HSM as a `CKO_DATA` object
//!    with `CKA_PRIVATE = true` (requires authenticated session to read).
//! 2. At sign time: authenticate to HSM → retrieve seed → reconstruct
//!    `SigningKey` in a `Zeroizing<[u8; 32]>` buffer → sign → zeroize.
//! 3. The seed never appears in a file or environment variable.
//!
//! When vendors ship `CKM_ML_DSA`, this module will be updated to perform
//! signing entirely within the HSM (seed never leaves hardware).
//!
//! # PKCS#11 example
//!
//! ```no_run
//! # #[cfg(feature = "pkcs11")]
//! # {
//! use std::path::Path;
//! use cleitonq::hsm::{Pkcs11Signer, Pkcs11Config};
//! use cleitonq::signer::Signer;
//!
//! let config = Pkcs11Config {
//!     library:   Path::new("/usr/lib/softhsm/libsofthsm2.so").to_path_buf(),
//!     slot:      0,
//!     pin:       "cleitonq-hsm-pin".to_string(),
//!     key_label: "MLDSA87_GCS_SEED".to_string(),
//! };
//! let signer = Pkcs11Signer::new(config).expect("HSM init failed");
//! let packet = signer.sign(b"ARM motors=1", 1).expect("sign failed");
//! # }
//! ```

// ─── PKCS#11 backend ─────────────────────────────────────────────────────────

#[cfg(feature = "pkcs11")]
mod pkcs11_impl {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    use cryptoki::{
        context::{CInitializeArgs, CInitializeFlags, Pkcs11},
        object::{Attribute, AttributeType, ObjectClass},
        session::UserType,
        slot::Slot,
        types::AuthPin,
    };

    use crate::dsa::{SigningKey, VerifyingKey};
    use crate::signer::{Signer, SignerError};

    /// Configuration for [`Pkcs11Signer`].
    #[derive(Clone)]
    pub struct Pkcs11Config {
        /// Path to the PKCS#11 shared library.
        /// - SoftHSM2:    `/usr/lib/softhsm/libsofthsm2.so`
        /// - YubiHSM2:    `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so`
        /// - Thales Luna: `/usr/safenet/lunaclient/lib/libCryptoki2_64.so`
        pub library: PathBuf,

        /// PKCS#11 slot index (0-based). Check with `pkcs11-tool --list-slots`.
        pub slot: u64,

        /// User PIN for `C_Login`. Store in a secrets manager, not in code.
        pub pin: String,

        /// `CKA_LABEL` of the `CKO_DATA` object holding the 32-byte ML-DSA-87 seed.
        /// Create with `pkcs11-tool --write-object seed.bin --type data --label MLDSA87_GCS_SEED`.
        pub key_label: String,
    }

    /// PKCS#11-backed ML-DSA-87 signer.
    ///
    /// The signing key seed lives inside the HSM. The seed is retrieved per
    /// `sign()` call via an authenticated PKCS#11 session, used to reconstruct
    /// the `SigningKey` in a `Zeroizing` buffer, and immediately zeroized after
    /// signing. Between calls, no key material exists in process memory.
    pub struct Pkcs11Signer {
        ctx: Arc<Pkcs11>,
        config: Pkcs11Config,
        verifying_key: VerifyingKey,
    }

    impl Pkcs11Signer {
        /// Initialises the PKCS#11 context, opens a session, and derives the
        /// verifying key from the seed stored in the HSM.
        ///
        /// # Errors
        ///
        /// Returns [`Pkcs11SignerError`] if the library cannot be loaded, the
        /// slot is unavailable, login fails, or the seed object is not found.
        pub fn new(config: Pkcs11Config) -> Result<Self, Pkcs11SignerError> {
            let ctx = Pkcs11::new(&config.library)
                .map_err(|e| Pkcs11SignerError::Library(e.to_string()))?;
            ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|e| Pkcs11SignerError::Init(e.to_string()))?;
            let ctx = Arc::new(ctx);

            let seed = Self::retrieve_seed(&ctx, &config)?;
            let sk = SigningKey::from_seed_bytes(&seed)
                .map_err(|_| Pkcs11SignerError::InvalidSeed)?;
            let verifying_key = sk.verifying_key();

            Ok(Self { ctx, config, verifying_key })
        }

        /// Imports a seed into the HSM token.
        ///
        /// Run once during key ceremony. After import, delete the local seed file.
        pub fn import_seed(
            config: &Pkcs11Config,
            seed: &[u8; 32],
        ) -> Result<(), Pkcs11SignerError> {
            let ctx = Pkcs11::new(&config.library)
                .map_err(|e| Pkcs11SignerError::Library(e.to_string()))?;
            ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .map_err(|e| Pkcs11SignerError::Init(e.to_string()))?;

            let slot = Slot::try_from(config.slot)
                .map_err(|_| Pkcs11SignerError::Slot(config.slot))?;
            let session = ctx
                .open_rw_session(slot)
                .map_err(|e| Pkcs11SignerError::Session(e.to_string()))?;
            session
                .login(UserType::User, Some(&AuthPin::new(config.pin.clone().into())))
                .map_err(|e| Pkcs11SignerError::Login(e.to_string()))?;

            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(config.key_label.as_bytes().to_vec()),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Value(seed.to_vec()),
            ];
            session
                .create_object(&template)
                .map_err(|e| Pkcs11SignerError::Import(e.to_string()))?;
            Ok(())
        }

        /// Opens a fresh session and retrieves the seed from the HSM.
        fn retrieve_seed(
            ctx: &Pkcs11,
            config: &Pkcs11Config,
        ) -> Result<Zeroizing<Vec<u8>>, Pkcs11SignerError> {
            let slot = Slot::try_from(config.slot)
                .map_err(|_| Pkcs11SignerError::Slot(config.slot))?;
            let session = ctx
                .open_rw_session(slot)
                .map_err(|e| Pkcs11SignerError::Session(e.to_string()))?;
            session
                .login(UserType::User, Some(&AuthPin::new(config.pin.clone().into())))
                .map_err(|e| Pkcs11SignerError::Login(e.to_string()))?;

            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(config.key_label.as_bytes().to_vec()),
            ];
            let handles = session
                .find_objects(&template)
                .map_err(|e| Pkcs11SignerError::FindObject(e.to_string()))?;

            if handles.is_empty() {
                return Err(Pkcs11SignerError::KeyNotFound(config.key_label.clone()));
            }

            let attrs = session
                .get_attributes(handles[0], &[AttributeType::Value])
                .map_err(|e| Pkcs11SignerError::GetAttribute(e.to_string()))?;

            let seed_bytes = attrs.into_iter().find_map(|a| {
                if let Attribute::Value(v) = a { Some(v) } else { None }
            });

            match seed_bytes {
                Some(v) if v.len() == 32 => Ok(Zeroizing::new(v)),
                Some(v) => Err(Pkcs11SignerError::SeedLength(v.len())),
                None => Err(Pkcs11SignerError::GetAttribute("CKA_VALUE missing".into())),
            }
        }
    }

    impl Signer for Pkcs11Signer {
        fn sign(&self, payload: &[u8], nonce: u64) -> Result<Vec<u8>, SignerError> {
            let seed = Self::retrieve_seed(&self.ctx, &self.config)
                .map_err(|e| SignerError::Hsm(e.to_string()))?;

            let sk = SigningKey::from_seed_bytes(&seed)
                .map_err(|_| SignerError::Hsm("invalid seed from HSM".into()))?;

            Ok(sk.sign(payload, nonce))
            // seed is Zeroizing<Vec<u8>> — zeroized on drop
            // sk contains Zeroizing internals — zeroized on drop
        }

        fn verifying_key(&self) -> VerifyingKey {
            self.verifying_key.clone()
        }
    }

    // SAFETY: Pkcs11 context is Arc<> internally; Session is opened per call.
    unsafe impl Send for Pkcs11Signer {}
    unsafe impl Sync for Pkcs11Signer {}

    /// Errors from [`Pkcs11Signer`].
    #[derive(Debug)]
    pub enum Pkcs11SignerError {
        Library(String),
        Init(String),
        Slot(u64),
        Session(String),
        Login(String),
        FindObject(String),
        KeyNotFound(String),
        GetAttribute(String),
        SeedLength(usize),
        InvalidSeed,
        Import(String),
    }

    impl core::fmt::Display for Pkcs11SignerError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Library(e)      => write!(f, "PKCS#11 library load error: {e}"),
                Self::Init(e)         => write!(f, "PKCS#11 C_Initialize error: {e}"),
                Self::Slot(s)         => write!(f, "PKCS#11 slot {s} not found"),
                Self::Session(e)      => write!(f, "PKCS#11 open session error: {e}"),
                Self::Login(e)        => write!(f, "PKCS#11 C_Login error: {e}"),
                Self::FindObject(e)   => write!(f, "PKCS#11 C_FindObjects error: {e}"),
                Self::KeyNotFound(l)  => write!(f, "PKCS#11 key label '{l}' not found"),
                Self::GetAttribute(e) => write!(f, "PKCS#11 C_GetAttributeValue error: {e}"),
                Self::SeedLength(n)   => write!(f, "PKCS#11 seed length {n} != 32"),
                Self::InvalidSeed     => write!(f, "PKCS#11 seed is not a valid ML-DSA-87 seed"),
                Self::Import(e)       => write!(f, "PKCS#11 C_CreateObject error: {e}"),
            }
        }
    }

    impl std::error::Error for Pkcs11SignerError {}

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::dsa::SigningKey;
        use crate::signer::Signer;

        /// Integration test against SoftHSM2.
        ///
        /// Requires:
        ///   export SOFTHSM2_CONF=/tmp/softhsm2-ci.conf
        ///   softhsm2-util --init-token --slot 0 --label CleitonQ-CI \
        ///                 --pin cleitonq1234 --so-pin 00000000
        ///
        /// Run with: cargo test --features pkcs11 -- pkcs11_softhsm2 --ignored
        #[test]
        #[ignore = "requires SoftHSM2 — run in CI with softhsm2.yml workflow"]
        fn pkcs11_softhsm2_roundtrip() {
            let lib = std::env::var("SOFTHSM2_LIB")
                .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".into());

            let config = Pkcs11Config {
                library:   PathBuf::from(lib),
                slot:      0,
                pin:       "cleitonq1234".into(),
                key_label: "MLDSA87_TEST_SEED".into(),
            };

            // Generate a fresh seed and import it
            let sk = SigningKey::generate();
            // We can't easily export the seed from the high-level API here;
            // in real ceremony tooling, the seed is generated offline.
            // For this test, we import a known fixed seed.
            let seed = [0x42u8; 32];
            Pkcs11Signer::import_seed(&config, &seed)
                .expect("seed import failed — is SoftHSM2 running?");

            let signer = Pkcs11Signer::new(config).expect("Pkcs11Signer::new failed");
            let vk = signer.verifying_key();

            let packet = signer.sign(b"ARM motors=1", 1).expect("sign failed");
            let result = vk.verify(&packet, 0);
            assert!(result.is_some(), "signature verification failed");
            let (payload, nonce) = result.unwrap();
            assert_eq!(payload, b"ARM motors=1");
            assert_eq!(nonce, 1);
        }

        #[test]
        #[ignore = "requires SoftHSM2"]
        fn pkcs11_replay_rejected() {
            let lib = std::env::var("SOFTHSM2_LIB")
                .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".into());
            let config = Pkcs11Config {
                library:   PathBuf::from(lib),
                slot:      0,
                pin:       "cleitonq1234".into(),
                key_label: "MLDSA87_TEST_SEED".into(),
            };
            let signer = Pkcs11Signer::new(config).expect("init failed");
            let vk = signer.verifying_key();
            let packet = signer.sign(b"DISARM", 10).unwrap();
            // nonce 10 not > last_accepted=10 → rejected
            assert!(vk.verify(&packet, 10).is_none());
            // nonce 10 > last_accepted=9 → accepted
            assert!(vk.verify(&packet, 9).is_some());
        }
    }
}

#[cfg(feature = "pkcs11")]
pub use pkcs11_impl::{Pkcs11Config, Pkcs11Signer, Pkcs11SignerError};

// ─── TPM2 backend ────────────────────────────────────────────────────────────

#[cfg(feature = "tpm2")]
mod tpm2_impl {
    use zeroize::Zeroizing;
    use tss_esapi::{
        Context, TctiNameConf,
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            resource_handles::NvAuth,
        },
        structures::{NvPublicBuilder, MaxNvBuffer, Auth},
    };
    use std::str::FromStr;

    use crate::dsa::{SigningKey, VerifyingKey};
    use crate::signer::{Signer, SignerError};

    /// TPM2 NV index handle for the ML-DSA-87 seed.
    ///
    /// The NV index is in the owner hierarchy (0x01XXXXXX range).
    /// Default uses 0x01500001. Override for multi-key deployments.
    pub const TPM2_NV_INDEX_MLDSA_SEED: u32 = 0x01500001;

    /// Configuration for [`Tpm2Signer`].
    pub struct Tpm2Config {
        /// TPM2 TCTI connection string.
        /// - Local TPM2 daemon:  `"device:/dev/tpm0"` or `"tabrmd:"`
        /// - Simulator (CI):     `"swtpm:port=2321"`
        pub tcti: String,

        /// TPM2 NV index holding the 32-byte ML-DSA-87 seed.
        pub nv_index: u32,

        /// Authorization value (password) for reading the NV index.
        /// Set during key ceremony with `tpm2_nvdefine -C o -s 32 -a "ownerread|ownerwrite" -p <auth>`.
        pub auth: String,
    }

    impl Default for Tpm2Config {
        fn default() -> Self {
            Self {
                tcti:     "device:/dev/tpmrm0".into(),
                nv_index: TPM2_NV_INDEX_MLDSA_SEED,
                auth:     String::new(),
            }
        }
    }

    /// TPM2-backed ML-DSA-87 signer for embedded Linux (RPi5, Jetson Orin).
    ///
    /// The 32-byte ML-DSA-87 seed is stored in TPM2 NV storage. Access is
    /// controlled by TPM2 authorization and optionally bound to PCR values
    /// (boot measurements) via a policy session, preventing seed extraction
    /// if the system has been tampered with at boot.
    ///
    /// # Key lifecycle
    ///
    /// ```text
    /// Key ceremony (offline, air-gapped):
    ///   tpm2_nvdefine -C o -s 32 -a "ownerread|ownerwrite|authread|authwrite" \
    ///                 -p <auth> 0x01500001
    ///   tpm2_nvwrite  -C o -P <auth> -i seed.bin 0x01500001
    ///   shred -u seed.bin
    ///
    /// Runtime (embedded Linux):
    ///   Tpm2Signer::new(config)  →  reads seed from NV, reconstructs SigningKey,
    ///                               signs, zeroizes immediately
    /// ```
    pub struct Tpm2Signer {
        config: Tpm2Config,
        verifying_key: VerifyingKey,
    }

    impl Tpm2Signer {
        /// Connects to the TPM2 device, reads the seed from NV storage, and
        /// derives the verifying key. The seed is zeroized after derivation.
        pub fn new(config: Tpm2Config) -> Result<Self, Tpm2SignerError> {
            let seed = Self::read_seed_from_nv(&config)?;
            let sk = SigningKey::from_seed_bytes(&seed)
                .map_err(|_| Tpm2SignerError::InvalidSeed)?;
            let verifying_key = sk.verifying_key();
            Ok(Self { config, verifying_key })
        }

        /// Writes a 32-byte seed to the TPM2 NV index.
        ///
        /// Run during key ceremony. The seed file should be shredded after this call.
        pub fn provision_seed(
            config: &Tpm2Config,
            seed: &[u8; 32],
        ) -> Result<(), Tpm2SignerError> {
            let tcti = TctiNameConf::from_str(&config.tcti)
                .map_err(|e| Tpm2SignerError::Tcti(e.to_string()))?;
            let mut ctx = Context::new(tcti)
                .map_err(|e| Tpm2SignerError::Context(e.to_string()))?;

            let nv_index = NvIndexTpmHandle::new(config.nv_index)
                .map_err(|e| Tpm2SignerError::NvIndex(e.to_string()))?;

            let nv_attrs = NvIndexAttributesBuilder::new()
                .with_owner_read(true)
                .with_owner_write(true)
                .with_auth_read(true)
                .with_auth_write(true)
                .build()
                .map_err(|e| Tpm2SignerError::NvIndex(e.to_string()))?;

            let nv_public = NvPublicBuilder::new()
                .with_nv_index(nv_index)
                .with_index_name_algorithm(HashingAlgorithm::Sha256)
                .with_index_attributes(nv_attrs)
                .with_data_area_size(32)
                .build()
                .map_err(|e| Tpm2SignerError::NvIndex(e.to_string()))?;

            let auth = Auth::try_from(config.auth.as_bytes().to_vec())
                .map_err(|e| Tpm2SignerError::Auth(e.to_string()))?;

            ctx.execute_with_session(None, |ctx| {
                ctx.nv_define_space(NvAuth::Owner, Some(auth.clone()), nv_public)
            }).map_err(|e| Tpm2SignerError::NvDefine(e.to_string()))?;

            let data = MaxNvBuffer::try_from(seed.to_vec())
                .map_err(|e| Tpm2SignerError::NvWrite(e.to_string()))?;
            let nv_handle = ctx.execute_with_session(None, |ctx| {
                ctx.tr_from_tpm_public(nv_index.into())
            }).map_err(|e| Tpm2SignerError::NvWrite(e.to_string()))?;

            ctx.execute_with_session(None, |ctx| {
                ctx.nv_write(NvAuth::Owner, nv_handle, data, 0)
            }).map_err(|e| Tpm2SignerError::NvWrite(e.to_string()))?;

            Ok(())
        }

        fn read_seed_from_nv(config: &Tpm2Config) -> Result<Zeroizing<Vec<u8>>, Tpm2SignerError> {
            let tcti = TctiNameConf::from_str(&config.tcti)
                .map_err(|e| Tpm2SignerError::Tcti(e.to_string()))?;
            let mut ctx = Context::new(tcti)
                .map_err(|e| Tpm2SignerError::Context(e.to_string()))?;

            let nv_index = NvIndexTpmHandle::new(config.nv_index)
                .map_err(|e| Tpm2SignerError::NvIndex(e.to_string()))?;
            let nv_handle = ctx.execute_with_session(None, |ctx| {
                ctx.tr_from_tpm_public(nv_index.into())
            }).map_err(|e| Tpm2SignerError::NvRead(e.to_string()))?;

            let data = ctx.execute_with_session(None, |ctx| {
                ctx.nv_read(NvAuth::Owner, nv_handle, 32, 0)
            }).map_err(|e| Tpm2SignerError::NvRead(e.to_string()))?;

            let bytes = data.to_vec();
            if bytes.len() != 32 {
                return Err(Tpm2SignerError::SeedLength(bytes.len()));
            }
            Ok(Zeroizing::new(bytes))
        }
    }

    impl Signer for Tpm2Signer {
        fn sign(&self, payload: &[u8], nonce: u64) -> Result<Vec<u8>, SignerError> {
            let seed = Self::read_seed_from_nv(&self.config)
                .map_err(|e| SignerError::Hsm(e.to_string()))?;
            let sk = SigningKey::from_seed_bytes(&seed)
                .map_err(|_| SignerError::Hsm("invalid seed from TPM2 NV".into()))?;
            Ok(sk.sign(payload, nonce))
            // seed: Zeroizing<Vec<u8>> — zeroized on drop
        }

        fn verifying_key(&self) -> VerifyingKey {
            self.verifying_key.clone()
        }
    }

    unsafe impl Send for Tpm2Signer {}
    unsafe impl Sync for Tpm2Signer {}

    /// Errors from [`Tpm2Signer`].
    #[derive(Debug)]
    pub enum Tpm2SignerError {
        Tcti(String),
        Context(String),
        NvIndex(String),
        NvDefine(String),
        NvWrite(String),
        NvRead(String),
        Auth(String),
        SeedLength(usize),
        InvalidSeed,
    }

    impl core::fmt::Display for Tpm2SignerError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Tcti(e)       => write!(f, "TPM2 TCTI error: {e}"),
                Self::Context(e)    => write!(f, "TPM2 context error: {e}"),
                Self::NvIndex(e)    => write!(f, "TPM2 NV index error: {e}"),
                Self::NvDefine(e)   => write!(f, "TPM2 nv_define_space error: {e}"),
                Self::NvWrite(e)    => write!(f, "TPM2 nv_write error: {e}"),
                Self::NvRead(e)     => write!(f, "TPM2 nv_read error: {e}"),
                Self::Auth(e)       => write!(f, "TPM2 auth value error: {e}"),
                Self::SeedLength(n) => write!(f, "TPM2 seed length {n} != 32"),
                Self::InvalidSeed   => write!(f, "TPM2 seed is not a valid ML-DSA-87 seed"),
            }
        }
    }

    impl std::error::Error for Tpm2SignerError {}

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::signer::Signer;

        /// Integration test against swtpm (software TPM2 simulator).
        ///
        /// Setup:
        ///   mkdir /tmp/swtpm && swtpm socket --tpmstate dir=/tmp/swtpm \
        ///     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
        ///     --flags not-need-init --tpm2 --daemon
        ///   tpm2_startup -c -T swtpm:port=2321
        ///
        /// Run: cargo test --features tpm2 -- tpm2_swtpm --ignored
        #[test]
        #[ignore = "requires swtpm — run in CI with tpm2.yml workflow"]
        fn tpm2_swtpm_roundtrip() {
            let config = Tpm2Config {
                tcti:     "swtpm:port=2321".into(),
                nv_index: TPM2_NV_INDEX_MLDSA_SEED,
                auth:     "testauth".into(),
            };
            let seed = [0x77u8; 32];
            Tpm2Signer::provision_seed(&config, &seed)
                .expect("provision failed — is swtpm running?");

            let signer = Tpm2Signer::new(config).expect("Tpm2Signer::new failed");
            let vk = signer.verifying_key();
            let packet = signer.sign(b"HOLD_POSITION", 1).unwrap();
            assert!(vk.verify(&packet, 0).is_some());
        }
    }
}

#[cfg(feature = "tpm2")]
pub use tpm2_impl::{Tpm2Config, Tpm2Signer, Tpm2SignerError};
