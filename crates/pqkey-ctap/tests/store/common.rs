//! Temporary directories, record builders, independent verification helpers,
//! and log capture.

use std::fs;
use std::path::{Path, PathBuf};

use ciborium::value::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use pqkey_ctap::store::{AttestationRecord, CredentialRecord, PrivateKeyMaterial};
use pqkey_ctap::{CoseAlg, mldsa_paramset_from_alg, try_sign_challenge};
use pqkey_mldsa::PublicKey;

pub const ALL_ALGS: [CoseAlg; 4] = [
    CoseAlg::ES256,
    CoseAlg::MLDSA44,
    CoseAlg::MLDSA65,
    CoseAlg::MLDSA87,
];

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("operating system RNG");
    bytes
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A uniquely named directory under the system temporary directory, removed
/// together with its contents when dropped.
///
/// This stands in for the `tempfile` crate, which would pull `rustix` into the
/// dependency graph and with it a second, differently featured build of
/// `bitflags`.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        let name = format!("authenticator-store-test-{}", hex(&random_bytes::<16>()));
        let path = std::env::temp_dir().join(name);
        fs::create_dir(&path).expect("create temporary directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A fresh credential with a random ID, random secrets, and `created_at`
/// left for the store to assign.
pub fn new_record(alg: CoseAlg) -> CredentialRecord {
    CredentialRecord {
        credential_id: random_bytes::<32>().to_vec(),
        rp_id: "example.com".into(),
        user_id: random_bytes::<16>().to_vec(),
        user_name: Some("alice@example.com".into()),
        user_display_name: Some("Alice Example".into()),
        alg,
        private_key: PrivateKeyMaterial::generate(alg),
        cred_random_with_uv: random_bytes(),
        cred_random_without_uv: random_bytes(),
        cred_protect: 1,
        sign_count: 0,
        created_at: 0,
    }
}

/// `record` with the creation order a store assigned, for comparisons.
pub fn with_created_at(record: &CredentialRecord, created_at: u64) -> CredentialRecord {
    let mut record = record.clone();
    record.created_at = created_at;
    record
}

pub fn attestation_record(certificates: &[usize]) -> AttestationRecord {
    AttestationRecord {
        private_key: match PrivateKeyMaterial::generate(CoseAlg::ES256) {
            PrivateKeyMaterial::Es256 { scalar } => scalar,
            PrivateKeyMaterial::MlDsa { .. } => unreachable!(),
        },
        certificate_chain: certificates
            .iter()
            .map(|&len| {
                let mut certificate = vec![0u8; len];
                getrandom::fill(&mut certificate).expect("operating system RNG");
                certificate
            })
            .collect(),
    }
}

pub fn ids(records: &[CredentialRecord]) -> Vec<Vec<u8>> {
    records
        .iter()
        .map(|record| record.credential_id.clone())
        .collect()
}

/// Materialise the signing key from `record`, sign an assertion-shaped
/// message, and verify the signature against the public key derived from the
/// record, using verifiers that do not go through the store.
pub fn assert_signature_verifies(record: &CredentialRecord) {
    let (secret_key, cose_public_key) = record.keypair().expect("materialise key pair");
    assert_eq!(
        record.cose_public_key().expect("derive public key"),
        cose_public_key
    );
    let auth_data = random_bytes::<37>();
    let client_data_hash = random_bytes::<32>();
    let signature = try_sign_challenge(record.alg, &secret_key, &auth_data, &client_data_hash)
        .expect("sign with the materialised key");
    let mut message = auth_data.to_vec();
    message.extend_from_slice(&client_data_hash);

    let Value::Map(entries) = ciborium::de::from_reader(cose_public_key.as_slice()).unwrap() else {
        panic!("COSE_Key must be a map");
    };
    let label = |wanted: i128| {
        entries
            .iter()
            .find(|(label, _)| matches!(label, Value::Integer(l) if i128::from(*l) == wanted))
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("COSE_Key lacks label {wanted}"))
    };
    let bytes = |wanted: i128| match label(wanted) {
        Value::Bytes(bytes) => bytes,
        other => panic!("COSE label {wanted} is {other:?}"),
    };
    assert_eq!(
        label(3),
        Value::Integer((record.alg as i32).into()),
        "COSE alg"
    );
    match record.alg {
        CoseAlg::ES256 => {
            let mut sec1 = vec![0x04];
            sec1.extend(bytes(-2));
            sec1.extend(bytes(-3));
            let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).expect("P-256 public key");
            let signature = Signature::from_der(&signature).expect("DER ECDSA signature");
            verifying_key
                .verify(&message, &signature)
                .expect("ES256 signature verifies under the derived public key");
        }
        alg => {
            let param_set = mldsa_paramset_from_alg(alg).expect("ML-DSA parameter set");
            assert!(
                pqkey_mldsa::verify(param_set, &PublicKey::new(bytes(-1)), &message, &signature),
                "{alg:?} signature verifies under the derived public key"
            );
        }
    }
}

/// Captures warnings logged anywhere in this test binary.
///
/// The logger is process-wide and tests run in parallel, so callers look for
/// messages naming something unique to their own test.
pub mod logs {
    use std::sync::{Mutex, Once};

    use log::{Level, LevelFilter, Log, Metadata, Record};

    static MESSAGES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static INSTALL: Once = Once::new();

    struct Capture;

    impl Log for Capture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.level() <= Level::Warn
        }

        fn log(&self, record: &Record<'_>) {
            if self.enabled(record.metadata()) {
                MESSAGES
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    pub fn install() {
        INSTALL.call_once(|| {
            log::set_logger(&Capture).expect("no other logger is installed");
            log::set_max_level(LevelFilter::Warn);
        });
    }

    /// Warnings logged so far that contain `needle`.
    pub fn warnings_containing(needle: &str) -> Vec<String> {
        MESSAGES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|message| message.contains(needle))
            .cloned()
            .collect()
    }
}
