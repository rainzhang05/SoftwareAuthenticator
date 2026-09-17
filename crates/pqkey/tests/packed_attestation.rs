//! Packed attestation with the certificate the daemon provisions for
//! `--attestation certificate`, through the CTAP engine: the AAGUID in the certificate must be the one in
//! authenticatorData (WebAuthn Level 3 §8.2, "If attestnCert contains an
//! extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify
//! that the value of this extension matches the aaguid in
//! authenticatorData"), and the attestation signature must verify with the
//! certificate's public key. Without that option the daemon uses self
//! attestation, even when an earlier run provisioned a certificate.

use std::{fs, path::PathBuf};

use ciborium::value::{Integer, Value};
use ctaphid_app::{App, Command};
use heapless_bytes::Bytes;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use pqkey::{
    MESSAGE_SIZE,
    attestation::IdentityConfig,
    service::{AttestationConfig, IdentityStrings, open_credential_store},
};
use pqkey_ctap::CoseAlg;
use pqkey_ctap::ctap::{AttestationMode, CtapApp, InterruptFlag, presence::AutoApprove};
use pqkey_ctap::store::{CredentialStore, FileStore};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/// An identity as `--manufacturer`, `--product`, `--country` and `--aaguid`
/// give it.
const IDENTITY: IdentityConfig<'static> = IdentityConfig {
    manufacturer: "Example Manufacturer",
    product: "Example Authenticator",
    country: "US",
    aaguid: *b"an example AAGUI",
};

const ALGORITHMS: [CoseAlg; 4] = [
    CoseAlg::ES256,
    CoseAlg::MLDSA44,
    CoseAlg::MLDSA65,
    CoseAlg::MLDSA87,
];

static INTERRUPT: InterruptFlag = InterruptFlag::new();

/// A uniquely named directory under the system temporary directory, removed
/// with its contents when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("pqkey-attestation-{name}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The engine as the daemon builds it with `--attestation certificate`: the
/// store provisioned by `open_credential_store`, and the same AAGUID.
fn open_app(dir: &TempDir, identity: IdentityConfig<'_>) -> CtapApp<'static> {
    let store = open_credential_store(&dir.0, identity).unwrap();
    let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, identity.aaguid);
    app.set_attestation_mode(certificate_mode());
    app
}

/// The engine mode of `--attestation certificate`.
fn certificate_mode() -> AttestationMode {
    AttestationConfig::Certificate(IdentityStrings {
        manufacturer: IDENTITY.manufacturer.into(),
        product: IDENTITY.product.into(),
        country: IDENTITY.country.into(),
    })
    .mode()
}

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn get(map: &Value, key: &Value) -> Value {
    let Value::Map(entries) = map else {
        panic!("not a map: {map:?}");
    };
    entries
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| panic!("missing {key:?}"))
}

fn bytes(value: Value) -> Vec<u8> {
    match value {
        Value::Bytes(bytes) => bytes,
        other => panic!("not bytes: {other:?}"),
    }
}

/// makeCredential with a 64-byte user ID, the longest CTAP allows. Returns
/// the response's length (status byte included), its client data hash and
/// the decoded response.
fn make_credential(app: &mut CtapApp<'static>, alg: CoseAlg, rk: bool) -> (usize, [u8; 32], Value) {
    let mut client_data_hash = [0u8; 32];
    getrandom::fill(&mut client_data_hash).unwrap();
    let mut user_id = [0u8; 64];
    getrandom::fill(&mut user_id).unwrap();
    let request = Value::Map(vec![
        (int(1), Value::Bytes(client_data_hash.to_vec())),
        (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
        (
            int(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(user_id.to_vec())),
                (text("name"), text("alice@example.com")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(alg as i64)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(7), Value::Map(vec![(text("rk"), Value::Bool(rk))])),
    ]);
    let mut encoded = vec![0x01];
    ciborium::ser::into_writer(&request, &mut encoded).unwrap();
    let mut response = Bytes::<MESSAGE_SIZE>::new();
    App::call(app, Command::Cbor, &encoded, &mut response)
        .expect("the response fits a CTAPHID message");
    assert_eq!(response[0], 0x00, "CTAP status {:#04x}", response[0]);
    let decoded = ciborium::de::from_reader(&response[1..]).unwrap();
    (response.len(), client_data_hash, decoded)
}

/// Check a packed attestation with an x5c certificate as a relying party
/// would, and return the certificate's size.
fn check_packed_attestation(response: &Value, client_data_hash: &[u8], aaguid: [u8; 16]) -> usize {
    assert_eq!(get(response, &int(1)), text("packed"));
    let auth_data = bytes(get(response, &int(2)));
    assert_eq!(auth_data[32] & 0x40, 0x40, "attested credential data");
    assert_eq!(auth_data[37..53], aaguid, "authenticatorData AAGUID");

    let att_stmt = get(response, &int(3));
    assert_eq!(get(&att_stmt, &text("alg")), int(CoseAlg::ES256 as i64));
    let Value::Array(x5c) = get(&att_stmt, &text("x5c")) else {
        panic!("x5c is not an array");
    };
    assert_eq!(x5c.len(), 1);
    let der = bytes(x5c[0].clone());
    let (rest, certificate) = X509Certificate::from_der(&der).unwrap();
    assert!(rest.is_empty());

    let aaguid_extensions: Vec<_> = certificate
        .extensions()
        .iter()
        .filter(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.45724.1.1.4")
        .collect();
    assert_eq!(aaguid_extensions.len(), 1);
    assert!(!aaguid_extensions[0].critical);
    let mut expected = vec![0x04, 0x10];
    expected.extend_from_slice(&auth_data[37..53]);
    assert_eq!(
        aaguid_extensions[0].value, expected,
        "the certificate's AAGUID is authenticatorData's"
    );

    let public_key =
        VerifyingKey::from_sec1_bytes(&certificate.public_key().subject_public_key.data).unwrap();
    let mut signed = auth_data;
    signed.extend_from_slice(client_data_hash);
    let signature = Signature::from_der(&bytes(get(&att_stmt, &text("sig")))).unwrap();
    public_key
        .verify(&signed, &signature)
        .expect("the attestation signature verifies with the certificate's key");
    der.len()
}

/// Every algorithm gets basic attestation with the provisioned certificate:
/// even the largest response, ML-DSA-87, stays within a CTAPHID message and
/// does not fall back to self attestation. Run with `--nocapture` to see the
/// sizes.
#[test]
fn packed_attestation_certificate_matches_authenticator_data() {
    let dir = TempDir::new();
    let mut largest = 0;
    for alg in ALGORITHMS {
        for rk in [false, true] {
            let mut app = open_app(&dir, IDENTITY);
            let (length, client_data_hash, response) = make_credential(&mut app, alg, rk);
            let certificate =
                check_packed_attestation(&response, &client_data_hash, IDENTITY.aaguid);
            println!(
                "{alg:?} rk={rk}: makeCredential response {length} bytes with a \
                 {certificate}-byte attestation certificate"
            );
            assert!(length <= MESSAGE_SIZE);
            largest = largest.max(length);
        }
    }
    println!("largest makeCredential response: {largest} of {MESSAGE_SIZE} bytes");
}

/// A daemon started without `--attestation certificate` uses self
/// attestation, signed with the credential key and with the configured AAGUID
/// in authenticatorData, even though an earlier run provisioned a
/// certificate. The certificate stays in the store.
#[test]
fn a_provisioned_certificate_is_only_used_when_selected() {
    let dir = TempDir::new();
    drop(open_app(&dir, IDENTITY));
    let provisioned = FileStore::open(&dir.0).unwrap().attestation().unwrap();
    assert!(provisioned.is_some());

    let store = FileStore::open(&dir.0).unwrap();
    let mut app = CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, IDENTITY.aaguid);
    assert_eq!(
        AttestationConfig::SelfAttestation.mode(),
        AttestationMode::default()
    );
    let (_, client_data_hash, response) = make_credential(&mut app, CoseAlg::ES256, true);
    assert_eq!(get(&response, &int(1)), text("packed"));
    let auth_data = bytes(get(&response, &int(2)));
    assert_eq!(
        auth_data[37..53],
        IDENTITY.aaguid,
        "authenticatorData AAGUID"
    );
    let att_stmt = get(&response, &int(3));
    let Value::Map(entries) = &att_stmt else {
        panic!("attStmt is not a map");
    };
    assert!(entries.iter().all(|(key, _)| *key != text("x5c")));
    assert_eq!(get(&att_stmt, &text("alg")), int(CoseAlg::ES256 as i64));

    // The credential public key from the attested credential data.
    let length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let cose_key: Value = ciborium::de::from_reader(&auth_data[55 + length..]).unwrap();
    let mut sec1 = vec![0x04];
    sec1.extend(bytes(get(&cose_key, &int(-2))));
    sec1.extend(bytes(get(&cose_key, &int(-3))));
    let public_key = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let mut signed = auth_data;
    signed.extend_from_slice(&client_data_hash);
    let signature = Signature::from_der(&bytes(get(&att_stmt, &text("sig")))).unwrap();
    public_key
        .verify(&signed, &signature)
        .expect("self attestation verifies with the credential key");

    drop(app);
    assert_eq!(
        FileStore::open(&dir.0).unwrap().attestation().unwrap(),
        provisioned,
        "the certificate is kept"
    );
}

/// After the AAGUID is changed, the certificate follows it.
#[test]
fn a_changed_aaguid_is_in_the_new_certificate_and_authenticator_data() {
    let dir = TempDir::new();
    let mut app = open_app(&dir, IDENTITY);
    let (_, client_data_hash, response) = make_credential(&mut app, CoseAlg::ES256, true);
    check_packed_attestation(&response, &client_data_hash, IDENTITY.aaguid);
    drop(app);

    let changed = IdentityConfig {
        aaguid: *b"another  AAGUID!",
        ..IDENTITY
    };
    let mut app = open_app(&dir, changed);
    let (_, client_data_hash, response) = make_credential(&mut app, CoseAlg::ES256, true);
    check_packed_attestation(&response, &client_data_hash, changed.aaguid);
}
