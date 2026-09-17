//! CTAP-level tests of the engine over a real `FileStore`.
//!
//! Every request is CBOR sent through `App::call`, as the CTAPHID dispatcher
//! sends it, into a response buffer of the CTAPHID maximum message size.
//! Between requests the app is dropped and rebuilt over the same state
//! directory, as a daemon restart would.  These are the tests that would
//! have caught the 1,024-byte limit of the old Trussed-backed store: every
//! ML-DSA registration failed to persist.

use std::fs;
use std::path::{Path, PathBuf};

use ciborium::value::{Integer, Value};
use ctaphid_app::{App, Command};
use heapless_bytes::Bytes;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier};
use pqkey_ctap::ctap::presence::AutoApprove;
use pqkey_ctap::ctap::{AttestationMode, CtapApp, InterruptFlag};
use pqkey_ctap::store::{AttestationRecord, CredentialStore, FileStore, PrivateKeyMaterial};
use pqkey_ctap::{CoseAlg, mldsa_paramset_from_alg};

/// CTAPHID's largest message: 64 - 7 + 128 * (64 - 5) bytes (CTAP 2.3
/// §11.2.4).
const CTAPHID_MAX_MESSAGE: usize = 7609;

const ALL_ALGS: [CoseAlg; 4] = [
    CoseAlg::ES256,
    CoseAlg::MLDSA44,
    CoseAlg::MLDSA65,
    CoseAlg::MLDSA87,
];

static INTERRUPT: InterruptFlag = InterruptFlag::new();

/// A uniquely named directory under the system temporary directory, removed
/// with its contents when dropped.  (Not the `tempfile` crate, which would add
/// a second build of `bitflags`.)
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).expect("operating system RNG");
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("authenticator-ctap-test-{name}"));
        fs::create_dir(&path).expect("create temporary directory");
        Self(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The AAGUID the tests configure.
const AAGUID: [u8; 16] = [0x5A; 16];

/// The engine as the daemon builds it by default, over the store in
/// `state_dir`.
fn open_app(state_dir: &Path) -> CtapApp<'static> {
    let store = FileStore::open(state_dir).expect("open file store");
    CtapApp::with_file_store(store, AutoApprove, &INTERRUPT, AAGUID)
}

/// [`open_app`] with attestation mode `mode`.
fn open_app_with(state_dir: &Path, mode: AttestationMode) -> CtapApp<'static> {
    let mut app = open_app(state_dir);
    app.set_attestation_mode(mode);
    app
}

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

fn get(entries: &Value, key: &Value) -> Value {
    let Value::Map(entries) = entries else {
        panic!("not a map: {entries:?}");
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

/// Send CTAP command `command` with CBOR `payload`; return the raw response
/// (status byte first).
fn call(app: &mut CtapApp<'static>, command: u8, payload: &Value) -> Vec<u8> {
    let mut request = vec![command];
    ciborium::ser::into_writer(payload, &mut request).expect("encode request");
    let mut response = Bytes::<CTAPHID_MAX_MESSAGE>::new();
    App::<CTAPHID_MAX_MESSAGE>::call(app, Command::Cbor, &request, &mut response)
        .expect("the response fits a CTAPHID message");
    response.to_vec()
}

/// Send a request that must succeed, and decode its response map.
fn call_ok(app: &mut CtapApp<'static>, command: u8, payload: &Value) -> Value {
    let response = call(app, command, payload);
    assert_eq!(response[0], 0x00, "CTAP status {:#04x}", response[0]);
    ciborium::de::from_reader(&response[1..]).expect("decode response")
}

fn make_credential_request(client_data_hash: &[u8], user_id: &[u8], alg: CoseAlg) -> Value {
    map(vec![
        (int(1), Value::Bytes(client_data_hash.to_vec())),
        (int(2), map(vec![(text("id"), text("example.com"))])),
        (
            int(3),
            map(vec![
                (text("id"), Value::Bytes(user_id.to_vec())),
                (text("name"), text("alice@example.com")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![map(vec![
                (text("alg"), int(alg as i64)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(7), map(vec![(text("rk"), Value::Bool(true))])),
    ])
}

fn get_assertion_request(client_data_hash: &[u8], allow: Option<&[u8]>) -> Value {
    let mut entries = vec![
        (int(1), text("example.com")),
        (int(2), Value::Bytes(client_data_hash.to_vec())),
    ];
    if let Some(credential_id) = allow {
        entries.push((
            int(3),
            Value::Array(vec![map(vec![
                (text("id"), Value::Bytes(credential_id.to_vec())),
                (text("type"), text("public-key")),
            ])]),
        ));
    }
    map(entries)
}

/// What a relying party keeps from a registration.
struct Registration {
    credential_id: Vec<u8>,
    public_key: Value,
    response: Value,
}

fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("operating system RNG");
    bytes
}

/// Split attested authenticator data into (credential ID, COSE key).
fn attested_credential(auth_data: &[u8]) -> (Vec<u8>, Value) {
    assert_eq!(auth_data[32] & 0x40, 0x40, "AT flag");
    let length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let credential_id = auth_data[55..55 + length].to_vec();
    let public_key: Value = ciborium::de::from_reader(&auth_data[55 + length..]).expect("COSE key");
    (credential_id, public_key)
}

fn register(app: &mut CtapApp<'static>, user_id: &[u8], alg: CoseAlg) -> Registration {
    let client_data_hash = random_32();
    let response = call_ok(
        app,
        0x01,
        &make_credential_request(&client_data_hash, user_id, alg),
    );
    let auth_data = bytes(get(&response, &int(2)));
    let (credential_id, public_key) = attested_credential(&auth_data);
    assert_eq!(get(&public_key, &int(3)), int(alg as i64), "COSE alg");
    Registration {
        credential_id,
        public_key,
        response,
    }
}

/// Verify `signature` over `message` with a COSE public key, independently
/// of the engine's signing code.
fn verify(public_key: &Value, message: &[u8], signature: &[u8]) {
    let alg = match get(public_key, &int(3)) {
        Value::Integer(alg) => CoseAlg::try_from(i128::from(alg) as i32).expect("known alg"),
        other => panic!("COSE alg {other:?}"),
    };
    match alg {
        CoseAlg::ES256 => {
            let mut sec1 = vec![0x04];
            sec1.extend(bytes(get(public_key, &int(-2))));
            sec1.extend(bytes(get(public_key, &int(-3))));
            let key = VerifyingKey::from_sec1_bytes(&sec1).expect("P-256 key");
            let signature = Signature::from_der(signature).expect("DER signature");
            key.verify(message, &signature)
                .expect("ES256 signature verifies");
        }
        alg => {
            let param_set = mldsa_paramset_from_alg(alg).expect("ML-DSA");
            let key = pqkey_mldsa::PublicKey(bytes(get(public_key, &int(-1))));
            assert!(
                pqkey_mldsa::verify(param_set, &key, message, signature),
                "{alg:?} signature verifies"
            );
        }
    }
}

/// Assert with `credential`, check the signature and return the counter.
fn authenticate(app: &mut CtapApp<'static>, registration: &Registration) -> u32 {
    let client_data_hash = random_32();
    let response = call_ok(
        app,
        0x02,
        &get_assertion_request(&client_data_hash, Some(&registration.credential_id)),
    );
    assert_eq!(
        bytes(get(&get(&response, &int(1)), &text("id"))),
        registration.credential_id
    );
    let auth_data = bytes(get(&response, &int(2)));
    let signature = bytes(get(&response, &int(3)));
    let mut message = auth_data.clone();
    message.extend_from_slice(&client_data_hash);
    verify(&registration.public_key, &message, &signature);
    u32::from_be_bytes(auth_data[33..37].try_into().unwrap())
}

#[test]
fn every_algorithm_registers_and_authenticates_across_restarts() {
    for alg in ALL_ALGS {
        let dir = TempDir::new();
        let registration = register(&mut open_app(&dir.state()), &[0x01], alg);
        // Self attestation, since no attestation key is provisioned.
        let att_stmt = get(&registration.response, &int(3));
        assert_eq!(get(&registration.response, &int(1)), text("packed"));
        assert_eq!(get(&att_stmt, &text("alg")), int(alg as i64));

        assert_eq!(authenticate(&mut open_app(&dir.state()), &registration), 1);
        assert_eq!(
            authenticate(&mut open_app(&dir.state()), &registration),
            2,
            "{alg:?}: the signature counter survives a restart"
        );
    }
}

#[test]
fn self_attestation_verifies_with_the_credential_key() {
    for alg in ALL_ALGS {
        let dir = TempDir::new();
        let mut app = open_app(&dir.state());
        let client_data_hash = random_32();
        let response = call_ok(
            &mut app,
            0x01,
            &make_credential_request(&client_data_hash, &[0x02], alg),
        );
        let auth_data = bytes(get(&response, &int(2)));
        let (_, public_key) = attested_credential(&auth_data);
        let att_stmt = get(&response, &int(3));
        assert!(matches!(&att_stmt, Value::Map(entries) if entries.len() == 2));
        let mut message = auth_data;
        message.extend_from_slice(&client_data_hash);
        verify(&public_key, &message, &bytes(get(&att_stmt, &text("sig"))));
    }
}

/// A fixed-size placeholder certificate; the engine returns the chain as
/// stored and never parses it.
fn attestation_record(certificate_len: usize) -> (AttestationRecord, VerifyingKey) {
    let PrivateKeyMaterial::Es256 { scalar } = PrivateKeyMaterial::generate(CoseAlg::ES256) else {
        unreachable!()
    };
    let verifying_key = *SigningKey::from_slice(&scalar).unwrap().verifying_key();
    let mut certificate = vec![0u8; certificate_len];
    getrandom::fill(&mut certificate).expect("operating system RNG");
    certificate[0] = 0x30;
    (
        AttestationRecord {
            private_key: scalar,
            certificate_chain: vec![certificate],
        },
        verifying_key,
    )
}

/// By default the attestation is self attestation even when the store holds
/// an attestation key and certificate: packed, without x5c, signed with the
/// credential's own key, and with the configured AAGUID in authenticatorData.
#[test]
fn self_attestation_is_the_default_even_with_a_provisioned_certificate() {
    for alg in ALL_ALGS {
        let dir = TempDir::new();
        let (record, _) = attestation_record(512);
        FileStore::open(dir.state())
            .unwrap()
            .set_attestation(&record)
            .expect("provision attestation");

        let mut app = open_app(&dir.state());
        let client_data_hash = random_32();
        let response = call_ok(
            &mut app,
            0x01,
            &make_credential_request(&client_data_hash, &[0x04], alg),
        );
        assert_eq!(get(&response, &int(1)), text("packed"), "{alg:?}");
        let auth_data = bytes(get(&response, &int(2)));
        assert_eq!(
            auth_data[37..53],
            AAGUID,
            "{alg:?}: authenticatorData AAGUID"
        );
        let att_stmt = get(&response, &int(3));
        let Value::Map(entries) = &att_stmt else {
            panic!("attStmt is not a map");
        };
        let keys: Vec<&Value> = entries.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, [&text("alg"), &text("sig")], "{alg:?}: no x5c");
        assert_eq!(get(&att_stmt, &text("alg")), int(alg as i64));
        let (_, public_key) = attested_credential(&auth_data);
        let mut message = auth_data;
        message.extend_from_slice(&client_data_hash);
        verify(&public_key, &message, &bytes(get(&att_stmt, &text("sig"))));
    }
}

/// AttestationMode::None returns "none", with or without a certificate.
#[test]
fn attestation_mode_none_returns_the_none_format() {
    for provisioned in [false, true] {
        let dir = TempDir::new();
        if provisioned {
            FileStore::open(dir.state())
                .unwrap()
                .set_attestation(&attestation_record(512).0)
                .expect("provision attestation");
        }
        let mut app = open_app_with(&dir.state(), AttestationMode::None);
        let response = call_ok(
            &mut app,
            0x01,
            &make_credential_request(&random_32(), &[0x05], CoseAlg::ES256),
        );
        assert_eq!(get(&response, &int(1)), text("none"));
        assert_eq!(get(&response, &int(3)), map(Vec::new()));
        assert_eq!(bytes(get(&response, &int(2)))[37..53], AAGUID);
    }
}

#[test]
fn packed_attestation_uses_the_provisioned_key_and_certificate_chain() {
    for alg in ALL_ALGS {
        let dir = TempDir::new();
        let (record, verifying_key) = attestation_record(512);
        FileStore::open(dir.state())
            .unwrap()
            .set_attestation(&record)
            .expect("provision attestation");

        let mut app = open_app_with(&dir.state(), AttestationMode::Certificate);
        let client_data_hash = random_32();
        let response = call_ok(
            &mut app,
            0x01,
            &make_credential_request(&client_data_hash, &[0x03], alg),
        );
        assert_eq!(get(&response, &int(1)), text("packed"));
        let att_stmt = get(&response, &int(3));
        assert_eq!(get(&att_stmt, &text("alg")), int(-7), "{alg:?}");
        assert_eq!(
            get(&att_stmt, &text("x5c")),
            Value::Array(vec![Value::Bytes(record.certificate_chain[0].clone())])
        );
        let mut message = bytes(get(&response, &int(2)));
        message.extend_from_slice(&client_data_hash);
        let signature = Signature::from_der(&bytes(get(&att_stmt, &text("sig")))).unwrap();
        verifying_key
            .verify(&message, &signature)
            .expect("attestation signature verifies with the attestation key");
    }
}

/// The old store serialized every credential into one 1,024-byte message, so
/// not even one ML-DSA credential fit.  Register many ML-DSA-87 credentials,
/// restart, and use every one of them through discovery.
#[test]
fn many_ml_dsa_87_credentials_persist_without_a_size_cap() {
    const COUNT: u8 = 12;
    let dir = TempDir::new();
    let mut registrations = Vec::new();
    for user in 0..COUNT {
        registrations.push(register(
            &mut open_app(&dir.state()),
            &[0x10, user],
            CoseAlg::MLDSA87,
        ));
    }
    assert_eq!(
        FileStore::open(dir.state()).unwrap().count().unwrap(),
        usize::from(COUNT)
    );

    let mut app = open_app(&dir.state());
    let client_data_hash = random_32();
    let mut responses = vec![call_ok(
        &mut app,
        0x02,
        &get_assertion_request(&client_data_hash, None),
    )];
    assert_eq!(get(&responses[0], &int(5)), int(i64::from(COUNT)));
    for _ in 1..COUNT {
        responses.push(call_ok(&mut app, 0x08, &map(Vec::new())));
    }
    // Most recently created first (CTAP 2.3 §6.2.2 step 12.2.1).
    for (response, registration) in responses.iter().zip(registrations.iter().rev()) {
        assert_eq!(
            bytes(get(&get(response, &int(1)), &text("id"))),
            registration.credential_id
        );
        let mut message = bytes(get(response, &int(2)));
        message.extend_from_slice(&client_data_hash);
        verify(
            &registration.public_key,
            &message,
            &bytes(get(response, &int(3))),
        );
    }
}

/// Registering a discoverable credential for an account that has one replaces
/// it (CTAP 2.3 §6.1.2 step 17.2), across a restart.
#[test]
fn re_registering_an_account_replaces_its_credential() {
    let dir = TempDir::new();
    let old = register(&mut open_app(&dir.state()), &[0x20], CoseAlg::MLDSA44);
    let new = register(&mut open_app(&dir.state()), &[0x20], CoseAlg::MLDSA44);
    let store = FileStore::open(dir.state()).unwrap();
    assert_eq!(store.count().unwrap(), 1);
    assert!(store.get(&old.credential_id).unwrap().is_none());
    assert!(store.get(&new.credential_id).unwrap().is_some());
}

/// The ML-DSA-87 makeCredential response in both attestation modes, against
/// the CTAPHID message limit.  Run with `--nocapture` to see the sizes.
#[test]
fn ml_dsa_87_make_credential_response_sizes() {
    let self_attested = {
        let dir = TempDir::new();
        let mut app = open_app(&dir.state());
        call(
            &mut app,
            0x01,
            &make_credential_request(&random_32(), &[0x30], CoseAlg::MLDSA87),
        )
        .len()
    };
    // 641 bytes is a generous size for a certificate the daemon generates
    // with typical identity strings.
    let packed_with_certificate = {
        let dir = TempDir::new();
        let (record, _) = attestation_record(641);
        FileStore::open(dir.state())
            .unwrap()
            .set_attestation(&record)
            .unwrap();
        let mut app = open_app_with(&dir.state(), AttestationMode::Certificate);
        call(
            &mut app,
            0x01,
            &make_credential_request(&random_32(), &[0x31], CoseAlg::MLDSA87),
        )
        .len()
    };
    println!(
        "ML-DSA-87 makeCredential response: self attestation {self_attested} bytes, \
         packed attestation with a 641-byte certificate {packed_with_certificate} bytes \
         (CTAPHID limit {CTAPHID_MAX_MESSAGE})"
    );
    assert!(self_attested <= CTAPHID_MAX_MESSAGE);
    assert!(packed_with_certificate < self_attested);
}
