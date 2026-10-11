//! Failed reset must never roll back a surviving credential's counter.

use std::cell::RefCell;
use std::process::{Command, Stdio};
use std::rc::Rc;

use ciborium::value::Value;
use sha2::{Digest, Sha256};

use super::*;
use crate::CoseAlg;
use crate::ctap::{CtapApp, InterruptFlag, constants::*, presence::AutoApprove, u2f::*};
use crate::store::{PrivateKeyMaterial, test_support::TempDir};

static INTERRUPT: InterruptFlag = InterruptFlag::new();
const RP: &str = "example.com";
const HASH: [u8; 32] = [0x37; 32];

fn int(value: i32) -> Value {
    Value::Integer(value.into())
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn call(app: &mut CtapApp<'_>, command: u8, fields: Vec<(Value, Value)>) -> Vec<u8> {
    let mut request = vec![command];
    ciborium::ser::into_writer(&Value::Map(fields), &mut request).unwrap();
    let response = app.call(&request);
    assert!(response.len() <= 7609);
    response
}

fn field(response: &[u8], key: i32) -> Value {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(fields) = ciborium::de::from_reader(&response[1..]).unwrap() else {
        panic!("response is not a map");
    };
    fields.into_iter().find(|(k, _)| *k == int(key)).unwrap().1
}

fn bytes(value: Value) -> Vec<u8> {
    let Value::Bytes(bytes) = value else {
        panic!("expected bytes");
    };
    bytes
}

fn app(path: &Path) -> CtapApp<'static> {
    let mut app = CtapApp::with_file_store(
        FileStore::open(path).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    );
    app.set_reset_window(None);
    app
}

fn register(app: &mut CtapApp<'_>) -> (Vec<u8>, Vec<u8>) {
    let response = call(
        app,
        CTAP_CMD_MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(HASH.to_vec())),
            (int(2), Value::Map(vec![(text("id"), text(RP))])),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ],
    );
    let data = bytes(field(&response, 2));
    let length = usize::from(u16::from_be_bytes(data[53..55].try_into().unwrap()));
    assert_eq!(length, 107);
    (data[55..55 + length].to_vec(), data[55 + length..].to_vec())
}

fn assertion(app: &mut CtapApp<'_>, id: &[u8]) -> Vec<u8> {
    call(
        app,
        CTAP_CMD_GET_ASSERTION,
        vec![
            (int(1), text(RP)),
            (int(2), Value::Bytes(HASH.to_vec())),
            (
                int(3),
                Value::Array(vec![Value::Map(vec![
                    (text("id"), Value::Bytes(id.to_vec())),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ],
    )
}

fn authenticate(app: &mut CtapApp<'_>, id: &[u8], public: &[u8]) -> u32 {
    let response = assertion(app, id);
    let data = bytes(field(&response, 2));
    crate::crypto::verify::verify_signature(
        CoseAlg::ES256,
        public,
        &[data.as_slice(), &HASH].concat(),
        &bytes(field(&response, 3)),
    )
    .unwrap();
    u32::from_be_bytes(data[33..37].try_into().unwrap())
}

fn u2f_authenticate(app: &mut CtapApp<'_>, id: &[u8], public: &[u8]) -> u32 {
    let application: [u8; 32] = Sha256::digest(RP.as_bytes()).into();
    let mut data = [HASH.as_slice(), &application, &[id.len() as u8], id].concat();
    let mut request = vec![0, 2, 3, 0, 0];
    request.extend_from_slice(&(data.len() as u16).to_be_bytes());
    request.append(&mut data);
    let response = app.call_u2f(&request);
    assert!(response.len() <= 7609);
    let end = response.len() - 2;
    assert_eq!(&response[end..], SW_NO_ERROR.to_be_bytes());
    crate::crypto::verify::verify_signature(
        CoseAlg::ES256,
        public,
        &[application.as_slice(), &response[..5], &HASH].concat(),
        &response[5..end],
    )
    .unwrap();
    u32::from_be_bytes(response[1..5].try_into().unwrap())
}

fn stored_record() -> CredentialRecord {
    CredentialRecord {
        credential_id: vec![1; 33],
        rp_id: RP.into(),
        user_id: vec![2],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::ES256,
        private_key: PrivateKeyMaterial::generate(CoseAlg::ES256),
        cred_random_with_uv: [1; 32],
        cred_random_without_uv: [2; 32],
        cred_blob: None,
        large_blob_key: None,
        cred_protect: 1,
        sign_count: 7,
        created_at: 0,
    }
}

fn setup(path: &Path, managed: bool) -> (Vec<u8>, Vec<u8>, CredentialRecord) {
    let (id, public) = register(&mut app(path));
    let mut store = FileStore::open(path).unwrap();
    let record = stored_record();
    if managed {
        store.insert_or_replace_discoverable(&record).unwrap();
    } else {
        store.put(&record).unwrap();
    }
    (id, public, record)
}

fn failure(path: &Path) -> StoreError {
    fsio::io_error(path, std::io::Error::other("injected reset failure"))
}

#[test]
fn published_configuration_is_immediately_used_despite_post_rename_failure() {
    for failing in ["renamed", "directory-flush", "directory-flushed"] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let mut engine = app(&path);
        let mut published = false;
        let response = fsio::with_hook(
            Box::new(move |event, path| {
                if event == "renamed" && path.ends_with(PIN_STATE_FILE) {
                    published = true;
                }
                if published && event == failing {
                    Err(failure(path))
                } else {
                    Ok(())
                }
            }),
            || {
                call(
                    &mut engine,
                    CTAP_CMD_AUTHENTICATOR_CONFIG,
                    vec![(int(1), int(2))],
                )
            },
        );
        assert!(
            FileStore::open(&path)
                .unwrap()
                .pin_state()
                .unwrap()
                .unwrap()
                .always_uv
        );
        let live = field(&engine.call(&[CTAP_CMD_GET_INFO]), 4);
        let restarted = field(&app(&path).call(&[CTAP_CMD_GET_INFO]), 4);
        assert_eq!(live, restarted, "live policy diverged after {failing}");
        assert_eq!(response, [CTAP2_OK]);
    }
}

#[test]
fn failed_rotation_preserves_shared_counter_across_restarts_and_protocols() {
    for (managed, restart) in [(false, false), (false, true), (true, false), (true, true)] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let (id, public, record) = setup(&path, managed);
        let stored_public = record.cose_public_key().unwrap();
        let mut engine = app(&path);
        assert_eq!(authenticate(&mut engine, &id, &public), 1);
        assert_eq!(authenticate(&mut engine, &id, &public), 2);
        for expected in 3..=6 {
            let response = fsio::with_hook(
                Box::new(|event, path| {
                    if event == "rename" && path.ends_with("credential.key") {
                        Err(failure(path))
                    } else {
                        Ok(())
                    }
                }),
                || engine.call(&[CTAP_CMD_RESET]),
            );
            assert_eq!(response, [CTAP2_ERR_PROCESSING]);
            if restart || expected % 2 == 0 {
                engine = app(&path);
            }
            let count = if expected % 2 == 0 {
                u2f_authenticate(&mut engine, &id, &public)
            } else {
                authenticate(&mut engine, &id, &public)
            };
            assert_eq!(count, expected);
            assert_eq!(
                authenticate(&mut engine, &record.credential_id, &stored_public),
                expected + 5
            );
            assert_eq!(
                FileStore::open(&path).unwrap().signature_counter().unwrap(),
                expected
            );
        }
        FileStore::open(&path)
            .unwrap()
            .set_signature_counter(u32::MAX - 1)
            .unwrap();
        assert_eq!(authenticate(&mut engine, &id, &public), u32::MAX);
        let response = fsio::with_hook(
            Box::new(|event, path| {
                if event == "rename" && path.ends_with("credential.key") {
                    Err(failure(path))
                } else {
                    Ok(())
                }
            }),
            || engine.call(&[CTAP_CMD_RESET]),
        );
        assert_eq!(response, [CTAP2_ERR_PROCESSING]);
        assert_eq!(u2f_authenticate(&mut app(&path), &id, &public), u32::MAX);
    }
}

fn policy() -> PinStateRecord {
    PinStateRecord {
        pin_hash: Some([0x42; 16]),
        pin_retries: 3,
        min_pin_length: 9,
        min_pin_length_rp_ids: vec![RP.into()],
        force_pin_change: true,
        pin_code_point_length: 4,
        always_uv: true,
        ..PinStateRecord::default()
    }
}

fn provision(path: &Path) {
    let mut store = FileStore::open(path).unwrap();
    store.set_pin_state(&policy()).unwrap();
    store.set_signature_counter(2).unwrap();
    store
        .set_large_blob_array(
            &[
                vec![0x81, 0x01],
                Sha256::digest([0x81, 0x01])[..16].to_vec(),
            ]
            .concat(),
        )
        .unwrap();
    store
        .set_attestation(&AttestationRecord {
            private_key: [0x41; 32],
            certificate_chain: vec![vec![0x30, 0x00]],
        })
        .unwrap();
}

fn trace(managed: bool) -> Vec<(String, PathBuf)> {
    let scratch = TempDir::new();
    let path = scratch.path().join("state");
    setup(&path, managed);
    provision(&path);
    let mut store = FileStore::open(&path).unwrap();
    let trace = Rc::new(RefCell::new(Vec::new()));
    let captured = trace.clone();
    fsio::with_hook(
        Box::new(move |event, path| {
            captured
                .borrow_mut()
                .push((event.into(), path.to_path_buf()));
            Ok(())
        }),
        || store.clear(),
    )
    .unwrap();
    Rc::try_unwrap(trace).unwrap().into_inner()
}

fn assert_defaults(path: &Path, managed: bool, id: &[u8], old: &CredentialRecord) {
    let mut store = FileStore::open(path).unwrap();
    assert_eq!(store.count().unwrap(), 0);
    assert!(store.list().unwrap().is_empty());
    assert!(store.get(&old.credential_id).unwrap().is_none());
    assert_eq!(store.signature_counter().unwrap(), 0);
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
    assert_eq!(store.large_blob_array().unwrap(), INITIAL_LARGE_BLOB_ARRAY);
    let mut engine = app(path);
    assert_eq!(assertion(&mut engine, id), [CTAP2_ERR_NO_CREDENTIALS]);
    assert_eq!(
        assertion(&mut engine, &old.credential_id),
        [CTAP2_ERR_NO_CREDENTIALS]
    );
    let (fresh, public) = register(&mut engine);
    assert_eq!(authenticate(&mut engine, &fresh, &public), 1);
    if managed {
        assert!(path.join(MANAGED_DIR).join(ACTIVE_FILE).is_file());
        assert!(path.join(FORMAT_FILE).is_file());
    }
    // Membership accepts a new stored credential after recovery, too.
    store.put(old).unwrap();
    assert!(store.get(&old.credential_id).unwrap().is_some());
}

fn assert_interruption(path: &Path, old_key: &RootKey, record: &CredentialRecord) {
    let source = FileKeySource::new(path.join(KEYS_DIR));
    let current = source.load(KeyDomain::Credential).unwrap().unwrap();
    let store = FileStore::open(path).unwrap();
    if current == *old_key {
        // Before rotation publication nothing protected by this key changed.
        assert_eq!(store.signature_counter().unwrap(), 2);
        assert_eq!(store.pin_state().unwrap(), Some(policy()));
        assert!(store.get(&record.credential_id).unwrap().is_some());
    } else {
        // Old IDs cannot decrypt even when cleanup and PIN work never ran.
        assert!(
            store.get(&record.credential_id).is_err()
                || store.get(&record.credential_id).unwrap().is_none()
        );
        assert!(store.signature_counter().is_err() || store.signature_counter().unwrap() == 0);
        let pin = store.pin_state();
        assert!(pin.is_err() || pin.unwrap() == Some(PinStateRecord::default()));
    }
}

#[test]
fn every_reset_checkpoint_preserves_survivors_or_invalidates_them_and_retry_recovers() {
    for managed in [false, true] {
        let events = trace(managed);
        assert!(
            events
                .iter()
                .any(|(event, path)| event == "renamed" && path.ends_with("credential.key"))
        );
        assert!(
            events
                .iter()
                .any(|(event, path)| event == "remove" && path.ends_with(SIGNATURE_COUNTER_FILE))
        );
        assert!(
            events
                .iter()
                .any(|(event, path)| event == "rename" && path.ends_with(PIN_STATE_FILE))
        );
        if managed {
            assert!(events.iter().any(|(event, _)| event == "publication"));
        }
        for (boundary, event) in events.iter().enumerate() {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let (id, _, record) = setup(&path, managed);
            provision(&path);
            let source = FileKeySource::new(path.join(KEYS_DIR));
            let old_key = source.load(KeyDomain::Credential).unwrap().unwrap();
            let device = fs::read(source.key_path(KeyDomain::Device)).unwrap();
            let attestation = fs::read(path.join(ATTESTATION_FILE)).unwrap();
            let mut engine = app(&path);
            let mut index = 0;
            let response = fsio::with_hook(
                Box::new(move |_, path| {
                    let current = index;
                    index += 1;
                    if current == boundary {
                        Err(failure(path))
                    } else {
                        Ok(())
                    }
                }),
                || engine.call(&[CTAP_CMD_RESET]),
            );
            assert!(
                response == [CTAP2_ERR_PROCESSING] || response == [CTAP2_OK],
                "{managed} {boundary} {event:?}: {response:?}"
            );
            assert_interruption(&path, &old_key, &record);
            if response != [CTAP2_OK] {
                assert_ne!(assertion(&mut engine, &id)[0], CTAP2_OK);
                assert_ne!(assertion(&mut app(&path), &id)[0], CTAP2_OK);
            }
            assert_eq!(
                fs::read(source.key_path(KeyDomain::Device)).unwrap(),
                device
            );
            assert_eq!(fs::read(path.join(ATTESTATION_FILE)).unwrap(), attestation);
            assert_eq!(app(&path).call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
            assert_defaults(&path, managed, &id, &record);
            assert_eq!(
                fs::read(source.key_path(KeyDomain::Device)).unwrap(),
                device
            );
            assert_eq!(fs::read(path.join(ATTESTATION_FILE)).unwrap(), attestation);
        }
    }
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("PQKEY_RESET_CHILD") else {
        return;
    };
    let boundary: usize = std::env::var("PQKEY_RESET_BOUNDARY")
        .unwrap()
        .parse()
        .unwrap();
    let mut store = FileStore::open(PathBuf::from(path)).unwrap();
    let mut index = 0;
    fsio::with_hook(
        Box::new(move |_, _| {
            let current = index;
            index += 1;
            if current == boundary {
                std::process::exit(83);
            }
            Ok(())
        }),
        || store.clear(),
    )
    .unwrap();
    panic!("reset crash boundary not reached: {boundary}");
}

#[test]
fn process_exit_at_every_reset_checkpoint_is_recoverable() {
    for managed in [false, true] {
        for (boundary, event) in trace(managed).iter().enumerate() {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let (id, _, record) = setup(&path, managed);
            provision(&path);
            let source = FileKeySource::new(path.join(KEYS_DIR));
            let old_key = source.load(KeyDomain::Credential).unwrap().unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::file::reset_tests::crash_child",
                    "--nocapture",
                ])
                .env("PQKEY_RESET_CHILD", &path)
                .env("PQKEY_RESET_BOUNDARY", boundary.to_string())
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(83), "{managed} {boundary} {event:?}");
            assert_interruption(&path, &old_key, &record);
            assert_ne!(assertion(&mut app(&path), &id)[0], CTAP2_OK);
            assert_eq!(app(&path).call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
            assert_defaults(&path, managed, &id, &record);
        }
    }
}

#[test]
fn unconfirmed_key_publication_preserves_old_records_and_defers_key_wiping() {
    for managed in [false, true] {
        for checkpoint in ["renamed", "directory-flush", "directory-flushed"] {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let (id, _, _) = setup(&path, managed);
            provision(&path);
            let source = FileKeySource::new(path.join(KEYS_DIR));
            let stale = scratch.path().join("old-key");
            fs::hard_link(source.key_path(KeyDomain::Credential), &stale).unwrap();
            let old_key = fs::read(&stale).unwrap();
            let counter = fs::read(path.join(SIGNATURE_COUNTER_FILE)).unwrap();
            let pin = fs::read(path.join(PIN_STATE_FILE)).unwrap();
            let mut store = FileStore::open(&path).unwrap();
            let result = fsio::with_hook(
                Box::new(move |event, path| {
                    if event == checkpoint
                        && (path.ends_with("credential.key") || path.ends_with(KEYS_DIR))
                    {
                        Err(failure(path))
                    } else {
                        Ok(())
                    }
                }),
                || store.clear(),
            );
            assert!(result.is_err());
            assert_ne!(
                fs::read(source.key_path(KeyDomain::Credential)).unwrap(),
                old_key
            );
            assert_eq!(
                fs::read(&stale).unwrap(),
                old_key,
                "unconfirmed publication must not wipe the old key"
            );
            assert_eq!(
                fs::read(path.join(SIGNATURE_COUNTER_FILE)).unwrap(),
                counter
            );
            assert_eq!(fs::read(path.join(PIN_STATE_FILE)).unwrap(), pin);
            assert!(store.signature_counter().is_err());
            assert!(store.pin_state().is_err());
            assert_ne!(assertion(&mut app(&path), &id)[0], CTAP2_OK);
            // Model power-loss rollback of an unflushed rename: the previous
            // key must still have its counter and policy, including membership.
            fs::write(source.key_path(KeyDomain::Credential), &old_key).unwrap();
            assert_eq!(store.signature_counter().unwrap(), 2);
            assert_eq!(store.pin_state().unwrap(), Some(policy()));
            assert_eq!(store.count().unwrap(), 1);
            store.clear().unwrap();
        }
    }
}

#[test]
fn corrupt_counter_is_preserved_on_rotation_error_and_reset_retry_repairs_it() {
    for managed in [false, true] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let (id, _, record) = setup(&path, managed);
        let mut engine = app(&path);
        let mut store = FileStore::open(&path).unwrap();
        store.set_signature_counter(2).unwrap();
        let mut corrupt = fs::read(path.join(SIGNATURE_COUNTER_FILE)).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(path.join(SIGNATURE_COUNTER_FILE), &corrupt).unwrap();
        assert_eq!(
            fsio::with_hook(
                Box::new(|event, path| {
                    if event == "rename" && path.ends_with("credential.key") {
                        Err(failure(path))
                    } else {
                        Ok(())
                    }
                }),
                || engine.call(&[CTAP_CMD_RESET])
            ),
            [CTAP2_ERR_PROCESSING]
        );
        assert_eq!(
            fs::read(path.join(SIGNATURE_COUNTER_FILE)).unwrap(),
            corrupt
        );
        assert_eq!(assertion(&mut engine, &id), [CTAP2_ERR_PROCESSING]);
        assert_eq!(assertion(&mut app(&path), &id), [CTAP2_ERR_PROCESSING]);
        assert_eq!(engine.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
        assert_defaults(&path, managed, &id, &record);
    }
}

struct FailingKeySource {
    source: FileKeySource,
    damage: bool,
}

impl KeySource for FailingKeySource {
    fn load(&self, domain: KeyDomain) -> Result<Option<RootKey>, StoreError> {
        self.source.load(domain)
    }
    fn create(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        self.source.create(domain)
    }
    fn rotate(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        self.source.rotate(domain)?;
        if self.damage {
            fs::write(self.source.key_path(domain), [0; 32]).unwrap();
        }
        Err(failure(&self.source.key_path(domain)))
    }
}

#[test]
fn rotation_error_after_publication_or_key_damage_never_signs_with_old_credentials() {
    for managed in [false, true] {
        for damage in [false, true] {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let (id, public, record) = setup(&path, managed);
            let mut engine = app(&path);
            assert_eq!(authenticate(&mut engine, &id, &public), 1);
            assert_eq!(authenticate(&mut engine, &id, &public), 2);
            let counter = fs::read(path.join(SIGNATURE_COUNTER_FILE)).unwrap();
            let pin = fs::read(path.join(PIN_STATE_FILE)).unwrap();
            let mut failing = FileStore::open_with_key_source(
                &path,
                FailingKeySource {
                    source: FileKeySource::new(path.join(KEYS_DIR)),
                    damage,
                },
            )
            .unwrap();
            assert!(failing.clear().is_err());
            assert_eq!(
                fs::read(path.join(SIGNATURE_COUNTER_FILE)).unwrap(),
                counter
            );
            assert_eq!(fs::read(path.join(PIN_STATE_FILE)).unwrap(), pin);
            assert!(failing.signature_counter().is_err());
            // The running engine still has the default PIN policy, so these
            // refusals must come from key/credential state, not a UV gate.
            assert!(matches!(
                assertion(&mut engine, &id).as_slice(),
                [CTAP2_ERR_NO_CREDENTIALS] | [CTAP2_ERR_PROCESSING]
            ));
            assert_ne!(assertion(&mut app(&path), &id)[0], CTAP2_OK);
            assert_eq!(app(&path).call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
            assert_defaults(&path, managed, &id, &record);
        }
    }
}

#[test]
fn successful_reset_restores_defaults_in_the_running_engine_and_preserves_attestation() {
    for managed in [false, true] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let (id, _, record) = setup(&path, managed);
        provision(&path);
        let source = FileKeySource::new(path.join(KEYS_DIR));
        let stale = scratch.path().join("old-key");
        fs::hard_link(source.key_path(KeyDomain::Credential), &stale).unwrap();
        let device = fs::read(source.key_path(KeyDomain::Device)).unwrap();
        let attestation = fs::read(path.join(ATTESTATION_FILE)).unwrap();
        let mut engine = app(&path);
        assert_ne!(assertion(&mut engine, &id)[0], CTAP2_OK);
        assert_eq!(engine.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
        assert_eq!(fs::read(&stale).unwrap(), [0; 32]);
        assert_eq!(assertion(&mut engine, &id), [CTAP2_ERR_NO_CREDENTIALS]);
        let (fresh, public) = register(&mut engine);
        assert_eq!(authenticate(&mut engine, &fresh, &public), 1);
        assert_eq!(u2f_authenticate(&mut engine, &fresh, &public), 2);
        // The next reset also works, and default membership is usable.
        assert_eq!(engine.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
        assert_defaults(&path, managed, &id, &record);
        assert_eq!(
            fs::read(source.key_path(KeyDomain::Device)).unwrap(),
            device
        );
        assert_eq!(fs::read(path.join(ATTESTATION_FILE)).unwrap(), attestation);
    }
}
