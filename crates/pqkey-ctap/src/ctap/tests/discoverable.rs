//! Discoverable and non-discoverable credentials (CTAP 2.3 §6.1.2 steps 17
//! and 18, §6.1.3): discoverable ones are stored, non-discoverable ones are
//! sealed into their credential ID.

use super::support::{
    NEVER_INTERRUPTED, TestApp, TestStore, app_with_store, created_credential, encode,
    es256_credential, get_assertion_request, install_pin_uv_auth_token, int, response_auth_data,
    test_app, token_pin_auth,
};
use crate::ctap::CtapApp;
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::PIN_PERMISSION_CM;
use crate::ctap::storage::{
    CREDENTIAL_ID_LENGTH, SEALED_ID_LENGTH, derive_sealed_cred_randoms, is_discoverable, is_sealed,
};
use crate::store::PrivateKeyMaterial;
use crate::{ClassicPinProtocol, CoseAlg};

use ciborium::{de::from_reader, value::Value};
use sha2::{Digest, Sha256};

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// makeCredential for `user_id` with `options`, and the new credential's ID.
fn register(app: &mut TestApp, user_id: &[u8], options: Option<Value>) -> Vec<u8> {
    register_with(app, user_id, options, vec![])
}

/// [`register`] with `extra` request parameters.
fn register_with(
    app: &mut TestApp,
    user_id: &[u8],
    options: Option<Value>,
    extra: Vec<(Value, Value)>,
) -> Vec<u8> {
    let mut entries = vec![
        (int(1), Value::Bytes(vec![0x11; 32])),
        (int(2), canonical_map(vec![(text("id"), text(RP_ID))])),
        (
            int(3),
            canonical_map(vec![(text("id"), Value::Bytes(user_id.to_vec()))]),
        ),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), int(CoseAlg::ES256 as i64)),
            ])]),
        ),
    ];
    if let Some(options) = options {
        entries.push((int(7), options));
    }
    entries.extend(extra);
    let response = app
        .handle_make_credential(&encode(&canonical_map(entries)))
        .expect("makeCredential succeeds");
    created_credential(app, &response, RP_ID)
        .credential_id
        .clone()
}

fn rk(value: bool) -> Option<Value> {
    Some(canonical_map(vec![(text("rk"), Value::Bool(value))]))
}

fn assertion_with_allow_list(app: &mut TestApp, credential_id: &[u8]) -> Result<Vec<u8>, u8> {
    assertion_for_rp(app, RP_ID, credential_id)
}

fn assertion_for_rp(app: &mut TestApp, rp_id: &str, credential_id: &[u8]) -> Result<Vec<u8>, u8> {
    let entries = vec![
        (int(1), text(rp_id)),
        (int(2), Value::Bytes(vec![0x22; 32])),
        (
            int(3),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("id"), Value::Bytes(credential_id.to_vec())),
            ])]),
        ),
    ];
    app.handle_get_assertion(&encode(&canonical_map(entries)))
}

fn discoverable_assertion(app: &mut TestApp) -> Result<Vec<u8>, u8> {
    app.handle_get_assertion(&get_assertion_request(&[0x22; 32], RP_ID, None, None))
}

#[test]
fn rk_false_creates_a_credential_only_an_allow_list_finds() {
    for options in [None, rk(false)] {
        let mut app = test_app([0x61; 16]);
        let credential_id = register(&mut app, &[0x01], options.clone());
        assert!(!is_discoverable(&credential_id), "{options:?}");

        assert_eq!(
            discoverable_assertion(&mut app),
            Err(CTAP2_ERR_NO_CREDENTIALS),
            "{options:?}"
        );
        let response = assertion_with_allow_list(&mut app, &credential_id).expect("allowList");
        assert_eq!(response[0], CTAP2_OK);
    }
}

#[test]
fn rk_true_creates_a_discoverable_credential() {
    let mut app = test_app([0x62; 16]);
    let credential_id = register(&mut app, &[0x01], rk(true));
    assert!(is_discoverable(&credential_id));
    assert_eq!(credential_id.len(), CREDENTIAL_ID_LENGTH);
    let response = discoverable_assertion(&mut app).expect("found without an allowList");
    assert_eq!(response[0], CTAP2_OK);
}

/// Credentials created before this distinction, with 32-byte random IDs, and
/// any other ID not of the new form, stay discoverable.
#[test]
fn credentials_with_other_ids_stay_discoverable() {
    let mut app = test_app([0x63; 16]);
    let legacy_id = [0x00; 32];
    app.store
        .put(&es256_credential(RP_ID, &legacy_id))
        .expect("store");
    assert!(is_discoverable(&legacy_id));
    assert!(is_discoverable(&[0x00; 34]));
    assert!(discoverable_assertion(&mut app).is_ok());
}

/// Overwriting "a credential for the same rp.id and account ID" (CTAP 2.3
/// §6.1.2 step 17.2) applies to discoverable credentials only.
#[test]
fn a_discoverable_registration_replaces_only_discoverable_credentials() {
    let mut app = test_app([0x64; 16]);
    let server_side = register(&mut app, &[0x01], rk(false));
    let first = register(&mut app, &[0x01], rk(true));
    let second = register(&mut app, &[0x01], rk(true));

    let ids: Vec<_> = app
        .store
        .list()
        .expect("list")
        .into_iter()
        .map(|credential| credential.credential_id.clone())
        .collect();
    assert_eq!(ids, [second]);
    assert!(!ids.contains(&first));
    assert!(assertion_with_allow_list(&mut app, &server_side).is_ok());
}

/// A non-discoverable credential is sealed into its ID: nothing is stored,
/// and the ID holds its algorithm, credProtect level and private key, sealed
/// for its relying party.
#[test]
fn a_non_discoverable_credential_is_sealed_into_its_id() {
    for alg in [CoseAlg::ES256, CoseAlg::MLDSA87] {
        let mut app = test_app([0x66; 16]);
        let entries = vec![
            (int(1), Value::Bytes(vec![0x11; 32])),
            (int(2), canonical_map(vec![(text("id"), text(RP_ID))])),
            (
                int(3),
                canonical_map(vec![(text("id"), Value::Bytes(vec![0x01]))]),
            ),
            (
                int(4),
                Value::Array(vec![canonical_map(vec![
                    (text("type"), text("public-key")),
                    (text("alg"), int(alg as i64)),
                ])]),
            ),
            (int(6), canonical_map(vec![(text("credProtect"), int(2))])),
        ];
        let response = app
            .handle_make_credential(&encode(&canonical_map(entries)))
            .expect("makeCredential succeeds");
        let credential = created_credential(&app, &response, RP_ID);
        let credential_id = &credential.credential_id;
        assert!(app.store.list().expect("list").is_empty(), "{alg:?}");
        assert_eq!(credential_id.len(), SEALED_ID_LENGTH);
        assert_eq!(credential_id[0], 0x02);
        assert!(is_sealed(credential_id) && !is_discoverable(credential_id));

        let mut associated_data = b"pqkey/v1/sealed-credential-id".to_vec();
        associated_data.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        let plaintext = app
            .store
            .open_credential_id(&credential_id[1..], &associated_data)
            .expect("open")
            .expect("sealed for the relying party");
        let key = match &credential.private_key {
            PrivateKeyMaterial::Es256 { scalar } => scalar,
            PrivateKeyMaterial::MlDsa { seed } => seed,
        };
        assert_eq!(plaintext[0], alg as i32 as i8 as u8, "{alg:?}");
        assert_eq!(plaintext[1], 2, "credProtect");
        assert_eq!(&plaintext[2..], key.as_slice());
        assert_eq!(credential.cred_protect, 2);
    }
}

/// A sealed credential is found only for its relying party, only unaltered,
/// and only until a reset replaces the key that sealed it.
#[test]
fn a_sealed_credential_opens_only_for_its_relying_party_unaltered_and_until_a_reset() {
    let mut app = test_app([0x67; 16]);
    let credential_id = register(&mut app, &[0x01], None);
    assert!(assertion_with_allow_list(&mut app, &credential_id).is_ok());
    assert_eq!(
        assertion_for_rp(&mut app, "other.example", &credential_id),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    for index in [0, 1, SEALED_ID_LENGTH / 2, SEALED_ID_LENGTH - 1] {
        let mut altered = credential_id.clone();
        altered[index] ^= 0x01;
        assert_eq!(
            assertion_with_allow_list(&mut app, &altered),
            Err(CTAP2_ERR_NO_CREDENTIALS),
            "byte {index}"
        );
    }
    app.store.clear().expect("reset");
    assert_eq!(
        assertion_with_allow_list(&mut app, &credential_id),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
}

/// A sealed credential has no state to count in, so every assertion reports
/// a signature count of 0, and nothing is written.
#[test]
fn a_sealed_credential_counts_no_signatures() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x68; 16], [], &NEVER_INTERRUPTED);
    let credential_id = register(&mut app, &[0x01], None);
    store.faults(|faults| faults.put = true);
    for _ in 0..2 {
        let response = assertion_with_allow_list(&mut app, &credential_id).expect("allowList");
        assert_eq!(response_auth_data(&response)[33..37], [0, 0, 0, 0]);
    }
}

/// Non-discoverable registrations need no room in the store, so they go on
/// when it is full, while discoverable ones are refused.
#[test]
fn a_full_store_still_registers_non_discoverable_credentials() {
    let (mut app, _) = app_with_store(
        TestStore::with_max_credentials(0),
        [0x69; 16],
        [],
        &NEVER_INTERRUPTED,
    );
    let credential_id = register(&mut app, &[0x01], rk(false));
    assert!(assertion_with_allow_list(&mut app, &credential_id).is_ok());
    let entries = vec![
        (int(1), Value::Bytes(vec![0x11; 32])),
        (int(2), canonical_map(vec![(text("id"), text(RP_ID))])),
        (
            int(3),
            canonical_map(vec![(text("id"), Value::Bytes(vec![0x02]))]),
        ),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), int(CoseAlg::ES256 as i64)),
            ])]),
        ),
        (int(7), rk(true).expect("options")),
    ];
    assert_eq!(
        app.handle_make_credential(&encode(&canonical_map(entries))),
        Err(CTAP2_ERR_KEY_STORE_FULL)
    );
}

/// A store that cannot be read fails the request instead of answering that
/// the sealed credential does not exist.
#[test]
fn a_store_failure_opening_a_sealed_id_fails_the_request() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x6A; 16], [], &NEVER_INTERRUPTED);
    let credential_id = register(&mut app, &[0x01], None);
    store.faults(|faults| faults.get = true);
    assert_eq!(
        assertion_with_allow_list(&mut app, &credential_id),
        Err(CTAP2_ERR_PROCESSING)
    );
}

/// authenticatorCredentialManagement manages discoverable credentials only
/// (CTAP 2.3 §6.8).
#[test]
fn credential_management_lists_only_discoverable_credentials() {
    let mut app = test_app([0x65; 16]);
    register(&mut app, &[0x01], rk(false));
    register(&mut app, &[0x02], rk(true));
    // And one stored before non-discoverable credentials were sealed.
    let mut stored_id = vec![0x5B; CREDENTIAL_ID_LENGTH];
    stored_id[0] = 0x00;
    app.store
        .put(&es256_credential(RP_ID, &stored_id))
        .expect("store");
    let token = [0x65; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_CM,
        None,
    );

    let metadata = canonical_map(vec![
        (int(1), int(0x01)),
        (int(3), int(2)),
        (
            int(4),
            Value::Bytes(token_pin_auth(ClassicPinProtocol::V2, &token, &[0x01])),
        ),
    ]);
    let response = app
        .handle_credential_management(&encode(&metadata))
        .expect("getCredsMetadata");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode") else {
        panic!("map");
    };
    assert!(map.contains(&(int(1), int(1))), "{map:?}");

    let rp_id_hash = CtapApp::cm_hash_rp_id(RP_ID);
    let params = canonical_map(vec![(int(1), Value::Bytes(rp_id_hash))]);
    let mut message = vec![0x04];
    message.extend(encode(&params));
    let begin = canonical_map(vec![
        (int(1), int(0x04)),
        (int(2), params),
        (int(3), int(2)),
        (
            int(4),
            Value::Bytes(token_pin_auth(ClassicPinProtocol::V2, &token, &message)),
        ),
    ]);
    let response = app
        .handle_credential_management(&encode(&begin))
        .expect("enumerateCredentialsBegin");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode") else {
        panic!("map");
    };
    assert!(map.contains(&(int(9), int(1))), "totalCredentials: {map:?}");
}

/// Non-discoverable credentials stored before they were sealed into their IDs
/// stay non-discoverable: found through an allowList only, and not replaced
/// by a discoverable registration for the same account.
#[test]
fn non_discoverable_credentials_stored_before_sealing_stay_non_discoverable() {
    let mut app = test_app([0x6B; 16]);
    let mut stored_id = vec![0x5A; CREDENTIAL_ID_LENGTH];
    stored_id[0] = 0x00;
    app.store
        .put(&es256_credential(RP_ID, &stored_id))
        .expect("store");
    assert!(!is_discoverable(&stored_id) && !is_sealed(&stored_id));

    assert_eq!(
        discoverable_assertion(&mut app),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    assert!(assertion_with_allow_list(&mut app, &stored_id).is_ok());
    // es256_credential gives user ID 0x01, the account registered here.
    register(&mut app, &[0x01], rk(true));
    assert!(app.store.get(&stored_id).expect("get").is_some());
    assert!(assertion_with_allow_list(&mut app, &stored_id).is_ok());
}

/// Pins how a sealed credential's hmac-secret CredRandom values derive from
/// its key to an independent computation with Python's standard library
/// (HKDF-SHA-256, RFC 5869, no salt, info strings as below).  A change would
/// change the hmac-secret outputs of every existing non-discoverable
/// credential, which can be disk encryption keys.
#[test]
fn sealed_cred_randoms_match_an_independent_implementation() {
    let mut credential = es256_credential(RP_ID, &[0x01]);
    credential.alg = CoseAlg::MLDSA44;
    credential.private_key = PrivateKeyMaterial::MlDsa {
        seed: core::array::from_fn(|i| 0x80 + i as u8),
    };
    derive_sealed_cred_randoms(&mut credential).expect("derive");
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    // pqkey/v1/sealed-credential/cred-random-with-uv
    assert_eq!(
        hex(&credential.cred_random_with_uv),
        "84adcaa5eebe8a26d2538bce06595434c507f05ba9c38c9ae317a8effc3382b4"
    );
    // pqkey/v1/sealed-credential/cred-random-without-uv
    assert_eq!(
        hex(&credential.cred_random_without_uv),
        "6e39697a8a3f192e1673f64f097d3dc55a7007f09c695c70c41a4df3d3ec9c7f"
    );
}
