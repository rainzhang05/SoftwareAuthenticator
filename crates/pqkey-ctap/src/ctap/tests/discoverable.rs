//! Discoverable and non-discoverable credentials (CTAP 2.3 §6.1.2 step 17,
//! §6.1.3).

use super::support::{
    TestApp, encode, es256_credential, get_assertion_request, install_pin_uv_auth_token, int,
    test_app, token_pin_auth,
};
use crate::ctap::CtapApp;
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::PIN_PERMISSION_CM;
use crate::ctap::storage::{CREDENTIAL_ID_LENGTH, is_discoverable};
use crate::{ClassicPinProtocol, CoseAlg};

use ciborium::{de::from_reader, value::Value};

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// makeCredential for `user_id` with `options`, and the new credential's ID.
fn register(app: &mut TestApp, user_id: &[u8], options: Option<Value>) -> Vec<u8> {
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
    app.handle_make_credential(&encode(&canonical_map(entries)))
        .expect("makeCredential succeeds");
    app.store.list().expect("list")[0].credential_id.clone()
}

fn rk(value: bool) -> Option<Value> {
    Some(canonical_map(vec![(text("rk"), Value::Bool(value))]))
}

fn assertion_with_allow_list(app: &mut TestApp, credential_id: &[u8]) -> Result<Vec<u8>, u8> {
    let entries = vec![
        (int(1), text(RP_ID)),
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
    assert!(ids.contains(&server_side));
    assert!(ids.contains(&second));
    assert!(!ids.contains(&first));
}

/// authenticatorCredentialManagement manages discoverable credentials only
/// (CTAP 2.3 §6.8).
#[test]
fn credential_management_lists_only_discoverable_credentials() {
    let mut app = test_app([0x65; 16]);
    register(&mut app, &[0x01], rk(false));
    register(&mut app, &[0x02], rk(true));
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
