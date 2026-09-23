//! authenticatorCredentialManagement tests.

use super::support::new_app;
use super::support::{TestApp, credential, insert, insert_owned, stored};
use super::support::{
    TestStore, encode, es256_credential, get_pin_uv_auth_token, install_pin_uv_auth_token, int,
    pin_hash, token_pin_auth,
};
use crate::ctap::CtapApp;
use crate::ctap::cbor::canonical_map;
use crate::ctap::credential_management::truncated_rp_id;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA};
use crate::ctap::pin::protocol::PIN_UV_AUTH_PROTOCOL_CLASSIC;
use crate::ctap::pin::token::{MAX_USAGE_TIME_PERIOD, ManualClock};
use crate::store::CredentialStore;
use crate::{ClassicPinProtocol, CoseAlg};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};

use crate::ctap::constants::*;

/// `authenticate(pinUvAuthToken, subCommand || subCommandParams)` over
/// protocol two, the protocol these tests declare (CTAP 2.3 §6.8).
fn cm_pin_param(token: &[u8; 32], subcommand: u8, params: Option<Value>) -> Vec<u8> {
    let mut message = vec![subcommand];
    if let Some(value) = params {
        let mut encoded = Vec::new();
        into_writer(&value, &mut encoded).expect("encode params");
        message.extend_from_slice(&encoded);
    }
    token_pin_auth(ClassicPinProtocol::V2, token, &message)
}

#[test]
fn credential_management_commands() {
    let mut app = new_app(TestStore::new(), [0x24; 16]);
    let token = [0x90; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_CM,
        None,
    );

    let mut record = credential("example.com", &[0x01], &[0xA1], CoseAlg::MLDSA44);
    record.user_name = Some("one".into());
    record.cred_random_with_uv = [0x44; 32];
    record.cred_random_without_uv = [0x45; 32];
    insert(&mut app, &record);
    let mut record = credential("example.com", &[0x02], &[0xA2], CoseAlg::MLDSA44);
    record.user_name = Some("two".into());
    record.cred_random_with_uv = [0x46; 32];
    record.cred_random_without_uv = [0x47; 32];
    insert(&mut app, &record);
    let mut record = credential("second.example", &[0x03], &[0xB1], CoseAlg::MLDSA44);
    record.user_name = Some("three".into());
    record.user_display_name = Some("Three".into());
    record.cred_random_with_uv = [0x48; 32];
    record.cred_random_without_uv = [0x49; 32];
    record.cred_protect = 2;
    insert(&mut app, &record);

    let metadata_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x01)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x01, None)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&metadata_request, &mut payload).expect("serialize metadata request");
    let response = app
        .handle_credential_management(&payload)
        .expect("metadata succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode metadata") else {
        panic!("metadata response must be map");
    };
    let existing: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some((*int).into()),
            _ => None,
        })
        .expect("existing count");
    assert_eq!(existing, 3);

    let rp_hash = CtapApp::cm_hash_rp_id("example.com");
    let rp_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x02)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x02, None)),
        ),
    ]);
    payload.clear();
    into_writer(&rp_request, &mut payload).expect("serialize RP begin");
    let response = app
        .handle_credential_management(&payload)
        .expect("rp begin succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode RP begin") else {
        panic!("response must be map");
    };
    assert!(map.iter().any(
        |(k, v)| *k == Value::Integer(Integer::from(4)) && *v == Value::Bytes(rp_hash.clone())
    ));

    let rp_next = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x03)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x03, None)),
        ),
    ]);
    payload.clear();
    into_writer(&rp_next, &mut payload).expect("serialize RP next");
    let response = app
        .handle_credential_management(&payload)
        .expect("rp next succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode RP next") else {
        panic!("response must be map");
    };
    assert!(map.iter().any(|(k, v)| {
        *k == Value::Integer(Integer::from(4))
            && *v == Value::Bytes(CtapApp::cm_hash_rp_id("second.example"))
    }));

    let params = canonical_map(vec![(
        Value::Integer(Integer::from(1)),
        Value::Bytes(rp_hash.clone()),
    )]);
    let cred_begin = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x04)),
        ),
        (Value::Integer(Integer::from(2)), params.clone()),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x04, Some(params.clone()))),
        ),
    ]);
    payload.clear();
    into_writer(&cred_begin, &mut payload).expect("serialize credential begin");
    let response = app
        .handle_credential_management(&payload)
        .expect("credential begin succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode credential begin") else {
        panic!("response must be map");
    };
    let total: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(9)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some((*int).into()),
            _ => None,
        })
        .expect("total credentials");
    assert_eq!(total, 2);

    let cred_next = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x05)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x05, None)),
        ),
    ]);
    payload.clear();
    into_writer(&cred_next, &mut payload).expect("serialize credential next");
    let response = app
        .handle_credential_management(&payload)
        .expect("credential next succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode credential next") else {
        panic!("response must be map");
    };
    assert!(
        map.iter()
            .any(|(k, v)| *k == Value::Integer(Integer::from(7)) && matches!(v, Value::Map(_)))
    );
    // totalCredentials only comes with enumerateCredentialsBegin (CTAP 2.3
    // §6.8.4).
    assert!(
        !map.iter()
            .any(|(k, _)| *k == Value::Integer(Integer::from(9))),
        "totalCredentials in a get-next response"
    );

    let delete_descriptor = canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (Value::Text("id".into()), Value::Bytes(vec![0xA1])),
    ]);
    let delete_params = canonical_map(vec![(
        Value::Integer(Integer::from(2)),
        delete_descriptor.clone(),
    )]);
    let delete_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x06)),
        ),
        (Value::Integer(Integer::from(2)), delete_params.clone()),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x06, Some(delete_params))),
        ),
    ]);
    payload.clear();
    into_writer(&delete_request, &mut payload).expect("serialize delete");
    let response = app
        .handle_credential_management(&payload)
        .expect("delete succeeds");
    assert_eq!(response, vec![CTAP2_OK]);
    assert_eq!(stored(&app).len(), 2);

    let update_descriptor = canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (Value::Text("id".into()), Value::Bytes(vec![0xA2])),
    ]);
    let updated_user = canonical_map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0x02])),
        (Value::Text("name".into()), Value::Text("updated".into())),
    ]);
    let update_params = canonical_map(vec![
        (Value::Integer(Integer::from(2)), update_descriptor.clone()),
        (Value::Integer(Integer::from(3)), updated_user.clone()),
    ]);
    let update_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x07)),
        ),
        (Value::Integer(Integer::from(2)), update_params.clone()),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x07, Some(update_params))),
        ),
    ]);
    payload.clear();
    into_writer(&update_request, &mut payload).expect("serialize update");
    let response = app
        .handle_credential_management(&payload)
        .expect("update succeeds");
    assert_eq!(response, vec![CTAP2_OK]);
    let updated = stored(&app)
        .into_iter()
        .find(|cred| cred.credential_id == vec![0xA2])
        .expect("credential remains");
    assert_eq!(updated.user_name.as_deref(), Some("updated"));
}

#[test]
fn credential_management_requires_cm_permission() {
    let mut app = new_app(TestStore::new(), [0x25; 16]);
    let token = [0x91; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_GA,
        None,
    );

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x01)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x01, None)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize metadata request");
    let result = app.handle_credential_management(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn credential_management_rejects_bound_token_for_rp_enumeration() {
    let mut app = new_app(TestStore::new(), [0x26; 16]);
    let token = [0x92; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_CM,
        Some("example.com"),
    );

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(0x02)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(&token, 0x02, None)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize enumerate RPs request");
    let result = app.handle_credential_management(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

fn credential_management(
    app: &mut TestApp,
    token: &[u8; 32],
    subcommand: u8,
    params: Option<Value>,
) -> Result<Vec<u8>, u8> {
    let mut entries = vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(subcommand)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(cm_pin_param(token, subcommand, params.clone())),
        ),
    ];
    if let Some(params) = params {
        entries.push((Value::Integer(Integer::from(2)), params));
    }
    let mut payload = Vec::new();
    into_writer(&canonical_map(entries), &mut payload).expect("serialize request");
    app.handle_credential_management(&payload)
}

fn rp_id_hash_params(rp_id: &str) -> Value {
    canonical_map(vec![(
        Value::Integer(Integer::from(1)),
        Value::Bytes(CtapApp::cm_hash_rp_id(rp_id)),
    )])
}

fn credential_id_params(credential_id: &[u8], user: Option<Value>) -> Value {
    let mut entries = vec![(
        Value::Integer(Integer::from(2)),
        canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential_id.to_vec()),
            ),
        ]),
    )];
    if let Some(user) = user {
        entries.push((Value::Integer(Integer::from(3)), user));
    }
    canonical_map(entries)
}

#[test]
fn credential_management_limits_an_rp_scoped_token_to_that_rp() {
    let mut app = new_app(TestStore::new(), [0x27; 16]);
    app.pin_state.set_pin(pin_hash(b"1234"));
    insert_owned(&mut app, es256_credential("example.com", &[0xA1]));
    insert_owned(&mut app, es256_credential("other.example", &[0xB1]));
    let token = get_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        b"1234",
        PIN_PERMISSION_CM.into(),
        Some("example.com"),
    )
    .expect("cm token scoped to example.com");

    // "the cm permission and no associated permissions RP ID" (CTAP 2.3 §6.8.2, §6.8.3)
    for subcommand in [0x01, 0x02] {
        assert_eq!(
            credential_management(&mut app, &token, subcommand, None),
            Err(CTAP2_ERR_PIN_AUTH_INVALID),
            "subCommand {subcommand:#x}"
        );
    }

    // enumerateCredentialsBegin for the token's own RP only.
    let response = credential_management(
        &mut app,
        &token,
        0x04,
        Some(rp_id_hash_params("example.com")),
    )
    .expect("own RP's credentials enumerate");
    assert_eq!(response[0], CTAP2_OK);
    assert_eq!(
        credential_management(
            &mut app,
            &token,
            0x04,
            Some(rp_id_hash_params("other.example"))
        ),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );

    // "the pinUvAuthToken permissions RP ID matches the RP ID of the
    // credential" (CTAP 2.3 §6.8.5, §6.8.6)
    let user = canonical_map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0x01])),
        (Value::Text("name".into()), Value::Text("renamed".into())),
    ]);
    assert_eq!(
        credential_management(
            &mut app,
            &token,
            0x07,
            Some(credential_id_params(&[0xB1], Some(user.clone())))
        ),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
    assert_eq!(
        credential_management(
            &mut app,
            &token,
            0x07,
            Some(credential_id_params(&[0xA1], Some(user)))
        ),
        Ok(vec![CTAP2_OK])
    );
    assert_eq!(
        credential_management(
            &mut app,
            &token,
            0x06,
            Some(credential_id_params(&[0xB1], None))
        ),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
    assert_eq!(
        credential_management(
            &mut app,
            &token,
            0x06,
            Some(credential_id_params(&[0xA1], None))
        ),
        Ok(vec![CTAP2_OK])
    );
    let remaining: Vec<_> = stored(&app)
        .into_iter()
        .map(|credential| credential.rp_id.clone())
        .collect();
    assert_eq!(remaining, ["other.example"]);
}

/// A credential management request with only a subCommand, as platforms send
/// enumerateRPsGetNextRP and enumerateCredentialsGetNextCredential.
fn get_next(app: &mut TestApp, subcommand: u8) -> Result<Vec<u8>, u8> {
    let request = canonical_map(vec![(
        Value::Integer(Integer::from(1)),
        Value::Integer(Integer::from(subcommand)),
    )]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize request");
    app.handle_credential_management(&payload)
}

fn response_map(response: &[u8]) -> Vec<(Value, Value)> {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    map
}

fn response_bytes(response: &[u8], key: i64) -> Vec<u8> {
    response_map(response)
        .into_iter()
        .find_map(|(k, v)| match v {
            Value::Bytes(bytes) if k == Value::Integer(Integer::from(key)) => Some(bytes),
            _ => None,
        })
        .expect("byte string member present")
}

fn credential_id_of(response: &[u8]) -> Vec<u8> {
    response_map(response)
        .into_iter()
        .find_map(|(k, v)| match v {
            Value::Map(descriptor) if k == Value::Integer(Integer::from(7)) => {
                descriptor.into_iter().find_map(|(k, v)| match v {
                    Value::Bytes(id) if k == Value::Text("id".into()) => Some(id),
                    _ => None,
                })
            }
            _ => None,
        })
        .expect("credentialID present")
}

fn app_with_cm_token(aaguid: u8) -> (TestApp, TestStore, [u8; 32]) {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [aaguid; 16]);
    app.pin_state.set_pin(pin_hash(b"1234"));
    let token = [aaguid; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_CM,
        None,
    );
    (app, store, token)
}

/// "Platform sends authenticatorCredentialManagement command with following
/// parameters: subCommand (0x01): enumerateRPsGetNextRP (0x03)." (CTAP 2.3
/// §6.8.3), and likewise enumerateCredentialsGetNextCredential (§6.8.4):
/// no pinUvAuthParam, as libfido2 and `ssh-keygen -K` send them.
#[test]
fn get_next_subcommands_need_no_pin_uv_auth_param() {
    let (mut app, _, token) = app_with_cm_token(0x31);
    insert_owned(&mut app, es256_credential("a.example", &[0xA1]));
    insert_owned(&mut app, es256_credential("b.example", &[0xB1]));
    insert_owned(&mut app, es256_credential("b.example", &[0xB2]));

    let first = credential_management(&mut app, &token, 0x02, None).expect("enumerateRPsBegin");
    let next = get_next(&mut app, 0x03).expect("enumerateRPsGetNextRP");
    let mut hashes = vec![response_bytes(&first, 4), response_bytes(&next, 4)];
    hashes.sort();
    let mut expected = vec![
        CtapApp::cm_hash_rp_id("a.example"),
        CtapApp::cm_hash_rp_id("b.example"),
    ];
    expected.sort();
    assert_eq!(hashes, expected);

    let first = credential_management(&mut app, &token, 0x04, Some(rp_id_hash_params("b.example")))
        .expect("enumerateCredentialsBegin");
    let next = get_next(&mut app, 0x05).expect("enumerateCredentialsGetNextCredential");
    let mut ids = vec![credential_id_of(&first), credential_id_of(&next)];
    ids.sort();
    assert_eq!(ids, [vec![0xB1], vec![0xB2]]);

    // Both enumerations are exhausted.
    assert_eq!(get_next(&mut app, 0x03), Err(CTAP2_ERR_NOT_ALLOWED));
    assert_eq!(get_next(&mut app, 0x05), Err(CTAP2_ERR_NOT_ALLOWED));
}

#[test]
fn get_next_subcommands_without_an_enumeration_are_not_allowed() {
    let (mut app, _, _) = app_with_cm_token(0x32);
    insert_owned(&mut app, es256_credential("a.example", &[0xA1]));
    assert_eq!(get_next(&mut app, 0x03), Err(CTAP2_ERR_NOT_ALLOWED));
    assert_eq!(get_next(&mut app, 0x05), Err(CTAP2_ERR_NOT_ALLOWED));
}

/// "An authenticator MUST discard the state for a stateful command command
/// if the pinUvAuthToken that authenticated the state initializing command
/// expires" (CTAP 2.3 §6).
#[test]
fn enumerations_end_when_the_authenticating_token_expires() {
    let (mut app, _, token) = app_with_cm_token(0x33);
    let clock = ManualClock::default();
    app.pin_state.set_clock(Box::new(clock.clone()));
    let install = |app: &mut TestApp| {
        install_pin_uv_auth_token(app, ClassicPinProtocol::V2, token, PIN_PERMISSION_CM, None)
    };
    install(&mut app);
    insert_owned(&mut app, es256_credential("a.example", &[0xA1]));
    insert_owned(&mut app, es256_credential("a.example", &[0xA2]));
    insert_owned(&mut app, es256_credential("b.example", &[0xB1]));

    credential_management(&mut app, &token, 0x02, None).expect("enumerateRPsBegin");
    credential_management(&mut app, &token, 0x04, Some(rp_id_hash_params("a.example")))
        .expect("enumerateCredentialsBegin");
    clock.advance(MAX_USAGE_TIME_PERIOD);
    assert_eq!(get_next(&mut app, 0x03), Err(CTAP2_ERR_NOT_ALLOWED));
    assert_eq!(get_next(&mut app, 0x05), Err(CTAP2_ERR_NOT_ALLOWED));

    // A token issued since does not continue an enumeration begun with an
    // earlier one.
    install(&mut app);
    credential_management(&mut app, &token, 0x02, None).expect("enumerateRPsBegin");
    install(&mut app);
    assert_eq!(get_next(&mut app, 0x03), Err(CTAP2_ERR_NOT_ALLOWED));
}

/// A credential deleted between enumerateCredentialsBegin and
/// enumerateCredentialsGetNextCredential is skipped rather than indexed.
#[test]
fn credential_enumeration_survives_the_store_shrinking() {
    let (mut app, store, token) = app_with_cm_token(0x34);
    for id in [0xA1, 0xA2, 0xA3] {
        insert_owned(&mut app, es256_credential("a.example", &[id]));
    }
    let first = credential_management(&mut app, &token, 0x04, Some(rp_id_hash_params("a.example")))
        .expect("enumerateCredentialsBegin");
    let first_id = credential_id_of(&first);
    let mut other_process = store.clone();
    let deleted = [0xA1u8, 0xA2, 0xA3]
        .into_iter()
        .find(|id| first_id != [*id])
        .expect("another credential");
    CredentialStore::delete(&mut other_process, &[deleted]).expect("delete");

    let next = get_next(&mut app, 0x05).expect("the credential still stored");
    let next_id = credential_id_of(&next);
    assert_ne!(next_id, [deleted]);
    assert_ne!(next_id, first_id);
    assert_eq!(get_next(&mut app, 0x05), Err(CTAP2_ERR_NOT_ALLOWED));
}

/// "If the authenticator implements a command code having subcommands, but
/// does not implement an invoked subcommand, it MUST return
/// CTAP2_ERR_INVALID_SUBCOMMAND." (CTAP 2.3 §8.1)
#[test]
fn unknown_subcommands_are_invalid_subcommands() {
    let (mut app, _, token) = app_with_cm_token(0x35);
    for subcommand in [0x00, 0x08, 0x41, 0xFF] {
        assert_eq!(
            credential_management(&mut app, &token, subcommand, None),
            Err(CTAP2_ERR_INVALID_SUBCOMMAND),
            "subCommand {subcommand:#x}"
        );
    }
}

/// subCommandParams that are not in the CTAP2 canonical CBOR encoding form
/// are rejected like any other non-canonical request, even when the
/// pinUvAuthParam covers them exactly as encoded: "All decoders SHOULD reject
/// CBOR that is not validly encoded in the CTAP2 canonical CBOR encoding form"
/// (CTAP 2.3 §8).
#[test]
fn non_canonical_sub_command_params_are_rejected() {
    let (mut app, _, token) = app_with_cm_token(0x36);
    insert_owned(&mut app, es256_credential("a.example", &[0xA1]));

    // {1: rpIDHash}, with the key 1 encoded in two bytes (0x18 0x01).
    let rp_hash = CtapApp::cm_hash_rp_id("a.example");
    let mut params = vec![0xA1, 0x18, 0x01, 0x58, 0x20];
    params.extend_from_slice(&rp_hash);
    let mut message = vec![0x04];
    message.extend_from_slice(&params);
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &token, &message);

    // {1: 4, 2: params, 3: 2, 4: pinUvAuthParam}
    let mut payload = vec![0xA4, 0x01, 0x04, 0x02];
    payload.extend_from_slice(&params);
    payload.extend_from_slice(&[0x03, 0x02, 0x04, 0x58, 0x20]);
    payload.extend_from_slice(&pin_uv_auth_param);

    assert_eq!(
        app.handle_credential_management(&payload),
        Err(CTAP2_ERR_INVALID_CBOR)
    );
}

/// The examples of CTAP 2.3 §6.8.7.
#[test]
fn rp_ids_are_truncated_as_the_specification_shows() {
    for (input, stored) in [
        ("example.com", "example.com"),
        (
            "myfidousingwebsite.hostingprovider.net",
            "\u{2026}ngwebsite.hostingprovider.net",
        ),
        (
            "mygreatsite.hostingprovider.info",
            "mygreatsite.hostingprovider.info",
        ),
        (
            "otherprotocol://myfidousingwebsite.hostingprovider.net",
            "otherprotocol:\u{2026}ingprovider.net",
        ),
        (
            "veryexcessivelylargeprotocolname://example.com",
            "veryexcessivelylargeprotocolname",
        ),
    ] {
        assert_eq!(truncated_rp_id(input), stored, "{input}");
    }
}

/// enumerateRPsBegin returns the truncated RP ID with the hash of the full
/// one.
#[test]
fn enumerate_rps_returns_truncated_rp_ids() {
    let (mut app, _, token) = app_with_cm_token(0x37);
    let long_rp_id = format!("{}.example", "a".repeat(5000));
    insert_owned(&mut app, es256_credential(&long_rp_id, &[0xA1]));
    let response = credential_management(&mut app, &token, 0x02, None).expect("enumerateRPsBegin");
    assert_eq!(
        response_bytes(&response, 4),
        CtapApp::cm_hash_rp_id(&long_rp_id)
    );
    let rp = response_map(&response)
        .into_iter()
        .find_map(|(k, v)| (k == Value::Integer(Integer::from(3))).then_some(v))
        .expect("rp present");
    assert_eq!(
        rp,
        canonical_map(vec![(
            Value::Text("id".into()),
            Value::Text("\u{2026}aaaaaaaaaaaaaaaaaaaaa.example".into())
        )])
    );
}

/// Once the request is authenticated, a wrongly typed subcommand parameter
/// is CTAP2_ERR_CBOR_UNEXPECTED_TYPE (CTAP 2.3 §8).
#[test]
fn wrongly_typed_subcommand_parameters_are_unexpected_types() {
    let text = |value: &str| Value::Text(value.into());
    let descriptor =
        |id: Value| canonical_map(vec![(text("id"), id), (text("type"), text("public-key"))]);
    let cases = [
        (0x04, canonical_map(vec![(int(1), text("not a hash"))])),
        (
            0x06,
            canonical_map(vec![(int(2), Value::Bytes(vec![0xC1]))]),
        ),
        (0x06, canonical_map(vec![(int(2), descriptor(text("C1")))])),
        (
            0x07,
            canonical_map(vec![
                (int(2), descriptor(Value::Bytes(vec![0xC1]))),
                (int(3), Value::Bytes(vec![0x01])),
            ]),
        ),
        (
            0x07,
            canonical_map(vec![
                (int(2), descriptor(Value::Bytes(vec![0xC1]))),
                (int(3), canonical_map(vec![(text("id"), int(1))])),
            ]),
        ),
    ];
    let token = [0x6E; 32];
    for (subcommand, params) in cases {
        let mut app = new_app(TestStore::new(), [0x6E; 16]);
        install_pin_uv_auth_token(
            &mut app,
            ClassicPinProtocol::V2,
            token,
            PIN_PERMISSION_CM,
            None,
        );
        let param = cm_pin_param(&token, subcommand, Some(params.clone()));
        let request = canonical_map(vec![
            (int(1), int(subcommand.into())),
            (int(2), params.clone()),
            (int(3), int(2)),
            (int(4), Value::Bytes(param)),
        ]);
        assert_eq!(
            app.handle_credential_management(&encode(&request)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            "subcommand {subcommand:#04x}, {params:?}"
        );
    }
}
