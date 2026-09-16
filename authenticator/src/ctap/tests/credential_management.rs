//! authenticatorCredentialManagement tests.

use super::support::{
    es256_credential, get_pin_uv_auth_token, install_pin_uv_auth_token, pin_hash, token_pin_auth,
    TestClient,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA};
use crate::ctap::pin::protocol::PIN_UV_AUTH_PROTOCOL_CLASSIC;
use crate::ctap::storage::StoredCredential;
use crate::ctap::CtapApp;
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
    let mut app = CtapApp::new(TestClient::new(), [0x24; 16]);
    let token = [0x90; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_CM,
        None,
    );

    app.stored_credentials.push(StoredCredential {
        rp_id: "example.com".into(),
        user_id: vec![0x01],
        user_name: Some("one".into()),
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA1],
        public_key: vec![0x11, 0x22],
        secret_key: vec![0x33; 32],
        cred_random_with_uv: Some(vec![0x44; 32]),
        cred_random_without_uv: Some(vec![0x45; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });
    app.stored_credentials.push(StoredCredential {
        rp_id: "example.com".into(),
        user_id: vec![0x02],
        user_name: Some("two".into()),
        user_display_name: None,
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xA2],
        public_key: vec![0x12, 0x23],
        secret_key: vec![0x34; 32],
        cred_random_with_uv: Some(vec![0x46; 32]),
        cred_random_without_uv: Some(vec![0x47; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    });
    app.stored_credentials.push(StoredCredential {
        rp_id: "second.example".into(),
        user_id: vec![0x03],
        user_name: Some("three".into()),
        user_display_name: Some("Three".into()),
        alg: CoseAlg::MLDSA44 as i32,
        credential_id: vec![0xB1],
        public_key: vec![0x21, 0x32],
        secret_key: vec![0x35; 32],
        cred_random_with_uv: Some(vec![0x48; 32]),
        cred_random_without_uv: Some(vec![0x49; 32]),
        cred_protect: Some(2),
        sign_count: 0,
    });

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
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("existing count");
    assert_eq!(existing, 3);

    let rp_hash = CtapApp::<TestClient>::cm_hash_rp_id("example.com");
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
            && *v == Value::Bytes(CtapApp::<TestClient>::cm_hash_rp_id("second.example"))
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
            Value::Integer(int) => Some(int.clone().into()),
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
    assert!(map
        .iter()
        .any(|(k, v)| *k == Value::Integer(Integer::from(7)) && matches!(v, Value::Map(_))));

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
    assert_eq!(app.stored_credentials.len(), 2);

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
    let updated = app
        .stored_credentials
        .iter()
        .find(|cred| cred.credential_id == vec![0xA2])
        .expect("credential remains");
    assert_eq!(updated.user_name.as_deref(), Some("updated"));
}

#[test]
fn credential_management_requires_cm_permission() {
    let mut app = CtapApp::new(TestClient::new(), [0x25; 16]);
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
    let mut app = CtapApp::new(TestClient::new(), [0x26; 16]);
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
    app: &mut CtapApp<TestClient>,
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
        Value::Bytes(CtapApp::<TestClient>::cm_hash_rp_id(rp_id)),
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
    let mut app = CtapApp::new(TestClient::new(), [0x27; 16]);
    app.pin_state.set_pin(pin_hash(b"1234"));
    app.stored_credentials
        .push(es256_credential("example.com", &[0xA1]));
    app.stored_credentials
        .push(es256_credential("other.example", &[0xB1]));
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
    let remaining: Vec<_> = app
        .stored_credentials
        .iter()
        .map(|credential| credential.rp_id.as_str())
        .collect();
    assert_eq!(remaining, ["other.example"]);
}
