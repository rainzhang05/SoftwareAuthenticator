//! User-presence tests: waiting, denial, cancellation and the keepalive log.

use super::support::TestClient;
use crate::ctap::cbor::canonical_map;
use crate::ctap::CtapApp;
use crate::CoseAlg;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use serial_test::serial;
use trussed::types::consent;

use transport_core::ctap::constants::*;

#[test]
#[serial]
fn make_credential_waits_for_user_presence() {
    let mut app = CtapApp::new(TestClient::new(), [0x21; 16]);
    app.client.set_presence_responses(vec![
        Err(consent::Error::TimedOut),
        Err(consent::Error::TimedOut),
        Ok::<(), consent::Error>(()),
    ]);
    super::take_waiting_log();

    let client_hash = vec![0x20; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert_eq!(auth_data[32] & 0x01, 0x01);
}

#[test]
#[serial]
fn make_credential_returns_not_allowed_when_presence_denied() {
    let mut app = CtapApp::new(TestClient::new(), [0x22; 16]);
    let attempts =
        (super::USER_PRESENCE_MAX_WAIT_MS / super::USER_PRESENCE_POLL_TIMEOUT_MS) as usize;
    app.client.set_presence_responses(
        std::iter::repeat(Err(consent::Error::TimedOut))
            .take(attempts)
            .collect::<Vec<_>>(),
    );
    super::take_waiting_log();

    let client_hash = vec![0x30; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x02]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let result = app.handle_make_credential(&payload);
    assert_eq!(result, Err(CTAP2_ERR_NOT_ALLOWED));
    assert!(app.stored_credentials.is_empty());
    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));
}

#[test]
#[serial]
fn make_credential_returns_keepalive_cancel_when_cancelled() {
    let mut app = CtapApp::new(TestClient::new(), [0x23; 16]);
    app.client
        .set_presence_responses(vec![Err(consent::Error::Interrupted)]);
    super::take_waiting_log();

    let client_hash = vec![0x40; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x03]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let result = app.handle_make_credential(&payload);
    assert_eq!(result, Err(CTAP2_ERR_KEEPALIVE_CANCEL));
    assert!(app.stored_credentials.is_empty());
    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));
}

#[test]
#[serial]
fn make_credential_recovers_after_cancellation() {
    let mut app = CtapApp::new(TestClient::new(), [0x25; 16]);
    app.client
        .set_presence_responses(vec![Err(consent::Error::Interrupted)]);
    super::take_waiting_log();

    let client_hash = vec![0x41; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x03]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let result = app.handle_make_credential(&payload);
    assert_eq!(result, Err(CTAP2_ERR_KEEPALIVE_CANCEL));
    assert!(app.stored_credentials.is_empty());
    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));

    app.client
        .set_presence_responses(vec![Ok::<(), consent::Error>(())]);
    super::take_waiting_log();

    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds after cancellation");
    assert_eq!(response[0], CTAP2_OK);
    assert_eq!(app.stored_credentials.len(), 1);
    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));
}

#[test]
#[serial]
fn get_assertion_waits_for_user_presence() {
    let mut app = CtapApp::new(TestClient::new(), [0x24; 16]);
    app.client
        .set_presence_responses(vec![Ok::<(), consent::Error>(())]);

    let make_client_hash = vec![0x50; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x11]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let make_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(make_client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_request, &mut payload).expect("serialize makeCredential request");
    app.handle_make_credential(&payload)
        .expect("makeCredential succeeds");

    let credential_id = app.stored_credentials[0].credential_id.clone();
    super::take_waiting_log();

    app.client.set_presence_responses(vec![
        Err(consent::Error::TimedOut),
        Ok::<(), consent::Error>(()),
    ]);

    let allow_list = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.clone()),
        ),
    ])]);
    let get_client_hash = vec![0x51; 32];
    let get_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text("example.com".into()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(get_client_hash.clone()),
        ),
        (Value::Integer(Integer::from(3)), allow_list),
    ]);

    let mut payload = Vec::new();
    into_writer(&get_request, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");

    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert_eq!(auth_data[32] & 0x01, 0x01);
}

#[test]
#[serial]
fn get_assertion_returns_not_allowed_when_presence_denied() {
    let mut app = CtapApp::new(TestClient::new(), [0x25; 16]);
    app.client
        .set_presence_responses(vec![Ok::<(), consent::Error>(())]);

    let make_client_hash = vec![0x60; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x21]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let make_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(make_client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_request, &mut payload).expect("serialize makeCredential request");
    app.handle_make_credential(&payload)
        .expect("makeCredential succeeds");

    let credential_id = app.stored_credentials[0].credential_id.clone();
    super::take_waiting_log();

    let attempts =
        (super::USER_PRESENCE_MAX_WAIT_MS / super::USER_PRESENCE_POLL_TIMEOUT_MS) as usize;
    app.client.set_presence_responses(
        std::iter::repeat(Err(consent::Error::TimedOut))
            .take(attempts)
            .collect::<Vec<_>>(),
    );

    let allow_list = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.clone()),
        ),
    ])]);
    let get_client_hash = vec![0x61; 32];
    let get_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text("example.com".into()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(get_client_hash.clone()),
        ),
        (Value::Integer(Integer::from(3)), allow_list),
    ]);

    let mut payload = Vec::new();
    into_writer(&get_request, &mut payload).expect("serialize getAssertion request");
    let result = app.handle_get_assertion(&payload);
    assert_eq!(result, Err(CTAP2_ERR_NOT_ALLOWED));
    let log = super::take_waiting_log();
    assert!(!log.is_empty(), "waiting log must record activity");
    assert_eq!(log.last(), Some(&false));
    assert!(log.windows(2).any(|pair| pair == [true, false]));
}
