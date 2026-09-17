//! attestationFormatsPreference, and responses that must fit the transport
//! (CTAP 2.3 §6.1.2 steps 18 and 19, §11.2.4).

use super::dispatch::call;
use super::support::{
    classic_pin_auth, encode, install_pin_uv_auth_token, int, test_app, token_pin_auth,
    PlatformPinSession, TestApp,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::AttestationMode;
use crate::store::AttestationRecord;
use crate::{ClassicPinProtocol, CoseAlg};

use ciborium::{de::from_reader, value::Value};

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn member(response: &[u8], key: i64) -> Value {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    map.into_iter()
        .find_map(|(k, v)| (k == int(key)).then_some(v))
        .unwrap_or_else(|| panic!("member {key} present"))
}

fn att_stmt_keys(response: &[u8]) -> Vec<Value> {
    match member(response, 3) {
        Value::Map(entries) => entries.into_iter().map(|(key, _)| key).collect(),
        other => panic!("attStmt must be a map, not {other:?}"),
    }
}

/// A makeCredential request with the largest user handle, both extensions
/// this authenticator supports, and `extra` parameters.
fn make_credential(alg: CoseAlg, user_id: u8, extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (int(1), Value::Bytes(vec![0x44; 32])),
        (int(2), canonical_map(vec![(text("id"), text(RP_ID))])),
        (
            int(3),
            canonical_map(vec![
                (text("id"), Value::Bytes(vec![user_id; 64])),
                (text("name"), text(&"n".repeat(64))),
                (text("displayName"), text(&"d".repeat(64))),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), int(alg as i64)),
            ])]),
        ),
        (
            int(6),
            canonical_map(vec![
                (text("hmac-secret"), Value::Bool(true)),
                (text("credProtect"), int(1)),
            ]),
        ),
    ];
    entries.extend(extra);
    let mut request = vec![CTAP_CMD_MAKE_CREDENTIAL];
    request.extend(encode(&canonical_map(entries)));
    request
}

fn preference(formats: &[&str]) -> (Value, Value) {
    (
        int(0x0B),
        Value::Array(formats.iter().map(|format| text(format)).collect()),
    )
}

/// "If attestationFormatsPreference is present and contains only one entry
/// with the value "none", omit attestation from the output." (CTAP 2.3
/// §6.1.2 step 18)  Any other preference gets the authenticator's one other
/// format, "packed".
#[test]
fn attestation_formats_preference_none_omits_attestation() {
    for (formats, expected) in [
        (vec!["none"], "none"),
        (vec!["packed"], "packed"),
        (vec!["none", "packed"], "packed"),
        (vec!["tpm"], "packed"),
        (vec![], "packed"),
    ] {
        let mut app = test_app([0x81; 16]);
        let response = call(
            &mut app,
            &make_credential(CoseAlg::ES256, 1, vec![preference(&formats)]),
        );
        assert_eq!(member(&response, 1), text(expected), "{formats:?}");
        if expected == "none" {
            assert!(att_stmt_keys(&response).is_empty());
        }
    }

    let mut app = test_app([0x81; 16]);
    let mut request = make_credential(CoseAlg::ES256, 1, vec![(int(0x0B), text("none"))]);
    assert_eq!(call(&mut app, &request), [CTAP2_ERR_CBOR_UNEXPECTED_TYPE]);
    request = make_credential(
        CoseAlg::ES256,
        1,
        vec![(int(0x0B), Value::Array(vec![int(1)]))],
    );
    assert_eq!(call(&mut app, &request), [CTAP2_ERR_CBOR_UNEXPECTED_TYPE]);
}

/// The largest makeCredential response, ML-DSA-87 with self attestation, the
/// longest user handle and both extensions, fits a CTAPHID message.
#[test]
fn the_largest_make_credential_response_fits() {
    let mut app = test_app([0x82; 16]);
    let response = call(
        &mut app,
        &make_credential(
            CoseAlg::MLDSA87,
            1,
            vec![(int(7), canonical_map(vec![(text("rk"), Value::Bool(true))]))],
        ),
    );
    assert_eq!(member(&response, 1), text("packed"));
    assert!(att_stmt_keys(&response).contains(&text("sig")));
    assert!(
        response.len() <= MAX_RESPONSE_SIZE,
        "{} bytes",
        response.len()
    );
}

/// An attestation certificate chain too long for the response gives way to
/// self attestation, and when that does not fit either, to "none".
#[test]
fn attestation_that_would_not_fit_gives_way() {
    let attestation = |certificate_length| AttestationRecord {
        private_key: [0x11; 32],
        certificate_chain: vec![vec![0x30; certificate_length]],
    };

    // 5,000 bytes of certificate fit next to an ES256 credential but not an
    // ML-DSA-87 one; ML-DSA-87 self attestation does fit.
    for (alg, has_x5c) in [(CoseAlg::ES256, true), (CoseAlg::MLDSA87, false)] {
        let mut app = test_app([0x83; 16]);
        app.set_attestation_mode(AttestationMode::Certificate);
        app.store
            .set_attestation(&attestation(5000))
            .expect("store attestation");
        let response = call(&mut app, &make_credential(alg, 1, vec![]));
        assert_eq!(member(&response, 1), text("packed"), "{alg:?}");
        assert_eq!(
            att_stmt_keys(&response).contains(&text("x5c")),
            has_x5c,
            "{alg:?}"
        );
        assert!(response.len() <= MAX_RESPONSE_SIZE);
    }
}

/// The largest getAssertion response: an ML-DSA-87 signature, user
/// verification (so the user's name and display name are returned), two
/// hmac-secret salts under PIN/UV auth protocol two, and numberOfCredentials.
#[test]
fn the_largest_get_assertion_response_fits() {
    let mut app: TestApp = test_app([0x84; 16]);
    let token = [0x84; 32];
    for user_id in [1, 2] {
        install_pin_uv_auth_token(
            &mut app,
            ClassicPinProtocol::V2,
            token,
            PIN_PERMISSION_MC,
            None,
        );
        let param = token_pin_auth(ClassicPinProtocol::V2, &token, &[0x44; 32]);
        let response = call(
            &mut app,
            &make_credential(
                CoseAlg::MLDSA87,
                user_id,
                vec![
                    (int(7), canonical_map(vec![(text("rk"), Value::Bool(true))])),
                    (int(8), Value::Bytes(param)),
                    (int(9), int(2)),
                ],
            ),
        );
        assert_eq!(response[0], CTAP2_OK);
    }

    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_GA,
        None,
    );
    let session = PlatformPinSession::establish(&mut app, ClassicPinProtocol::V2, 0x84);
    let salt_enc = session.encrypt(&[0x55; 64]);
    let salt_auth = classic_pin_auth(ClassicPinProtocol::V2, &session.keys, &salt_enc);
    let client_data_hash = [0x66; 32];
    let request = canonical_map(vec![
        (int(1), text(RP_ID)),
        (int(2), Value::Bytes(client_data_hash.to_vec())),
        (
            int(4),
            canonical_map(vec![(
                text("hmac-secret"),
                canonical_map(vec![
                    (int(1), session.key_agreement.clone()),
                    (int(2), Value::Bytes(salt_enc)),
                    (int(3), Value::Bytes(salt_auth)),
                    (int(4), int(2)),
                ]),
            )]),
        ),
        (
            int(6),
            Value::Bytes(token_pin_auth(
                ClassicPinProtocol::V2,
                &token,
                &client_data_hash,
            )),
        ),
        (int(7), int(2)),
    ]);
    let mut payload = vec![CTAP_CMD_GET_ASSERTION];
    payload.extend(encode(&request));
    let response = call(&mut app, &payload);
    assert_eq!(member(&response, 5), int(2), "numberOfCredentials");
    let Value::Map(user) = member(&response, 4) else {
        panic!("user must be a map");
    };
    assert_eq!(user.len(), 3, "id, name and displayName");
    assert!(
        response.len() <= MAX_RESPONSE_SIZE,
        "{} bytes",
        response.len()
    );

    let next = call(&mut app, &[CTAP_CMD_GET_NEXT_ASSERTION]);
    assert_eq!(next[0], CTAP2_OK);
    assert!(next.len() <= MAX_RESPONSE_SIZE);
}
