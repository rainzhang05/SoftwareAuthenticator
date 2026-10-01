//! The platform side of the PIN/UV auth protocols (`pqkey_ctap::platform`)
//! against the engine, through `CtapApp::call` as a client would: set a PIN,
//! get a pinUvAuthToken with the cm permission, and use it for credential
//! management, with both protocols.

use ciborium::value::{Integer, Value};
use pqkey_ctap::ClassicPinProtocol;
use pqkey_ctap::ctap::presence::AutoApprove;
use pqkey_ctap::ctap::{CtapApp, InterruptFlag};
use pqkey_ctap::platform::{PlatformKeyAgreement, authenticate, padded_pin, pin_hash};
use pqkey_ctap::store::MemoryStore;

static INTERRUPT: InterruptFlag = InterruptFlag::new();

const CLIENT_PIN: u8 = 0x06;
const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
const PERMISSION_CM: i64 = 0x04;

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn call(app: &mut CtapApp<'static>, command: u8, entries: Vec<(Value, Value)>) -> (u8, Value) {
    let mut request = vec![command];
    ciborium::ser::into_writer(&Value::Map(entries), &mut request).expect("encode");
    let response = app.call(&request);
    let body = if response.len() > 1 {
        ciborium::de::from_reader(&response[1..]).expect("decode")
    } else {
        Value::Null
    };
    (response[0], body)
}

fn member(map: &Value, key: i64) -> &Value {
    let Value::Map(entries) = map else {
        panic!("not a map: {map:?}");
    };
    &entries
        .iter()
        .find(|(k, _)| *k == int(key))
        .unwrap_or_else(|| panic!("no member {key} in {map:?}"))
        .1
}

fn bytes(value: &Value) -> &[u8] {
    match value {
        Value::Bytes(bytes) => bytes,
        other => panic!("not bytes: {other:?}"),
    }
}

/// getKeyAgreement, and a shared secret with the authenticator's key.
fn key_agreement(app: &mut CtapApp<'static>, protocol: ClassicPinProtocol) -> PlatformKeyAgreement {
    let id = i64::from(protocol.identifier());
    let (status, body) = call(app, CLIENT_PIN, vec![(int(1), int(id)), (int(2), int(2))]);
    assert_eq!(status, 0);
    let key = member(&body, 1);
    let x: [u8; 32] = bytes(member(key, -2)).try_into().unwrap();
    let y: [u8; 32] = bytes(member(key, -3)).try_into().unwrap();
    let secret = PlatformKeyAgreement::generate_key().unwrap();
    PlatformKeyAgreement::new(protocol, &x, &y, &secret).unwrap()
}

fn cose_key(shared: &PlatformKeyAgreement) -> Value {
    let (x, y) = shared.public_key();
    Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-25)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(x.to_vec())),
        (int(-3), Value::Bytes(y.to_vec())),
    ])
}

#[test]
fn a_platform_sets_a_pin_and_manages_credentials_with_a_token() {
    for protocol in [ClassicPinProtocol::V2, ClassicPinProtocol::V1] {
        let id = i64::from(protocol.identifier());
        let mut app = CtapApp::new(
            MemoryStore::new(),
            rand_core::UnwrapErr(getrandom::SysRng),
            AutoApprove,
            &INTERRUPT,
            [0; 16],
        );

        // setPIN (CTAP 2.3 §6.5.5.5).
        let shared = key_agreement(&mut app, protocol);
        let new_pin_enc = shared
            .encrypt(&padded_pin(b"1234").unwrap()[..], [0x11; 16])
            .unwrap();
        let (status, _) = call(
            &mut app,
            CLIENT_PIN,
            vec![
                (int(1), int(id)),
                (int(2), int(3)),
                (int(3), cose_key(&shared)),
                (int(4), Value::Bytes(shared.authenticate(&new_pin_enc))),
                (int(5), Value::Bytes(new_pin_enc)),
            ],
        );
        assert_eq!(status, 0, "setPIN with {protocol:?}");

        // getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2), cm.
        let shared = key_agreement(&mut app, protocol);
        let pin_hash_enc = shared.encrypt(&pin_hash(b"1234")[..], [0x22; 16]).unwrap();
        let (status, body) = call(
            &mut app,
            CLIENT_PIN,
            vec![
                (int(1), int(id)),
                (int(2), int(9)),
                (int(3), cose_key(&shared)),
                (int(6), Value::Bytes(pin_hash_enc)),
                (int(9), int(PERMISSION_CM)),
            ],
        );
        assert_eq!(status, 0, "getPinUvAuthToken with {protocol:?}");
        let token = shared.decrypt(bytes(member(&body, 2))).unwrap();

        // getCredsMetadata (§6.8.2) authenticated with the token.
        let (status, body) = call(
            &mut app,
            CREDENTIAL_MANAGEMENT,
            vec![
                (int(1), int(1)),
                (int(3), int(id)),
                (
                    int(4),
                    Value::Bytes(authenticate(protocol, &token, &[0x01])),
                ),
            ],
        );
        assert_eq!(status, 0, "getCredsMetadata with {protocol:?}");
        assert_eq!(*member(&body, 1), int(0));
    }
}
