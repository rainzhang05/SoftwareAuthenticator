//! Controlled stateful probes isolate metadata from unrelated command errors.
use super::*;
use pqkey_ctap::store::CredentialRecord;

const PIN: &[u8] = b"1234";
const RP: &str = "key-agreement.example";

fn session(engine: &mut Engine, protocol: ClassicPinProtocol) -> Session {
    let response = engine.call(&command(
        CTAP_CMD_CLIENT_PIN,
        &Value::Map(vec![(int(1), protocol_value(protocol)), (int(2), int(2))]),
    ));
    Session::establish(protocol, &response, [0x13; 32])
        .expect("standard response metadata and point")
}

fn pin_request(
    session: &Session,
    protocol: ClassicPinProtocol,
    consumer: u8,
    key: Value,
    wrong: bool,
) -> Vec<u8> {
    let sub = match consumer {
        0 => 3,
        1 => 4,
        2 => 5,
        _ => 9,
    };
    let mut fields = vec![
        (int(1), protocol_value(protocol)),
        (int(2), int(sub)),
        (int(3), key),
    ];
    let mut authenticated = Vec::new();
    if consumer <= 1 {
        let mut padded = b"5678".to_vec();
        padded.resize(64, 0);
        let encrypted = session.encrypt(&padded, [0x31; 16]);
        authenticated.extend_from_slice(&encrypted);
        fields.push((int(5), bytes(&encrypted)));
    }
    if consumer != 0 {
        let encrypted = session.encrypt(&pin_hash(if wrong { b"wrong" } else { PIN }), [0x32; 16]);
        authenticated.extend_from_slice(&encrypted);
        fields.push((int(6), bytes(&encrypted)));
    }
    if consumer <= 1 {
        fields.push((int(4), bytes(&session.authenticate(&authenticated))));
    }
    if consumer >= 3 {
        fields.push((int(9), int(if consumer == 4 { 0x40 } else { 4 })));
    }
    command(CTAP_CMD_CLIENT_PIN, &Value::Map(fields))
}

fn credential_request(extension: Value, resident: bool) -> Vec<u8> {
    command(
        CTAP_CMD_MAKE_CREDENTIAL,
        &Value::Map(vec![
            (int(1), bytes(&[0x44; 32])),
            (int(2), Value::Map(vec![(text("id"), text(RP))])),
            (int(3), Value::Map(vec![(text("id"), bytes(&[1]))])),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("type"), text("public-key")),
                    (text("alg"), int(-7)),
                ])]),
            ),
            (int(6), extension),
            (
                int(7),
                Value::Map(vec![(text("rk"), Value::Bool(resident))]),
            ),
        ]),
    )
}

fn manage(engine: &mut Engine, protocol: ClassicPinProtocol, token: &[u8]) -> u8 {
    engine.call(&command(
        CTAP_CMD_CREDENTIAL_MANAGEMENT,
        &Value::Map(vec![
            (int(1), int(1)),
            (int(3), protocol_value(protocol)),
            (int(4), bytes(&authenticate(protocol, token, &[1]))),
        ]),
    ))[0]
}

fn unchanged_credentials(engine: &Engine, before: &[CredentialRecord]) {
    assert!(
        engine.credentials() == before,
        "metadata rejection changed credentials/counters"
    );
}

pub(super) fn probe(v2: bool, consumer: u8, case: u8, wrong: bool) -> Vec<(u8, u16)> {
    let protocol = protocol(v2);
    let consumer = consumer % 7;
    let mut engine = Engine::new(0x5eed);
    assert_eq!(
        engine.call(&credential_request(
            Value::Map(vec![(text("hmac-secret"), Value::Bool(true))]),
            true
        ))[0],
        CTAP2_OK
    );
    if consumer != 0 {
        let setup = session(&mut engine, protocol);
        // Use the same PIN in every controlled fixture.
        let mut padded = PIN.to_vec();
        padded.resize(64, 0);
        let encrypted = setup.encrypt(&padded, [0x31; 16]);
        assert_eq!(
            engine.call(&command(
                CTAP_CMD_CLIENT_PIN,
                &Value::Map(vec![
                    (int(1), protocol_value(protocol)),
                    (int(2), int(3)),
                    (int(3), setup.key_agreement.clone()),
                    (int(4), bytes(&setup.authenticate(&encrypted))),
                    (int(5), bytes(&encrypted))
                ])
            )),
            [CTAP2_OK]
        );
    }
    let mut retained = Vec::new();
    if consumer != 0 {
        for (selected, kind) in [
            (ClassicPinProtocol::V1, 4),
            (ClassicPinProtocol::V2, 4),
            (protocol, 3),
        ] {
            let exchange = session(&mut engine, selected);
            let response = engine.call(&pin_request(
                &exchange,
                selected,
                kind,
                exchange.key_agreement.clone(),
                false,
            ));
            assert_eq!(response[0], CTAP2_OK);
            let map = decode_map(&response[1..]).unwrap();
            let encrypted = get_int(&map, 2).unwrap().as_bytes().unwrap();
            assert_eq!(
                encrypted.len(),
                if selected == ClassicPinProtocol::V1 {
                    32
                } else {
                    48
                }
            );
            let token = exchange.decrypt(encrypted).unwrap();
            assert_eq!(token.len(), 32);
            retained.push((selected, token));
        }
    }
    let exchange = session(&mut engine, protocol);
    let (key, accepted) = crate::key_agreement::mutate(exchange.key_agreement.clone(), case);
    let request = if consumer < 5 {
        pin_request(&exchange, protocol, consumer, key, wrong)
    } else {
        let encrypted = exchange.encrypt(&[0x98; 32], [0x33; 16]);
        let mac = exchange.authenticate(&encrypted);
        assert_eq!(mac.len(), if v2 { 32 } else { 16 });
        let input = Value::Map(vec![
            (int(1), key),
            (int(2), bytes(&encrypted)),
            (int(3), bytes(&mac)),
            (int(4), protocol_value(protocol)),
        ]);
        if consumer == 5 {
            command(
                CTAP_CMD_GET_ASSERTION,
                &Value::Map(vec![
                    (int(1), text(RP)),
                    (int(2), bytes(&[0x44; 32])),
                    (int(4), Value::Map(vec![(text("hmac-secret"), input)])),
                ]),
            )
        } else {
            credential_request(
                Value::Map(vec![
                    (text("hmac-secret"), Value::Bool(true)),
                    (text("hmac-secret-mc"), input),
                ]),
                false,
            )
        }
    };
    let before = engine.pin_record();
    let credentials = engine.credentials();
    let counter = engine.signature_counter();
    engine.take_pin_writes();
    let response = engine.call(&request);
    if !accepted {
        assert_eq!(response, [CTAP1_ERR_INVALID_PARAMETER]);
        assert!(
            engine.take_pin_writes().is_empty(),
            "retry debit or publication after metadata failure"
        );
        assert_eq!(engine.pin_record(), before);
        unchanged_credentials(&engine, &credentials);
        assert_eq!(engine.signature_counter(), counter);
        // Earlier presence can consume the transient grant for hmac extensions.
        for (index, (selected, token)) in retained.iter().enumerate() {
            assert_eq!(
                manage(&mut engine, *selected, token),
                if index == 2 && consumer >= 5 {
                    CTAP2_ERR_PIN_AUTH_INVALID
                } else {
                    CTAP2_OK
                }
            );
        }
        engine.restart();
        assert_eq!(engine.pin_record(), before);
        unchanged_credentials(&engine, &credentials);
    } else if wrong && (1..5).contains(&consumer) {
        assert_eq!(response, [CTAP2_ERR_PIN_INVALID]);
        assert_eq!(
            engine.pin_record().unwrap().pin_retries,
            before.unwrap().pin_retries - 1
        );
    } else {
        assert_eq!(response[0], CTAP2_OK);
        if (2..5).contains(&consumer) {
            let map = decode_map(&response[1..]).unwrap();
            let encrypted = get_int(&map, 2).unwrap().as_bytes().unwrap();
            assert_eq!(encrypted.len(), if v2 { 48 } else { 32 });
            assert_eq!(exchange.decrypt(encrypted).unwrap().len(), 32);
        } else if consumer >= 5 {
            let map = decode_map(&response[1..]).unwrap();
            let data = get_int(&map, 2).unwrap().as_bytes().unwrap();
            let offset = if consumer == 5 {
                37
            } else {
                let start = 55 + usize::from(u16::from_be_bytes([data[53], data[54]]));
                let mut cursor = std::io::Cursor::new(&data[start..]);
                let _: Value = ciborium::de::from_reader(&mut cursor).unwrap();
                start + usize::try_from(cursor.position()).unwrap()
            };
            let extensions = decode_map(&data[offset..]).unwrap();
            let encrypted = get_text(
                &extensions,
                if consumer == 5 {
                    "hmac-secret"
                } else {
                    "hmac-secret-mc"
                },
            )
            .unwrap()
            .as_bytes()
            .unwrap();
            assert_eq!(encrypted.len(), if v2 { 48 } else { 32 });
            assert_eq!(exchange.decrypt(encrypted).unwrap().len(), 32);
        }
    }
    engine.take_trace()
}
