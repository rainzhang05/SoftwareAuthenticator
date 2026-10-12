//! Export signed CTAP responses for libfido2 compatibility verification without HID.
//! Run with `cargo run --locked -p pqkey-ctap --example payment_compatibility`.

use ciborium::value::Value;
use pqkey_ctap::ctap::{CtapApp, InterruptFlag, presence::AutoApprove};
use pqkey_ctap::store::MemoryStore;

fn int(v: i32) -> Value {
    Value::Integer(v.into())
}
fn text(v: &str) -> Value {
    Value::Text(v.into())
}
fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}
fn get(v: &Value, key: Value) -> &Value {
    v.as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap()
}
fn call(app: &mut CtapApp<'_>, cmd: u8, v: Value) -> Value {
    let mut request = vec![cmd];
    ciborium::ser::into_writer(&v, &mut request).unwrap();
    let response = app.call(&request);
    assert_eq!(response[0], 0);
    ciborium::de::from_reader(&response[1..]).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let interrupt = InterruptFlag::new();
    for enabled in [false, true] {
        for rk in [false, true] {
            let mut app = CtapApp::new(
                MemoryStore::new(),
                rand_core::UnwrapErr(getrandom::SysRng),
                AutoApprove,
                &interrupt,
                [0; 16],
            );
            let hash = [0x44; 32];
            let registration = call(
                &mut app,
                1,
                map(vec![
                    (int(1), Value::Bytes(hash.to_vec())),
                    (
                        int(2),
                        map(vec![(text("id"), text("third-party-payment.e2e.example"))]),
                    ),
                    (int(3), map(vec![(text("id"), Value::Bytes(vec![1]))])),
                    (
                        int(4),
                        Value::Array(vec![map(vec![
                            (text("type"), text("public-key")),
                            (text("alg"), int(-7)),
                        ])]),
                    ),
                    (
                        int(6),
                        map(vec![(text("thirdPartyPayment"), Value::Bool(enabled))]),
                    ),
                    (int(7), map(vec![(text("rk"), Value::Bool(rk))])),
                ]),
            );
            let data = get(&registration, int(2)).as_bytes().unwrap();
            let length = usize::from(u16::from_be_bytes([data[53], data[54]]));
            let id = &data[55..55 + length];
            assert_eq!(length, if rk || enabled { 33 } else { 107 });
            let public: Value = ciborium::de::from_reader(&data[55 + length..]).unwrap();
            let coordinates = [
                get(&public, int(-2)).as_bytes().unwrap().as_slice(),
                get(&public, int(-3)).as_bytes().unwrap().as_slice(),
            ]
            .concat();
            for requested in [None, Some(false), Some(true)] {
                let mut entries = vec![
                    (int(1), text("third-party-payment.e2e.example")),
                    (int(2), Value::Bytes(hash.to_vec())),
                    (
                        int(3),
                        Value::Array(vec![map(vec![
                            (text("type"), text("public-key")),
                            (text("id"), Value::Bytes(id.to_vec())),
                        ])]),
                    ),
                ];
                if let Some(requested) = requested {
                    entries.push((
                        int(4),
                        map(vec![(text("thirdPartyPayment"), Value::Bool(requested))]),
                    ));
                }
                let assertion = call(&mut app, 2, map(entries));
                let auth = get(&assertion, int(2)).as_bytes().unwrap();
                let sig = get(&assertion, int(3)).as_bytes().unwrap();
                let requested = match requested {
                    None => "absent",
                    Some(false) => "false",
                    Some(true) => "true",
                };
                println!(
                    "{} {} {requested} {} {} {} {}",
                    enabled,
                    rk,
                    hex(&hash),
                    hex(&coordinates),
                    hex(auth),
                    hex(sig)
                );
            }
        }
    }
}
