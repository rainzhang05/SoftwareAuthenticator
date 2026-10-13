//! Export real Brainpool CTAP responses for independent Python/OpenSSL verification.
use ciborium::value::Value;
use pqkey_ctap::{
    CoseAlg,
    ctap::{CtapApp, InterruptFlag, presence::AutoApprove},
    store::MemoryStore,
};
fn int(v: i32) -> Value {
    Value::Integer(v.into())
}
fn text(v: &str) -> Value {
    Value::Text(v.into())
}
fn map(mut entries: Vec<(Value, Value)>) -> Value {
    entries.sort_by_cached_key(|(key, _)| {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(key, &mut encoded).unwrap();
        (encoded[0] >> 5, encoded.len(), encoded)
    });
    Value::Map(entries)
}
fn get(v: &Value, k: i32) -> &Value {
    &v.as_map()
        .unwrap()
        .iter()
        .find(|(key, _)| *key == int(k))
        .unwrap()
        .1
}
fn call(app: &mut CtapApp<'_>, cmd: u8, v: Value) -> Vec<u8> {
    let mut request = vec![cmd];
    ciborium::ser::into_writer(&v, &mut request).unwrap();
    let response = app.call(&request);
    assert_eq!(response[0], 0);
    response
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let interrupt = InterruptFlag::new();
    for alg in [CoseAlg::ESB256, CoseAlg::ESB384] {
        for rk in [false, true] {
            for payment in [false, true] {
                let mut app = CtapApp::new(
                    MemoryStore::new(),
                    rand_core::UnwrapErr(getrandom::SysRng),
                    AutoApprove,
                    &interrupt,
                    [0; 16],
                );
                let hash = [0x44; 32];
                let mut extensions = vec![
                    (text("thirdPartyPayment"), Value::Bool(payment)),
                    (text("credBlob"), Value::Bytes(b"brainpool".to_vec())),
                    (text("hmac-secret"), Value::Bool(true)),
                ];
                if rk {
                    extensions.push((text("largeBlobKey"), Value::Bool(true)));
                }
                let registration = call(
                    &mut app,
                    1,
                    map(vec![
                        (int(1), Value::Bytes(hash.to_vec())),
                        (
                            int(2),
                            map(vec![(text("id"), text("brainpool.e2e.example"))]),
                        ),
                        (int(3), map(vec![(text("id"), Value::Bytes(vec![1]))])),
                        (
                            int(4),
                            Value::Array(vec![map(vec![
                                (text("alg"), int(alg.identifier())),
                                (text("type"), text("public-key")),
                            ])]),
                        ),
                        (int(6), map(extensions)),
                        (int(7), map(vec![(text("rk"), Value::Bool(rk))])),
                    ]),
                );
                let decoded: Value = ciborium::de::from_reader(&registration[1..]).unwrap();
                let data = get(&decoded, 2).as_bytes().unwrap();
                assert_eq!(data[53..55], [0, 33]);
                assert_eq!(data[55], u8::from(rk));
                let mut responses = vec![registration.clone()];
                for _ in 0..2 {
                    responses.push(call(
                        &mut app,
                        2,
                        map(vec![
                            (int(1), text("brainpool.e2e.example")),
                            (int(2), Value::Bytes(hash.to_vec())),
                            (
                                int(3),
                                Value::Array(vec![map(vec![
                                    (text("id"), Value::Bytes(data[55..88].to_vec())),
                                    (text("type"), text("public-key")),
                                ])]),
                            ),
                            (
                                int(4),
                                map(vec![
                                    (text("thirdPartyPayment"), Value::Bool(true)),
                                    (text("credBlob"), Value::Bool(true)),
                                ]),
                            ),
                        ]),
                    ));
                }
                println!(
                    "{} {} {} {} {}",
                    alg.identifier(),
                    rk,
                    payment,
                    hex(&hash),
                    responses
                        .iter()
                        .map(|r| hex(r))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
    }
}
