//! Shared public-engine exercise for stack and retained-heap probes.
use ciborium::value::Value;
use pqkey_ctap::{
    ClassicPinProtocol,
    ctap::{CtapApp, InterruptFlag, presence::AutoApprove},
    platform::{PlatformKeyAgreement, authenticate, padded_pin, pin_hash},
    store::{CredentialStore, MemoryStore, PersistentTokenRecord, PinStateRecord},
};
use rand_core::{Infallible, TryCryptoRng, TryRng};

struct ProbeRng(u8);
impl TryRng for ProbeRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
        bytes.fill(self.0);
        self.0 += 1;
        Ok(())
    }
}
impl TryCryptoRng for ProbeRng {}
static INTERRUPT: InterruptFlag = InterruptFlag::new();
fn int(value: i64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn request(command: u8, fields: Vec<(Value, Value)>) -> Vec<u8> {
    let mut wire = vec![command];
    ciborium::ser::into_writer(&Value::Map(fields), &mut wire).unwrap();
    wire
}
fn field(map: &Value, key: i64) -> &Value {
    &map.as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| *k == int(key))
        .unwrap()
        .1
}
/// Build everything before the stack probe wipes its baseline.
pub fn fixture() -> (Box<CtapApp<'static>>, Vec<(Vec<u8>, u8)>) {
    fixture_with_store(MemoryStore::new())
}

/// Exercise actual encrypted PIN-state serialization in a file store.
pub fn file_fixture(path: &std::path::Path) -> (Box<CtapApp<'static>>, Vec<(Vec<u8>, u8)>) {
    fixture_with_store(pqkey_ctap::store::FileStore::open(path).unwrap())
}

fn fixture_with_store(
    mut store: impl CredentialStore + Send + 'static,
) -> (Box<CtapApp<'static>>, Vec<(Vec<u8>, u8)>) {
    let mut state = PinStateRecord::default();
    state.pin_hash = Some(*pin_hash(b"1234"));
    state.persistent_tokens = [
        Some(PersistentTokenRecord {
            secret: [0x91; 32],
            granted: false,
        }),
        Some(PersistentTokenRecord {
            secret: [0x92; 32],
            granted: false,
        }),
    ];
    store.set_pin_state(&state).unwrap();
    let mut app = Box::new(CtapApp::new(
        store,
        ProbeRng(0xb3),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    ));
    // Full debug stack scans can outlast the production reset window.
    app.set_reset_window(None);
    let mut requests = Vec::new();
    let mut changes = Vec::new();
    for (protocol, secret) in [
        (ClassicPinProtocol::V1, [0x91; 32]),
        (ClassicPinProtocol::V2, [0x92; 32]),
    ] {
        let response = app.call(&request(
            6,
            vec![
                (int(1), int(protocol.identifier().into())),
                (int(2), int(2)),
            ],
        ));
        let body: Value = ciborium::de::from_reader(&response[1..]).unwrap();
        let key = field(&body, 1);
        let x = field(key, -2)
            .as_bytes()
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let y = field(key, -3)
            .as_bytes()
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let session = PlatformKeyAgreement::new(protocol, &x, &y, &[0x31; 32]).unwrap();
        let (x, y) = session.public_key();
        let agreement = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), bytes(&x)),
            (int(-3), bytes(&y)),
        ]);
        let common = vec![
            (int(1), int(protocol.identifier().into())),
            (int(2), int(9)),
            (int(3), agreement.clone()),
            (
                int(6),
                bytes(&session.encrypt(&pin_hash(b"1234")[..], [0x32; 16]).unwrap()),
            ),
            (int(9), int(0x40)),
        ];
        requests.push((request(6, common.clone()), 0));
        requests.push((
            request(
                0x0a,
                vec![
                    (int(1), int(1)),
                    (int(3), int(protocol.identifier().into())),
                    (int(4), bytes(&authenticate(protocol, &secret, &[1]))),
                ],
            ),
            0,
        ));
        requests.push((request(6, common), 0));
        let new = session
            .encrypt(&padded_pin(b"5678").unwrap()[..], [0x32; 16])
            .unwrap();
        let old = session.encrypt(&pin_hash(b"1234")[..], [0x32; 16]).unwrap();
        let auth = session.authenticate(&[new.as_slice(), old.as_slice()].concat());
        changes.push(request(
            6,
            vec![
                (int(1), int(protocol.identifier().into())),
                (int(2), int(4)),
                (int(3), agreement),
                (int(4), bytes(&auth)),
                (int(5), bytes(&new)),
                (int(6), bytes(&old)),
            ],
        ));
    }
    requests.push((changes.remove(0), 0));
    for (protocol, secret) in [
        (ClassicPinProtocol::V1, [0x91; 32]),
        (ClassicPinProtocol::V2, [0x92; 32]),
    ] {
        requests.push((
            request(
                0x0a,
                vec![
                    (int(1), int(1)),
                    (int(3), int(protocol.identifier().into())),
                    (int(4), bytes(&authenticate(protocol, &secret, &[1]))),
                ],
            ),
            0x33,
        ));
    }
    requests.push((vec![7], 0));
    (app, requests)
}
/// Existing and every possible newly drawn secret/key/IV canary.
pub fn needles() -> Vec<Vec<u8>> {
    [0x91, 0x92]
        .into_iter()
        .chain(0xb3..=0xc7)
        .map(|byte| vec![byte; 32])
        .collect()
}
