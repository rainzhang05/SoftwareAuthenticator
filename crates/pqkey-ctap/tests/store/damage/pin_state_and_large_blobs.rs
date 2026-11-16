//! A damaged PIN state or large-blob array, which repair leaves alone: each
//! is named and fails what it is said to, repair leaves it as it is, and,
//! moved out of the state directory as its fix says, the PIN state leaves
//! the passkeys usable and a new PIN can be set.  A missing or unreadable
//! one is no damage.

use super::*;

use crate::common::serialized_large_blob_array;
use pqkey_ctap::ClassicPinProtocol;
use pqkey_ctap::ctap::constants::{
    CTAP_CMD_CLIENT_PIN, CTAP_CMD_LARGE_BLOBS, CTAP2_ERR_PIN_AUTH_INVALID, CTAP2_ERR_PIN_BLOCKED,
    CTAP2_ERR_PUAT_REQUIRED,
};
use pqkey_ctap::platform::{PlatformKeyAgreement, padded_pin, pin_hash};
use pqkey_ctap::store::INITIAL_LARGE_BLOB_ARRAY;

/// What a summary says fails after damage to the PIN state, and what the
/// engine's hint advises.
const PIN_STATE: &str = "the key treats its PIN as blocked and requires it, so it cannot \
                         register passkeys, sign in or set a new PIN";
const PIN_STATE_FIX: &str = "Stop the key with `pqkey stop`, move pin-state out of the state \
                             directory, then start the key again with `pqkey start` and set a \
                             new PIN with `pqkey pin`, and any PIN settings again with `pqkey \
                             config`; `pqkey reset` erases every passkey, so use it only as a \
                             last resort";
/// The same after damage to the large-blob array.
const LARGE_BLOBS: &str = "the key cannot return the large blobs that sites stored on it";
const LARGE_BLOBS_FIX: &str = "Stop the key with `pqkey stop`, move large-blobs out of the state \
                               directory, then start the key again with `pqkey start`";
/// The PIN the tests set.
const PIN: &[u8] = b"1234";

/// The value of `key` in the CBOR map `map`.
fn field(map: &Value, key: i64) -> &Value {
    let Value::Map(entries) = map else {
        panic!("not a map: {map:?}");
    };
    &entries
        .iter()
        .find(|(name, _)| *name == int(key))
        .unwrap()
        .1
}

/// The response map of `command` with `parameters`, which must succeed.
fn answer(app: &mut CtapApp<'static>, command: u8, parameters: Vec<(Value, Value)>) -> Value {
    let response = app.call(&request(command, parameters));
    assert_eq!(response[0], CTAP2_OK, "{command:#x}");
    ciborium::de::from_reader(&response[1..]).unwrap()
}

/// clientPIN `subcommand` of PIN/UV auth protocol two, with a shared secret
/// from getKeyAgreement and the parameters `more` makes with it: the status.
fn client_pin(
    app: &mut CtapApp<'static>,
    subcommand: i64,
    more: impl FnOnce(&PlatformKeyAgreement) -> Vec<(Value, Value)>,
) -> u8 {
    let protocol = (int(1), int(2));
    let key = answer(
        app,
        CTAP_CMD_CLIENT_PIN,
        vec![protocol.clone(), (int(2), int(2))],
    );
    let coordinate = |label| -> [u8; 32] {
        let Value::Bytes(bytes) = field(field(&key, 1), label) else {
            panic!("not a coordinate");
        };
        bytes.as_slice().try_into().unwrap()
    };
    let secret = PlatformKeyAgreement::generate_key().unwrap();
    let shared = PlatformKeyAgreement::new(
        ClassicPinProtocol::V2,
        &coordinate(-2),
        &coordinate(-3),
        &secret,
    )
    .unwrap();
    let (x, y) = shared.public_key();
    let platform = Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-25)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(x.to_vec())),
        (int(-3), Value::Bytes(y.to_vec())),
    ]);
    let mut parameters = vec![protocol, (int(2), int(subcommand)), (int(3), platform)];
    parameters.extend(more(&shared));
    app.call(&request(CTAP_CMD_CLIENT_PIN, parameters))[0]
}

/// setPIN with `pin`: the status.
fn set_pin(app: &mut CtapApp<'static>, pin: &[u8]) -> u8 {
    client_pin(app, 3, |shared| {
        let new = shared
            .encrypt(&padded_pin(pin).unwrap()[..], random_bytes())
            .unwrap();
        vec![
            (int(4), Value::Bytes(shared.authenticate(&new))),
            (int(5), Value::Bytes(new)),
        ]
    })
}

/// changePIN from `pin` to another: the status.
fn change_pin(app: &mut CtapApp<'static>, pin: &[u8]) -> u8 {
    client_pin(app, 4, |shared| {
        let new = shared
            .encrypt(&padded_pin(b"9999").unwrap()[..], random_bytes())
            .unwrap();
        let old = shared.encrypt(&pin_hash(pin)[..], random_bytes()).unwrap();
        let auth = shared.authenticate(&[new.as_slice(), old.as_slice()].concat());
        vec![
            (int(4), Value::Bytes(auth)),
            (int(5), Value::Bytes(new)),
            (int(6), Value::Bytes(old)),
        ]
    })
}

/// getPinToken with `pin`: the status.
fn pin_token(app: &mut CtapApp<'static>, pin: &[u8]) -> u8 {
    client_pin(app, 5, |shared| {
        let hash = shared.encrypt(&pin_hash(pin)[..], random_bytes()).unwrap();
        vec![(int(6), Value::Bytes(hash))]
    })
}

/// The PIN retries getPINRetries reports.
fn pin_retries(app: &mut CtapApp<'static>) -> Value {
    let retries = answer(
        app,
        CTAP_CMD_CLIENT_PIN,
        vec![(int(1), int(2)), (int(2), int(1))],
    );
    field(&retries, 3).clone()
}

/// getInfo's clientPin and alwaysUv options.
fn pin_options(app: &mut CtapApp<'static>) -> (Value, Value) {
    let info = answer(app, CTAP_CMD_GET_INFO, Vec::new());
    let Value::Map(options) = field(&info, 4) else {
        panic!("getInfo has options");
    };
    let option = |name: &str| {
        options
            .iter()
            .find(|(key, _)| *key == text(name))
            .map(|(_, value)| value.clone())
            .unwrap()
    };
    (option("clientPin"), option("alwaysUv"))
}

/// The serialized large-blob array the key returns, read whole.
fn large_blob_array(app: &mut CtapApp<'static>) -> Vec<u8> {
    let read = answer(
        app,
        CTAP_CMD_LARGE_BLOBS,
        vec![(int(1), int(1024)), (int(3), int(0))],
    );
    let Value::Bytes(array) = field(&read, 1) else {
        panic!("not an array");
    };
    array.clone()
}

/// A damaged PIN state: the inspection names it, and what the summary says
/// fails does.  The key reports the PIN set and blocked and requires it, so
/// a token, a registration, sign-ins over CTAP 2 and U2F that worked before,
/// and a new PIN all fail, and the engine names the file and what to do,
/// whether it finds the file damaged as it runs or as it starts.  Moved out
/// of the state directory with the key stopped, as that says, it leaves a
/// key without a PIN, which takes a new one, and every passkey is listed and
/// signs in again.
#[test]
fn a_damaged_pin_state_fails_what_its_summary_says_until_it_is_moved_out() {
    logs::install();
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    let mut app = engine(&state);
    assert_eq!(set_pin(&mut app, PIN), CTAP2_OK);
    let application = [0x55; 32];
    let handle = register_u2f(&mut app, application);
    for (record, _) in &passkeys {
        assert_eq!(sign_in(&mut app, Some(&record.credential_id)), CTAP2_OK);
    }
    assert_eq!(pin_token(&mut app, PIN), CTAP2_OK);
    let pin_state = state.join("pin-state");
    flip_last_byte(&pin_state);
    let hint =
        format!("The credential store is damaged at pin-state: {PIN_STATE}. {PIN_STATE_FIX}");
    let (status, logged) = logging(&hint, || pin_token(&mut app, PIN));
    assert_eq!(status, CTAP2_ERR_PROCESSING);
    assert_eq!(
        logged,
        [format!(
            "cannot read persistent authority: pin-state is corrupt: authentication failed. \
             {hint}"
        )]
    );
    assert_eq!(pin_token(&mut app, PIN), CTAP2_ERR_PIN_BLOCKED);
    drop(app);

    let store = FileStore::open(&state).unwrap();
    let found = inspect(&store, &state);
    let corrupt = Fault::Corrupt(Corruption::Authentication);
    assert_eq!(faults(&found), [("pin-state".to_owned(), corrupt)]);
    assert_eq!(
        damage_summary(&found),
        format!(
            "the credential store is damaged (pin-state is corrupt: authentication failed): \
             {PIN_STATE}"
        )
    );
    let (mut app, logged) = logging(&hint, || engine(&state));
    assert_eq!(
        logged,
        [format!(
            "treating the PIN as set and blocked, since the stored PIN state cannot be read: \
             pin-state is corrupt: authentication failed. {hint}"
        )]
    );
    assert_eq!(
        pin_options(&mut app),
        (Value::Bool(true), Value::Bool(true))
    );
    assert_eq!(pin_retries(&mut app), int(0));
    assert_eq!(pin_token(&mut app, PIN), CTAP2_ERR_PIN_BLOCKED);
    assert_eq!(register(&mut app), CTAP2_ERR_PUAT_REQUIRED);
    for (record, _) in &passkeys {
        assert_eq!(
            sign_in(&mut app, Some(&record.credential_id)),
            CTAP2_ERR_PUAT_REQUIRED
        );
    }
    assert_eq!(
        authenticate_u2f(&mut app, application, &handle),
        [0x69, 0x86],
        "SW_COMMAND_NOT_ALLOWED"
    );
    assert_eq!(set_pin(&mut app, b"5678"), CTAP2_ERR_PIN_AUTH_INVALID);
    assert_eq!(change_pin(&mut app, PIN), CTAP2_ERR_PIN_BLOCKED);
    drop(app);

    let damaged = fs::read(&pin_state).unwrap();
    let moved = scratch.path().join("pin-state");
    fs::rename(&pin_state, &moved).unwrap();
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    let mut app = engine(&state);
    assert_eq!(
        pin_options(&mut app),
        (Value::Bool(false), Value::Bool(false))
    );
    assert_eq!(set_pin(&mut app, b"5678"), CTAP2_OK);
    assert_eq!(pin_token(&mut app, b"5678"), CTAP2_OK);
    for (record, _) in &passkeys {
        assert_eq!(sign_in(&mut app, Some(&record.credential_id)), CTAP2_OK);
    }
    assert_eq!(
        authenticate_u2f(&mut app, application, &handle),
        [0x90, 0x00]
    );
    drop(app);
    let listed: BTreeSet<Vec<u8>> = ids(&FileStore::open(&state).unwrap().list().unwrap())
        .into_iter()
        .collect();
    let stored: BTreeSet<Vec<u8>> = passkeys
        .iter()
        .map(|(record, _)| record.credential_id.clone())
        .collect();
    assert_eq!(listed, stored);
    assert_eq!(
        fs::read(&moved).unwrap(),
        damaged,
        "kept where it was moved"
    );
}

/// A damaged large-blob array: the inspection names it, and what the summary
/// says fails does: the key returns the initial array in its place, not the
/// one stored, and names the file and what to do.  Moved out of the state
/// directory, as that says, it is no damage, and the key returns the
/// initial array, as it did.
#[test]
fn a_damaged_large_blob_array_fails_what_its_summary_says() {
    logs::install();
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    passkeys_in(&state, true);
    let stored = serialized_large_blob_array(&[0x81, 0x43, 1, 2, 3]);
    FileStore::open(&state)
        .unwrap()
        .set_large_blob_array(&stored)
        .unwrap();
    assert_eq!(large_blob_array(&mut engine(&state)), stored);
    let large_blobs = state.join("large-blobs");
    flip_last_byte(&large_blobs);

    let store = FileStore::open(&state).unwrap();
    let found = inspect(&store, &state);
    let corrupt = Fault::Corrupt(Corruption::Authentication);
    assert_eq!(faults(&found), [("large-blobs".to_owned(), corrupt)]);
    assert_eq!(
        damage_summary(&found),
        format!(
            "the credential store is damaged (large-blobs is corrupt: authentication failed): \
             {LARGE_BLOBS}"
        )
    );
    let hint =
        format!("The credential store is damaged at large-blobs: {LARGE_BLOBS}. {LARGE_BLOBS_FIX}");
    let mut app = engine(&state);
    let (array, logged) = logging(&hint, || large_blob_array(&mut app));
    assert_eq!(array, INITIAL_LARGE_BLOB_ARRAY);
    assert_eq!(
        logged,
        [format!(
            "using the initial large-blob array: large-blobs is corrupt: authentication failed. \
             {hint}"
        )]
    );
    drop(app);

    fs::rename(&large_blobs, scratch.path().join("large-blobs")).unwrap();
    assert_eq!(FileStore::inspect_in(&state).unwrap(), []);
    assert_eq!(
        large_blob_array(&mut engine(&state)),
        INITIAL_LARGE_BLOB_ARRAY
    );
}

/// A damaged PIN state and large-blob array are named with the credential
/// set's and the counter's damage, first, even where membership metadata
/// that cannot be used hides every record.  Repair, which leaves both
/// alone, plans as it would without them and leaves both files as they
/// were; with only them left, it finds nothing to repair, changing nothing.
#[test]
fn repair_leaves_a_damaged_pin_state_and_array_alone() {
    for membership in [false, true] {
        let scratch = TempDir::new();
        let state = scratch.path().join("state");
        let passkeys = passkeys_in(&state, true);
        let mut store = FileStore::open(&state).unwrap();
        let pin = PinStateRecord {
            pin_hash: Some(random_bytes()),
            min_pin_length_rp_ids: Vec::new(),
            persistent_tokens: [None, None],
            ..PinStateRecord::default()
        };
        store.set_pin_state(&pin).unwrap();
        store
            .set_large_blob_array(&serialized_large_blob_array(&[0x80]))
            .unwrap();
        store.set_signature_counter(7).unwrap();
        let corrupt = Fault::Corrupt(Corruption::Authentication);
        let set = if membership {
            flip_last_byte(&state.join("credential-set").join("active"));
            "credential-set/active".to_owned()
        } else {
            flip_last_byte(&passkeys[2].1);
            relative(&state, &passkeys[2].1)
        };
        flip_last_byte(&state.join("signature-counter"));
        let without = FileStore::plan_repair_in(&state).unwrap().unwrap();

        let left = ["pin-state", "large-blobs"];
        for file in left {
            flip_last_byte(&state.join(file));
        }
        let damaged = left.map(|file| fs::read(state.join(file)).unwrap());
        let found = inspect(&store, &state);
        assert_eq!(
            faults(&found),
            [
                ("pin-state".to_owned(), corrupt.clone()),
                ("large-blobs".to_owned(), corrupt.clone()),
                ("signature-counter".to_owned(), corrupt.clone()),
                (set, corrupt.clone()),
            ],
            "membership: {membership}"
        );
        let plan = FileStore::plan_repair_in(&state).unwrap().unwrap();
        assert_eq!(plan, without, "membership: {membership}");
        let repaired = FileStore::repair_in(&state, &plan).unwrap();
        let quarantine = repaired.quarantine.unwrap();
        for (file, contents) in left.into_iter().zip(&damaged) {
            assert_eq!(&fs::read(state.join(file)).unwrap(), contents, "{file}");
            assert!(!quarantine.join(file).exists(), "{file}");
        }
        assert_eq!(
            faults(&inspect(&store, &state)),
            left.map(|file| (file.to_owned(), corrupt.clone()))
        );
        let before = snapshot(&state);
        assert_eq!(FileStore::plan_repair_in(&state).unwrap(), None);
        assert_eq!(snapshot(&state), before, "membership: {membership}");
    }
}

/// A PIN state or large-blob array that is missing, or that cannot be read,
/// as a directory in its place cannot, is no damage: it fails neither the
/// inspection nor the repair of a damaged record beside it, which leaves it
/// as it is.
#[test]
fn a_missing_or_unreadable_pin_state_or_array_is_no_damage() {
    let scratch = TempDir::new();
    let state = scratch.path().join("state");
    let passkeys = passkeys_in(&state, true);
    let mut store = FileStore::open(&state).unwrap();
    store.set_pin_state(&PinStateRecord::default()).unwrap();
    store
        .set_large_blob_array(&serialized_large_blob_array(&[0x80]))
        .unwrap();
    for file in ["pin-state", "large-blobs"] {
        fs::remove_file(state.join(file)).unwrap();
    }
    assert_eq!(inspect(&store, &state), [], "missing");
    for file in ["pin-state", "large-blobs"] {
        fs::create_dir(state.join(file)).unwrap();
    }
    assert!(store.pin_state().is_err() && store.large_blob_array().is_err());
    assert_eq!(inspect(&store, &state), [], "unreadable");
    flip_last_byte(&passkeys[2].1);
    let (plan, _) = repair(&state);
    assert_eq!(
        faults(&plan.damage),
        [(
            relative(&state, &passkeys[2].1),
            Fault::Corrupt(Corruption::Authentication)
        )]
    );
    for file in ["pin-state", "large-blobs"] {
        assert!(state.join(file).is_dir(), "{file}");
    }
}
