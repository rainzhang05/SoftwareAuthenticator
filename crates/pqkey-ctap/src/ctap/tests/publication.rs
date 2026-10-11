//! Publication commits settings; verification requires confirmed retry writes.

use super::support::*;
use crate::ClassicPinProtocol;
use crate::ctap::constants::*;
use crate::ctap::pin::observation;
use crate::store::{CommitDurability, CredentialStore};
use ciborium::value::Value;

const PIN: &[u8] = b"1234";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

fn ready(protocol: ClassicPinProtocol) -> (TestApp, TestStore) {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x42; 16]);
    set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
    observation::take();
    (app, store)
}

#[test]
fn failed_and_unconfirmed_debits_never_decrypt_compare_or_issue_tokens() {
    for protocol in PROTOCOLS {
        for unconfirmed in [false, true] {
            for subcommand in [5, 9] {
                for candidate in [Some(PIN), Some(b"9999".as_slice()), None] {
                    let (mut app, store) = ready(protocol);
                    store.faults(|f| {
                        f.set_pin_state = !unconfirmed;
                        f.pin_state_unconfirmed_after = unconfirmed.then_some(0);
                    });
                    let session = PlatformPinSession::establish(&mut app, protocol, 0x57);
                    let encrypted =
                        candidate.map_or_else(|| vec![1], |pin| session.encrypt(&pin_hash(pin)));
                    let mut fields = vec![
                        (int(1), int(protocol.identifier().into())),
                        (int(2), int(subcommand)),
                        (int(3), session.key_agreement.clone()),
                        (int(6), Value::Bytes(encrypted)),
                    ];
                    if subcommand == 9 {
                        fields.push((int(9), int(4)));
                    }
                    assert_eq!(client_pin(&mut app, fields), Err(CTAP2_ERR_PROCESSING));
                    assert_eq!(observation::take(), [0, 0, 0]);
                    assert_eq!(get_pin_retries(&mut app), (7, None));
                    assert_eq!(
                        store.pin_state().unwrap().unwrap().pin_retries,
                        if unconfirmed { 7 } else { 8 }
                    );
                    store.faults(|f| {
                        f.set_pin_state = false;
                        f.pin_state_unconfirmed_after = None;
                    });
                    get_pin_token(&mut app, protocol, PIN).unwrap();
                    assert_eq!(observation::take(), [1, 1, 1]);
                }
            }
        }
    }
}

#[test]
fn restoration_adopts_only_published_state_and_never_authorizes_on_uncertainty() {
    for protocol in PROTOCOLS {
        for unconfirmed in [false, true] {
            let (mut app, store) = ready(protocol);
            store.faults(|f| {
                f.set_pin_state_after = (!unconfirmed).then_some(1);
                f.pin_state_unconfirmed_after = unconfirmed.then_some(1);
            });
            assert_eq!(
                get_pin_token(&mut app, protocol, PIN),
                Err(CTAP2_ERR_PROCESSING)
            );
            assert_eq!(observation::take(), [1, 1, 0]);
            let expected = if unconfirmed { 8 } else { 7 };
            assert_eq!(get_pin_retries(&mut app), (expected, None));
            assert_eq!(store.pin_state().unwrap().unwrap().pin_retries, expected);
            store.faults(|f| {
                f.set_pin_state_after = None;
                f.pin_state_unconfirmed_after = None;
            });
            get_pin_token(&mut app, protocol, PIN).unwrap();
            assert_eq!(get_pin_retries(&mut app), (8, None));
        }
    }
}

#[test]
fn uncertain_retry_writes_cannot_publish_a_replacement_pin() {
    for protocol in PROTOCOLS {
        for after in [0, 1] {
            let (mut app, store) = ready(protocol);
            store.faults(|f| f.pin_state_unconfirmed_after = Some(after));
            assert_eq!(
                change_pin(&mut app, protocol, PIN, b"5678"),
                Err(CTAP2_ERR_PROCESSING)
            );
            assert_eq!(
                store.pin_state().unwrap().unwrap().pin_hash,
                Some(pin_hash(PIN))
            );
            assert_eq!(
                observation::take(),
                if after == 0 { [0, 0, 0] } else { [1, 1, 0] }
            );
        }
    }
}

#[test]
fn unconfirmed_debits_exhaust_the_budget_without_observing_a_pin() {
    for protocol in PROTOCOLS {
        let (mut app, store) = ready(protocol);
        store.faults(|f| f.pin_state_unconfirmed_after = Some(0));
        for remaining in (0..8).rev() {
            assert_eq!(
                get_pin_token(&mut app, protocol, PIN),
                Err(CTAP2_ERR_PROCESSING)
            );
            assert_eq!(get_pin_retries(&mut app), (remaining, None));
        }
        assert_eq!(
            get_pin_token(&mut app, protocol, PIN),
            Err(CTAP2_ERR_PIN_BLOCKED)
        );
        assert_eq!(observation::take(), [0, 0, 0]);
        let mut restarted = new_app(store, [0x42; 16]);
        assert_eq!(
            get_pin_token(&mut restarted, protocol, PIN),
            Err(CTAP2_ERR_PIN_BLOCKED)
        );
    }
}

#[test]
fn failed_restoration_preserves_observed_mismatches_and_lockout() {
    for protocol in PROTOCOLS {
        let (mut app, store) = ready(protocol);
        for _ in 0..2 {
            assert_eq!(
                get_pin_token(&mut app, protocol, b"9999"),
                Err(CTAP2_ERR_PIN_INVALID)
            );
        }
        store.faults(|f| f.set_pin_state_after = Some(1));
        assert_eq!(
            get_pin_token(&mut app, protocol, PIN),
            Err(CTAP2_ERR_PROCESSING)
        );
        assert_eq!(get_pin_retries(&mut app), (5, None));
        store.faults(|f| f.set_pin_state_after = None);
        assert_eq!(
            get_pin_token(&mut app, protocol, b"9999"),
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
        );
        assert_eq!(get_pin_retries(&mut app), (4, Some(true)));
        let mut restarted = new_app(store, [0x42; 16]);
        assert_eq!(get_pin_retries(&mut restarted), (4, None));
        get_pin_token(&mut restarted, protocol, PIN).unwrap();
    }
}

#[test]
fn wrong_pin_remains_spent_when_its_following_write_fails() {
    for protocol in PROTOCOLS {
        for unconfirmed in [false, true] {
            let (mut app, store) = ready(protocol);
            store.faults(|f| {
                f.set_pin_state_after = (!unconfirmed).then_some(1);
                f.pin_state_unconfirmed_after = unconfirmed.then_some(1);
            });
            assert_eq!(
                get_pin_token(&mut app, protocol, b"9999"),
                Err(CTAP2_ERR_PROCESSING)
            );
            assert_eq!(get_pin_retries(&mut app), (7, None));
            assert_eq!(store.pin_state().unwrap().unwrap().pin_retries, 7);
            assert_eq!(observation::take(), [1, 1, 0]);
        }
    }
}

#[test]
fn flushed_and_volatile_writes_allow_verification_and_reset_publication_is_commitment() {
    for durability in [CommitDurability::Flushed, CommitDurability::Volatile] {
        let (mut app, store) = ready(ClassicPinProtocol::V2);
        store.faults(|f| f.pin_state_durability = Some(durability));
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).unwrap();
        store.faults(|f| f.clear_unconfirmed = true);
        assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
        assert!(!app.pin_state.is_set());
        assert_eq!(get_pin_retries(&mut app), (8, None));
        assert_eq!(
            store.pin_state().unwrap().unwrap(),
            crate::store::PinStateRecord::default()
        );
    }
}
