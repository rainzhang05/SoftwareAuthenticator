//! Stored seeded keys whose algorithm IDs cannot fit a sealed credential ID.
use super::hmac_secret_mc::{HASH, creation_request, text, verify_response};
use super::support::*;
use crate::CoseAlg;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::store::CredentialStore;
use ciborium::{de::from_reader, value::Value};

fn call(app: &mut TestApp, command: u8, request: &[u8]) -> Vec<u8> {
    app.call(&[&[command], request].concat())
}
fn params(request: &[u8], label: i64, value: Value) -> Vec<u8> {
    let Value::Map(mut fields) = from_reader(request).unwrap() else {
        panic!("map")
    };
    fields.retain(|(k, _)| *k != int(label));
    fields.push((int(label), value));
    encode(&canonical_map(fields))
}
fn assert_request(id: &[u8]) -> Vec<u8> {
    params(
        &get_assertion_request(&HASH, "example.com", None, None),
        3,
        Value::Array(vec![canonical_map(vec![
            (text("type"), text("public-key")),
            (text("id"), Value::Bytes(id.to_vec())),
        ])]),
    )
}

#[test]
fn brainpool_modalities_preference_counter_floors_capacity_and_replacement_faults() {
    for alg in [CoseAlg::ESB256, CoseAlg::ESB384] {
        for rk in [false, true] {
            let store = TestStore::with_max_credentials(1);
            let mut app = new_app(store.clone(), [0x93; 16]);
            let request = creation_request(
                alg,
                rk,
                canonical_map(vec![
                    (text("credBlob"), Value::Bytes(vec![7; 32])),
                    (text("hmac-secret"), Value::Bool(true)),
                ]),
                None,
                1,
            );
            let request = params(
                &request,
                4,
                Value::Array(vec![
                    canonical_map(vec![
                        (text("type"), text("public-key")),
                        (text("alg"), int(-266)),
                    ]),
                    canonical_map(vec![
                        (text("type"), text("public-key")),
                        (text("alg"), int(alg.identifier().into())),
                    ]),
                    canonical_map(vec![
                        (text("type"), text("public-key")),
                        (text("alg"), int(-7)),
                    ]),
                ]),
            );
            let response = call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &request);
            assert_eq!(response[0], CTAP2_OK);
            let old = created_credential(&app, &response, "example.com");
            verify_response(&response, &old, true);
            assert_eq!(old.alg, alg);
            assert_eq!(old.credential_id.len(), 33);
            assert_eq!(old.credential_id[0], u8::from(rk));
            assert_eq!(old.cred_blob, Some(vec![7; 32]));
            assert_eq!(old.user_id.is_empty(), !rk);
            assert!(matches!(
                old.private_key,
                crate::store::PrivateKeyMaterial::Seed { .. }
            ));
            assert_eq!(store.count().unwrap(), 1);
            let assertion = assert_request(&old.credential_id);
            store.faults(|faults| faults.put = true);
            assert_eq!(
                call(&mut app, CTAP_CMD_GET_ASSERTION, &assertion),
                [CTAP2_ERR_PROCESSING]
            );
            assert_eq!(store.credential(&old.credential_id).sign_count, 0);
            store.faults(|faults| faults.put = false);
            for count in 1..=2 {
                let response = call(&mut app, CTAP_CMD_GET_ASSERTION, &assertion);
                verify_response(&response, &old, false);
                assert_eq!(
                    u32::from_be_bytes(response_auth_data(&response)[33..37].try_into().unwrap()),
                    count
                );
            }
            assert_eq!(store.signature_counter().unwrap(), 0);
            let mut floor = store.credential(&old.credential_id);
            floor.sign_count = u32::MAX;
            app.store.put(&floor).unwrap();
            drop(app);
            app = new_app(store.clone(), [0x93; 16]);
            let response = call(&mut app, CTAP_CMD_GET_ASSERTION, &assertion);
            verify_response(&response, &old, false);
            assert_eq!(response_auth_data(&response)[33..37], [0xff; 4]);
            let exclude = params(
                &request,
                5,
                Value::Array(vec![canonical_map(vec![
                    (text("type"), text("public-key")),
                    (text("id"), Value::Bytes(old.credential_id.clone())),
                ])]),
            );
            assert_eq!(
                call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &exclude),
                [CTAP2_ERR_CREDENTIAL_EXCLUDED]
            );
            let other = params(
                &request,
                3,
                canonical_map(vec![(text("id"), Value::Bytes(vec![2]))]),
            );
            // Restarting this deterministic test RNG repeats the first ID.
            // The occupied ID fails closed; the next attempt reaches capacity.
            assert_eq!(
                call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &other),
                [CTAP2_ERR_PROCESSING]
            );
            assert_eq!(
                call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &other),
                [CTAP2_ERR_KEY_STORE_FULL]
            );
            if rk {
                store.faults(|f| f.replacement_write = true);
                assert_eq!(
                    call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &request),
                    [CTAP2_ERR_PROCESSING]
                );
                assert_eq!(store.credential(&old.credential_id).sign_count, u32::MAX);
                store.faults(|f| {
                    f.replacement_write = false;
                    f.delete = true;
                });
                let replacement = call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &request);
                assert_eq!(replacement[0], CTAP2_OK);
                let new = created_credential(&app, &replacement, "example.com");
                assert_ne!(new.credential_id, old.credential_id);
                assert_ne!(
                    new.cose_public_key().unwrap(),
                    old.cose_public_key().unwrap()
                );
                assert_ne!(new.cred_random_with_uv, old.cred_random_with_uv);
                assert_eq!(new.sign_count, 0);
                assert_eq!(
                    call(&mut app, CTAP_CMD_GET_ASSERTION, &assertion),
                    [CTAP2_ERR_NO_CREDENTIALS]
                );
                verify_response(
                    &call(
                        &mut app,
                        CTAP_CMD_GET_ASSERTION,
                        &assert_request(&new.credential_id),
                    ),
                    &new,
                    false,
                );
            } else {
                assert_eq!(
                    call(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &request),
                    [CTAP2_ERR_KEY_STORE_FULL]
                );
                assert_eq!(
                    call(
                        &mut app,
                        CTAP_CMD_GET_ASSERTION,
                        &get_assertion_request(&HASH, "example.com", None, None)
                    ),
                    [CTAP2_ERR_NO_CREDENTIALS]
                );
                let body: Value = from_reader(&response[1..]).unwrap();
                assert!(map_get(body.as_map().unwrap(), int(4)).is_none());
            }
        }
    }
}
