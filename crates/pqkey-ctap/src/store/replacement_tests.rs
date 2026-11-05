//! Real filesystem failures and process exits at transaction boundaries.

#![expect(
    clippy::disallowed_methods,
    reason = "tests remove, move and roll back store files directly, outside the store's wrappers"
)]

use std::cell::{Cell, RefCell};
use std::process::{Command, Stdio};
use std::rc::Rc;

use super::*;
use crate::CoseAlg;
use crate::ctap::{CtapApp, InterruptFlag, constants::*, presence::AutoApprove};
use crate::store::{PrivateKeyMaterial, test_support::TempDir};

fn record(id: &[u8]) -> CredentialRecord {
    CredentialRecord {
        credential_id: id.to_vec(),
        rp_id: "example.com".into(),
        user_id: vec![1],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::MLDSA44,
        private_key: PrivateKeyMaterial::Seed { seed: [0x42; 32] },
        cred_random_with_uv: [1; 32],
        cred_random_without_uv: [2; 32],
        cred_blob: Some(vec![7; 32]),
        large_blob_key: Some([9; 32]),
        third_party_payment: id != b"new",
        cred_protect: 1,
        sign_count: 0,
        created_at: 0,
    }
}

fn setup(path: &Path, migrating: bool) -> FileStore {
    let mut store = FileStore::open(path).unwrap().with_max_credentials(3);
    let mut other = record(b"other");
    other.user_id = vec![2];
    if migrating {
        store.put(&other).unwrap();
    } else {
        store.insert_or_replace_discoverable(&other).unwrap();
    }
    store.put(&record(b"old")).unwrap();
    store.put(&record(b"duplicate")).unwrap();
    store
}

fn assert_set(path: &Path, committed: bool) {
    let store = FileStore::open(path).unwrap().with_max_credentials(3);
    assert!(store.get(b"other").unwrap().unwrap().third_party_payment);
    assert_eq!(store.get(b"new").unwrap().is_some(), committed);
    if committed {
        assert!(!store.get(b"new").unwrap().unwrap().third_party_payment);
    }
    for old in [b"old".as_slice(), b"duplicate"] {
        assert_eq!(store.get(old).unwrap().is_some(), !committed);
        if !committed {
            assert!(store.get(old).unwrap().unwrap().third_party_payment);
        }
    }
    assert_eq!(store.count().unwrap(), if committed { 2 } else { 3 });
    assert_eq!(store.count().unwrap(), store.list().unwrap().len());
    if committed {
        assert_old_assertions_rejected(path);
    }
}

fn assert_old_assertions_rejected(path: &Path) {
    static INTERRUPT: InterruptFlag = InterruptFlag::new();
    let mut app = CtapApp::with_file_store(
        FileStore::open(path).unwrap(),
        AutoApprove,
        &INTERRUPT,
        [0; 16],
    );
    for id in [b"old".as_slice(), b"duplicate"] {
        use ciborium::value::Value;
        let value = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("example.com".into())),
            (Value::Integer(2.into()), Value::Bytes(vec![0; 32])),
            (
                Value::Integer(3.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(id.to_vec())),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ])]),
            ),
        ]);
        let mut request = vec![CTAP_CMD_GET_ASSERTION];
        ciborium::ser::into_writer(&value, &mut request).unwrap();
        assert_eq!(app.call(&request), [CTAP2_ERR_NO_CREDENTIALS]);
    }
}

fn trace(migrating: bool) -> Vec<String> {
    let scratch = TempDir::new();
    let mut store = setup(&scratch.path().join("state"), migrating);
    let trace = Rc::new(RefCell::new(Vec::new()));
    let captured = trace.clone();
    let committed = fsio::with_hook(
        Box::new(move |event, _| {
            captured.borrow_mut().push(event.to_owned());
            Ok(())
        }),
        || store.insert_or_replace_discoverable(&record(b"new")),
    )
    .unwrap();
    assert_eq!(committed.durability, CommitDurability::Flushed);
    assert!(!committed.cleanup_pending);
    Rc::try_unwrap(trace).unwrap().into_inner()
}

#[test]
fn every_persistence_failure_has_unambiguous_commit_semantics() {
    for migrating in [true, false] {
        let events = trace(migrating);
        let publication = events
            .iter()
            .position(|event| event == "published")
            .unwrap();
        for (boundary, event) in events.iter().enumerate() {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let mut store = setup(&path, migrating);
            let mut index = 0;
            let result = fsio::with_hook(
                Box::new(move |_, path| {
                    let current = index;
                    index += 1;
                    if current == boundary {
                        Err(fsio::io_error(
                            path,
                            std::io::Error::other("injected boundary failure"),
                        ))
                    } else {
                        Ok(())
                    }
                }),
                || store.insert_or_replace_discoverable(&record(b"new")),
            );
            let committed = boundary >= publication;
            assert_eq!(
                result.is_ok(),
                committed,
                "migration={migrating}, boundary={boundary}: {event}: {result:?}"
            );
            if let Ok(outcome) = result {
                assert!(outcome.cleanup_pending);
            }
            assert_set(&path, committed);
        }
    }
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("PQKEY_REPLACEMENT_CHILD") else {
        return;
    };
    let target: usize = std::env::var("PQKEY_REPLACEMENT_BOUNDARY")
        .unwrap()
        .parse()
        .unwrap();
    let mut store = FileStore::open(PathBuf::from(path))
        .unwrap()
        .with_max_credentials(3);
    let mut index = 0;
    let result = fsio::with_hook(
        Box::new(move |_, _| {
            let current = index;
            index += 1;
            if current == target {
                std::process::exit(83);
            }
            Ok(())
        }),
        || store.insert_or_replace_discoverable(&record(b"new")),
    );
    panic!("crash boundary not reached: {target}, {result:?}");
}

#[test]
fn process_exit_at_every_boundary_recovers_only_the_committed_set() {
    for migrating in [true, false] {
        let events = trace(migrating);
        let publication = events
            .iter()
            .position(|event| event == "published")
            .unwrap();
        for (boundary, event) in events.iter().enumerate() {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            drop(setup(&path, migrating));
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::file::replacement_tests::crash_child",
                    "--nocapture",
                ])
                .env("PQKEY_REPLACEMENT_CHILD", &path)
                .env("PQKEY_REPLACEMENT_BOUNDARY", boundary.to_string())
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(83),
                "migration={migrating}, boundary={boundary}: {event}"
            );
            assert_set(&path, boundary >= publication);
        }
    }
}

#[test]
fn cleanup_failures_and_restored_ciphertext_never_reactivate_retired_ids() {
    let scratch = TempDir::new();
    let path = scratch.path().join("state");
    let mut store = setup(&path, true);
    let keys = store.credential_keys().unwrap().unwrap();
    let old_names: Vec<_> = [b"old".as_slice(), b"duplicate"]
        .into_iter()
        .map(|id| keys.file_name(id).unwrap())
        .collect();
    let old_bytes: Vec<_> = old_names
        .iter()
        .map(|name| fs::read(store.credentials_dir.join(name)).unwrap())
        .collect();
    for id in [b"new".as_slice(), b"second", b"third"] {
        let result = fsio::with_hook(
            Box::new(|event, path| {
                if event == "cleanup" {
                    Err(fsio::io_error(
                        path,
                        std::io::Error::other("cleanup failure"),
                    ))
                } else {
                    Ok(())
                }
            }),
            || store.insert_or_replace_discoverable(&record(id)),
        )
        .unwrap();
        assert_eq!(result.durability, CommitDurability::Flushed);
        assert!(result.cleanup_pending);
        for (name, bytes) in old_names.iter().zip(&old_bytes) {
            fs::write(store.root.join(MANAGED_DIR).join(name), bytes).unwrap();
        }
        assert_old_assertions_rejected(&path);
        store = FileStore::open(&path).unwrap().with_max_credentials(3);
        assert_eq!(store.count().unwrap(), 2);
    }
    fsio::with_hook(
        Box::new(|event, path| {
            if event == "cleanup" {
                Err(fsio::io_error(
                    path,
                    std::io::Error::other("cleanup failure"),
                ))
            } else {
                Ok(())
            }
        }),
        || store.delete(b"third"),
    )
    .unwrap();
    assert_old_assertions_rejected(&path);
    assert_eq!(FileStore::open(&path).unwrap().count().unwrap(), 1);
}

#[test]
fn unconfirmed_publication_preserves_both_possible_power_loss_states() {
    for migrating in [true, false] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let mut store = setup(&path, migrating);
        let active = store.root.join(MANAGED_DIR).join(ACTIVE_FILE);
        let previous = if migrating {
            None
        } else {
            Some(fs::read(&active).unwrap())
        };
        let published = Rc::new(Cell::new(false));
        let captured = published.clone();
        let outcome = fsio::with_hook(
            Box::new(move |event, path| {
                if event == "published" {
                    captured.set(true);
                }
                if event == "directory-flush" && captured.get() {
                    Err(fsio::io_error(
                        path,
                        std::io::Error::other("publication flush failed"),
                    ))
                } else {
                    Ok(())
                }
            }),
            || store.insert_or_replace_discoverable(&record(b"new")),
        )
        .unwrap();
        assert_eq!(outcome.durability, CommitDurability::Unconfirmed);
        assert!(outcome.cleanup_pending);
        assert_set(&path, true);
        // Model rollback of an unflushed namespace entry, not a guarantee
        // about any particular filesystem's power-loss behavior.
        if let Some(previous) = previous {
            fs::write(&active, previous).unwrap();
        } else {
            fs::rename(store.root.join(MANAGED_DIR), &store.credentials_dir).unwrap();
        }
        assert_set(&path, false);
    }
}

#[test]
fn metadata_damage_fails_closed_without_modifying_policy_or_records() {
    for damage in [
        "missing",
        "truncated",
        "authentication",
        "encoding",
        "marker",
        "missing-marker",
        "missing-namespace",
    ] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let mut store = setup(&path, false);
        store
            .insert_or_replace_discoverable(&record(b"new"))
            .unwrap();
        let pin = PinStateRecord {
            pin_hash: Some([0x78; 16]),
            always_uv: true,
            min_pin_length_rp_ids: Vec::new(),
            persistent_tokens: [None, None],
            ..PinStateRecord::default()
        };
        store.set_pin_state(&pin).unwrap();
        let active = store.root.join(MANAGED_DIR).join(ACTIVE_FILE);
        match damage {
            "missing" => fs::remove_file(&active).unwrap(),
            "truncated" => fs::write(&active, b"FTSA").unwrap(),
            "authentication" => {
                let mut bytes = fs::read(&active).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(&active, bytes).unwrap();
            }
            "encoding" => {
                let keys = store.credential_keys().unwrap().unwrap();
                let sealed = envelope::seal(
                    &keys.record,
                    RecordType::CredentialSet,
                    &format!("{MANAGED_DIR}/{ACTIVE_FILE}"),
                    b"PQC1\0\0\0\x01",
                )
                .unwrap();
                fs::write(&active, sealed).unwrap();
            }
            "marker" => fs::write(store.root.join(FORMAT_FILE), b"broken").unwrap(),
            "missing-marker" => fs::remove_file(store.root.join(FORMAT_FILE)).unwrap(),
            "missing-namespace" => {
                fs::rename(store.root.join(MANAGED_DIR), store.root.join("lost-set")).unwrap()
            }
            _ => unreachable!(),
        }
        let mut reopened = FileStore::open(&path).unwrap();
        assert!(matches!(
            reopened.get(b"new"),
            Err(StoreError::CredentialSetUnavailable { .. })
        ));
        // The inspection reports the file that operations refuse to go on
        // without, as they report it.
        let damaged = match damage {
            "marker" | "missing-marker" => FORMAT_FILE.to_owned(),
            "missing-namespace" => MANAGED_DIR.to_owned(),
            _ => format!("{MANAGED_DIR}/{ACTIVE_FILE}"),
        };
        let found = reopened.inspect().unwrap();
        let [found] = found.as_slice() else {
            panic!("{damage}: {found:?}");
        };
        assert_eq!(found.file, damaged, "{damage}");
        let summary = crate::store::damage_summary(std::slice::from_ref(found));
        assert!(
            summary.ends_with("the key cannot register, use or list passkeys"),
            "{damage}: {summary}"
        );
        let Err(StoreError::CredentialSetUnavailable { object, detail }) = reopened.list() else {
            panic!("{damage}: membership is unavailable");
        };
        assert_eq!((object, detail), (damaged, found.to_string()), "{damage}");
        assert!(reopened.list().is_err());
        assert!(reopened.count().is_err());
        assert!(
            reopened
                .insert_or_replace_discoverable(&record(b"next"))
                .is_err()
        );
        assert!(reopened.put(&record(b"next")).is_err());
        assert!(reopened.delete(b"new").is_err());
        assert_eq!(reopened.pin_state().unwrap(), Some(pin));
        if damage != "missing-namespace" {
            reopened.clear().unwrap();
            assert_eq!(reopened.count().unwrap(), 0);
        }
    }
}

/// Another process can commit between the inspection's reads of the
/// manifest and of a member: publish a manifest without the member, then
/// remove its file in cleanup.  That is no damage, and a second look, which
/// reads the new manifest, does not report it.  A member's file removed
/// while the manifest still names it is damage.
#[test]
fn inspection_does_not_report_a_member_a_concurrent_commit_removed() {
    let scratch = TempDir::new();
    let path = scratch.path().join("state");
    let store = setup(&path, false);
    let keys = store.credential_keys().unwrap().unwrap();
    let old = keys.file_name(b"old").unwrap();
    let managed = store.root.join(MANAGED_DIR);
    let mut retired = store.active_manifest(&keys).unwrap().unwrap();
    let location = retired.remove(&old).unwrap();
    let published = store.prepare_manifest(&keys, &retired, &managed).unwrap();
    let record = store.record_dir(location).join(&old);
    let committed = Rc::new(Cell::new(false));
    let commit = committed.clone();
    let found = fsio::with_hook(
        Box::new(move |event, path| {
            if event == "inspect" && path.ends_with(&old) && !commit.replace(true) {
                fs::rename(&published, managed.join(ACTIVE_FILE)).unwrap();
                fs::remove_file(&record).unwrap();
            }
            Ok(())
        }),
        || store.inspect(),
    );
    assert!(committed.get(), "the commit ran between the reads");
    assert_eq!(found.unwrap(), []);
    assert_eq!(store.get(b"old").unwrap(), None);

    let duplicate = keys.file_name(b"duplicate").unwrap();
    let removed = store.record_dir(Location::Managed).join(&duplicate);
    fs::remove_file(&removed).unwrap();
    assert_eq!(
        store.inspect().unwrap(),
        [Damage::missing(format!(
            "{MANAGED_DIR}/{RECORDS_DIR}/{duplicate}"
        ))]
    );
}

/// Looks that never agree, as when another process commits during each of
/// them, report no damage: the inspection fails, saying the store kept
/// changing.  Two looks in a row that agree are reported, even after one
/// that did not.
#[test]
fn inspection_fails_when_no_two_looks_in_a_row_agree() {
    let scratch = TempDir::new();
    let path = scratch.path().join("state");
    let store = setup(&path, false);
    let keys = store.credential_keys().unwrap().unwrap();
    // The members, in the order each look reads them, and their records.
    let members: Vec<PathBuf> = store
        .active_manifest(&keys)
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|(name, location)| store.record_dir(location).join(name))
        .collect();
    let records: Vec<Vec<u8>> = members.iter().map(|path| fs::read(path).unwrap()).collect();
    let restore = |members: &[PathBuf], records: &[Vec<u8>]| {
        for (member, record) in members.iter().zip(records) {
            fs::write(member, record).unwrap();
        }
    };
    // Each look, as it reaches its first member, finds the records restored
    // and the member `removed` names for that look missing.
    let inspect = |removed: [usize; INSPECTIONS]| {
        let (looked, kept) = (members.clone(), records.clone());
        let mut removed = removed.into_iter();
        let found = fsio::with_hook(
            Box::new(move |event, path| {
                if event == "inspect" && path == looked[0].as_path() {
                    restore(&looked, &kept);
                    fs::remove_file(&looked[removed.next().unwrap()]).unwrap();
                }
                Ok(())
            }),
            || store.inspect(),
        );
        restore(&members, &records);
        found
    };
    let missing = |index: usize| {
        let member = &members[index];
        let name = member.file_name().unwrap().to_str().unwrap();
        Damage::missing(store.relative(member.parent().unwrap(), name))
    };

    let Err(err) = inspect([0, 1, 2]) else {
        panic!("three looks that disagree are no report");
    };
    assert!(matches!(&err, StoreError::Io { path, .. } if *path == store.root));
    assert_eq!(
        crate::store::damage_unchecked(&err),
        format!(
            "the credential store cannot be checked: {}: it kept changing while it was checked; \
             run `pqkey status` again",
            store.root.display()
        )
    );
    assert_eq!(inspect([0, 1, 1]).unwrap(), [missing(1)]);
    assert_eq!(store.inspect().unwrap(), []);
}

#[test]
fn collisions_with_corrupt_and_staged_records_are_rejected() {
    let scratch = TempDir::new();
    let mut store = setup(&scratch.path().join("state"), true);
    let name = store
        .credential_keys()
        .unwrap()
        .unwrap()
        .file_name(b"new")
        .unwrap();
    let dir = store.credentials_dir.join(RECORDS_DIR);
    fsio::ensure_private_dir(&dir).unwrap();
    fs::write(dir.join(&name), b"unpublished corrupt candidate").unwrap();
    assert!(matches!(
        store.insert_or_replace_discoverable(&record(b"new")),
        Err(StoreError::InvalidRecord(_))
    ));
    assert_eq!(store.count().unwrap(), 3);
    assert!(store.get(b"new").unwrap().is_none());
    let old = store
        .credential_keys()
        .unwrap()
        .unwrap()
        .file_name(b"old")
        .unwrap();
    fs::write(store.credentials_dir.join(old), b"corrupt").unwrap();
    assert!(matches!(
        store.insert_or_replace_discoverable(&record(b"old")),
        Err(StoreError::InvalidRecord(_))
    ));
    assert_eq!(store.count().unwrap(), 2);
}

#[test]
fn unreadable_active_records_abort_replacement_instead_of_leaving_duplicates() {
    for migrating in [true, false] {
        let scratch = TempDir::new();
        let path = scratch.path().join("state");
        let mut store = setup(&path, migrating);
        let keys = store.credential_keys().unwrap().unwrap();
        let name = keys.file_name(b"old").unwrap();
        let old_path = if migrating {
            store.credentials_dir.join(name)
        } else {
            store.record_dir(Location::Managed).join(name)
        };
        let ciphertext = fs::read(&old_path).unwrap();
        fs::write(&old_path, b"corrupt temporarily").unwrap();
        assert_eq!(
            store.count().unwrap(),
            2,
            "listing still skips individual corruption"
        );
        assert!(
            store
                .insert_or_replace_discoverable(&record(b"new"))
                .is_err()
        );
        fs::write(old_path, ciphertext).unwrap();
        assert_set(&path, false);
    }
}

#[test]
fn brainpool_replacements_preserve_commit_semantics_at_every_boundary() {
    for alg in [CoseAlg::ESB256, CoseAlg::ESB384] {
        for migrating in [true, false] {
            let events = trace(migrating);
            let publication = events
                .iter()
                .position(|event| event == "published")
                .unwrap();
            for boundary in 0..events.len() {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                let mut store = setup(&path, migrating);
                let mut new = record(b"new");
                new.alg = alg;
                let mut index = 0;
                let result = fsio::with_hook(
                    Box::new(move |_, path| {
                        let current = index;
                        index += 1;
                        if current == boundary {
                            Err(fsio::io_error(
                                path,
                                std::io::Error::other("Brainpool boundary failure"),
                            ))
                        } else {
                            Ok(())
                        }
                    }),
                    || store.insert_or_replace_discoverable(&new),
                );
                assert_eq!(
                    result.is_ok(),
                    boundary >= publication,
                    "{alg:?} boundary {boundary}"
                );
                assert_set(&path, boundary >= publication);
                if boundary >= publication {
                    let loaded = FileStore::open(&path)
                        .unwrap()
                        .get(b"new")
                        .unwrap()
                        .unwrap();
                    assert_eq!(loaded.alg, alg);
                    assert_eq!(
                        loaded.cose_public_key().unwrap(),
                        new.cose_public_key().unwrap()
                    );
                }
            }
        }
    }
}
