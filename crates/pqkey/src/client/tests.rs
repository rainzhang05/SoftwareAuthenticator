//! The client against the whole daemon stack: the engine on a file store,
//! the worker thread and the CTAPHID transport, through the backend's test
//! peer: Linux uhid events or a callback queue.

use std::{io, sync::mpsc, thread, time::Duration};

use pqkey_ctap::CoseAlg;
use pqkey_ctap::ctap::AttestationMode;
use pqkey_ctap::store::{CredentialRecord, CredentialStore, FileStore, PrivateKeyMaterial};

use super::ctap2::{Authenticator, ClientError, PinRetries};
use super::ctaphid::{Report, ReportLink};
use crate::platform::test_support::Peer;
use crate::presence::PresenceMode;
use crate::service::AppData;
use crate::shutdown::ShutdownSignal;
use crate::test_support::TempDir;

/// Reports through the test peer of the selected device.
pub(crate) struct TestLink(Peer);

impl ReportLink for TestLink {
    fn send(&mut self, report: &Report) -> io::Result<()> {
        self.0.send(report)
    }

    fn receive(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
        self.0.receive(timeout)
    }
}

/// A running daemon over `dir`'s store, approving every presence request,
/// and a client of it.  The daemon stops when the returned guard drops.
pub(crate) struct Daemon {
    shutdown: ShutdownSignal,
    done: mpsc::Receiver<()>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.shutdown.request();
        let _ = self.done.recv_timeout(Duration::from_secs(10));
    }
}

pub(crate) fn start(dir: &TempDir) -> (Daemon, Authenticator<TestLink>) {
    start_with(dir, PresenceMode::AutoApprove)
}

pub(crate) fn start_with(
    dir: &TempDir,
    presence: PresenceMode,
) -> (Daemon, Authenticator<TestLink>) {
    let (device, kernel) = crate::platform::test_support::pair();
    let data = AppData {
        store: FileStore::open(dir.path()).expect("open the store"),
        state_dir: dir.path().to_owned(),
        aaguid: [0; 16],
        presence,
        presence_timeout: None,
        attestation: AttestationMode::SelfAttestation,
        allow_late_reset: false,
    };
    let shutdown = ShutdownSignal::new();
    let (ready_sender, ready) = mpsc::channel();
    let (done_sender, done) = mpsc::channel();
    let loop_shutdown = shutdown.clone();
    thread::spawn(move || {
        let _ = crate::test_support::serve_ctap(device, data, loop_shutdown, move || {
            ready_sender.send(()).unwrap();
            Ok(())
        });
        let _ = done_sender.send(());
    });
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("the daemon started");
    let client = Authenticator::open(TestLink(kernel)).expect("CTAPHID_INIT");
    (Daemon { shutdown, done }, client)
}

pub(crate) fn discoverable(rp_id: &str, id: u8, name: &str, alg: CoseAlg) -> CredentialRecord {
    let mut credential_id = vec![0x01];
    credential_id.extend([id; 32]);
    CredentialRecord {
        credential_id,
        rp_id: rp_id.into(),
        user_id: vec![id],
        user_name: Some(name.into()),
        user_display_name: Some(name.to_uppercase()),
        alg,
        private_key: PrivateKeyMaterial::generate(alg),
        cred_random_with_uv: [0x10; 32],
        cred_random_without_uv: [0x20; 32],
        cred_blob: None,
        cred_protect: 1,
        sign_count: 0,
        created_at: 0,
    }
}

#[test]
fn a_pin_is_set_and_changed_with_its_retries_counted() {
    let dir = TempDir::new("client-pin");
    let (_daemon, mut key) = start(&dir);
    assert_eq!(key.info().unwrap().pin_set, Some(false));

    key.set_pin(b"1234").unwrap();
    assert_eq!(key.info().unwrap().pin_set, Some(true));
    let retries = |key: &mut Authenticator<TestLink>| key.pin_retries().unwrap();
    assert_eq!(
        retries(&mut key),
        PinRetries {
            retries: 8,
            power_cycle_needed: false
        }
    );

    // A second setPIN is refused: "If a PIN has already been set,
    // authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error." (CTAP 2.3
    // §6.5.5.5)  It can only be changed.
    assert!(matches!(
        key.set_pin(b"5678"),
        Err(ClientError::Status(0x33))
    ));

    // CTAP2_ERR_PIN_INVALID, and one retry spent.
    assert!(matches!(
        key.change_pin(b"0000", b"5678"),
        Err(ClientError::Status(0x31))
    ));
    assert_eq!(retries(&mut key).retries, 7);
    key.change_pin(b"1234", b"5678").unwrap();
    assert_eq!(retries(&mut key).retries, 8);
    assert!(key.management_token(b"5678").is_ok());
}

#[test]
fn passkeys_are_listed_and_deleted_with_a_management_token() {
    let dir = TempDir::new("client-passkeys");
    {
        let mut store = FileStore::open(dir.path()).unwrap();
        store
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
        store
            .put(&discoverable("example.com", 2, "bob", CoseAlg::MLDSA87))
            .unwrap();
        store
            .put(&discoverable("other.example", 3, "carol", CoseAlg::MLDSA44))
            .unwrap();
    }
    let (_daemon, mut key) = start(&dir);
    key.set_pin(b"1234").unwrap();
    let token = key.management_token(b"1234").unwrap();

    let mut listed: Vec<_> = key
        .passkeys(&token)
        .unwrap()
        .into_iter()
        .map(|passkey| {
            (
                passkey.rp_id,
                passkey.user_name,
                passkey.user_display_name,
                passkey.alg,
            )
        })
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        [
            (
                "example.com".into(),
                Some("alice".into()),
                Some("ALICE".into()),
                Some(-7)
            ),
            (
                "example.com".into(),
                Some("bob".into()),
                Some("BOB".into()),
                Some(-50)
            ),
            (
                "other.example".into(),
                Some("carol".into()),
                Some("CAROL".into()),
                Some(-48)
            ),
        ]
    );

    let bob = discoverable("example.com", 2, "bob", CoseAlg::ES256)
        .credential_id
        .clone();
    key.delete(&token, &bob).unwrap();
    assert!(matches!(
        key.delete(&token, &bob),
        Err(ClientError::Status(0x2E))
    ));
    assert_eq!(key.passkeys(&token).unwrap().len(), 2);

    // A wrong PIN gets no token.
    assert!(matches!(
        key.management_token(b"0000"),
        Err(ClientError::Status(0x31))
    ));
}

/// Passkeys of every algorithm are listed with their COSE algorithm, which
/// the client reads from the public key credential management returns.
#[test]
fn passkeys_are_listed_with_their_algorithm() {
    let dir = TempDir::new("client-algorithms");
    let passkeys: Vec<CredentialRecord> = (1..)
        .zip(CoseAlg::ALL)
        .map(|(id, alg)| discoverable("example.com", id, "user", alg))
        .collect();
    {
        let mut store = FileStore::open(dir.path()).unwrap();
        for passkey in &passkeys {
            store.put(passkey).unwrap();
        }
    }
    let (_daemon, mut key) = start(&dir);
    key.set_pin(b"1234").unwrap();
    let token = key.management_token(b"1234").unwrap();

    let mut listed: Vec<(Vec<u8>, Option<i64>)> = key
        .passkeys(&token)
        .unwrap()
        .into_iter()
        .map(|passkey| (passkey.credential_id, passkey.alg))
        .collect();
    listed.sort();
    let expected: Vec<(Vec<u8>, Option<i64>)> = passkeys
        .iter()
        .map(|passkey| {
            (
                passkey.credential_id.clone(),
                Some(i64::from(passkey.alg.identifier())),
            )
        })
        .collect();
    assert_eq!(listed, expected);
}

#[test]
fn a_key_without_passkeys_lists_none() {
    let dir = TempDir::new("client-empty");
    let (_daemon, mut key) = start(&dir);
    key.set_pin(b"1234").unwrap();
    let token = key.management_token(b"1234").unwrap();
    assert!(key.passkeys(&token).unwrap().is_empty());
}

#[test]
fn a_reset_right_after_start_erases_the_pin_and_passkeys() {
    let dir = TempDir::new("client-reset");
    {
        let mut store = FileStore::open(dir.path()).unwrap();
        store
            .put(&discoverable("example.com", 1, "alice", CoseAlg::ES256))
            .unwrap();
    }
    let (_daemon, mut key) = start(&dir);
    key.set_pin(b"1234").unwrap();
    let mut waited = Vec::new();
    key.reset(&mut |status| waited.push(status)).unwrap();
    assert_eq!(key.info().unwrap().pin_set, Some(false));
    assert_eq!(key.info().unwrap().remaining_discoverable, Some(1000));
}

/// While the key waits for its user, Ctrl-C cancels the request with
/// CTAPHID_CANCEL, and the key answers CTAP2_ERR_KEEPALIVE_CANCEL.
#[test]
fn a_request_waiting_for_the_user_is_cancelled() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let dir = TempDir::new("client-cancel");
    let (_daemon, key) = start_with(&dir, PresenceMode::Unanswered);
    let mut key = key.with_cancel_flag(Arc::clone(&cancel));
    let mut statuses = Vec::new();
    let result = key.reset(&mut |status| {
        statuses.push(status);
        if status == super::ctaphid::STATUS_UPNEEDED {
            cancel.store(true, Ordering::Relaxed);
        }
    });
    assert!(
        matches!(result, Err(ClientError::Status(0x2D))),
        "{result:?}"
    );
    assert!(statuses.contains(&super::ctaphid::STATUS_UPNEEDED));
}
