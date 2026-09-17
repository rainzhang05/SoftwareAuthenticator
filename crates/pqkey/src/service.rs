use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use pqkey_ctap::ctap::{
    AttestationMode, CtapApp, InterruptFlag, RESET_WINDOW_AFTER_POWER_UP,
    presence::{AutoApprove, UserPresence},
};
use pqkey_ctap::store::{AttestationRecord, CredentialStore, FileStore};

use crate::{
    CTAPHID_FRAME_LEN, HidDeviceDescriptor, WaitingForUser,
    attestation::{IdentityConfig, certificate_aaguid, generate_attestation_certificate},
    create_device, exec,
    presence::{PresenceMode, Unanswered, dbus::SessionBus, notification::NotificationPresence},
    shutdown::{ShutdownSignal, is_shutdown, ok_if_shutdown},
    state::remove_and_log_legacy_state,
    uhid::UhidDevice,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Uhid,
}

/// Who a newly provisioned attestation certificate names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityStrings {
    pub manufacturer: String,
    pub product: String,
    pub country: String,
}

/// The attestation the daemon gives registrations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationConfig {
    /// Self attestation with each credential's own key.
    SelfAttestation,
    /// Basic attestation with a certificate made for this installation,
    /// naming `IdentityStrings`, and provisioned when the daemon starts.
    Certificate(IdentityStrings),
    /// No attestation statement.
    None,
}

impl AttestationConfig {
    /// The engine's attestation mode for this configuration.
    pub fn mode(&self) -> AttestationMode {
        match self {
            AttestationConfig::SelfAttestation => AttestationMode::SelfAttestation,
            AttestationConfig::Certificate(_) => AttestationMode::Certificate,
            AttestationConfig::None => AttestationMode::None,
        }
    }
}

pub struct RunnerConfig {
    pub descriptor: HidDeviceDescriptor,
    pub state_dir: PathBuf,
    pub aaguid: [u8; 16],
    pub attestation: AttestationConfig,
    pub presence: PresenceMode,
    /// How long presence requests wait for the user, if not the engine's
    /// default.
    pub presence_timeout: Option<Duration>,
    pub allow_late_reset: bool,
    pub backend: Backend,
}

/// What the CTAP app is built from.
pub struct AppData {
    /// The credential store in the state directory.
    pub store: FileStore,
    pub aaguid: [u8; 16],
    /// How the user is asked for presence.
    pub presence: PresenceMode,
    /// How long presence requests wait for the user, if not the engine's
    /// default.
    pub presence_timeout: Option<Duration>,
    /// The attestation registrations get.
    pub attestation: AttestationMode,
    /// Accept authenticatorReset after the CTAP start-up window (test rigs only).
    pub allow_late_reset: bool,
}

/// Open the credential store in `state_dir`, and provision the attestation key
/// and certificate if it has none, or if its certificate does not carry
/// `identity.aaguid`.
///
/// The latter replaces the certificates made before they met WebAuthn Level 3
/// §8.2.1, which have no AAGUID extension, and the certificate of an
/// authenticator whose AAGUID was changed, which would contradict the AAGUID
/// in authenticatorData. Only the attestation key and certificate are
/// replaced: credentials have keys of their own and stay usable. A change to
/// the other identity strings does not replace a certificate.
///
/// A stored attestation record that cannot be read is left alone for
/// inspection; registrations then use self attestation.
///
/// Only the daemon started with `--attestation certificate` calls this. In
/// the other modes the store is opened as it is, and a certificate provisioned
/// earlier is kept but not used.
pub fn open_credential_store(
    state_dir: &Path,
    identity: IdentityConfig<'_>,
) -> io::Result<FileStore> {
    let mut store = FileStore::open(state_dir).map_err(io::Error::other)?;
    let replacing = match store.attestation() {
        Ok(None) => None,
        Ok(Some(record)) => match record
            .certificate_chain
            .first()
            .and_then(|c| certificate_aaguid(c))
        {
            Some(aaguid) if aaguid == identity.aaguid => return Ok(store),
            Some(_) => Some("its certificate names another AAGUID"),
            None => Some("its certificate has no AAGUID extension"),
        },
        Err(err) => {
            log::warn!("the attestation record cannot be read ({err}); using self attestation");
            return Ok(store);
        }
    };
    let (private_key, certificate) = generate_attestation_certificate(&identity)?;
    let record = AttestationRecord {
        private_key: *private_key,
        certificate_chain: vec![certificate],
    };
    store.set_attestation(&record).map_err(io::Error::other)?;
    match replacing {
        None => log::info!("provisioned a new attestation key and certificate"),
        Some(reason) => log::info!("replaced the attestation key and certificate: {reason}"),
    }
    Ok(store)
}

#[cfg(test)]
mod provisioning_tests {
    use super::*;
    use crate::test_support::TempDir;

    const IDENTITY: IdentityConfig<'static> = IdentityConfig {
        manufacturer: "Example Manufacturer",
        product: "Example Authenticator",
        country: "US",
        aaguid: [0x11; 16],
    };

    fn stored(dir: &TempDir) -> AttestationRecord {
        FileStore::open(dir.path())
            .unwrap()
            .attestation()
            .unwrap()
            .expect("an attestation record")
    }

    #[test]
    fn a_new_store_gets_a_certificate_with_the_configured_aaguid_and_keeps_it() {
        let dir = TempDir::new("provision");
        drop(open_credential_store(dir.path(), IDENTITY).unwrap());
        let first = stored(&dir);
        assert_eq!(first.certificate_chain.len(), 1);
        assert_eq!(
            certificate_aaguid(&first.certificate_chain[0]),
            Some(IDENTITY.aaguid)
        );

        // Restarting, even with other identity strings, keeps the key and
        // certificate.
        let renamed = IdentityConfig {
            manufacturer: "Another Manufacturer",
            country: "DE",
            ..IDENTITY
        };
        drop(open_credential_store(dir.path(), renamed).unwrap());
        let second = stored(&dir);
        assert_eq!(second.private_key, first.private_key);
        assert_eq!(second.certificate_chain, first.certificate_chain);
    }

    /// State directories provisioned before the certificate carried the
    /// AAGUID get a new attestation key and certificate.
    #[test]
    fn a_certificate_without_the_aaguid_is_replaced() {
        let dir = TempDir::new("provision-legacy");
        let (private_key, _) = generate_attestation_certificate(&IDENTITY).unwrap();
        // Any certificate without the extension, such as the old generator's.
        let legacy = AttestationRecord {
            private_key: *private_key,
            certificate_chain: vec![vec![0x30, 0x03, 0x30, 0x01, 0x00]],
        };
        FileStore::open(dir.path())
            .unwrap()
            .set_attestation(&legacy)
            .unwrap();

        drop(open_credential_store(dir.path(), IDENTITY).unwrap());
        let replaced = stored(&dir);
        assert_ne!(replaced.private_key, legacy.private_key);
        assert_eq!(
            certificate_aaguid(&replaced.certificate_chain[0]),
            Some(IDENTITY.aaguid)
        );
    }

    /// The AAGUID in authenticatorData comes from the configuration, so a
    /// certificate naming another one is replaced rather than contradicting it.
    #[test]
    fn a_certificate_with_another_aaguid_is_replaced() {
        let dir = TempDir::new("provision-aaguid");
        drop(open_credential_store(dir.path(), IDENTITY).unwrap());
        let before = stored(&dir);

        let changed = IdentityConfig {
            aaguid: [0x22; 16],
            ..IDENTITY
        };
        drop(open_credential_store(dir.path(), changed).unwrap());
        let after = stored(&dir);
        assert_ne!(after.private_key, before.private_key);
        assert_eq!(
            certificate_aaguid(&after.certificate_chain[0]),
            Some([0x22; 16])
        );
    }

    #[test]
    fn an_invalid_country_fails_provisioning() {
        let dir = TempDir::new("provision-country");
        let identity = IdentityConfig {
            country: "XX",
            ..IDENTITY
        };
        let err = open_credential_store(dir.path(), identity).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            FileStore::open(dir.path())
                .unwrap()
                .attestation()
                .unwrap()
                .is_none()
        );
    }
}

/// Run the authenticator until the device fails or `shutdown` is requested.
/// A requested shutdown returns `Ok(())`. `on_ready` runs once the virtual
/// device exists.
///
/// The caller holds the state lock.
pub fn run(
    config: RunnerConfig,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let RunnerConfig {
        descriptor,
        state_dir,
        aaguid,
        attestation,
        presence,
        presence_timeout,
        allow_late_reset,
        backend,
    } = config;

    remove_and_log_legacy_state(&state_dir)?;
    let store = match &attestation {
        AttestationConfig::Certificate(identity) => {
            log::warn!(
                "--attestation certificate: every registration carries this installation's \
                 attestation certificate, so relying parties can link its credentials across sites"
            );
            open_credential_store(
                &state_dir,
                IdentityConfig {
                    manufacturer: &identity.manufacturer,
                    product: &identity.product,
                    country: &identity.country,
                    aaguid,
                },
            )?
        }
        AttestationConfig::SelfAttestation | AttestationConfig::None => {
            FileStore::open(&state_dir).map_err(io::Error::other)?
        }
    };
    let data = AppData {
        store,
        aaguid,
        presence,
        presence_timeout,
        attestation: attestation.mode(),
        allow_late_reset,
    };

    match backend {
        Backend::Uhid => {
            let result = create_device(descriptor)
                .and_then(|device| serve_ctap(device, data, shutdown, on_ready));
            if result.as_ref().is_err_and(is_shutdown) {
                log::info!("shutdown requested; the virtual authenticator has been removed");
            }
            ok_if_shutdown(result)
        }
    }
}

/// Build the CTAP app from `data` and serve it on `device` until the device
/// fails or `shutdown` is requested; the latter ends with
/// [`shutdown_error`](crate::shutdown::shutdown_error). `on_ready` runs just
/// before requests are served.
pub fn serve_ctap(
    device: UhidDevice,
    data: AppData,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    match data.presence {
        PresenceMode::Notify => {
            log::info!("asking for user presence with desktop notifications");
            let presence = NotificationPresence::new(SessionBus::new());
            serve_ctap_with_presence(device, data, presence, shutdown, on_ready)
        }
        PresenceMode::AutoApprove => {
            log::warn!(
                "--presence auto-approve: approving every registration, sign-in and reset without asking; \
                 anything running as this user can use the passkeys unnoticed. Use this for tests only"
            );
            serve_ctap_with_presence(device, data, AutoApprove, shutdown, on_ready)
        }
        PresenceMode::Unanswered => {
            log::warn!(
                "--presence unanswered: no presence request is ever approved; every request waits \
                 until it is cancelled or times out. Use this for tests only"
            );
            serve_ctap_with_presence(device, data, Unanswered, shutdown, on_ready)
        }
    }
}

/// [`serve_ctap`] with `presence` asking the user for presence. `data.presence`
/// names the mode `presence` implements.
///
/// The app runs on a worker thread (see [`exec`]), so `presence` may block
/// while the user decides: the transport keeps sending keepalives meanwhile,
/// and CTAPHID_CANCEL, resynchronisation of the channel and shutdown reach
/// `presence` through its [`Cancellation`](pqkey_ctap::ctap::presence::Cancellation).
pub fn serve_ctap_with_presence(
    device: UhidDevice,
    data: AppData,
    presence: impl UserPresence + Send + 'static,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Through this the transport cancels the request the app is processing.
    let interrupt = InterruptFlag::new();
    let waiting = WaitingForUser::new();
    let mut ctap = CtapApp::with_file_store(data.store, presence, &interrupt, data.aaguid);
    ctap.set_attestation_mode(data.attestation);
    if let Some(timeout) = data.presence_timeout {
        ctap.set_presence_timeout(timeout);
    }
    let window = reset_window(data.presence, data.allow_late_reset);
    if window.is_none() {
        if data.presence == PresenceMode::Notify {
            log::info!(
                "accepting authenticatorReset at any time: the notification says what a reset deletes and needs Approve"
            );
        } else {
            log::warn!(
                "accepting authenticatorReset at any time (--allow-late-reset); this does not conform to CTAP"
            );
        }
    }
    ctap.set_reset_window(window);
    let app_waiting = waiting.clone();
    ctap.set_keepalive_callback(move |waiting| app_waiting.set(waiting));
    exec(device, &mut ctap, &waiting, shutdown, on_ready)
}

/// How long after start-up authenticatorReset is accepted, if limited.
///
/// CTAP 2.3 §6.6: "In case of authenticators with no display, request MUST
/// have come to the authenticator within 10 seconds of powering up of the
/// authenticator." Without a display, a touch is all the user gives, and it
/// does not say what it approves, so a reset is only accepted right after
/// the user plugged the key in. With `--presence notify` the notification
/// is the display: it states "Reset the security key? This deletes all
/// passkeys." and the reset needs its Approve button, so the window does not
/// apply. `auto-approve` and `unanswered` show nothing and keep it, unless
/// `allow_late_reset` lifts it for a test rig.
pub fn reset_window(presence: PresenceMode, allow_late_reset: bool) -> Option<Duration> {
    match presence {
        PresenceMode::Notify => None,
        PresenceMode::AutoApprove | PresenceMode::Unanswered if allow_late_reset => None,
        PresenceMode::AutoApprove | PresenceMode::Unanswered => Some(RESET_WINDOW_AFTER_POWER_UP),
    }
}

pub fn descriptor(
    name: String,
    vendor_id: u32,
    product_id: u32,
    version: u32,
) -> HidDeviceDescriptor {
    HidDeviceDescriptor {
        name,
        vendor_id,
        product_id,
        version,
        country: 0,
        feature_report: vec![0; CTAPHID_FRAME_LEN],
    }
}

pub fn parse_aaguid(input: &str) -> Result<[u8; 16], String> {
    let mut cleaned = input.to_owned();
    cleaned.retain(|c| c != '-');
    if cleaned.len() != 32 {
        return Err(format!("expected 32 hex characters, got {}", cleaned.len()));
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in AAGUID".to_string())?;
        out[idx] =
            u8::from_str_radix(hex, 16).map_err(|_| format!("invalid hex at byte {}", idx))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_support::TempDir, tests::socket_device, uhid};
    use pqkey_ctap::ctap::presence::{Cancellation, PresenceOutcome, PresenceRequest};
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    const BROADCAST_CID: u32 = 0xffff_ffff;
    const CTAPHID_PING: u8 = 0x81;
    const CTAPHID_INIT: u8 = 0x86;
    const CTAPHID_CBOR: u8 = 0x90;
    const CTAPHID_CANCEL: u8 = 0x91;
    const CTAPHID_KEEPALIVE: u8 = 0xbb;
    const CTAPHID_ERROR: u8 = 0xbf;
    const ERR_CHANNEL_BUSY: u8 = 0x06;
    const STATUS_PROCESSING: u8 = 1;
    const STATUS_UPNEEDED: u8 = 2;
    const CTAP_GET_INFO: u8 = 0x04;
    const CTAP_RESET: u8 = 0x07;
    const CTAP2_OK: u8 = 0x00;
    const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2d;

    /// Long enough for anything that is going to happen to have happened.
    const TIMEOUT: Duration = Duration::from_secs(20);
    /// How long the tests watch for packets that must not come.
    const QUIET: Duration = Duration::from_millis(300);

    /// What the device side of the socket produced.
    #[derive(Debug)]
    enum Event {
        /// A CTAPHID message, when its last packet arrived: channel, command
        /// byte and payload.
        Message(Instant, u32, u8, Vec<u8>),
        Destroyed,
    }

    /// The host side of a uhid device: sends packets into the socket and
    /// reads what the daemon writes on a thread of its own, timestamped as
    /// it arrives.
    struct Host {
        stream: UnixStream,
        events: mpsc::Receiver<Event>,
    }

    impl Host {
        fn new(stream: UnixStream) -> Self {
            let mut reader = stream.try_clone().unwrap();
            let (sender, events) = mpsc::channel();
            thread::spawn(move || {
                let mut next_event = || {
                    let mut event = vec![0u8; uhid::UHID_EVENT_SIZE];
                    reader.read_exact(&mut event).ok()?;
                    Some(match uhid::input_report(&event) {
                        Some(frame) => Ok(frame),
                        None => {
                            let event_type = u32::from_ne_bytes(event[..4].try_into().unwrap());
                            assert_eq!(event_type, uhid::UHID_EVENT_TYPE_DESTROY);
                            Err(Event::Destroyed)
                        }
                    })
                };
                while let Some(event) = next_event() {
                    let event = match event {
                        Ok(frame) => {
                            let cid = u32::from_be_bytes(frame[..4].try_into().unwrap());
                            assert_ne!(frame[4] & 0x80, 0, "a stray continuation packet");
                            let length = u16::from_be_bytes([frame[5], frame[6]]) as usize;
                            let mut payload = frame[7..7 + length.min(57)].to_vec();
                            while payload.len() < length {
                                let Some(Ok(next)) = next_event() else {
                                    panic!("a message was cut short");
                                };
                                assert_eq!(next[..4], cid.to_be_bytes(), "interleaved messages");
                                let missing = length - payload.len();
                                payload.extend_from_slice(&next[5..5 + missing.min(59)]);
                            }
                            Event::Message(Instant::now(), cid, frame[4], payload)
                        }
                        Err(destroyed) => destroyed,
                    };
                    if sender.send(event).is_err() {
                        return;
                    }
                }
            });
            Self { stream, events }
        }

        /// Send a single-packet CTAPHID request.
        fn send(&mut self, cid: u32, command: u8, payload: &[u8]) {
            let mut frame = [0u8; uhid::CTAPHID_FRAME_LEN];
            frame[..4].copy_from_slice(&cid.to_be_bytes());
            frame[4] = command;
            frame[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            frame[7..7 + payload.len()].copy_from_slice(payload);
            self.stream.write_all(&uhid::output_event(&frame)).unwrap();
        }

        fn next(&self, timeout: Duration) -> Option<Event> {
            match self.events.recv_timeout(timeout) {
                Ok(event) => Some(event),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("the socket closed"),
            }
        }

        /// The next message that is not a keepalive on `cid`.
        fn receive(&self, cid: u32) -> (u8, Vec<u8>) {
            loop {
                match self.next(TIMEOUT).expect("no response") {
                    Event::Message(_, channel, CTAPHID_KEEPALIVE, _) if channel == cid => {}
                    Event::Message(_, channel, command, payload) => {
                        assert_eq!(channel, cid, "{command:#04x} {payload:02x?}");
                        return (command, payload);
                    }
                    Event::Destroyed => panic!("the device was destroyed"),
                }
            }
        }

        /// Allocate a channel.
        fn init(&mut self) -> u32 {
            let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
            self.send(BROADCAST_CID, CTAPHID_INIT, &nonce);
            let (command, payload) = self.receive(BROADCAST_CID);
            assert_eq!(command, CTAPHID_INIT);
            assert_eq!(payload[..8], nonce);
            u32::from_be_bytes(payload[8..12].try_into().unwrap())
        }

        /// Assert that nothing arrives for a while.
        fn assert_quiet(&self) {
            if let Some(event) = self.next(QUIET) {
                panic!("unexpected {event:?}");
            }
        }
    }

    fn app_data(dir: &TempDir) -> AppData {
        AppData {
            store: FileStore::open(dir.path()).expect("open credential store"),
            aaguid: [0; 16],
            presence: PresenceMode::AutoApprove,
            presence_timeout: None,
            attestation: AttestationMode::SelfAttestation,
            allow_late_reset: false,
        }
    }

    /// Run `serve` with a fresh device on a thread, and return the host side
    /// once requests are served, and the loop's result.
    fn start(
        serve: impl FnOnce(UhidDevice, Box<dyn FnOnce() -> io::Result<()>>) -> io::Result<()>
        + Send
        + 'static,
    ) -> (Host, mpsc::Receiver<io::Result<()>>) {
        let (device, host_end) = socket_device();
        let host = Host::new(host_end);
        let (ready_sender, ready) = mpsc::channel();
        let (result_sender, result) = mpsc::channel();
        thread::spawn(move || {
            let on_ready = Box::new(move || {
                ready_sender.send(()).unwrap();
                Ok(())
            });
            let result = serve(device, on_ready);
            if let Err(err) = &result
                && !is_shutdown(err)
            {
                // A test waiting for a packet would only see it missing.
                eprintln!("the loop failed: {err}");
            }
            let _ = result_sender.send(result);
        });
        ready
            .recv_timeout(TIMEOUT)
            .expect("the loop never became ready");
        (host, result)
    }

    /// Stop the loop and check it returned for that reason and destroyed the
    /// device on the way out.
    fn shut_down(host: &Host, shutdown: &ShutdownSignal, result: mpsc::Receiver<io::Result<()>>) {
        shutdown.request();
        let result = result
            .recv_timeout(TIMEOUT)
            .expect("the loop did not return after shutdown was requested");
        let err = result.unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        assert!(ok_if_shutdown(Err(err)).is_ok());
        loop {
            match host.next(TIMEOUT).expect("the device was not destroyed") {
                Event::Destroyed => break,
                // A keepalive may cross the shutdown request.
                Event::Message(_, _, CTAPHID_KEEPALIVE, _) => {}
                event => panic!("unexpected {event:?}"),
            }
        }
    }

    #[test]
    fn only_notifications_lift_the_reset_window_unless_a_test_rig_asks() {
        let window = Some(RESET_WINDOW_AFTER_POWER_UP);
        assert_eq!(reset_window(PresenceMode::Notify, false), None);
        assert_eq!(reset_window(PresenceMode::Notify, true), None);
        assert_eq!(reset_window(PresenceMode::AutoApprove, false), window);
        assert_eq!(reset_window(PresenceMode::AutoApprove, true), None);
        assert_eq!(reset_window(PresenceMode::Unanswered, false), window);
        assert_eq!(reset_window(PresenceMode::Unanswered, true), None);
    }

    /// The daemon loop must build the CTAP app, answer a request that goes
    /// through the whole stack (uhid events, CTAPHID framing, the worker
    /// thread, the app and its credential store), and return once shutdown is
    /// requested, destroying the device on the way out.
    #[test]
    fn runner_answers_requests_and_returns_when_shutdown_is_requested() {
        let dir = TempDir::new("runner");
        let data = app_data(&dir);
        let shutdown = ShutdownSignal::new();
        let loop_shutdown = shutdown.clone();
        let (mut host, result) =
            start(move |device, on_ready| serve_ctap(device, data, loop_shutdown, on_ready));

        let cid = host.init();
        // authenticatorReset clears the credential store, so this also checks
        // the store handed to the app works.
        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        assert_eq!(host.receive(cid), (CTAPHID_CBOR, vec![CTAP2_OK]));

        shut_down(&host, &shutdown, result);
    }

    /// A presence double that waits like a prompt: until the test answers,
    /// the request is cancelled, or a minute passes. It reports when it is
    /// asked and how each request ended.
    struct Prompt {
        asked: mpsc::Sender<()>,
        answers: mpsc::Receiver<PresenceOutcome>,
        outcomes: mpsc::Sender<PresenceOutcome>,
    }

    impl UserPresence for Prompt {
        fn confirm(
            &mut self,
            _request: &PresenceRequest<'_>,
            cancellation: Cancellation<'_>,
        ) -> PresenceOutcome {
            let _ = self.asked.send(());
            let deadline = Instant::now() + TIMEOUT;
            let outcome = loop {
                if cancellation.is_cancelled() {
                    break PresenceOutcome::Cancelled;
                }
                match self.answers.recv_timeout(Duration::from_millis(5)) {
                    Ok(answer) => break answer,
                    Err(_) if Instant::now() > deadline => break PresenceOutcome::TimedOut,
                    Err(_) => {}
                }
            };
            let _ = self.outcomes.send(outcome);
            outcome
        }
    }

    struct PromptHandle {
        asked: mpsc::Receiver<()>,
        answers: mpsc::Sender<PresenceOutcome>,
        outcomes: mpsc::Receiver<PresenceOutcome>,
    }

    impl PromptHandle {
        fn wait_until_asked(&self) {
            self.asked
                .recv_timeout(TIMEOUT)
                .expect("the user was never asked");
        }

        fn outcome(&self) -> PresenceOutcome {
            self.outcomes
                .recv_timeout(TIMEOUT)
                .expect("the prompt never ended")
        }
    }

    /// Serve the CTAP app with a [`Prompt`] for presence.
    fn start_with_prompt(
        dir: &TempDir,
    ) -> (
        Host,
        mpsc::Receiver<io::Result<()>>,
        ShutdownSignal,
        PromptHandle,
    ) {
        let (asked_sender, asked) = mpsc::channel();
        let (answer_sender, answers) = mpsc::channel();
        let (outcome_sender, outcomes) = mpsc::channel();
        let prompt = Prompt {
            asked: asked_sender,
            answers,
            outcomes: outcome_sender,
        };
        let data = app_data(dir);
        let shutdown = ShutdownSignal::new();
        let loop_shutdown = shutdown.clone();
        let (host, result) = start(move |device, on_ready| {
            serve_ctap_with_presence(device, data, prompt, loop_shutdown, on_ready)
        });
        let handle = PromptHandle {
            asked,
            answers: answer_sender,
            outcomes,
        };
        (host, result, shutdown, handle)
    }

    /// While the user is asked, the device keeps talking: keepalives with
    /// STATUS_UPNEEDED at least every 100 ms (CTAP 2.3 §11.2.9.1.7) but not
    /// in a flood, and a request on another channel is refused with
    /// ERR_CHANNEL_BUSY (§11.2.5.1) instead of waiting for the prompt. The
    /// app used to run on the loop's thread, so nothing was sent at all.
    #[test]
    fn keepalives_report_the_prompt_and_other_channels_are_busy() {
        let dir = TempDir::new("keepalive");
        let (mut host, result, shutdown, prompt) = start_with_prompt(&dir);
        let cid = host.init();
        let other = host.init();

        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        let sent_at = Instant::now();
        prompt.wait_until_asked();

        let mut keepalives: Vec<(Instant, [u8; 1])> = Vec::new();
        let mut busy = false;
        while sent_at.elapsed() < Duration::from_millis(1_000) {
            match host.next(TIMEOUT).expect("no keepalive") {
                Event::Message(at, channel, CTAPHID_KEEPALIVE, status) if channel == cid => {
                    keepalives.push((at, status[..].try_into().unwrap()));
                    if keepalives.len() == 5 {
                        host.send(other, CTAPHID_PING, b"are you there?");
                    }
                }
                Event::Message(_, channel, CTAPHID_ERROR, code) if channel == other => {
                    assert_eq!(code, [ERR_CHANNEL_BUSY]);
                    busy = true;
                }
                event => panic!("unexpected {event:?}"),
            }
        }
        assert!(busy, "the PING on the other channel was not answered");

        let statuses: Vec<[u8; 1]> = keepalives.iter().map(|(_, status)| *status).collect();
        let first_up_needed = statuses
            .iter()
            .position(|s| *s == [STATUS_UPNEEDED])
            .unwrap();
        assert!(
            statuses[..first_up_needed]
                .iter()
                .all(|s| *s == [STATUS_PROCESSING])
        );
        assert!(
            statuses[first_up_needed..]
                .iter()
                .all(|s| *s == [STATUS_UPNEEDED]),
            "{statuses:?}"
        );
        let mut previous = sent_at;
        for (at, _) in &keepalives {
            let gap = at.duration_since(previous);
            assert!(
                gap <= Duration::from_millis(100),
                "{gap:?} without a keepalive"
            );
            previous = *at;
        }
        let rate_limited = keepalives
            .windows(2)
            .all(|pair| pair[1].0.duration_since(pair[0].0) >= Duration::from_millis(20));
        assert!(rate_limited, "{} keepalives in a second", keepalives.len());

        prompt.answers.send(PresenceOutcome::Approved).unwrap();
        assert_eq!(prompt.outcome(), PresenceOutcome::Approved);
        assert_eq!(host.receive(cid), (CTAPHID_CBOR, vec![CTAP2_OK]));
        host.assert_quiet();
        shut_down(&host, &shutdown, result);
    }

    /// CTAP 2.3 §11.2.9.1.5: CTAPHID_CANCEL during the prompt cancels it, "the
    /// authenticator MUST NOT reply to the CTAPHID_CANCEL message itself", and
    /// "The CTAP2_ERR_KEEPALIVE_CANCEL response MUST be the response to that
    /// request, not an error response in the HID transport."
    #[test]
    fn cancel_during_the_prompt_answers_the_request_with_keepalive_cancel() {
        let dir = TempDir::new("cancel");
        let (mut host, result, shutdown, prompt) = start_with_prompt(&dir);
        let cid = host.init();

        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        prompt.wait_until_asked();
        host.send(cid, CTAPHID_CANCEL, &[]);
        assert_eq!(prompt.outcome(), PresenceOutcome::Cancelled);
        assert_eq!(
            host.receive(cid),
            (CTAPHID_CBOR, vec![CTAP2_ERR_KEEPALIVE_CANCEL])
        );
        host.assert_quiet();

        // The device is free again, and CANCEL while idle is ignored.
        host.send(cid, CTAPHID_CANCEL, &[]);
        host.send(cid, CTAPHID_PING, b"still there");
        assert_eq!(host.receive(cid), (CTAPHID_PING, b"still there".to_vec()));
        shut_down(&host, &shutdown, result);
    }

    /// CTAP 2.3 §11.2.5.3: INIT on the channel whose request waits for the
    /// user aborts the transaction. The prompt is cancelled, its late answer
    /// is discarded, and the next request on the channel is served once the
    /// app is free.
    #[test]
    fn init_during_the_prompt_aborts_it_and_the_channel_is_served_again() {
        let dir = TempDir::new("resync");
        let (mut host, result, shutdown, prompt) = start_with_prompt(&dir);
        let cid = host.init();

        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        prompt.wait_until_asked();
        let nonce = [8, 7, 6, 5, 4, 3, 2, 1];
        host.send(cid, CTAPHID_INIT, &nonce);
        host.send(cid, CTAPHID_CBOR, &[CTAP_GET_INFO]);
        let (command, payload) = host.receive(cid);
        assert_eq!(command, CTAPHID_INIT);
        assert_eq!(payload[..8], nonce);
        assert_eq!(payload[8..12], cid.to_be_bytes());
        assert_eq!(prompt.outcome(), PresenceOutcome::Cancelled);

        let (command, payload) = host.receive(cid);
        assert_eq!(command, CTAPHID_CBOR);
        assert_eq!(payload[0], CTAP2_OK, "getInfo");
        host.assert_quiet();
        shut_down(&host, &shutdown, result);
    }

    /// Shutting down while the user is asked cancels the prompt, so the
    /// worker thread can be joined and the loop returns.
    #[test]
    fn shutdown_during_the_prompt_cancels_it() {
        let dir = TempDir::new("shutdown");
        let (mut host, result, shutdown, prompt) = start_with_prompt(&dir);
        let cid = host.init();

        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        prompt.wait_until_asked();
        shut_down(&host, &shutdown, result);
        assert_eq!(prompt.outcome(), PresenceOutcome::Cancelled);
    }
}
