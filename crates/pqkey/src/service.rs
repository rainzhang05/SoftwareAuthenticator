use std::{
    cell::RefCell,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use pqkey_ctap::ctap::{
    AttestationMode, Clock, CtapApp, InterruptFlag, RESET_WINDOW_AFTER_POWER_UP,
    presence::{AutoApprove, UserPresence},
};
use pqkey_ctap::store::{
    AttestationRecord, CredentialStore, DirectoryFlush, FileStore, damage_log, damage_unchecked_log,
};

use crate::{
    WaitingForUser,
    attestation::{IdentityConfig, certificate_aaguid, generate_attestation_certificate},
    create_device,
    platform::{self, BootTimeClock},
    presence::{
        PresenceMode, Unanswered,
        notification::{NotificationPresence, PROMPT_FILE},
    },
    seat::{Seat, SeatDevice, SeatSource, Unwatched, is_unplugged},
    shutdown::{ShutdownSignal, is_shutdown, ok_if_shutdown},
    transport::{HidDevice, HidDeviceDescriptor, exec_with_identifier},
};

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

#[derive(Debug)]
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
}

/// What the CTAP app is built from.
pub struct AppData {
    /// The credential store in the state directory.
    pub store: FileStore,
    /// The state directory, for the daemon's own files in it.
    pub state_dir: PathBuf,
    pub aaguid: [u8; 16],
    /// How the user is asked for presence.
    pub presence: PresenceMode,
    /// How long presence requests wait for the user, if not the engine's
    /// default.
    pub presence_timeout: Option<Duration>,
    /// The attestation registrations get.
    pub attestation: AttestationMode,
    /// Accept authenticatorReset after the CTAP start-up window (test
    /// rigs only).
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
/// device exists, or once the key first keeps it unplugged because another
/// user's session is active on its seat or the key cannot tell from the
/// seat's record who is.
///
/// The device exists while the session logind records as active on its
/// seat is one of this user's, or no session is active there (see
/// [`crate::seat`]). The key removes it while another user's session is the
/// active one, or the record cannot be read or understood, or has gone
/// since the key saw it, and creates a new one when the seat is free again.
/// It also replaces the device whenever logind saves the record, even when
/// that leaves this user active, so that a switch away and back cannot go
/// unseen.
///
/// The caller holds the state lock.
pub fn run(
    config: RunnerConfig,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    platform::disable_core_dumps()?;
    let RunnerConfig {
        descriptor,
        state_dir,
        aaguid,
        attestation,
        presence,
        presence_timeout,
        allow_late_reset,
    } = config;

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
        state_dir: state_dir.clone(),
        aaguid,
        presence,
        presence_timeout,
        attestation: attestation.mode(),
        allow_late_reset,
    };

    let seat = Seat::new(
        platform::SeatWatch::new(&descriptor.uniq),
        nix::unistd::getuid().as_raw(),
    );
    let result = serve_ctap_plugged(
        || create_device(descriptor.clone()),
        seat,
        data,
        BootTimeClock::new,
        shutdown,
        on_ready,
    );
    if result.as_ref().is_err_and(is_shutdown) {
        log::info!("shutdown requested; the virtual authenticator has been removed");
    }
    ok_if_shutdown(result)
}

/// Build the CTAP app from `data` and serve it on `device` until the device
/// fails or `shutdown` is requested; the latter ends with
/// [`shutdown_error`](crate::shutdown::shutdown_error). `on_ready` runs just
/// before requests are served.
pub fn serve_ctap(
    device: impl HidDevice,
    data: AppData,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    serve_ctap_with_clock(device, data, BootTimeClock::new, shutdown, on_ready)
}

/// Serve with an injected clock factory, called when the CTAP app is built.
/// Tests provide their clock through the same engine interface as the backend.
pub(crate) fn serve_ctap_with_clock<C: Clock + 'static>(
    device: impl HidDevice,
    data: AppData,
    clock: impl FnOnce() -> io::Result<C>,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let seat = Seat::new(Unwatched, 0);
    serve_ctap_plugged(once(device), seat, data, clock, shutdown, on_ready)
}

/// The device factory of a single device.
fn once<D>(device: D) -> impl FnMut() -> io::Result<D> {
    let mut device = Some(device);
    move || {
        device
            .take()
            .ok_or_else(|| io::Error::other("this device can be plugged in only once"))
    }
}

/// [`serve_ctap_with_clock`] on the devices `devices` creates, one at a time,
/// whenever `seat` lets one exist. The CTAP app is built once and serves
/// every device: a new device is not a new power-up.
pub(crate) fn serve_ctap_plugged<D: HidDevice, S: SeatSource, C: Clock + 'static>(
    devices: impl FnMut() -> io::Result<D>,
    seat: Seat<S>,
    data: AppData,
    clock: impl FnOnce() -> io::Result<C>,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    match data.presence {
        PresenceMode::Notify => {
            log::info!("asking for user presence with desktop notifications");
            let mut presence = NotificationPresence::new(platform::notifications()?)
                .with_prompt_record(data.state_dir.join(PROMPT_FILE));
            presence.withdraw_stale_prompt();
            serve_plugged_with_presence(devices, seat, data, presence, clock, shutdown, on_ready)
        }
        PresenceMode::AutoApprove => {
            log::warn!(
                "--presence auto-approve: approving every registration, sign-in and reset without asking; \
                 anything running as this user can use the passkeys unnoticed. Use this for tests only"
            );
            serve_plugged_with_presence(devices, seat, data, AutoApprove, clock, shutdown, on_ready)
        }
        PresenceMode::Unanswered => {
            log::warn!(
                "--presence unanswered: no presence request is ever approved; every request waits \
                 until it is cancelled or times out. Use this for tests only"
            );
            serve_plugged_with_presence(devices, seat, data, Unanswered, clock, shutdown, on_ready)
        }
    }
}

/// [`serve_ctap`] with `presence` asking the user for presence. `data.presence`
/// names the mode `presence` implements.
///
/// The app runs on a worker thread (see [`exec_with_identifier`]), so `presence` may block
/// while the user decides: the transport keeps sending keepalives meanwhile,
/// and CTAPHID_CANCEL, resynchronisation of the channel and shutdown reach
/// `presence` through its
/// [`Cancellation`](pqkey_ctap::ctap::presence::Cancellation).
pub fn serve_ctap_with_presence<C: Clock + 'static>(
    device: impl HidDevice,
    data: AppData,
    presence: impl UserPresence + Send + 'static,
    clock: impl FnOnce() -> io::Result<C>,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let seat = Seat::new(Unwatched, 0);
    serve_plugged_with_presence(
        once(device),
        seat,
        data,
        presence,
        clock,
        shutdown,
        on_ready,
    )
}

/// [`serve_ctap_with_presence`] on the devices `devices` creates, whenever
/// `seat` lets one exist.
///
/// Each device is served as a [`SeatDevice`], so a report that arrives once
/// `seat` says the device must go is neither handled nor answered. The
/// transport then ends: it cancels the request the app is working on, a
/// presence prompt included, destroys the device, which ends every file
/// opened on it, and drops its CTAPHID channels. The app, its clock and its
/// PIN state stay: the reset window and the run of wrong PINs go on counting
/// from when the app was built.
pub(crate) fn serve_plugged_with_presence<D: HidDevice, S: SeatSource, C: Clock + 'static>(
    mut devices: impl FnMut() -> io::Result<D>,
    seat: Seat<S>,
    data: AppData,
    presence: impl UserPresence + Send + 'static,
    clock: impl FnOnce() -> io::Result<C>,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Through this the transport cancels the request the app is processing.
    let interrupt = InterruptFlag::new();
    let waiting = WaitingForUser::new();
    log_if_state_dir_cannot_flush(data.store.state_dir());
    log_if_store_damaged(&data.store);
    let mut ctap = CtapApp::with_file_store(data.store, presence, &interrupt, data.aaguid);
    ctap.set_clock(clock()?);
    ctap.set_attestation_mode(data.attestation);
    if let Some(timeout) = data.presence_timeout {
        warn_if_presence_timeout_too_short(timeout);
        ctap.set_presence_timeout(timeout);
    }
    let window = reset_window(data.allow_late_reset);
    if window.is_none() {
        log::warn!(
            "accepting authenticatorReset at any time (--allow-late-reset); this does not conform to CTAP 2.3 §6.6"
        );
    }
    ctap.set_reset_window(window);
    let app_waiting = waiting.clone();
    ctap.set_keepalive_callback(move |waiting| app_waiting.set(waiting));
    let identity = device_uniq(std::process::id());
    let seat = RefCell::new(seat);
    let mut on_ready = Some(on_ready);
    let mut ready = || on_ready.take().map_or(Ok(()), |on_ready| on_ready());
    loop {
        seat.borrow_mut().wait_for_turn(&shutdown, &mut ready)?;
        let device = SeatDevice::new(devices()?, &seat);
        seat.borrow_mut().plugged();
        let result = exec_with_identifier(
            device,
            &mut ctap,
            &waiting,
            shutdown.clone(),
            &mut ready,
            |deadline| platform::identify(&identity, deadline),
        );
        if !result.as_ref().is_err_and(is_unplugged) {
            return result;
        }
    }
}

/// Log that the key cannot use a PIN or save passkeys in `state_dir`, if
/// its filesystem does not support flushing directories: no PIN-state write
/// could be confirmed there, so the engine refuses to set or check a PIN,
/// and saving a passkey fails.
fn log_if_state_dir_cannot_flush(state_dir: &Path) {
    if let DirectoryFlush::Unsupported(err) = FileStore::directory_flush_in(state_dir) {
        log::error!(
            "the key cannot use a PIN or save passkeys in its state directory, which cannot be \
             flushed ({err}): no PIN retry could be stored durably there, so setting or checking \
             a PIN is refused, without using up a retry, and saving a passkey fails. Stop the \
             key (`pqkey stop`), move the state directory to a local filesystem (or copy it and \
             verify the copy before deleting the original), leave a symbolic link in its place, \
             then start the key (`pqkey start`), which checks again; until then use the key only \
             as a security key, without a PIN"
        );
    }
}

/// Log what is damaged in `store`'s credential set and signature counter,
/// and what fails, or that it cannot be checked, with what to do: what
/// `pqkey status` reports (`cli::key::store_problem`). The engine logs the
/// same with each operation the damage fails; this names all of it once,
/// before any operation, reading every record as one listing does. A legacy
/// `credentials` directory that opening the store created again is logged
/// by the store itself ([`FileStore::open`]).
fn log_if_store_damaged(store: &FileStore) {
    let state_dir = store.state_dir().display().to_string();
    match store.inspect() {
        Ok(damage) if damage.is_empty() => {}
        Ok(damage) => log::error!("{}", damage_log(&damage, &state_dir)),
        Err(err) => log::warn!("{}", damage_unchecked_log(&err, &state_dir)),
    }
}

/// The shortest user action timeout CTAP allows: "This timeout MUST be at
/// least 10 seconds" (CTAP 2.3 §5).
const MIN_USER_ACTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Log that a presence timeout under [`MIN_USER_ACTION_TIMEOUT`], which test
/// rigs use to keep their runs short, does not conform to CTAP.
fn warn_if_presence_timeout_too_short(timeout: Duration) {
    if timeout < MIN_USER_ACTION_TIMEOUT {
        log::warn!(
            "a presence timeout of {} s does not conform to CTAP 2.3 section 5, which says the user \
             action timeout MUST be at least 10 seconds; use it for test rigs only",
            timeout.as_secs()
        );
    }
}

/// How long after start-up authenticatorReset is accepted, if limited.
///
/// CTAP 2.3 §6.6: "In case of authenticators with no display, request MUST
/// have come to the authenticator within 10 seconds of powering up of the
/// authenticator."  pqkey has no display in any presence mode: a desktop
/// notification belongs to the platform, which any program on the session
/// bus can replace or close, and the engine follows CTAP's steps for an
/// authenticator without one throughout (see `CtapApp`).  So a reset is
/// only accepted right after the key is started, as a hardware key only
/// accepts it right after it is plugged in; `pqkey reset` restarts the key
/// first.  Only `allow_late_reset`, for test rigs, lifts the window.
pub fn reset_window(allow_late_reset: bool) -> Option<Duration> {
    (!allow_late_reset).then_some(RESET_WINDOW_AFTER_POWER_UP)
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
        uniq: device_uniq(std::process::id()),
    }
}

/// The HID unique identifier the daemon with process ID `pid` gives its
/// device, by which commands find its client link: `pqkey-<pid>`.
pub fn device_uniq(pid: u32) -> String {
    format!("pqkey-{pid}")
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
    use crate::{
        platform::test_support::{Device as TestDevice, Peer as DevicePeer, pair as socket_device},
        test_support::TempDir,
        transport::CTAPHID_FRAME_LEN,
    };
    use ciborium::value::{Integer, Value};
    use pqkey_ctap::ctap::presence::{Cancellation, PresenceOutcome, PresenceRequest};
    use pqkey_ctap::{CoseAlg, verify_signature};
    use std::{
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
    const CTAP_MAKE_CREDENTIAL: u8 = 0x01;
    const CTAP_GET_ASSERTION: u8 = 0x02;
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
        stream: DevicePeer,
        events: mpsc::Receiver<Event>,
    }

    impl Host {
        fn new(stream: DevicePeer) -> Self {
            let mut reader = stream.try_clone().unwrap();
            let (sender, events) = mpsc::channel();
            thread::spawn(move || {
                let mut next_event = || {
                    Some(match reader.read_event().ok()? {
                        crate::test_support::callback::Event::Report(frame) => Ok(frame.0),
                        crate::test_support::callback::Event::Destroyed => Err(Event::Destroyed),
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

        /// Send a CTAPHID request: an initialization packet, then as many
        /// continuation packets as the payload needs.
        fn send(&mut self, cid: u32, command: u8, payload: &[u8]) {
            let (first, mut rest) = payload.split_at(payload.len().min(57));
            let mut frame = [0u8; CTAPHID_FRAME_LEN];
            frame[..4].copy_from_slice(&cid.to_be_bytes());
            frame[4] = command;
            frame[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            frame[7..7 + first.len()].copy_from_slice(first);
            self.stream.send(&frame).unwrap();
            for sequence in 0u8.. {
                if rest.is_empty() {
                    break;
                }
                let (chunk, remaining) = rest.split_at(rest.len().min(59));
                let mut frame = [0u8; CTAPHID_FRAME_LEN];
                frame[..4].copy_from_slice(&cid.to_be_bytes());
                frame[4] = sequence;
                frame[5..5 + chunk.len()].copy_from_slice(chunk);
                self.stream.send(&frame).unwrap();
                rest = remaining;
            }
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
            state_dir: dir.path().to_owned(),
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
        serve: impl FnOnce(TestDevice, Box<dyn FnOnce() -> io::Result<()>>) -> io::Result<()>
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

    /// A presence timeout under the 10 seconds CTAP 2.3 §5 requires is
    /// allowed for test rigs, and logged as non-conforming.
    #[test]
    fn a_presence_timeout_under_10_seconds_is_reported() {
        use crate::test_support::logs;
        logs::install();
        warn_if_presence_timeout_too_short(Duration::from_secs(10));
        assert!(logs::containing("presence timeout of 10 s").is_empty());
        warn_if_presence_timeout_too_short(Duration::from_secs(3));
        let warned = logs::containing("presence timeout of 3 s");
        assert!(
            warned
                .iter()
                .any(|(level, message)| *level == log::Level::Warn
                    && message.contains("MUST be at least 10 seconds")),
            "{warned:?}"
        );
    }

    /// A state directory whose filesystem refuses to flush directories, as
    /// procfs does with EINVAL, is reported as one where the key cannot use a
    /// PIN, with the fix; one that flushes is not reported.
    #[test]
    fn a_state_directory_that_cannot_be_flushed_is_reported() {
        use crate::test_support::logs;
        logs::install();
        let flushing = TempDir::new("flushing-state");
        log_if_state_dir_cannot_flush(flushing.path());
        assert!(logs::containing(&flushing.path().display().to_string()).is_empty());
        log_if_state_dir_cannot_flush(Path::new("/proc"));
        let logged = logs::containing("(/proc: ");
        // The key is stopped before its directory moves, and started after.
        let in_order = |message: &str, parts: &[&str]| {
            let at: Vec<_> = parts.iter().map(|part| message.find(part)).collect();
            at.iter().all(Option::is_some) && at.windows(2).all(|pair| pair[0] < pair[1])
        };
        assert!(
            logged
                .iter()
                .any(|(level, message)| *level == log::Level::Error
                    && message.contains("cannot use a PIN")
                    && message.contains("setting or checking a PIN is refused")
                    && in_order(
                        message,
                        &["`pqkey stop`", "to a local filesystem", "`pqkey start`"]
                    )),
            "{logged:?}"
        );
    }

    /// The notification is no display of the authenticator, so a reset is
    /// only accepted within 10 seconds of start-up whatever presence shows,
    /// unless a test rig asks otherwise.
    #[test]
    fn only_a_test_rig_lifts_the_reset_window() {
        assert_eq!(reset_window(false), Some(RESET_WINDOW_AFTER_POWER_UP));
        assert_eq!(reset_window(true), None);
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
        let (mut host, result) = start(move |device, on_ready| {
            crate::test_support::serve_ctap(device, data, loop_shutdown, on_ready)
        });

        let cid = host.init();
        // authenticatorReset clears the credential store, so this also checks
        // the store handed to the app works.
        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        assert_eq!(host.receive(cid), (CTAPHID_CBOR, vec![CTAP2_OK]));

        shut_down(&host, &shutdown, result);
    }

    fn int(value: i64) -> Value {
        Value::Integer(Integer::from(value))
    }

    fn text(value: &str) -> Value {
        Value::Text(value.into())
    }

    /// The value of `key` in the CBOR map `map`.
    fn get(map: &Value, key: Value) -> Value {
        let Value::Map(entries) = map else {
            panic!("not a map: {map:?}");
        };
        entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("missing {key:?}"))
    }

    fn bytes(value: Value) -> Vec<u8> {
        match value {
            Value::Bytes(bytes) => bytes,
            other => panic!("not bytes: {other:?}"),
        }
    }

    /// Send the CTAP command `command` with `parameters` (in canonical order)
    /// on `cid`, and return the parameters of its successful response.
    fn ctap(host: &mut Host, cid: u32, command: u8, parameters: Vec<(Value, Value)>) -> Value {
        let mut request = vec![command];
        ciborium::into_writer(&Value::Map(parameters), &mut request).unwrap();
        host.send(cid, CTAPHID_CBOR, &request);
        let (response_command, response) = host.receive(cid);
        assert_eq!(response_command, CTAPHID_CBOR);
        assert_eq!(response[0], CTAP2_OK, "CTAP status {:#04x}", response[0]);
        ciborium::from_reader(&response[1..]).unwrap()
    }

    /// Check that `signature` signs `auth_data || client_data_hash` with the
    /// `alg` key `public_key`, a COSE key.
    fn assert_signed(
        alg: CoseAlg,
        public_key: &Value,
        auth_data: &[u8],
        client_data_hash: &[u8],
        signature: &[u8],
    ) {
        let message = [auth_data, client_data_hash].concat();
        let mut cose_key = Vec::new();
        ciborium::into_writer(public_key, &mut cose_key).unwrap();
        verify_signature(alg, &cose_key, &message, signature)
            .unwrap_or_else(|err| panic!("{alg:?}: {err}"));
    }

    /// Registration and authentication with every algorithm through the
    /// whole stack: uhid events, CTAPHID messages of several packets each way,
    /// the worker thread, the engine and its file store. ML-DSA-87 has the
    /// longest responses there are. Every signature must verify with the
    /// public key the registration returned, and the assertion must name the
    /// credential it created.
    #[test]
    fn registers_and_authenticates_through_the_whole_stack() {
        let dir = TempDir::new("full-stack");
        let data = app_data(&dir);
        let shutdown = ShutdownSignal::new();
        let loop_shutdown = shutdown.clone();
        let (mut host, result) = start(move |device, on_ready| {
            crate::test_support::serve_ctap(device, data, loop_shutdown, on_ready)
        });
        let cid = host.init();

        for alg in CoseAlg::ALL {
            let client_data_hash = [0x11; 32];
            let registration = ctap(
                &mut host,
                cid,
                CTAP_MAKE_CREDENTIAL,
                vec![
                    (int(1), Value::Bytes(client_data_hash.to_vec())),
                    (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
                    (
                        int(3),
                        Value::Map(vec![
                            (text("id"), Value::Bytes(vec![0x42; 64])),
                            (text("name"), text("alice@example.com")),
                        ]),
                    ),
                    (
                        int(4),
                        Value::Array(vec![Value::Map(vec![
                            (text("alg"), int(i64::from(alg.identifier()))),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])),
                ],
            );
            // Self attestation: the new credential signs its own registration.
            assert_eq!(get(&registration, int(1)), text("packed"));
            let auth_data = bytes(get(&registration, int(2)));
            let statement = get(&registration, int(3));
            assert_eq!(
                get(&statement, text("alg")),
                int(i64::from(alg.identifier()))
            );
            // After the AAGUID: the credential ID's length, the ID, the key.
            let id_length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
            let credential_id = auth_data[55..55 + id_length].to_vec();
            let public_key: Value = ciborium::from_reader(&auth_data[55 + id_length..]).unwrap();
            let signature = bytes(get(&statement, text("sig")));
            assert_signed(alg, &public_key, &auth_data, &client_data_hash, &signature);

            let client_data_hash = [0x22; 32];
            let assertion = ctap(
                &mut host,
                cid,
                CTAP_GET_ASSERTION,
                vec![
                    (int(1), text("example.com")),
                    (int(2), Value::Bytes(client_data_hash.to_vec())),
                    (
                        int(3),
                        Value::Array(vec![Value::Map(vec![
                            (text("id"), Value::Bytes(credential_id.clone())),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                ],
            );
            let credential = get(&assertion, int(1));
            assert_eq!(bytes(get(&credential, text("id"))), credential_id);
            let auth_data = bytes(get(&assertion, int(2)));
            let signature = bytes(get(&assertion, int(3)));
            assert_signed(alg, &public_key, &auth_data, &client_data_hash, &signature);
        }

        shut_down(&host, &shutdown, result);
    }

    /// ML-DSA-87 goes deepest into the stack of the worker the app runs on
    /// (`CTAP_WORKER_STACK` in the transport): each operation zeroes 1,600 KiB
    /// below the engine's frames, and its frames are largest in a debug build,
    /// the one `cargo test` makes. Registration expands a key, derives its
    /// public key and signs its own attestation; an assertion opens the key
    /// from a sealed credential ID, or from the store for a discoverable
    /// credential, and signs again. Each must succeed with a signature that
    /// verifies, and the loop must still shut down cleanly.
    #[test]
    fn ml_dsa_87_requests_fit_the_ctap_worker_stack() {
        let dir = TempDir::new("worker-stack");
        let data = app_data(&dir);
        let shutdown = ShutdownSignal::new();
        let loop_shutdown = shutdown.clone();
        let (mut host, result) = start(move |device, on_ready| {
            serve_ctap_with_presence(
                device,
                data,
                AutoApprove,
                crate::test_support::clock,
                loop_shutdown,
                on_ready,
            )
        });
        let cid = host.init();
        let alg = CoseAlg::MLDSA87;

        for resident in [false, true] {
            let client_data_hash = [0x33; 32];
            let registration = ctap(
                &mut host,
                cid,
                CTAP_MAKE_CREDENTIAL,
                vec![
                    (int(1), Value::Bytes(client_data_hash.to_vec())),
                    (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
                    (
                        int(3),
                        Value::Map(vec![(text("id"), Value::Bytes(vec![0x42; 64]))]),
                    ),
                    (
                        int(4),
                        Value::Array(vec![Value::Map(vec![
                            (text("alg"), int(i64::from(alg.identifier()))),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (
                        int(7),
                        Value::Map(vec![(text("rk"), Value::Bool(resident))]),
                    ),
                ],
            );
            assert_eq!(get(&registration, int(1)), text("packed"));
            let auth_data = bytes(get(&registration, int(2)));
            let statement = get(&registration, int(3));
            assert_eq!(get(&statement, text("alg")), int(-50));
            let id_length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
            let credential_id = auth_data[55..55 + id_length].to_vec();
            let public_key: Value = ciborium::from_reader(&auth_data[55 + id_length..]).unwrap();
            let signature = bytes(get(&statement, text("sig")));
            assert_signed(alg, &public_key, &auth_data, &client_data_hash, &signature);

            let client_data_hash = [0x44; 32];
            let assertion = ctap(
                &mut host,
                cid,
                CTAP_GET_ASSERTION,
                vec![
                    (int(1), text("example.com")),
                    (int(2), Value::Bytes(client_data_hash.to_vec())),
                    (
                        int(3),
                        Value::Array(vec![Value::Map(vec![
                            (text("id"), Value::Bytes(credential_id.clone())),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                ],
            );
            let credential = get(&assertion, int(1));
            assert_eq!(bytes(get(&credential, text("id"))), credential_id);
            let auth_data = bytes(get(&assertion, int(2)));
            let signature = bytes(get(&assertion, int(3)));
            assert_signed(alg, &public_key, &auth_data, &client_data_hash, &signature);
        }

        shut_down(&host, &shutdown, result);
    }

    #[test]
    fn transport_commands_preserve_engine_assertion_continuations() {
        let dir = TempDir::new("transport-continuations");
        let data = app_data(&dir);
        let shutdown = ShutdownSignal::new();
        let loop_shutdown = shutdown.clone();
        let (mut host, result) = start(move |device, on_ready| {
            crate::test_support::serve_ctap(device, data, loop_shutdown, on_ready)
        });
        let cid = host.init();
        for user in [1, 2] {
            ctap(
                &mut host,
                cid,
                CTAP_MAKE_CREDENTIAL,
                vec![
                    (int(1), Value::Bytes(vec![0x11; 32])),
                    (
                        int(2),
                        Value::Map(vec![(text("id"), text("continuation.example"))]),
                    ),
                    (
                        int(3),
                        Value::Map(vec![(text("id"), Value::Bytes(vec![user]))]),
                    ),
                    (
                        int(4),
                        Value::Array(vec![Value::Map(vec![
                            (text("alg"), int(-7)),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])),
                ],
            );
        }
        let first = ctap(
            &mut host,
            cid,
            CTAP_GET_ASSERTION,
            vec![
                (int(1), text("continuation.example")),
                (int(2), Value::Bytes(vec![0x22; 32])),
            ],
        );
        assert_eq!(get(&first, int(5)), int(2));
        host.send(cid, 0x84, &[1]);
        assert_eq!(host.receive(cid), (0x84, vec![]));
        host.send(cid, 0x88, &[]);
        let (command, payload) = host.receive(cid);
        assert!(matches!(
            (command, payload.as_slice()),
            (0x88, []) | (0xbf, [0x7f])
        ));
        host.send(cid, 0x84, &[0]);
        assert_eq!(host.receive(cid), (0x84, vec![]));
        let next = ctap(&mut host, cid, 0x08, vec![]);
        assert_ne!(get(&first, int(1)), get(&next, int(1)));
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
            serve_ctap_with_presence(
                device,
                data,
                prompt,
                crate::test_support::clock,
                loop_shutdown,
                on_ready,
            )
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

    // The key's device comes and goes with the session that is active on
    // its seat.

    use crate::client::{
        ctap2::{Authenticator, ClientError, PinRetries},
        ctaphid::{Report, ReportLink},
    };
    use crate::seat::{Active, scripted::ScriptedSeat};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    const OWNER: u32 = 1000;
    const ERR_INVALID_CHANNEL: u8 = 0x0b;
    const CTAP2_ERR_NOT_ALLOWED: u8 = 0x30;
    const CTAP2_ERR_PIN_INVALID: u8 = 0x31;
    const CTAP2_ERR_PIN_AUTH_BLOCKED: u8 = 0x34;

    fn owner() -> Active {
        Active::Session {
            id: "2".into(),
            uid: OWNER,
        }
    }

    fn other() -> Active {
        Active::Session {
            id: "5".into(),
            uid: 1001,
        }
    }

    /// GDM's login screen runs as a user of its own.
    fn greeter() -> Active {
        Active::Session {
            id: "c1".into(),
            uid: 120,
        }
    }

    /// What a daemon loop serving plugged devices produced.
    struct Plugged {
        /// The host side of each device the loop created.
        devices: mpsc::Receiver<DevicePeer>,
        ready: mpsc::Receiver<()>,
        result: mpsc::Receiver<io::Result<()>>,
    }

    impl Plugged {
        fn next_device(&self) -> DevicePeer {
            self.devices
                .recv_timeout(TIMEOUT)
                .expect("no device was plugged in")
        }

        fn assert_no_device(&self) {
            assert!(
                self.devices.recv_timeout(QUIET).is_err(),
                "a device was plugged in"
            );
        }
    }

    /// Serve the CTAP app, asking `presence` and running on `clock`, on
    /// devices plugged in while `script` lets one exist, for a key that
    /// runs as [`OWNER`].
    fn start_plugged<C: Clock + 'static>(
        dir: &TempDir,
        presence: impl UserPresence + Send + 'static,
        clock: impl FnOnce() -> io::Result<C> + Send + 'static,
        script: &ScriptedSeat,
        shutdown: &ShutdownSignal,
    ) -> Plugged {
        let data = app_data(dir);
        let seat = Seat::new(script.clone(), OWNER);
        let shutdown = shutdown.clone();
        let (device_sender, devices) = mpsc::channel();
        let (ready_sender, ready) = mpsc::channel();
        let (result_sender, result) = mpsc::channel();
        thread::spawn(move || {
            let plug = move || {
                let (device, peer) = socket_device();
                device_sender.send(peer).map_err(io::Error::other)?;
                Ok(device)
            };
            let result = serve_plugged_with_presence(
                plug,
                seat,
                data,
                presence,
                clock,
                shutdown,
                move || {
                    let _ = ready_sender.send(());
                    Ok(())
                },
            );
            if let Err(err) = &result
                && !is_shutdown(err)
            {
                eprintln!("the loop failed: {err}");
            }
            let _ = result_sender.send(result);
        });
        Plugged {
            devices,
            ready,
            result,
        }
    }

    /// The next event on `host` is its device's destruction.
    fn assert_destroyed(host: &Host) {
        match host.next(TIMEOUT).expect("the device was not destroyed") {
            Event::Destroyed => {}
            event => panic!("unexpected {event:?}"),
        }
    }

    /// While another user's session or a login screen is active on the
    /// seat, the key runs without a device; the owner's session brings one,
    /// and so does a seat with no active session. Another user's session
    /// becoming active as a request arrives leaves the request unanswered
    /// and removes the device. A new record that leaves nobody else active
    /// replaces the device.
    #[test]
    fn the_device_exists_only_while_no_other_users_session_is_active() {
        let dir = TempDir::new("seat-plug");
        let script = ScriptedSeat::new(other());
        let shutdown = ShutdownSignal::new();
        let plugged = start_plugged(
            &dir,
            AutoApprove,
            crate::test_support::clock,
            &script,
            &shutdown,
        );
        plugged
            .ready
            .recv_timeout(TIMEOUT)
            .expect("the key never said it runs");
        plugged.assert_no_device();
        script.switch(&[greeter()]);
        plugged.assert_no_device();

        script.switch(&[owner()]);
        let mut host = Host::new(plugged.next_device());
        let cid = host.init();
        host.send(cid, CTAPHID_PING, b"owner");
        assert_eq!(host.receive(cid), (CTAPHID_PING, b"owner".to_vec()));

        script.switch_at_next_report(&[other()]);
        host.send(cid, CTAPHID_PING, b"theirs");
        assert_destroyed(&host);
        plugged.assert_no_device();

        script.switch(&[Active::Nobody]);
        let mut host = Host::new(plugged.next_device());
        let cid = host.init();
        host.send(cid, CTAPHID_PING, b"nobody");
        assert_eq!(host.receive(cid), (CTAPHID_PING, b"nobody".to_vec()));

        // Every save of the record replaces the device, also one that leaves
        // nobody else active.
        script.switch(&[Active::Nobody]);
        assert_destroyed(&host);
        let mut host = Host::new(plugged.next_device());
        let cid = host.init();
        host.send(cid, CTAPHID_PING, b"replaced");
        assert_eq!(host.receive(cid), (CTAPHID_PING, b"replaced".to_vec()));
        plugged.assert_no_device();
        shut_down(&host, &shutdown, plugged.result);
    }

    /// A switch to another user and back between two looks replaces the
    /// device, although the owner is active at both. The new device knows
    /// none of the old one's channels.
    #[test]
    fn a_switch_away_and_back_between_two_looks_replaces_the_device() {
        let dir = TempDir::new("seat-replug");
        let script = ScriptedSeat::new(owner());
        let shutdown = ShutdownSignal::new();
        let plugged = start_plugged(
            &dir,
            AutoApprove,
            crate::test_support::clock,
            &script,
            &shutdown,
        );
        let mut host = Host::new(plugged.next_device());
        let cid = host.init();
        host.send(cid, CTAPHID_PING, b"before");
        assert_eq!(host.receive(cid), (CTAPHID_PING, b"before".to_vec()));

        for away in [other(), greeter()] {
            script.switch(&[away, owner()]);
            assert_destroyed(&host);
            host = Host::new(plugged.next_device());
            // Resynchronising the old channel is refused: it was never
            // allocated on this device.
            host.send(cid, CTAPHID_INIT, &[9; 8]);
            assert_eq!(
                host.receive(cid),
                (CTAPHID_ERROR, vec![ERR_INVALID_CHANNEL])
            );
            let cid = host.init();
            host.send(cid, CTAPHID_PING, b"after");
            assert_eq!(host.receive(cid), (CTAPHID_PING, b"after".to_vec()));
        }
        plugged.assert_no_device();
        shut_down(&host, &shutdown, plugged.result);
    }

    /// Another user's session becoming active while the owner is asked to
    /// approve cancels the prompt: nothing is approved, the request is not
    /// answered, and the device goes. The engine carries on on the next
    /// device.
    #[test]
    fn unplugging_cancels_the_prompt_and_answers_nothing() {
        let dir = TempDir::new("seat-prompt");
        let (asked_sender, asked) = mpsc::channel();
        let (answer_sender, answers) = mpsc::channel();
        let (outcome_sender, outcomes) = mpsc::channel();
        let prompt = Prompt {
            asked: asked_sender,
            answers,
            outcomes: outcome_sender,
        };
        let handle = PromptHandle {
            asked,
            answers: answer_sender,
            outcomes,
        };
        let script = ScriptedSeat::new(owner());
        let shutdown = ShutdownSignal::new();
        let plugged = start_plugged(&dir, prompt, crate::test_support::clock, &script, &shutdown);
        let mut host = Host::new(plugged.next_device());
        let cid = host.init();
        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        handle.wait_until_asked();

        script.switch(&[other()]);
        assert_eq!(handle.outcome(), PresenceOutcome::Cancelled);
        loop {
            match host.next(TIMEOUT).expect("the device was not destroyed") {
                Event::Destroyed => break,
                Event::Message(_, channel, CTAPHID_KEEPALIVE, _) if channel == cid => {}
                event => panic!("unexpected {event:?}"),
            }
        }
        plugged.assert_no_device();

        script.switch(&[owner()]);
        let mut host = Host::new(plugged.next_device());
        let cid = host.init();
        host.send(cid, CTAPHID_CBOR, &[CTAP_GET_INFO]);
        let (command, payload) = host.receive(cid);
        assert_eq!((command, payload[0]), (CTAPHID_CBOR, CTAP2_OK));
        host.assert_quiet();
        shut_down(&host, &shutdown, plugged.result);
    }

    /// A clock the test sets.
    struct ManualClock(Arc<AtomicU64>);

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    /// The command line's client on a device's host side.
    struct Link(DevicePeer);

    impl ReportLink for Link {
        fn send(&mut self, report: &Report) -> io::Result<()> {
            self.0.send(report)
        }

        fn receive(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
            self.0.receive(timeout)
        }
    }

    /// A new device is not a new power-up: three wrong PINs in a row still
    /// block PIN checks on it, and the reset window still counts from when
    /// the key started.
    #[test]
    fn a_new_device_is_not_a_power_up() {
        let dir = TempDir::new("seat-power");
        let millis = Arc::new(AtomicU64::new(0));
        let clock = {
            let millis = Arc::clone(&millis);
            move || Ok(ManualClock(millis))
        };
        let script = ScriptedSeat::new(owner());
        let shutdown = ShutdownSignal::new();
        let plugged = start_plugged(&dir, AutoApprove, clock, &script, &shutdown);
        let mut key = Authenticator::open(Link(plugged.next_device())).unwrap();
        // Within the window a reset works.
        key.reset(&mut |_| {}).unwrap();
        key.set_pin(b"1234").unwrap();
        for status in [
            CTAP2_ERR_PIN_INVALID,
            CTAP2_ERR_PIN_INVALID,
            CTAP2_ERR_PIN_AUTH_BLOCKED,
        ] {
            let attempt = key.management_token(b"0000");
            assert!(
                matches!(attempt, Err(ClientError::Status(code)) if code == status),
                "{attempt:?}"
            );
        }
        let blocked = PinRetries {
            retries: 5,
            power_cycle_needed: true,
        };
        assert_eq!(key.pin_retries().unwrap(), blocked);
        millis.store(11_000, Ordering::SeqCst);

        script.switch(&[other(), owner()]);
        let mut key = Authenticator::open(Link(plugged.next_device())).unwrap();
        assert_eq!(key.pin_retries().unwrap(), blocked);
        let attempt = key.management_token(b"1234");
        assert!(
            matches!(
                attempt,
                Err(ClientError::Status(CTAP2_ERR_PIN_AUTH_BLOCKED))
            ),
            "{attempt:?}"
        );
        let reset = key.reset(&mut |_| {});
        assert!(
            matches!(reset, Err(ClientError::Status(CTAP2_ERR_NOT_ALLOWED))),
            "{reset:?}"
        );
        shutdown.request();
        let result = plugged
            .result
            .recv_timeout(TIMEOUT)
            .expect("the loop did not return after shutdown was requested");
        assert!(is_shutdown(&result.unwrap_err()));
    }

    /// Shutdown is honoured while the key waits for the seat, without a
    /// device ever being created.
    #[test]
    fn shutdown_while_the_device_waits_for_the_seat() {
        let dir = TempDir::new("seat-shutdown");
        let script = ScriptedSeat::new(greeter());
        let shutdown = ShutdownSignal::new();
        let plugged = start_plugged(
            &dir,
            AutoApprove,
            crate::test_support::clock,
            &script,
            &shutdown,
        );
        plugged.ready.recv_timeout(TIMEOUT).unwrap();
        shutdown.request();
        let result = plugged
            .result
            .recv_timeout(TIMEOUT)
            .expect("the loop did not return after shutdown was requested");
        assert!(is_shutdown(&result.unwrap_err()));
        plugged.assert_no_device();
    }
}
