use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use authenticator::ctap::{presence::AutoApprove, CtapApp, InterruptFlag};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use transport_core::state::{
    reset_state_dir, IdentityConfig, PersistentStore, StoredPinState, DEFAULT_PIN_RETRIES,
};
use transport_core::{
    set_waiting, Apps as TrussedApps, Builder, Client, Options, Platform, Syscall,
};
use trussed::{
    backend::{CoreOnly, NoId},
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};

use crate::{
    exec,
    shutdown::{is_shutdown, ok_if_shutdown, ShutdownSignal},
    HidDeviceDescriptor, CTAPHID_FRAME_LEN,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Uhid,
}

#[derive(Clone)]
pub struct IdentityStrings {
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
}

pub struct RunnerConfig {
    pub descriptor: HidDeviceDescriptor,
    pub options: Options,
    pub state_dir: PathBuf,
    pub aaguid: [u8; 16],
    pub identity: IdentityStrings,
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
    pub backend: Backend,
}

#[derive(Clone, Copy)]
pub struct AppData {
    pub aaguid: [u8; 16],
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
}

pub struct Apps {
    ctap: CtapApp<Client>,
}

impl<'a> TrussedApps<'a, CoreOnly> for Apps {
    type Data = AppData;

    fn new(
        service: &mut Service<Platform, CoreOnly>,
        endpoints: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
        syscall: Syscall,
        data: Self::Data,
    ) -> Self {
        // Only one `Apps` can exist at a time; the channel is released again
        // when the runner drops it.
        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().expect("Trussed channel split");
        let context = CoreContext::new(littlefs2::path!("authenticator").into());
        endpoints.push(ServiceEndpoint::new(responder, context, &[]));
        let client = Client::new(requester, syscall, None);
        // Cancels the request being processed. There is one `Apps` at a time.
        static INTERRUPT: InterruptFlag = InterruptFlag::new();
        if !data.auto_user_presence {
            log::warn!(
                "asking the user for presence is not implemented yet; approving every request"
            );
        }
        let mut ctap = serving_syscalls(service, endpoints, || {
            CtapApp::new(client, OsRng, AutoApprove, &INTERRUPT, data.aaguid)
        });
        ctap.suppress_attestation(data.suppress_attestation);
        ctap.set_keepalive_callback(set_waiting);
        Self { ctap }
    }

    fn with_ctaphid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'a, N>]) -> T,
    ) -> T {
        f(&mut [&mut self.ctap])
    }
}

/// Run `construct` while another thread answers Trussed requests.
///
/// `CtapApp::new` reads the persisted PIN state through a Trussed syscall and
/// busy-waits for the reply, but `transport_core::Runner::exec` only starts
/// the thread that answers syscalls after `Apps::new` has returned. Without
/// this, startup never gets past constructing the app.
fn serving_syscalls<T>(
    service: &mut Service<Platform, CoreOnly>,
    endpoints: &mut [ServiceEndpoint<'static, NoId, NoData>],
    construct: impl FnOnce() -> T,
) -> T {
    /// Stops the helper thread even if `construct` panics.
    struct SetOnDrop<'a>(&'a AtomicBool);

    impl Drop for SetOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let constructed = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            while !constructed.load(Ordering::Acquire) {
                service.process(endpoints);
                thread::sleep(Duration::from_millis(1));
            }
        });
        let _stop_helper = SetOnDrop(&constructed);
        construct()
    })
}

/// Run the authenticator until the device fails or `shutdown` is requested.
/// A requested shutdown returns `Ok(())`. `on_ready` runs once the virtual
/// device exists.
pub fn run(
    config: RunnerConfig,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let RunnerConfig {
        descriptor,
        options,
        state_dir,
        aaguid,
        identity,
        auto_user_presence,
        suppress_attestation,
        backend,
    } = config;

    let mut persistent = PersistentStore::new(&state_dir)?;
    persistent.initialize_identity(IdentityConfig {
        aaguid,
        manufacturer: &identity.manufacturer,
        product: &identity.product,
        serial: &identity.serial,
    })?;
    let store = persistent.store();
    let platform = Platform::new(store);
    let data = AppData {
        aaguid,
        auto_user_presence,
        suppress_attestation,
    };

    match backend {
        Backend::Uhid => {
            let runner = Builder::new(options).build::<Apps>();
            let result = exec(runner, descriptor, platform, data, shutdown, on_ready);
            if result.as_ref().is_err_and(is_shutdown) {
                log::info!("shutdown requested; the virtual authenticator has been removed");
            }
            ok_if_shutdown(result)
        }
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

pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    transport_core::state::ensure_state_dir(path)
}

/// Minimum PIN length in Unicode code points (CTAP 2.1 section 6.5.1).
pub const MIN_PIN_CODE_POINTS: usize = 4;
/// Maximum PIN length in bytes of UTF-8 (CTAP 2.1 section 6.5.1).
pub const MAX_PIN_BYTES: usize = 63;

/// Check a new PIN against the CTAP 2.1 composition rules: at least
/// [`MIN_PIN_CODE_POINTS`] code points, at most [`MAX_PIN_BYTES`] bytes, and no
/// trailing NUL (CTAP pads PINs with NUL bytes, so a platform could never send
/// such a PIN).
pub fn validate_pin(pin: &str) -> io::Result<()> {
    if pin.chars().count() < MIN_PIN_CODE_POINTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PIN must be at least {MIN_PIN_CODE_POINTS} characters long"),
        ));
    }
    if pin.len() > MAX_PIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PIN must be at most {MAX_PIN_BYTES} bytes long in UTF-8"),
        ));
    }
    if pin.ends_with('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PIN must not end with a NUL character",
        ));
    }
    Ok(())
}

fn hash_pin(pin: &str) -> [u8; 16] {
    let digest = Sha256::digest(pin.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Summary view of the persistent PIN state for the `pin status` CLI.
pub struct PinInfo {
    pub is_set: bool,
    pub retries: u8,
    pub blocked: bool,
}

/// Read the persistent PIN summary for the CLI.
pub fn pin_info(state_dir: &Path) -> io::Result<PinInfo> {
    let store = PersistentStore::new(state_dir)?;
    let state = store.read_pin_state()?;
    Ok(PinInfo {
        is_set: state.pin_hash.is_some(),
        retries: state.pin_retries,
        blocked: pin_is_blocked(&state),
    })
}

/// Persist a brand-new PIN.  Fails if a PIN is already set.
pub fn pin_set(state_dir: &Path, new_pin: &str) -> io::Result<()> {
    validate_pin(new_pin)?;
    let store = PersistentStore::new(state_dir)?;
    let existing = store.read_pin_state()?;
    if existing.pin_hash.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a PIN is already set; use 'pin change' instead",
        ));
    }
    let updated = StoredPinState {
        pin_hash: Some(hash_pin(new_pin)),
        pin_retries: DEFAULT_PIN_RETRIES,
        consecutive_failures: 0,
        pin_auth_blocked: false,
    };
    store.write_pin_state(&updated)
}

/// Persist a replacement PIN after verifying the current one.
pub fn pin_change(state_dir: &Path, current_pin: &str, new_pin: &str) -> io::Result<()> {
    validate_pin(new_pin)?;
    let store = PersistentStore::new(state_dir)?;
    let mut state = store.read_pin_state()?;
    verify_current_pin(&store, &mut state, current_pin)?;
    state.pin_hash = Some(hash_pin(new_pin));
    store.write_pin_state(&state)
}

/// Clear the PIN after verifying the current one.
pub fn pin_remove(state_dir: &Path, current_pin: &str) -> io::Result<()> {
    let store = PersistentStore::new(state_dir)?;
    let mut state = store.read_pin_state()?;
    verify_current_pin(&store, &mut state, current_pin)?;
    state.pin_hash = None;
    store.write_pin_state(&state)
}

/// Wipe credentials and reset PIN state.  Equivalent to a factory reset.
pub fn reset_state(state_dir: &Path) -> io::Result<()> {
    reset_state_dir(state_dir)
}

/// Whether PIN verification is refused outright. `pin_retries == 0` is the
/// permanent block; `pin_auth_blocked` is also set by the CTAP side after
/// repeated failures, and is honoured here as well.
fn pin_is_blocked(state: &StoredPinState) -> bool {
    state.pin_auth_blocked || state.pin_retries == 0
}

/// Check `candidate` against the stored PIN, spending one retry.
///
/// As in CTAP 2.1 (section 6.5.5.6), the retry counter is decremented and
/// written to disk *before* the comparison, so an attempt always counts even
/// if the process is killed before it reports the result. On success the
/// counters in `state` are reset; the caller persists that together with the
/// change the PIN was verified for.
fn verify_current_pin(
    store: &PersistentStore,
    state: &mut StoredPinState,
    candidate: &str,
) -> io::Result<()> {
    let stored = state.pin_hash.ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "no PIN is currently set")
    })?;
    if pin_is_blocked(state) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PIN is blocked until the authenticator is reset",
        ));
    }
    // Every PIN ever accepted, by this CLI or over CTAP, is at least
    // MIN_PIN_CODE_POINTS bytes and at most MAX_PIN_BYTES bytes long, so a
    // candidate outside that range cannot match. Reject it without spending a
    // retry, e.g. when Enter is pressed at the prompt by accident.
    if candidate.len() < MIN_PIN_CODE_POINTS || candidate.len() > MAX_PIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PIN is incorrect (it has an impossible length; no retry was used)",
        ));
    }

    state.pin_retries -= 1;
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    if state.pin_retries == 0 {
        state.pin_auth_blocked = true;
    }
    store.write_pin_state(state)?;

    if hashes_match(&stored, &hash_pin(candidate)) {
        state.pin_retries = DEFAULT_PIN_RETRIES;
        state.consecutive_failures = 0;
        state.pin_auth_blocked = false;
        Ok(())
    } else if state.pin_retries == 0 {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PIN is incorrect; no retries remain and the PIN is now blocked until the authenticator is reset",
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("PIN is incorrect ({} retries remaining)", state.pin_retries),
        ))
    }
}

/// Compare two PIN hashes without an early exit on the first difference.
fn hashes_match(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use ctaphid_dispatch::{
        app::{App, Command},
        DEFAULT_MESSAGE_SIZE,
    };
    use heapless_bytes::Bytes;
    use std::sync::mpsc;
    use transport_core::Transport;

    // Test characters by UTF-8 width, so the boundaries below are explicit.
    const TWO_BYTES: &str = "\u{e9}"; // e with acute accent
    const THREE_BYTES: &str = "\u{20ac}"; // euro sign
    const FOUR_BYTES: &str = "\u{1f511}"; // key emoji

    #[test]
    fn test_characters_have_the_expected_utf8_widths() {
        assert_eq!(TWO_BYTES.len(), 2);
        assert_eq!(THREE_BYTES.len(), 3);
        assert_eq!(FOUR_BYTES.len(), 4);
    }

    #[test]
    fn minimum_pin_length_counts_code_points_not_bytes() {
        // Enough bytes, too few code points.
        assert!(validate_pin(&TWO_BYTES.repeat(2)).is_err()); // 4 bytes, 2 code points
        assert!(validate_pin(&THREE_BYTES.repeat(3)).is_err()); // 9 bytes, 3 code points
        assert!(validate_pin(&FOUR_BYTES.repeat(3)).is_err()); // 12 bytes, 3 code points
        assert!(validate_pin("abc").is_err());
        assert!(validate_pin("").is_err());

        // Four code points are enough however they are encoded.
        assert!(validate_pin("abcd").is_ok());
        assert!(validate_pin(&TWO_BYTES.repeat(4)).is_ok());
        assert!(validate_pin(&FOUR_BYTES.repeat(4)).is_ok());
        assert!(validate_pin(&format!("ab{TWO_BYTES}{THREE_BYTES}")).is_ok());
    }

    #[test]
    fn maximum_pin_length_counts_bytes_not_code_points() {
        let at_limit = THREE_BYTES.repeat(21);
        assert_eq!(at_limit.len(), MAX_PIN_BYTES);
        assert!(validate_pin(&at_limit).is_ok());

        let at_limit_mixed = format!("{}{TWO_BYTES}", "a".repeat(61));
        assert_eq!(at_limit_mixed.len(), MAX_PIN_BYTES);
        assert!(validate_pin(&at_limit_mixed).is_ok());

        // 63 code points, but the last one takes the encoding to 64 bytes.
        let over_limit = format!("{}{TWO_BYTES}", "a".repeat(62));
        assert_eq!(over_limit.chars().count(), 63);
        assert!(validate_pin(&over_limit).is_err());

        // Only 16 code points, but 64 bytes.
        assert!(validate_pin(&FOUR_BYTES.repeat(16)).is_err());
    }

    #[test]
    fn pin_must_not_end_with_nul() {
        assert!(validate_pin("1234\u{0}").is_err());
        assert!(validate_pin("12\u{0}34").is_ok());
    }

    const PIN: &str = "1234";
    const WRONG_PIN: &str = "9999";
    const NEW_PIN: &str = "5678";

    /// Read the PIN state back through a fresh mount, as the next CLI
    /// invocation would.
    fn state_on_disk(dir: &Path) -> StoredPinState {
        PersistentStore::new(dir)
            .expect("mount state")
            .read_pin_state()
            .expect("read PIN state")
    }

    #[test]
    fn wrong_pin_decrements_the_retry_counter_on_disk() {
        let dir = TempDir::new("pin-retries");
        pin_set(dir.path(), PIN).unwrap();

        let err = pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_retries, DEFAULT_PIN_RETRIES - 1);
        assert_eq!(state.consecutive_failures, 1);
        assert!(!state.pin_auth_blocked);

        // The next invocation continues from the persisted counter, whichever
        // command it is.
        let err = pin_remove(dir.path(), WRONG_PIN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_retries, DEFAULT_PIN_RETRIES - 2);
        assert_eq!(state.consecutive_failures, 2);
        assert_eq!(state.pin_hash, Some(hash_pin(PIN)));
    }

    #[test]
    fn pin_blocks_when_retries_run_out_and_then_refuses_the_correct_pin() {
        let dir = TempDir::new("pin-block");
        pin_set(dir.path(), PIN).unwrap();
        for _ in 0..DEFAULT_PIN_RETRIES {
            let err = pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }

        let info = pin_info(dir.path()).unwrap();
        assert!(info.is_set);
        assert_eq!(info.retries, 0);
        assert!(info.blocked);

        for result in [
            pin_change(dir.path(), PIN, NEW_PIN),
            pin_remove(dir.path(), PIN),
        ] {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_hash, Some(hash_pin(PIN)));
        assert_eq!(state.pin_retries, 0);
        assert!(state.pin_auth_blocked);
    }

    #[test]
    fn correct_pin_resets_the_failure_counters() {
        let dir = TempDir::new("pin-reset-counters");
        pin_set(dir.path(), PIN).unwrap();
        for _ in 0..DEFAULT_PIN_RETRIES - 1 {
            pin_change(dir.path(), WRONG_PIN, NEW_PIN).unwrap_err();
        }
        assert_eq!(state_on_disk(dir.path()).pin_retries, 1);

        // The last remaining retry still accepts the correct PIN.
        pin_change(dir.path(), PIN, NEW_PIN).unwrap();
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_hash, Some(hash_pin(NEW_PIN)));
        assert_eq!(state.pin_retries, DEFAULT_PIN_RETRIES);
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.pin_auth_blocked);

        pin_remove(dir.path(), WRONG_PIN).unwrap_err();
        pin_remove(dir.path(), NEW_PIN).unwrap();
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_hash, None);
        assert_eq!(state.pin_retries, DEFAULT_PIN_RETRIES);
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn rejected_input_does_not_spend_a_retry() {
        let dir = TempDir::new("pin-no-retry");
        pin_set(dir.path(), PIN).unwrap();

        // A current PIN no authenticator could have accepted.
        for impossible in ["", "123", &"1".repeat(MAX_PIN_BYTES + 1)] {
            let err = pin_remove(dir.path(), impossible).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        // An invalid new PIN is refused before the current PIN is checked.
        let err = pin_change(dir.path(), WRONG_PIN, "12").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_retries, DEFAULT_PIN_RETRIES);
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn pin_blocked_by_the_ctap_side_is_honoured() {
        let dir = TempDir::new("pin-auth-blocked");
        pin_set(dir.path(), PIN).unwrap();
        let store = PersistentStore::new(dir.path()).unwrap();
        let mut state = store.read_pin_state().unwrap();
        state.pin_auth_blocked = true;
        state.pin_retries = 5;
        store.write_pin_state(&state).unwrap();

        let err = pin_change(dir.path(), PIN, NEW_PIN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let state = state_on_disk(dir.path());
        assert_eq!(state.pin_retries, 5);
        assert_eq!(state.pin_hash, Some(hash_pin(PIN)));
    }

    /// Sends one CTAP request through the apps and reports its status, then
    /// asks for shutdown and fails like the uhid transport does when it sees
    /// the request.
    struct OneRequestTransport {
        status: mpsc::Sender<Option<u8>>,
        shutdown: ShutdownSignal,
    }

    impl<'interrupt, D: trussed::backend::Dispatch> Transport<'interrupt, D> for OneRequestTransport {
        fn poll<A: TrussedApps<'interrupt, D>>(&mut self, apps: &mut A) -> io::Result<bool> {
            self.shutdown.check()?;
            // authenticatorReset writes to storage, so it only completes if
            // the runner's Trussed service thread is answering syscalls.
            const CTAP_RESET: u8 = 0x07;
            let status = apps.with_ctaphid_apps(
                |apps: &mut [&mut dyn App<'interrupt, DEFAULT_MESSAGE_SIZE>]| {
                    let mut response = Bytes::new();
                    apps[0]
                        .call(Command::Cbor, &[CTAP_RESET], &mut response)
                        .ok()
                        .and_then(|()| response.first().copied())
                },
            );
            let _ = self.status.send(status);
            self.shutdown.request();
            Ok(true)
        }

        fn send(&mut self, _waiting_for_user: bool) -> io::Result<bool> {
            Ok(false)
        }

        fn wait(&mut self) -> io::Result<()> {
            self.shutdown.check()
        }
    }

    /// `Runner::exec` must get through `Apps::new`, answer requests, and
    /// return once shutdown is requested. Returning requires every Trussed
    /// client (and with it every syscall sender) to be dropped, or the scoped
    /// service thread never finishes and `exec` hangs.
    ///
    /// This is the only test that constructs `Apps`, whose Trussed channel is
    /// a process-wide static.
    #[test]
    fn runner_answers_requests_and_returns_when_shutdown_is_requested() {
        let dir = TempDir::new("runner");
        let state_dir = dir.path().to_owned();
        let (status_tx, status_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        thread::spawn(move || {
            let store = PersistentStore::new(&state_dir).expect("mount state");
            let options = Options {
                manufacturer: None,
                product: None,
                serial_number: None,
                vid: 0,
                pid: 0,
                device_class: None,
            };
            let data = AppData {
                aaguid: [0; 16],
                auto_user_presence: true,
                suppress_attestation: false,
            };
            let transport = OneRequestTransport {
                status: status_tx,
                shutdown: ShutdownSignal::new(),
            };
            let result = Builder::new(options).build::<Apps>().exec(
                Platform::new(store.store()),
                data,
                transport,
            );
            let _ = result_tx.send(result);
        });

        let timeout = Duration::from_secs(60);
        let status = status_rx
            .recv_timeout(timeout)
            .expect("the runner never polled the transport");
        assert_eq!(status, Some(0), "authenticatorReset did not succeed");
        let result = result_rx
            .recv_timeout(timeout)
            .expect("Runner::exec did not return after shutdown was requested");
        let err = result.unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        assert!(ok_if_shutdown(Err(err)).is_ok());
    }
}
