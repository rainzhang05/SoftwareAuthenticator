use std::{
    io,
    path::{Path, PathBuf},
};

use authenticator::ctap::{presence::AutoApprove, CtapApp, InterruptFlag};
use authenticator::store::{AttestationRecord, CredentialStore, FileStore};

use crate::{
    attestation::{generate_attestation_certificate, IdentityConfig},
    create_device, exec,
    shutdown::{is_shutdown, ok_if_shutdown, ShutdownSignal},
    state::remove_and_log_legacy_state,
    uhid::UhidDevice,
    HidDeviceDescriptor, WaitingForUser, CTAPHID_FRAME_LEN,
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
    pub state_dir: PathBuf,
    pub aaguid: [u8; 16],
    pub identity: IdentityStrings,
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
    pub allow_late_reset: bool,
    pub backend: Backend,
}

/// What the CTAP app is built from.
pub struct AppData {
    /// The credential store in the state directory.
    pub store: FileStore,
    pub aaguid: [u8; 16],
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
    /// Accept authenticatorReset after the CTAP start-up window (test rigs only).
    pub allow_late_reset: bool,
}

/// Open the credential store in `state_dir`, and provision the attestation key
/// and certificate if it has none.
///
/// A stored attestation record that cannot be read is left alone for
/// inspection; registrations then use self attestation.
pub fn open_credential_store(
    state_dir: &Path,
    identity: IdentityConfig<'_>,
) -> io::Result<FileStore> {
    let mut store = FileStore::open(state_dir).map_err(io::Error::other)?;
    match store.attestation() {
        Ok(Some(_)) => {}
        Ok(None) => {
            let (private_key, certificate) = generate_attestation_certificate(&identity)?;
            let record = AttestationRecord {
                private_key: *private_key,
                certificate_chain: vec![certificate],
            };
            store.set_attestation(&record).map_err(io::Error::other)?;
            log::info!("provisioned a new attestation key and certificate");
        }
        Err(err) => {
            log::warn!("the attestation record cannot be read ({err}); using self attestation");
        }
    }
    Ok(store)
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
        identity,
        auto_user_presence,
        suppress_attestation,
        allow_late_reset,
        backend,
    } = config;

    remove_and_log_legacy_state(&state_dir)?;
    let store = open_credential_store(
        &state_dir,
        IdentityConfig {
            manufacturer: &identity.manufacturer,
            product: &identity.product,
            serial: &identity.serial,
        },
    )?;
    let data = AppData {
        store,
        aaguid,
        auto_user_presence,
        suppress_attestation,
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
///
/// The app runs on this thread, inside the loop: a request that waits for the
/// user blocks the loop until it is answered.
pub fn serve_ctap(
    device: UhidDevice,
    data: AppData,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Through this the CTAPHID dispatcher cancels the request being processed.
    let interrupt = InterruptFlag::new();
    let waiting = WaitingForUser::new();
    if !data.auto_user_presence {
        log::warn!("asking the user for presence is not implemented yet; approving every request");
    }
    let mut ctap = CtapApp::with_file_store(data.store, AutoApprove, &interrupt, data.aaguid);
    ctap.suppress_attestation(data.suppress_attestation);
    if data.allow_late_reset {
        log::warn!("accepting authenticatorReset at any time (--allow-late-reset); this does not conform to CTAP");
        ctap.set_reset_window(None);
    }
    let app_waiting = waiting.clone();
    ctap.set_keepalive_callback(move |waiting| app_waiting.set(waiting));
    exec(device, &mut [&mut ctap], &waiting, shutdown, on_ready)
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
    use crate::{test_support::TempDir, uhid};
    use std::{
        io::{Read, Write},
        os::{fd::OwnedFd, unix::net::UnixStream},
        sync::mpsc,
        thread,
        time::Duration,
    };

    const BROADCAST_CID: u32 = 0xffff_ffff;
    const CTAPHID_INIT: u8 = 0x86;
    const CTAPHID_CBOR: u8 = 0x90;
    const CTAPHID_KEEPALIVE: u8 = 0xbb;

    /// The host side of a uhid device: one end of a socket pair that speaks
    /// uhid events.
    struct Host(UnixStream);

    impl Host {
        /// Send a single-packet CTAPHID request.
        fn send(&mut self, cid: u32, command: u8, payload: &[u8]) {
            let mut frame = [0u8; uhid::CTAPHID_FRAME_LEN];
            frame[..4].copy_from_slice(&cid.to_be_bytes());
            frame[4] = command;
            frame[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            frame[7..7 + payload.len()].copy_from_slice(payload);
            self.0.write_all(&uhid::output_event(&frame)).unwrap();
        }

        /// The next single-packet CTAPHID response that is not a keepalive:
        /// its command and payload.
        fn receive(&mut self, cid: u32) -> (u8, Vec<u8>) {
            loop {
                let mut event = vec![0u8; uhid::UHID_EVENT_SIZE];
                self.0.read_exact(&mut event).unwrap();
                let frame = uhid::input_report(&event).expect("an input report");
                assert_eq!(u32::from_be_bytes(frame[..4].try_into().unwrap()), cid);
                if frame[4] == CTAPHID_KEEPALIVE {
                    continue;
                }
                let length = u16::from_be_bytes([frame[5], frame[6]]) as usize;
                assert!(length <= frame.len() - 7, "a multi-packet response");
                return (frame[4], frame[7..7 + length].to_vec());
            }
        }
    }

    /// The daemon loop must build the CTAP app, answer a request that goes
    /// through the whole stack (uhid events, CTAPHID framing, the dispatcher,
    /// the app and its credential store), and return once shutdown is
    /// requested, destroying the device on the way out.
    #[test]
    fn runner_answers_requests_and_returns_when_shutdown_is_requested() {
        let dir = TempDir::new("runner");
        let (device_end, host_end) = UnixStream::pair().unwrap();
        device_end.set_nonblocking(true).unwrap();
        host_end
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut host = Host(host_end);
        let device = UhidDevice::from_fd(OwnedFd::from(device_end), HidDeviceDescriptor::default());
        let data = AppData {
            store: FileStore::open(dir.path()).expect("open credential store"),
            aaguid: [0; 16],
            auto_user_presence: true,
            suppress_attestation: false,
            allow_late_reset: false,
        };

        let shutdown = ShutdownSignal::new();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let loop_shutdown = shutdown.clone();
        thread::spawn(move || {
            let result = serve_ctap(device, data, loop_shutdown, || {
                ready_tx.send(()).unwrap();
                Ok(())
            });
            let _ = result_tx.send(result);
        });
        let timeout = Duration::from_secs(60);
        ready_rx
            .recv_timeout(timeout)
            .expect("the loop never became ready");

        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        host.send(BROADCAST_CID, CTAPHID_INIT, &nonce);
        let (command, payload) = host.receive(BROADCAST_CID);
        assert_eq!(command, CTAPHID_INIT);
        assert_eq!(payload[..8], nonce);
        let cid = u32::from_be_bytes(payload[8..12].try_into().unwrap());

        // authenticatorReset clears the credential store, so this also checks
        // the store handed to the app works.
        const CTAP_RESET: u8 = 0x07;
        host.send(cid, CTAPHID_CBOR, &[CTAP_RESET]);
        let (command, payload) = host.receive(cid);
        assert_eq!(command, CTAPHID_CBOR);
        assert_eq!(payload, [0], "authenticatorReset did not succeed");

        shutdown.request();
        let result = result_rx
            .recv_timeout(timeout)
            .expect("the loop did not return after shutdown was requested");
        let err = result.unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        assert!(ok_if_shutdown(Err(err)).is_ok());

        let mut rest = Vec::new();
        host.0.read_to_end(&mut rest).unwrap();
        assert_eq!(
            rest.len(),
            uhid::UHID_EVENT_SIZE,
            "one event after the response"
        );
        let event_type = u32::from_ne_bytes(rest[..4].try_into().unwrap());
        assert_eq!(event_type, uhid::UHID_EVENT_TYPE_DESTROY);
    }
}
