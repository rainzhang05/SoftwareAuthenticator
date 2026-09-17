use std::{
    io,
    path::{Path, PathBuf},
};

use authenticator::ctap::{presence::AutoApprove, CtapApp, InterruptFlag};
use authenticator::store::{AttestationRecord, CredentialStore, FileStore};
use transport_core::state::{generate_attestation_certificate, IdentityConfig, PersistentStore};
use transport_core::{set_waiting, Apps as TrussedApps, Builder, Options, Platform, Syscall};
use trussed::{
    backend::{CoreOnly, NoId},
    pipe::ServiceEndpoint,
    service::Service,
    types::NoData,
};
use zeroize::Zeroize;

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

pub struct AppData {
    /// The credential store in the state directory.
    pub store: FileStore,
    pub aaguid: [u8; 16],
    pub auto_user_presence: bool,
    pub suppress_attestation: bool,
}

pub struct Apps {
    ctap: CtapApp<'static>,
}

impl<'a> TrussedApps<'a, CoreOnly> for Apps {
    type Data = AppData;

    fn new(
        _service: &mut Service<Platform, CoreOnly>,
        _endpoints: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
        _syscall: Syscall,
        data: Self::Data,
    ) -> Self {
        // The CTAP engine makes no Trussed requests, so no client is created
        // and dropping `_syscall` lets the runner's service thread finish.
        //
        // Cancels the request being processed. There is one `Apps` at a time.
        static INTERRUPT: InterruptFlag = InterruptFlag::new();
        if !data.auto_user_presence {
            log::warn!(
                "asking the user for presence is not implemented yet; approving every request"
            );
        }
        let mut ctap = CtapApp::with_file_store(data.store, AutoApprove, &INTERRUPT, data.aaguid);
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
            let (mut private_key, certificate) = generate_attestation_certificate(&identity)?;
            let record = AttestationRecord {
                private_key: private_key.as_slice().try_into().map_err(|_| {
                    io::Error::other("the generated attestation key is not 32 bytes")
                })?,
                certificate_chain: vec![certificate],
            };
            private_key.zeroize();
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

    let credential_store = open_credential_store(
        &state_dir,
        IdentityConfig {
            aaguid,
            manufacturer: &identity.manufacturer,
            product: &identity.product,
            serial: &identity.serial,
        },
    )?;
    // The Trussed runner still needs a platform; the CTAP engine no longer
    // stores anything in it.
    let persistent = PersistentStore::new(&state_dir)?;
    let platform = Platform::new(persistent.store());
    let data = AppData {
        store: credential_store,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use ctaphid_dispatch::{
        app::{App, Command},
        DEFAULT_MESSAGE_SIZE,
    };
    use heapless_bytes::Bytes;
    use std::{sync::mpsc, thread, time::Duration};
    use transport_core::Transport;

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
            // authenticatorReset clears the credential store, so this also
            // checks the store opened for the runner works.
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
                store: FileStore::open(&state_dir).expect("open credential store"),
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
