use std::{
    io,
    path::{Path, PathBuf},
};

use authenticator::ctap::CtapApp;
use sha2::{Digest, Sha256};
use transport_core::state::{
    reset_state_dir, IdentityConfig, PersistentStore, StoredPinState, DEFAULT_PIN_RETRIES,
};
use transport_core::{set_waiting, Apps as TrussedApps, Builder, Options, Platform, Syscall};
use trussed::{
    backend::{CoreOnly, NoId},
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, NoData},
};

use crate::{exec, HidDeviceDescriptor, CTAPHID_FRAME_LEN};

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
    ctap: CtapApp<crate::Client>,
}

impl<'a> TrussedApps<'a, CoreOnly> for Apps {
    type Data = AppData;

    fn new(
        _service: &mut Service<Platform, CoreOnly>,
        endpoints: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
        syscall: Syscall,
        data: Self::Data,
    ) -> Self {
        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().expect("Trussed channel split");
        let context = CoreContext::new(littlefs2::path!("authenticator").into());
        endpoints.push(ServiceEndpoint::new(responder, context, &[]));
        let client = crate::Client::new(requester, syscall, None);
        let mut ctap = CtapApp::new(client, data.aaguid);
        ctap.set_auto_user_presence(data.auto_user_presence);
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

    #[cfg(feature = "ccid")]
    fn with_ccid_apps<T, const N: usize>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn apdu_dispatch::app::App<N>]) -> T,
    ) -> T {
        f(&mut [])
    }
}

pub fn run(config: RunnerConfig) -> io::Result<()> {
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
            exec(runner, descriptor, platform, data)
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

pub fn default_identity() -> IdentityStrings {
    IdentityStrings {
        manufacturer: "Feitian Technologies Co., Ltd.".to_string(),
        product: "Feitian FIDO2 Software Authenticator (ML-DSA)".to_string(),
        serial: "FEITIAN-PQC-001".to_string(),
    }
}

pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    transport_core::state::ensure_state_dir(path)
}

/// Minimum PIN length enforced by the CTAP layer.
const MIN_PIN_LENGTH: usize = 4;
/// Maximum PIN length permitted by CTAP (63 byte UTF-8 string max).
const MAX_PIN_LENGTH: usize = 63;

fn validate_pin(pin: &str) -> io::Result<()> {
    let bytes = pin.as_bytes();
    if bytes.len() < MIN_PIN_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PIN must be at least {MIN_PIN_LENGTH} bytes"),
        ));
    }
    if bytes.len() > MAX_PIN_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("PIN must be at most {MAX_PIN_LENGTH} bytes"),
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
        blocked: state.pin_auth_blocked,
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
    verify_current_pin(&mut state, current_pin)?;
    state.pin_hash = Some(hash_pin(new_pin));
    state.pin_retries = DEFAULT_PIN_RETRIES;
    state.consecutive_failures = 0;
    state.pin_auth_blocked = false;
    store.write_pin_state(&state)
}

/// Clear the PIN after verifying the current one.
pub fn pin_remove(state_dir: &Path, current_pin: &str) -> io::Result<()> {
    let store = PersistentStore::new(state_dir)?;
    let mut state = store.read_pin_state()?;
    verify_current_pin(&mut state, current_pin)?;
    state.pin_hash = None;
    state.pin_retries = DEFAULT_PIN_RETRIES;
    state.consecutive_failures = 0;
    state.pin_auth_blocked = false;
    store.write_pin_state(&state)
}

/// Wipe credentials and reset PIN state.  Equivalent to a factory reset.
pub fn reset_state(state_dir: &Path) -> io::Result<()> {
    reset_state_dir(state_dir)
}

fn verify_current_pin(state: &mut StoredPinState, candidate: &str) -> io::Result<()> {
    let stored = state.pin_hash.ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "no PIN is currently set")
    })?;
    if state.pin_auth_blocked {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PIN is blocked until the authenticator is reset",
        ));
    }
    let provided = hash_pin(candidate);
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(provided.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        state.pin_retries = DEFAULT_PIN_RETRIES;
        state.consecutive_failures = 0;
        Ok(())
    } else {
        if state.pin_retries > 0 {
            state.pin_retries -= 1;
        }
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.pin_retries == 0 {
            state.pin_auth_blocked = true;
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "PIN is incorrect ({} retries remaining)",
                state.pin_retries
            ),
        ))
    }
}
