//! The commands that manage the running key: `status`, `pin`, `config`,
//! `passkeys` and `reset`.
//!
//! They talk to the key over CTAP through its platform client link, as a
//! security
//! key's management application does ([`crate::client`]). So the key itself
//! checks the PIN and counts retries, asks its user to approve a reset, and
//! accepts a reset only shortly after it is plugged in.

use std::{
    io::{self, BufRead, Write},
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use pqkey_ctap::CoseAlg;
use pqkey_ctap::ctap::constants::{
    CTAP2_ERR_KEEPALIVE_CANCEL, CTAP2_ERR_KEY_STORE_FULL, CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_OPERATION_DENIED, CTAP2_ERR_PIN_AUTH_BLOCKED, CTAP2_ERR_PIN_BLOCKED,
    CTAP2_ERR_PIN_INVALID, CTAP2_ERR_PIN_NOT_SET, CTAP2_ERR_PIN_POLICY_VIOLATION,
    CTAP2_ERR_PUAT_REQUIRED, CTAP2_ERR_USER_ACTION_TIMEOUT,
};
use signal_hook::{consts::SIGINT, flag};

use super::ConfigAction;
use super::checks::Problem;
use super::daemon::{self, Running};
use super::output::{self, errln, outln};
use crate::client::ctap2::{Authenticator, ClientError, Info, Passkey, PinRetries, Token};
use crate::client::ctaphid::{ReportLink, STATUS_UPNEEDED};
use crate::pin_input::{MIN_PIN_CODE_POINTS, Pin, PinReader, PinSource, validate_pin};
use crate::platform::{self, ClientLink};
use crate::platform::{System, UserService};
use crate::presence::notification::{ConnectError, Keep, NotificationServer, ServerInfo, sanitise};
use crate::service;
use crate::state::default_state_dir;

/// How long to wait for the running key's device and for access to it.
const DEVICE_WAIT: Duration = Duration::from_secs(5);
/// The same for `status`, which only reports what it finds.
const STATUS_WAIT: Duration = Duration::from_secs(1);

/// What re-plugging the key takes, for the messages that ask for it.
const REPLUG: &str = "pqkey stop && pqkey start";

fn not_running() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "the key is not running; start it with `pqkey start`",
    )
}

fn client_error(err: ClientError) -> io::Error {
    match err {
        ClientError::Hid(crate::client::ctaphid::HidError::Io(err)) => err,
        ClientError::Hid(err @ crate::client::ctaphid::HidError::Busy) => {
            io::Error::new(io::ErrorKind::ResourceBusy, err.to_string())
        }
        err => io::Error::other(err.to_string()),
    }
}

/// The running key on `state_dir`, through its platform client link.
fn connect(state_dir: &Path) -> io::Result<Authenticator<ClientLink>> {
    let running = daemon::running(state_dir)?.ok_or_else(not_running)?;
    connect_to(running, DEVICE_WAIT).map(|(_, key)| key)
}

/// The display label and CTAPHID channel of the key `running`, waiting up
/// to `wait` for its device and access to it.
fn connect_to(running: Running, wait: Duration) -> io::Result<(String, Authenticator<ClientLink>)> {
    let (path, link) = open_node(running, wait)?;
    let key = Authenticator::open(link).map_err(client_error)?;
    Ok((path, key))
}

/// Open the selected platform's client link to this daemon's device.
fn open_node(running: Running, wait: Duration) -> io::Result<(String, ClientLink)> {
    platform::open_client(
        &service::device_uniq(running.pid().as_raw().unsigned_abs()),
        wait,
    )
}

/// Ask `question` on the terminal; only "y" or "yes" is a yes.
fn confirm(question: &str) -> io::Result<bool> {
    ask(question, false)
}

/// Ask `question` on the terminal. An empty answer is `default_yes`.
pub(crate) fn ask(question: &str, default_yes: bool) -> io::Result<bool> {
    {
        let mut stderr = io::stderr().lock();
        let choices = if default_yes { "[Y/n]" } else { "[y/N]" };
        write!(stderr, "{question} {choices} ")?;
        stderr.flush()?;
    }
    // Standard input's own buffer, which PIN lines read before were taken
    // from: a reader of its own could swallow lines meant for later.
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(is_yes(&answer, default_yes))
}

fn is_yes(answer: &str, default_yes: bool) -> bool {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// status

/// `pqkey status`: whether the key runs, its device, PIN and room for
/// passkeys, then every problem found, with its fix.
pub fn status(state_dir: &Path) -> io::Result<()> {
    let system = System::real()?;
    let mut problems = Vec::new();
    let running = match daemon::running(state_dir) {
        Err(err) if err.kind() == io::ErrorKind::ResourceBusy => {
            return outln!("Key:      starting or stopping");
        }
        result => result?,
    };
    match running {
        None => {
            outln!("Key:      not running; `pqkey start` starts it")?;
            problems.extend(system.start_problems()?);
            // `pqkey start` asks with notifications on the default state
            // directory; test rigs choose for themselves.
            if state_dir == default_state_dir() {
                problems.extend(system.notification_problem(&notification_server())?);
            }
        }
        Some(running) => {
            match running {
                Running::Service(pid) => outln!(
                    "Key:      running (pid {pid}, {})",
                    UserService::DESCRIPTION
                )?,
                Running::Daemon(pid) => outln!("Key:      running (pid {pid})")?,
            }
            show_key(running)?;
            problems.extend(running_problems(state_dir, &system, running, STATUS_WAIT)?);
        }
    }
    problems.extend(service_problems(state_dir, running)?);
    if !problems.is_empty() {
        outln!()?;
        output::problems(&problems)?;
    }
    Ok(())
}

/// The lines of `status` about the running key itself.
fn show_key(running: Running) -> io::Result<()> {
    let Ok((path, link)) = open_node(running, STATUS_WAIT) else {
        return outln!("Device:   cannot be opened (see below)");
    };
    let mut key = match Authenticator::open_within(link, STATUS_WAIT) {
        Ok(key) => key,
        Err(ClientError::Hid(crate::client::ctaphid::HidError::Busy)) => {
            return outln!(
                "Device:   {}, busy with another program's request (a browser waiting for your \
                 approval?)",
                path
            );
        }
        Err(err) => return outln!("Device:   {}, not answering: {err}", path),
    };
    outln!("Device:   {}", path)?;
    let info = key.info().map_err(client_error)?;
    match info.pin_set {
        Some(true) => {
            let retries = key.pin_retries().map_err(client_error)?;
            outln!("PIN:      {}", pin_state(retries))?;
        }
        Some(false) => {
            outln!("PIN:      not set; `pqkey pin` sets one (Chromium asks for one)")?;
        }
        None => outln!("PIN:      not supported")?,
    }
    for line in policy_status(&info) {
        outln!("{line}")?;
    }
    if let Some(remaining) = info.remaining_discoverable {
        outln!("Passkeys: room for {remaining} more")?;
    }
    Ok(())
}

fn policy_status(info: &Info) -> Vec<&'static str> {
    let mut lines = Vec::new();
    if info.always_uv == Some(true) {
        lines.push("Always UV: on; registrations and sign-ins require the PIN");
    }
    if info.force_pin_change == Some(true) {
        lines.push("PIN change required; run `pqkey pin`");
    }
    lines
}

fn minimum_pin_length(info: &Info) -> usize {
    info.min_pin_length
        .and_then(|minimum| usize::try_from(minimum).ok())
        .unwrap_or(MIN_PIN_CODE_POINTS)
}

/// What keeps browsers from using the key `running`, waiting up to `wait`
/// for its device: one they cannot open, or notifications that cannot ask.
pub fn running_problems(
    state_dir: &Path,
    system: &System,
    running: Running,
    wait: Duration,
) -> io::Result<Vec<Problem>> {
    let mut problems = system.device_problems(running.pid(), wait)?;
    if asks_with_notifications(state_dir, running) {
        problems.extend(system.notification_problem(&notification_server())?);
    }
    Ok(problems)
}

/// Whether the key `running` asks for presence with notifications, as the
/// user service and `pqkey start` without test options have it do.
fn asks_with_notifications(state_dir: &Path, running: Running) -> bool {
    match running {
        Running::Service(_) => true,
        Running::Daemon(pid) => super::daemon_args_of(state_dir, pid)
            .is_ok_and(|args| args.presence == super::PresenceArg::Notify),
    }
}

/// What the desktop's notification server says about itself.
fn notification_server() -> Result<ServerInfo, ConnectError> {
    let mut bus = platform::notifications().map_err(|err| ConnectError::Failed(err.to_string()))?;
    let server = bus.connect();
    bus.disconnect();
    server
}

/// Whether the installed user service runs the key on the default state
/// directory, as `pqkey setup` arranges.
fn service_problems(state_dir: &Path, running: Option<Running>) -> io::Result<Vec<Problem>> {
    if state_dir != default_state_dir() {
        return Ok(Vec::new());
    }
    if !daemon::uses_service(state_dir)? {
        return Ok(vec![Problem::new(
            "the key does not start with your session",
            "run `pqkey setup`",
        )]);
    }
    Ok(match running {
        Some(Running::Daemon(pid)) => vec![UserService::manual_start_problem(pid)?],
        _ => Vec::new(),
    })
}

/// How often `pqkey setup` asks for a new PIN that was mistyped.
const PIN_ATTEMPTS: usize = 3;

/// The last step of `pqkey setup`: a PIN on the key `running`, which
/// browsers ask for before they use passkeys. Asked for on a terminal, and
/// again if it was mistyped. Returns whether the key has a PIN now.
pub fn ensure_pin(running: Running, interactive: bool) -> io::Result<bool> {
    let Ok((_, mut key)) = connect_to(running, DEVICE_WAIT) else {
        output::problem(
            "the key could not be reached to set its PIN",
            "run `pqkey pin`",
        )?;
        return Ok(false);
    };
    let info = key.info().map_err(client_error)?;
    match info.pin_set {
        Some(true) => {
            if info.force_pin_change == Some(true) {
                output::problem("the key requires a new PIN", "run `pqkey pin`")?;
                return Ok(false);
            }
            output::done("PIN is set")?;
            return Ok(true);
        }
        Some(false) => {}
        // A key without PINs, which pqkey is not.
        None => return Ok(true),
    }
    if !interactive {
        output::problem(
            "the key has no PIN, which browsers ask for before they use passkeys",
            "run `pqkey pin`",
        )?;
        return Ok(false);
    }
    outln!()?;
    let minimum = minimum_pin_length(&info);
    outln!(
        "Choose a PIN for the key, at least {minimum} characters. Browsers ask for it \
         before they use passkeys."
    )?;
    set_first_pin(&mut key, &mut PinReader::from_stdin())?;
    output::done("PIN set")?;
    Ok(true)
}

/// Set a PIN on `key`, which has none, asking `pins` again for one that was
/// mistyped: too short, or not the same twice.
fn set_first_pin<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
) -> io::Result<()> {
    let mut attempt = 1;
    loop {
        match set_or_change_pin(key, pins) {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::InvalidInput && attempt < PIN_ATTEMPTS => {
                errln!("{err}; try again.");
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

fn pin_state(retries: PinRetries) -> String {
    if retries.retries == 0 {
        "blocked; only `pqkey reset` makes the key usable again".into()
    } else if retries.power_cycle_needed {
        format!("set; locked after 3 wrong PINs in a row until re-plugged: {REPLUG}")
    } else {
        format!("set ({} retries left)", retries.retries)
    }
}

// ---------------------------------------------------------------------------
// pin

/// What `pqkey pin` did.
#[derive(Debug, PartialEq, Eq)]
enum PinChange {
    Set,
    Changed,
}

/// `pqkey pin`.
pub fn pin(state_dir: &Path) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    match set_or_change_pin(&mut key, &mut PinReader::from_stdin())? {
        PinChange::Set => outln!("PIN set."),
        PinChange::Changed => outln!("PIN changed."),
    }
}

/// setPIN on a key without a PIN, changePIN on one with a PIN.
fn set_or_change_pin<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
) -> io::Result<PinChange> {
    let info = key.info().map_err(client_error)?;
    let minimum = minimum_pin_length(&info);
    match info.pin_set {
        Some(false) => {
            let new = pins.new_pin(minimum)?;
            key.set_pin(new.as_bytes())
                .map_err(|err| new_pin_error(key, err, minimum, false))?;
            Ok(PinChange::Set)
        }
        Some(true) => {
            check_pin_usable(key)?;
            let current = plausible_pin(pins.current_pin()?)?;
            let new = pins.new_pin(minimum)?;
            let same_pin = *current == *new;
            key.change_pin(current.as_bytes(), new.as_bytes())
                .map_err(|err| new_pin_error(key, err, minimum, same_pin))?;
            Ok(PinChange::Changed)
        }
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the key does not support a PIN",
        )),
    }
}

fn new_pin_error<L: ReportLink>(
    key: &mut Authenticator<L>,
    err: ClientError,
    minimum: usize,
    same_pin: bool,
) -> io::Error {
    if matches!(err, ClientError::Status(CTAP2_ERR_PIN_POLICY_VIOLATION)) {
        let updated = key.info().ok();
        let message = if same_pin
            && updated
                .as_ref()
                .is_some_and(|info| info.force_pin_change == Some(true))
        {
            "the new PIN must differ from the current PIN when a change is required; \
             run `pqkey pin` and choose another PIN"
                .into()
        } else {
            let minimum = updated.as_ref().map_or(minimum, minimum_pin_length);
            format!("the new PIN is too short; choose at least {minimum} characters")
        };
        return io::Error::new(io::ErrorKind::InvalidInput, message);
    }
    pin_error(key, err)
}

fn token_error<L: ReportLink>(key: &mut Authenticator<L>, err: ClientError) -> io::Error {
    if matches!(err, ClientError::Status(CTAP2_ERR_PIN_POLICY_VIOLATION)) {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the key requires a PIN change; run `pqkey pin` before trying again",
        );
    }
    pin_error(key, err)
}

/// Refuse before asking for the PIN when the key would refuse any PIN.
fn check_pin_usable<L: ReportLink>(key: &mut Authenticator<L>) -> io::Result<()> {
    let retries = key.pin_retries().map_err(client_error)?;
    if retries.retries == 0 {
        Err(pin_error_message(
            &ClientError::Status(CTAP2_ERR_PIN_BLOCKED),
            None,
        ))
    } else if retries.power_cycle_needed {
        Err(pin_error_message(
            &ClientError::Status(CTAP2_ERR_PIN_AUTH_BLOCKED),
            None,
        ))
    } else {
        Ok(())
    }
}

/// `pin`, unless it could never have been set: then it is wrong without the
/// key spending a retry on it, as when Enter is pressed by accident.
fn plausible_pin(pin: Pin) -> io::Result<Pin> {
    match validate_pin(&pin) {
        Ok(()) => Ok(pin),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("wrong PIN: {err}, so it cannot be the key's (no retry was used)"),
        )),
    }
}

/// The error for a PIN the key refused, with the retries left after a wrong
/// one.
fn pin_error<L: ReportLink>(key: &mut Authenticator<L>, err: ClientError) -> io::Error {
    let retries = match err {
        ClientError::Status(CTAP2_ERR_PIN_INVALID) => key.pin_retries().ok(),
        _ => None,
    };
    pin_error_message(&err, retries)
}

fn pin_error_message(err: &ClientError, retries: Option<PinRetries>) -> io::Error {
    use io::ErrorKind::{InvalidInput, PermissionDenied};
    let ClientError::Status(status) = err else {
        return io::Error::other(err.to_string());
    };
    let (kind, message) = match *status {
        CTAP2_ERR_PIN_INVALID => (
            PermissionDenied,
            match retries {
                Some(PinRetries { retries: 1, .. }) => {
                    "wrong PIN; 1 retry left, after which only a reset makes the key usable again"
                        .into()
                }
                Some(PinRetries { retries, .. }) => format!("wrong PIN; {retries} retries left"),
                None => "wrong PIN".into(),
            },
        ),
        CTAP2_ERR_PIN_AUTH_BLOCKED => (
            PermissionDenied,
            format!(
                "the key refuses PIN checks after 3 wrong PINs in a row until it is plugged in \
                 again: {REPLUG}"
            ),
        ),
        CTAP2_ERR_PIN_BLOCKED => (
            PermissionDenied,
            "the PIN is blocked: it was entered wrongly too often. Only a reset makes the key \
             usable again (`pqkey reset`), and it erases every passkey on it"
                .into(),
        ),
        CTAP2_ERR_PIN_POLICY_VIOLATION => (
            InvalidInput,
            "the key does not accept this PIN as the new one".into(),
        ),
        CTAP2_ERR_PIN_NOT_SET => (
            InvalidInput,
            "the key has no PIN; `pqkey pin` sets one".into(),
        ),
        _ => return io::Error::other(err.to_string()),
    };
    io::Error::new(kind, message)
}

// ---------------------------------------------------------------------------
// config

/// `pqkey config`, and its authenticated configuration changes.
pub(super) fn config(state_dir: &Path, action: Option<&ConfigAction>) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    for line in configure(&mut key, &mut PinReader::from_stdin(), action, &mut confirm)? {
        outln!("{line}")?;
    }
    Ok(())
}

fn config_lines(info: &Info) -> Vec<String> {
    vec![
        format!("Always UV: {}", on_off(info.always_uv == Some(true))),
        format!("Minimum PIN length: {}", minimum_pin_length(info)),
        format!(
            "PIN change required: {}",
            if info.force_pin_change == Some(true) {
                "yes"
            } else {
                "no"
            }
        ),
    ]
}

fn on_off(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

fn config_token<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
    info: &Info,
) -> io::Result<Option<Token>> {
    if info.pin_set != Some(true) {
        return Ok(None);
    }
    acquire_pin_token(key, pins, Authenticator::config_token).map(Some)
}

fn acquire_pin_token<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
    request: fn(&mut Authenticator<L>, &[u8]) -> Result<Token, ClientError>,
) -> io::Result<Token> {
    check_pin_usable(key)?;
    let pin = plausible_pin(pins.pin()?)?;
    request(key, pin.as_bytes()).map_err(|err| token_error(key, err))
}

fn configure<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
    action: Option<&ConfigAction>,
    confirmation: &mut dyn FnMut(&str) -> io::Result<bool>,
) -> io::Result<Vec<String>> {
    let info = key.info().map_err(client_error)?;
    let Some(action) = action else {
        return Ok(config_lines(&info));
    };
    let subcommand = match action {
        ConfigAction::AlwaysUv { .. } => 2,
        ConfigAction::MinPinLength { .. } | ConfigAction::ForcePinChange => 3,
    };
    if info.authenticator_config != Some(true) || !info.config_commands.contains(&subcommand) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the key does not support this configuration command; update pqkey and restart it",
        ));
    }
    let mut lines = Vec::new();
    match action {
        ConfigAction::AlwaysUv { setting } => {
            if (info.always_uv == Some(true)) != setting.enabled() {
                let token = config_token(key, pins, &info)?;
                key.toggle_always_uv(token.as_ref())
                    .map_err(|err| config_error(key, err, &info))?;
            }
            let updated = key.info().map_err(client_error)?;
            lines.push(format!(
                "Always UV: {}.",
                on_off(updated.always_uv == Some(true))
            ));
            if updated.pin_set == Some(false) {
                lines.push(
                    "Browsers will need a PIN before they can register or sign in; \
                     `pqkey pin` sets one."
                        .into(),
                );
            }
        }
        ConfigAction::MinPinLength {
            minimum,
            rp_ids,
            yes,
        } => {
            if !yes
                && !confirmation(&format!(
                    "Set the minimum PIN length to {minimum}? Only a reset, which erases every \
                 passkey, can lower it again."
                ))?
            {
                return Ok(vec!["Nothing was changed.".into()]);
            }
            let token = config_token(key, pins, &info)?;
            let rp_ids = if rp_ids.is_empty() {
                None
            } else {
                Some(rp_ids.as_slice())
            };
            key.set_min_pin_length(token.as_ref(), Some(*minimum), rp_ids, None)
                .map_err(|err| config_error(key, err, &info))?;
            let updated = key.info().map_err(client_error)?;
            lines.push(format!(
                "Minimum PIN length: {}.",
                minimum_pin_length(&updated)
            ));
            if updated.force_pin_change == Some(true) {
                lines.push("A PIN change is required; run `pqkey pin`.".into());
            }
        }
        ConfigAction::ForcePinChange => {
            if info.pin_set != Some(true) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the key has no PIN to change; `pqkey pin` sets one",
                ));
            }
            let token = config_token(key, pins, &info)?;
            key.set_min_pin_length(token.as_ref(), None, None, Some(true))
                .map_err(|err| config_error(key, err, &info))?;
            lines.push("A PIN change is required; run `pqkey pin`.".into());
        }
    }
    Ok(lines)
}

fn config_error<L: ReportLink>(
    key: &mut Authenticator<L>,
    err: ClientError,
    info: &Info,
) -> io::Error {
    let message = match err {
        ClientError::Status(CTAP2_ERR_PIN_POLICY_VIOLATION) => format!(
            "the minimum PIN length cannot be lowered below {}; only `pqkey reset` lowers \
             it, and erases every passkey",
            minimum_pin_length(info)
        ),
        ClientError::Status(CTAP2_ERR_KEY_STORE_FULL) => format!(
            "the key cannot store that RP ID list; use at most {} RP IDs, each at most 253 bytes",
            info.max_rp_ids_for_min_pin_length.unwrap_or(8)
        ),
        ClientError::Status(CTAP2_ERR_PUAT_REQUIRED) if info.pin_set == Some(false) => {
            "always-UV requires a PIN for this change; set one with `pqkey pin`, or turn \
             always-UV off with `pqkey config always-uv off` first"
                .into()
        }
        _ => return pin_error(key, err),
    };
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// ---------------------------------------------------------------------------
// passkeys

/// A pinUvAuthToken with the credential management permission, for which
/// the user enters the PIN.
fn management_token<L: ReportLink>(
    key: &mut Authenticator<L>,
    pins: &mut dyn PinSource,
) -> io::Result<Token> {
    if key.info().map_err(client_error)?.pin_set != Some(true) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passkeys are managed with the key's PIN, and it has none; `pqkey pin` sets one",
        ));
    }
    acquire_pin_token(key, pins, Authenticator::management_token)
}

/// `pqkey passkeys`.
pub fn list_passkeys(state_dir: &Path) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    let token = management_token(&mut key, &mut PinReader::from_stdin())?;
    let passkeys = key.passkeys(&token).map_err(client_error)?;
    if passkeys.is_empty() {
        outln!("No passkeys are stored on the key.")?;
        return outln!("{NOT_LISTED}");
    }
    for line in passkey_table(&passkeys) {
        outln!("{line}")?;
    }
    Ok(())
}

/// `pqkey passkeys delete QUERY`.
pub fn delete_passkey(state_dir: &Path, query: &str, yes: bool) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    let token = management_token(&mut key, &mut PinReader::from_stdin())?;
    let passkeys = key.passkeys(&token).map_err(client_error)?;
    let passkey = matching_passkey(&passkeys, query)?;
    let question = format!(
        "Delete the passkey of {} for {}? Signing in with it stops working; the site keeps its \
         record of it until you remove it there.",
        user(passkey),
        site(passkey)
    );
    if !yes && !confirm(&question)? {
        errln!("Nothing was deleted.");
        return Ok(());
    }
    key.delete(&token, &passkey.credential_id)
        .map_err(client_error)?;
    outln!("Passkey deleted.")
}

/// Why a registration can be missing from `pqkey passkeys`: a credential that
/// is not discoverable requires the site to supply its ID. Whether sealed
/// or stored, credential management does not list it.
const NOT_LISTED: &str = "A site that registered it as a security key (a second factor), or \
                          before the PIN was set,\nkeeps that sign-in itself: it works, but is \
                          not listed here.";

/// Columns of [`passkey_table`].
const HEADINGS: [&str; 4] = ["SITE", "USER", "ALGORITHM", "ID"];
/// The most of a site or user name the table shows.
const MAX_COLUMN_CHARS: usize = 40;
/// Hex digits of a credential ID the table shows: enough to tell passkeys
/// apart, and to name one in `pqkey passkeys delete`.
const SHORT_ID_DIGITS: usize = 16;

/// The relying party, as safe to print: websites choose these, and must not
/// get escape sequences onto the terminal.
fn site(passkey: &Passkey) -> String {
    sanitise(&passkey.rp_id, MAX_COLUMN_CHARS, Keep::End).unwrap_or_else(|| "-".into())
}

/// The user's name and display name, as safe to print.
fn user(passkey: &Passkey) -> String {
    let clean = |name: &Option<String>| {
        name.as_deref()
            .and_then(|name| sanitise(name, MAX_COLUMN_CHARS, Keep::Start))
    };
    match (clean(&passkey.user_name), clean(&passkey.user_display_name)) {
        (Some(name), Some(display)) if name != display => format!("{name} ({display})"),
        (Some(name), _) | (None, Some(name)) => name,
        (None, None) => "-".into(),
    }
}

fn algorithm(alg: Option<i64>) -> String {
    let Some(alg) = alg else {
        return "-".into();
    };
    match i32::try_from(alg).ok().map(CoseAlg::try_from) {
        Some(Ok(alg)) => alg.name().into(),
        Some(Err(_)) | None => format!("COSE {alg}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The passkeys as an aligned table, sorted by site and user, with a heading.
fn passkey_table(passkeys: &[Passkey]) -> Vec<String> {
    let mut rows: Vec<[String; 4]> = passkeys
        .iter()
        .map(|passkey| {
            let mut id = hex(&passkey.credential_id);
            id.truncate(SHORT_ID_DIGITS);
            [site(passkey), user(passkey), algorithm(passkey.alg), id]
        })
        .collect();
    rows.sort();
    let mut widths = HEADINGS.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    std::iter::once(HEADINGS.map(String::from))
        .chain(rows)
        .map(|row| {
            let mut line = String::new();
            for (column, (cell, width)) in row.iter().zip(widths).enumerate() {
                if column + 1 == HEADINGS.len() {
                    line.push_str(cell);
                } else {
                    let padding = width - cell.chars().count();
                    line.push_str(cell);
                    line.extend(std::iter::repeat_n(' ', padding + 2));
                }
            }
            line
        })
        .collect()
}

/// The one passkey whose site, user name, display name or hex ID contains
/// `query`, ignoring case.
fn matching_passkey<'a>(passkeys: &'a [Passkey], query: &str) -> io::Result<&'a Passkey> {
    let needle = query.to_lowercase();
    if needle.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "name the passkey to delete by part of its site, user or ID",
        ));
    }
    let contains = |text: &str| text.to_lowercase().contains(&needle);
    let matches: Vec<&Passkey> = passkeys
        .iter()
        .filter(|passkey| {
            contains(&passkey.rp_id)
                || passkey.user_name.as_deref().is_some_and(contains)
                || passkey.user_display_name.as_deref().is_some_and(contains)
                || contains(&hex(&passkey.credential_id))
        })
        .collect();
    match matches[..] {
        [passkey] => Ok(passkey),
        [] => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no passkey matches \"{query}\"; `pqkey passkeys` lists them"),
        )),
        _ => {
            let owned: Vec<Passkey> = matches.into_iter().cloned().collect();
            let table = passkey_table(&owned).join("\n");
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "\"{query}\" matches {} passkeys; name one by more of its site, user or ID:\n{table}",
                    owned.len()
                ),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// reset

/// `pqkey reset`.
///
/// CTAP 2.3 §6.6: "In order to prevent accidental trigger of this mechanism,
/// some form of user approval MAY be performed on the authenticator itself,
/// meaning that the platform will need to give the user an indication that
/// the authenticator is waiting for this approval." and, for authenticators
/// without a display, "the request MUST have come to the authenticator within
/// 10 seconds of powering up". So the key is plugged in afresh, as one would
/// a hardware key, and left as it was found afterwards.
pub fn reset(state_dir: &Path, yes: bool) -> io::Result<()> {
    let was_running = daemon::running(state_dir)?.is_some();
    if !yes
        && !confirm(
            "Reset the key? Every passkey on it and its PIN are erased, and signing in with \
             those passkeys stops working. This cannot be undone.",
        )?
    {
        errln!("Nothing was reset.");
        return Ok(());
    }
    let running = daemon::replug(state_dir)?;
    let result = connect_to(running, DEVICE_WAIT).and_then(|(_, key)| reset_key(key));
    let restored = if was_running {
        Ok(())
    } else {
        daemon::unplug(state_dir).map(drop)
    };
    result?;
    restored?;
    outln!("The key is reset: its passkeys and its PIN are erased.")
}

/// authenticatorReset, which the user approves in a notification; Ctrl-C
/// cancels it, and a second Ctrl-C ends pqkey.
fn reset_key<L: ReportLink>(key: Authenticator<L>) -> io::Result<()> {
    let cancel = Arc::new(AtomicBool::new(false));
    // Registered in this order, the first action only sees the flag the
    // second set on an earlier Ctrl-C.
    flag::register_conditional_default(SIGINT, Arc::clone(&cancel))?;
    flag::register(SIGINT, Arc::clone(&cancel))?;
    let mut key = key.with_cancel_flag(cancel);
    let mut asked = false;
    key.reset(&mut |status| {
        if status == STATUS_UPNEEDED && !asked {
            asked = true;
            errln!("Approve the reset in the notification on your desktop (Ctrl-C cancels).");
        }
    })
    .map_err(reset_error)
}

fn reset_error(err: ClientError) -> io::Error {
    let ClientError::Status(status) = err else {
        return client_error(err);
    };
    let message = match status {
        CTAP2_ERR_OPERATION_DENIED => "the reset was denied; nothing was erased",
        CTAP2_ERR_USER_ACTION_TIMEOUT => "the reset was not approved in time; nothing was erased",
        CTAP2_ERR_KEEPALIVE_CANCEL => "the reset was cancelled; nothing was erased",
        CTAP2_ERR_NOT_ALLOWED => {
            "the key refused the reset: it accepts one only within 10 seconds of starting. \
             Nothing was erased; try again"
        }
        _ => return client_error(ClientError::Status(status)),
    };
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use pqkey_ctap::store::{CredentialStore, FileStore};

    use super::*;
    use crate::client::tests::{discoverable, start};
    use crate::test_support::TempDir;

    /// PINs from a script; reading past its end fails.
    struct Script(VecDeque<&'static str>);

    impl Script {
        fn of(pins: &[&'static str]) -> Self {
            Self(pins.iter().copied().collect())
        }

        fn next(&mut self) -> io::Result<Pin> {
            self.0
                .pop_front()
                .map(|pin| Pin::new(pin.into()))
                .ok_or_else(|| io::Error::other("asked for a PIN the script does not have"))
        }
    }

    impl PinSource for Script {
        fn pin(&mut self) -> io::Result<Pin> {
            self.next()
        }

        fn current_pin(&mut self) -> io::Result<Pin> {
            self.next()
        }

        fn new_pin(&mut self, minimum: usize) -> io::Result<Pin> {
            let pin = self.next()?;
            crate::pin_input::validate_new_pin(&pin, minimum)?;
            Ok(pin)
        }
    }

    fn retries<L: ReportLink>(key: &mut Authenticator<L>) -> u64 {
        key.pin_retries().unwrap().retries
    }

    #[test]
    fn pin_sets_a_pin_and_then_changes_it() {
        let dir = TempDir::new("cli-pin");
        let (_daemon, mut key) = start(&dir);
        assert_eq!(
            set_or_change_pin(&mut key, &mut Script::of(&["1234"])).unwrap(),
            PinChange::Set
        );
        assert_eq!(
            set_or_change_pin(&mut key, &mut Script::of(&["1234", "5678"])).unwrap(),
            PinChange::Changed
        );
        assert!(key.management_token(b"5678").is_ok());
    }

    #[test]
    fn setup_asks_again_for_a_mistyped_pin() {
        let dir = TempDir::new("cli-first-pin");
        let (_daemon, mut key) = start(&dir);
        set_first_pin(&mut key, &mut Script::of(&["12", "1234"])).unwrap();
        assert!(key.management_token(b"1234").is_ok());

        let dir = TempDir::new("cli-first-pin-gives-up");
        let (_daemon, mut key) = start(&dir);
        let err = set_first_pin(&mut key, &mut Script::of(&["1", "2", "3", "4567"])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert_eq!(key.info().unwrap().pin_set, Some(false));
    }

    #[test]
    fn a_wrong_pin_reports_the_retries_left() {
        let dir = TempDir::new("cli-wrong-pin");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let err = set_or_change_pin(&mut key, &mut Script::of(&["0000", "5678"])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "wrong PIN; 7 retries left");

        // A PIN that could never have been set costs no retry.
        let err = set_or_change_pin(&mut key, &mut Script::of(&["12"])).unwrap_err();
        assert!(err.to_string().contains("no retry was used"), "{err}");
        assert_eq!(retries(&mut key), 7);
    }

    #[test]
    fn three_wrong_pins_in_a_row_ask_for_a_replug() {
        let dir = TempDir::new("cli-replug");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        for _ in 0..2 {
            let err = management_token(&mut key, &mut Script::of(&["0000"])).unwrap_err();
            assert!(err.to_string().starts_with("wrong PIN"), "{err}");
        }
        let err = management_token(&mut key, &mut Script::of(&["0000"])).unwrap_err();
        assert!(err.to_string().contains(REPLUG), "{err}");
        // From now on no PIN is asked for: the script is empty.
        let err = management_token(&mut key, &mut Script::of(&[])).unwrap_err();
        assert!(err.to_string().contains(REPLUG), "{err}");
        let err = set_or_change_pin(&mut key, &mut Script::of(&[])).unwrap_err();
        assert!(err.to_string().contains(REPLUG), "{err}");
    }

    #[test]
    fn passkeys_need_a_pin() {
        let dir = TempDir::new("cli-passkeys-no-pin");
        let (_daemon, mut key) = start(&dir);
        let err = management_token(&mut key, &mut Script::of(&[])).unwrap_err();
        assert!(err.to_string().contains("`pqkey pin` sets one"), "{err}");
    }

    #[test]
    fn a_passkey_is_deleted_by_part_of_its_name() {
        let dir = TempDir::new("cli-delete");
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            for (rp, id, name) in [("example.com", 1, "alice"), ("example.com", 2, "bob")] {
                store
                    .put(&discoverable(rp, id, name, CoseAlg::MLDSA65))
                    .unwrap();
            }
        }
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let token = management_token(&mut key, &mut Script::of(&["1234"])).unwrap();
        let passkeys = key.passkeys(&token).unwrap();
        let bob = matching_passkey(&passkeys, "BO").unwrap();
        key.delete(&token, &bob.credential_id).unwrap();
        let left = key.passkeys(&token).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].user_name.as_deref(), Some("alice"));
    }

    #[test]
    fn config_displays_defaults_and_toggles_without_a_pin() {
        let dir = TempDir::new("cli-config-no-pin");
        let (_daemon, mut key) = start(&dir);
        let mut no_confirmation = |_: &str| -> io::Result<bool> {
            panic!("this action must not ask for confirmation");
        };
        let lines = configure(&mut key, &mut Script::of(&[]), None, &mut no_confirmation).unwrap();
        assert_eq!(
            lines,
            [
                "Always UV: off",
                "Minimum PIN length: 4",
                "PIN change required: no",
            ]
        );
        assert!(policy_status(&key.info().unwrap()).is_empty());
        for setting in [
            super::super::AlwaysUv::Off,
            super::super::AlwaysUv::On,
            super::super::AlwaysUv::On,
            super::super::AlwaysUv::Off,
        ] {
            let action = ConfigAction::AlwaysUv { setting };
            let lines = configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&action),
                &mut no_confirmation,
            )
            .unwrap();
            assert_eq!(
                lines[0],
                format!("Always UV: {}.", on_off(setting.enabled()))
            );
            assert!(lines[1].contains("`pqkey pin` sets one"), "{lines:?}");
            assert_eq!(key.info().unwrap().always_uv, Some(setting.enabled()));
        }
        let err = configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&ConfigAction::ForcePinChange),
            &mut no_confirmation,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no PIN to change"), "{err}");
        assert!(err.to_string().contains("pqkey pin"), "{err}");
    }

    #[test]
    fn a_minimum_change_is_confirmed_before_reading_the_pin() {
        let dir = TempDir::new("cli-config-confirm");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let action = ConfigAction::MinPinLength {
            minimum: 6,
            rp_ids: Vec::new(),
            yes: false,
        };
        let mut questions = Vec::new();
        let lines = configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&action),
            &mut |question| {
                questions.push(question.to_owned());
                Ok(false)
            },
        )
        .unwrap();
        assert_eq!(lines, ["Nothing was changed."]);
        assert_eq!(key.info().unwrap().min_pin_length, Some(4));
        assert_eq!(retries(&mut key), 8);
        assert_eq!(questions.len(), 1);
        assert!(questions[0].contains("Only a reset"), "{questions:?}");
        assert!(
            questions[0].contains("erases every passkey"),
            "{questions:?}"
        );
        let lines = configure(
            &mut key,
            &mut Script::of(&["1234"]),
            Some(&action),
            &mut |_| Ok(true),
        )
        .unwrap();
        assert_eq!(
            lines,
            [
                "Minimum PIN length: 6.",
                "A PIN change is required; run `pqkey pin`."
            ]
        );
        assert_eq!(key.info().unwrap().min_pin_length, Some(6));
        assert_eq!(
            policy_status(&key.info().unwrap()),
            ["PIN change required; run `pqkey pin`"]
        );
        let err = management_token(&mut key, &mut Script::of(&["1234"])).unwrap_err();
        assert!(err.to_string().contains("PIN change"), "{err}");
        assert!(err.to_string().contains("pqkey pin"), "{err}");
        let err = set_or_change_pin(&mut key, &mut Script::of(&["1234", "12345"])).unwrap_err();
        assert_eq!(err.to_string(), "PIN must be at least 6 characters long");
        assert_eq!(retries(&mut key), 8);
        assert_eq!(
            set_or_change_pin(&mut key, &mut Script::of(&["1234", "123456"])).unwrap(),
            PinChange::Changed
        );
        assert!(management_token(&mut key, &mut Script::of(&["123456"])).is_ok());
    }

    #[test]
    fn minimum_changes_preserve_rps_when_omitted_and_report_capacity() {
        let dir = TempDir::new("cli-config-rps");
        let (_daemon, mut key) = start(&dir);
        let change = |minimum, rp_ids| ConfigAction::MinPinLength {
            minimum,
            rp_ids,
            yes: true,
        };
        let mut no_confirmation = |_: &str| -> io::Result<bool> {
            panic!("--yes must skip confirmation");
        };
        let action = change(6, vec!["example.com".into(), "other.example".into()]);
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&action),
                &mut no_confirmation
            )
            .unwrap(),
            ["Minimum PIN length: 6."]
        );
        let stored = || {
            FileStore::open(dir.path())
                .unwrap()
                .pin_state()
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            stored().min_pin_length_rp_ids,
            ["example.com", "other.example"]
        );
        configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&change(7, Vec::new())),
            &mut no_confirmation,
        )
        .unwrap();
        assert_eq!(
            stored().min_pin_length_rp_ids,
            ["example.com", "other.example"]
        );
        let unchanged = stored();
        let err = configure(
            &mut key,
            &mut Script::of(&[]),
            Some(&change(6, Vec::new())),
            &mut no_confirmation,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cannot be lowered below 7"),
            "{err}"
        );
        assert!(err.to_string().contains("erases every passkey"), "{err}");
        assert_eq!(stored(), unchanged);
        for rp_ids in [vec!["example.com".into(); 9], vec!["a".repeat(254)]] {
            let err = configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&change(8, rp_ids)),
                &mut no_confirmation,
            )
            .unwrap_err();
            assert!(err.to_string().contains("at most 8 RP IDs"), "{err}");
            assert!(err.to_string().contains("at most 253 bytes"), "{err}");
            assert_eq!(stored(), unchanged);
        }
        let err = set_or_change_pin(&mut key, &mut Script::of(&["1234"])).unwrap_err();
        assert_eq!(err.to_string(), "PIN must be at least 7 characters long");
        set_first_pin(&mut key, &mut Script::of(&["123456", "1234567"])).unwrap();
        assert!(key.config_token(b"1234567").is_ok());
    }

    #[test]
    fn forced_pin_change_refuses_reuse_and_explains_token_errors() {
        let dir = TempDir::new("cli-config-force");
        let (_daemon, mut key) = start(&dir);
        key.set_pin(b"1234").unwrap();
        let mut no_confirmation = |_: &str| -> io::Result<bool> {
            panic!("force-pin-change does not ask for confirmation");
        };
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&["1234"]),
                Some(&ConfigAction::ForcePinChange),
                &mut no_confirmation
            )
            .unwrap(),
            ["A PIN change is required; run `pqkey pin`."]
        );
        let on = ConfigAction::AlwaysUv {
            setting: super::super::AlwaysUv::On,
        };
        let off = ConfigAction::AlwaysUv {
            setting: super::super::AlwaysUv::Off,
        };
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&off),
                &mut no_confirmation
            )
            .unwrap(),
            ["Always UV: off."]
        );
        let err = configure(
            &mut key,
            &mut Script::of(&["1234"]),
            Some(&on),
            &mut no_confirmation,
        )
        .unwrap_err();
        assert!(err.to_string().contains("run `pqkey pin`"), "{err}");
        let err = set_or_change_pin(&mut key, &mut Script::of(&["1234", "1234"])).unwrap_err();
        assert!(
            err.to_string().contains("must differ from the current PIN"),
            "{err}"
        );
        assert_eq!(key.info().unwrap().force_pin_change, Some(true));
        set_or_change_pin(&mut key, &mut Script::of(&["1234", "5678"])).unwrap();
        assert_eq!(key.info().unwrap().force_pin_change, Some(false));
        configure(
            &mut key,
            &mut Script::of(&["5678"]),
            Some(&on),
            &mut no_confirmation,
        )
        .unwrap();
        assert_eq!(
            policy_status(&key.info().unwrap()),
            ["Always UV: on; registrations and sign-ins require the PIN"]
        );
        assert_eq!(
            configure(
                &mut key,
                &mut Script::of(&[]),
                Some(&on),
                &mut no_confirmation
            )
            .unwrap(),
            ["Always UV: on."]
        );
    }

    #[test]
    fn config_displays_persisted_settings_after_a_restart() {
        let dir = TempDir::new("cli-config-restart");
        {
            let (_daemon, mut key) = start(&dir);
            key.set_min_pin_length(None, Some(6), None, None).unwrap();
            key.set_pin(b"123456").unwrap();
            let token = key.config_token(b"123456").unwrap();
            key.toggle_always_uv(Some(&token)).unwrap();
            key.set_min_pin_length(Some(&token), None, None, Some(true))
                .unwrap();
        }
        let (_daemon, mut key) = start(&dir);
        let lines = configure(&mut key, &mut Script::of(&[]), None, &mut |_| {
            panic!("display must not ask for confirmation")
        })
        .unwrap();
        assert_eq!(
            lines,
            [
                "Always UV: on",
                "Minimum PIN length: 6",
                "PIN change required: yes"
            ]
        );
        assert_eq!(
            policy_status(&key.info().unwrap()),
            [
                "Always UV: on; registrations and sign-ins require the PIN",
                "PIN change required; run `pqkey pin`",
            ]
        );
    }

    #[test]
    fn a_no_pin_minimum_change_explains_always_uv_recovery() {
        let dir = TempDir::new("cli-config-no-pin-always-uv");
        let (_daemon, mut key) = start(&dir);
        key.toggle_always_uv(None).unwrap();
        let action = ConfigAction::MinPinLength {
            minimum: 6,
            rp_ids: Vec::new(),
            yes: true,
        };
        let err = configure(&mut key, &mut Script::of(&[]), Some(&action), &mut |_| {
            panic!("--yes must skip confirmation")
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("set one with `pqkey pin`"),
            "{err}"
        );
        assert!(
            err.to_string().contains("pqkey config always-uv off"),
            "{err}"
        );
        assert_eq!(key.info().unwrap().min_pin_length, Some(4));
    }

    fn passkey(rp_id: &str, name: Option<&str>, display: Option<&str>, id: u8) -> Passkey {
        Passkey {
            rp_id: rp_id.into(),
            user_id: vec![id],
            user_name: name.map(Into::into),
            user_display_name: display.map(Into::into),
            credential_id: [0x01].into_iter().chain([id; 32]).collect(),
            alg: Some(-49),
        }
    }

    #[test]
    fn a_query_names_exactly_one_passkey() {
        let passkeys = [
            passkey("example.com", Some("alice"), Some("Alice A."), 0xaa),
            passkey("example.com", Some("bob"), None, 0xbb),
            passkey("other.example", Some("alice"), None, 0xcc),
        ];
        let user_of = |query| matching_passkey(&passkeys, query).map(|p| p.credential_id[1]);
        assert_eq!(user_of("bob").unwrap(), 0xbb);
        assert_eq!(user_of("OTHER").unwrap(), 0xcc);
        assert_eq!(user_of("alice a.").unwrap(), 0xaa);
        assert_eq!(user_of("01cccc").unwrap(), 0xcc);

        let err = user_of("alice").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("matches 2 passkeys"), "{err}");
        assert!(err.to_string().contains("other.example"), "{err}");
        assert_eq!(
            user_of("carol").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(user_of("").unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn the_table_is_aligned_sorted_and_safe_to_print() {
        let passkeys = [
            passkey("z.example", Some("zed"), Some("Zed"), 0x22),
            passkey(
                "evil.example",
                Some("a\u{1b}[2Jb\u{202e}c"),
                Some("Mallory"),
                0x11,
            ),
            passkey("a.example", None, None, 0x33),
        ];
        let table = passkey_table(&passkeys);
        assert_eq!(
            table,
            [
                "SITE          USER               ALGORITHM  ID",
                "a.example     -                  ML-DSA-65  0133333333333333",
                "evil.example  a [2Jbc (Mallory)  ML-DSA-65  0111111111111111",
                "z.example     zed (Zed)          ML-DSA-65  0122222222222222",
            ]
        );
        for line in &table {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
        for (alg, name) in [
            (-7, "ES256"),
            (-48, "ML-DSA-44"),
            (-49, "ML-DSA-65"),
            (-50, "ML-DSA-87"),
            (-9, "ESP256"),
            (-35, "ES384"),
            (-51, "ESP384"),
            (-36, "ES512"),
            (-52, "ESP512"),
            (-47, "ES256K"),
            (-8, "EdDSA"),
            (-19, "Ed25519"),
            (-53, "Ed448"),
            (-257, "RS256"),
            (-258, "RS384"),
            (-259, "RS512"),
            (-37, "PS256"),
            (-38, "PS384"),
            (-39, "PS512"),
        ] {
            assert_eq!(algorithm(Some(alg)), name);
        }
        assert_eq!(algorithm(Some(-65535)), "COSE -65535");
        assert_eq!(algorithm(None), "-");
    }

    #[test]
    fn an_empty_answer_takes_the_default() {
        assert!(is_yes("\n", true));
        assert!(!is_yes("\n", false));
        assert!(is_yes(" Yes\n", false));
        assert!(!is_yes("no\n", true));
        assert!(!is_yes("yep\n", true));
    }

    #[test]
    fn pin_and_reset_errors_name_the_fix() {
        let status = |code| pin_error_message(&ClientError::Status(code), None).to_string();
        assert!(status(CTAP2_ERR_PIN_AUTH_BLOCKED).contains(REPLUG));
        assert!(status(CTAP2_ERR_PIN_BLOCKED).contains("pqkey reset"));
        assert!(status(CTAP2_ERR_PIN_NOT_SET).contains("pqkey pin"));
        let last = PinRetries {
            retries: 1,
            power_cycle_needed: false,
        };
        let message =
            pin_error_message(&ClientError::Status(CTAP2_ERR_PIN_INVALID), Some(last)).to_string();
        assert!(message.contains("1 retry left"), "{message}");
        for (code, says) in [
            (CTAP2_ERR_OPERATION_DENIED, "denied"),
            (CTAP2_ERR_USER_ACTION_TIMEOUT, "not approved in time"),
            (CTAP2_ERR_KEEPALIVE_CANCEL, "cancelled"),
            (CTAP2_ERR_NOT_ALLOWED, "within 10 seconds"),
        ] {
            let message = reset_error(ClientError::Status(code)).to_string();
            assert!(message.contains(says), "{code:#x}: {message}");
        }
        assert_eq!(
            pin_state(PinRetries {
                retries: 8,
                power_cycle_needed: false
            }),
            "set (8 retries left)"
        );
    }
}
