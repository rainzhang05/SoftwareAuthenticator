//! The commands that manage the running key: `status`, `pin`, `passkeys` and
//! `reset`.
//!
//! They talk to the key over CTAP through its hidraw node, as a security
//! key's management application does ([`crate::client`]). So the key itself
//! checks the PIN and counts retries, asks its user to approve a reset, and
//! accepts a reset only shortly after it is plugged in.

use std::{
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use pqkey_ctap::CoseAlg;
use pqkey_ctap::ctap::constants::{
    CTAP2_ERR_KEEPALIVE_CANCEL, CTAP2_ERR_NOT_ALLOWED, CTAP2_ERR_OPERATION_DENIED,
    CTAP2_ERR_PIN_AUTH_BLOCKED, CTAP2_ERR_PIN_BLOCKED, CTAP2_ERR_PIN_INVALID,
    CTAP2_ERR_PIN_NOT_SET, CTAP2_ERR_PIN_POLICY_VIOLATION, CTAP2_ERR_USER_ACTION_TIMEOUT,
};
use signal_hook::{consts::SIGINT, flag};

use super::daemon::{self, Running};
use super::output::{errln, outln};
use crate::client::ctap2::{Authenticator, ClientError, Passkey, PinRetries, Token};
use crate::client::ctaphid::{ReportLink, STATUS_UPNEEDED};
use crate::client::hidraw::{self, Hidraw};
use crate::pin_input::{Pin, PinReader, PinSource, validate_pin};
use crate::presence::notification::{Keep, sanitise};
use crate::service;

/// How long to wait for the running key's hidraw node, and for access to it:
/// the kernel creates the node and udev grants access just after the key
/// starts.
const DEVICE_WAIT: Duration = Duration::from_secs(5);

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
        err => io::Error::other(err.to_string()),
    }
}

/// The running key on `state_dir`, through its hidraw node.
fn connect(state_dir: &Path) -> io::Result<Authenticator<Hidraw>> {
    let running = daemon::running(state_dir)?.ok_or_else(not_running)?;
    connect_to(running).map(|(_, key)| key)
}

/// The hidraw node of the key `running`, which names its device after its
/// pid, and a CTAPHID channel to it.
fn connect_to(running: Running) -> io::Result<(PathBuf, Authenticator<Hidraw>)> {
    let pid = running.pid();
    let uniq = service::device_uniq(pid.as_raw().unsigned_abs());
    let deadline = Instant::now() + DEVICE_WAIT;
    loop {
        let waited = Instant::now() >= deadline;
        match hidraw::find_system_node(&uniq)? {
            Some(path) => match Hidraw::open(&path) {
                Ok(link) => {
                    let key = Authenticator::open(link).map_err(client_error)?;
                    return Ok((path, key));
                }
                // udev has not granted access yet.
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied && !waited => {}
                Err(err) => {
                    return Err(io::Error::new(
                        err.kind(),
                        format!(
                            "cannot open the key's device {}: {err}; `pqkey status` shows why",
                            path.display()
                        ),
                    ));
                }
            },
            None if waited => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("the key runs (pid {pid}), but its device is missing"),
                ));
            }
            None => {}
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Ask `question` on the terminal; only "y" or "yes" is a yes.
fn confirm(question: &str) -> io::Result<bool> {
    {
        let mut stderr = io::stderr().lock();
        write!(stderr, "{question} [y/N] ")?;
        stderr.flush()?;
    }
    // Standard input's own buffer, which PIN lines read before were taken
    // from: a reader of its own could swallow lines meant for later.
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

// ---------------------------------------------------------------------------
// status

/// `pqkey status`.
pub fn status(state_dir: &Path) -> io::Result<()> {
    let running = match daemon::running(state_dir) {
        Ok(running) => running,
        Err(err) if err.kind() == io::ErrorKind::ResourceBusy => {
            return outln!("Key:      starting or stopping");
        }
        Err(err) => return Err(err),
    };
    let Some(running) = running else {
        return outln!("Key:      not running; `pqkey start` starts it");
    };
    match running {
        Running::Service(pid) => {
            outln!(
                "Key:      running (pid {pid}, systemd user service {})",
                daemon::UNIT
            )?;
        }
        Running::Daemon(pid) => outln!("Key:      running (pid {pid})")?,
    }
    let (path, mut key) = match connect_to(running) {
        Ok(connected) => connected,
        Err(err) => return outln!("Device:   {err}"),
    };
    outln!("Device:   {}", path.display())?;
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
    if let Some(remaining) = info.remaining_discoverable {
        outln!("Passkeys: room for {remaining} more")?;
    }
    Ok(())
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
    match key.info().map_err(client_error)?.pin_set {
        Some(false) => {
            let new = pins.new_pin()?;
            key.set_pin(new.as_bytes())
                .map_err(|err| pin_error(key, err))?;
            Ok(PinChange::Set)
        }
        Some(true) => {
            check_pin_usable(key)?;
            let current = plausible_pin(pins.current_pin()?)?;
            let new = pins.new_pin()?;
            key.change_pin(current.as_bytes(), new.as_bytes())
                .map_err(|err| pin_error(key, err))?;
            Ok(PinChange::Changed)
        }
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the key does not support a PIN",
        )),
    }
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
    check_pin_usable(key)?;
    let pin = plausible_pin(pins.pin()?)?;
    key.management_token(pin.as_bytes())
        .map_err(|err| pin_error(key, err))
}

/// `pqkey passkeys`.
pub fn list_passkeys(state_dir: &Path) -> io::Result<()> {
    let mut key = connect(state_dir)?;
    let token = management_token(&mut key, &mut PinReader::from_stdin())?;
    let passkeys = key.passkeys(&token).map_err(client_error)?;
    if passkeys.is_empty() {
        return outln!("No passkeys are stored on the key.");
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
    match alg.map(|alg| i32::try_from(alg).map(CoseAlg::try_from)) {
        Some(Ok(Ok(CoseAlg::ES256))) => "ES256".into(),
        Some(Ok(Ok(CoseAlg::MLDSA44))) => "ML-DSA-44".into(),
        Some(Ok(Ok(CoseAlg::MLDSA65))) => "ML-DSA-65".into(),
        Some(Ok(Ok(CoseAlg::MLDSA87))) => "ML-DSA-87".into(),
        Some(_) => format!("COSE {}", alg.unwrap_or_default()),
        None => "-".into(),
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
    let result = connect_to(running).and_then(|(_, key)| reset_key(key));
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

        fn new_pin(&mut self) -> io::Result<Pin> {
            let pin = self.next()?;
            validate_pin(&pin)?;
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
        assert_eq!(algorithm(Some(-7)), "ES256");
        assert_eq!(algorithm(Some(-8)), "COSE -8");
        assert_eq!(algorithm(None), "-");
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
