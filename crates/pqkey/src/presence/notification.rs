//! User presence through a desktop notification with Approve and Deny
//! buttons.
//!
//! [`NotificationPresence`] shows one notification per presence request,
//! following the freedesktop.org Desktop Notifications Specification (1.2):
//! `Notify` with two actions, then `ActionInvoked` and `NotificationClosed`
//! for the user's answer, and `CloseNotification` when the request ends
//! without one. The D-Bus side is behind [`NotificationServer`], implemented
//! by [`SessionBus`](super::dbus::SessionBus), so the logic here can be
//! tested without a bus.
//!
//! It fails closed: if no notification can be shown with buttons to answer
//! it, the request is denied, never approved.
//!
//! Logs at info level and above name only the kind of request. The relying
//! party and the user names come from whichever process wrote to the key, and
//! nothing has verified the user yet, so they are logged at debug level only.

use std::{
    fmt, fs,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};

use pqkey_ctap::ctap::presence::{
    Cancellation, PresenceOperation, PresenceOutcome, PresenceRequest, UserPresence,
};

use super::CANCELLATION_POLL;

/// The action key of the Approve button.
pub const APPROVE_ACTION: &str = "approve";
/// The action key of the Deny button.
pub const DENY_ACTION: &str = "deny";

/// How often an unanswered prompt is nudged on GNOME Shell.
///
/// GNOME Shell 50 can leave a critical notification queued and never shown:
/// when the banner in front of it is removed by its own source (Chromium's
/// "is ready" banner when its window gets focus), `MessageTray._updateState`
/// hides it from inside `_updateState` itself, and the re-entrancy guard
/// swallows the call that would show the next one.  The prompt then waits,
/// invisible, until some other notification arrives.  Any new notification
/// that requests a banner runs the queue again and shows the prompt, which
/// is critical and so first in line; one of low urgency requests no banner
/// and does not.  So while a prompt waits, a normal-urgency notification
/// is posted and withdrawn at once every few seconds: it changes nothing
/// when the prompt is already shown, and shows it within this interval when
/// it is stuck, as a hardware key keeps blinking until it is touched.
pub const NUDGE_INTERVAL: Duration = Duration::from_secs(2);

/// `GetServerInformation`'s name of the server whose queue needs nudging.
const GNOME_SHELL: &str = "gnome-shell";

/// `NotificationClosed` reason 1: the notification expired.
const CLOSED_EXPIRED: u32 = 1;

/// The longest relying party ID shown, in characters. Longer ones keep their
/// end, which names the registrable domain.
const MAX_RP_ID_CHARS: usize = 80;
/// The longest user name or display name shown, in characters.
const MAX_USER_CHARS: usize = 64;

/// A notification to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// A fixed title; never contains text from the request.
    pub summary: &'static str,
    /// The question, escaped for markup if the server interprets it.
    pub body: String,
    /// How long the server should show the notification.
    pub timeout: Duration,
}

/// Something the notification server reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotificationEvent {
    /// `ActionInvoked`: the user chose the action `key` on notification `id`.
    ActionInvoked { id: u32, key: String },
    /// `NotificationClosed`: notification `id` went away for `reason` (1
    /// expired, 2 dismissed by the user, 3 closed by `CloseNotification`, 4
    /// undefined).
    Closed { id: u32, reason: u32 },
}

/// What [`NotificationServer::connect`] learnt about the server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerInfo {
    /// `GetCapabilities`.
    pub capabilities: Vec<String>,
    /// The product name from `GetServerInformation`, if the server answered
    /// it, such as "gnome-shell".
    pub name: Option<String>,
    /// The unique bus name of the server's connection, such as ":1.42".
    pub owner: Option<String>,
    /// The ID of the bus (`org.freedesktop.DBus.GetId`).  With `owner` it
    /// names one server process on one bus: unique names are never reused
    /// while a bus runs.
    pub bus_id: Option<String>,
}

/// The file in the state directory that records the prompt on screen, so
/// that a daemon killed while it showed one (and so never withdrew it) can
/// withdraw it when it starts again; see
/// [`NotificationPresence::with_prompt_record`].
pub const PROMPT_FILE: &str = "authenticator.prompt";

/// Why no notification server could be reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// There is no session bus to connect to.
    NoSessionBus(String),
    /// Nothing on the session bus provides org.freedesktop.Notifications.
    NoServer(String),
    /// Anything else.
    Failed(String),
}

/// A desktop notification server, reached once per presence request.
pub trait NotificationServer {
    /// Connect to the server for one request, and subscribe to its signals
    /// before anything is shown, so no answer can be missed. Returns the
    /// server's capabilities and name.
    fn connect(&mut self) -> Result<ServerInfo, ConnectError>;
    /// Show `notification` with an Approve and a Deny button (`Notify`), and
    /// return its ID.
    fn notify(&mut self, notification: &Notification) -> Result<u32, String>;
    /// The next event from the server, waiting at most `wait` for one.
    /// Events about other notifications are returned too.
    fn next_event(&mut self, wait: Duration) -> Result<Option<NotificationEvent>, String>;
    /// Withdraw notification `id` (`CloseNotification`).
    fn close(&mut self, id: u32) -> Result<(), String>;
    /// Post an empty, silent, transient notification of normal urgency and
    /// withdraw it at once, which makes GNOME Shell show a prompt stuck in
    /// its queue (see [`NUDGE_INTERVAL`]). Returns its ID.
    fn nudge(&mut self) -> Result<u32, String>;
    /// End what [`connect`](Self::connect) started.
    fn disconnect(&mut self);
}

/// Asks the user with a desktop notification.
///
/// * Approve approves the request.
/// * Deny, dismissing the notification, or anything else that closes it
///   denies the request; if the server lets it expire, the request timed out.
/// * If the request's timeout passes first, the notification is withdrawn and
///   the request timed out.
/// * If the platform cancels the request, the notification is withdrawn
///   within about 20 ms plus one D-Bus call.
/// * If there is no session bus or notification server, the server cannot
///   show buttons, or talking to it fails, the request is denied and the
///   reason logged.
/// * On GNOME Shell an unanswered prompt is nudged every [`NUDGE_INTERVAL`]
///   so that a prompt stuck in its queue is shown.
/// * A prompt left on screen by a daemon that was killed is withdrawn by the
///   next one, if it has a prompt record (see [`Self::with_prompt_record`]).
#[derive(Debug)]
pub struct NotificationPresence<S> {
    server: S,
    nudge_interval: Duration,
    record: Option<PathBuf>,
}

impl<S: NotificationServer> NotificationPresence<S> {
    pub fn new(server: S) -> Self {
        Self {
            server,
            nudge_interval: NUDGE_INTERVAL,
            record: None,
        }
    }

    /// Record each prompt while it is on screen in the file `path` (mode
    /// 0600), and withdraw a prompt recorded there earlier, by a daemon that
    /// was killed before it could, at the next request or through
    /// [`Self::withdraw_stale_prompt`].  The record names the bus, the server's
    /// connection and the notification, so a prompt is only withdrawn from
    /// the server instance that showed it: after a restart of the server its
    /// IDs start again and could name another program's notification.
    pub fn with_prompt_record(mut self, path: PathBuf) -> Self {
        self.record = Some(path);
        self
    }

    /// Withdraw the prompt a previous daemon recorded and left on screen, if
    /// any, then forget it.  Best effort: without a session bus or server it
    /// waits for the next request.
    pub fn withdraw_stale_prompt(&mut self) {
        if !self.record.as_ref().is_some_and(|path| path.exists()) {
            return;
        }
        if let Ok(info) = self.server.connect() {
            self.close_stale_prompt(&info);
        }
        self.server.disconnect();
    }

    /// The recorded prompt, if `info` names the server that showed it, is
    /// withdrawn; the record goes either way.
    fn close_stale_prompt(&mut self, info: &ServerInfo) {
        let Some(path) = self.record.clone() else {
            return;
        };
        let Ok(recorded) = fs::read_to_string(&path) else {
            return;
        };
        let mut lines = recorded.lines();
        let (bus_id, owner, id) = (lines.next(), lines.next(), lines.next());
        if let Some(id) = id.and_then(|id| id.parse::<u32>().ok())
            && bus_id.is_some()
            && bus_id == info.bus_id.as_deref()
            && owner.is_some()
            && owner == info.owner.as_deref()
        {
            log::info!("withdrawing a prompt a previous daemon left on screen");
            if let Err(err) = self.server.close(id) {
                log::debug!("could not withdraw notification {id}: {err}");
            }
        }
        self.forget_prompt();
    }

    /// Record prompt `id` of the server `info` describes.
    fn record_prompt(&self, info: &ServerInfo, id: u32) {
        let (Some(path), Some(bus_id), Some(owner)) = (&self.record, &info.bus_id, &info.owner)
        else {
            return;
        };
        let written = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut file| writeln!(file, "{bus_id}\n{owner}\n{id}"));
        if let Err(err) = written {
            log::debug!("could not record the prompt in {}: {err}", path.display());
        }
    }

    fn forget_prompt(&self) {
        if let Some(path) = &self.record
            && let Err(err) = fs::remove_file(path)
            && err.kind() != io::ErrorKind::NotFound
        {
            log::debug!("could not remove {}: {err}", path.display());
        }
    }

    /// Nudge every `interval` instead of [`NUDGE_INTERVAL`], for tests.
    #[cfg(test)]
    fn with_nudge_interval(mut self, interval: Duration) -> Self {
        self.nudge_interval = interval;
        self
    }

    fn ask(
        &mut self,
        request: &PresenceRequest<'_>,
        cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        let deadline = Instant::now() + request.timeout;
        let info = match self.server.connect() {
            Ok(info) => info,
            Err(err) => {
                log::error!("{}", Unavailable::Connect(err).message(request));
                return PresenceOutcome::Denied;
            }
        };
        self.close_stale_prompt(&info);
        let capabilities = &info.capabilities;
        if !capabilities.iter().any(|c| c == "actions") {
            log::error!("{}", Unavailable::NoActions.message(request));
            return PresenceOutcome::Denied;
        }
        // The relying party, the account and what a reset deletes are only
        // in the body: "Some implementations may only show the summary"
        // (Desktop Notifications Specification, "body" capability).
        if !capabilities.iter().any(|c| c == "body") {
            log::error!("{}", Unavailable::NoBody.message(request));
            return PresenceOutcome::Denied;
        }
        let markup = capabilities.iter().any(|c| c == "body-markup");
        let notification = notification_for(request, markup);
        log::debug!("notification prompt: {}", prompt_text(request));
        if cancellation.is_cancelled() {
            return PresenceOutcome::Cancelled;
        }
        let id = match self.server.notify(&notification) {
            Ok(id) => id,
            Err(err) => {
                log::error!("{}", Unavailable::Failed(err).message(request));
                return PresenceOutcome::Denied;
            }
        };
        self.record_prompt(&info, id);
        log::info!(
            "asking the user with a desktop notification: {}",
            notification.summary
        );

        let mut nudging = info.name.as_deref() == Some(GNOME_SHELL);
        let mut next_nudge = Instant::now() + self.nudge_interval;
        let outcome = loop {
            if cancellation.is_cancelled() {
                break PresenceOutcome::Cancelled;
            }
            let mut now = Instant::now();
            if now >= deadline {
                break PresenceOutcome::TimedOut;
            }
            if nudging && now >= next_nudge {
                // Events about the nudge, whose ID is not the prompt's, are
                // ignored like any other notification's below.
                if let Err(err) = self.server.nudge() {
                    log::debug!("could not nudge the notification queue: {err}");
                    nudging = false;
                }
                now = Instant::now();
                next_nudge = now + self.nudge_interval;
            }
            let mut wait = CANCELLATION_POLL.min(deadline.saturating_duration_since(now));
            if nudging {
                wait = wait.min(next_nudge.saturating_duration_since(now));
            }
            match self.server.next_event(wait) {
                Ok(Some(NotificationEvent::ActionInvoked { id: event_id, key }))
                    if event_id == id =>
                {
                    break if key == APPROVE_ACTION {
                        PresenceOutcome::Approved
                    } else {
                        PresenceOutcome::Denied
                    };
                }
                Ok(Some(NotificationEvent::Closed {
                    id: event_id,
                    reason,
                })) if event_id == id => {
                    // Already gone: nothing to withdraw.
                    return if reason == CLOSED_EXPIRED {
                        PresenceOutcome::TimedOut
                    } else {
                        PresenceOutcome::Denied
                    };
                }
                Ok(_) => {}
                Err(err) => {
                    log::error!("{}", Unavailable::Failed(err).message(request));
                    break PresenceOutcome::Denied;
                }
            }
        };
        // The answer is final whatever happens here. A server may keep a
        // notification whose action was invoked; withdraw it either way.
        if let Err(err) = self.server.close(id) {
            log::debug!("could not withdraw notification {id}: {err}");
        }
        outcome
    }
}

impl<S: NotificationServer> UserPresence for NotificationPresence<S> {
    fn confirm(
        &mut self,
        request: &PresenceRequest<'_>,
        cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        let outcome = self.ask(request, cancellation);
        // Whatever the answer, the prompt is gone from the screen by now.
        self.forget_prompt();
        self.server.disconnect();
        log::info!("presence request {:?}: {outcome:?}", request.operation);
        outcome
    }
}

/// Why a request was denied without asking.
enum Unavailable {
    Connect(ConnectError),
    NoActions,
    NoBody,
    Failed(String),
}

impl Unavailable {
    fn message(&self, request: &PresenceRequest<'_>) -> String {
        const OPT_OUT: &str = "or, for tests only, start the daemon with --presence auto-approve, which approves everything without asking";
        // The summary, unlike the prompt, holds no text from the request.
        let denied = format!("denied without asking ({}): ", summary(request));
        match self {
            Unavailable::Connect(ConnectError::NoSessionBus(err)) => format!(
                "{denied}cannot ask for user presence because there is no D-Bus session bus ({err}). \
                 Run the daemon in your desktop session, for example as the systemd user service, \
                 so that DBUS_SESSION_BUS_ADDRESS is set, {OPT_OUT}"
            ),
            Unavailable::Connect(ConnectError::NoServer(err)) => format!(
                "{denied}cannot ask for user presence because no desktop notification server \
                 answers on the session bus ({err}). Log in to a desktop that provides one, or run \
                 a notification daemon that supports action buttons, {OPT_OUT}"
            ),
            Unavailable::Connect(ConnectError::Failed(err)) => format!(
                "{denied}cannot ask for user presence because the notification server could not \
                 be reached ({err}); {OPT_OUT}"
            ),
            Unavailable::NoActions => format!(
                "{denied}cannot ask for user presence because the desktop notification server \
                 cannot show Approve and Deny buttons (it lacks the \"actions\" capability). Use a \
                 notification server that supports actions, such as GNOME Shell, KDE Plasma or \
                 dunst, {OPT_OUT}"
            ),
            Unavailable::NoBody => format!(
                "{denied}cannot ask for user presence because the desktop notification server \
                 shows no notification text (it lacks the \"body\" capability), so the prompt \
                 could not say what it asks to approve. Use a notification server that shows \
                 bodies, such as GNOME Shell, KDE Plasma or dunst, {OPT_OUT}"
            ),
            Unavailable::Failed(err) => {
                format!("{denied}the desktop notification server failed ({err}); {OPT_OUT}")
            }
        }
    }
}

/// The notification for `request`; `markup` if the server interprets markup
/// in the body.
pub fn notification_for(request: &PresenceRequest<'_>, markup: bool) -> Notification {
    let text = prompt_text(request);
    Notification {
        summary: summary(request),
        body: if markup { escape_markup(&text) } else { text },
        timeout: request.timeout,
    }
}

/// The notification title for `request`'s operation: fixed text, nothing
/// the request's sender chose.
fn summary(request: &PresenceRequest<'_>) -> &'static str {
    match request.operation {
        PresenceOperation::Register if request.discoverable => "Create a passkey",
        // The relying party keeps the credential: nothing is stored on the
        // key, and `pqkey passkeys` will not list it.
        PresenceOperation::Register => "Register a security key",
        PresenceOperation::Authenticate => "Sign in with a passkey",
        PresenceOperation::Reset => "Reset the security key",
        PresenceOperation::CredentialManagement => "Manage passkeys",
        PresenceOperation::Select => "Select a security key",
        _ => "Security key request",
    }
}

/// The question the user is asked, in plain text, with every string from the
/// request sanitised.
pub fn prompt_text(request: &PresenceRequest<'_>) -> String {
    let rp = request
        .rp_id
        .and_then(|rp| sanitise(rp, MAX_RP_ID_CHARS, Keep::End));
    // "The prompt SHOULD display rpEntity.id, rpEntity.name, userEntity.name
    // and userEntity.displayName, if possible." (WebAuthn Level 3 §6.3.2 step
    // 6)  Any website can claim any name, so it only ever follows the RP ID,
    // quoted as a claim, and is left out where it just repeats the ID.
    let rp_name = request
        .rp_name
        .and_then(|name| sanitise(name, MAX_USER_CHARS, Keep::Start))
        .filter(|name| Some(name) != rp.as_ref());
    let name = request
        .user_name
        .and_then(|name| sanitise(name, MAX_USER_CHARS, Keep::Start));
    let display_name = request
        .user_display_name
        .and_then(|name| sanitise(name, MAX_USER_CHARS, Keep::Start));
    let user = match (name, display_name) {
        (Some(name), Some(display)) if display != name => Some(format!("{name} ({display})")),
        (Some(name), _) => Some(name),
        (None, display) => display,
    };
    let as_user = user.map(|user| format!(" as {user}")).unwrap_or_default();
    match (request.operation, rp) {
        (PresenceOperation::Register, Some(rp)) => {
            let rp_name = rp_name
                .map(|name| format!(" (\u{201c}{name}\u{201d})"))
                .unwrap_or_default();
            if request.discoverable {
                format!("Create a passkey for {rp}{rp_name}{as_user}?")
            } else {
                format!("Register this security key with {rp}{rp_name}{as_user}?")
            }
        }
        (PresenceOperation::Authenticate, Some(rp)) => format!("Sign in to {rp}{as_user}?"),
        // The platform asks the user to pick this authenticator among
        // several; no relying party is involved.
        (PresenceOperation::Select, _) => "Select this security key?".to_owned(),
        // The engine always names the relying party of a registration or
        // sign-in; a request without a usable one is not described as either.
        (PresenceOperation::Register | PresenceOperation::Authenticate, None) => {
            "Use this security key?".to_owned()
        }
        (PresenceOperation::Reset, _) => "Reset the security key? Every passkey and every \
             other sign-in made with it stops working, and its PIN is removed."
            .to_owned(),
        (PresenceOperation::CredentialManagement, _) => {
            "Allow access to the passkeys stored on the security key?".to_owned()
        }
        _ => "Allow a request to the security key?".to_owned(),
    }
}

/// Which end of a long text [`sanitise`] keeps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keep {
    Start,
    End,
}

/// `text` made safe to show: control characters become spaces, invisible
/// characters ([`is_invisible_format`]) are removed, runs of whitespace collapse, and anything longer than
/// `max_chars` is cut, keeping its start or its end, with an ellipsis. `None`
/// if nothing is left.
pub(crate) fn sanitise(text: &str, max_chars: usize, keep: Keep) -> Option<String> {
    let mut cleaned = String::with_capacity(text.len().min(4 * max_chars));
    for c in text.chars() {
        if is_invisible_format(c) {
            continue;
        }
        let c = if c.is_control() || c.is_whitespace() {
            ' '
        } else {
            c
        };
        if c == ' ' && (cleaned.is_empty() || cleaned.ends_with(' ')) {
            continue;
        }
        cleaned.push(c);
    }
    let cleaned = cleaned.trim_end();
    let count = cleaned.chars().count();
    if count == 0 {
        return None;
    }
    if count <= max_chars {
        return Some(cleaned.to_owned());
    }
    let kept = max_chars - 1;
    Some(match keep {
        Keep::Start => format!("{}…", cleaned.chars().take(kept).collect::<String>()),
        Keep::End => format!(
            "…{}",
            cleaned.chars().skip(count - kept).collect::<String>()
        ),
    })
}

/// Characters that are not displayed themselves but can change how the text
/// around them is: every Default_Ignorable_Code_Point and every character of
/// general category Cf (format) in Unicode 16.0, including bidirectional
/// overrides, zero-width characters, tag characters and variation selectors.
///
/// Generated from DerivedCoreProperties-16.0.0.txt and
/// extracted/DerivedGeneralCategory-16.0.0.txt of the Unicode Character
/// Database: the code points with `Default_Ignorable_Code_Point` or `Cf`,
/// merged into ranges.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// `text` with the characters the notification markup (a subset of XML)
/// gives meaning to replaced by entities.
fn escape_markup(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c => escaped.push(c),
        }
    }
    escaped
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::NoSessionBus(err) => write!(f, "no session bus: {err}"),
            ConnectError::NoServer(err) => write!(f, "no notification server: {err}"),
            ConnectError::Failed(err) => f.write_str(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqkey_ctap::ctap::InterruptFlag;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        thread,
    };

    /// What the fake server was asked to do.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Connect,
        Notify(Notification),
        Close(u32),
        Nudge,
        Disconnect,
    }

    #[derive(Default)]
    struct Script {
        connect: Option<Result<ServerInfo, ConnectError>>,
        notify: Option<Result<u32, String>>,
        /// What a nudge fails with; it succeeds otherwise.
        nudge_error: Option<String>,
        /// A prompt record to read, with its mode, at every `next_event`.
        record_to_observe: Option<PathBuf>,
        observed_records: Vec<Option<String>>,
        /// Events delivered in order, each once `next_event` has been called
        /// the given number of times since the previous one.
        events: VecDeque<Result<NotificationEvent, String>>,
        calls: Vec<Call>,
    }

    /// A notification server that follows a script and records the calls.
    #[derive(Clone, Default)]
    struct FakeServer(Arc<Mutex<Script>>);

    impl FakeServer {
        fn with_capabilities(capabilities: &[&str]) -> Self {
            let server = Self::default();
            server.script().connect = Some(Ok(ServerInfo {
                capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
                name: None,
                owner: Some(":1.42".into()),
                bus_id: Some("0123456789abcdef0123456789abcdef".into()),
            }));
            server.script().notify = Some(Ok(7));
            server
        }

        /// A working server that answers GetServerInformation with `name`.
        fn named(name: &str) -> Self {
            let server = Self::working();
            if let Some(Ok(info)) = server.script().connect.as_mut() {
                info.name = Some(name.to_owned());
            }
            server
        }

        fn nudges(&self) -> usize {
            self.calls()
                .iter()
                .filter(|call| **call == Call::Nudge)
                .count()
        }

        fn working() -> Self {
            Self::with_capabilities(&["actions", "body"])
        }

        fn script(&self) -> std::sync::MutexGuard<'_, Script> {
            self.0.lock().unwrap()
        }

        fn event(self, event: NotificationEvent) -> Self {
            self.script().events.push_back(Ok(event));
            self
        }

        fn calls(&self) -> Vec<Call> {
            self.script().calls.clone()
        }
    }

    impl NotificationServer for FakeServer {
        fn connect(&mut self) -> Result<ServerInfo, ConnectError> {
            let mut script = self.script();
            script.calls.push(Call::Connect);
            script.connect.clone().expect("connect not scripted")
        }

        fn notify(&mut self, notification: &Notification) -> Result<u32, String> {
            let mut script = self.script();
            script.calls.push(Call::Notify(notification.clone()));
            script.notify.clone().expect("notify not scripted")
        }

        fn nudge(&mut self) -> Result<u32, String> {
            let mut script = self.script();
            script.calls.push(Call::Nudge);
            match &script.nudge_error {
                Some(err) => Err(err.clone()),
                None => Ok(1000 + script.calls.len() as u32),
            }
        }

        fn next_event(&mut self, wait: Duration) -> Result<Option<NotificationEvent>, String> {
            let observe = self.script().record_to_observe.clone();
            if let Some(path) = observe {
                use std::os::unix::fs::PermissionsExt;
                let record = fs::metadata(&path).ok().map(|meta| {
                    assert_eq!(meta.permissions().mode() & 0o777, 0o600, "record mode");
                    fs::read_to_string(&path).unwrap()
                });
                self.script().observed_records.push(record);
            }
            assert!(
                wait <= CANCELLATION_POLL,
                "waited {wait:?} without looking at cancellation"
            );
            let next = self.script().events.pop_front();
            match next {
                Some(event) => event.map(Some),
                None => {
                    thread::sleep(wait);
                    Ok(None)
                }
            }
        }

        fn close(&mut self, id: u32) -> Result<(), String> {
            self.script().calls.push(Call::Close(id));
            Ok(())
        }

        fn disconnect(&mut self) {
            self.script().calls.push(Call::Disconnect);
        }
    }

    const TIMEOUT: Duration = Duration::from_secs(30);

    fn register<'a>() -> PresenceRequest<'a> {
        PresenceRequest {
            rp_id: Some("example.com"),
            user_name: Some("alice"),
            user_display_name: Some("Alice"),
            discoverable: true,
            ..PresenceRequest::new(PresenceOperation::Register, TIMEOUT)
        }
    }

    fn working_flag() -> InterruptFlag {
        let flag = InterruptFlag::new();
        flag.set_working();
        flag
    }

    fn confirm(server: &FakeServer, request: &PresenceRequest<'_>) -> PresenceOutcome {
        let flag = working_flag();
        NotificationPresence::new(server.clone()).confirm(request, Cancellation::new(&flag))
    }

    fn notified(server: &FakeServer) -> Notification {
        server
            .calls()
            .into_iter()
            .find_map(|call| match call {
                Call::Notify(notification) => Some(notification),
                _ => None,
            })
            .expect("nothing was shown")
    }

    /// The relying party and user names come from an unverified request;
    /// only debug logs may carry them.
    #[test]
    fn only_debug_logs_name_the_relying_party_or_the_user() {
        use crate::test_support::logs;
        use log::Level;

        logs::install();
        let request = PresenceRequest {
            rp_id: Some("logged-rp.example"),
            user_name: Some("logged-user"),
            user_display_name: Some("Logged Display Name"),
            ..register()
        };
        let answered = FakeServer::working().event(NotificationEvent::ActionInvoked {
            id: 7,
            key: DENY_ACTION.into(),
        });
        assert_eq!(confirm(&answered, &request), PresenceOutcome::Denied);
        let unreachable = FakeServer::default();
        unreachable.script().connect = Some(Err(ConnectError::Failed("broken".into())));
        assert_eq!(confirm(&unreachable, &request), PresenceOutcome::Denied);

        for needle in ["logged-rp.example", "logged-user", "Logged Display Name"] {
            let logged = logs::containing(needle);
            assert!(!logged.is_empty(), "the prompt is logged at debug level");
            assert!(
                logged.iter().all(|(level, _)| *level >= Level::Debug),
                "{needle} logged above debug level: {logged:?}"
            );
        }
    }

    #[test]
    fn approve_approves_and_withdraws_the_notification() {
        let server = FakeServer::working().event(NotificationEvent::ActionInvoked {
            id: 7,
            key: APPROVE_ACTION.into(),
        });
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Approved);
        assert_eq!(
            server.calls(),
            [
                Call::Connect,
                Call::Notify(Notification {
                    summary: "Create a passkey",
                    body: "Create a passkey for example.com as alice (Alice)?".into(),
                    timeout: TIMEOUT,
                }),
                Call::Close(7),
                Call::Disconnect,
            ]
        );
    }

    #[test]
    fn deny_denies() {
        let server = FakeServer::working().event(NotificationEvent::ActionInvoked {
            id: 7,
            key: DENY_ACTION.into(),
        });
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
        assert!(server.calls().contains(&Call::Close(7)));
    }

    #[test]
    fn any_other_action_denies() {
        let server = FakeServer::working().event(NotificationEvent::ActionInvoked {
            id: 7,
            key: "default".into(),
        });
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
    }

    #[test]
    fn dismissing_or_closing_the_notification_denies() {
        for reason in [2, 3, 4, 99] {
            let server = FakeServer::working().event(NotificationEvent::Closed { id: 7, reason });
            assert_eq!(
                confirm(&server, &register()),
                PresenceOutcome::Denied,
                "reason {reason}"
            );
            assert!(!server.calls().contains(&Call::Close(7)), "reason {reason}");
            assert_eq!(server.calls().last(), Some(&Call::Disconnect));
        }
    }

    #[test]
    fn a_notification_the_server_lets_expire_times_out() {
        let server = FakeServer::working().event(NotificationEvent::Closed { id: 7, reason: 1 });
        assert_eq!(confirm(&server, &register()), PresenceOutcome::TimedOut);
    }

    #[test]
    fn events_about_other_notifications_are_ignored() {
        let server = FakeServer::working()
            .event(NotificationEvent::ActionInvoked {
                id: 6,
                key: APPROVE_ACTION.into(),
            })
            .event(NotificationEvent::Closed { id: 8, reason: 2 })
            .event(NotificationEvent::ActionInvoked {
                id: 7,
                key: DENY_ACTION.into(),
            });
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
    }

    #[test]
    fn no_answer_within_the_timeout_times_out_and_withdraws_the_notification() {
        let server = FakeServer::working();
        let request = PresenceRequest {
            timeout: Duration::from_millis(150),
            ..register()
        };
        let started = Instant::now();
        assert_eq!(confirm(&server, &request), PresenceOutcome::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(&server.calls()[2..], [Call::Close(7), Call::Disconnect]);
    }

    #[test]
    fn cancellation_withdraws_the_notification_within_100_ms() {
        let server = FakeServer::working();
        let flag = working_flag();
        let mut presence = NotificationPresence::new(server.clone());
        let (outcome, cancelled_at) = thread::scope(|scope| {
            let canceller = scope.spawn(|| {
                while !server.calls().iter().any(|c| matches!(c, Call::Notify(_))) {
                    thread::sleep(Duration::from_millis(1));
                }
                thread::sleep(Duration::from_millis(200));
                flag.interrupt();
                Instant::now()
            });
            let outcome = presence.confirm(&register(), Cancellation::new(&flag));
            (outcome, canceller.join().unwrap())
        });
        let latency = cancelled_at.elapsed();
        assert_eq!(outcome, PresenceOutcome::Cancelled);
        assert!(latency <= Duration::from_millis(100), "{latency:?}");
        assert_eq!(&server.calls()[2..], [Call::Close(7), Call::Disconnect]);
    }

    #[test]
    fn a_request_cancelled_before_it_is_shown_is_not_shown() {
        let server = FakeServer::working();
        let flag = working_flag();
        flag.interrupt();
        let outcome = NotificationPresence::new(server.clone())
            .confirm(&register(), Cancellation::new(&flag));
        assert_eq!(outcome, PresenceOutcome::Cancelled);
        assert_eq!(server.calls(), [Call::Connect, Call::Disconnect]);
    }

    #[test]
    fn no_session_bus_or_server_denies() {
        for err in [
            ConnectError::NoSessionBus("DBUS_SESSION_BUS_ADDRESS is not set".into()),
            ConnectError::NoServer("org.freedesktop.DBus.Error.ServiceUnknown".into()),
            ConnectError::Failed("broken".into()),
        ] {
            let server = FakeServer::default();
            server.script().connect = Some(Err(err.clone()));
            assert_eq!(
                confirm(&server, &register()),
                PresenceOutcome::Denied,
                "{err}"
            );
            assert_eq!(server.calls(), [Call::Connect, Call::Disconnect]);
        }
    }

    #[test]
    fn a_server_without_actions_denies_without_showing_anything() {
        let server = FakeServer::with_capabilities(&["body", "body-markup"]);
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
        assert_eq!(server.calls(), [Call::Connect, Call::Disconnect]);
    }

    /// The relying party, the account and what a reset deletes are all in
    /// the body, so a server that shows only summaries cannot ask the user
    /// anything meaningful (notification spec §3: "Some implementations may
    /// only show the summary").
    #[test]
    fn a_server_without_bodies_denies_without_showing_anything() {
        let server = FakeServer::with_capabilities(&["actions"]);
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
        assert_eq!(server.calls(), [Call::Connect, Call::Disconnect]);
    }

    #[test]
    fn failing_to_show_or_to_wait_denies() {
        let server = FakeServer::working();
        server.script().notify = Some(Err("org.freedesktop.DBus.Error.NoReply".into()));
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
        assert_eq!(server.calls().last(), Some(&Call::Disconnect));

        let server = FakeServer::working();
        server
            .script()
            .events
            .push_back(Err("the connection closed".into()));
        assert_eq!(confirm(&server, &register()), PresenceOutcome::Denied);
        assert_eq!(&server.calls()[2..], [Call::Close(7), Call::Disconnect]);
    }

    fn text(operation: PresenceOperation, rp_id: Option<&str>, name: Option<&str>) -> String {
        prompt_text(&PresenceRequest {
            rp_id,
            user_name: name,
            ..PresenceRequest::new(operation, TIMEOUT)
        })
    }

    #[test]
    fn the_question_names_the_operation_and_the_relying_party() {
        use PresenceOperation::*;
        assert_eq!(
            text(Register, Some("example.com"), None),
            "Register this security key with example.com?"
        );
        assert_eq!(
            text(Register, Some("example.com"), Some("alice")),
            "Register this security key with example.com as alice?"
        );
        assert_eq!(
            prompt_text(&PresenceRequest {
                rp_id: Some("example.com"),
                user_name: Some("alice"),
                discoverable: true,
                ..PresenceRequest::new(Register, TIMEOUT)
            }),
            "Create a passkey for example.com as alice?"
        );
        assert_eq!(
            text(Authenticate, Some("example.com"), Some("alice")),
            "Sign in to example.com as alice?"
        );
        assert_eq!(
            text(Authenticate, Some("example.com"), None),
            "Sign in to example.com?"
        );
        // It says what a reset does to a user who may not call every
        // credential a passkey (REPORT F12).
        assert_eq!(
            text(Reset, None, None),
            "Reset the security key? Every passkey and every other sign-in made \
             with it stops working, and its PIN is removed."
        );
        assert_eq!(
            text(CredentialManagement, None, None),
            "Allow access to the passkeys stored on the security key?"
        );
        assert_eq!(text(Select, None, None), "Select this security key?");
        // A name without a relying party is not shown.
        assert_eq!(
            text(Select, None, Some("alice")),
            "Select this security key?"
        );
        assert_eq!(text(Authenticate, None, None), "Use this security key?");
        assert_eq!(
            prompt_text(&PresenceRequest {
                rp_id: Some("example.com"),
                user_name: Some("alice"),
                user_display_name: Some("Alice"),
                ..PresenceRequest::new(Authenticate, TIMEOUT)
            }),
            "Sign in to example.com as alice (Alice)?"
        );
        assert_eq!(
            prompt_text(&PresenceRequest {
                rp_id: Some("example.com"),
                user_display_name: Some("Alice"),
                discoverable: true,
                ..PresenceRequest::new(Register, TIMEOUT)
            }),
            "Create a passkey for example.com as Alice?"
        );

        // The relying party's own name, as it claims it, follows its ID, and
        // is left out when it only repeats the ID.
        assert_eq!(
            prompt_text(&PresenceRequest {
                rp_id: Some("example.com"),
                rp_name: Some("Example Corp"),
                user_name: Some("alice"),
                ..PresenceRequest::new(Register, TIMEOUT)
            }),
            "Register this security key with example.com (\u{201c}Example Corp\u{201d}) as alice?"
        );
        assert_eq!(
            prompt_text(&PresenceRequest {
                rp_id: Some("example.com"),
                rp_name: Some("example.com"),
                discoverable: true,
                ..PresenceRequest::new(Register, TIMEOUT)
            }),
            "Create a passkey for example.com?"
        );

        let summaries: Vec<_> = [Register, Authenticate, Reset, CredentialManagement, Select]
            .into_iter()
            .map(|op| notification_for(&PresenceRequest::new(op, TIMEOUT), false).summary)
            .collect();
        assert_eq!(
            summaries,
            [
                "Register a security key",
                "Sign in with a passkey",
                "Reset the security key",
                "Manage passkeys",
                "Select a security key"
            ]
        );
        assert_eq!(
            notification_for(&register(), false).summary,
            "Create a passkey"
        );
    }

    #[test]
    fn control_and_invisible_characters_are_removed() {
        assert_eq!(
            text(
                PresenceOperation::Authenticate,
                Some("exa\u{202E}mple.com\n\n"),
                Some("al\u{0}ice\r\nApprove this\u{200B}\u{7}")
            ),
            "Sign in to example.com as al ice Approve this?"
        );
        // Every default-ignorable or format character of Unicode 16.0 is
        // removed: tag characters, Arabic and Kaithi number signs, musical
        // symbol formatting, the combining grapheme joiner, variation
        // selectors and Hangul fillers among them.
        assert_eq!(
            text(
                PresenceOperation::Authenticate,
                Some("ex\u{E0041}\u{E0001}am\u{0600}ple\u{110BD}.\u{1D173}com"),
                Some("a\u{034F}l\u{FE0F}i\u{3164}c\u{115F}e\u{FFA0}\u{180F}")
            ),
            "Sign in to example.com as alice?"
        );
        // Nothing but invisible characters is no name at all.
        assert_eq!(
            text(
                PresenceOperation::Register,
                Some("\u{2066}\u{FEFF}\t"),
                Some("\u{1b}")
            ),
            "Use this security key?"
        );
    }

    #[test]
    fn long_rp_ids_keep_their_end_and_long_names_their_start() {
        let rp_id = format!("accounts.example.com.{}.attacker.example", "a".repeat(200));
        let name = "b".repeat(300);
        let question = text(PresenceOperation::Authenticate, Some(&rp_id), Some(&name));
        let expected_rp = format!("…{}", &rp_id[rp_id.len() - (MAX_RP_ID_CHARS - 1)..]);
        let expected_name = format!("{}…", "b".repeat(MAX_USER_CHARS - 1));
        assert_eq!(
            question,
            format!("Sign in to {expected_rp} as {expected_name}?")
        );
        assert!(question.contains(".attacker.example as "));

        // Characters, not bytes.
        let wide = "é".repeat(MAX_USER_CHARS);
        assert_eq!(
            sanitise(&wide, MAX_USER_CHARS, Keep::Start).as_deref(),
            Some(wide.as_str())
        );
    }

    #[test]
    fn markup_is_escaped_only_for_servers_that_interpret_it() {
        let request = PresenceRequest {
            rp_id: Some("<b>evil</b>.example"),
            user_name: Some("<a href=\"https://x\">bob</a> & 'co'"),
            discoverable: true,
            ..PresenceRequest::new(PresenceOperation::Register, TIMEOUT)
        };
        let plain = notification_for(&request, false);
        assert_eq!(
            plain.body,
            "Create a passkey for <b>evil</b>.example as <a href=\"https://x\">bob</a> & 'co'?"
        );
        let escaped = notification_for(&request, true);
        assert_eq!(
            escaped.body,
            "Create a passkey for &lt;b&gt;evil&lt;/b&gt;.example as \
             &lt;a href=&quot;https://x&quot;&gt;bob&lt;/a&gt; &amp; &apos;co&apos;?"
        );
        assert!(!escaped.body.contains(['<', '>', '"', '\'']));

        let server = FakeServer::with_capabilities(&["actions", "body", "body-markup"]).event(
            NotificationEvent::ActionInvoked {
                id: 7,
                key: DENY_ACTION.into(),
            },
        );
        confirm(&server, &request);
        assert_eq!(notified(&server), escaped);
    }

    /// The interval tests nudge at.
    const TEST_NUDGE: Duration = Duration::from_millis(30);

    fn confirm_nudging(server: &FakeServer, request: &PresenceRequest<'_>) -> PresenceOutcome {
        let flag = working_flag();
        NotificationPresence::new(server.clone())
            .with_nudge_interval(TEST_NUDGE)
            .confirm(request, Cancellation::new(&flag))
    }

    fn short(operation: PresenceOperation, timeout_ms: u64) -> PresenceRequest<'static> {
        PresenceRequest {
            rp_id: Some("example.com"),
            ..PresenceRequest::new(operation, Duration::from_millis(timeout_ms))
        }
    }

    /// On GNOME Shell a prompt that waits is nudged every interval, between
    /// showing it and withdrawing it, and the request still times out when
    /// its own timeout says.
    ///
    /// The prompt waits a second, many nudge intervals, because a loaded
    /// machine can oversleep each wait several times over (GitHub's macOS
    /// runners take about 100 ms for a 20 ms sleep).
    #[test]
    fn an_unanswered_prompt_is_nudged_on_gnome() {
        let server = FakeServer::named("gnome-shell");
        let started = Instant::now();
        assert_eq!(
            confirm_nudging(&server, &short(PresenceOperation::Register, 1_000)),
            PresenceOutcome::TimedOut
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1_000) && elapsed < Duration::from_millis(1_400),
            "the deadline moved: {elapsed:?}"
        );
        let calls = server.calls();
        assert!(matches!(calls[1], Call::Notify(_)), "{calls:?}");
        assert!(server.nudges() >= 3, "{calls:?}");
        assert!(
            calls[2..calls.len() - 2]
                .iter()
                .all(|call| *call == Call::Nudge),
            "{calls:?}"
        );
        assert_eq!(calls[calls.len() - 2..], [Call::Close(7), Call::Disconnect]);
    }

    /// Other servers have no such queue, and are left alone.
    #[test]
    fn prompts_are_not_nudged_elsewhere() {
        for server in [FakeServer::working(), FakeServer::named("Plasma")] {
            assert_eq!(
                confirm_nudging(&server, &short(PresenceOperation::Authenticate, 120)),
                PresenceOutcome::TimedOut
            );
            assert_eq!(server.nudges(), 0);
        }
    }

    /// Nothing is nudged once the user has answered or the request was
    /// cancelled.
    #[test]
    fn an_answered_or_cancelled_prompt_is_not_nudged() {
        let server = FakeServer::named("gnome-shell").event(NotificationEvent::ActionInvoked {
            id: 7,
            key: APPROVE_ACTION.into(),
        });
        assert_eq!(
            confirm_nudging(&server, &short(PresenceOperation::Register, 5_000)),
            PresenceOutcome::Approved
        );
        assert_eq!(server.nudges(), 0);

        let server = FakeServer::named("gnome-shell");
        let flag = working_flag();
        flag.interrupt();
        let outcome = NotificationPresence::new(server.clone())
            .with_nudge_interval(TEST_NUDGE)
            .confirm(
                &short(PresenceOperation::Register, 5_000),
                Cancellation::new(&flag),
            );
        assert_eq!(outcome, PresenceOutcome::Cancelled);
        assert_eq!(server.nudges(), 0);
    }

    /// A nudge that fails is only logged: the prompt still waits for its
    /// answer, and is not nudged again.
    #[test]
    fn a_failing_nudge_denies_nothing() {
        let server = FakeServer::named("gnome-shell");
        server.script().nudge_error = Some("org.freedesktop.DBus.Error.NoReply".into());
        assert_eq!(
            confirm_nudging(&server, &short(PresenceOperation::Register, 200)),
            PresenceOutcome::TimedOut
        );
        assert_eq!(server.nudges(), 1);
    }

    /// While a prompt is shown its server, bus and ID are recorded, and the
    /// record goes once the request ends, whatever the answer.
    #[test]
    fn a_shown_prompt_is_recorded_until_the_request_ends() {
        let dir = crate::test_support::TempDir::new("prompt-record");
        let path = dir.path().join(PROMPT_FILE);
        let server = FakeServer::working();
        server.script().record_to_observe = Some(path.clone());
        let flag = working_flag();
        let outcome = NotificationPresence::new(server.clone())
            .with_prompt_record(path.clone())
            .confirm(
                &short(PresenceOperation::Register, 100),
                Cancellation::new(&flag),
            );
        assert_eq!(outcome, PresenceOutcome::TimedOut);
        assert_eq!(
            server
                .script()
                .observed_records
                .first()
                .cloned()
                .flatten()
                .as_deref(),
            Some("0123456789abcdef0123456789abcdef\n:1.42\n7\n")
        );
        assert!(!path.exists(), "the record outlived the request");
    }

    /// A prompt a killed daemon left on screen is withdrawn at start-up when
    /// the same server instance still runs, and only then.
    #[test]
    fn a_prompt_left_by_a_killed_daemon_is_withdrawn_at_start() {
        let dir = crate::test_support::TempDir::new("stale-prompt");
        let path = dir.path().join(PROMPT_FILE);
        for (recorded, withdrawn) in [
            ("0123456789abcdef0123456789abcdef\n:1.42\n41\n", true),
            // The server restarted, or another bus: its IDs mean other things.
            ("0123456789abcdef0123456789abcdef\n:1.99\n41\n", false),
            ("ffffffffffffffffffffffffffffffff\n:1.42\n41\n", false),
            ("garbage", false),
        ] {
            fs::write(&path, recorded).unwrap();
            let server = FakeServer::working();
            NotificationPresence::new(server.clone())
                .with_prompt_record(path.clone())
                .withdraw_stale_prompt();
            let expected = if withdrawn {
                vec![Call::Connect, Call::Close(41), Call::Disconnect]
            } else {
                vec![Call::Connect, Call::Disconnect]
            };
            assert_eq!(server.calls(), expected, "{recorded:?}");
            assert!(!path.exists(), "{recorded:?}: the record was kept");
        }

        // Without a record nothing connects at all.
        let server = FakeServer::working();
        NotificationPresence::new(server.clone())
            .with_prompt_record(path.clone())
            .withdraw_stale_prompt();
        assert_eq!(server.calls(), []);
    }

    /// If start-up could not reach the server, the next request withdraws
    /// the stale prompt before it shows its own.
    #[test]
    fn the_next_request_withdraws_a_stale_prompt_first() {
        let dir = crate::test_support::TempDir::new("stale-prompt-request");
        let path = dir.path().join(PROMPT_FILE);
        fs::write(&path, "0123456789abcdef0123456789abcdef\n:1.42\n41\n").unwrap();
        let server = FakeServer::working().event(NotificationEvent::ActionInvoked {
            id: 7,
            key: APPROVE_ACTION.into(),
        });
        let flag = working_flag();
        let outcome = NotificationPresence::new(server.clone())
            .with_prompt_record(path.clone())
            .confirm(&register(), Cancellation::new(&flag));
        assert_eq!(outcome, PresenceOutcome::Approved);
        let calls = server.calls();
        assert_eq!(calls[..2], [Call::Connect, Call::Close(41)]);
        assert!(matches!(calls[2], Call::Notify(_)), "{calls:?}");
        assert!(!path.exists());
    }
}
