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

use std::{
    fmt,
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
    /// server's capabilities (`GetCapabilities`).
    fn connect(&mut self) -> Result<Vec<String>, ConnectError>;
    /// Show `notification` with an Approve and a Deny button (`Notify`), and
    /// return its ID.
    fn notify(&mut self, notification: &Notification) -> Result<u32, String>;
    /// The next event from the server, waiting at most `wait` for one.
    /// Events about other notifications are returned too.
    fn next_event(&mut self, wait: Duration) -> Result<Option<NotificationEvent>, String>;
    /// Withdraw notification `id` (`CloseNotification`).
    fn close(&mut self, id: u32) -> Result<(), String>;
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
#[derive(Debug)]
pub struct NotificationPresence<S> {
    server: S,
}

impl<S: NotificationServer> NotificationPresence<S> {
    pub fn new(server: S) -> Self {
        Self { server }
    }

    fn ask(
        &mut self,
        request: &PresenceRequest<'_>,
        cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        let deadline = Instant::now() + request.timeout;
        let capabilities = match self.server.connect() {
            Ok(capabilities) => capabilities,
            Err(err) => {
                log::error!("{}", Unavailable::Connect(err).message(request));
                return PresenceOutcome::Denied;
            }
        };
        if !capabilities.iter().any(|c| c == "actions") {
            log::error!("{}", Unavailable::NoActions.message(request));
            return PresenceOutcome::Denied;
        }
        let markup = capabilities.iter().any(|c| c == "body-markup");
        let notification = notification_for(request, markup);
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
        log::info!(
            "asking the user with a desktop notification: {}",
            prompt_text(request)
        );

        let outcome = loop {
            if cancellation.is_cancelled() {
                break PresenceOutcome::Cancelled;
            }
            let now = Instant::now();
            if now >= deadline {
                break PresenceOutcome::TimedOut;
            }
            match self
                .server
                .next_event(CANCELLATION_POLL.min(deadline - now))
            {
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
        self.server.disconnect();
        log::info!("presence request {:?}: {outcome:?}", request.operation);
        outcome
    }
}

/// Why a request was denied without asking.
enum Unavailable {
    Connect(ConnectError),
    NoActions,
    Failed(String),
}

impl Unavailable {
    fn message(&self, request: &PresenceRequest<'_>) -> String {
        const OPT_OUT: &str =
            "or, for tests only, start the daemon with --presence auto-approve, which approves everything without asking";
        let denied = format!(
            "denied without asking ({}): ",
            prompt_text(request).trim_end_matches('?')
        );
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
            Unavailable::Failed(err) => format!(
                "{denied}the desktop notification server failed ({err}); {OPT_OUT}"
            ),
        }
    }
}

/// The notification for `request`; `markup` if the server interprets markup
/// in the body.
pub fn notification_for(request: &PresenceRequest<'_>, markup: bool) -> Notification {
    let summary = match request.operation {
        PresenceOperation::Register => "Create a passkey",
        PresenceOperation::Authenticate => "Sign in with a passkey",
        PresenceOperation::Reset => "Reset the security key",
        PresenceOperation::CredentialManagement => "Manage passkeys",
        PresenceOperation::Select => "Select a security key",
        _ => "Security key request",
    };
    let text = prompt_text(request);
    Notification {
        summary,
        body: if markup { escape_markup(&text) } else { text },
        timeout: request.timeout,
    }
}

/// The question the user is asked, in plain text, with every string from the
/// request sanitised.
pub fn prompt_text(request: &PresenceRequest<'_>) -> String {
    let rp = request
        .rp_id
        .and_then(|rp| sanitise(rp, MAX_RP_ID_CHARS, Keep::End));
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
        (PresenceOperation::Register, Some(rp)) => format!("Create a passkey for {rp}{as_user}?"),
        (PresenceOperation::Authenticate, Some(rp)) => format!("Sign in to {rp}{as_user}?"),
        // The platform asks the user to pick this authenticator among
        // several; no relying party is involved.
        (PresenceOperation::Select, _) => "Select this security key?".to_owned(),
        // The engine always names the relying party of a registration or
        // sign-in; a request without a usable one is not described as either.
        (PresenceOperation::Register | PresenceOperation::Authenticate, None) => {
            "Use this security key?".to_owned()
        }
        (PresenceOperation::Reset, _) => {
            "Reset the security key? This deletes all passkeys.".to_owned()
        }
        (PresenceOperation::CredentialManagement, _) => {
            "Allow access to the passkeys stored on the security key?".to_owned()
        }
        _ => "Allow a request to the security key?".to_owned(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    Start,
    End,
}

/// `text` made safe to show: control characters become spaces, invisible
/// formatting characters (bidirectional overrides, zero-width characters)
/// are removed, runs of whitespace collapse, and anything longer than
/// `max_chars` is cut, keeping its start or its end, with an ellipsis. `None`
/// if nothing is left.
fn sanitise(text: &str, max_chars: usize, keep: Keep) -> Option<String> {
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

/// Characters that change how surrounding text is displayed without being
/// visible themselves (Unicode general category Cf, the ones in use).
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
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
        Disconnect,
    }

    #[derive(Default)]
    struct Script {
        connect: Option<Result<Vec<String>, ConnectError>>,
        notify: Option<Result<u32, String>>,
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
            server.script().connect =
                Some(Ok(capabilities.iter().map(|c| c.to_string()).collect()));
            server.script().notify = Some(Ok(7));
            server
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
        fn connect(&mut self) -> Result<Vec<String>, ConnectError> {
            let mut script = self.script();
            script.calls.push(Call::Connect);
            script.connect.clone().expect("connect not scripted")
        }

        fn notify(&mut self, notification: &Notification) -> Result<u32, String> {
            let mut script = self.script();
            script.calls.push(Call::Notify(notification.clone()));
            script.notify.clone().expect("notify not scripted")
        }

        fn next_event(&mut self, wait: Duration) -> Result<Option<NotificationEvent>, String> {
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
            "Create a passkey for example.com?"
        );
        assert_eq!(
            text(Register, Some("example.com"), Some("alice")),
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
        assert_eq!(
            text(Reset, None, None),
            "Reset the security key? This deletes all passkeys."
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
                ..PresenceRequest::new(Register, TIMEOUT)
            }),
            "Create a passkey for example.com as Alice?"
        );

        let summaries: Vec<_> = [Register, Authenticate, Reset, CredentialManagement, Select]
            .into_iter()
            .map(|op| notification_for(&PresenceRequest::new(op, TIMEOUT), false).summary)
            .collect();
        assert_eq!(
            summaries,
            [
                "Create a passkey",
                "Sign in with a passkey",
                "Reset the security key",
                "Manage passkeys",
                "Select a security key"
            ]
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

        let server = FakeServer::with_capabilities(&["actions", "body-markup"]).event(
            NotificationEvent::ActionInvoked {
                id: 7,
                key: DENY_ACTION.into(),
            },
        );
        confirm(&server, &request);
        assert_eq!(notified(&server), escaped);
    }
}
