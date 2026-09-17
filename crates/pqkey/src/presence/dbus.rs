//! The desktop notification server on the D-Bus session bus.
//!
//! A new connection is opened for every presence request and closed when the
//! request ends, rather than one connection held for the daemon's lifetime:
//!
//! * The daemon usually starts with the user's service manager, before the
//!   desktop session and its notification server exist, and it outlives
//!   them when the user logs out and in again. A connection per request
//!   always reaches the session bus and notification server of the moment,
//!   with no reconnection logic that could itself go stale.
//! * The server's capabilities and the unique bus name its signals must come
//!   from are looked up again each time, so a replaced notification server
//!   is neither missed nor impersonated by its successor's name.
//! * Presence requests are rare and wait for a person for seconds; the few
//!   milliseconds a connection takes do not matter, and nothing is kept open
//!   while the daemon is idle.

use std::{
    collections::HashMap,
    thread,
    time::{Duration, Instant},
};

use futures_lite::{future, StreamExt};
use zbus::{
    blocking::{connection, fdo::DBusProxy, Connection, MessageIterator},
    message::Type,
    names::BusName,
    zvariant::Value,
    MatchRule, Message, MessageStream,
};

use super::notification::{
    ConnectError, Notification, NotificationEvent, NotificationServer, APPROVE_ACTION, DENY_ACTION,
};

const NOTIFICATIONS_NAME: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";

/// The longest a single D-Bus call may take. It bounds how long a hung
/// notification server can hold up a cancelled request or the daemon's
/// shutdown.
const METHOD_TIMEOUT: Duration = Duration::from_secs(2);

/// How often [`SessionBus::next_event`] looks for a signal.
const EVENT_POLL: Duration = Duration::from_millis(5);

/// The application name notifications are shown under.
const APP_NAME: &str = "Security key";
/// A freedesktop.org icon naming specification name.
const APP_ICON: &str = "security-high";
/// The `urgency` hint for critical notifications, which servers keep on
/// screen until they are answered.
const URGENCY_CRITICAL: u8 = 2;

/// Notifications through org.freedesktop.Notifications on the session bus.
#[derive(Default)]
pub struct SessionBus {
    session: Option<Session>,
}

/// The connection for one presence request.
struct Session {
    connection: Connection,
    /// Signals from the notification server's unique name.
    signals: MessageStream,
}

impl SessionBus {
    pub fn new() -> Self {
        Self::default()
    }

    fn session(&mut self) -> Result<&mut Session, String> {
        self.session
            .as_mut()
            .ok_or_else(|| "not connected to the session bus".to_owned())
    }
}

impl NotificationServer for SessionBus {
    fn connect(&mut self) -> Result<Vec<String>, ConnectError> {
        self.disconnect();
        // Uses DBUS_SESSION_BUS_ADDRESS, or $XDG_RUNTIME_DIR/bus without it.
        let connection = connection::Builder::session()
            .map(|builder| builder.method_timeout(METHOD_TIMEOUT))
            .and_then(|builder| builder.build())
            .map_err(|err| ConnectError::NoSessionBus(err.to_string()))?;

        // Also starts a D-Bus activatable server that is not running yet.
        let capabilities: Vec<String> = connection
            .call_method(
                Some(NOTIFICATIONS_NAME),
                NOTIFICATIONS_PATH,
                Some(NOTIFICATIONS_INTERFACE),
                "GetCapabilities",
                &(),
            )
            .and_then(|reply| reply.body().deserialize())
            .map_err(|err| ConnectError::NoServer(err.to_string()))?;

        // Only signals from the process that owns the name count: any client
        // on the bus can emit a signal claiming to be ActionInvoked.
        let owner = DBusProxy::new(&connection)
            .and_then(|bus| {
                let name = BusName::try_from(NOTIFICATIONS_NAME)?;
                Ok(bus.get_name_owner(name)?)
            })
            .map_err(|err: zbus::Error| ConnectError::NoServer(err.to_string()))?;
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(owner.as_str())
            .and_then(|rule| rule.path(NOTIFICATIONS_PATH))
            .and_then(|rule| rule.interface(NOTIFICATIONS_INTERFACE))
            .map(|rule| rule.build())
            .map_err(|err| ConnectError::Failed(err.to_string()))?;
        let signals = MessageIterator::for_match_rule(rule, &connection, Some(64))
            .map_err(|err| ConnectError::Failed(err.to_string()))?
            .into_inner();

        self.session = Some(Session {
            connection,
            signals,
        });
        Ok(capabilities)
    }

    fn notify(&mut self, notification: &Notification) -> Result<u32, String> {
        let session = self.session()?;
        let actions = [APPROVE_ACTION, "Approve", DENY_ACTION, "Deny"];
        let hints = HashMap::from([
            ("urgency", Value::U8(URGENCY_CRITICAL)),
            ("category", Value::from("device")),
        ]);
        let expire_timeout = i32::try_from(notification.timeout.as_millis()).unwrap_or(i32::MAX);
        session
            .connection
            .call_method(
                Some(NOTIFICATIONS_NAME),
                NOTIFICATIONS_PATH,
                Some(NOTIFICATIONS_INTERFACE),
                "Notify",
                &(
                    APP_NAME,
                    0u32,
                    APP_ICON,
                    notification.summary,
                    notification.body.as_str(),
                    &actions[..],
                    hints,
                    expire_timeout,
                ),
            )
            .and_then(|reply| reply.body().deserialize::<u32>())
            .map_err(|err| format!("Notify failed: {err}"))
    }

    fn next_event(&mut self, wait: Duration) -> Result<Option<NotificationEvent>, String> {
        let session = self.session()?;
        let deadline = Instant::now() + wait;
        loop {
            // Messages are read from the socket on zbus's own thread; this
            // only takes what has arrived.
            match future::block_on(future::poll_once(session.signals.next())) {
                Some(Some(Ok(message))) => {
                    if let Some(event) = parse_signal(&message) {
                        return Ok(Some(event));
                    }
                }
                Some(Some(Err(err))) => return Err(err.to_string()),
                Some(None) => return Err("the session bus connection closed".to_owned()),
                None => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(None);
                    }
                    thread::sleep(EVENT_POLL.min(deadline - now));
                }
            }
        }
    }

    fn close(&mut self, id: u32) -> Result<(), String> {
        self.session()?
            .connection
            .call_method(
                Some(NOTIFICATIONS_NAME),
                NOTIFICATIONS_PATH,
                Some(NOTIFICATIONS_INTERFACE),
                "CloseNotification",
                &(id,),
            )
            .map(drop)
            .map_err(|err| format!("CloseNotification failed: {err}"))
    }

    fn disconnect(&mut self) {
        if let Some(Session {
            connection,
            signals,
        }) = self.session.take()
        {
            drop(signals);
            if let Err(err) = connection.close() {
                log::debug!("closing the session bus connection: {err}");
            }
        }
    }
}

impl Drop for SessionBus {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// The event an ActionInvoked or NotificationClosed signal reports.
fn parse_signal(message: &Message) -> Option<NotificationEvent> {
    let header = message.header();
    let body = message.body();
    match header.member()?.as_str() {
        "ActionInvoked" => {
            let (id, key): (u32, String) = body.deserialize().ok()?;
            Some(NotificationEvent::ActionInvoked { id, key })
        }
        "NotificationClosed" => {
            let (id, reason): (u32, u32) = body.deserialize().ok()?;
            Some(NotificationEvent::Closed { id, reason })
        }
        _ => None,
    }
}
