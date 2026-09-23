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

use futures_lite::{StreamExt, future};
use zbus::{
    MatchRule, Message, MessageStream,
    blocking::{Connection, MessageIterator, fdo::DBusProxy},
    connection,
    message::Type,
    names::BusName,
    zvariant::Value,
};

use super::notification::{
    APPROVE_ACTION, ConnectError, DENY_ACTION, Notification, NotificationEvent, NotificationServer,
};

const NOTIFICATIONS_NAME: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATIONS_INTERFACE: &str = "org.freedesktop.Notifications";

/// The longest connecting to the session bus, or a single D-Bus call, may
/// take. It bounds how long a hung bus or notification server can hold up a
/// cancelled request or the daemon's shutdown.
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
        let builder = connection::Builder::session()
            .map_err(|err| ConnectError::NoSessionBus(err.to_string()))?;
        let connection = connect_bus(builder, METHOD_TIMEOUT)?;

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

/// Connect to the bus `builder` names within `timeout`, with every method
/// call on the connection limited to `timeout` as well.
///
/// zbus limits method calls with the builder's `method_timeout`, but not
/// connecting: authentication and `Hello` wait as long as the bus takes, so a
/// bus that accepts the connection and never answers would hold the presence
/// request, and the daemon's shutdown, forever.
fn connect_bus(
    builder: connection::Builder<'_>,
    timeout: Duration,
) -> Result<Connection, ConnectError> {
    let connect = async {
        builder
            .method_timeout(timeout)
            .build()
            .await
            .map_err(|err| ConnectError::NoSessionBus(err.to_string()))
    };
    let expire = async {
        async_io::Timer::after(timeout).await;
        Err(ConnectError::Failed(format!(
            "the session bus did not answer within {} ms",
            timeout.as_millis()
        )))
    };
    async_io::block_on(future::or(connect, expire)).map(Connection::from)
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

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn connecting_to_a_bus_that_never_answers_times_out() {
        let dir = TempDir::new("silent-bus");
        let path = dir.path().join("bus");
        // The kernel accepts connections into the backlog; nothing ever reads
        // from them or answers.
        let _listener = UnixListener::bind(&path).unwrap();
        let address = format!("unix:path={}", path.display());
        let builder = connection::Builder::address(address.as_str()).unwrap();

        let timeout = Duration::from_millis(200);
        let started = Instant::now();
        match connect_bus(builder, timeout) {
            Err(ConnectError::Failed(err)) => assert!(err.contains("did not answer"), "{err}"),
            Err(err) => panic!("unexpected error: {err:?}"),
            Ok(_) => panic!("connected to a bus that never answers"),
        }
        let elapsed = started.elapsed();
        assert!(elapsed >= timeout, "gave up after {elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "gave up only after {elapsed:?}"
        );
    }
}
