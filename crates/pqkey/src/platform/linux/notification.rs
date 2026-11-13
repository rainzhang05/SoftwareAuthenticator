//! Linux notification details and diagnostics.

use crate::presence::notification::{ConnectError, Unavailable};
use std::time::Duration;

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

pub(crate) fn refresh_interval(name: Option<&str>) -> Option<Duration> {
    (name == Some(GNOME_SHELL)).then_some(NUDGE_INTERVAL)
}

/// The error logged when `unavailable` denied the request `summary` names
/// without asking: why, and how to make the prompt work. Never how to do
/// without it: `--presence auto-approve` lets anything running as the user
/// use the passkeys unnoticed.
pub(crate) fn failure_message(unavailable: &Unavailable, summary: &str) -> String {
    // `pqkey status` connects as the daemon does, to the session bus the
    // daemon published (cli/daemon_info.rs), but never to one over TCP: that
    // is the problem for the service, and for a daemon started by hand status
    // checks the bus of its own environment instead
    // (`checks::key_notification_problem`). It sees what is wrong only while
    // it runs.
    const STATUS: &str = "`pqkey status` checks this on the daemon's session bus while the \
        daemon runs, and names the fix while the problem lasts. For a daemon started by hand on a \
        TCP bus, it checks the session bus of the terminal it runs in instead";
    // The summary, unlike the prompt, holds no text from the request.
    let denied = format!("denied without asking ({}): ", summary);
    match unavailable {
        // The service, too, may lack a bus: it has the service manager's
        // environment, which the import changes for the restarted key.
        Unavailable::Connect(ConnectError::NoSession(err)) => format!(
            "{denied}cannot ask for user presence because the daemon cannot connect to a D-Bus \
                 session bus ({err}). In a terminal of your desktop session, run `systemctl --user \
                 import-environment DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey start`. \
                 {STATUS}"
        ),
        Unavailable::Connect(ConnectError::NoServer(err)) => format!(
            "{denied}cannot ask for user presence because no desktop notification server \
                 answers on the daemon's session bus ({err}). Log in to a desktop that provides \
                 one, or run a notification daemon that supports action buttons. {STATUS}"
        ),
        Unavailable::Connect(ConnectError::Failed(err)) => format!(
            "{denied}cannot ask for user presence because the notification server could not \
                 be reached ({err}). Try again, as each request connects anew. {STATUS}"
        ),
        Unavailable::NoActions => format!(
            "{denied}cannot ask for user presence because the desktop notification server \
                 cannot show Approve and Deny buttons (it lacks the \"actions\" capability). Use a \
                 notification server that supports actions, such as GNOME Shell, KDE Plasma or \
                 dunst. {STATUS}"
        ),
        Unavailable::NoBody => format!(
            "{denied}cannot ask for user presence because the desktop notification server \
                 shows no notification text (it lacks the \"body\" capability), so the prompt \
                 could not say what it asks to approve. Use a notification server that shows \
                 bodies, such as GNOME Shell, KDE Plasma or dunst. {STATUS}"
        ),
        // Showing the prompt or waiting for its answer failed, which
        // `pqkey status` never tries.
        Unavailable::Failed(err) => format!(
            "{denied}the desktop notification server failed ({err}). Try again; if every \
                 request fails like this, restart the notification server or use another one, \
                 such as GNOME Shell, KDE Plasma or dunst. `pqkey status` does not test this, as \
                 it shows no notification"
        ),
    }
}

pub(crate) fn connect_error_message(error: &ConnectError) -> String {
    match error {
        ConnectError::NoSession(err) => format!("no session bus: {err}"),
        ConnectError::NoServer(err) => format!("no notification server: {err}"),
        ConnectError::Failed(err) => err.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way the daemon can fail to ask, with two things its message must
    /// say: the cause, with the error, and its own remedy.
    fn denials() -> [(Unavailable, [&'static str; 2]); 6] {
        // A new way to fail stops this from compiling until it is listed.
        let _: fn(&Unavailable) = |unavailable| match unavailable {
            Unavailable::Connect(
                ConnectError::NoSession(_) | ConnectError::NoServer(_) | ConnectError::Failed(_),
            )
            | Unavailable::NoActions
            | Unavailable::NoBody
            | Unavailable::Failed(_) => {}
        };
        [
            (
                Unavailable::Connect(ConnectError::NoSession("no address".into())),
                [
                    "the daemon cannot connect to a D-Bus session bus (no address)",
                    "In a terminal of your desktop session, run `systemctl --user \
                     import-environment DBUS_SESSION_BUS_ADDRESS`, then `pqkey stop && pqkey \
                     start`. ",
                ],
            ),
            (
                Unavailable::Connect(ConnectError::NoServer("ServiceUnknown".into())),
                [
                    "no desktop notification server answers on the daemon's session bus \
                     (ServiceUnknown)",
                    "Log in to a desktop that provides one, or run a notification daemon that \
                     supports action buttons",
                ],
            ),
            (
                Unavailable::Connect(ConnectError::Failed("timed out".into())),
                [
                    "the notification server could not be reached (timed out)",
                    "Try again, as each request connects anew",
                ],
            ),
            (
                Unavailable::NoActions,
                [
                    "cannot show Approve and Deny buttons",
                    "Use a notification server that supports actions",
                ],
            ),
            (
                Unavailable::NoBody,
                [
                    "shows no notification text",
                    "Use a notification server that shows bodies",
                ],
            ),
            (
                Unavailable::Failed("Notify failed: NoReply".into()),
                [
                    "the desktop notification server failed (Notify failed: NoReply)",
                    "Try again; if every request fails like this, restart the notification \
                     server or use another one",
                ],
            ),
        ]
    }

    /// `--presence auto-approve` approves everything without asking, so that
    /// anything running as the user can use the passkeys unnoticed. A denial
    /// says how to make the prompt work, never how to do without it.
    #[test]
    fn no_denial_recommends_auto_approve() {
        for (unavailable, _) in denials() {
            let message = failure_message(&unavailable, "Create a passkey");
            assert!(
                message.starts_with("denied without asking (Create a passkey): "),
                "{message}"
            );
            let lower = message.to_lowercase();
            for advice in ["auto-approve", "auto approve", "--presence"] {
                assert!(!lower.contains(advice), "{advice:?} in: {message}");
            }
        }
    }

    /// Each denial keeps its cause and remedy, and claims no more for `pqkey
    /// status` than it does: while the daemon runs, status checks the
    /// daemon's session bus, or its own for a daemon started by hand on a TCP
    /// bus, and it never shows a notification.
    #[test]
    fn denials_keep_their_remedy_and_say_what_pqkey_status_checks() {
        let status = ". `pqkey status` checks this on the daemon's session bus while the daemon \
                      runs, and names the fix while the problem lasts. For a daemon started by \
                      hand on a TCP bus, it checks the session bus of the terminal it runs in \
                      instead";
        for (unavailable, said) in denials() {
            let message = failure_message(&unavailable, "Sign in with a passkey");
            for words in said {
                assert!(message.contains(words), "{words:?} not in: {message}");
            }
            // What status did before it checked the daemon's own bus.
            assert!(!message.contains("of the shell it runs in"), "{message}");
            assert!(
                !message.contains("the daemon is not on that bus"),
                "{message}"
            );
            if let Unavailable::Failed(_) = unavailable {
                assert!(
                    message.ends_with(
                        "`pqkey status` does not test this, as it shows no notification"
                    ),
                    "{message}"
                );
                assert!(!message.contains("repeats this check"), "{message}");
                assert!(!message.contains("checks this"), "{message}");
            } else {
                assert!(message.ends_with(status), "{message}");
            }
        }
    }
}
