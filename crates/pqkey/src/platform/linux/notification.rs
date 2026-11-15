//! Linux notification details and diagnostics.

use super::checks::{SERVERS, notification_problem};
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
/// without asking: why, and how to make the prompt work, as `pqkey status`
/// says it while the problem lasts. Never how to do without it: `--presence
/// auto-approve` lets anything running as the user use the passkeys unnoticed.
pub(crate) fn failure_message(unavailable: &Unavailable, summary: &str) -> String {
    // The summary, unlike the prompt, holds no text from the request.
    let denied = format!("denied without asking ({summary})");
    // This process is the key: its bus is the one status checks and names
    // (cli/daemon_info.rs).
    let bus =
        super::dbus::session_bus_address(std::env::var_os("DBUS_SESSION_BUS_ADDRESS").as_deref());
    match unavailable {
        Unavailable::CannotAsk(server) => match notification_problem(server, Some(&bus)) {
            Some(problem) => format!(
                "{denied}: {}. Fix: {}. Then run `pqkey status` to check",
                problem.what, problem.fix
            ),
            // The key does not deny for a server that can ask.
            None => denied,
        },
        // Showing the prompt or waiting for its answer failed, which
        // `pqkey status` never tries.
        Unavailable::Failed(err) => format!(
            "{denied}: the notification server failed ({err}). Fix: try again; if every request \
             fails like this, restart the notification server or use another one, {SERVERS}. \
             `pqkey status` does not test this, as it shows no notification"
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
    use crate::presence::notification::ServerInfo;
    use crate::test_support::assert_names;

    /// Every way the daemon can fail to ask, with two things its message must
    /// name, in order: the cause, by its error, and the fix.
    fn denials() -> [(Unavailable, [&'static str; 2]); 6] {
        // A new way to fail stops this from compiling until it is listed.
        let _: fn(&Unavailable) = |unavailable| match unavailable {
            Unavailable::CannotAsk(
                Err(
                    ConnectError::NoSession(_)
                    | ConnectError::NoServer(_)
                    | ConnectError::Failed(_),
                )
                | Ok(_),
            )
            | Unavailable::Failed(_) => {}
        };
        let connect = |err| Unavailable::CannotAsk(Err(err));
        let server = |actions, body| {
            Unavailable::CannotAsk(Ok(ServerInfo {
                supports_actions: actions,
                supports_body: body,
                name: Some("example".into()),
                ..ServerInfo::default()
            }))
        };
        [
            (
                connect(ConnectError::NoSession("no address".into())),
                ["(no address)", "`systemctl --user import-environment"],
            ),
            (
                connect(ConnectError::NoServer("ServiceUnknown".into())),
                ["ServiceUnknown", SERVERS],
            ),
            (
                connect(ConnectError::Failed("timed out".into())),
                ["(timed out)", "try again"],
            ),
            (server(false, true), ["Approve and Deny buttons", SERVERS]),
            (server(true, false), ["notification text", SERVERS]),
            (
                Unavailable::Failed("Notify failed: NoReply".into()),
                ["(Notify failed: NoReply)", SERVERS],
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

    /// Each denial gives the cause and fix that `pqkey status` gives on the
    /// key's bus, and sends the user to it, unless status cannot see the
    /// problem: status never shows a notification.
    #[test]
    fn denials_give_the_cause_and_fix_of_pqkey_status_and_send_the_user_to_it() {
        let bus = super::super::dbus::session_bus_address(
            std::env::var_os("DBUS_SESSION_BUS_ADDRESS").as_deref(),
        );
        for (unavailable, [cause, fix]) in denials() {
            let message = failure_message(&unavailable, "Sign in with a passkey");
            assert_names(&message, &[cause, "Fix: ", fix]);
            let end = match &unavailable {
                Unavailable::CannotAsk(server) => {
                    let status = notification_problem(server, Some(&bus)).unwrap();
                    format!(
                        ": {}. Fix: {}. Then run `pqkey status` to check",
                        status.what, status.fix
                    )
                }
                Unavailable::Failed(_) => {
                    ". `pqkey status` does not test this, as it shows no notification".to_owned()
                }
            };
            assert!(message.ends_with(&end), "{message}");
        }
    }
}
