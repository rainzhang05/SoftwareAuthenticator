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

pub(crate) fn failure_message(unavailable: &Unavailable, summary: &str) -> String {
    const OPT_OUT: &str = "or, for tests only, start the daemon with --presence auto-approve, which approves everything without asking";
    // The summary, unlike the prompt, holds no text from the request.
    let denied = format!("denied without asking ({}): ", summary);
    match unavailable {
        Unavailable::Connect(ConnectError::NoSession(err)) => format!(
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

pub(crate) fn connect_error_message(error: &ConnectError) -> String {
    match error {
        ConnectError::NoSession(err) => format!("no session bus: {err}"),
        ConnectError::NoServer(err) => format!("no notification server: {err}"),
        ConnectError::Failed(err) => err.clone(),
    }
}
