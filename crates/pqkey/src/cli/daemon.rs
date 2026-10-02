//! Running the key, and plugging it in and out: `run`, `start`, `stop`.
//!
//! The key is a daemon, `pqkey run`, which holds an exclusive lock on its
//! state directory for as long as it runs.  When the systemd user service is
//! installed for the default state directory, `start` and `stop` go through
//! it, so systemd keeps track of the daemon; otherwise `start` runs one in
//! the background itself.

use std::{
    env,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::{self, Group, Pid},
};

use super::DaemonArgs;
use super::output::{errln, outln};
use crate::{
    permissions, service,
    shutdown::ShutdownSignal,
    state::{self, default_state_dir},
    state_lock::{self, DaemonState, StateLock},
};

/// The systemd user unit `pqkey setup` installs.
pub const UNIT: &str = "pqkey.service";

/// How long `start` waits for the key to be ready, and `stop` for it to go.
const WAIT: Duration = Duration::from_secs(10);

/// The log of a daemon `start` runs in the background.
fn log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("authenticator.log")
}

/// A key runs on the state directory already, so another cannot start; pqkey
/// exits with [`EXIT_ALREADY_RUNNING`](super::EXIT_ALREADY_RUNNING).
#[derive(Debug)]
pub struct AlreadyRunning(String);

impl fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for AlreadyRunning {}

/// The error for a key that runs already.
fn already_running(state_dir: &Path) -> io::Error {
    let message = match state_lock::read_pid(state_dir) {
        Ok(Some(pid)) => format!("the key is already running (pid {pid})"),
        _ => format!("{} is in use by another pqkey process", state_dir.display()),
    };
    io::Error::new(io::ErrorKind::ResourceBusy, AlreadyRunning(message))
}

/// The error for a key that is still starting or already stopping.
fn starting_or_stopping() -> io::Error {
    io::Error::new(
        io::ErrorKind::ResourceBusy,
        "the key is starting or stopping; try again in a moment",
    )
}

/// `pqkey run`: the key itself, in the foreground until it is told to stop,
/// holding the state directory's lock throughout.  The pid file is published
/// once the virtual device exists and removed on the way out.
pub fn run(state_dir: PathBuf, args: &DaemonArgs) -> io::Result<()> {
    state::ensure_state_dir(&state_dir)?;
    let config = args
        .to_runner_config(state_dir.clone())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let lock = StateLock::try_acquire(&state_dir)?.ok_or_else(|| already_running(&state_dir))?;
    // Nothing else can be running, so a pid file is left over from a daemon
    // that did not exit cleanly.
    state_lock::remove_pid_file(&state_dir, &lock)?;
    warn_uhid_access();
    // Without RUST_LOG, warnings too: that --presence auto-approve asks
    // nobody, for example, is only ever logged.
    let _ = env_logger::try_init_from_env(env_logger::Env::default().default_filter_or("warn"));
    let shutdown = ShutdownSignal::new();
    shutdown.install_signal_handlers()?;
    let result = service::run(config, shutdown, || {
        state_lock::write_pid_file(&state_dir, &lock)
    });
    if let Err(err) = state_lock::remove_pid_file(&state_dir, &lock) {
        log::warn!("could not remove the pid file: {err}");
    }
    result
}

/// How the key runs, if it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Running {
    /// As the systemd user service.
    Service(Pid),
    /// As a daemon of its own.
    Daemon(Pid),
}

impl Running {
    pub fn pid(self) -> Pid {
        match self {
            Running::Service(pid) | Running::Daemon(pid) => pid,
        }
    }
}

/// Whether and how the key on `state_dir` runs.  `Busy` while it is still
/// starting or stopping.
pub fn running(state_dir: &Path) -> io::Result<Option<Running>> {
    Ok(match state_lock::daemon_state(state_dir)? {
        DaemonState::Running(pid) if uses_service(state_dir) && unit_main_pid() == Some(pid) => {
            Some(Running::Service(pid))
        }
        DaemonState::Running(pid) => Some(Running::Daemon(pid)),
        DaemonState::Busy => return Err(starting_or_stopping()),
        DaemonState::Stopped => None,
    })
}

/// `pqkey start`: plug the key in.
pub fn start(state_dir: &Path, args: &DaemonArgs) -> io::Result<()> {
    if state_lock::daemon_state(state_dir)? != DaemonState::Stopped {
        return Err(already_running(state_dir));
    }
    let how = plug_in(state_dir, args)?;
    match how {
        Running::Service(pid) => outln!("Key started (pid {pid}, systemd user service {UNIT})"),
        Running::Daemon(pid) => outln!(
            "Key started (pid {pid}); logging to {}",
            log_path(state_dir).display()
        ),
    }
}

/// Start the key, through the user service when it is installed for this
/// state directory and the default options, and wait until it serves.
pub fn plug_in(state_dir: &Path, args: &DaemonArgs) -> io::Result<Running> {
    state::ensure_state_dir(state_dir)?;
    if args.are_defaults() && uses_service(state_dir) {
        systemctl(&["start", UNIT])?;
        let pid = wait_for_pid(state_dir, |_| true)?;
        return Ok(Running::Service(pid));
    }
    spawn_daemon(state_dir, args).map(Running::Daemon)
}

/// Restart the key with the options it runs with, or start it if it does
/// not run: what pulling a hardware key out and plugging it back in does.
pub fn replug(state_dir: &Path) -> io::Result<Running> {
    match running(state_dir)? {
        None => plug_in(state_dir, &DaemonArgs::default()),
        Some(Running::Service(old)) => {
            systemctl(&["restart", UNIT])?;
            wait_for_pid(state_dir, |pid| pid != old).map(Running::Service)
        }
        Some(Running::Daemon(pid)) => {
            let args = super::daemon_args_of(pid)?;
            unplug(state_dir)?;
            spawn_daemon(state_dir, &args).map(Running::Daemon)
        }
    }
}

/// `pqkey stop`: pull the key out.
pub fn stop(state_dir: &Path) -> io::Result<()> {
    match unplug(state_dir)? {
        Some(_) => outln!("Key stopped"),
        None => outln!("The key is not running"),
    }
}

/// Stop the key if it runs, through the user service if it runs as that,
/// and wait until it has gone.  Returns how it ran.
pub fn unplug(state_dir: &Path) -> io::Result<Option<Running>> {
    let Some(running) = running(state_dir)? else {
        return Ok(None);
    };
    match running {
        Running::Service(_) => drop(systemctl(&["stop", UNIT])?),
        Running::Daemon(pid) => match signal::kill(pid, Signal::SIGTERM) {
            // ESRCH: it exited in the meantime.
            Ok(()) | Err(Errno::ESRCH) => {}
            Err(err) => {
                return Err(io::Error::other(format!(
                    "could not signal the key (pid {pid}): {err}"
                )));
            }
        },
    }
    // The daemon holds the lock until its very end, and unlike a pid the lock
    // cannot end up belonging to some unrelated process.
    let deadline = Instant::now() + WAIT;
    while state_lock::is_locked(state_dir)? {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the key (pid {}) did not stop within {}s",
                    running.pid(),
                    WAIT.as_secs()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(Some(running))
}

/// Wait until a daemon whose pid `accept` takes has published its pid file.
fn wait_for_pid(state_dir: &Path, accept: impl Fn(Pid) -> bool) -> io::Result<Pid> {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(pid) = state_lock::read_pid(state_dir)?
            && accept(pid)
            && state_lock::is_locked(state_dir)?
        {
            return Ok(pid);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the key has not started within {}s; see `journalctl --user -u {UNIT}` or {}",
                    WAIT.as_secs(),
                    log_path(state_dir).display()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Run `pqkey run` with `args` in the background, in a new session and with
/// its output going to the log file, then wait until it has written its pid
/// file.
fn spawn_daemon(state_dir: &Path, args: &DaemonArgs) -> io::Result<Pid> {
    let log_path = log_path(state_dir);
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    let log_offset = log.metadata()?.len();

    let mut command = ProcessCommand::new(env::current_exe()?);
    command
        .arg("--state-dir")
        .arg(state_dir)
        .arg("run")
        .args(args.to_args())
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // A new session detaches the daemon from this terminal, so closing the
    // terminal or pressing Ctrl-C in it does not reach the daemon.
    // SAFETY: setsid is async-signal-safe and nothing here allocates.
    unsafe {
        command.pre_exec(|| unistd::setsid().map(drop).map_err(io::Error::from));
    }
    let mut child = command.spawn()?;
    let daemon_pid = Pid::from_raw(child.id() as i32);

    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait()? {
            let log = read_log_from(&log_path, log_offset);
            if !log.trim().is_empty() {
                errln!("{}", log.trim_end());
            }
            return Err(io::Error::other(format!(
                "the key failed to start ({status}); see {}",
                log_path.display()
            )));
        }
        if state_lock::read_pid(state_dir)? == Some(daemon_pid) {
            return Ok(daemon_pid);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the key (pid {daemon_pid}) has not finished starting after {}s; see {}",
                    WAIT.as_secs(),
                    log_path.display()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// What the daemon logged after `offset`, capped to the last few kilobytes.
fn read_log_from(path: &Path, offset: u64) -> String {
    const MAX_BYTES: u64 = 8 * 1024;
    let mut bytes = Vec::new();
    if let Ok(mut file) = File::open(path) {
        let end = file.metadata().map(|meta| meta.len()).unwrap_or(offset);
        let start = offset.max(end.saturating_sub(MAX_BYTES));
        if file.seek(SeekFrom::Start(start)).is_ok() {
            let _ = file.take(MAX_BYTES).read_to_end(&mut bytes);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Run `systemctl --user` with `args`, failing with its message.
pub fn systemctl(args: &[&str]) -> io::Result<String> {
    let output = ProcessCommand::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    } else {
        Err(io::Error::other(format!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// A property of the user unit, if systemd answers.
fn unit_property(property: &str) -> Option<String> {
    systemctl(&["show", "--property", property, "--value", UNIT]).ok()
}

/// Whether the key on `state_dir` is the one the user service runs: the
/// unit is installed, and `state_dir` is the default state directory it uses.
pub fn uses_service(state_dir: &Path) -> bool {
    state_dir == default_state_dir() && unit_property("LoadState").as_deref() == Some("loaded")
}

/// The pid of the user service's daemon, if it runs.
fn unit_main_pid() -> Option<Pid> {
    unit_property("MainPID")
        .and_then(|pid| pid.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .map(Pid::from_raw)
}

fn warn_uhid_access() {
    if unistd::geteuid().is_root() {
        return;
    }
    match permissions::check_uhid_access() {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => warn_group_membership(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            errln!("warning: /dev/uhid is not available; run `pqkey setup`");
        }
        Err(_) => {}
    }
}

fn warn_group_membership() {
    const GROUP_NAME: &str = "plugdev";
    let plugdev_gid = Group::from_name(GROUP_NAME).ok().flatten().map(|g| g.gid);
    // nix does not expose getgroups on Apple platforms. The daemon only runs on
    // Linux (it needs /dev/uhid), but gating this keeps the crate compiling and
    // testable on macOS development machines.
    #[cfg(target_os = "linux")]
    let groups = unistd::getgroups().unwrap_or_default();
    #[cfg(not(target_os = "linux"))]
    let groups: Vec<unistd::Gid> = Vec::new();
    let in_group = plugdev_gid.is_some_and(|gid| groups.contains(&gid) || unistd::getegid() == gid);
    if in_group {
        errln!(
            "warning: cannot open /dev/uhid although you are in '{GROUP_NAME}'; run `pqkey setup`"
        );
    } else {
        errln!(
            "warning: cannot open /dev/uhid: you are not in '{GROUP_NAME}' yet, or have not \
             logged in again since you joined it; run `pqkey setup`"
        );
    }
}
