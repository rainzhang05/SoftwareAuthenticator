use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
use nix::unistd::{self, Gid, Group};
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::Pid,
};

use crate::{
    attestation, permissions,
    pin_input::PinReader,
    presence::PresenceMode,
    service,
    shutdown::ShutdownSignal,
    state::{self, default_state_dir},
    state_lock::{self, DaemonState, StateLock},
    HidDeviceDescriptor,
};

/// The AAGUID pqkey reports unless `--aaguid` says otherwise: a random
/// (version 4) UUID of its own.
pub const DEFAULT_AAGUID: &str = "5931e805-a166-4eb7-845a-7f6aa93d9cd8";

/// The HID product name, and the product a newly provisioned attestation
/// certificate names, unless `--name` and `--product` say otherwise.
pub const DEFAULT_NAME: &str = "pqkey FIDO2 Software Authenticator (ML-DSA)";

#[derive(Parser, Debug)]
#[clap(
    name = "pqkey",
    about = "pqkey: a FIDO2 security key with post-quantum ML-DSA, as a virtual USB HID device",
    version,
    author
)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the authenticator service and expose the virtual security key
    #[clap(alias = "start")]
    Attach(StartCommand),
    /// Stop the authenticator service and remove the virtual security key
    #[clap(alias = "stop")]
    Detach(StateArgs),
    /// Show service status
    Status(StateArgs),
    /// Wipe all credentials and PIN state (requires the daemon to be detached)
    Reset(ResetArgs),
    /// Manage the authenticator PIN
    ///
    /// PINs are never taken from command-line arguments, which other local
    /// users can read and shells save to history. On a terminal the PIN is
    /// prompted for with echo off; otherwise it is read from standard input,
    /// one PIN per line.
    Pin(PinCommand),
}

#[derive(Args, Debug, Clone)]
pub struct ResetArgs {
    #[clap(flatten)]
    pub state: StateArgs,
    /// Skip the interactive confirmation prompt
    #[clap(long)]
    pub yes: bool,
}

#[derive(Args, Debug, Clone)]
pub struct PinCommand {
    #[clap(subcommand)]
    pub action: PinAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PinAction {
    /// Set a new PIN on a PIN-less authenticator
    ///
    /// Reads the new PIN from the terminal (twice) or, when standard input is
    /// not a terminal, as a single line from standard input.
    Set {
        #[clap(flatten)]
        state: StateArgs,
    },
    /// Change the existing PIN
    ///
    /// Reads the current PIN and then the new PIN (twice) from the terminal
    /// or, when standard input is not a terminal, as two lines from standard
    /// input: the current PIN first, then the new one.
    Change {
        #[clap(flatten)]
        state: StateArgs,
    },
    /// Remove the PIN entirely
    ///
    /// Reads the current PIN from the terminal or, when standard input is not
    /// a terminal, as a single line from standard input.
    Remove {
        #[clap(flatten)]
        state: StateArgs,
    },
    /// Show whether a PIN is set, retries remaining, and block status
    Status {
        #[clap(flatten)]
        state: StateArgs,
    },
}

#[derive(Args, Debug, Clone)]
pub struct StartCommand {
    #[clap(flatten)]
    device: DeviceArgs,
    #[clap(flatten)]
    state: StateArgs,
    /// Run in the foreground (useful for systemd integration)
    #[clap(long)]
    pub foreground: bool,
    #[clap(flatten)]
    presence: PresenceArgs,
}

#[derive(Args, Debug, Clone)]
pub struct PresenceArgs {
    /// How the user approves registrations, sign-ins and resets
    #[clap(long, value_enum, default_value_t = PresenceArg::Notify)]
    pub presence: PresenceArg,
    /// Seconds a presence request waits for the user (default 30). For test
    /// rigs; CTAP 2.3 section 5 asks for at least 10.
    #[clap(long, hide = true, value_parser = clap::value_parser!(u64).range(1..=600))]
    pub presence_timeout: Option<u64>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum PresenceArg {
    /// Ask with a desktop notification that has Approve and Deny buttons.
    /// Without a session bus and a notification server that can show
    /// buttons, every request is denied
    Notify,
    /// Approve every request without asking. Anything running as you can then
    /// use your passkeys unnoticed; for tests and CI only
    AutoApprove,
    /// Never answer, so every request waits until it is cancelled or times
    /// out (for tests)
    #[value(hide = true)]
    Unanswered,
}

impl PresenceArg {
    fn into_mode(self) -> PresenceMode {
        match self {
            PresenceArg::Notify => PresenceMode::Notify,
            PresenceArg::AutoApprove => PresenceMode::AutoApprove,
            PresenceArg::Unanswered => PresenceMode::Unanswered,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct StateArgs {
    /// Directory where the credential store, lock, pid and log files are kept
    #[clap(long, value_parser, default_value_os_t = default_state_dir())]
    pub state_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct DeviceArgs {
    /// HID product name
    #[clap(long, default_value = DEFAULT_NAME)]
    pub name: String,
    /// The attestation statement registrations get
    #[clap(long, value_enum, default_value_t = AttestationArg::SelfAttestation)]
    pub attestation: AttestationArg,
    /// Manufacturer named in a newly provisioned attestation certificate.
    /// Required with --attestation certificate
    #[clap(long, required_if_eq("attestation", "certificate"))]
    pub manufacturer: Option<String>,
    /// Product named in a newly provisioned attestation certificate
    #[clap(long, default_value = DEFAULT_NAME)]
    pub product: String,
    /// Country (ISO 3166-1 alpha-2 code) where the manufacturer is
    /// incorporated, named in a newly provisioned attestation certificate.
    /// Required with --attestation certificate
    #[clap(
        long,
        value_parser = attestation::parse_country,
        required_if_eq("attestation", "certificate")
    )]
    pub country: Option<String>,
    /// Ignored; accepted so that existing command lines keep working. The
    /// attestation certificate's serial number is random.
    #[clap(long, hide = true)]
    pub serial: Option<String>,
    /// USB vendor ID for the virtual HID device (default: pid.codes' open
    /// source vendor ID)
    #[clap(long, value_parser = maybe_hex::<u32>, default_value = "0x1209")]
    pub vendor_id: u32,
    /// USB product ID for the virtual HID device (default: a pid.codes test
    /// product ID, which is not unique to pqkey)
    #[clap(long, value_parser = maybe_hex::<u32>, default_value = "0x0001")]
    pub product_id: u32,
    /// Version reported by the HID descriptor
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0001)]
    pub version: u32,
    /// Ignored; accepted so that existing command lines keep working
    #[clap(short, long, hide = true, value_parser = maybe_hex::<u16>)]
    pub vid: Option<u16>,
    /// Ignored; accepted so that existing command lines keep working
    #[clap(short, long, hide = true, value_parser = maybe_hex::<u16>)]
    pub pid: Option<u16>,
    /// Authenticator AAGUID, reported in authenticatorGetInfo and in every
    /// registration
    #[clap(long, default_value = DEFAULT_AAGUID)]
    pub aaguid: String,
    /// Accept authenticatorReset at any time instead of only within 10 seconds
    /// of start-up. Does not conform to CTAP 2.3 section 6.6; for test rigs that
    /// reset a long-running authenticator. User presence is still required.
    /// With --presence notify a reset is accepted at any time anyway.
    #[clap(long, hide = true)]
    pub allow_late_reset: bool,
    /// Backend transport to use
    #[clap(long, value_enum, default_value_t = BackendArg::Uhid)]
    pub backend: BackendArg,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum AttestationArg {
    /// Self attestation: each registration is signed with the new
    /// credential's own key. Relying parties learn nothing about the
    /// authenticator from it and cannot link credentials to each other
    #[value(name = "self")]
    SelfAttestation,
    /// Basic attestation with a certificate generated for this installation
    /// (needs --manufacturer and --country). The same certificate comes with
    /// every registration, so relying parties that compare certificates can
    /// tell that credentials on different sites belong to the same
    /// authenticator, and so to the same person (WebAuthn Level 3 §14.4.1)
    Certificate,
    /// No attestation statement (format "none")
    None,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum BackendArg {
    Uhid,
}

impl BackendArg {
    fn into_backend(self) -> service::Backend {
        match self {
            BackendArg::Uhid => service::Backend::Uhid,
        }
    }
}

impl StateArgs {
    fn log_path(&self) -> PathBuf {
        self.state_dir.join("authenticator.log")
    }

    /// Take exclusive use of the state directory for a command that reads or
    /// writes the stored state, failing if the daemon or another command has
    /// it.
    fn lock(&self) -> io::Result<StateLock> {
        state::ensure_state_dir(&self.state_dir)?;
        let lock = StateLock::try_acquire(&self.state_dir)?.ok_or_else(|| self.in_use_error())?;
        // Nothing else can be running, so a pid file is left over from a
        // daemon that did not exit cleanly.
        state_lock::remove_pid_file(&self.state_dir, &lock)?;
        Ok(lock)
    }

    fn in_use_error(&self) -> io::Error {
        let message = match state_lock::read_pid(&self.state_dir) {
            Ok(Some(pid)) => {
                format!("the authenticator daemon is running (pid {pid}); run 'pqkey detach' first")
            }
            _ => format!(
                "{} is in use by another pqkey process",
                self.state_dir.display()
            ),
        };
        io::Error::new(io::ErrorKind::ResourceBusy, message)
    }
}

impl StartCommand {
    fn to_runner_config(&self) -> Result<service::RunnerConfig, String> {
        let aaguid = service::parse_aaguid(&self.device.aaguid)?;
        let descriptor = service::descriptor(
            self.device.name.clone(),
            self.device.vendor_id,
            self.device.product_id,
            self.device.version,
        );
        let attestation = match self.device.attestation {
            AttestationArg::SelfAttestation => service::AttestationConfig::SelfAttestation,
            AttestationArg::None => service::AttestationConfig::None,
            AttestationArg::Certificate => {
                let required = |value: &Option<String>, flag: &str| {
                    value
                        .clone()
                        .ok_or_else(|| format!("--attestation certificate requires {flag}"))
                };
                service::AttestationConfig::Certificate(service::IdentityStrings {
                    manufacturer: required(&self.device.manufacturer, "--manufacturer")?,
                    product: self.device.product.clone(),
                    country: required(&self.device.country, "--country")?,
                })
            }
        };
        Ok(service::RunnerConfig {
            descriptor,
            state_dir: self.state.state_dir.clone(),
            aaguid,
            attestation,
            presence: self.presence.presence.into_mode(),
            presence_timeout: self.presence.presence_timeout.map(Duration::from_secs),
            allow_late_reset: self.device.allow_late_reset,
            backend: self.device.backend.into_backend(),
        })
    }
}

/// Run the daemon in this process until it is told to stop, holding the
/// state directory lock throughout. The pid file is published once the
/// virtual device exists and removed again on the way out.
fn run_foreground(
    lock: StateLock,
    state: &StateArgs,
    config: service::RunnerConfig,
) -> io::Result<()> {
    let _ = env_logger::try_init();
    let shutdown = ShutdownSignal::new();
    shutdown.install_signal_handlers()?;
    let result = service::run(config, shutdown, || {
        state_lock::write_pid_file(&state.state_dir, &lock)
    });
    if let Err(err) = state_lock::remove_pid_file(&state.state_dir, &lock) {
        log::warn!("could not remove the pid file: {err}");
    }
    result
}

/// How long `attach` waits for the background daemon to create the device.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Start the daemon in the background: run this same binary again with the
/// same arguments plus `--foreground`, in a new session and with its output
/// going to the log file, then wait until it has written its pid file.
fn spawn_daemon(state: &StateArgs) -> io::Result<()> {
    let log_path = state.log_path();
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    let log_offset = log.metadata()?.len();

    let mut command = ProcessCommand::new(env::current_exe()?);
    command
        .args(env::args_os().skip(1))
        .arg("--foreground")
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

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            eprint!("{}", read_log_from(&log_path, log_offset));
            return Err(io::Error::other(format!(
                "authenticator failed to start ({status}); see {}",
                log_path.display()
            )));
        }
        if state_lock::read_pid(&state.state_dir)? == Some(daemon_pid) {
            println!(
                "Authenticator attached (pid {daemon_pid}); logging to {}",
                log_path.display()
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "authenticator (pid {daemon_pid}) has not finished starting after {}s; see {}",
                    STARTUP_TIMEOUT.as_secs(),
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

fn warn_device_permissions(descriptor: &HidDeviceDescriptor) {
    let euid = unistd::geteuid();
    if euid.is_root() {
        return;
    }

    match permissions::check_uhid_access() {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            warn_group_membership();
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            eprintln!(
                "warning: /dev/uhid is not available. Load the uhid kernel module with 'sudo modprobe uhid'."
            );
        }
        Err(_) => {}
    }

    if let Ok(nodes) = permissions::hidraw_nodes_for_descriptor(descriptor) {
        for node in nodes {
            let mode = node.mode & 0o777;
            if mode & 0o007 != 0 {
                eprintln!(
                    "warning: {} is world-accessible (mode {:o}). Install contrib/udev/70-pqkey.rules or tighten permissions.",
                    node.path.display(),
                    mode
                );
            }
        }
    }
}

fn warn_group_membership() {
    const GROUP_NAME: &str = "plugdev";
    let plugdev_gid = group_by_name(GROUP_NAME);
    // nix does not expose getgroups on Apple platforms. The daemon only runs on
    // Linux (it needs /dev/uhid), but gating this keeps the crate compiling and
    // testable on macOS development machines.
    #[cfg(target_os = "linux")]
    let groups = unistd::getgroups().unwrap_or_default();
    #[cfg(not(target_os = "linux"))]
    let groups: Vec<Gid> = Vec::new();
    let egid = unistd::getegid();

    if let Some(gid) = plugdev_gid {
        if !groups.contains(&gid) && egid != gid {
            eprintln!(
                "warning: insufficient permissions to access /dev/uhid. Add your user to the '{}' group or adjust contrib/udev/70-pqkey.rules.",
                GROUP_NAME
            );
        } else {
            eprintln!(
                "warning: unable to access /dev/uhid even though '{}' group is present. Verify the udev rule contrib/udev/70-pqkey.rules is installed.",
                GROUP_NAME
            );
        }
    } else {
        eprintln!(
            "warning: insufficient permissions to access /dev/uhid and '{}' group was not found. Install contrib/udev/70-pqkey.rules and adjust the GROUP value for your system.",
            GROUP_NAME
        );
    }
}

fn group_by_name(name: &str) -> Option<Gid> {
    Group::from_name(name).ok().flatten().map(|g| g.gid)
}

fn start(cmd: StartCommand) -> io::Result<()> {
    state::ensure_state_dir(&cmd.state.state_dir)?;
    let config = cmd
        .to_runner_config()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    if cmd.foreground {
        // Taken before anything touches the stored state and held until the
        // daemon exits; this is what makes a second daemon refuse to start.
        let lock = cmd.state.lock()?;
        warn_device_permissions(&config.descriptor);
        run_foreground(lock, &cmd.state, config)
    } else {
        // Only a quick check for a friendlier message: the daemon started
        // below takes the lock itself and exits if it cannot.
        if state_lock::daemon_state(&cmd.state.state_dir)? != DaemonState::Stopped {
            return Err(cmd.state.in_use_error());
        }
        warn_device_permissions(&config.descriptor);
        spawn_daemon(&cmd.state)
    }
}

/// How long `detach` waits for the daemon to exit after asking it to.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

fn stop(state: StateArgs) -> io::Result<()> {
    let pid = match state_lock::daemon_state(&state.state_dir)? {
        DaemonState::Stopped => {
            println!("Authenticator is not running");
            return Ok(());
        }
        DaemonState::Busy => return Err(state.in_use_error()),
        DaemonState::Running(pid) => pid,
    };
    match signal::kill(pid, Signal::SIGTERM) {
        // ESRCH: it exited in the meantime.
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(err) => {
            return Err(io::Error::other(format!(
                "could not signal the authenticator (pid {pid}): {err}"
            )))
        }
    }
    // The daemon holds the lock until its very end, and unlike a pid the lock
    // cannot end up belonging to some unrelated process.
    let deadline = Instant::now() + STOP_TIMEOUT;
    while state_lock::is_locked(&state.state_dir)? {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the authenticator (pid {pid}) did not stop within {}s",
                    STOP_TIMEOUT.as_secs()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    println!("Authenticator stopped");
    Ok(())
}

fn status(state: StateArgs) -> io::Result<()> {
    match state_lock::daemon_state(&state.state_dir)? {
        DaemonState::Running(pid) => println!("Authenticator running (pid {pid})"),
        DaemonState::Busy => println!(
            "Authenticator state is in use: the daemon is still starting, or a pin or reset command is running"
        ),
        DaemonState::Stopped => println!("Authenticator is not running"),
    }
    Ok(())
}

impl Command {
    /// The state directory the command works on.
    fn state_dir(&self) -> &Path {
        match self {
            Command::Attach(cmd) => &cmd.state.state_dir,
            Command::Detach(state) | Command::Status(state) => &state.state_dir,
            Command::Reset(args) => &args.state.state_dir,
            Command::Pin(cmd) => match &cmd.action {
                PinAction::Set { state }
                | PinAction::Change { state }
                | PinAction::Remove { state }
                | PinAction::Status { state } => &state.state_dir,
            },
        }
    }
}

pub fn run_cli() -> io::Result<()> {
    let cli = Cli::parse();
    if let Some(notice) = state::unused_legacy_state_dir_notice(cli.command.state_dir()) {
        eprintln!("{notice}");
    }
    match cli.command {
        Command::Attach(cmd) => start(cmd),
        Command::Detach(state) => stop(state),
        Command::Status(state) => status(state),
        Command::Reset(args) => reset(args),
        Command::Pin(cmd) => pin(cmd),
    }
}

fn confirm(prompt: &str) -> io::Result<bool> {
    use std::io::{BufRead, BufReader};
    eprint!("{prompt} [y/N] ");
    use std::io::Write;
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    BufReader::new(stdin.lock()).read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

fn reset(args: ResetArgs) -> io::Result<()> {
    let _lock = args.state.lock()?;
    if !args.yes
        && !confirm(&format!(
            "This will wipe ALL credentials and PIN state under {}. Continue?",
            args.state.state_dir.display()
        ))?
    {
        eprintln!("Reset cancelled.");
        return Ok(());
    }
    let legacy = state::reset_state(&args.state.state_dir)?;
    if !legacy.is_empty() {
        println!(
            "Removed state from an earlier version: {}.",
            legacy.join(", ")
        );
    }
    println!("Authenticator state has been reset.");
    Ok(())
}

fn pin(cmd: PinCommand) -> io::Result<()> {
    match cmd.action {
        PinAction::Status { state } => pin_status(state),
        PinAction::Set { state } => {
            let _lock = state.lock()?;
            let pin = PinReader::from_stdin().new_pin()?;
            state::pin_set(&state.state_dir, &pin)?;
            println!("PIN set.");
            Ok(())
        }
        PinAction::Change { state } => {
            let _lock = state.lock()?;
            let reader = PinReader::from_stdin();
            let current = reader.current_pin()?;
            let new = reader.new_pin()?;
            state::pin_change(&state.state_dir, &current, &new)?;
            println!("PIN changed.");
            Ok(())
        }
        PinAction::Remove { state } => {
            let _lock = state.lock()?;
            let current = PinReader::from_stdin().current_pin()?;
            state::pin_remove(&state.state_dir, &current)?;
            println!("PIN removed.");
            Ok(())
        }
    }
}

fn pin_status(state: StateArgs) -> io::Result<()> {
    // Reading needs no lock (see `state::pin_info`), so this also works while
    // the daemon runs.
    let info = state::pin_info(&state.state_dir)?;
    println!("PIN set:           {}", info.is_set);
    println!("Retries remaining: {}", info.retries);
    println!("Blocked:           {}", info.blocked);
    if let DaemonState::Running(_) = state_lock::daemon_state(&state.state_dir)? {
        println!("(After 3 wrong PINs in a row the running daemon also refuses PIN checks until it restarts.)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{error::ErrorKind, CommandFactory};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pqkey").chain(args.iter().copied()))
    }

    #[test]
    fn command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn pins_are_not_accepted_as_arguments() {
        for args in [
            &["pin", "set", "--pin", "1234"][..],
            &["pin", "set", "1234"],
            &["pin", "change", "--current", "1234", "--new", "5678"],
            &["pin", "change", "1234", "5678"],
            &["pin", "remove", "--current", "1234"],
            &["pin", "remove", "1234"],
        ] {
            let err = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            assert_eq!(err.kind(), ErrorKind::UnknownArgument, "{args:?}: {err}");
        }
        assert!(parse(&["pin", "change", "--state-dir", "/tmp/x"]).is_ok());
    }

    fn presence_of(args: &[&str]) -> Result<(PresenceMode, Option<Duration>), clap::Error> {
        let Command::Attach(start) = parse(args)?.command else {
            panic!("not attach");
        };
        let config = start.to_runner_config().unwrap();
        Ok((config.presence, config.presence_timeout))
    }

    #[test]
    fn presence_mode_is_chosen_with_presence() {
        assert_eq!(
            presence_of(&["attach"]).unwrap(),
            (PresenceMode::Notify, None)
        );
        assert_eq!(
            presence_of(&["attach", "--presence", "notify"]).unwrap(),
            (PresenceMode::Notify, None)
        );
        assert_eq!(
            presence_of(&["attach", "--presence", "auto-approve"]).unwrap(),
            (PresenceMode::AutoApprove, None)
        );
        assert_eq!(
            presence_of(&[
                "attach",
                "--presence",
                "unanswered",
                "--presence-timeout",
                "3"
            ])
            .unwrap(),
            (PresenceMode::Unanswered, Some(Duration::from_secs(3)))
        );
        let err = presence_of(&["attach", "--presence", "maybe"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidValue, "{err}");
        let err = presence_of(&["attach", "--presence-timeout", "0"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation, "{err}");
    }

    #[test]
    fn the_old_manual_user_presence_flag_is_gone() {
        let err = parse(&["attach", "--manual-user-presence"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }

    fn attach_config(args: &[&str]) -> Result<service::RunnerConfig, clap::Error> {
        let args: Vec<&str> = std::iter::once("attach")
            .chain(args.iter().copied())
            .collect();
        match parse(&args)?.command {
            Command::Attach(cmd) => Ok(cmd.to_runner_config().unwrap()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_defaults_name_no_vendor() {
        let config = attach_config(&[]).unwrap();
        assert_eq!(
            config.aaguid,
            [
                0x59, 0x31, 0xe8, 0x05, 0xa1, 0x66, 0x4e, 0xb7, 0x84, 0x5a, 0x7f, 0x6a, 0xa9, 0x3d,
                0x9c, 0xd8
            ]
        );
        // A version 4 (random) UUID of the RFC 4122 variant.
        assert_eq!(config.aaguid[6] >> 4, 4);
        assert_eq!(config.aaguid[8] >> 6, 0b10);
        assert_eq!(config.descriptor.vendor_id, 0x1209);
        assert_eq!(config.descriptor.product_id, 0x0001);
        assert_eq!(config.descriptor.vendor_id, crate::uhid::DEFAULT_VENDOR_ID);
        assert_eq!(
            config.descriptor.product_id,
            crate::uhid::DEFAULT_PRODUCT_ID
        );
        assert_eq!(
            config.descriptor.name,
            "pqkey FIDO2 Software Authenticator (ML-DSA)"
        );
        let Command::Attach(start) = parse(&["attach"]).unwrap().command else {
            panic!("not attach");
        };
        assert_eq!(start.device.manufacturer, None);
        assert_eq!(start.device.country, None);
        assert_eq!(start.device.product, DEFAULT_NAME);

        let config = attach_config(&[
            "--vendor-id",
            "0x1234",
            "--product-id",
            "0x5678",
            "--aaguid",
            "00112233445566778899aabbccddeeff",
        ])
        .unwrap();
        assert_eq!(config.descriptor.vendor_id, 0x1234);
        assert_eq!(config.descriptor.product_id, 0x5678);
        assert_eq!(config.aaguid[..4], [0x00, 0x11, 0x22, 0x33]);
        // The ignored legacy flags still parse.
        assert!(attach_config(&["--vid", "0x1998", "-p", "0x0616"]).is_ok());
    }

    #[test]
    fn self_attestation_is_the_default() {
        let config = attach_config(&[]).unwrap();
        assert_eq!(
            config.attestation,
            service::AttestationConfig::SelfAttestation
        );
        // Identity strings alone do not select certificate attestation.
        let config = attach_config(&["--manufacturer", "Example", "--country", "US"]).unwrap();
        assert_eq!(
            config.attestation,
            service::AttestationConfig::SelfAttestation
        );
        let config = attach_config(&["--attestation", "self"]).unwrap();
        assert_eq!(
            config.attestation,
            service::AttestationConfig::SelfAttestation
        );
    }

    #[test]
    fn attestation_none_is_selected_with_attestation() {
        let config = attach_config(&["--attestation", "none"]).unwrap();
        assert_eq!(config.attestation, service::AttestationConfig::None);
        let err = attach_config(&["--attestation", "basic"]).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidValue, "{err}");
    }

    #[test]
    fn certificate_attestation_needs_a_manufacturer_and_a_country() {
        for args in [
            &["--attestation", "certificate"][..],
            &["--attestation", "certificate", "--manufacturer", "Example"],
            &["--attestation", "certificate", "--country", "US"],
        ] {
            let err = attach_config(args).err().unwrap();
            assert_eq!(
                err.kind(),
                ErrorKind::MissingRequiredArgument,
                "{args:?}: {err}"
            );
        }
        let config = attach_config(&[
            "--attestation",
            "certificate",
            "--manufacturer",
            "Example Manufacturer",
            "--product",
            "Example Authenticator",
            "--country",
            "us",
        ])
        .unwrap();
        assert_eq!(
            config.attestation,
            service::AttestationConfig::Certificate(service::IdentityStrings {
                manufacturer: "Example Manufacturer".into(),
                product: "Example Authenticator".into(),
                country: "US".into(),
            })
        );
    }

    #[test]
    fn the_certificate_country_is_an_iso_3166_code() {
        for country in ["USA", "EU", "1"] {
            let err = attach_config(&["--country", country]).err().unwrap();
            assert_eq!(err.kind(), ErrorKind::ValueValidation, "{country}: {err}");
        }
        // The serial number is random now; --serial is still accepted.
        assert!(attach_config(&["--serial", "PQC-001"]).is_ok());
    }

    #[test]
    fn the_old_suppress_attestation_flag_is_gone() {
        let err = parse(&["attach", "--suppress-attestation"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnknownArgument);
    }
}
