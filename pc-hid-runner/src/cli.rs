use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
use daemonize::Daemonize;
use nix::unistd::{self, Gid, Group};
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::Pid,
};
use transport_core::{state::default_state_dir, Options};

use crate::{
    permissions, pin_input::PinReader, service, shutdown::ShutdownSignal, HidDeviceDescriptor,
};

#[derive(Parser, Debug)]
#[clap(
    about = "Feitian ML-DSA authenticator service controller",
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
}

#[derive(Args, Debug, Clone)]
pub struct StateArgs {
    /// Directory where persistent Trussed state and pid files are stored
    #[clap(long, value_parser, default_value_os_t = default_state_dir())]
    pub state_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct DeviceArgs {
    /// HID product name
    #[clap(long, default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)")]
    pub name: String,
    /// USB manufacturer string used by Trussed
    #[clap(long, default_value = "Feitian Technologies Co., Ltd.")]
    pub manufacturer: String,
    /// USB product string used by Trussed
    #[clap(long, default_value = "Feitian FIDO2 Software Authenticator (ML-DSA)")]
    pub product: String,
    /// USB serial number string used by Trussed
    #[clap(long, default_value = "FEITIAN-PQC-001")]
    pub serial: String,
    /// Vendor ID for the virtual HID device
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x096e)]
    pub vendor_id: u32,
    /// Product ID for the virtual HID device
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0858)]
    pub product_id: u32,
    /// Version reported by the HID descriptor
    #[clap(long, value_parser = maybe_hex::<u32>, default_value_t = 0x0001)]
    pub version: u32,
    /// USB VID presented by Trussed (for legacy tooling)
    #[clap(short, long, value_parser = maybe_hex::<u16>, default_value_t = 0x1998)]
    pub vid: u16,
    /// USB PID presented by Trussed (for legacy tooling)
    #[clap(short, long, value_parser = maybe_hex::<u16>, default_value_t = 0x0616)]
    pub pid: u16,
    /// Authenticator AAGUID
    #[clap(long, default_value = "4645495449414E980616525A30310000")]
    pub aaguid: String,
    /// Require user gestures instead of automatically satisfying presence checks
    #[clap(long)]
    pub manual_user_presence: bool,
    /// Suppress attestation certificate material for makeCredential operations
    #[clap(long)]
    pub suppress_attestation: bool,
    /// Backend transport to use
    #[clap(long, value_enum, default_value_t = BackendArg::Uhid)]
    pub backend: BackendArg,
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
    fn pid_path(&self) -> PathBuf {
        self.state_dir.join("authenticator.pid")
    }
}

impl StartCommand {
    fn to_runner_config(&self) -> Result<service::RunnerConfig, String> {
        let aaguid = service::parse_aaguid(&self.device.aaguid)?;
        let options = Options {
            manufacturer: Some(self.device.manufacturer.clone()),
            product: Some(self.device.product.clone()),
            serial_number: Some(self.device.serial.clone()),
            vid: self.device.vid,
            pid: self.device.pid,
            device_class: None,
        };
        let descriptor = service::descriptor(
            self.device.name.clone(),
            self.device.vendor_id,
            self.device.product_id,
            self.device.version,
        );
        Ok(service::RunnerConfig {
            descriptor,
            options,
            state_dir: self.state.state_dir.clone(),
            aaguid,
            identity: service::IdentityStrings {
                manufacturer: self.device.manufacturer.clone(),
                product: self.device.product.clone(),
                serial: self.device.serial.clone(),
            },
            auto_user_presence: !self.device.manual_user_presence,
            suppress_attestation: self.device.suppress_attestation,
            backend: self.device.backend.into_backend(),
        })
    }
}

fn read_pid(path: &Path) -> io::Result<Option<Pid>> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                fs::remove_file(path).ok();
                return Ok(None);
            }
            match trimmed.parse::<i32>() {
                Ok(pid) => Ok(Some(Pid::from_raw(pid))),
                Err(_) => {
                    fs::remove_file(path).ok();
                    Ok(None)
                }
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn process_running(pid: Pid) -> bool {
    match signal::kill(pid, None) {
        Ok(_) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => true,
    }
}

fn run_service(config: service::RunnerConfig) -> io::Result<()> {
    let _ = env_logger::try_init();
    let shutdown = ShutdownSignal::new();
    shutdown.install_signal_handlers()?;
    service::run(config, shutdown)
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
                    "warning: {} is world-accessible (mode {:o}). Install contrib/udev/70-feitian-authenticator.rules or tighten permissions.",
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
                "warning: insufficient permissions to access /dev/uhid. Add your user to the '{}' group or adjust contrib/udev/70-feitian-authenticator.rules.",
                GROUP_NAME
            );
        } else {
            eprintln!(
                "warning: unable to access /dev/uhid even though '{}' group is present. Verify the udev rule contrib/udev/70-feitian-authenticator.rules is installed.",
                GROUP_NAME
            );
        }
    } else {
        eprintln!(
            "warning: insufficient permissions to access /dev/uhid and '{}' group was not found. Install contrib/udev/70-feitian-authenticator.rules and adjust the GROUP value for your system.",
            GROUP_NAME
        );
    }
}

fn group_by_name(name: &str) -> Option<Gid> {
    Group::from_name(name).ok().flatten().map(|g| g.gid)
}

fn start(cmd: StartCommand) -> io::Result<()> {
    let state_dir = cmd.state.state_dir.clone();
    service::ensure_state_dir(&state_dir)?;
    let pid_path = cmd.state.pid_path();
    if let Some(pid) = read_pid(&pid_path)? {
        if process_running(pid) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("authenticator already running (pid {})", pid),
            ));
        }
        fs::remove_file(&pid_path).ok();
    }

    let config = cmd
        .to_runner_config()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    warn_device_permissions(&config.descriptor);

    if cmd.foreground {
        fs::write(&pid_path, format!("{}\n", process::id()))?;
        let result = run_service(config);
        fs::remove_file(&pid_path).ok();
        return result;
    }

    let log_path = state_dir.join("authenticator.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;

    let daemon = Daemonize::new()
        .pid_file(&pid_path)
        .stdout(stdout)
        .stderr(stderr)
        .exit_action(|| println!("Authenticator daemonizing..."));

    daemon
        .start()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    let result = run_service(config);
    fs::remove_file(&pid_path).ok();
    result
}

fn stop(state: StateArgs) -> io::Result<()> {
    let pid_path = state.pid_path();
    match read_pid(&pid_path)? {
        Some(pid) => {
            if process_running(pid) {
                signal::kill(pid, Signal::SIGTERM)
                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                let deadline = Instant::now() + Duration::from_secs(5);
                while process_running(pid) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(200));
                }
                if process_running(pid) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for authenticator to stop",
                    ));
                }
            }
            fs::remove_file(&pid_path).ok();
            println!("Authenticator stopped");
            Ok(())
        }
        None => {
            println!("Authenticator is not running");
            Ok(())
        }
    }
}

fn status(state: StateArgs) -> io::Result<()> {
    let pid_path = state.pid_path();
    match read_pid(&pid_path)? {
        Some(pid) if process_running(pid) => {
            println!("Authenticator running (pid {})", pid);
        }
        Some(_) => {
            fs::remove_file(&pid_path).ok();
            println!("Authenticator is not running");
        }
        None => println!("Authenticator is not running"),
    }
    Ok(())
}

pub fn run_cli() -> io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Attach(cmd) => start(cmd),
        Command::Detach(state) => stop(state),
        Command::Status(state) => status(state),
        Command::Reset(args) => reset(args),
        Command::Pin(cmd) => pin(cmd),
    }
}

fn require_daemon_stopped(state: &StateArgs) -> io::Result<()> {
    if let Some(pid) = read_pid(&state.pid_path())? {
        if process_running(pid) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "authenticator daemon is running (pid {pid}); run 'feitian-authenticator detach' first"
                ),
            ));
        }
    }
    Ok(())
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
    require_daemon_stopped(&args.state)?;
    service::ensure_state_dir(&args.state.state_dir)?;
    if !args.yes
        && !confirm(&format!(
            "This will wipe ALL credentials and PIN state under {}. Continue?",
            args.state.state_dir.display()
        ))?
    {
        eprintln!("Reset cancelled.");
        return Ok(());
    }
    service::reset_state(&args.state.state_dir)?;
    println!("Authenticator state has been reset.");
    Ok(())
}

fn pin(cmd: PinCommand) -> io::Result<()> {
    match cmd.action {
        PinAction::Status { state } => pin_status(state),
        PinAction::Set { state } => {
            require_daemon_stopped(&state)?;
            let pin = PinReader::from_stdin().new_pin()?;
            service::pin_set(&state.state_dir, &pin)?;
            println!("PIN set.");
            Ok(())
        }
        PinAction::Change { state } => {
            require_daemon_stopped(&state)?;
            let reader = PinReader::from_stdin();
            let current = reader.current_pin()?;
            let new = reader.new_pin()?;
            service::pin_change(&state.state_dir, &current, &new)?;
            println!("PIN changed.");
            Ok(())
        }
        PinAction::Remove { state } => {
            require_daemon_stopped(&state)?;
            let current = PinReader::from_stdin().current_pin()?;
            service::pin_remove(&state.state_dir, &current)?;
            println!("PIN removed.");
            Ok(())
        }
    }
}

fn pin_status(state: StateArgs) -> io::Result<()> {
    service::ensure_state_dir(&state.state_dir)?;
    let info = service::pin_info(&state.state_dir)?;
    println!("PIN set:           {}", info.is_set);
    println!("Retries remaining: {}", info.retries);
    println!("Blocked:           {}", info.blocked);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{error::ErrorKind, CommandFactory};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pc-hid-runner").chain(args.iter().copied()))
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
}
