//! The `pqkey` command line: a few commands that do what a hardware security
//! key's owner does with it.
//!
//! ```text
//! pqkey setup [--uninstall]   install for this user (or remove), once
//! pqkey start | stop          plug the key in / pull it out
//! pqkey status                the key and everything it needs (the default)
//! pqkey pin                   set the PIN, or change it
//! pqkey passkeys [delete Q]   list the passkeys stored on the key, or delete one
//! pqkey reset [--yes]         erase every passkey and the PIN
//! ```
//!
//! While the key runs, `pin`, `passkeys` and `reset` talk to it over CTAP,
//! through its hidraw node, as a key's management application does
//! ([`crate::client`]): the key itself checks the PIN, counts retries and asks
//! the user to approve a reset.  The hidden `run` command is the daemon
//! itself, for the systemd unit and for test rigs, with the options only they
//! need.

pub(crate) mod checks;
mod daemon;
pub(crate) mod daemon_info;
pub(crate) mod key;
pub mod output;
mod setup;

use std::{ffi::OsString, io, path::PathBuf, process::ExitCode, time::Duration};

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;

use crate::{attestation, presence::PresenceMode, service, state::default_state_dir};

/// The exit status when the key runs already, so a second one cannot start.
/// The systemd unit does not restart on it (`RestartPreventExitStatus=3`): a
/// key started by hand holds the state, and restarting cannot change that.
pub const EXIT_ALREADY_RUNNING: u8 = 3;

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
    long_about = "pqkey: a FIDO2 security key with post-quantum ML-DSA, as a virtual USB HID \
                  device.\n\nRun `pqkey setup` once, then use it like a hardware key: browsers \
                  find it, and each registration, sign-in and reset asks you to approve it in a \
                  desktop notification. Without a command, pqkey shows its status.",
    version,
    author
)]
pub struct Cli {
    /// The key's state directory (for test rigs; also PQKEY_STATE_DIR)
    #[clap(
        long,
        global = true,
        hide = true,
        env = "PQKEY_STATE_DIR",
        value_parser,
        default_value_os_t = default_state_dir()
    )]
    state_dir: PathBuf,
    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install pqkey for this user: set up what needs root (with sudo),
    /// install and start the user service, and set a PIN
    Setup {
        /// Remove the user service again, and print what undoes the root part
        #[clap(long)]
        uninstall: bool,
        /// Run the steps that need root without asking first
        #[clap(long, conflicts_with = "uninstall")]
        yes: bool,
    },
    /// Plug the key in: start it, through its systemd user service when that
    /// is installed
    #[clap(about = crate::platform::START_HELP)]
    Start(DaemonArgs),
    /// Pull the key out: stop it
    Stop,
    /// Show whether the key is plugged in, whether browsers can reach it, its
    /// PIN and free passkey slots, and anything that needs fixing
    Status,
    /// Set the key's PIN, or change it if one is set
    ///
    /// PINs are never taken from command-line arguments, which other local
    /// users can read and shells save to history. On a terminal they are
    /// prompted for with echo off, and a new PIN twice; otherwise standard
    /// input gives one PIN per line: the current PIN first, if one is set,
    /// then the new one.
    Pin,
    /// List the passkeys stored on the key, or delete one (needs the PIN)
    Passkeys {
        #[clap(subcommand)]
        action: Option<PasskeysAction>,
    },
    /// Erase every passkey and the PIN: the key restarts, then asks you to
    /// approve in a notification
    Reset {
        /// Do not ask for confirmation on the terminal
        #[clap(long)]
        yes: bool,
    },
    /// Run the key in the foreground until it is stopped (for the systemd
    /// unit and test rigs)
    #[clap(hide = true, about = crate::platform::RUN_HELP)]
    Run(DaemonArgs),
}

#[derive(Subcommand, Debug)]
enum PasskeysAction {
    /// Delete the passkey QUERY names: part of its relying party, user name,
    /// display name or ID, as `pqkey passkeys` lists them
    Delete {
        query: String,
        /// Do not ask for confirmation on the terminal
        #[clap(long)]
        yes: bool,
    },
}

/// The daemon's options, for test rigs: hidden from help, and taken by `run`
/// and by `start`, which passes them on.
#[derive(Args, Debug, Clone)]
pub struct DaemonArgs {
    /// How the user approves registrations, sign-ins and resets
    #[clap(long, hide = true, value_enum, default_value_t = PresenceArg::Notify)]
    presence: PresenceArg,
    /// Seconds a presence request waits for the user (default 30). CTAP 2.3
    /// section 5 says the user action timeout MUST be at least 10 seconds:
    /// shorter values do not conform and are for test rigs only.
    #[clap(long, hide = true, value_parser = clap::value_parser!(u64).range(1..=600))]
    presence_timeout: Option<u64>,
    /// Accept authenticatorReset at any time instead of only within 10
    /// seconds of start-up. Does not conform to CTAP 2.3 section 6.6; for test
    /// rigs that reset a long-running authenticator. User presence is still
    /// required.
    #[clap(long, hide = true)]
    allow_late_reset: bool,
    /// HID product name
    #[clap(long, hide = true, default_value = DEFAULT_NAME)]
    name: String,
    /// USB vendor ID (default: pid.codes' open source vendor ID)
    #[clap(long, hide = true, value_parser = maybe_hex::<u16>, default_value = "0x1209")]
    vendor_id: u16,
    /// USB product ID (default: a pid.codes test product ID, which is not
    /// unique to pqkey)
    #[clap(long, hide = true, value_parser = maybe_hex::<u16>, default_value = "0x0001")]
    product_id: u16,
    /// Version reported by the HID descriptor
    #[clap(long, hide = true, value_parser = maybe_hex::<u32>, default_value_t = 0x0001)]
    version: u32,
    /// AAGUID, reported in authenticatorGetInfo and in every registration
    #[clap(long, hide = true, default_value = DEFAULT_AAGUID)]
    aaguid: String,
    /// The attestation statement registrations get
    #[clap(long, hide = true, value_enum, default_value_t = AttestationArg::SelfAttestation)]
    attestation: AttestationArg,
    /// Manufacturer named in a newly provisioned attestation certificate.
    /// Required with --attestation certificate
    #[clap(long, hide = true, required_if_eq("attestation", "certificate"))]
    manufacturer: Option<String>,
    /// Product named in a newly provisioned attestation certificate
    #[clap(long, hide = true, default_value = DEFAULT_NAME)]
    product: String,
    /// Country (ISO 3166-1 alpha-2 code) named in a newly provisioned
    /// attestation certificate. Required with --attestation certificate
    #[clap(
        long,
        hide = true,
        value_parser = attestation::parse_country,
        required_if_eq("attestation", "certificate")
    )]
    country: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum PresenceArg {
    /// Ask with a desktop notification that has Approve and Deny buttons.
    /// Without a session bus and a notification server that can show
    /// buttons, every request is denied
    #[value(help = crate::platform::PRESENCE_NOTIFY_HELP)]
    Notify,
    /// Approve every request without asking. Anything running as you can then
    /// use your passkeys unnoticed; for tests and CI only
    AutoApprove,
    /// Never answer, so every request waits until it is cancelled or times
    /// out (for tests)
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

    fn name(self) -> &'static str {
        match self {
            PresenceArg::Notify => "notify",
            PresenceArg::AutoApprove => "auto-approve",
            PresenceArg::Unanswered => "unanswered",
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum AttestationArg {
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

impl AttestationArg {
    fn name(self) -> &'static str {
        match self {
            AttestationArg::SelfAttestation => "self",
            AttestationArg::Certificate => "certificate",
            AttestationArg::None => "none",
        }
    }
}

impl DaemonArgs {
    pub(crate) fn to_runner_config(
        &self,
        state_dir: PathBuf,
    ) -> Result<service::RunnerConfig, String> {
        let aaguid = service::parse_aaguid(&self.aaguid)?;
        let descriptor = service::descriptor(
            self.name.clone(),
            self.vendor_id.into(),
            self.product_id.into(),
            self.version,
        );
        let attestation = match self.attestation {
            AttestationArg::SelfAttestation => service::AttestationConfig::SelfAttestation,
            AttestationArg::None => service::AttestationConfig::None,
            AttestationArg::Certificate => {
                let required = |value: &Option<String>, flag: &str| {
                    value
                        .clone()
                        .ok_or_else(|| format!("--attestation certificate requires {flag}"))
                };
                service::AttestationConfig::Certificate(service::IdentityStrings {
                    manufacturer: required(&self.manufacturer, "--manufacturer")?,
                    product: self.product.clone(),
                    country: required(&self.country, "--country")?,
                })
            }
        };
        Ok(service::RunnerConfig {
            descriptor,
            state_dir,
            aaguid,
            attestation,
            presence: self.presence.into_mode(),
            presence_timeout: self.presence_timeout.map(Duration::from_secs),
            allow_late_reset: self.allow_late_reset,
        })
    }

    /// The command-line arguments that give `run` these options.
    pub(crate) fn to_args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            "--presence".into(),
            self.presence.name().into(),
            "--name".into(),
            self.name.clone().into(),
            "--vendor-id".into(),
            format!("{:#06x}", self.vendor_id).into(),
            "--product-id".into(),
            format!("{:#06x}", self.product_id).into(),
            "--version".into(),
            format!("{:#x}", self.version).into(),
            "--aaguid".into(),
            self.aaguid.clone().into(),
            "--attestation".into(),
            self.attestation.name().into(),
            "--product".into(),
            self.product.clone().into(),
        ];
        if let Some(timeout) = self.presence_timeout {
            args.extend(["--presence-timeout".into(), timeout.to_string().into()]);
        }
        if self.allow_late_reset {
            args.push("--allow-late-reset".into());
        }
        if let Some(manufacturer) = &self.manufacturer {
            args.extend(["--manufacturer".into(), manufacturer.clone().into()]);
        }
        if let Some(country) = &self.country {
            args.extend(["--country".into(), country.clone().into()]);
        }
        args
    }

    /// Whether these are the options a key for a person runs with, the ones
    /// the systemd unit uses.
    pub(crate) fn are_defaults(&self) -> bool {
        self.to_args() == Self::default().to_args()
    }
}

impl Default for DaemonArgs {
    fn default() -> Self {
        let Some(Command::Run(args)) = Cli::parse_from(["pqkey", "run"]).command else {
            unreachable!("`run` parses to Command::Run");
        };
        args
    }
}

/// The options the daemon `pid` runs with, from its published information.
/// Without it the options are unknown, and never replaced with defaults.
pub(crate) fn daemon_args_of(
    state_dir: &std::path::Path,
    pid: nix::unistd::Pid,
) -> io::Result<DaemonArgs> {
    daemon_info::DaemonInfo::read(state_dir, pid)
        .and_then(|info| info.args())
        .map_err(|_| {
            io::Error::other(format!(
                "the key (pid {pid}) was not started by this version of pqkey; restart it with \
                 `pqkey stop && pqkey start` first"
            ))
        })
}

/// The options of `pqkey run` in a NUL-separated command line, as
/// `/proc/PID/cmdline` holds it.
fn daemon_args_from(cmdline: &[u8]) -> Option<DaemonArgs> {
    use std::os::unix::ffi::OsStrExt;
    let args = cmdline
        .strip_suffix(b"\0")
        .unwrap_or(cmdline)
        .split(|&byte| byte == 0)
        .map(|arg| std::ffi::OsStr::from_bytes(arg).to_owned());
    match Cli::try_parse_from(args).ok()?.command? {
        Command::Run(args) => Some(args),
        _ => None,
    }
}

/// Run the command line and turn its outcome into pqkey's exit status:
/// 0 on success, [`EXIT_ALREADY_RUNNING`], or 1 with the error on standard
/// error.
pub fn main() -> ExitCode {
    let result = run_cli();
    if let Err(err) = &result
        && !output::is_closed_output(err)
    {
        output::error_line(format_args!("pqkey: {err}"));
    }
    ExitCode::from(exit_status(&result))
}

fn exit_status(result: &io::Result<()>) -> u8 {
    match result {
        Ok(()) => 0,
        // Whoever read the output has all they wanted, as with `| head`.
        Err(err) if output::is_closed_output(err) => 0,
        Err(err)
            if err
                .get_ref()
                .is_some_and(|inner| inner.is::<daemon::AlreadyRunning>()) =>
        {
            EXIT_ALREADY_RUNNING
        }
        Err(_) => 1,
    }
}

pub fn run_cli() -> io::Result<()> {
    let cli = Cli::parse();
    let state_dir = cli.state_dir;
    match cli.command.unwrap_or(Command::Status) {
        Command::Run(args) => daemon::run(state_dir, &args),
        Command::Start(args) => daemon::start(&state_dir, &args),
        Command::Stop => daemon::stop(&state_dir),
        Command::Status => key::status(&state_dir),
        Command::Pin => key::pin(&state_dir),
        Command::Passkeys { action: None } => key::list_passkeys(&state_dir),
        Command::Passkeys {
            action: Some(PasskeysAction::Delete { query, yes }),
        } => key::delete_passkey(&state_dir, &query, yes),
        Command::Reset { yes } => key::reset(&state_dir, yes),
        Command::Setup {
            uninstall: false,
            yes,
        } => setup::setup(&state_dir, yes),
        Command::Setup {
            uninstall: true, ..
        } => setup::uninstall(&state_dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pqkey").chain(args.iter().copied()))
    }

    #[test]
    fn command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// The commands a person uses, and nothing else, are in the help.
    #[test]
    fn help_lists_the_commands_of_a_security_key() {
        let help = Cli::command().render_help().to_string();
        for command in [
            "setup", "start", "stop", "status", "pin", "passkeys", "reset",
        ] {
            assert!(
                help.contains(&format!("  {command} ")),
                "{command} missing:\n{help}"
            );
        }
        for hidden in ["run", "attach", "detach", "--state-dir"] {
            assert!(!help.contains(hidden), "{hidden} shown:\n{help}");
        }
        let start = Cli::command()
            .find_subcommand_mut("start")
            .unwrap()
            .render_help()
            .to_string();
        assert!(!start.contains("--presence"), "{start}");
    }

    #[test]
    fn no_command_shows_the_status() {
        assert!(parse(&[]).unwrap().command.is_none());
    }

    #[test]
    fn pins_are_not_accepted_as_arguments() {
        for args in [
            &["pin", "1234"][..],
            &["pin", "--pin", "1234"],
            &["pin", "--current", "1234", "--new", "5678"],
            &["passkeys", "--pin", "1234"],
            &["reset", "1234"],
        ] {
            let err = parse(args)
                .err()
                .unwrap_or_else(|| panic!("{args:?} parsed"));
            assert!(
                matches!(
                    err.kind(),
                    ErrorKind::UnknownArgument | ErrorKind::InvalidSubcommand
                ),
                "{args:?}: {err}"
            );
        }
        assert!(parse(&["pin", "--state-dir", "/tmp/x"]).is_ok());
    }

    /// The commands of the earlier command line are gone.
    #[test]
    fn the_old_commands_are_gone() {
        for args in [
            &["attach"][..],
            &["detach"],
            &["pin", "set"],
            &["pin", "remove"],
            &["pin", "status"],
            &["run", "--serial", "x"],
            &["run", "--vid", "0x1998"],
            &["run", "--backend", "uhid"],
        ] {
            assert!(parse(args).is_err(), "{args:?} parsed");
        }
    }

    fn run_config(args: &[&str]) -> Result<service::RunnerConfig, clap::Error> {
        let args: Vec<&str> = std::iter::once("run").chain(args.iter().copied()).collect();
        match parse(&args)?.command {
            Some(Command::Run(daemon)) => Ok(daemon.to_runner_config("/tmp/state".into()).unwrap()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn presence_mode_is_chosen_with_presence() {
        let presence = |args: &[&str]| {
            run_config(args).map(|config| (config.presence, config.presence_timeout))
        };
        assert_eq!(presence(&[]).unwrap(), (PresenceMode::Notify, None));
        assert_eq!(
            presence(&["--presence", "auto-approve"]).unwrap(),
            (PresenceMode::AutoApprove, None)
        );
        assert_eq!(
            presence(&["--presence", "unanswered", "--presence-timeout", "3"]).unwrap(),
            (PresenceMode::Unanswered, Some(Duration::from_secs(3)))
        );
        let err = presence(&["--presence", "maybe"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidValue, "{err}");
        let err = presence(&["--presence-timeout", "0"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation, "{err}");
    }

    #[test]
    fn the_defaults_name_no_vendor() {
        let config = run_config(&[]).unwrap();
        assert_eq!(
            config.descriptor.vendor_id,
            crate::transport::DEFAULT_VENDOR_ID
        );
        assert_eq!(
            config.descriptor.product_id,
            crate::transport::DEFAULT_PRODUCT_ID
        );
        assert_eq!(config.descriptor.name, DEFAULT_NAME);
        assert_eq!(config.state_dir, PathBuf::from("/tmp/state"));
        assert!(!config.allow_late_reset);
        let config = run_config(&[
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

        // USB vendor and product IDs are 16 bits; larger values are refused
        // instead of reaching clients truncated.
        for option in ["--vendor-id", "--product-id"] {
            let err = parse(&["run", option, "0x10000"]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ValueValidation, "{option}: {err}");
        }
    }

    #[test]
    fn attestation_is_chosen_with_attestation() {
        assert_eq!(
            run_config(&[]).unwrap().attestation,
            service::AttestationConfig::SelfAttestation
        );
        assert_eq!(
            run_config(&["--attestation", "none"]).unwrap().attestation,
            service::AttestationConfig::None
        );
        for args in [
            &["--attestation", "certificate"][..],
            &["--attestation", "certificate", "--manufacturer", "Example"],
            &["--attestation", "certificate", "--country", "US"],
        ] {
            let err = run_config(args).err().unwrap();
            assert_eq!(
                err.kind(),
                ErrorKind::MissingRequiredArgument,
                "{args:?}: {err}"
            );
        }
        let config = run_config(&[
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
        for country in ["USA", "EU", "1"] {
            let err = run_config(&["--country", country]).err().unwrap();
            assert_eq!(err.kind(), ErrorKind::ValueValidation, "{country}: {err}");
        }
    }

    /// `start` hands its options to the `run` it starts unchanged.
    #[test]
    fn start_passes_its_options_on_to_run() {
        let options = [
            "--presence",
            "auto-approve",
            "--presence-timeout",
            "3",
            "--allow-late-reset",
            "--product-id",
            "0x0005",
            "--attestation",
            "certificate",
            "--manufacturer",
            "Example",
            "--country",
            "US",
        ];
        let Some(Command::Start(start)) =
            parse(&[&["start"][..], &options].concat()).unwrap().command
        else {
            panic!("not start");
        };
        assert!(!start.are_defaults());
        let mut run = vec![OsString::from("pqkey"), "run".into()];
        run.extend(start.to_args());
        let Some(Command::Run(parsed)) = Cli::try_parse_from(run).unwrap().command else {
            panic!("not run");
        };
        assert_eq!(parsed.to_args(), start.to_args());
        assert_eq!(
            format!("{:?}", parsed.to_runner_config("/s".into())),
            format!("{:?}", start.to_runner_config("/s".into()))
        );
        assert!(DaemonArgs::default().are_defaults());
    }

    /// A second key on the same state exits with a status of its own, which
    /// the systemd unit does not restart on.
    #[test]
    fn a_second_key_on_the_same_state_exits_with_status_3() {
        let dir = crate::test_support::TempDir::new("cli-already-running");
        let lock = crate::state_lock::StateLock::try_acquire(dir.path())
            .unwrap()
            .unwrap();
        crate::state_lock::write_pid_file(dir.path(), &lock).unwrap();
        let result = daemon::run(dir.path().to_owned(), &DaemonArgs::default());
        let err = result.as_ref().unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("the key is already running (pid {})", std::process::id())
        );
        assert_eq!(exit_status(&result), EXIT_ALREADY_RUNNING);
        assert_eq!(exit_status(&Ok(())), 0);
        assert_eq!(exit_status(&Err(io::Error::other("failed"))), 1);
    }

    /// A re-plug restarts the daemon with the options it was started with,
    /// read back from its command line.
    #[test]
    fn a_daemon_s_options_are_read_back_from_its_command_line() {
        let Some(Command::Start(start)) =
            parse(&["start", "--presence", "unanswered", "--product-id", "5"])
                .unwrap()
                .command
        else {
            panic!("not start");
        };
        let mut cmdline = b"/usr/bin/pqkey\0--state-dir\0/tmp/s\0run\0".to_vec();
        for arg in start.to_args() {
            cmdline.extend(arg.as_encoded_bytes());
            cmdline.push(0);
        }
        let read = daemon_args_from(&cmdline).unwrap();
        assert_eq!(read.to_args(), start.to_args());
        assert!(daemon_args_from(b"/usr/bin/pqkey\0attach\0--foreground\0").is_none());
        assert!(daemon_args_from(b"/usr/bin/pqkey\0status\0").is_none());
    }
}
