//! Install, start and check the key, then ask for its PIN.
use super::{
    checks,
    daemon::{self, Running},
    key,
    output::{self, outln},
};
use crate::platform::{ServiceAction, System, UserService};
use nix::unistd;
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, IsTerminal},
    path::Path,
    time::Duration,
};

/// `pqkey setup`; `yes` approves installation, never supplies a PIN.
pub fn setup(state_dir: &Path, yes: bool) -> io::Result<()> {
    setup_result(setup_inner(state_dir, yes), "pqkey setup")
}

fn setup_result(result: io::Result<()>, command: &str) -> io::Result<()> {
    result.map_err(|err| {
        // A closed pipe is a successful read-only command, but must never
        // turn an interrupted installation into success.
        if output::is_closed_output(&err) {
            io::Error::other(format!("setup did not finish: {err}; rerun `{command}`"))
        } else {
            err
        }
    })
}

fn setup_inner(state_dir: &Path, yes: bool) -> io::Result<()> {
    System::check_setup_caller(state_dir)?;
    let binary = env::current_exe()?.canonicalize()?;
    if binary.components().any(|part| part.as_os_str() == "target") {
        return Err(io::Error::other(format!(
            "{} is in a build directory; install with ./install.sh, which runs setup itself",
            binary.display()
        )));
    }
    let path = env::var_os("PATH");
    run_setup(
        &mut System::real()?,
        SetupRequest {
            state: state_dir,
            binary: &binary,
            yes,
            interactive: io::stdin().is_terminal(),
            path: path.as_deref(),
        },
        &mut || key::ask("Set these up with sudo?", true),
    )
}

/// The effects of setup, kept narrow so regression tests run the actual
/// orchestration without changing the host's service, groups or devices.
trait SetupHost {
    fn steps(&self) -> io::Result<Option<crate::platform::SetupSteps>>;
    fn apply(&mut self, steps: &crate::platform::SetupSteps) -> io::Result<()>;
    fn blockers(&mut self) -> io::Result<Vec<checks::Problem>>;
    fn start(&mut self, state: &Path, binary: &Path) -> io::Result<Running>;
    fn problems(&self, state: &Path, running: Running) -> io::Result<Vec<checks::Problem>>;
    /// What setup shows without failing on it.
    fn warning(&self, state: &Path, running: Running) -> io::Result<Option<checks::Problem>>;
    fn pin(&mut self, running: Running, interactive: bool) -> io::Result<()>;
    fn verify(&self, state: &Path, binary: &Path, running: Running) -> io::Result<()>;
}

impl SetupHost for System {
    fn steps(&self) -> io::Result<Option<crate::platform::SetupSteps>> {
        self.setup_steps()
    }
    fn apply(&mut self, steps: &crate::platform::SetupSteps) -> io::Result<()> {
        self.apply_setup_steps(steps)
    }
    fn blockers(&mut self) -> io::Result<Vec<checks::Problem>> {
        self.refresh()?;
        self.start_problems()
    }
    fn start(&mut self, state: &Path, binary: &Path) -> io::Result<Running> {
        start_service(state, binary, System::can_ask_at)
    }
    fn problems(&self, state: &Path, running: Running) -> io::Result<Vec<checks::Problem>> {
        key::running_problems(state, self, running, Duration::from_secs(5))
    }
    fn warning(&self, state: &Path, running: Running) -> io::Result<Option<checks::Problem>> {
        key::presence_warning(state, running)
    }
    fn pin(&mut self, running: Running, interactive: bool) -> io::Result<()> {
        key::ensure_pin(running, interactive)
    }
    fn verify(&self, state: &Path, binary: &Path, running: Running) -> io::Result<()> {
        if daemon::running(state)? != Some(running) || !matches!(running, Running::Service(_)) {
            return Err(io::Error::other(
                "the installed service is not running; check `journalctl --user -u pqkey`",
            ));
        }
        if runs_another_binary(state, running.pid(), binary) {
            return Err(io::Error::other(
                "the service runs another executable; fix its ExecStart or drop-ins, then rerun `pqkey setup`",
            ));
        }
        let info = super::daemon_info::DaemonInfo::read(state, running.pid())?;
        // Setup restarts a service that started before the user manager gave
        // services this shell's bus (`start_service`), so one that still uses
        // another bus gets it from its unit or a drop-in. Without this shell's
        // bus in the manager, the readiness check tests the key's own.
        if info.args()?.presence == super::PresenceArg::Notify
            && !info.session_bus_matches()
            && UserService::gives_shell_bus()?
        {
            return Err(io::Error::other(
                "the service uses another notification session; remove its DBUS_SESSION_BUS_ADDRESS override and rerun `pqkey setup`",
            ));
        }
        Ok(())
    }
}

/// Install, enable and start the user service, or restart it where it runs
/// with an older unit, binary or session bus. `can_ask` checks this shell's
/// session bus before the user manager is given it.
fn start_service(
    state_dir: &Path,
    binary: &Path,
    can_ask: impl FnOnce(&str) -> bool,
) -> io::Result<Running> {
    let before = daemon::running(state_dir)?;
    if let Some(Running::Daemon(pid)) = before
        && !super::daemon_args_of(state_dir, pid)?.are_defaults()
    {
        // One path whether or not the user service is installed yet: once
        // the key is stopped, setup installs and starts the service; options
        // the key still needs, never --presence auto-approve, then go into
        // the service and apply when `pqkey stop && pqkey setup` starts it
        // anew, as setup does not restart a running one for them (below).
        let refusal = "the running key was started by hand with options of its own";
        return Err(io::Error::other(
            match key::presence_warning(state_dir, Running::Daemon(pid))? {
                Some(warning) => {
                    output::problem(
                        warning.what,
                        "run `pqkey stop` and rerun `pqkey setup`; if the key still needs other \
                         options, add them with `systemctl --user edit pqkey`, never --presence \
                         auto-approve, then run `pqkey stop && pqkey setup`",
                    )?;
                    format!("{refusal}; fix the above")
                }
                None => format!(
                    "{refusal}; run `pqkey stop` and rerun `pqkey setup`; if it still needs some \
                     of them, add them with `systemctl --user edit pqkey`, then run `pqkey stop && \
                     pqkey setup`"
                ),
            },
        ));
    }
    let changed = UserService::install(binary)?;
    UserService::action(ServiceAction::Enable)?;
    UserService::action(ServiceAction::ResetFailed)?;
    let shell_bus = UserService::prepare_session(can_ask)?;
    let running = match daemon::running(state_dir)? {
        Some(Running::Daemon(_)) => {
            daemon::unplug(state_dir)?;
            None
        }
        running => running,
    };
    let (running, how) = match running {
        // A running service keeps the environment it started with, so one
        // started before the user manager had this shell's bus, or before a
        // drop-in's DBUS_SESSION_BUS_ADDRESS was removed, needs a restart.
        Some(Running::Service(pid))
            if changed
                || runs_another_binary(state_dir, pid, binary)
                || (shell_bus && !runs_on_shell_bus(state_dir, pid)) =>
        {
            (daemon::replug(state_dir)?, "restarted")
        }
        Some(running) => (running, "running"),
        None => (
            daemon::plug_in(state_dir, &crate::cli::DaemonArgs::default())?,
            "started",
        ),
    };
    output::done(format_args!("Key {how}; it starts with your session"))?;
    Ok(running)
}

struct SetupRequest<'a> {
    state: &'a Path,
    binary: &'a Path,
    yes: bool,
    interactive: bool,
    path: Option<&'a OsStr>,
}

fn run_setup(
    host: &mut impl SetupHost,
    request: SetupRequest<'_>,
    confirm: &mut impl FnMut() -> io::Result<bool>,
) -> io::Result<()> {
    let SetupRequest {
        state,
        binary,
        yes,
        interactive,
        path,
    } = request;
    if let Some(steps) = host.steps()? {
        if !yes {
            outln!("{}", steps.heading)?;
            for step in &steps.summary {
                outln!("  - {step}")?;
            }
            if !interactive {
                return Err(io::Error::other(
                    "setup needs approval; run `pqkey setup --yes` or ./install.sh in a terminal",
                ));
            }
            if !confirm()? {
                return outln!("Setup cancelled; nothing was installed.");
            }
        }
        host.apply(&steps)?;
        for step in &steps.summary {
            output::done(step)?;
        }
    }
    let blockers = host.blockers()?;
    if !blockers.is_empty() {
        output::problems(&blockers)?;
        return Err(io::Error::other(
            "the key cannot start; fix the above, then rerun `pqkey setup`",
        ));
    }
    let running = host.start(state, binary)?;
    host.verify(state, binary, running)?;
    let mut problems = host.problems(state, running)?;
    problems.extend(path_problem(binary, path));
    // A key that approves without asking works: shown, but setup goes on.
    let warning = host.warning(state, running)?;
    output::problems(&problems)?;
    output::problems(warning.as_slice())?;
    // Keep the final PIN interaction even when a separate repair is needed.
    host.pin(running, interactive)?;
    if !problems.is_empty() {
        return Err(io::Error::other(
            "setup is incomplete; fix the above, then rerun `pqkey setup`",
        ));
    }
    host.verify(state, binary, running)?;
    finish(warning.is_none())
}

/// Only reached after every readiness check has passed. `asks` is false for a
/// key that approves requests without asking, which setup has warned about.
fn finish(asks: bool) -> io::Result<()> {
    outln!()?;
    outln!(
        "pqkey is ready. Use it on sites supporting passkeys or security keys; {}.",
        if asks {
            "approve requests with the configured presence provider"
        } else {
            "it approves requests without asking until you fix the above"
        }
    )?;
    outln!()?;
    for (command, what) in [
        ("pqkey", "the key's status"),
        ("pqkey passkeys", "your passkeys"),
        ("pqkey --help", "every command"),
    ] {
        outln!("  {command:<16} {what}")?;
    }
    Ok(())
}

/// Whether the daemon runs another inode than `binary`, as after `cargo
/// install` replaced it. A daemon whose identity is unknown counts as running
/// another, so that setup restarts it.
fn runs_another_binary(state_dir: &Path, pid: unistd::Pid, binary: &Path) -> bool {
    !crate::cli::daemon_info::DaemonInfo::read(state_dir, pid)
        .and_then(|info| info.runs_binary(binary))
        .unwrap_or(false)
}

/// Whether the daemon uses this shell's session bus. A daemon whose bus is
/// unknown does not, so that setup restarts it.
fn runs_on_shell_bus(state_dir: &Path, pid: unistd::Pid) -> bool {
    crate::cli::daemon_info::DaemonInfo::read(state_dir, pid)
        .is_ok_and(|info| info.session_bus_matches())
}

/// Whether `pqkey`, run from the shell, is `binary`, as the README's
/// commands assume: an older pqkey earlier on the PATH would run instead.
fn path_problem(binary: &Path, path: Option<&OsStr>) -> Option<checks::Problem> {
    let dir = binary.parent()?;
    let found = path.and_then(|path| {
        env::split_paths(path)
            .map(|entry| entry.join("pqkey"))
            .find(|candidate| is_executable(candidate))
    });
    match found {
        Some(found) if found.canonicalize().is_ok_and(|found| found == binary) => None,
        Some(found) => Some(checks::Problem {
            what: format!(
                "`pqkey` runs {}, not {}, which the service runs",
                found.display(),
                binary.display()
            ),
            fix: format!(
                "remove {} if it is an older pqkey, or put {} first on your PATH",
                found.display(),
                dir.display()
            ),
        }),
        None => Some(checks::Problem {
            what: format!("{} is not on your PATH", dir.display()),
            fix: format!(
                "in this terminal, run `export PATH=\"{}:$PATH\"`, then rerun `pqkey setup`",
                dir.display()
            ),
        }),
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// `pqkey setup --uninstall`.
pub fn uninstall(state_dir: &Path) -> io::Result<()> {
    setup_result(uninstall_inner(state_dir), "pqkey setup --uninstall")
}

fn uninstall_inner(state_dir: &Path) -> io::Result<()> {
    System::check_setup_caller(state_dir)?;
    if daemon::unplug(state_dir)?.is_some() {
        output::done("Key stopped")?;
    }
    if let Some(path) = UserService::remove()? {
        output::done(format_args!("Removed {}", path.display()))?;
    }
    let binary = env::current_exe()?.canonicalize()?;
    for line in System::uninstall_instructions(&binary, state_dir)? {
        outln!("{line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::path::PathBuf;
    struct Fixture {
        scenario: String,
        trace: std::cell::RefCell<Vec<&'static str>>,
    }
    impl Fixture {
        fn effect(&self, name: &'static str) -> io::Result<()> {
            self.trace.borrow_mut().push(name);
            if self.scenario == name {
                Err(io::Error::other(format!("{name} failed; retry setup")))
            } else {
                Ok(())
            }
        }
    }
    impl SetupHost for Fixture {
        fn steps(&self) -> io::Result<Option<crate::platform::SetupSteps>> {
            self.effect("prepare")?;
            Ok(
                (self.scenario != "configured").then(|| crate::platform::SetupSteps {
                    summary: vec!["fixture permissions".into()],
                    heading: "Setup needs root:",
                    question: "Continue?",
                    script: "exit 0".into(),
                }),
            )
        }
        fn apply(&mut self, _: &crate::platform::SetupSteps) -> io::Result<()> {
            self.effect("root")
        }
        fn blockers(&mut self) -> io::Result<Vec<checks::Problem>> {
            self.effect("refresh")?;
            Ok(if self.scenario == "blockers" {
                vec![checks::Problem::new(
                    "cannot open /dev/uhid",
                    "install acl and rerun setup",
                )]
            } else {
                Vec::new()
            })
        }
        fn start(&mut self, state: &Path, binary: &Path) -> io::Result<Running> {
            self.effect("service")?;
            if self.scenario.starts_with("hand-started") {
                // The real start, which refuses a key started by hand with
                // options before it installs anything.
                return start_service(state, binary, System::can_ask_at);
            }
            Ok(Running::Service(unistd::Pid::this()))
        }
        fn problems(&self, _: &Path, _: Running) -> io::Result<Vec<checks::Problem>> {
            self.effect("client")?;
            Ok(
                if ["device", "notifications"].contains(&self.scenario.as_str()) {
                    vec![checks::Problem::new(
                        format!("{} unavailable", self.scenario),
                        "repair and rerun setup",
                    )]
                } else {
                    Vec::new()
                },
            )
        }
        fn warning(&self, state: &Path, running: Running) -> io::Result<Option<checks::Problem>> {
            self.effect("warning")?;
            key::presence_warning(state, running)
        }
        fn pin(&mut self, _: Running, interactive: bool) -> io::Result<()> {
            self.effect("pin")?;
            if self.scenario == "missing-pin" && !interactive {
                return Err(io::Error::other("PIN setup incomplete; run pqkey pin"));
            }
            Ok(())
        }
        fn verify(&self, _: &Path, _: &Path, _: Running) -> io::Result<()> {
            self.effect("verify")
        }
    }

    // Each scenario is a process: observe the real orchestration's output and
    // the CLI's exit-status mapping, including explicit cancellation.
    #[test]
    fn setup_scenario_child() {
        let Ok(scenario) = env::var("PQKEY_SETUP_SCENARIO") else {
            return;
        };
        if scenario == "closed-output" {
            let (reader, writer) = io::pipe().unwrap();
            drop(reader);
            unistd::dup2_stdout(writer).unwrap();
        }
        let dir = TempDir::new("setup-scenario");
        let binary = dir.path().join("pqkey");
        fs::write(&binary, "fixture").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        // The key setup finds running is this process, run with --presence
        // auto-approve in the scenarios about that, and with an option of
        // its own in `hand-started-options`.
        let lock = crate::state_lock::StateLock::try_acquire(dir.path())
            .unwrap()
            .unwrap();
        let args = match scenario.as_str() {
            "auto-approve" | "hand-started" => crate::cli::DaemonArgs {
                presence: crate::cli::PresenceArg::AutoApprove,
                ..Default::default()
            },
            "hand-started-options" => crate::cli::DaemonArgs {
                presence_timeout: Some(60),
                ..Default::default()
            },
            _ => crate::cli::DaemonArgs::default(),
        };
        crate::test_support::daemon_info(&args)
            .publish(dir.path(), &lock)
            .unwrap();
        crate::state_lock::write_pid_file(dir.path(), &lock).unwrap();
        let mut host = Fixture {
            scenario: scenario.clone(),
            trace: Default::default(),
        };
        let result = run_setup(
            &mut host,
            SetupRequest {
                state: dir.path(),
                binary: &binary,
                yes: !["cancel", "approval"].contains(&scenario.as_str()),
                interactive: !["approval", "missing-pin", "configured"]
                    .contains(&scenario.as_str()),
                path: (scenario != "path").then_some(dir.path().as_os_str()),
            },
            &mut || Ok(false),
        );
        let result = setup_result(result, "pqkey setup");
        if let Err(err) = &result {
            eprintln!("pqkey: {err}");
        }
        let _ = output::line(format_args!("TRACE:{}", host.trace.borrow().join(",")));
        let status = crate::cli::exit_status(&result);
        drop(dir);
        std::process::exit(i32::from(status));
    }

    #[test]
    fn interrupted_setup_output_is_failure_while_status_pipes_remain_successful() {
        let result = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::setup::tests::setup_scenario_child",
                "--nocapture",
            ])
            .env("PQKEY_SETUP_SCENARIO", "closed-output")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("setup did not finish"));
    }

    #[test]
    fn setup_completion_cancellation_and_failure_statuses() {
        // Whatever a scenario's start does, it finds no systemctl, and its
        // user units would go to a directory of the test's own.
        let home = TempDir::new("setup-scenarios");
        let mut traces = std::collections::HashMap::new();
        for scenario in [
            "fresh",
            "configured",
            "auto-approve",
            "hand-started",
            "hand-started-options",
            "cancel",
            "approval",
            "prepare",
            "root",
            "refresh",
            "blockers",
            "service",
            "client",
            "device",
            "notifications",
            "pin",
            "missing-pin",
            "path",
            "verify",
        ] {
            let result = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::setup::tests::setup_scenario_child",
                    "--nocapture",
                ])
                .env("PQKEY_SETUP_SCENARIO", scenario)
                .env("PATH", home.path())
                .env("XDG_CONFIG_HOME", home.path())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            let ready = ["fresh", "configured", "auto-approve"].contains(&scenario);
            let success = ready || scenario == "cancel";
            assert_eq!(
                result.status.code(),
                Some(if success { 0 } else { 1 }),
                "{scenario}: {stdout} {stderr}"
            );
            assert_eq!(
                stdout.contains("pqkey is ready."),
                ready,
                "{scenario}: {stdout}"
            );
            assert!(!stdout.contains("almost ready"));
            if ["cancel", "approval", "prepare"].contains(&scenario) {
                assert!(
                    !stdout.contains("TRACE:prepare,root"),
                    "{scenario}: {stdout}"
                );
            }
            if scenario == "blockers" {
                assert!(!stdout.contains(",service"));
            }
            if scenario == "configured" {
                assert!(!stdout.contains(",root"));
            }
            if !success {
                assert!(!stderr.trim().is_empty(), "{scenario}");
            }
            // A key that approves without asking is named with the fix for
            // how it runs, and setup ends as it did: ready with the service,
            // refused for a key started by hand with options. The refusal
            // and the warning give one path, whether or not the service is
            // installed yet: stop the key and rerun setup, then add the
            // options it still needs, never --presence auto-approve, and run
            // `pqkey stop && pqkey setup`.
            let warning = |fix: &str| {
                format!(
                    "  ! the key runs with --presence auto-approve: it approves every \
                     registration, sign-in and reset without asking, so anything running as you \
                     can use your passkeys unnoticed\n    Fix: {fix}\n"
                )
            };
            let service = warning(
                "remove --presence auto-approve from the ExecStart= line that `systemctl --user \
                 cat pqkey` shows, in the unit or drop-in file named above it, then run `pqkey \
                 stop && pqkey setup`",
            );
            let by_hand = warning(
                "run `pqkey stop` and rerun `pqkey setup`; if the key still needs other options, \
                 add them with `systemctl --user edit pqkey`, never --presence auto-approve, then \
                 run `pqkey stop && pqkey setup`",
            );
            assert_eq!(
                stdout.contains(&service),
                scenario == "auto-approve",
                "{scenario}: {stdout}"
            );
            assert_eq!(
                stdout.contains(&by_hand),
                scenario == "hand-started",
                "{scenario}: {stdout}"
            );
            // Status's other path for a key started by hand is not setup's.
            assert!(
                !stdout.contains("`pqkey start` without"),
                "{scenario}: {stdout}"
            );
            let refusal = "pqkey: the running key was started by hand with options of its own; ";
            for (case, ending) in [
                ("hand-started", "fix the above\n"),
                (
                    "hand-started-options",
                    "run `pqkey stop` and rerun `pqkey setup`; if it still needs some of them, add \
                     them with `systemctl --user edit pqkey`, then run `pqkey stop && pqkey \
                     setup`\n",
                ),
            ] {
                assert_eq!(
                    stderr.contains(&format!("{refusal}{ending}")),
                    scenario == case,
                    "{scenario}: {stderr}"
                );
            }
            assert_eq!(
                stdout.matches("--presence auto-approve:").count(),
                usize::from(["auto-approve", "hand-started"].contains(&scenario)),
                "{scenario}: {stdout}"
            );
            if !["auto-approve", "hand-started"].contains(&scenario) {
                assert!(
                    !format!("{stdout}{stderr}").contains("auto-approve"),
                    "{scenario}: {stdout}{stderr}"
                );
            }
            if ready {
                let asks = scenario != "auto-approve";
                for (ending, shown) in [
                    (
                        "approve requests with the configured presence provider.\n",
                        asks,
                    ),
                    (
                        "it approves requests without asking until you fix the above.\n",
                        !asks,
                    ),
                ] {
                    assert_eq!(
                        stdout.contains(&format!(
                            "pqkey is ready. Use it on sites supporting passkeys or security keys; \
                             {ending}"
                        )),
                        shown,
                        "{scenario}: {stdout}"
                    );
                }
            }
            let trace = stdout
                .find("TRACE:")
                .and_then(|at| stdout[at..].lines().next())
                .unwrap_or_else(|| panic!("{scenario}: {stdout}"));
            traces.insert(scenario, trace.to_owned());
        }
        // The same steps with a key that approves without asking, and none
        // after the refusal of one started by hand.
        assert_eq!(traces["auto-approve"], traces["fresh"]);
        assert_eq!(
            traces["fresh"],
            "TRACE:prepare,root,refresh,service,verify,client,warning,pin,verify"
        );
        for scenario in ["hand-started", "hand-started-options"] {
            assert_eq!(traces[scenario], "TRACE:prepare,root,refresh,service");
        }
    }

    #[test]
    fn an_older_pqkey_earlier_on_the_path_is_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("setup-path");
        let (old, new, none) = (
            dir.path().join("old"),
            dir.path().join("new"),
            dir.path().join("none"),
        );
        for bin in [&old, &new] {
            fs::create_dir_all(bin).unwrap();
            fs::write(bin.join("pqkey"), "").unwrap();
            fs::set_permissions(bin.join("pqkey"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(&none).unwrap();
        let binary = new.join("pqkey").canonicalize().unwrap();
        let path = |dirs: &[&PathBuf]| env::join_paths(dirs).unwrap();

        assert_eq!(
            path_problem(&binary, Some(&path(&[&none, &new, &old]))),
            None
        );
        let shadowed = path_problem(&binary, Some(&path(&[&old, &new]))).unwrap();
        assert!(shadowed.what.contains("old/pqkey"), "{shadowed:?}");
        assert!(shadowed.fix.starts_with("remove "), "{shadowed:?}");
        let missing = path_problem(&binary, Some(&path(&[&none]))).unwrap();
        assert!(missing.what.ends_with("is not on your PATH"), "{missing:?}");
        assert!(path_problem(&binary, None).is_some());
    }
    #[test]
    fn a_service_running_a_replaced_binary_is_restarted() {
        let dir = TempDir::new("setup-binary");
        let lock = crate::state_lock::StateLock::try_acquire(dir.path())
            .unwrap()
            .unwrap();
        crate::test_support::daemon_info(&crate::cli::DaemonArgs::default())
            .publish(dir.path(), &lock)
            .unwrap();
        crate::state_lock::write_pid_file(dir.path(), &lock).unwrap();
        let me = unistd::Pid::this();
        let exe = env::current_exe().unwrap().canonicalize().unwrap();
        assert!(!runs_another_binary(dir.path(), me, &exe));
        assert!(runs_another_binary(
            dir.path(),
            me,
            Path::new("/usr/bin/pqkey")
        ));
        assert!(runs_another_binary(
            dir.path(),
            me,
            Path::new("/nonexistent/pqkey")
        ));
    }
    #[test]
    fn an_unknown_running_binary_is_restarted() {
        assert!(runs_another_binary(
            Path::new("/nonexistent"),
            unistd::Pid::from_raw(i32::MAX),
            &env::current_exe().unwrap()
        ));
    }

    /// A user manager for `start_service`, played by a fake systemctl: it
    /// keeps the manager's environment block in the file `environment`,
    /// records each call in `trace`, and runs `service_key_child` as the
    /// service. The key gets the session bus that block gives it, or the one
    /// in the file `override`, as from a drop-in's `Environment=`, and the
    /// presence in the file `presence`, as from a drop-in's `ExecStart=`.
    struct Manager {
        dir: TempDir,
    }

    const FAKE_SYSTEMCTL: &str = r#"#!/bin/sh
PATH=/usr/bin:/bin
printf '%s\n' "$*" >> "$FIXTURE/trace"
run_key() {
    if [ -e "$FIXTURE/override" ]; then
        set -- env DBUS_SESSION_BUS_ADDRESS="$(cat "$FIXTURE/override")"
    elif bus=$(sed -n 's/^DBUS_SESSION_BUS_ADDRESS=//p' "$FIXTURE/environment") && [ -n "$bus" ]; then
        set -- env DBUS_SESSION_BUS_ADDRESS="$bus"
    else
        set -- env -u DBUS_SESSION_BUS_ADDRESS
    fi
    "$@" PQKEY_SERVICE_KEY="$(cat "$FIXTURE/presence" 2>/dev/null)" "$KEY" --exact \
        cli::setup::tests::service_key_child --nocapture </dev/null >/dev/null 2>&1 &
    echo $! > "$FIXTURE/main-pid"
}
stop_key() {
    pid=$(cat "$FIXTURE/main-pid" 2>/dev/null)
    [ "${pid:-0}" -gt 0 ] && kill "$pid"
    echo 0 > "$FIXTURE/main-pid"
}
case "$*" in
"--user show-environment") cat "$FIXTURE/environment" ;;
"--user set-environment "*)
    grep -v "^${3%%=*}=" "$FIXTURE/environment" > "$FIXTURE/environment.new"
    printf '%s\n' "$3" >> "$FIXTURE/environment.new"
    mv "$FIXTURE/environment.new" "$FIXTURE/environment" ;;
*LoadState*) echo loaded ;;
*MainPID*) cat "$FIXTURE/main-pid" 2>/dev/null || echo 0 ;;
"--user start pqkey.service") run_key ;;
"--user restart pqkey.service") stop_key; run_key ;;
"--user stop pqkey.service") stop_key ;;
esac
"#;

    impl Manager {
        /// A manager whose environment block is empty.
        fn new(label: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = TempDir::new(label);
            let bin = dir.path().join("bin");
            fs::create_dir(&bin).unwrap();
            fs::write(bin.join("systemctl"), FAKE_SYSTEMCTL).unwrap();
            fs::set_permissions(bin.join("systemctl"), fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(dir.path().join("environment"), "").unwrap();
            Self { dir }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// The address of a bus at `name` in this manager's directory.
        fn bus(&self, name: &str) -> String {
            format!("unix:path={}", self.file(name).display())
        }

        fn environment(&self) -> String {
            fs::read_to_string(self.file("environment")).unwrap()
        }

        /// The manager's environment block from now on, as after
        /// `systemctl --user import-environment`.
        fn set_environment(&self, block: &str) {
            fs::write(self.file("environment"), block).unwrap();
        }

        /// The calls to systemctl so far, each without `--user`, and none
        /// from now on.
        fn calls(&self) -> Vec<String> {
            let calls = fs::read_to_string(self.file("trace")).unwrap_or_default();
            fs::remove_file(self.file("trace")).ok();
            calls
                .lines()
                .map(|call| call.trim_start_matches("--user ").to_owned())
                .collect()
        }

        /// `service_child` with `step` and this shell's session bus
        /// `shell_bus`; `can_ask` is the one bus where a notification server
        /// can ask, or `None` for the check setup makes.
        fn run(
            &self,
            step: &str,
            shell_bus: Option<&str>,
            can_ask: Option<&str>,
        ) -> std::process::Output {
            let mut child = std::process::Command::new(env::current_exe().unwrap());
            child
                .args(["--exact", "cli::setup::tests::service_child", "--nocapture"])
                .env("PQKEY_SERVICE_CHILD", step)
                .env("PATH", self.file("bin"))
                .env("XDG_CONFIG_HOME", self.file("config"))
                .env("XDG_DATA_HOME", self.file("data"))
                .env("FIXTURE", self.dir.path())
                .env("KEY", env::current_exe().unwrap())
                .env_remove("DBUS_SESSION_BUS_ADDRESS")
                .env_remove("PQKEY_CAN_ASK");
            if let Some(bus) = shell_bus {
                child.env("DBUS_SESSION_BUS_ADDRESS", bus);
            }
            if let Some(bus) = can_ask {
                child.env("PQKEY_CAN_ASK", bus);
            }
            child.output().unwrap()
        }

        /// `pqkey setup`'s start of the service and its check of it, from a
        /// shell on `shell_bus`; its standard output, or its error.
        fn setup(&self, shell_bus: Option<&str>, can_ask: Option<&str>) -> Result<String, String> {
            let output = self.run("setup", shell_bus, can_ask);
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            match output.status.code() {
                Some(0) => Ok(stdout),
                Some(1) => Err(stderr),
                _ => panic!("{output:?}"),
            }
        }

        /// The key the service runs: its pid, the session bus in its
        /// environment and its presence, as it published them.
        fn key(&self) -> (unistd::Pid, Option<String>, crate::cli::PresenceArg) {
            let state = self.file("data").join("pqkey");
            let pid = crate::state_lock::read_pid(&state).unwrap().unwrap();
            let presence = crate::cli::daemon_args_of(&state, pid).unwrap().presence;
            let info = fs::read(state.join(crate::state_lock::INFO_FILE)).unwrap();
            let end = info.iter().position(|&byte| byte == b'\n').unwrap();
            let header = String::from_utf8(info[..end].to_vec()).unwrap();
            let bus = header
                .split(' ')
                .nth(4)
                .unwrap()
                .strip_prefix('x')
                .map(|hex| {
                    let bytes = (0..hex.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                        .collect();
                    String::from_utf8(bytes).unwrap()
                });
            (pid, bus, presence)
        }
    }

    impl Drop for Manager {
        fn drop(&mut self) {
            let state = self.file("data").join("pqkey");
            if let Ok(crate::state_lock::DaemonState::Running(pid)) =
                crate::state_lock::daemon_state(&state)
            {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
            }
        }
    }

    /// The child of the tests with a `Manager`: `pqkey stop`, or, for
    /// `setup`, the start of the service and its check, as `pqkey setup`
    /// runs them. `PQKEY_CAN_ASK` names the one bus where a notification
    /// server can ask; without it, a bus gets the check setup makes.
    #[test]
    fn service_child() {
        let Ok(step) = env::var("PQKEY_SERVICE_CHILD") else {
            return;
        };
        let state = crate::state::default_state_dir();
        let binary = env::current_exe().unwrap().canonicalize().unwrap();
        let result = if step == "stop" {
            daemon::stop(&state)
        } else {
            let can_ask = |address: &str| match env::var("PQKEY_CAN_ASK") {
                Ok(bus) => address == bus,
                Err(_) => System::can_ask_at(address),
            };
            start_service(&state, &binary, can_ask).and_then(|running| {
                SetupHost::verify(&System::real().unwrap(), &state, &binary, running)
            })
        };
        if let Err(err) = &result {
            eprintln!("pqkey: {err}");
        }
        std::process::exit(i32::from(result.is_err()));
    }

    /// The key a `Manager` runs as the service: once the key before it has
    /// let go of the state directory, it publishes this process, with the
    /// presence `PQKEY_SERVICE_KEY` names and its own session bus, as the
    /// daemon does, and runs until SIGTERM.
    #[test]
    fn service_key_child() {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            time::Instant,
        };
        let Ok(presence) = env::var("PQKEY_SERVICE_KEY") else {
            return;
        };
        let stop = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop)).unwrap();
        let state = crate::state::default_state_dir();
        crate::state::ensure_state_dir(&state).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let lock = loop {
            if let Some(lock) = crate::state_lock::StateLock::try_acquire(&state).unwrap() {
                break lock;
            }
            assert!(Instant::now() < deadline, "the key before never stopped");
        };
        crate::state_lock::remove_pid_file(&state, &lock).unwrap();
        crate::state_lock::remove_info_file(&state, &lock).unwrap();
        let args = crate::cli::DaemonArgs {
            presence: if presence == "unanswered" {
                crate::cli::PresenceArg::Unanswered
            } else {
                crate::cli::PresenceArg::Notify
            },
            ..Default::default()
        };
        crate::test_support::daemon_info(&args)
            .publish(&state, &lock)
            .unwrap();
        crate::state_lock::write_pid_file(&state, &lock).unwrap();
        // Never outlive its test for long.
        let deadline = Instant::now() + Duration::from_secs(60);
        while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        crate::state_lock::remove_pid_file(&state, &lock).unwrap();
        crate::state_lock::remove_info_file(&state, &lock).unwrap();
    }

    /// Only the calls that read or change the manager's environment, or
    /// start, restart or stop the service, in order.
    fn session_calls(calls: &[String]) -> Vec<&str> {
        calls
            .iter()
            .map(String::as_str)
            .filter(|call| {
                call.contains("environment")
                    || (call.ends_with("pqkey.service")
                        && ["start ", "restart ", "stop "]
                            .iter()
                            .any(|action| call.starts_with(action)))
            })
            .collect()
    }

    /// Setup gives the user manager this shell's session bus only where a
    /// notification server there can ask, and never a bus over TCP, which
    /// the service cannot use: an unreachable bus, as in a terminal left from
    /// an earlier login, leaves the manager's environment as it was, and the
    /// service starts with the bus the manager gives it. A bus that can ask
    /// is given before the service starts.
    #[test]
    fn setup_gives_the_user_manager_only_a_checked_unix_bus() {
        let block = |bus: &str| format!("HOME=/home/u\nDBUS_SESSION_BUS_ADDRESS={bus}\n");
        for case in ["unreachable", "tcp", "no-bus", "can-ask"] {
            let manager = Manager::new("setup-bus-check");
            let user_bus = manager.bus("user-bus");
            manager.set_environment(&block(&user_bus));
            let tcp = "tcp:host=127.0.0.1,port=9";
            let desktop = manager.bus("desktop-bus");
            let (shell_bus, can_ask) = match case {
                // Checked as setup checks it: nothing listens there.
                "unreachable" => (Some(manager.bus("gone")), None),
                // Even where the check would pass.
                "tcp" => (Some(tcp.to_owned()), Some(tcp)),
                "no-bus" => (None, None),
                _ => (Some(desktop.clone()), Some(desktop.as_str())),
            };
            let shown = manager.setup(shell_bus.as_deref(), can_ask);
            let stdout = shown.unwrap_or_else(|err| panic!("{case}: {err}"));
            assert!(
                stdout.contains("✓ Key started; it starts with your session\n"),
                "{case}: {stdout}"
            );
            let calls = manager.calls();
            let (_, bus, _) = manager.key();
            if case == "can-ask" {
                assert_eq!(
                    manager.environment(),
                    format!("HOME=/home/u\nDBUS_SESSION_BUS_ADDRESS={desktop}\n")
                );
                assert_eq!(
                    session_calls(&calls),
                    [
                        "show-environment".to_owned(),
                        format!("set-environment DBUS_SESSION_BUS_ADDRESS={desktop}"),
                        "start pqkey.service".to_owned()
                    ]
                );
                // The unit is read again before then.
                let reload = calls.iter().position(|call| call == "daemon-reload");
                let set = calls
                    .iter()
                    .position(|call| call.starts_with("set-environment"));
                assert!(reload < set, "{calls:?}");
                assert_eq!(bus, Some(desktop));
            } else {
                assert_eq!(manager.environment(), block(&user_bus), "{case}");
                assert!(
                    !calls.iter().any(|call| call.starts_with("set-environment")),
                    "{case}: {calls:?}"
                );
                assert_eq!(bus, Some(user_bus), "{case}");
            }
        }
    }

    /// A service that started before the user manager had this shell's bus,
    /// as one does after `systemctl --user import-environment` without a
    /// restart, is restarted onto it: setup neither keeps it on its old bus
    /// nor tells the user to remove an override there is none of. A bus that
    /// setup gives the manager itself is given before the restart.
    #[test]
    fn setup_restarts_a_service_started_before_the_bus_was_imported() {
        let manager = Manager::new("setup-imported-bus");
        let (user_bus, desktop) = (manager.bus("user-bus"), manager.bus("desktop-bus"));
        manager.set_environment(&format!("DBUS_SESSION_BUS_ADDRESS={user_bus}\n"));
        manager.setup(Some(&user_bus), None).unwrap();
        let (before, bus, _) = manager.key();
        assert_eq!(bus.as_deref(), Some(user_bus.as_str()));
        // `systemctl --user import-environment DBUS_SESSION_BUS_ADDRESS` in
        // a terminal of the desktop.
        manager.set_environment(&format!("DBUS_SESSION_BUS_ADDRESS={desktop}\n"));
        manager.calls();
        let stdout = manager.setup(Some(&desktop), None).unwrap();
        assert!(
            stdout.contains("✓ Key restarted; it starts with your session\n"),
            "{stdout}"
        );
        assert_eq!(
            session_calls(&manager.calls()),
            ["show-environment", "restart pqkey.service"]
        );
        let (after, bus, _) = manager.key();
        assert_ne!(after, before);
        assert_eq!(bus, Some(desktop));
        // From a terminal on a bus that can ask and that the manager does not
        // have yet.
        let next = manager.bus("next-desktop-bus");
        let stdout = manager.setup(Some(&next), Some(&next)).unwrap();
        assert!(
            stdout.contains("✓ Key restarted; it starts with your session\n"),
            "{stdout}"
        );
        let calls = manager.calls();
        assert_eq!(
            session_calls(&calls),
            [
                "show-environment".to_owned(),
                format!("set-environment DBUS_SESSION_BUS_ADDRESS={next}"),
                "restart pqkey.service".to_owned()
            ]
        );
        let reload = calls.iter().position(|call| call == "daemon-reload");
        let restart = calls
            .iter()
            .position(|call| call == "restart pqkey.service");
        assert!(reload < restart, "{calls:?}");
        let (last, bus, _) = manager.key();
        assert_ne!(last, after);
        assert_eq!(bus, Some(next));
    }

    /// Setup's fix for a service whose unit or drop-in sets its own
    /// DBUS_SESSION_BUS_ADDRESS, followed as written, ends with the service
    /// on this shell's bus: rerun after the override is gone, setup restarts
    /// it. A shell without a bus the manager gives, here none at all, gets
    /// no such fix: setup checks the bus the key has.
    #[test]
    fn the_override_fix_followed_as_written_moves_the_service_to_the_shells_bus() {
        let manager = Manager::new("setup-override");
        let (user_bus, desktop) = (manager.bus("user-bus"), manager.bus("desktop-bus"));
        manager.set_environment(&format!("DBUS_SESSION_BUS_ADDRESS={user_bus}\n"));
        let other = manager.bus("other-bus");
        fs::write(manager.file("override"), &other).unwrap();
        assert_eq!(
            manager.setup(Some(&desktop), Some(&desktop)),
            Err(
                "pqkey: the service uses another notification session; remove its \
                 DBUS_SESSION_BUS_ADDRESS override and rerun `pqkey setup`\n"
                    .to_owned()
            )
        );
        assert_eq!(manager.key().1, Some(other.clone()));
        // Without this shell's bus in the manager, the bus is not setup's to
        // require, nor to restart the service for.
        let stdout = manager.setup(None, None).unwrap();
        assert!(stdout.contains("✓ Key running;"), "{stdout}");
        assert_eq!(manager.key().1, Some(other));
        fs::remove_file(manager.file("override")).unwrap();
        let stdout = manager.setup(Some(&desktop), Some(&desktop)).unwrap();
        assert!(
            stdout.contains("✓ Key restarted; it starts with your session\n"),
            "{stdout}"
        );
        assert_eq!(manager.key().1, Some(desktop));
    }

    /// The fix for a service that never answers, followed as written after
    /// its drop-in is changed, ends with the service running the changed
    /// options: setup does not restart a running service for a drop-in, so
    /// the fix stops it first.
    #[test]
    fn the_unanswered_fix_followed_as_written_runs_the_changed_options() {
        use crate::cli::PresenceArg;
        let manager = Manager::new("setup-options");
        let user_bus = manager.bus("user-bus");
        manager.set_environment(&format!("DBUS_SESSION_BUS_ADDRESS={user_bus}\n"));
        fs::write(manager.file("presence"), "unanswered").unwrap();
        manager.setup(Some(&user_bus), None).unwrap();
        let (before, _, presence) = manager.key();
        assert_eq!(presence, PresenceArg::Unanswered);
        let fix = key::running_problems(
            &manager.file("data").join("pqkey"),
            &System::real().unwrap(),
            Running::Service(before),
            Duration::ZERO,
        )
        .unwrap()
        .pop()
        .unwrap()
        .fix;
        assert!(
            fix.ends_with(", then run `pqkey stop && pqkey setup`"),
            "{fix}"
        );
        // The drop-in, changed to the default presence.
        fs::write(manager.file("presence"), "").unwrap();
        // Setup alone keeps the key it finds.
        let stdout = manager.setup(Some(&user_bus), None).unwrap();
        assert!(stdout.contains("✓ Key running;"), "{stdout}");
        assert_eq!(
            manager.key(),
            (before, Some(user_bus.clone()), PresenceArg::Unanswered)
        );
        // `pqkey stop && pqkey setup`
        let stopped = manager.run("stop", Some(&user_bus), None);
        assert!(stopped.status.success(), "{stopped:?}");
        let stdout = manager.setup(Some(&user_bus), None).unwrap();
        assert!(stdout.contains("✓ Key started;"), "{stdout}");
        let (after, _, presence) = manager.key();
        assert_ne!(after, before);
        assert_eq!(presence, PresenceArg::Notify);
    }
}
