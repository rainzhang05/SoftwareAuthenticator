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
        start_service(state, binary)
    }
    fn problems(&self, state: &Path, running: Running) -> io::Result<Vec<checks::Problem>> {
        key::running_problems(state, self, running, Duration::from_secs(5))
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
        if info.args()?.presence == super::PresenceArg::Notify && !info.session_bus_matches() {
            return Err(io::Error::other(
                "the service uses another notification session; remove its DBUS_SESSION_BUS_ADDRESS override and rerun `pqkey setup`",
            ));
        }
        Ok(())
    }
}

fn start_service(state_dir: &Path, binary: &Path) -> io::Result<Running> {
    let before = daemon::running(state_dir)?;
    if let Some(Running::Daemon(pid)) = before
        && !super::daemon_args_of(state_dir, pid)?.are_defaults()
    {
        return Err(io::Error::other(
            "the running key has custom options; configure them in the user service before running setup (see `systemctl --user edit pqkey`)",
        ));
    }
    let changed = UserService::install(binary)?;
    UserService::action(ServiceAction::Enable)?;
    UserService::action(ServiceAction::ResetFailed)?;
    let session_changed = UserService::prepare_session()?;
    let running = match daemon::running(state_dir)? {
        Some(Running::Daemon(_)) => {
            daemon::unplug(state_dir)?;
            None
        }
        running => running,
    };
    let (running, how) = match running {
        Some(Running::Service(pid))
            if changed || session_changed || runs_another_binary(state_dir, pid, binary) =>
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
    output::problems(&problems)?;
    // Keep the final PIN interaction even when a separate repair is needed.
    host.pin(running, interactive)?;
    if !problems.is_empty() {
        return Err(io::Error::other(
            "setup is incomplete; fix the above, then rerun `pqkey setup`",
        ));
    }
    host.verify(state, binary, running)?;
    finish()
}

/// Only reached after every readiness check has passed.
fn finish() -> io::Result<()> {
    outln!()?;
    outln!(
        "pqkey is ready. Use it on sites supporting passkeys or security keys; approve requests with the configured presence provider."
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
        fn start(&mut self, _: &Path, _: &Path) -> io::Result<Running> {
            self.effect("service")?;
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
        for scenario in [
            "fresh",
            "configured",
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
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);
            let ready = ["fresh", "configured"].contains(&scenario);
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
}
