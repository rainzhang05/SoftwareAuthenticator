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

/// `pqkey setup`; `yes` runs the steps that need root without asking.
pub fn setup(state_dir: &Path, yes: bool) -> io::Result<()> {
    System::check_setup_caller(state_dir)?;
    let binary = env::current_exe()?.canonicalize()?;
    if binary.components().any(|part| part.as_os_str() == "target") {
        output::problem(
            format!(
                "{} is in a build directory, which `cargo clean` empties",
                binary.display()
            ),
            "install pqkey with ./install.sh, which runs setup itself",
        )?;
    }
    let mut system = System::real()?;

    let interactive = io::stdin().is_terminal();
    if let Some(root) = system.setup_steps()? {
        if !yes {
            outln!("{}", root.heading)?;
            for step in &root.summary {
                outln!("  - {step}")?;
            }
            if !interactive || !key::ask(root.question, true)? {
                for line in &root.instructions {
                    outln!("{line}")?;
                }
                return Ok(());
            }
        }
        system.apply_setup_steps(&root)?;
        for step in &root.summary {
            output::done(step)?;
        }
    }
    // The script may have added this user to the device's access group.
    system.refresh()?;
    if let Some(problem) = system.login_problem()? {
        UserService::install(&binary)?;
        UserService::action(ServiceAction::Enable)?;
        return output::problem(problem.what, problem.fix);
    }
    let problems = system.start_problems()?;
    if !problems.is_empty() {
        output::problems(&problems)?;
        outln!()?;
        outln!("The key cannot start yet: fix the above, then run `pqkey setup` again.")?;
        return Ok(());
    }

    let changed = UserService::install(&binary)?;
    UserService::action(ServiceAction::Enable)?;
    // A unit that failed to start too often refuses to start until this.
    let _ = UserService::action(ServiceAction::ResetFailed);
    let running = match daemon::running(state_dir)? {
        // The service runs it from now on.
        Some(Running::Daemon(_)) => {
            daemon::unplug(state_dir)?;
            None
        }
        running => running,
    };
    let (running, how) = match running {
        // A new unit, or a new binary in place of the one the service runs.
        Some(Running::Service(pid)) if changed || runs_another_binary(state_dir, pid, &binary) => {
            (daemon::replug(state_dir)?, "restarted")
        }
        Some(running) => (running, "running"),
        None => (
            daemon::plug_in(state_dir, &crate::cli::DaemonArgs::default())?,
            "started",
        ),
    };
    output::done(format_args!("Key {how}; it starts with your session"))?;

    let mut problems = key::running_problems(state_dir, &system, running, Duration::from_secs(5))?;
    problems.extend(path_problem(&binary, env::var_os("PATH").as_deref()));
    output::problems(&problems)?;
    let has_pin = match key::ensure_pin(running, interactive) {
        Ok(has_pin) => has_pin,
        Err(err) => {
            output::problem(format!("the PIN is not set: {err}"), "run `pqkey pin`")?;
            false
        }
    };
    finish(problems.is_empty() && has_pin)
}

/// The last words of setup: whether the key is ready, and the commands to
/// use it with.
fn finish(ready: bool) -> io::Result<()> {
    outln!()?;
    if ready {
        outln!(
            "pqkey is ready. Use it on any site that supports passkeys or security keys, and \
             approve the desktop notification that appears."
        )?;
    } else {
        outln!("pqkey is almost ready: fix what is marked with ! above.")?;
    }
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
            fix: "add it in your shell's profile, or log in again if your profile adds it".into(),
        }),
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// `pqkey setup --uninstall`.
pub fn uninstall(state_dir: &Path) -> io::Result<()> {
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
        crate::cli::daemon_info::DaemonInfo::current(&crate::cli::DaemonArgs::default())
            .unwrap()
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
