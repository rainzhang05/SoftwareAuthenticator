"""Observable install.sh regression tests. Never run directly on the host."""
import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest

SOURCE = Path(__file__).resolve().parents[2]
INSTALLED = Path("/usr/local/bin/pqkey")
RECOVERY = Path(str(INSTALLED) + ".previous")
GIT = shutil.which("git")
GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
               GIT_COMMITTER_NAME="fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
WARNING = "Warning: this commit is not on the stable branch, so it has not passed CI yet."
NOTE = "Note: without a stable branch, this clone cannot tell whether this commit passed CI."
HINT = "git fetch origin && git switch stable && ./install.sh"
UPDATE = ["rustup", "toolchain", "install", "stable", "--profile", "minimal", "--no-self-update"]
BUILD = ["cargo", "+stable", "build", "--release", "--locked", "-p", "pqkey", "--target-dir", "target"]
# sudo forgetting its cached password, checking that it has, and asking for it.
FORGET, CHECK = ["sudo", "-k"], ["sudo", "-n", "-v"]
ASK_FOR_TOOLS = ["sudo", "-v", "-p", "Password for sudo (%p), to install what building needs: "]
ASK_FOR_PQKEY = ["sudo", "-v", "-p", "Password for sudo (%p), to install pqkey: "]
TOOLS_PROMPT = "Password for sudo (tester), to install what building needs:"
PQKEY_PROMPT = "Password for sudo (tester), to install pqkey:"


def running(pid):
    """Whether process PID still runs: a zombie only while threads of its process do."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X") or len(os.listdir(f"/proc/{pid}/task")) > 1
    except (OSError, IndexError):
        return False


class Installer(unittest.TestCase):
    def setUp(self):
        if not Path("/pqkey-installer-fixture").exists() or not Path("/.dockerenv").exists():
            self.fail("Use scripts/install-tests.sh: these tests require their disposable container")
        self.temp = tempfile.TemporaryDirectory(prefix="pqkey-installer-")
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.clone = self.root / "clone"
        self.clone.mkdir()
        shutil.copyfile(SOURCE / "install.sh", self.clone / "install.sh")
        (self.clone / "Cargo.toml").write_text('[workspace.package]\nrust-version = "1.89"\n')
        self.home = self.root / "home"
        self.home.mkdir()
        (self.home / "pin-set").write_text("configured")
        self.state = self.home / ".local/share/pqkey"
        self.state.mkdir(parents=True)
        for file in ("credentials", "pin", "policy"):
            (self.state / file).write_bytes(f"preserved {file}".encode())
        self.env = dict(os.environ, HOME=str(self.home), CARGO_HOME=str(self.home / "cargo"),
                        PATH=f"{self.bin}:/usr/local/bin", COMMAND_TRACE=str(self.root / "trace"),
                        FIXTURE_BIN=str(self.bin), PQKEY_TEMPLATE=str(SOURCE / "tests/installer/pqkey.py"),
                        SUDO_TICKET=str(self.root / "sudo-ticket"), INSTALLER_SID=str(os.getsid(0)),
                        NO_COLOR="1")
        # Expose only the prerequisites this case chooses; host tools cannot
        # accidentally satisfy a missing prerequisite or run a package manager.
        for name in ("bash", "sh", "dirname", "mkdir", "tail", "tr", "grep", "sed", "wc",
                     "awk", "sort", "head", "cut", "sleep", "tee", "ln", "setsid"):
            (self.bin / name).symlink_to(shutil.which(name))
        for name in ("uname", "id", "df", "sudo", "cc", "curl", "setfacl", "cargo", "rustc",
                     "rustup", "apt-get", "install", "mv", "cp", "rm", "cargo-source", "rustup-source",
                     "rustc-source"):
            (self.bin / name).symlink_to(SOURCE / "tests/installer/command.py")
        self.env["PATH"] += ":" + str(self.home / "cargo/bin")
        for path in (INSTALLED, RECOVERY):
            path.unlink(missing_ok=True)

    def tearDown(self):
        for path in (INSTALLED, RECOVERY):
            path.unlink(missing_ok=True)
        self.temp.cleanup()

    def commands(self):
        path = self.root / "trace"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def sudo_and_build(self):
        return [command for command in self.commands() if command[0] in ("sudo", "cargo")]

    def planted_here(self):
        """Commands planted in your directories (command.py's plant) that ran in the
        installer's own session, where only install.sh's commands run."""
        return [command for command in self.commands()
                if command[0] == "planted" and command[-1] == "installer session"]

    def functions_run(self):
        """Records of functions from the environment, BASH_ENV or rustup's env file."""
        return [command for command in self.commands() if "function" in command[0] or "trap" in command[0]]

    def installers(self):
        """Processes running this case's install.sh: the script, or a subshell of it."""
        script = str(self.clone / "install.sh").encode()
        running = []
        for process in Path("/proc").iterdir():
            with contextlib.suppress(OSError):
                if process.name.isdigit() and script in (process / "cmdline").read_bytes().split(b"\0"):
                    running.append(int(process.name))
        return running

    def outliving(self, seconds=5):
        """What still runs install.sh after up to SECONDS."""
        deadline = time.monotonic() + seconds
        while (running := self.installers()) and time.monotonic() < deadline:
            time.sleep(0.05)
        return running

    def run_on_terminal(self, command):
        """Run COMMAND with a new pty as its controlling terminal, as a terminal would."""
        pid, fd = pty.fork()
        if pid == 0:
            os.execve(command[0], command, self.env)
        output, deadline = b"", time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(fd, 8192)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
            else:
                os.kill(pid, signal.SIGKILL)
        finally:
            os.close(fd)
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), output.decode(errors="replace")

    def build_processes(self, seconds=5):
        """The processes the fake build listed (BUILD_PIDS) still running after up to SECONDS."""
        path, deadline = self.root / "build-pids", time.monotonic() + seconds
        while True:
            alive = [pid for pid in (path.read_text().split() if path.exists() else []) if running(pid)]
            if not alive or time.monotonic() >= deadline:
                return alive
            time.sleep(0.05)

    def run_install(self, args=("--yes",), interactive=False, responses=(), shell="/bin/bash", terminal=True,
                    argv=None):
        """install.sh, its input none (or, interactive, a pty that is its terminal too).
        Like the tests, it has the pty of __main__ as its terminal, unless not terminal:
        then it runs in a session of its own, which has none."""
        command = argv or [shell, str(self.clone / "install.sh"), *args]
        if not interactive:
            result = subprocess.run(command, env=self.env, input=b"", stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=20, start_new_session=not terminal)
            return result.returncode, result.stdout.decode()
        master, slave = pty.openpty()
        process = subprocess.Popen(command, env=self.env, stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True,
                                   preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        output = b""
        remaining = list(responses)
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(master, 8192)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output += chunk
                    if remaining and remaining[0][0].encode() in output:
                        _, answer = remaining.pop(0)
                        os.write(master, (answer + "\n").encode())
                elif process.poll() is not None:
                    break
            if process.poll() is None:
                process.kill()
            status = process.wait(timeout=3)
            self.assertFalse(remaining, output.decode(errors="replace"))
            return status, output.decode(errors="replace")
        finally:
            os.close(master)

    def assert_preserved(self):
        for file in ("credentials", "pin", "policy"):
            self.assertEqual((self.state / file).read_bytes(), f"preserved {file}".encode())

    def git(self, *args, cwd=None):
        self.assertIsNotNone(GIT, "the installer's stable checks need git in the test image")
        subprocess.run([GIT, *args], cwd=cwd or self.clone, env=GIT_ENV, check=True, capture_output=True)

    def make_origin(self):
        # The fixture becomes the repository users clone: main has two commits,
        # and the installer finds git.
        origin = self.root / "origin"
        self.clone.rename(origin)
        (origin / "install.sh").chmod(0o755)
        for args in (("init", "-q", "-b", "main"), ("add", "-A"), ("commit", "-q", "-m", "one"),
                     ("commit", "-q", "--allow-empty", "-m", "two")):
            self.git(*args, cwd=origin)
        (self.bin / "git").symlink_to(GIT)
        return origin

    def run_hint(self):
        # What the warning and the note tell the user to run, unattended. Its
        # output includes git's own messages, which name stable.
        result = subprocess.run(["/bin/bash", "-c", HINT + " --yes"], cwd=self.clone, env=self.env, input=b"",
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        return result.returncode, result.stdout.decode()

    def test_configured_install_and_rerun_preserve_state(self):
        for _ in range(2):
            status, output = self.run_install()
            self.assertEqual(status, 0, output)
            self.assertIn("pqkey is ready.", output)
            self.assertIn(["pqkey", "setup", "--yes"], self.commands())
            self.assert_preserved()
            self.assertFalse(RECOVERY.exists())
        self.assertIn("pqkey is ready.", (self.home / ".cache/pqkey/install.log").read_text())

    def test_fresh_interactive_install_keeps_pin_prompt_visible_and_private(self):
        (self.home / "pin-set").unlink()
        status, output = self.run_install(args=(), interactive=True,
                                         responses=(("Continue?", "y"), ("New PIN:", "secret123"),
                                                    ("Confirm new PIN:", "secret123")))
        self.assertEqual(status, 0, output)
        self.assertIn("pqkey is ready.", output)
        self.assertNotIn("secret123", output)
        self.assertNotIn("secret123", (self.home / ".cache/pqkey/install.log").read_text())
        self.assertTrue((self.home / "pin-set").exists())

    def test_yes_does_not_supply_a_noninteractive_pin(self):
        (self.home / "pin-set").unlink()
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("pqkey pin", output)
        self.assertNotIn("pqkey is ready.", output)
        self.assertTrue(INSTALLED.exists())

    def test_cancel_is_a_clean_noop(self):
        status, output = self.run_install(args=(), interactive=True, responses=(("Continue?", "n"),))
        self.assertEqual(status, 0, output)
        self.assertFalse(INSTALLED.exists())
        self.assertFalse((self.home / ".cache").exists())
        self.assertFalse(any(command[0] == "sudo" for command in self.commands()))
        self.assert_preserved()

    def test_noninteractive_approval_is_required(self):
        status, output = self.run_install(args=())
        self.assertNotEqual(status, 0, output)
        self.assertIn("--yes", output)
        self.assertFalse(INSTALLED.exists())
        self.assertFalse((self.home / ".cache").exists())

    def test_package_update_failure_cannot_be_masked_by_install(self):
        (self.bin / "cc").unlink()
        self.env["FAIL_COMMAND"] = "apt-get update"
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("apt-get update failed", output)
        self.assertFalse(any(command[:2] == ["apt-get", "install"] for command in self.commands()))
        self.assertFalse(INSTALLED.exists())

    def test_missing_prerequisites_and_package_manager(self):
        for name in ("cc", "setfacl", "apt-get"):
            (self.bin / name).unlink()
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("install the missing", output)
        self.assertFalse(INSTALLED.exists())

    def test_installs_acl_with_each_supported_package_manager(self):
        for manager in ("apt-get", "dnf", "pacman", "zypper"):
            with self.subTest(manager=manager):
                (self.bin / "setfacl").unlink(missing_ok=True)
                (self.bin / "apt-get").unlink(missing_ok=True)
                for candidate in ("dnf", "pacman", "zypper"):
                    (self.bin / candidate).unlink(missing_ok=True)
                (self.bin / manager).symlink_to(SOURCE / "tests/installer/command.py")
                status, output = self.run_install()
                self.assertEqual(status, 0, output)
                self.assertTrue(any(command[0] == manager and "acl" in command for command in self.commands()))

    def test_rustup_failure_does_not_attempt_build(self):
        self.env.update(TOOLCHAINS="", FAIL_COMMAND="rustup toolchain install stable --profile minimal")
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertFalse(any(command[0] == "cargo" for command in self.commands()))

    def test_custom_cargo_home_without_env_file(self):
        cargo_bin = Path(self.env["CARGO_HOME"]) / "bin"
        cargo_bin.mkdir(parents=True)
        (cargo_bin / "cargo").symlink_to(self.bin / "cargo")
        (self.bin / "cargo").rename(self.bin / "cargo-source")
        (cargo_bin / "cargo").unlink()
        (cargo_bin / "cargo").symlink_to(self.bin / "cargo-source")
        self.env["PATH"] = f"{self.bin}:/usr/local/bin"
        status, output = self.run_install()
        self.assertEqual(status, 0, output)

    def test_rust_installation_and_download_failure(self):
        for name in ("cargo", "rustup"):
            (self.bin / name).unlink()
        self.env["FAIL_COMMAND"] = "curl"
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("fixture: curl --proto", output)
        self.assertFalse(INSTALLED.exists())
        del self.env["FAIL_COMMAND"]
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertTrue((Path(self.env["CARGO_HOME"]) / "bin/cargo").exists())

    def test_missing_sudo_fails_before_build(self):
        (self.bin / "sudo").unlink()
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("needs sudo", output)
        self.assertFalse(any(command[0] == "cargo" for command in self.commands()))

    def test_with_nothing_to_install_sudo_asks_once_after_the_build(self):
        # A password sudo cached before, as by sudo earlier in this terminal, is
        # forgotten before the build: the fake build fails if one is cached.
        Path(self.env["SUDO_TICKET"]).touch()
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn("It needs your password for sudo once, after building pqkey.", output)
        self.assertEqual(self.sudo_and_build()[:4], [FORGET, CHECK, BUILD, ASK_FOR_PQKEY])
        self.assertEqual(output.count("Password for sudo"), 1, output)
        order = ["✓ pqkey built", PQKEY_PROMPT, "✓ pqkey installed"]
        self.assertEqual(sorted(order, key=output.index), order, output)

    def test_sudo_asks_for_the_build_tools_and_again_after_the_build(self):
        (self.bin / "setfacl").unlink()
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn("It needs your password for sudo twice: to install what building needs, "
                      "and after building pqkey.", output)
        self.assertEqual(self.sudo_and_build()[:7],
                         [ASK_FOR_TOOLS, ["sudo", "-n", "apt-get", "update"],
                          ["sudo", "-n", "apt-get", "install", "-y", "acl"], FORGET, CHECK, BUILD, ASK_FOR_PQKEY])
        self.assertEqual(output.count("Password for sudo"), 2, output)
        order = [TOOLS_PROMPT, "✓ Build tools installed", "✓ pqkey built", PQKEY_PROMPT, "✓ pqkey installed"]
        self.assertEqual(sorted(order, key=output.index), order, output)

    def test_a_password_sudo_k_leaves_cached_is_forgotten_with_sudo_K(self):
        # As with sudo 1.9.17 and earlier and timestamp_type=kernel on Linux: -k
        # clears another record than the one sudo checks.
        self.env["SUDO_K_MISSES_TICKET"] = "1"
        for missing in (False, True):
            with self.subTest(missing=missing):
                (self.root / "trace").unlink(missing_ok=True)
                Path(self.env["SUDO_TICKET"]).touch()
                if missing:
                    (self.bin / "setfacl").unlink()
                status, output = self.run_install()
                self.assertEqual(status, 0, output)
                commands = self.sudo_and_build()
                start = commands.index(FORGET)
                self.assertEqual(commands[start:start + 5], [FORGET, CHECK, ["sudo", "-K"], BUILD, ASK_FOR_PQKEY])

    def test_sudo_is_kept_fresh_only_after_the_build_and_while_the_installer_runs(self):
        # The keeper's minute lasts under a second here; the build takes two, setup three.
        sleep = self.bin / "sleep"
        real = sleep.resolve()
        sleep.unlink()
        sleep.write_text(f"#!/bin/sh\nexec {real} 0.01\n")
        sleep.chmod(0o755)
        self.env.update(BUILD_SECONDS="2", SETUP_SECONDS="3")
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        commands = self.sudo_and_build()
        asked = commands.index(ASK_FOR_PQKEY)
        forgot = len(commands) - 1 - commands[::-1].index(FORGET)  # as the installer ends
        # Nothing ran sudo while cargo ran, and the keeper refreshed during setup.
        self.assertEqual(commands[asked - 1], BUILD)
        self.assertIn(CHECK, commands[asked:forgot])
        self.assertEqual(self.outliving(), [])

    def test_sudo_keeper_ends_when_the_installer_is_killed(self):
        # Killed, the installer runs no cleanup; its keeper stops within a second.
        self.env["SETUP_SECONDS"] = "60"
        with open(self.root / "output", "wb") as output:
            process = subprocess.Popen(["/bin/bash", str(self.clone / "install.sh"), "--yes"], env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                       process_group=0)
        try:
            deadline = time.monotonic() + 15
            while (["pqkey", "setup", "--yes"] not in self.commands() or len(self.installers()) < 2) \
                    and time.monotonic() < deadline:
                time.sleep(0.05)
            running = self.installers()
            self.assertIn(process.pid, running, (self.root / "output").read_text())
            self.assertGreater(len(running), 1, "no keeper while setup runs")
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            self.assertEqual(self.outliving(), [])
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)

    def assert_nothing_left_running(self, status, output):
        self.assertEqual(status, 0, output)
        self.assertEqual(len((self.root / "build-pids").read_text().split()), 2, output)
        commands = self.commands()
        self.assertIn(ASK_FOR_PQKEY, commands)
        self.assertNotIn(["left running", "when sudo asked"], commands)
        self.assertNotIn(["left running", "found a password cached"], commands)
        self.assertEqual(self.build_processes(), [])

    def test_what_the_build_leaves_running_is_gone_before_sudo_asks(self):
        # It leaves the build's process group, ignores INT, TERM and HUP, and waits
        # for sudo to cache a password, as is or with a name holding a newline, its
        # main thread gone, a new PID every fork, or a chain of processes that each
        # fork the next; the build's session is emptied first.
        self.env["BUILD_PIDS"] = str(self.root / "build-pids")
        for shape in ("plain", "newline", "thread", "hop", "chain"):
            with self.subTest(shape=shape):
                for path in (self.root / "trace", self.root / "build-pids"):
                    path.unlink(missing_ok=True)
                self.env["LEAVE_BEHIND"] = shape
                self.assert_nothing_left_running(*self.run_install())

    def test_job_control_leaves_the_build_within_reach(self):
        # bash -i, bash -p -i, monitor in SHELLOPTS and set -m in BASH_ENV each turn
        # job control on, which makes setsid fork and the session ID differ from $!.
        # install.sh starts again, once, in a shell without it, and set +m keeps it so.
        self.env.update(LEAVE_BEHIND="plain", BUILD_PIDS=str(self.root / "build-pids"))
        (self.root / "bash-env").write_text("set -m\n")
        script = str(self.clone / "install.sh")
        for trigger, extra, run in (
                ("bash -i", {}, lambda: self.run_on_terminal(["/bin/bash", "-i", script, "--yes"])),
                ("bash -p -i", {}, lambda: self.run_on_terminal(["/bin/bash", "-p", "-i", script, "--yes"])),
                ("SHELLOPTS", {"SHELLOPTS": "braceexpand:hashall:interactive-comments:monitor"},
                 lambda: self.run_on_terminal(["/bin/bash", script, "--yes"])),
                ("BASH_ENV", {"BASH_ENV": str(self.root / "bash-env")}, self.run_install)):
            with self.subTest(trigger=trigger):
                for path in (self.root / "trace", self.root / "build-pids"):
                    path.unlink(missing_ok=True)
                saved = dict(self.env)
                self.env.update(extra)
                try:
                    self.assert_nothing_left_running(*run())
                finally:
                    self.env = saved

    def test_a_session_it_cannot_establish_stops_the_install_before_sudo_asks(self):
        # A setsid that forks leaves the session ID unknown: the session's own shell
        # sees it and stops before the build starts, saying why.
        (self.bin / "setsid").unlink()
        (self.bin / "setsid").write_text(f"#!/bin/sh\nexec {shutil.which('setsid')} --fork \"$@\"\n")
        (self.bin / "setsid").chmod(0o755)
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("cannot run cargo in a session of its own, so sudo is not asked for your password", output)
        self.assertNotIn(BUILD, self.commands())
        self.assertNotIn(ASK_FOR_PQKEY, self.commands())

    def test_a_setsid_that_makes_no_session_stops_the_install_before_sudo_asks(self):
        # A setsid that runs the command in place leaves it in this session, whose ID
        # is not the session shell's own: that shell sees it and stops before the
        # build starts, saying why.
        (self.bin / "setsid").unlink()
        (self.bin / "setsid").write_text('#!/bin/sh\n[ "$1" != --wait ] || shift\nexec "$@"\n')
        (self.bin / "setsid").chmod(0o755)
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("cannot run cargo in a session of its own, so sudo is not asked for your password", output)
        self.assertNotIn(BUILD, self.commands())
        self.assertNotIn(ASK_FOR_PQKEY, self.commands())

    def test_a_password_sudo_cannot_forget_stops_the_install_before_rust_and_the_build(self):
        # sudo -k failing, or -K when -k left the password cached: install.sh stops,
        # and nothing that is not root's runs.
        (self.bin / "setfacl").unlink()
        for name in ("cargo", "rustup"):
            (self.bin / name).unlink()
        self.env["SUDO_K_MISSES_TICKET"] = "1"
        for command, message in (("sudo -k", "cannot make sudo forget a cached password (sudo -k failed)"),
                                 ("sudo -K", "cannot make sudo forget cached passwords (sudo -K failed)")):
            with self.subTest(command=command):
                (self.root / "trace").unlink(missing_ok=True)
                self.env["FAIL_COMMAND"] = command
                status, output = self.run_install()
                self.assertNotEqual(status, 0, output)
                self.assertIn(message, output)
                self.assertFalse(any(entry[0] in ("curl", "rustup", "rustc", "cargo")
                                     for entry in self.commands()), self.commands())

    def test_the_rust_installer_runs_after_sudo_forgets_in_a_session_of_its_own(self):
        # Build tools missing: sudo has a password cached before them. The fake Rust
        # installer fails if it still is, or if it shares the installer's session.
        for name in ("setfacl", "cargo", "rustup"):
            (self.bin / name).unlink()
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        commands = self.commands()
        rust = next(command for command in commands if command[0] == "curl")
        order = [ASK_FOR_TOOLS, FORGET, rust, BUILD, ASK_FOR_PQKEY]
        self.assertEqual(sorted(order, key=commands.index), order)

    def test_the_rust_update_runs_after_sudo_forgets_in_a_session_of_its_own(self):
        (self.bin / "setfacl").unlink()
        self.env["RUST_VERSION"] = "1.88.0"
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        commands = self.commands()
        order = [ASK_FOR_TOOLS, FORGET, UPDATE, BUILD, ASK_FOR_PQKEY]
        self.assertEqual(sorted(order, key=commands.index), order)

    def nosuid_directory(self):
        """A directory of root's on a mount that is nosuid, as every mount a user can
        make is, but not noexec, so that its commands could run: Docker's /dev."""
        mounts = {fields[4]: fields[5].split(",") for fields in
                  (line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines())}
        self.assertIn("nosuid", mounts.get("/dev", []), "the fixture needs /dev mounted nosuid")
        self.assertNotIn("noexec", mounts["/dev"])
        directory = Path(tempfile.mkdtemp(prefix="pqkey-installer-", dir="/dev"))
        directory.chmod(0o755)
        self.addCleanup(shutil.rmtree, directory)
        return directory

    def fake_fuse(self, directory):
        """Have stat -f say that DIRECTORY is on FUSE, when asked as install.sh asks:
        the system's stat, which command -p finds, is replaced for this case."""
        stat = Path("/usr/bin/stat")
        real = stat.with_name("stat.fixture-real")
        stat.rename(real)
        self.addCleanup(real.rename, stat)
        stat.write_text(f"""#!/usr/bin/python3
import os, subprocess, sys
args = sys.argv[1:]
if args[:3] != ["-fc", "%t", "--"]:
    os.execv("{real}", ["stat", *args])
for path in args[3:]:
    if path == "{directory}" or path.startswith("{directory}/"):
        print("65735546", flush=True)  # FUSE_SUPER_MAGIC
    elif subprocess.call(["{real}", "-fc", "%t", "--", path]):
        sys.exit(1)
""")
        stat.chmod(0o755)

    def test_commands_the_build_plants_in_your_directories_are_not_run(self):
        # The build plants commands of install.sh's names in directories ahead of the
        # system's on PATH that you, and so the build, can change: ~/.local/bin and
        # ~/.cargo/bin, which you own; one of root's in one of yours; one your group
        # can write; a sticky one anyone can write; one on a nosuid mount, as every
        # mount you can make is; and one on FUSE, whose daemon says who owns what.
        # install.sh runs none of them: it finds commands only in the others.
        local, cargo, tools = self.home / ".local/bin", Path(self.env["CARGO_HOME"]) / "bin", self.home / "tools"
        for directory in (local, cargo, tools):
            directory.mkdir(parents=True)
            os.chown(directory, 1000, 1000)
        in_yours, group, sticky, fuse = tools / "bin", self.root / "group", self.root / "sticky", self.root / "fuse"
        for directory, mode in ((in_yours, 0o755), (group, 0o775), (sticky, 0o1777), (fuse, 0o755)):
            directory.mkdir()
            directory.chmod(mode)
        self.fake_fuse(fuse)
        directories = [local, cargo, in_yours, group, sticky, self.nosuid_directory(), fuse]
        self.env.update(PATH=":".join(map(str, [*directories, self.env["PATH"]])),
                        PLANT=":".join(map(str, directories)))
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        for directory in directories:
            self.assertTrue((directory / "tee").exists(), directory)
        self.assertIn(ASK_FOR_PQKEY, self.commands())
        self.assertEqual(self.planted_here(), [])

    def test_rust_in_your_directories_and_what_it_leaves_there(self):
        # Rust only in ~/.cargo/bin, which you own, with rustup's env file and commands
        # of install.sh's names beside it, which functions in the env file shadow too,
        # and those commands in ~/.local/bin, first on PATH: left by an earlier
        # install, or by this one's Rust installer. install.sh finds Rust there, gives
        # Rust and the build your PATH, and runs none of the rest itself.
        cargo, local = Path(self.env["CARGO_HOME"]) / "bin", self.home / ".local/bin"
        for name in ("cargo", "rustup", "rustc"):
            (self.bin / name).unlink()
        self.env.update(PATH=f"{local}:{self.env['PATH']}", RUST_INSTALLER_PLANTS=f"{cargo}:{local}")
        for case, version in (("Rust installer", "1.89.0"), ("earlier install", "1.88.0")):
            with self.subTest(case=case):
                shutil.rmtree(cargo.parent, ignore_errors=True)
                shutil.rmtree(local, ignore_errors=True)
                local.mkdir(parents=True)
                os.chown(local, 1000, 1000)
                self.env["RUST_VERSION"] = version  # 1.88.0: an update too, run alone
                if case == "earlier install":
                    # The fake Rust installer, run before install.sh, outside its session.
                    Path(self.env["SUDO_TICKET"]).unlink(missing_ok=True)
                    env = {name: value for name, value in self.env.items() if name != "INSTALLER_SID"}
                    script = subprocess.run([str(self.bin / "curl")], env=env, check=True,
                                            stdout=subprocess.PIPE).stdout
                    subprocess.run(["/bin/sh"], input=script, env=env, check=True)
                (self.root / "trace").unlink(missing_ok=True)
                status, output = self.run_install()
                self.assertEqual(status, 0, output)
                commands = self.commands()
                self.assertIn(BUILD, commands)
                self.assertIn(UPDATE if case == "earlier install" else ["curl", "--proto", "=https", "--tlsv1.2",
                                                                       "-sSf", "https://sh.rustup.rs"], commands)
                self.assertTrue((cargo / "tee").exists() and (cargo.parent / "env").exists())
                self.assertEqual(self.functions_run(), [])
                self.assertEqual(self.planted_here(), [])

    def test_functions_and_bash_env_from_your_environment_never_run(self):
        # Exported functions, and a BASH_ENV file's functions and DEBUG trap, of the
        # names install.sh runs: none of them runs once install.sh starts again in a
        # clean shell, nor in the shell of the build's session.
        names = ("sudo", "sleep", "tee", "setsid", "kill", "dirname", "tail", "wc", "readstat", "end_session")
        bash_env = self.root / "bash-env"
        bash_env.write_text("".join(f"{name}() {{ printf '[\"BASH_ENV function\", \"{name}\"]\\n' "
                                    f">>\"$COMMAND_TRACE\"; command {name} \"$@\"; }}\n" for name in names) +
                            "trap 'grep -q \"\\\"build\\\"\" \"$COMMAND_TRACE\" 2>/dev/null && "
                            "printf \"[\\\"BASH_ENV trap\\\"]\\\\n\" >>\"$COMMAND_TRACE\"' DEBUG\n")
        for name in names:
            self.env[f"BASH_FUNC_{name}%%"] = (f"() {{ printf '[\"environment function\", \"{name}\"]\\n' "
                                               f">>\"$COMMAND_TRACE\"; command {name} \"$@\"; }}")
        self.env.update(BASH_ENV=str(bash_env), LEAVE_BEHIND="plain", BUILD_PIDS=str(self.root / "build-pids"))
        self.assert_nothing_left_running(*self.run_install())
        self.assertEqual(self.functions_run(), [])

    def test_what_the_build_writes_into_install_sh_is_not_run(self):
        # The build overwrites install.sh in place, from the command after the build
        # on, which bash would read next if it read the script as it ran it. Having
        # read all of itself first, install.sh asks for the password and installs.
        self.env["REWRITE_INSTALLER"] = "1"
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn(b"installer rewritten", (self.clone / "install.sh").read_bytes())
        self.assertNotIn(["installer rewritten"], self.commands())
        self.assertIn(ASK_FOR_PQKEY, self.commands())
        self.assertIn("pqkey is ready.", output)

    def test_a_bash_of_yours_hands_over_to_the_systems(self):
        # Started by a bash in a directory of yours, first on PATH, where
        # #!/usr/bin/env bash finds it: install.sh starts again in the system's bash,
        # which runs it from then on.
        local, system = self.home / ".local/bin", os.path.realpath(shutil.which("bash"))
        local.mkdir(parents=True)
        shutil.copy2(system, local / "bash")
        for path in (local, local / "bash"):
            os.chown(path, 1000, 1000)
        self.env["PATH"] = f"{local}:{self.env['PATH']}"
        status, output = self.run_install(shell=str(local / "bash"))
        self.assertEqual(status, 0, output)
        self.assertEqual([command[1] for command in self.commands() if command[0] == "installer shell"], [system])

    def forgetting(self, seconds=15):
        """Wait until the installer has sudo forget as it ends: a second sudo -k, after
        the one before the build."""
        deadline = time.monotonic() + seconds
        while self.commands().count(FORGET) < 2 and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertEqual(self.commands().count(FORGET), 2, self.sudo_and_build())

    def test_sudo_forgets_the_password_when_the_installer_ends(self):
        # However install.sh ends, unless a signal kills it first (kill -9): done,
        # failing after the password was given, or stopped by Ctrl-C, kill or a closed
        # terminal while setup runs (signals to its process group, as a terminal sends
        # them: a closed one sends HUP twice, the second here as the installer has sudo
        # forget), also with its output going to a pipe no one reads any more
        # (./install.sh | tee log, tee gone); and done, with every signal that would end
        # or pause it and that it can ignore sent to it as it has sudo forget. -k forgets
        # it, or, when -k misses as with timestamp_type=kernel, -K; the exit status
        # stays install.sh's.
        anything = sorted(signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD, signal.SIGCONT,
                                                    signal.SIGURG, signal.SIGWINCH})
        for ending, number, expected in (("done", None, 0), ("failed", None, 1), ("INT", signal.SIGINT, 130),
                                         ("TERM", signal.SIGTERM, 143), ("HUP twice", signal.SIGHUP, 129),
                                         ("INT, output unread", signal.SIGINT, 130), ("any signal", None, 0)):
            for kernel in (False, True):
                with self.subTest(ending=ending, kernel=kernel):
                    (self.root / "trace").unlink(missing_ok=True)
                    self.env.pop("SUDO_K_MISSES_TICKET", None)
                    if kernel:
                        self.env["SUDO_K_MISSES_TICKET"] = "1"
                    self.env.pop("FAIL_SETUP", None)
                    if ending == "failed":
                        self.env["FAIL_SETUP"] = "1"
                    self.env["SETUP_SECONDS"] = "60" if number else "0"
                    if ending in ("done", "failed"):
                        status, output = self.run_install()
                    else:
                        unread = ending == "INT, output unread"
                        process = subprocess.Popen(["/bin/bash", str(self.clone / "install.sh"), "--yes"],
                                                   env=self.env, stdin=subprocess.DEVNULL,
                                                   stdout=subprocess.PIPE if unread else subprocess.DEVNULL,
                                                   stderr=subprocess.STDOUT, process_group=0)
                        try:
                            if number:
                                deadline = time.monotonic() + 15
                                while ["pqkey", "setup", "--yes"] not in self.commands() and time.monotonic() < deadline:
                                    time.sleep(0.05)
                                if unread:
                                    process.stdout.close()
                                os.killpg(process.pid, number)
                                if ending == "HUP twice":
                                    self.forgetting()
                                    os.killpg(process.pid, signal.SIGHUP)
                            else:
                                self.forgetting()
                                for each in anything:
                                    os.kill(process.pid, each)
                            status, output = process.wait(timeout=15), ""
                        finally:
                            with contextlib.suppress(ProcessLookupError):
                                os.killpg(process.pid, signal.SIGCONT)
                                os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)
                    self.assertEqual(status, expected, output)
                    self.assertIn(ASK_FOR_PQKEY, self.commands())
                    self.assertFalse(Path(self.env["SUDO_TICKET"]).exists(), self.sudo_and_build())
                    ended = self.sudo_and_build()[-3 if kernel else -2:]
                    self.assertEqual(ended, [FORGET, CHECK, ["sudo", "-K"]] if kernel else [FORGET, CHECK])

    def test_a_failed_prompt_after_the_build_stops_the_install(self):
        # A wrong password, three times, or Ctrl-C at the prompt after the build: the
        # install stops there, saying so; nothing after the prompt runs (no keeper,
        # no install, no setup), and it has sudo forget as it ends.
        for answer, expected, message in (("wrong", 1, "install.sh: installing pqkey needs sudo"),
                                          ("Ctrl-C", 130, "Installation did not finish.")):
            with self.subTest(answer=answer):
                (self.root / "trace").unlink(missing_ok=True)
                self.env["SUDO_ANSWER"] = answer
                # In a process group of its own, which the fake sudo interrupts.
                process = subprocess.Popen(["/bin/bash", str(self.clone / "install.sh"), "--yes"], env=self.env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, process_group=0)
                output = process.communicate(timeout=20)[0].decode()
                self.assertEqual(process.returncode, expected, output)
                self.assertIn(message, output)
                commands = self.sudo_and_build()
                self.assertEqual(commands[commands.index(BUILD):], [BUILD, ASK_FOR_PQKEY, FORGET, CHECK])
                self.assertNotIn(["pqkey", "setup", "--yes"], self.commands())
                self.assertFalse(INSTALLED.exists())
                self.assertFalse(Path(self.env["SUDO_TICKET"]).exists())
                self.assertEqual(self.outliving(), [])

    def test_without_a_terminal_sudo_runs_no_helper_after_the_build(self):
        # No terminal, DISPLAY set and an askpass helper in your home, named by
        # SUDO_ASKPASS or by sudo.conf: sudo would run the helper, as you, to ask for
        # the password. After the build install.sh lets no sudo ask: it stops, saying
        # why, and the helper never runs.
        helper = self.home / "bin/askpass"
        helper.parent.mkdir()
        helper.write_text('#!/bin/sh\nprintf \'["askpass ran"]\\n\' >>"$COMMAND_TRACE"\necho fixture-password\n')
        helper.chmod(0o755)
        self.env["DISPLAY"] = ":0"
        for variable in ("SUDO_ASKPASS", "SUDO_CONF_ASKPASS"):
            with self.subTest(helper=variable):
                (self.root / "trace").unlink(missing_ok=True)
                self.env.pop("SUDO_ASKPASS", None)
                self.env.pop("SUDO_CONF_ASKPASS", None)
                self.env[variable] = str(helper)
                status, output = self.run_install(terminal=False)
                self.assertNotEqual(status, 0, output)
                self.assertIn("installing pqkey needs your password for sudo, and there is no terminal to ask on: "
                              "run ./install.sh in a terminal", output)
                commands = self.commands()
                self.assertIn(BUILD, commands)
                self.assertNotIn(["askpass ran"], commands)
                self.assertNotIn(ASK_FOR_PQKEY, commands)
                self.assertFalse(INSTALLED.exists())

    def test_without_a_terminal_the_install_goes_on_where_sudo_needs_no_password(self):
        # As on CI runners: a NOPASSWD rule, no terminal. install.sh checks with sudo
        # -n -v and goes on. With a terminal or without, nothing after the build sees
        # SUDO_ASKPASS: no sudo, and not pqkey setup.
        helper = self.home / "bin/askpass"
        helper.parent.mkdir()
        helper.write_text('#!/bin/sh\nprintf \'["askpass ran"]\\n\' >>"$COMMAND_TRACE"\necho fixture-password\n')
        helper.chmod(0o755)
        self.env.update(DISPLAY=":0", SUDO_ASKPASS=str(helper))
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                (self.root / "trace").unlink(missing_ok=True)
                self.env.pop("SUDO_NOPASSWD", None)
                if not terminal:
                    self.env["SUDO_NOPASSWD"] = "1"
                status, output = self.run_install(terminal=terminal)
                self.assertEqual(status, 0, output)
                self.assertIn("pqkey is ready.", output)
                commands = self.commands()
                # What runs after the build, which itself gets your environment.
                after = [command for command in commands[commands.index(BUILD) + 1:]
                         if command != ["askpass variable", " ".join(BUILD)]]
                self.assertEqual(next(command for command in after if command[0] == "sudo"),
                                 ASK_FOR_PQKEY if terminal else CHECK)
                self.assertNotIn(["askpass ran"], commands)
                self.assertEqual([command for command in after if command[0] == "askpass variable"], [])

    def test_a_shell_that_read_your_startup_files_is_left_before_the_build(self):
        # bash -p -i reads ~/.bashrc, and bash -p -l ~/.bash_profile, here a DEBUG trap
        # that sources ~/.hook, which the build rewrites. install.sh starts again, once,
        # in a shell that read neither, so the hook never runs.
        (self.home / ".hook").write_text(":\n")
        trap = "trap '. \"$HOME/.hook\"' DEBUG\n"
        (self.home / ".bashrc").write_text(trap)
        # A login shell's /etc/profile sets PATH; ~/.bash_profile puts the fixture's back.
        (self.home / ".bash_profile").write_text('PATH=$FIXTURE_PATH\n' + trap)
        self.env.update(REWRITE_HOOK="1", FIXTURE_PATH=self.env["PATH"])
        script = str(self.clone / "install.sh")
        for option in ("-i", "-l"):
            with self.subTest(option=option):
                (self.root / "trace").unlink(missing_ok=True)
                (self.home / ".hook").write_text(":\n")
                status, output = self.run_on_terminal(["/bin/bash", "-p", option, script, "--yes"])
                self.assertEqual(status, 0, output)
                self.assertIn("pqkey is ready.", output)
                self.assertIn("hook ran", (self.home / ".hook").read_text())
                self.assertNotIn(["hook ran"], self.commands())

    def test_a_shell_install_sh_did_not_start_clean_stops_it(self):
        # A shell that passes on PQKEY_INSTALL_PID as its own PID, as the restart does,
        # but is not the clean one: install.sh stops before anything else.
        script = str(self.clone / "install.sh")
        for shell, extra in (("/bin/bash", {}), ("/bin/bash -p -i", {}), ("/bin/bash -p -l", {}),
                             ("/bin/bash -p", {"LD_PRELOAD": "libc.so.6"})):
            with self.subTest(shell=shell, extra=extra):
                (self.root / "trace").unlink(missing_ok=True)
                saved = dict(self.env)
                self.env.update(extra)
                try:
                    status, output = self.run_install(argv=["/bin/sh", "-c", f'PQKEY_INSTALL_PID=$$ exec {shell} "$0" --yes',
                                                            script])
                finally:
                    self.env = saved
                self.assertNotEqual(status, 0, output)
                self.assertIn("cannot start again in a clean shell", output)
                # (A login shell's /etc/profile runs id itself.)
                self.assertEqual([command for command in self.commands() if command[0] != "id"], [])

    def test_a_nosuid_mount_is_found_whatever_its_name(self):
        # The kernel writes a mount point's space, tab, newline and backslash as \040,
        # \011, \012 and \134, so a name like "USB 2" reads USB\0402. Root's directories
        # on nosuid mounts named so are not trusted. install.sh's own trusted, reading
        # the fixture's mount table: this one, plus those mounts.
        names = ("USB 2", "Backup 2024", "Tab\t7", "back\\slash 0")
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
        directories = []
        for number, name in enumerate(names):
            mount = self.root / name
            (mount / "bin").mkdir(parents=True)
            directories.append(mount / "bin")
            escaped = str(mount).replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")
            lines.append(f"{900 + number} 1 0:{900 + number} / {escaped} rw,nosuid,nodev,relatime - tmpfs tmpfs rw")
        (self.root / "mountinfo").write_text("\n".join(lines) + "\n")
        function = re.search(r"^trusted\(\) \{\n.*?^\}\n", (self.clone / "install.sh").read_text(), re.M | re.S)[0]
        self.assertEqual(function.count("</proc/self/mountinfo"), 1)
        function = function.replace("</proc/self/mountinfo", '<"$FIXTURE_MOUNTINFO"')
        result = subprocess.run(["/bin/bash", "-c", function + 'trusted "$1"', "trusted",
                                 ":".join(map(str, [*directories, self.bin]))], env=dict(
                                    self.env, FIXTURE_MOUNTINFO=str(self.root / "mountinfo")),
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, f"{self.bin}\n")

    def test_setup_finds_pqkey_where_usr_local_bin_is_not_trusted(self):
        # Debian's staff option makes /usr/local and /usr/local/bin 2775 root:staff,
        # which install.sh does not trust. pqkey setup checks that the first pqkey on
        # its PATH is itself: it gets pqkey's directory last.
        for path in (Path("/usr/local"), Path("/usr/local/bin")):
            info = path.stat()
            self.addCleanup(os.chown, path, info.st_uid, info.st_gid)
            self.addCleanup(os.chmod, path, info.st_mode & 0o7777)
            os.chown(path, 0, 50)
            os.chmod(path, 0o2775)
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn("pqkey is ready.", output)
        self.assertEqual([command[1] for command in self.commands() if command[0] == "setup PATH"],
                         [f"{self.bin}:/usr/local/bin"])

    def test_loader_variables_reach_rust_and_the_build_alone(self):
        # The variables with which a program's environment names files it loads code
        # or data from: what install.sh runs itself never sees them, the system's
        # commands included; what it runs alone, here the Rust update and the build,
        # gets them back as you set them.
        yours = {"LD_PRELOAD": "libc.so.6", "LD_LIBRARY_PATH": f"{self.home}/lib:", "LD_AUDIT": "",
                 "GCONV_PATH": f"{self.home}/gconv", "MALLOC_TRACE": f"{self.home}/malloc",
                 "TMPDIR": str(self.root)}
        self.env.update(yours, RUST_VERSION="1.88.0")
        names = "|".join(["LD_[A-Za-z0-9_]*", *yours])
        for name in ("sleep", "tee", "dirname", "tail", "wc", "grep", "sed", "tr", "mkdir", "sort", "head",
                     "cut", "awk", "ln", "setsid"):
            real = (self.bin / name).resolve()
            (self.bin / name).unlink()
            (self.bin / name).write_text(
                f"#!/bin/sh\nseen=$(/usr/bin/env | /usr/bin/grep -oE '^({names})=' | /usr/bin/tr -d '=\\n')\n"
                f"[ -z \"$seen\" ] || printf '[\"loader\", \"{name}\"]\\n' >>\"$COMMAND_TRACE\"\n"
                f"exec {real} \"$@\"\n")
            (self.bin / name).chmod(0o755)
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        seen = [command[1:] for command in self.commands() if command[0] == "loader"]
        expected = sorted(f"{name}={value}" for name, value in yours.items())
        self.assertEqual(seen, [[" ".join(UPDATE), *expected], [" ".join(BUILD), *expected]])

    def test_the_build_ends_with_the_installer(self):
        # Interrupted (as by Ctrl-C), terminated, hung up (as by a closed terminal) or
        # killed while the build runs, the installer ends the build, and what the build
        # left running, with it: TERM first (INT is ignored by background jobs), so the
        # build can stop by itself.
        self.env.update(BUILD_SECONDS="60", LEAVE_BEHIND="plain", BUILD_PIDS=str(self.root / "build-pids"))
        for number, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143), (signal.SIGHUP, 129),
                                 (signal.SIGKILL, -signal.SIGKILL)):
            with self.subTest(signal=number.name):
                for path in (self.root / "trace", self.root / "build-pids"):
                    path.unlink(missing_ok=True)
                with open(self.root / "output", "wb") as output:
                    process = subprocess.Popen(["/bin/bash", str(self.clone / "install.sh"), "--yes"],
                                               env=self.env, stdin=subprocess.DEVNULL, stdout=output,
                                               stderr=subprocess.STDOUT, process_group=0)
                try:
                    deadline = time.monotonic() + 15
                    while len(self.build_processes(0)) < 2 and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertEqual(len(self.build_processes(0)), 2, (self.root / "output").read_text())
                    os.kill(process.pid, number)
                    self.assertEqual(process.wait(timeout=10), expected, (self.root / "output").read_text())
                    self.assertEqual(self.build_processes(), [])
                    if number != signal.SIGKILL:
                        self.assertIn(["cargo", "stopped by TERM"], self.commands())
                finally:
                    for pid in self.build_processes(0):
                        os.kill(int(pid), signal.SIGKILL)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)

    def test_missing_setsid_fails_before_sudo_or_build(self):
        (self.bin / "setsid").unlink()
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("needs setsid", output)
        self.assertFalse(any(command[0] in ("sudo", "cargo") for command in self.commands()))

    def test_old_system_rust_is_actionable(self):
        (self.bin / "rustup").unlink()
        self.env["RUST_VERSION"] = "1.88.0"
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("older than", output)
        self.assertFalse(INSTALLED.exists())

    def test_old_rustup_stable_is_updated_before_build(self):
        self.env["RUST_VERSION"] = "1.88.0"
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn("✓ Rust updated", output)
        self.assertIn("pqkey is ready.", output)
        commands = self.commands()
        build = next(command for command in commands if command[0] == "cargo")
        self.assertEqual(build[:3], ["cargo", "+stable", "build"])
        self.assertIn(UPDATE, commands)
        self.assertLess(commands.index(UPDATE), commands.index(build))

    def test_rustup_stable_left_old_stops_before_build(self):
        # The update fails, or succeeds with a stable still older than 1.89.
        for variable, value, left in (("FAIL_COMMAND", " ".join(UPDATE), "1.88.0"),
                                      ("LATEST_RUST_VERSION", "1.88.1", "1.88.1")):
            with self.subTest(variable=variable):
                (self.root / "trace").unlink(missing_ok=True)
                self.env.update(RUST_VERSION="1.88.0", **{variable: value})
                status, output = self.run_install()
                self.assertNotEqual(status, 0, output)
                self.assertIn(f"Rust {left} is older than the 1.89 pqkey needs", output)
                self.assertIn(UPDATE, self.commands())
                self.assertFalse(any(command[0] == "cargo" for command in self.commands()))
                self.assertFalse(INSTALLED.exists())
                del self.env[variable]

    def test_current_rustup_stable_is_not_updated(self):
        for version in ("1.89.0", "1.100.0"):
            with self.subTest(version=version):
                (self.root / "trace").unlink(missing_ok=True)
                self.env["RUST_VERSION"] = version
                status, output = self.run_install()
                self.assertEqual(status, 0, output)
                self.assertNotIn("Rust updated", output)
                commands = self.commands()
                self.assertIn(["rustc", "+stable", "--version"], commands)
                self.assertFalse(any(command[:3] == UPDATE[:3] for command in commands))
                self.assertTrue(any(command[0] == "cargo" for command in commands))

    def test_rust_check_installs_nothing_and_logs_what_rustup_prints(self):
        # In the clone, rustup 1.28 and later install what rust-toolchain.toml names
        # even to list toolchains, updating a stable that lacks those components.
        self.env.update(RUST_VERSION="1.88.0", MISSING_COMPONENTS="1", RUST_STDERR="fixture: rust diagnostics")
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn("✓ Rust updated", output)
        self.assertNotIn("fixture: rust diagnostics", output)
        self.assertNotIn("syncing", output)
        self.assertIn("fixture: rust diagnostics", (self.home / ".cache/pqkey/install.log").read_text())
        # Nor does the check before the build: rustup installs Rust only alone.
        self.assertNotIn(["rustup", "installed by itself"], self.commands())

    def test_build_install_and_setup_failures_leave_recovery(self):
        for failure in ("cargo", "install", "mv", "setup"):
            with self.subTest(failure=failure):
                INSTALLED.write_text("previous executable")
                RECOVERY.unlink(missing_ok=True)
                self.env.pop("FAIL_COMMAND", None)
                self.env.pop("FAIL_SETUP", None)
                self.env["FAIL_SETUP" if failure == "setup" else "FAIL_COMMAND"] = "1" if failure == "setup" else failure
                status, output = self.run_install()
                self.assertNotEqual(status, 0, output)
                self.assertNotIn("pqkey is ready.", output)
                self.assert_preserved()
                if failure in ("cargo", "install", "mv"):
                    self.assertEqual(INSTALLED.read_text(), "previous executable")
                if failure == "setup":
                    self.assertEqual(RECOVERY.read_text(), "previous executable")
                    self.assertIn("sudo mv -f", output)

    def test_failed_update_rerun_keeps_first_recovery_then_repairs(self):
        INSTALLED.write_text("known good executable")
        self.env["FAIL_SETUP"] = "1"
        for version in ("failed-one", "failed-two"):
            self.env["BUILD_VERSION"] = version
            status, output = self.run_install()
            self.assertNotEqual(status, 0, output)
            self.assertEqual(RECOVERY.read_text(), "known good executable")
        del self.env["FAIL_SETUP"]
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertFalse(RECOVERY.exists())
        self.assert_preserved()

    def test_legacy_executable_link_is_repaired(self):
        cargo_bin = Path(self.env["CARGO_HOME"]) / "bin"
        cargo_bin.mkdir(parents=True)
        old = cargo_bin / "pqkey"
        old.write_text("old executable")
        old.chmod(0o755)
        self.env["PATH"] = f"{cargo_bin}:" + self.env["PATH"]
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertTrue(old.is_symlink())
        self.assertEqual(old.resolve(), INSTALLED)

    def test_cargo_install_root_does_not_link_the_binary_to_itself(self):
        self.env["CARGO_INSTALL_ROOT"] = "/usr/local"
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertFalse(INSTALLED.is_symlink())
        self.assertIn("pqkey is ready.", output)

    def test_missing_or_shadowed_path_requires_current_shell_repair(self):
        for shadow in (False, True):
            with self.subTest(shadow=shadow):
                self.env["PATH"] = str(self.bin)
                if shadow:
                    old = self.bin / "pqkey"
                    old.write_text("old executable")
                    old.chmod(0o755)
                status, output = self.run_install()
                self.assertNotEqual(status, 0, output)
                self.assertIn("export PATH=", output)
                self.assertNotIn("pqkey is ready.", output)

    def test_sudo_disk_space_os_and_argument_failures(self):
        for variable, value, expected in (("FAIL_COMMAND", "sudo", "sudo"), ("FREE_MB", "1", "disk space"),
                                          ("FIXTURE_OS", "Darwin", "Linux only")):
            with self.subTest(variable=variable):
                self.env[variable] = value
                status, output = self.run_install()
                self.assertNotEqual(status, 0, output)
                self.assertIn(expected, output)
                self.assertFalse(INSTALLED.exists())
                del self.env[variable]
        status, output = self.run_install(args=("--yes", "unexpected"))
        self.assertEqual(status, 2, output)

    def test_stable_clone_builds_without_a_ci_note(self):
        origin = self.make_origin()
        self.git("branch", "stable", "main~1", cwd=origin)
        self.git("clone", "-q", "--branch", "stable", str(origin), str(self.clone), cwd=self.root)
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertNotIn("stable", output)
        # Stable moves on; a fetched clone still builds a commit stable contains.
        self.git("branch", "-f", "stable", "main", cwd=origin)
        self.git("fetch", "-q", "origin")
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertNotIn("stable", output)

    def test_commit_not_on_stable_warns_before_continuing(self):
        origin = self.make_origin()
        self.git("branch", "stable", "main~1", cwd=origin)
        self.git("clone", "-q", str(origin), str(self.clone), cwd=self.root)
        status, output = self.run_install(args=(), interactive=True, responses=(("Continue?", "y"),))
        self.assertEqual(status, 0, output)
        self.assertIn("pqkey is ready.", output)
        self.assertLess(output.index(WARNING), output.index("Continue?"))
        self.assertIn("To install stable: " + HINT, output)
        self.assertIn(WARNING, (self.home / ".cache/pqkey/install.log").read_text())
        status, output = self.run_hint()
        self.assertEqual(status, 0, output)
        self.assertNotIn("passed CI", output)

    def test_clone_without_stable_is_noted(self):
        origin = self.make_origin()
        self.git("clone", "-q", str(origin), str(self.clone), cwd=self.root)
        self.git("branch", "stable", "main~1", cwd=origin)
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertIn(NOTE + "\nTo install stable: " + HINT, output)
        self.assertNotIn(WARNING, output)
        self.assertIn(NOTE, (self.home / ".cache/pqkey/install.log").read_text())
        status, output = self.run_hint()
        self.assertEqual(status, 0, output)
        self.assertNotIn("passed CI", output)

    def test_no_ci_note_without_git_or_outside_a_git_clone(self):
        origin = self.make_origin()
        self.git("branch", "stable", "main~1", cwd=origin)
        self.git("clone", "-q", str(origin), str(self.clone), cwd=self.root)
        (self.bin / "git").unlink()
        status, output = self.run_install()
        self.assertEqual(status, 0, output)
        self.assertNotIn("stable", output)
        # Copies of the source, alone or inside another clone, are not clones.
        (self.bin / "git").symlink_to(GIT)
        for copy in (self.root / "copy", origin / "copy"):
            with self.subTest(copy=copy):
                copy.mkdir()
                for name in ("install.sh", "Cargo.toml"):
                    shutil.copy2(self.clone / name, copy / name)
                self.clone = copy
                status, output = self.run_install()
                self.assertEqual(status, 0, output)
                self.assertNotIn("stable", output)


if __name__ == "__main__":
    # As in a terminal: the tests run in a session of their own whose controlling
    # terminal is a pty, the /dev/tty of the installs they start (run_install's
    # terminal). This process waits for them, reaping what is left to it, as the
    # container's first process must, and reads what is written to the terminal.
    master, slave = pty.openpty()
    tests = os.fork()
    if tests == 0:
        os.close(master)
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.close(slave)
        unittest.main()
    os.close(slave)
    while True:
        if select.select([master], [], [], 0.1)[0]:
            with contextlib.suppress(OSError):
                os.read(master, 65536)
        with contextlib.suppress(ChildProcessError):
            pid, wait_status = os.waitpid(-1, os.WNOHANG)
            if pid == tests:
                sys.exit(os.waitstatus_to_exitcode(wait_status))
