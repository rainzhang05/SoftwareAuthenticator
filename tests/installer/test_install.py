"""Observable install.sh regression tests. Never run directly on the host."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[2]
INSTALLED = Path("/usr/local/bin/pqkey")
RECOVERY = Path(str(INSTALLED) + ".previous")


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
                        NO_COLOR="1")
        # Expose only the prerequisites this case chooses; host tools cannot
        # accidentally satisfy a missing prerequisite or run a package manager.
        for name in ("bash", "sh", "dirname", "mkdir", "tail", "tr", "grep", "sed", "wc",
                     "awk", "sort", "head", "cut", "sleep", "tee", "ln"):
            (self.bin / name).symlink_to(shutil.which(name))
        for name in ("uname", "id", "df", "sudo", "cc", "curl", "setfacl", "cargo", "rustc",
                     "rustup", "apt-get", "install", "mv", "cp", "rm", "cargo-source", "rustup-source"):
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

    def run_install(self, args=("--yes",), interactive=False, responses=()):
        command = ["/bin/bash", str(self.clone / "install.sh"), *args]
        if not interactive:
            result = subprocess.run(command, env=self.env, input=b"", stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=20)
            return result.returncode, result.stdout.decode()
        master, slave = pty.openpty()
        process = subprocess.Popen(command, env=self.env, stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True)
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

    def test_old_system_rust_is_actionable(self):
        (self.bin / "rustup").unlink()
        self.env["RUST_VERSION"] = "1.88.0"
        status, output = self.run_install()
        self.assertNotEqual(status, 0, output)
        self.assertIn("older than", output)
        self.assertFalse(INSTALLED.exists())

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


if __name__ == "__main__":
    unittest.main()
