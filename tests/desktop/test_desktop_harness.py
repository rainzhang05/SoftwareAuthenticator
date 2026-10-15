"""Offline regression evidence only: no installed service or notification server."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

E2E = Path(__file__).resolve().parents[1] / 'e2e'
sys.path.insert(0, str(E2E))
import desktop_acceptance as desktop
import desktop_results as results



class Ownership(unittest.TestCase):
    def test_rejected_preflight_never_uninstalls_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
            with patch.object(run, 'command') as command, patch.object(desktop, 'fido_devices') as devices:
                run.cleanup()
            command.assert_not_called()
            devices.assert_not_called()
            self.assertFalse(run.cleanup_ok)

    def test_runner_owned_identity_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            control, ledger = home / 'control', home / 'owner.json'
            user = 'pqd123a1f'
            owner = dict(uid=os.getuid(), user=user, home=str(home), source='a' * 40,
                         baseline=results.BASELINE, scenario='fresh')
            ledger.write_text(json.dumps(owner))
            metadata = MagicMock(st_uid=os.getuid() + 1, st_mode=0o100644)
            account = MagicMock(pw_name=user, pw_dir=str(home))
            with patch.dict(os.environ, PQKEY_OWNER_LEDGER=str(ledger)), \
                 patch.object(desktop.Path, 'stat', return_value=metadata), \
                 patch.object(desktop.Path, 'is_symlink', return_value=False), \
                 patch.object(desktop.Path, 'home', return_value=home), \
                 patch.object(desktop.pwd, 'getpwuid', return_value=account):
                self.assertEqual(desktop.owner_record(control), owner)
                metadata.st_uid = os.getuid()
                with self.assertRaises(AssertionError):
                    desktop.owner_record(control)
                metadata.st_uid += 1
                account.pw_name = 'personal-user'
                with self.assertRaises(AssertionError):
                    desktop.owner_record(control)

    def test_command_timeout_is_retained_without_partial_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
            with patch.object(desktop.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['probe'], 1, output=b'private')):
                with self.assertRaises(RuntimeError):
                    run.command(['probe'], timeout=1)
            text = (Path(directory) / 'commands.jsonl').read_text()
            self.assertNotIn('private', text)
            self.assertEqual(json.loads(text)['status'], 124)

    def test_entrypoint_refuses_non_runner_before_any_sudo(self):
        root = E2E.parents[1]
        env = dict(os.environ, GITHUB_ACTIONS='', RUNNER_ENVIRONMENT='')
        result = subprocess.run(['bash', str(root / 'scripts/desktop-acceptance.sh'), 'cleanup', 'fresh'],
                                env=env, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'UNAVAILABLE', result.stderr)



if __name__ == '__main__':
    unittest.main()
