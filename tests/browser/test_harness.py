"""Mocked harness peers only. Never included in acceptance artifacts."""
import json
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import acceptance
import runtime


class Harness(unittest.TestCase):
    def make_run(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return acceptance.Run('chromium', Path(directory.name), None)

    def test_nonlinux_fails_before_device_or_process_operations(self):
        with patch.object(runtime.platform, 'system', return_value='Darwin'), patch.object(runtime.os, 'open') as opened, patch.object(runtime.subprocess, 'Popen') as spawned:
            with self.assertRaisesRegex(runtime.UnavailableRuntime, 'unavailable runtime: real Linux'):
                runtime.preflight()
            opened.assert_not_called()
            spawned.assert_not_called()

    def test_missing_uhid_is_not_a_skipped_browser_capability(self):
        with patch.object(runtime.platform, 'system', return_value='Linux'), patch.object(runtime.platform, 'machine', return_value='x86_64'), patch.object(runtime.Path, 'stat', side_effect=FileNotFoundError('no UHID')):
            with self.assertRaisesRegex(runtime.UnavailableRuntime, 'cannot open real /dev/uhid'):
                runtime.preflight()

    def test_cleanup_tracks_groups_and_is_idempotent_after_leader_exit(self):
        owned = runtime.OwnedProcesses()
        process = MagicMock(pid=987654321)
        process.poll.return_value = 0
        owned.children.append(process)
        process._pqkey_stopped = False
        with patch.object(runtime.os, 'killpg') as kill:
            self.assertEqual(owned.cleanup(), [])
            self.assertEqual([call.args for call in kill.call_args_list],
                             [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)])
            owned.cleanup()
            self.assertEqual(kill.call_count, 2)

    def test_fallback_refuses_reused_pid_without_signaling(self):
        with tempfile.TemporaryDirectory() as directory:
            pid = 987654321
            (Path(directory) / 'processes.json').write_text(json.dumps([{'pid': pid, 'start': 'OLD', 'stopped': False}]))
            original_read, original_exists = Path.read_text, Path.exists
            fields = ['R', '1', str(pid), str(pid)] + ['0'] * 15 + ['NEW']
            def read(filename, *args, **kwargs):
                return f'{pid} (owned) ' + ' '.join(fields) if str(filename).startswith('/proc/') else original_read(filename, *args, **kwargs)
            def exists(filename):
                return True if str(filename).startswith('/proc/') else original_exists(filename)
            with patch.object(Path, 'read_text', read), patch.object(Path, 'exists', exists), patch.object(runtime.os, 'killpg') as kill:
                with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                    runtime.fallback_cleanup(directory)
                kill.assert_not_called()

    def test_partial_setup_cleanup_copies_only_public_evidence(self):
        run = self.make_run()
        run.work = tempfile.TemporaryDirectory()
        run.rp_data = Path(run.work.name) / 'rp'
        run.rp_data.mkdir()
        (run.rp_data / 'results.jsonl').write_text('{"outcome":"PASS"}\n')
        (run.rp_data / 'db.json').write_text('PRIVATE FIXTURE STATE')
        work = Path(run.work.name)
        run.cleanup()
        self.assertFalse(work.exists())
        self.assertTrue((run.out / 'rp-verifier.jsonl').exists())
        self.assertFalse((run.out / 'db.json').exists())

    def test_failure_does_not_stop_remaining_presets_or_turn_into_skip(self):
        run = self.make_run()
        run.driver = MagicMock()
        run.driver.execute_script.return_value = True
        run.port = 12345
        with patch.object(run, 'ceremony', side_effect=RuntimeError('mock UI peer failed')) as ceremony, patch.object(run, 'screenshot'):
            run.run_presets()
        self.assertEqual(ceremony.call_count, 44)
        self.assertTrue(all(row['attempted'] and row['outcome'] == 'infrastructure_failure' for row in run.rows))

    def test_native_ui_wait_expires_without_retyping_pin(self):
        run = self.make_run()
        run.driver = MagicMock()
        run.daemon = run.driver_process = run.rp_process = MagicMock()
        run.daemon.poll.return_value = None
        run.version = '158.0'
        tick = [0.0]
        def sleep(seconds):
            tick[0] += seconds
        observation = {"action": None, "fingerprint": 'same', "evidence": [], "tree": []}
        first = {**observation, 'action': 'entered PIN in native dialog'}
        with patch.object(acceptance.time, 'monotonic', side_effect=lambda: tick[0]), patch.object(acceptance.time, 'sleep', side_effect=sleep), patch.object(run, 'results', return_value=[]), patch.object(acceptance, 'peer', side_effect=[first] + [observation] * 100):
            with self.assertRaisesRegex(TimeoutError, 'native UI did not advance'):
                run.ceremony({'id': 'R1', 'label': 'mock', 'kind': 'reg'})
        self.assertGreaterEqual(tick[0], 10)
        self.assertLess(tick[0], acceptance.CEREMONY_SECONDS)

    def test_sensitive_stdin_is_not_in_peer_failure(self):
        response = subprocess.CompletedProcess([], 1, stdout='private PIN here', stderr='private PIN here')
        with patch.object(acceptance.subprocess, 'run', return_value=response) as execute:
            with self.assertRaisesRegex(RuntimeError, '^ui.py failed') as raised:
                acceptance.peer('ui.py', {'pin': 'private PIN here'}, {})
        self.assertNotIn('private PIN here', str(raised.exception))
        self.assertNotIn('private PIN here', str(execute.call_args.args))

    def test_console_never_serializes_protocol_payloads(self):
        run = self.make_run()
        entry = MagicMock(level='info', text=run.pin, timestamp=1)
        entry.args = {'token': 'PRIVATE'}
        run.console(entry)
        public = run.console_file.read_text()
        self.assertNotIn(run.pin, public)
        self.assertNotIn('PRIVATE', public)


if __name__ == '__main__':
    unittest.main()
