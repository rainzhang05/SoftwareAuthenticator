"""Mocked harness peers only. Never included in acceptance artifacts."""
import json
import signal
import sys
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
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

    def test_driver_output_redacts_control_tokens_before_disk(self):
        line = b"DevTools listening on ws://127.0.0.1:1234/devtools/browser/secret-session sessionId=0123456789abcdef Session ID: 0123456789abcdef 'session_id': '0123456789abcdef' /session/0123456789abcdef/execute PIN=unit-secret http://localhost:8080"
        public = runtime.public_log(line, ('unit-secret',)).decode()
        self.assertNotIn('secret-session', public)
        self.assertNotIn('0123456789abcdef', public)
        self.assertNotIn('unit-secret', public)
        self.assertIn('http://localhost:8080', public)

    def test_owned_process_logging_and_shutdown_on_a_real_child(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = runtime.OwnedProcesses()
            owned.redactions = ('test-redaction',)
            filename = Path(directory) / 'owned.log'
            process = owned.start([sys.executable, '-u', '-c',
                                   "import time; print('test-redaction ws://127.0.0.1:1234/private'); time.sleep(60)"], filename)
            try:
                acceptance.wait_until(lambda: filename.exists() and filename.stat().st_size > 0, 3)
            finally:
                failures = owned.cleanup()
            self.assertEqual(failures, [])
            self.assertIsNotNone(process.poll())
            self.assertNotIn('test-redaction', filename.read_text())
            self.assertNotIn('/private', filename.read_text())

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

    def test_separate_browser_groups_are_tracked_by_ancestry_only(self):
        owned = runtime.OwnedProcesses()
        owned.children = [SimpleNamespace(pid=10, _pqkey_identity='100', _pqkey_stopped=False)]
        files = []
        for pid, parent, start in [(10, 1, '100'), (20, 10, '200'), (30, 20, '300'), (40, 1, '400')]:
            fields = ['R', str(parent), str(pid), str(pid)] + ['0'] * 15 + [start]
            text = f'{pid} (fixture) ' + ' '.join(fields)
            files.append(SimpleNamespace(parent=SimpleNamespace(name=str(pid)), read_text=lambda text=text: text))
        with patch.object(runtime.Path, 'glob', return_value=files):
            owned.adopt_descendants()
        self.assertEqual(set(owned.descendants), {20, 30})
        self.assertTrue(all(not r['group'] and r['root'] == 10 for r in owned.descendants.values()))
        with patch.object(runtime, 'terminate_records') as terminate:
            owned.stop_descendants(10)
            self.assertEqual({r['pid'] for r in terminate.call_args.args[0]}, {20, 30})

    def test_adopted_browser_is_never_signaled_as_an_unrelated_group(self):
        fields = ['R', '1', '99', '99'] + ['0'] * 15 + ['200']
        record = {'pid': 20, 'start': '200', 'group': False, 'stopped': False, 'root': 10}
        with patch.object(runtime.Path, 'exists', return_value=True), patch.object(runtime.Path, 'read_text', return_value='20 (fixture) ' + ' '.join(fields)), patch.object(runtime.os, 'kill') as kill, patch.object(runtime.os, 'killpg') as kill_group, patch.object(runtime.time, 'sleep'):
            runtime.terminate_records([record])
        kill_group.assert_not_called()
        self.assertEqual([call.args for call in kill.call_args_list], [(20, signal.SIGTERM), (20, signal.SIGKILL)])

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

    def test_cancellation_runs_cleanup_and_does_not_continue_the_matrix(self):
        run = self.make_run()
        with patch.object(run, 'setup', side_effect=acceptance.RunInterrupted(signal.SIGTERM)), patch.object(run, 'cleanup') as cleanup, patch.object(run, 'run_presets') as presets:
            with self.assertRaises(acceptance.RunInterrupted):
                run.execute()
            cleanup.assert_called_once()
            presets.assert_not_called()
        report = json.loads((run.out / 'matrix.json').read_text())
        self.assertFalse(report['acceptance_passed'])
        self.assertIn('interrupted by signal', report['failures'][0])

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
        with patch.object(run, 'check_device_isolation'), patch.object(acceptance.time, 'monotonic', side_effect=lambda: tick[0]), patch.object(acceptance.time, 'sleep', side_effect=sleep), patch.object(run, 'results', return_value=[]), patch.object(acceptance, 'peer', side_effect=[first] + [observation] * 100):
            with self.assertRaisesRegex(TimeoutError, 'native UI did not advance'):
                run.ceremony({'id': 'R1', 'label': 'mock', 'kind': 'reg'})
        self.assertGreaterEqual(tick[0], 10)
        self.assertLess(tick[0], acceptance.CEREMONY_SECONDS)

    def test_foreign_device_blocks_browser_and_pin_actions(self):
        run = self.make_run()
        run.node = '/dev/owned-unit-fixture'
        run.driver = MagicMock()
        with patch.object(acceptance, 'fido_devices', return_value={run.node, '/dev/foreign-unit-fixture'}), patch.object(acceptance, 'peer') as peer:
            with self.assertRaisesRegex(RuntimeError, 'inventory changed'):
                run.ceremony({'id': 'R1', 'kind': 'reg'})
            run.driver.execute_script.assert_not_called()
            peer.assert_not_called()

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

    def test_prior_evidence_is_never_silently_overwritten(self):
        run = self.make_run()
        run.write()
        with self.assertRaisesRegex(ValueError, 'prior evidence exists'):
            acceptance.Run(run.browser, run.out.parent, None)
        run.metadata['initialized_only'] = True
        run.write()
        initialized = acceptance.Run(run.browser, run.out.parent, None)
        self.assertFalse(initialized.metadata['initialized_only'])


if __name__ == '__main__':
    unittest.main()
