"""Fail-closed result aggregation regressions; no native acceptance evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'e2e'))
import desktop_results as results


class Results(unittest.TestCase):
    def result(self, scenario='fresh'):
        return {'metadata': {'scenario': scenario, 'native_executed': True}, 'cleanup': True,
                'events': [{'case': case, 'status': 'pass'} for case in sorted(results.REQUIRED[scenario])]}

    def test_every_case_and_native_execution_and_cleanup_are_required(self):
        result = self.result()
        self.assertTrue(results.scenario_pass(result))
        for changed in ({**result, 'cleanup': False},
                        {**result, 'events': result['events'][:-1]},
                        {**result, 'metadata': {'scenario': 'fresh', 'native_executed': False}},
                        {**result, 'events': result['events'] + [{'case': 'execution', 'status': 'fail'}]}):
            self.assertFalse(results.scenario_pass(changed))

    def test_workflow_and_both_runner_cleanups_must_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            self.assertFalse(results.initialize(directory, 'a' * 40))
            for scenario in results.REQUIRED:
                (directory / scenario / 'result.json').write_text(json.dumps(self.result(scenario)))
                (directory / scenario / 'runner-cleanup-status').write_text('0\n')
            self.assertTrue(results.finalize(directory, 'success'))
            self.assertFalse(results.finalize(directory, 'cancelled'))
            self.assertFalse(results.finalize(directory, 'failure'))
            (directory / 'upgrade/runner-cleanup-status').write_text('1\n')
            self.assertFalse(results.finalize(directory, 'success'))
            (directory / 'upgrade/result.json').write_text('truncated')
            self.assertFalse(results.finalize(directory, 'success'))

    def test_summary_names_calls_refused_for_the_daemon(self):
        refused = {'pid': '4242', 'exe': '/usr/local/bin/pqkey', 'syscall': '161', 'name': 'chroot', 'code': '0x50000'}
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            results.initialize(directory, 'a' * 40)
            for scenario in results.REQUIRED:
                result = self.result(scenario)
                check = {'case': 'seccomp', 'status': 'pass', 'refused': [], 'canaries': {'start': True, 'end': True},
                         'lost': [], 'missed_kernel_messages': [], 'filter_counts': ['11']}
                if scenario == 'upgrade':
                    check.update(status='fail', refused=[refused])
                result['events'] = [row for row in result['events'] if row['case'] != 'seccomp'] + [check]
                (directory / scenario / 'result.json').write_text(json.dumps(result))
                (directory / scenario / 'runner-cleanup-status').write_text('0\n')
            self.assertFalse(results.finalize(directory, 'success'))
            summary = (directory / 'summary.md').read_text()
            self.assertIn('- fresh: PASS; refused calls for pqkey: 0; canaries: start logged, end logged; '
                          'lost records: 0; filter counts: 11\n', summary)
            self.assertIn('- upgrade: FAILED; refused calls for pqkey: 1 (chroot 161);', summary)
            report = json.loads((directory / 'report.json').read_text())
            self.assertEqual([row['seccomp']['status'] for row in report['scenarios']], ['pass', 'fail'])

    def test_a_missing_or_incomplete_check_is_reported(self):
        self.assertEqual(results.seccomp_summary({'events': []}), 'NOT CHECKED')
        incomplete = {'events': [{'case': 'seccomp', 'status': 'fail', 'error_type': 'TimeoutError'}]}
        self.assertEqual(results.seccomp_summary(incomplete), 'FAILED: the check did not complete (TimeoutError)')


if __name__ == "__main__":
    unittest.main()
