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


if __name__ == "__main__":
    unittest.main()
