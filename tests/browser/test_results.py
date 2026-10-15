"""Offline harness-unit tests; these are NOT browser acceptance evidence."""
import json
import tempfile
import unittest
from pathlib import Path

from results import CONTROL_IDS, classify, finalize_workflow, initial_rows, wait_until, write_report


class Results(unittest.TestCase):
    def test_catalog_and_pending_records(self):
        presets = json.loads(Path(__file__).with_name("presets.json").read_text())
        self.assertEqual([p["id"] for p in presets],
                         [f"R{i}" for i in range(1, 36)] + [f"L{i}" for i in range(1, 8)])
        self.assertTrue(all(not row["attempted"] for row in initial_rows(presets)))

    def test_errors_are_narrow_and_timeouts_never_unsupported(self):
        error = {"outcome": "InvalidStateError", "stage": "webauthn"}
        self.assertEqual(classify(error, "R14", "chromium", "158.0"), "expected_webauthn_error")
        self.assertEqual(classify(error, "R1", "chromium", "158.0"), "unexpected_failure")
        self.assertEqual(classify({**error, "stage": "verification"}, "R14", "chromium", "158.0"), "infrastructure_failure")
        self.assertEqual(classify({"outcome": "PASS"}, "R14", "chromium", "158.0"), "unexpected_failure")
        error = {"outcome": "NotAllowedError", "stage": "webauthn", "request": {"algs": [-48]}, 'elapsed_ms': 500}
        self.assertEqual(classify(error, "R3", "firefox", "158.0"), "unexpected_failure")
        transport = [{'command': 4, 'status': 0}, {'command': 1, 'status': 0x26}]
        self.assertEqual(classify(error, "R3", "firefox", "158.0", transport=transport), "unsupported_browser_capability")
        self.assertEqual(classify(error, "R3", "firefox", "159.0", transport=transport), "unexpected_failure")
        self.assertEqual(classify(error, "R3", "firefox", "158.0", transport=transport, timed_out=True), "infrastructure_failure")
        for invalid in ([], [{'command': 1, 'status': 0}], transport + [{'command': 6, 'status': 0x31}], transport * 2):
            self.assertEqual(classify(error, "R3", "firefox", "158.0", transport=invalid), 'unexpected_failure')
        self.assertEqual(classify({**error, 'elapsed_ms': 25000}, 'R3', 'firefox', '158.0', transport=transport), 'unexpected_failure')
        self.assertEqual(classify({"outcome": "FAIL"}, "R3", "firefox", "158.0"), "unexpected_failure")

    def test_chromium_policy_rejections_require_exact_preset_and_parameters(self):
        message = 'Requested protection policy is inconsistent or incongruent with other requested parameters.'
        entry = {'outcome': 'NotSupportedError', 'stage': 'webauthn', 'error': {'message': message},
                 'request': {'credProtect': 'userVerificationRequired', 'userVerification': 'preferred'}}
        self.assertEqual(classify(entry, 'R19', 'chromium', '158.0'), 'expected_webauthn_error')
        self.assertEqual(classify(entry, 'R18', 'chromium', '158.0'), 'unexpected_failure')
        self.assertEqual(classify({**entry, 'request': {**entry['request'], 'userVerification': 'required'}}, 'R19', 'chromium', '158.0'), 'unexpected_failure')

    def test_waits_have_a_real_deadline_and_propagate_peer_failures(self):
        tick = [0]
        def sleep(seconds):
            tick[0] += seconds
        with self.assertRaises(TimeoutError):
            wait_until(lambda: None, 0.25, clock=lambda: tick[0], sleep=sleep)
        self.assertAlmostEqual(tick[0], 0.25)
        with self.assertRaisesRegex(RuntimeError, "peer gone"):
            wait_until(lambda: (_ for _ in ()).throw(RuntimeError("peer gone")), 2)

    def test_missing_controls_and_setup_failure_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = [{"preset": "R3", "attempted": True, "outcome": "unsupported_browser_capability"}]
            self.assertFalse(write_report(directory, "firefox", {}, rows, []))
            report = json.loads((Path(directory) / "matrix.json").read_text())
            self.assertEqual(report["results"][0]["outcome"], "infrastructure_failure")
            self.assertEqual(rows[0]["outcome"], "unsupported_browser_capability")
            rows = [{"preset": key, "attempted": True, "outcome": "verified_success"} for key in CONTROL_IDS]
            self.assertFalse(write_report(directory, "firefox", {}, rows, ["cleanup failed"]))
            self.assertTrue(write_report(directory, "firefox", {}, rows, []))
            self.assertFalse(finalize_workflow(directory, 'failure'))
            final = json.loads((Path(directory) / 'matrix.json').read_text())
            self.assertEqual(final['metadata']['workflow_stage_status'], 'failure')
            self.assertTrue(all(row['outcome'] == 'verified_success' for row in final['results']))


if __name__ == "__main__":
    unittest.main()
