"""Acceptance result policy. No browser/device imports; unit-testable offline."""
from __future__ import annotations

import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL_IDS = {"R1", "R2", "R12", "R13", "R15", "R30", "L1", "L2", "L3"}
GOOD = {"verified_success", "expected_webauthn_error", "unsupported_browser_capability"}


def wait_until(probe, seconds, *, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    while True:
        result = probe()
        if result:
            return result
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError(f"condition not reached within {seconds}s")
        sleep(min(0.1, remaining))


def classify(entry, preset, browser, version, ui=(), *, timed_out=False):
    """Unsupported needs an explicit native incompatibility screen AND source rule.

    A DOMException name, a cancellation or a timeout is never sufficient.
    Rules are deliberately conservative until a native run supplies more evidence.
    """
    if timed_out or entry is None:
        return "infrastructure_failure"
    if entry.get("outcome") == "FAIL":
        return "unexpected_failure"
    if entry.get("outcome") == "PASS":
        return "unexpected_failure" if preset == "R14" else "verified_success"
    if entry.get("stage") != "webauthn":
        return "infrastructure_failure"
    if preset == "R14" and entry.get("outcome") == "InvalidStateError":
        return "expected_webauthn_error"
    rules = json.loads((HERE / "expectations.json").read_text())["rejection_rules"]
    algs = (entry.get("request") or {}).get("algs", [])
    for rule in rules:
        if (browser == rule["browser"] and version.startswith(rule["version_prefix"])
                and algs and set(algs) <= set(rule["algorithms"])
                and entry.get("outcome") in rule["errors"]
                and rule["ui_evidence"] in ui):
            return "unsupported_browser_capability"
    return "unexpected_failure"


def initial_rows(presets):
    return [{"preset": p["id"], "label": p["label"], "attempted": False,
             "outcome": "infrastructure_failure", "reason": "runtime not reached",
             "ceremonies": []} for p in presets]


def write_report(directory, browser, metadata, rows, failures):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    controls = all(any(r["preset"] == key and r["outcome"] == "verified_success" for r in rows)
                   for key in CONTROL_IDS)
    # Unsupported observations are invalid without all mandatory controls.
    for row in rows:
        if row["outcome"] == "unsupported_browser_capability" and not controls:
            row["outcome"] = "infrastructure_failure"
            row["reason"] = "unsupported observation invalid: mandatory controls failed"
    ok = controls and not failures and all(r["attempted"] and r["outcome"] in GOOD for r in rows)
    report = {"schema_version": 1, "browser": browser, "metadata": metadata,
              "presence": "auto-approve (automated compatibility; no manual physical presence)",
              "acceptance_passed": ok, "mandatory_controls_passed": controls,
              "failures": failures, "results": rows}
    (directory / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [f"# {browser}: {'PASS' if ok else 'FAIL / incomplete'}", "",
             report["presence"], "", "| Preset | Attempted | Outcome | Detail |", "|---|---|---|---|"]
    for row in rows:
        detail = str(row.get("reason", "")).replace("|", "/").replace("\n", " ")
        lines.append(f"| {row['preset']} | {row['attempted']} | {row['outcome']} | {detail} |")
    lines.extend(["", *[f"- {str(f).replace(chr(10), ' ')}" for f in failures]])
    (directory / "summary.md").write_text("\n".join(lines) + "\n")
    return ok
