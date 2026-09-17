"""Tests for the Dependabot auto-merge decision.

    python3 -m unittest discover -s .github/scripts -p 'test_*.py'

cargo_semver_check.py is tested directly. dependabot-automerge.sh runs with
DRY_RUN=1 against a fake `gh` that answers from a scripted pull request, so its
decisions are tested without GitHub. It needs bash, jq and python3 3.11 or later.
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import cargo_semver_check  # noqa: E402

REPO = "owner/repo"
HEAD_SHA = "f" * 40
BASE_SHA = "b" * 40


def lockfile(**packages):
    """A Cargo.lock with one [[package]] per name; a list gives several versions."""
    lines = ["version = 4", ""]
    for name, versions in packages.items():
        for version in versions if isinstance(versions, list) else [versions]:
            lines += ["[[package]]", f'name = "{name}"', f'version = "{version}"', ""]
    return "\n".join(lines)


class CompatibleTest(unittest.TestCase):
    def test_cargo_semver_rules(self):
        for old, new, expected in [
            ("1.2.3", "1.9.0", True),
            ("1.2.3", "2.0.0", False),
            ("1.2.3", "1.2.2", False),
            ("0.12.4", "0.12.9", True),
            ("0.12.4", "0.13.0", False),
            ("0.0.3", "0.0.3", True),
            ("0.0.3", "0.0.4", False),
            ("1.2.3", "1.3.0-rc.1", False),
            ("1.2.3", "1.3.0+build.5", True),
        ]:
            with self.subTest(old=old, new=new):
                self.assertEqual(cargo_semver_check.compatible(old, new), expected)


class MainTest(unittest.TestCase):
    def check(self, base, head):
        with tempfile.TemporaryDirectory() as tmp:
            base_path, head_path = Path(tmp, "base.lock"), Path(tmp, "head.lock")
            base_path.write_text(base)
            head_path.write_text(head)
            result = subprocess.run(
                [sys.executable, SCRIPTS / "cargo_semver_check.py", base_path, head_path],
                capture_output=True,
                text=True,
            )
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    def test_identical_lockfiles_have_no_changes(self):
        lock = lockfile(sha2="0.11.0")
        self.assertEqual(self.check(lock, lock), (0, "no version changes", ""))

    def test_compatible_updates_and_new_packages_pass(self):
        status, out, _ = self.check(lockfile(sha2="0.11.0"), lockfile(sha2="0.11.1", zeroize="1.8.0"))
        self.assertEqual(status, 0)
        self.assertEqual(out, "sha2 0.11.0 -> 0.11.1; +zeroize 1.8.0")

    def test_an_incompatible_update_fails(self):
        status, _, err = self.check(lockfile(ctaphid_app="0.1.3"), lockfile(ctaphid_app="0.2.0"))
        self.assertEqual(status, 1)
        self.assertIn("ctaphid_app 0.1.3 -> 0.2.0", err)

    def test_every_new_version_needs_a_compatible_old_one(self):
        # 0.6.4 appears next to 0.10.x and is compatible with no version there was.
        status, _, _ = self.check(lockfile(rand_core="0.10.0"), lockfile(rand_core=["0.6.4", "0.10.1"]))
        self.assertEqual(status, 1)
        status, _, _ = self.check(lockfile(rand_core=["0.6.4", "0.10.0"]), lockfile(rand_core=["0.6.4", "0.10.1"]))
        self.assertEqual(status, 0)


FAKE_GH = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import base64, json, os, sys
    from urllib.parse import urlparse, parse_qs

    state_path = os.environ["FAKE_GH_STATE"]
    with open(state_path) as handle:
        state = json.load(handle)
    args = sys.argv[1:]
    state["calls"].append(args)
    with open(state_path, "w") as handle:
        json.dump(state, handle)

    if args[:2] == ["pr", "list"]:
        print(json.dumps(state["pr"]))
    elif args[:2] == ["pr", "merge"] or args[:2] == ["workflow", "run"]:
        pass
    elif args[0] == "api":
        path = next(arg for arg in args[1:] if arg.startswith("repos/"))
        url = urlparse(path)
        if "/actions/workflows/" in url.path:
            workflow = url.path.split("/actions/workflows/")[1].split("/")[0]
            print(state["runs"].get(workflow, "success"))
        elif "/compare/" in url.path:
            print(state["merge_base"])
        elif "/contents/" in url.path:
            file = url.path.split("/contents/", 1)[1]
            ref = parse_qs(url.query)["ref"][0]
            content = state["files"].get(f"{file}@{ref}")
            if content is None:
                print("gh: Not Found (HTTP 404)", file=sys.stderr)
                sys.exit(1)
            if "--jq" in args:
                # The JSON form: `--jq .content` is the file in base64.
                print(base64.b64encode(content.encode()).decode())
            else:
                sys.stdout.write(content)
        else:
            sys.exit(f"unexpected api call {args}")
    else:
        sys.exit(f"unexpected gh call {args}")
    """
)


class AutomergeScriptTest(unittest.TestCase):
    """dependabot-automerge.sh with DRY_RUN=1 against a fake gh."""

    script = SCRIPTS / "dependabot-automerge.sh"

    def run_script(self, files, lockfiles, runs=None, branch="dependabot/cargo/sha2-0.11.1"):
        """Run the script for a Dependabot PR changing `files`.

        `lockfiles` maps "path@ref" (ref "base" or "head") to content.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp, "bin")
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
            state_path = Path(tmp, "state.json")
            refs = {"base": BASE_SHA, "head": HEAD_SHA}
            state = {
                "calls": [],
                "pr": {
                    "number": 7,
                    "author": {"login": "app/dependabot"},
                    "headRefOid": HEAD_SHA,
                    "files": [{"path": path} for path in files],
                    "url": "https://example.invalid/pull/7",
                },
                "runs": runs or {},
                "merge_base": BASE_SHA,
                "files": {
                    f"{key.split('@')[0]}@{refs[key.split('@')[1]]}": content
                    for key, content in lockfiles.items()
                },
            }
            state_path.write_text(json.dumps(state))
            env = dict(
                os.environ,
                PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                FAKE_GH_STATE=str(state_path),
                DRY_RUN="1",
                REPO=REPO,
                HEAD_SHA=HEAD_SHA,
                HEAD_BRANCH=branch,
            )
            result = subprocess.run(["bash", self.script], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = json.loads(state_path.read_text())["calls"]
        return result.stdout, calls

    def assert_merges(self, out):
        self.assertIn("DRY RUN: would merge PR #7", out)

    def assert_skips(self, out, reason):
        self.assertNotIn("would merge", out)
        self.assertIn(f"skip: {reason}", out)

    def test_a_compatible_root_update_is_merged(self):
        out, calls = self.run_script(
            ["Cargo.lock", "crates/pqkey-ctap/Cargo.toml"],
            {"Cargo.lock@base": lockfile(sha2="0.11.0"), "Cargo.lock@head": lockfile(sha2="0.11.1")},
        )
        self.assert_merges(out)
        self.assertIn("Cargo.lock: compatible changes: sha2 0.11.0 -> 0.11.1", out)
        queried = [c for c in calls if c[0] == "api" and "/actions/workflows/" in c[1]]
        self.assertEqual(len(queried), 3, "no fuzz.yml for a root update")
        self.assertFalse(any(c[:2] == ["pr", "merge"] for c in calls))

    def test_an_incompatible_fuzz_lockfile_update_is_not_merged(self):
        # The root lockfile is untouched; only fuzz/Cargo.lock says what changes.
        out, _ = self.run_script(
            ["fuzz/Cargo.lock"],
            {
                "Cargo.lock@base": lockfile(arbitrary="1.4.0"),
                "Cargo.lock@head": lockfile(arbitrary="1.4.0"),
                "fuzz/Cargo.lock@base": lockfile(libfuzzer_sys="0.4.9"),
                "fuzz/Cargo.lock@head": lockfile(libfuzzer_sys="0.5.0"),
            },
            branch="dependabot/cargo/fuzz/libfuzzer-sys-0.5.0",
        )
        self.assert_skips(out, "fuzz/Cargo.lock has semver-incompatible version changes")

    def test_a_compatible_fuzz_lockfile_update_waits_for_the_fuzz_workflow(self):
        files = ["fuzz/Cargo.lock"]
        lockfiles = {
            "fuzz/Cargo.lock@base": lockfile(arbitrary="1.4.0"),
            "fuzz/Cargo.lock@head": lockfile(arbitrary="1.4.2"),
        }
        out, _ = self.run_script(files, lockfiles, runs={"fuzz.yml": "in_progress"})
        self.assert_skips(out, "fuzz.yml is in_progress")
        out, _ = self.run_script(files, lockfiles, runs={"fuzz.yml": "success"})
        self.assert_merges(out)
        self.assertIn("fuzz/Cargo.lock: compatible changes: arbitrary 1.4.0 -> 1.4.2", out)

    def test_every_changed_lockfile_must_be_compatible(self):
        out, _ = self.run_script(
            ["Cargo.lock", "fuzz/Cargo.lock"],
            {
                "Cargo.lock@base": lockfile(sha2="0.11.0"),
                "Cargo.lock@head": lockfile(sha2="0.11.1"),
                "fuzz/Cargo.lock@base": lockfile(sha2="0.10.9"),
                "fuzz/Cargo.lock@head": lockfile(sha2="0.11.1"),
            },
        )
        self.assertIn("Cargo.lock: compatible changes: sha2 0.11.0 -> 0.11.1", out)
        self.assert_skips(out, "fuzz/Cargo.lock has semver-incompatible version changes")

    def test_a_pull_request_without_a_lockfile_change_is_not_merged(self):
        out, _ = self.run_script(["crates/pqkey/Cargo.toml"], {})
        self.assert_skips(out, "PR #7 changes no Cargo.lock")

    def test_a_lockfile_new_on_the_branch_is_not_merged(self):
        out, _ = self.run_script(
            ["tools/Cargo.lock"],
            {"tools/Cargo.lock@head": lockfile(sha2="0.11.1")},
        )
        self.assert_skips(out, "tools/Cargo.lock could not be read on main")

    def test_other_files_are_not_merged(self):
        out, _ = self.run_script(
            ["Cargo.lock", "README.md"],
            {"Cargo.lock@base": lockfile(sha2="0.11.0"), "Cargo.lock@head": lockfile(sha2="0.11.1")},
        )
        self.assert_skips(out, "PR touches files other than Cargo manifests")


if __name__ == "__main__":
    unittest.main()
