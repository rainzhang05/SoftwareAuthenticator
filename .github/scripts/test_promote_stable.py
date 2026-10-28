"""Tests for the decision that moves the `stable` branch.

    python3 -m unittest discover -s .github/scripts -p 'test_*.py'

promote-stable.sh runs against a fake `gh` that answers from a scripted
repository: a commit graph, its branches and each workflow's runs. The fake
applies the script's own --jq filters with jq, so the decision is tested as
written, without GitHub. It needs bash, jq and python3.
"""

import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent

REPO = "owner/repo"
WORKFLOWS = ("ci.yml", "e2e.yml", "security.yml")


def sha(number, prefix="c"):
    """A readable commit id: sha(3) is c000...0003, the third commit on main."""
    return f"{prefix}{number:039d}"


def tree(number):
    """A readable id for a version of .github/workflows."""
    return sha(number, prefix="a")


FAKE_GH = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json, os, subprocess, sys
    from urllib.parse import urlparse, parse_qs

    state_path = os.environ["FAKE_GH_STATE"]
    with open(state_path) as handle:
        state = json.load(handle)
    args = sys.argv[1:]
    refs = state["refs"]
    jq = None


    def answer(body):
        text = json.dumps(body)
        if jq is not None:
            # gh's --jq prints strings raw, as jq -r does.
            text = subprocess.run(["jq", "-r", jq], input=text, capture_output=True, text=True, check=True).stdout
        sys.stdout.write(text)


    def refuse(message):
        sys.exit(f"gh: {message}")


    def ancestors(commit):
        if commit not in state["commits"]:
            refuse("Not Found (HTTP 404)")
        seen, todo = set(), [commit]
        while todo:
            current = todo.pop()
            if current not in seen:
                seen.add(current)
                todo += state["commits"][current]["parents"]
        return seen


    def compare(base, head):
        base_side, head_side = ancestors(base), ancestors(head)
        if base == head:
            status = "identical"
        elif base in head_side:
            status = "ahead"
        elif head in base_side:
            status = "behind"
        else:
            status = "diverged"
        return {"status": status, "ahead_by": len(head_side - base_side), "behind_by": len(base_side - head_side)}


    def ref(name):
        return {"ref": f"refs/heads/{name}", "object": {"sha": refs[name], "type": "commit"}}


    def serve():
        global jq
        if args[:1] != ["api"]:
            refuse(f"unexpected gh call {args}")
        method, fields, path = None, {}, None
        rest = iter(args[1:])
        for arg in rest:
            if arg in ("--method", "-X"):
                method = next(rest)
            elif arg in ("--jq", "-q"):
                jq = next(rest)
            elif arg in ("-f", "--raw-field", "-F", "--field"):
                key, _, value = next(rest).partition("=")
                if arg in ("-F", "--field") and value in ("true", "false"):
                    value = value == "true"
                fields[key] = value
            elif path is None and not arg.startswith("-"):
                path = arg
            else:
                refuse(f"unexpected argument {arg}")
        # As gh api: GET, or POST once there are fields.
        method = method or ("POST" if fields else "GET")
        for part, error in state["broken"].items():
            if part in path:
                refuse(error)
        url = urlparse(path)
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        prefix = f"repos/{state['repo']}/"
        if not url.path.startswith(prefix):
            refuse(f"unexpected path {path}")
        route = url.path[len(prefix):]
        per_page = int(query.get("per_page", 30))

        if method == "GET" and route.startswith("git/ref/heads/"):
            name = route[len("git/ref/heads/"):]
            if name not in refs:
                refuse("Not Found (HTTP 404)")
            answer(ref(name))
        elif method == "GET" and route.startswith("git/matching-refs/heads/"):
            start = route[len("git/matching-refs/heads/"):]
            answer([ref(name) for name in sorted(refs) if name.startswith(start)])
        elif method == "GET" and route.startswith("compare/"):
            base, head = route[len("compare/"):].split("...")
            answer(compare(base, head))
        elif method == "GET" and route == "contents/.github":
            commit = query["ref"]
            ancestors(commit)
            answer(
                [
                    # Neighbours whose ids change with every commit.
                    {"name": "dependabot.yml", "type": "file", "sha": "1" + commit[1:]},
                    {"name": "scripts", "type": "dir", "sha": "2" + commit[1:]},
                    {"name": "workflows", "type": "dir", "sha": state["commits"][commit]["workflows"]},
                ]
            )
        elif method == "GET" and route == "commits":
            # Newest first, as `git log` lists them.
            listed = sorted(ancestors(query["sha"]), key=lambda c: state["commits"][c]["date"], reverse=True)
            answer([{"sha": commit} for commit in listed[:per_page]])
        elif method == "GET" and route.startswith("actions/workflows/") and route.endswith("/runs"):
            workflow = route.split("/")[2]
            runs = [run for run in state["runs"][workflow] if query.get("head_sha", run["head_sha"]) == run["head_sha"]]
            # Newest first, as GitHub lists them.
            runs.sort(key=lambda run: run["created_at"], reverse=True)
            answer({"total_count": len(runs), "workflow_runs": runs[:per_page]})
        elif method == "PATCH" and route.startswith("git/refs/heads/"):
            name = route[len("git/refs/heads/"):]
            if name not in refs:
                refuse("Reference does not exist (HTTP 422)")
            if not fields.get("force", False) and compare(refs[name], fields["sha"])["status"] != "ahead":
                refuse("Update is not a fast forward (HTTP 422)")
            refs[name] = fields["sha"]
            answer(ref(name))
        elif method == "POST" and route == "git/refs":
            name = fields["ref"][len("refs/heads/"):]
            if name in refs:
                refuse("Reference already exists (HTTP 422)")
            ancestors(fields["sha"])
            refs[name] = fields["sha"]
            answer(ref(name))
        else:
            refuse(f"unexpected {method} {path}")


    state["calls"].append(args)
    try:
        serve()
    finally:
        with open(state_path, "w") as handle:
            json.dump(state, handle)
    """
)


class PromoteScriptTest(unittest.TestCase):
    """promote-stable.sh against a fake gh."""

    script = SCRIPTS / "promote-stable.sh"

    def setUp(self):
        self.commits = {}
        self.refs = {}
        self.runs = {workflow: [] for workflow in WORKFLOWS}
        self.broken = {}  # requests whose path contains a key fail with its error

    def add_commit(self, commit, *parents):
        """A commit dated after every commit added before it, with the same
        .github/workflows as every other commit unless a test changes it."""
        self.commits[commit] = {"parents": list(parents), "date": len(self.commits), "workflows": tree(0)}
        return commit

    def main_history(self, count):
        """Commits sha(1) to sha(count) in a line, main at the newest."""
        commits = [sha(number) for number in range(1, count + 1)]
        for parent, commit in zip([None] + commits, commits):
            self.add_commit(commit, *([parent] if parent else []))
        self.refs["main"] = commits[-1]
        return commits

    def add_run(self, workflow, commit, conclusion="success", event="push", status="completed"):
        """A run of `workflow` for `commit`, created after every run added before it."""
        number = sum(len(runs) for runs in self.runs.values()) + 1
        created = datetime(2026, 10, 1) + timedelta(minutes=number)
        self.runs[workflow].append(
            {
                "id": number,
                "head_sha": commit,
                "event": event,
                "status": status,
                "conclusion": conclusion if status == "completed" else None,
                "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )

    def passes(self, commit, event="push"):
        for workflow in WORKFLOWS:
            self.add_run(workflow, commit, event=event)

    def workflow_files(self, commits, versions):
        """Give each commit its version of .github/workflows."""
        for commit, version in zip(commits, versions):
            self.commits[commit]["workflows"] = tree(version)

    def promote(self, dry_run=True, returncode=0):
        """Run the script; return its output, the gh calls it made and the branches after.

        With `dry_run` false the script goes on to change branches, in the fake.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp, "bin")
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
            state_path = Path(tmp, "state.json")
            state = {
                "repo": REPO,
                "commits": self.commits,
                "refs": self.refs,
                "runs": self.runs,
                "broken": self.broken,
                "calls": [],
            }
            state_path.write_text(json.dumps(state))
            env = dict(
                os.environ,
                PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                FAKE_GH_STATE=str(state_path),
                DRY_RUN="1" if dry_run else "0",
                REPO=REPO,
            )
            result = subprocess.run(["bash", self.script], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, returncode, result.stdout + result.stderr)
            state = json.loads(state_path.read_text())
        return result.stdout, state["calls"], state["refs"]

    def writes(self, calls):
        """The calls that change something; every other call is a GET."""
        return [call for call in calls if "--method" in call]

    def assert_promotes_nothing(self, out, calls, reason):
        self.assertIn(f"nothing to promote: {reason}", out)
        self.assertNotIn("would", out)
        self.assertEqual(self.writes(calls), [])

    def test_the_newest_commit_that_passed_becomes_stable(self):
        c = self.main_history(5)
        self.refs["stable"] = c[1]
        self.passes(c[2])
        self.passes(c[3])
        self.add_run("ci.yml", c[4], status="in_progress")
        out, _, _ = self.promote()
        self.assertIn(f"{c[4]}: ci.yml is in_progress", out)
        self.assertIn(f"{c[3]}: ci.yml e2e.yml security.yml all succeeded", out)
        self.assertIn(f"DRY RUN: would fast-forward stable from {c[1]} to {c[3]}", out)

        out, calls, refs = self.promote(dry_run=False)
        self.assertIn(f"fast-forwarded stable from {c[1]} to {c[3]}", out)
        self.assertEqual(
            self.writes(calls),
            [["api", "--method", "PATCH", f"repos/{REPO}/git/refs/heads/stable", "-f", f"sha={c[3]}", "-F", "force=false"]],
        )
        self.assertEqual(refs.get("stable"), c[3])

    def test_stable_is_created_when_missing(self):
        c = self.main_history(3)
        self.refs["stable-old"] = c[0]  # a name that only starts with "stable"
        self.passes(c[0])
        self.passes(c[1])
        self.add_run("ci.yml", c[2])
        self.add_run("e2e.yml", c[2], "failure")
        out, _, _ = self.promote()
        self.assertIn("stable does not exist yet", out)
        self.assertIn(f"{c[2]}: e2e.yml is failure", out)
        self.assertIn(f"DRY RUN: would create stable at {c[1]}", out)

        out, calls, refs = self.promote(dry_run=False)
        self.assertIn(f"created stable at {c[1]}", out)
        self.assertEqual(
            self.writes(calls),
            [["api", "--method", "POST", f"repos/{REPO}/git/refs", "-f", "ref=refs/heads/stable", "-f", f"sha={c[1]}"]],
        )
        self.assertEqual(refs.get("stable"), c[1])
        self.assertEqual(refs["stable-old"], c[0])

    def test_a_dry_run_changes_nothing(self):
        c = self.main_history(2)
        self.passes(c[1])
        for stable in (None, c[0]):
            with self.subTest(stable=stable):
                self.refs.pop("stable", None)
                if stable:
                    self.refs["stable"] = stable
                out, calls, refs = self.promote()
                self.assertIn(f"DRY RUN: would {'fast-forward' if stable else 'create'} stable", out)
                self.assertEqual(self.writes(calls), [])
                self.assertEqual(refs, self.refs)

    def test_every_workflow_must_have_succeeded(self):
        for workflow, state in [
            ("ci.yml", "failure"),
            ("e2e.yml", "cancelled"),
            ("security.yml", "timed_out"),
            ("ci.yml", "skipped"),
            ("ci.yml", "in_progress"),
            ("e2e.yml", "queued"),
            ("security.yml", "waiting"),
            ("e2e.yml", "missing"),
            ("security.yml", "missing"),
        ]:
            with self.subTest(workflow=workflow, state=state):
                self.setUp()
                c = self.main_history(3)
                self.refs["stable"] = c[0]
                self.passes(c[1])
                for other in WORKFLOWS:
                    if other != workflow:
                        self.add_run(other, c[2])
                    elif state in ("in_progress", "queued", "waiting"):
                        self.add_run(other, c[2], status=state)
                    elif state != "missing":
                        self.add_run(other, c[2], state)
                out, _, _ = self.promote()
                self.assertIn(f"{c[2]}: {workflow} is {state}", out)
                self.assertIn(f"would fast-forward stable from {c[0]} to {c[1]}", out)

    def test_only_runs_of_the_commit_itself_count(self):
        """Pull request runs test a merge with the pull request's own workflow
        files, and runs of other commits test other code."""
        c = self.main_history(3)
        self.refs["stable"] = c[0]
        self.passes(c[1])
        self.add_run("ci.yml", c[2])
        self.add_run("security.yml", c[2])
        self.add_run("e2e.yml", c[2], event="pull_request")
        self.add_run("e2e.yml", sha(1, prefix="f"))  # a commit that is not on main
        out, _, _ = self.promote()
        self.assertIn(f"{c[2]}: e2e.yml is missing", out)
        self.assertIn(f"would fast-forward stable from {c[0]} to {c[1]}", out)

    def test_a_failed_pull_request_run_does_not_hold_a_commit_back(self):
        c = self.main_history(2)
        self.refs["stable"] = c[0]
        self.passes(c[1])
        self.add_run("e2e.yml", c[1], "failure", event="pull_request")
        out, _, _ = self.promote()
        self.assertIn(f"would fast-forward stable from {c[0]} to {c[1]}", out)

    def test_runs_of_other_events_never_count(self):
        """Only push, schedule and dispatch runs count. A run of any other event
        neither passes a commit nor holds one back."""
        others = ("workflow_run", "repository_dispatch", "merge_group")
        c = self.main_history(3)
        self.refs["stable"] = c[0]
        self.passes(c[1])
        for event in others:
            self.add_run("e2e.yml", c[1], "failure", event=event)
        self.add_run("ci.yml", c[2])
        self.add_run("security.yml", c[2])
        for event in others:
            self.add_run("e2e.yml", c[2], event=event)
        out, _, _ = self.promote()
        self.assertIn(f"{c[2]}: e2e.yml is missing", out)
        self.assertIn(f"would fast-forward stable from {c[0]} to {c[1]}", out)

    def test_the_latest_run_of_each_workflow_decides(self):
        c = self.main_history(4)
        self.refs["stable"] = c[0]
        # c[1] failed E2E on push, then passed when E2E was dispatched again.
        self.add_run("ci.yml", c[1])
        self.add_run("e2e.yml", c[1], "failure")
        self.add_run("security.yml", c[1])
        self.add_run("e2e.yml", c[1], event="workflow_dispatch")
        # c[2] passed, then failed Security's weekly scan.
        self.passes(c[2])
        self.add_run("security.yml", c[2], "failure", event="schedule")
        # c[3] passed, and CI is running again.
        self.passes(c[3])
        self.add_run("ci.yml", c[3], status="in_progress", event="workflow_dispatch")
        out, _, _ = self.promote()
        self.assertIn(f"{c[3]}: ci.yml is in_progress", out)
        self.assertIn(f"{c[2]}: security.yml is failure", out)
        self.assertIn(f"would fast-forward stable from {c[0]} to {c[1]}", out)

    def test_stable_at_main_is_left_alone(self):
        c = self.main_history(2)
        self.refs["stable"] = c[1]
        self.passes(c[0])
        self.passes(c[1])
        out, calls, _ = self.promote(dry_run=False)
        self.assert_promotes_nothing(out, calls, "stable is already at main's head")

    def test_commits_stable_contains_are_not_candidates(self):
        c = self.main_history(5)
        self.refs["stable"] = c[2]
        for commit in c[:3]:
            self.passes(commit)
        self.add_run("ci.yml", c[3], "failure")
        self.add_run("ci.yml", c[4], status="queued")
        out, calls, refs = self.promote(dry_run=False)
        self.assert_promotes_nothing(
            out, calls, "none of the 2 newest commits on main that stable does not contain qualifies"
        )
        self.assertEqual(len([call for call in calls if "/actions/workflows/" in " ".join(call)]), 2)
        self.assertEqual(refs.get("stable"), c[2])

    def test_stable_never_moves_back(self):
        """main reset to an older commit: following it would move stable back."""
        c = self.main_history(5)
        self.refs["main"] = c[2]
        self.refs["stable"] = c[4]
        for commit in c:
            self.passes(commit)
        out, calls, refs = self.promote(dry_run=False, returncode=1)
        self.assertIn(f"::error::stable ({c[4]}) is not an ancestor of main ({c[2]}) (compare: behind)", out)
        self.assertEqual(self.writes(calls), [])
        self.assertEqual(refs.get("stable"), c[4])

    def test_stable_never_moves_sideways(self):
        """main rewritten under stable: no commit on main is a fast-forward."""
        c = self.main_history(3)
        self.refs["stable"] = self.add_commit(sha(1, prefix="d"), c[0])
        for commit in c:
            self.passes(commit)
        out, calls, _ = self.promote(dry_run=False, returncode=1)
        self.assertIn(f"::error::stable ({self.refs['stable']}) is not an ancestor of main ({c[2]}) (compare: diverged)", out)
        self.assertEqual(self.writes(calls), [])

    def test_a_merged_commit_that_is_not_ahead_of_stable_is_skipped(self):
        """main is c1, c2, then a merge of d1, which branched off at c1: d1
        passed, but moving stable from c2 to it would move it sideways."""
        c = self.main_history(2)
        self.refs["stable"] = c[1]
        side = self.add_commit(sha(1, prefix="d"), c[0])
        self.refs["main"] = self.add_commit(sha(1, prefix="e"), c[1], side)
        self.passes(side, event="workflow_dispatch")
        self.add_run("ci.yml", self.refs["main"], status="in_progress")
        out, calls, _ = self.promote(dry_run=False)
        self.assertIn(f"{side}: passed, but is not ahead of stable (compare: diverged)", out)
        self.assert_promotes_nothing(out, calls, "none of the 2 newest commits")

    def test_other_workflow_files_than_main_s_and_stable_s_are_skipped(self):
        """GitHub refuses GITHUB_TOKEN ref writes that point a branch at workflow
        files main's head does not have, unless the write changes none. Such a
        commit is skipped, and older ones are still considered: c[1] has
        stable's workflow files, so moving stable there changes none."""
        c = self.main_history(4)
        self.refs["stable"] = c[0]
        self.workflow_files(c, (1, 1, 2, 3))
        self.passes(c[1])
        self.passes(c[2])
        self.add_run("ci.yml", c[3], status="in_progress")
        out, _, refs = self.promote(dry_run=False)
        self.assertIn(f"{c[2]}: workflow files differ from main's head; GITHUB_TOKEN cannot move stable there", out)
        self.assertIn(f"fast-forwarded stable from {c[0]} to {c[1]}", out)
        self.assertEqual(refs.get("stable"), c[1])

    def test_stable_can_take_main_s_workflow_files(self):
        c = self.main_history(3)
        self.refs["stable"] = c[0]
        self.workflow_files(c, (1, 3, 3))
        self.passes(c[1])
        self.add_run("ci.yml", c[2], status="in_progress")
        out, _, refs = self.promote(dry_run=False)
        self.assertIn(f"fast-forwarded stable from {c[0]} to {c[1]}", out)
        self.assertEqual(refs.get("stable"), c[1])

    def test_stable_is_created_only_with_main_s_workflow_files(self):
        """As after the push that adds promote.yml: the older commits that passed
        lack it, so stable waits for main's head."""
        c = self.main_history(3)
        self.workflow_files(c, (2, 2, 3))
        self.passes(c[0])
        self.passes(c[1])
        self.add_run("ci.yml", c[2], status="in_progress")
        out, calls, refs = self.promote(dry_run=False)
        for commit in c[:2]:
            self.assertIn(f"{commit}: workflow files differ from main's head; GITHUB_TOKEN cannot move stable there", out)
        self.assert_promotes_nothing(out, calls, "none of the 3 newest commits on main that stable does not contain qualifies")
        self.assertNotIn("stable", refs)
        self.passes(c[2])
        out, _, refs = self.promote(dry_run=False)
        self.assertIn(f"created stable at {c[2]}", out)
        self.assertEqual(refs.get("stable"), c[2])

    def test_nothing_passed(self):
        c = self.main_history(3)
        self.add_run("ci.yml", c[0], "failure")
        self.add_run("ci.yml", c[1])
        self.add_run("e2e.yml", c[1])
        self.add_run("security.yml", c[1], "failure")
        out, calls, refs = self.promote(dry_run=False)
        self.assertIn(f"{c[2]}: ci.yml is missing", out)
        self.assertIn(f"{c[1]}: security.yml is failure", out)
        self.assertIn(f"{c[0]}: ci.yml is failure", out)
        self.assert_promotes_nothing(
            out, calls, "none of the 3 newest commits on main that stable does not contain qualifies"
        )
        self.assertNotIn("stable", refs)

    def test_it_looks_at_the_30_newest_commits_at_most(self):
        c = self.main_history(35)
        self.passes(c[4])  # the 31st newest
        out, calls, _ = self.promote(dry_run=False)
        self.assert_promotes_nothing(out, calls, "none of the 30 newest commits")
        self.assertFalse([call for call in calls if c[4] in " ".join(call)])
        self.passes(c[5])  # the 30th newest
        _, _, refs = self.promote(dry_run=False)
        self.assertEqual(refs.get("stable"), c[5])

    def test_an_api_failure_moves_nothing(self):
        """Failing to read c[2]'s runs must not let stable move to the older c[1]."""
        c = self.main_history(3)
        self.refs["stable"] = c[0]
        self.passes(c[1])
        self.passes(c[2])
        self.broken[f"head_sha={c[2]}"] = "Server Error (HTTP 500)"
        out, calls, refs = self.promote(dry_run=False, returncode=1)
        self.assertNotIn(c[1], out)
        self.assertEqual(self.writes(calls), [])
        self.assertEqual(refs.get("stable"), c[0])

    def test_a_refused_write_fails_the_run(self):
        """A write GitHub refuses anyway fails the run loudly and leaves stable."""
        for stable in (None, sha(1)):
            with self.subTest(stable=stable):
                self.setUp()
                c = self.main_history(2)
                if stable:
                    self.refs["stable"] = stable
                self.passes(c[1])
                self.broken["git/refs"] = "Resource not accessible by integration (HTTP 403)"
                out, calls, refs = self.promote(dry_run=False, returncode=1)
                self.assertEqual(len(self.writes(calls)), 1)
                self.assertNotIn("created stable", out)
                self.assertNotIn("fast-forwarded stable", out)
                self.assertEqual(refs.get("stable"), stable)


if __name__ == "__main__":
    unittest.main()
