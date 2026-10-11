#!/usr/bin/python3
"""Built executable fixture; real setup orchestration is tested in Rust/E2E."""
import getpass
import json
import os
from pathlib import Path
import sys

with open(os.environ["COMMAND_TRACE"], "a") as trace:
    trace.write(json.dumps(["pqkey", *sys.argv[1:]]) + "\n")
if os.environ.get("FAIL_SETUP"):
    print("pqkey: setup incomplete; run pqkey pin or repair the reported blocker", file=sys.stderr)
    sys.exit(1)
state = Path(os.environ["HOME"]) / "pin-set"
if not state.exists():
    if not sys.stdin.isatty():
        print("pqkey: PIN setup incomplete; run pqkey pin in a terminal", file=sys.stderr)
        sys.exit(1)
    first = getpass.getpass("New PIN: ")
    second = getpass.getpass("Confirm new PIN: ")
    if len(first) < 4 or first != second:
        print("pqkey: PIN setup incomplete; run pqkey pin", file=sys.stderr)
        sys.exit(1)
    state.write_text("configured")
print("pqkey is ready.")
