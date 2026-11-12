#!/usr/bin/python3
"""Built executable fixture; real setup orchestration is tested in Rust/E2E."""
import getpass
import json
import os
from pathlib import Path
import sys
import time

with open(os.environ["COMMAND_TRACE"], "a") as trace:
    trace.write(json.dumps(["pqkey", *sys.argv[1:]]) + "\n")
    # The variables install.sh clears for what it runs itself (command.py's LOADER).
    loader = sorted(name for name in os.environ if name.startswith("LD_") or name in (
        "GCONV_PATH", "GETCONF_DIR", "GLIBC_TUNABLES", "HOSTALIASES", "LOCALDOMAIN", "LOCPATH",
        "MALLOC_ARENA_MAX", "MALLOC_ARENA_TEST", "MALLOC_MMAP_MAX_", "MALLOC_MMAP_THRESHOLD_",
        "MALLOC_PERTURB_", "MALLOC_TOP_PAD_", "MALLOC_TRACE", "MALLOC_TRIM_THRESHOLD_", "NIS_PATH",
        "NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TMPDIR", "TZDIR"))
    if loader:
        trace.write(json.dumps(["loader", "pqkey", *loader]) + "\n")
    if "SUDO_ASKPASS" in os.environ:
        trace.write(json.dumps(["askpass variable", "pqkey"]) + "\n")
    trace.write(json.dumps(["setup PATH", os.environ.get("PATH", "")]) + "\n")
# Setup taking its time, as when you take yours over the PIN.
time.sleep(float(os.environ.get("SETUP_SECONDS", "0")))
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
# As setup.rs's path_problem: the first executable pqkey on PATH must be this one.
binary = Path(sys.argv[0]).resolve()
found = next((candidate for candidate in (Path(entry, "pqkey") for entry in os.environ.get("PATH", "").split(":"))
              if candidate.is_file() and os.access(candidate, os.X_OK)), None)
if found is None or found.resolve() != binary:
    print(f"pqkey: {binary.parent} is not on your PATH" if found is None else
          f"pqkey: `pqkey` runs {found}, not {binary}", file=sys.stderr)
    print("pqkey: setup is incomplete; fix the above, then rerun `pqkey setup`", file=sys.stderr)
    sys.exit(1)
print("pqkey is ready.")
