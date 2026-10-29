#!/usr/bin/python3
"""Controlled prerequisites for install.sh, only inside its disposable container."""
import json
import os
from pathlib import Path
import subprocess
import sys

name = Path(sys.argv[0]).name.removesuffix("-source")
args = sys.argv[1:]
# The version rustup last installed as stable; until then rustc reports RUST_VERSION.
stable = Path(os.environ["HOME"], "stable-version")
with open(os.environ["COMMAND_TRACE"], "a") as trace:
    trace.write(json.dumps([name, *args]) + "\n")
command = " ".join([name, *args])
if command == os.environ.get("FAIL_COMMAND") or name == os.environ.get("FAIL_COMMAND"):
    print(f"fixture: {command} failed", file=sys.stderr)
    sys.exit(17)
if name in ("rustc", "rustup") and "RUST_STDERR" in os.environ:
    print(os.environ["RUST_STDERR"], file=sys.stderr)
if name == "uname":
    print(os.environ.get("FIXTURE_OS", "Linux"))
elif name == "id":
    print("1000" if "-u" in args else "tester")
elif name == "df":
    print("Filesystem 1048576-blocks Used Available Capacity Mounted on")
    print(f"fixture 10000 0 {os.environ.get('FREE_MB', '10000')} 0% /")
elif name == "sudo":
    if args[0] in ("-v", "-n"):
        args = args[1:]
    if not args or args[0] == "-v" or args[0] == "-p":
        sys.exit(0)
    sys.exit(subprocess.call(args))
elif name == "rustc":
    print(f"rustc {stable.read_text() if stable.exists() else os.environ.get('RUST_VERSION', '1.89.0')}")
elif name == "rustup":
    if args == ["toolchain", "list"]:
        # As rustup 1.28 and later in the clone: unless told not to, it installs the
        # components rust-toolchain.toml names, which updates a stable lacking them.
        if os.environ.get("MISSING_COMPONENTS") and os.environ.get("RUSTUP_AUTO_INSTALL") != "0":
            print("info: syncing channel updates for 'stable-aarch64-unknown-linux-gnu'", file=sys.stderr)
            stable.write_text(os.environ.get("LATEST_RUST_VERSION", "1.99.0"))
        print(os.environ.get("TOOLCHAINS", "stable-aarch64-unknown-linux-gnu"))
    elif args[:3] == ["toolchain", "install", "stable"]:
        stable.write_text(os.environ.get("LATEST_RUST_VERSION", "1.99.0"))
elif name == "cargo":
    if "build" in args:
        target = Path("target/release/pqkey")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(Path(os.environ["PQKEY_TEMPLATE"]).read_text() +
                          f"\n# version {os.environ.get('BUILD_VERSION', 'new')}\n")
        target.chmod(0o755)
elif name == "curl":
    # rustup installer installed at the custom Cargo home used by this fixture.
    print('mkdir -p "$CARGO_HOME/bin"')
    print('ln -sf "$FIXTURE_BIN/cargo-source" "$CARGO_HOME/bin/cargo"')
    print('ln -sf "$FIXTURE_BIN/rustup-source" "$CARGO_HOME/bin/rustup"')
elif name in ("install", "mv", "cp", "rm"):
    sys.exit(subprocess.call([f"/usr/bin/{name}", *args]))
# Package managers, cc and setfacl succeed unless explicitly faulted.
