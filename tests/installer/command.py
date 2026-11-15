#!/usr/bin/python3
"""Controlled prerequisites for install.sh, only inside its disposable container."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def record(*entry):
    with open(os.environ["COMMAND_TRACE"], "a") as trace:
        trace.write(json.dumps(list(entry)) + "\n")


# Commands planted in your directories, by name: install.sh's own and more.
PLANTED = ("sudo", "sleep", "tee", "dirname", "ln", "tail", "tr", "grep", "sed", "wc", "setsid", "mkdir",
           "cut", "sort", "head", "awk", "df", "uname", "id", "git", "bash", "sh", "env", "cat", "stat",
           "kill", "install", "mv", "cp", "rm", "cc", "setfacl", "apt-get", "curl")


def plant(directory):
    """Recording commands in DIRECTORY, by the names in PLANTED, that then run the
    fixture's (or the system's) command."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for tool in PLANTED:
        entry = json.dumps(["planted", tool, str(directory)])
        planted = directory / tool
        planted.unlink(missing_ok=True)
        planted.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' '{entry}' >>\"$COMMAND_TRACE\"\n"
            f"for real in \"$FIXTURE_BIN/{tool}\" /usr/bin/{tool} /bin/{tool}; do\n"
            "  [ -x \"$real\" ] && exec \"$real\" \"$@\"\n"
            "done\n"
            "exit 127\n")
        planted.chmod(0o755)


def third_party(what):
    """Code that is not pqkey's own runs with no password cached."""
    if Path(os.environ["SUDO_TICKET"]).exists():
        print(f"fixture: sudo had a password cached while {what} ran", file=sys.stderr)
        sys.exit(18)


name = Path(sys.argv[0]).name.removesuffix("-source")
args = sys.argv[1:]
# The version rustup last installed as stable; until then rustc reports RUST_VERSION.
stable = Path(os.environ["HOME"], "stable-version")
record(name, *args)
command = " ".join([name, *args])
if "SUDO_ASKPASS" in os.environ:
    record("askpass variable", command)
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
    # The password sudo caches, as with its default timestamp_type (tty): one
    # ticket, which every process of the installation can use. -v caches it,
    # asking for the password unless it is cached: on the terminal, /dev/tty,
    # where the prompt is printed and the fixture's user answers; without one,
    # through a helper (SUDO_ASKPASS, else SUDO_CONF_ASKPASS for sudo.conf's
    # askpass), as you, if DISPLAY is set; else it fails. -n fails rather than
    # ask; -k forgets it, except with SUDO_K_MISSES_TICKET, as sudo 1.9.17 and
    # earlier with timestamp_type=kernel on Linux; -K forgets every one. With
    # SUDO_NOPASSWD, as with a NOPASSWD rule, no password is needed. SUDO_ANSWER
    # is how the prompt is answered: "wrong", a wrong password three times; or
    # "Ctrl-C", which the terminal sends to its foreground process group, sudo's.
    ticket = Path(os.environ["SUDO_TICKET"])
    options, prompt = [], "[sudo] password for %p: "
    while args and args[0].startswith("-"):
        options.append(args.pop(0))
        if options[-1] == "-p":
            prompt = args.pop(0)
    if "-K" in options or ("-k" in options and not os.environ.get("SUDO_K_MISSES_TICKET")):
        ticket.unlink(missing_ok=True)
    if "-k" in options or "-K" in options:
        sys.exit(0)
    if not ticket.exists() and not os.environ.get("SUDO_NOPASSWD"):
        if "-n" in options:
            print("sudo: a password is required", file=sys.stderr)
            sys.exit(1)
        prompt = prompt.replace("%p", "tester")
        askpass = os.environ.get("SUDO_ASKPASS") or os.environ.get("SUDO_CONF_ASKPASS")
        try:
            os.close(os.open("/dev/tty", os.O_RDWR))
            print(prompt, file=sys.stderr)
        except OSError:
            if not (askpass and os.environ.get("DISPLAY")):
                print("sudo: a terminal is required to read the password", file=sys.stderr)
                sys.exit(1)
            subprocess.run([askpass, prompt], stdout=subprocess.DEVNULL)
        if os.environ.get("SUDO_ANSWER") == "wrong":
            print("sudo: 3 incorrect password attempts", file=sys.stderr)
            sys.exit(1)
        if os.environ.get("SUDO_ANSWER") == "Ctrl-C":
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            os.killpg(0, signal.SIGINT)
        ticket.touch()
    # What it runs it finds as with sudo's secure_path: here the fixture's commands first.
    path = f"{os.environ['FIXTURE_BIN']}:/usr/sbin:/usr/bin:/sbin:/bin"
    sys.exit(0 if "-v" in options or not args else subprocess.call(args, env=dict(os.environ, PATH=path)))
elif name == "rustc":
    print(f"rustc {stable.read_text() if stable.exists() else os.environ.get('RUST_VERSION', '1.89.0')}")
elif name == "rustup":
    if args == ["toolchain", "list"]:
        # As rustup 1.28 and later in the clone: unless told not to, it installs the
        # components rust-toolchain.toml names, which updates a stable lacking them.
        if os.environ.get("MISSING_COMPONENTS") and os.environ.get("RUSTUP_AUTO_INSTALL") != "0":
            print("info: syncing channel updates for 'stable-aarch64-unknown-linux-gnu'", file=sys.stderr)
            stable.write_text(os.environ.get("LATEST_RUST_VERSION", "1.99.0"))
            record("rustup", "installed by itself")
        print(os.environ.get("TOOLCHAINS", "stable-aarch64-unknown-linux-gnu"))
    elif args[:3] == ["toolchain", "install", "stable"]:
        third_party("rustup toolchain install")
        stable.write_text(os.environ.get("LATEST_RUST_VERSION", "1.99.0"))
elif name == "cargo":
    if "build" in args:
        # Build scripts and proc macros could run sudo -n, which works whenever
        # sudo has a password cached: none may be, from start to end.
        ticket = Path(os.environ["SUDO_TICKET"])
        third_party("the build")
        # Commands the build plants in your directories (PLANT), recording any run.
        for directory in filter(None, os.environ.get("PLANT", "").split(":")):
            plant(directory)
        if os.environ.get("REWRITE_INSTALLER"):
            # install.sh, in place, from the command after the build on, as bash
            # would read it next if it read the script as it went.
            with open("install.sh", "r+b") as script:
                text = script.read()
                script.seek(text.index(b'step 60 cargo "Building pqkey" "pqkey built" build\n') + 51)
                script.write(b'printf \'["installer rewritten"]\\n\' >>"$COMMAND_TRACE"; exit 0\n')
        time.sleep(float(os.environ.get("BUILD_SECONDS", "0")))
        if ticket.exists():
            print("fixture: sudo had a password cached during the build", file=sys.stderr)
            sys.exit(18)
        target = Path("target/release/pqkey")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(Path(os.environ["PQKEY_TEMPLATE"]).read_text() +
                          f"\n# version {os.environ.get('BUILD_VERSION', 'new')}\n")
        target.chmod(0o755)
elif name == "curl":
    # rustup installer installed at the custom Cargo home used by this fixture.
    third_party("the Rust installer")
    print('mkdir -p "$CARGO_HOME/bin"')
    for tool in ("cargo", "rustup", "rustc"):
        print(f'ln -sf "$FIXTURE_BIN/{tool}-source" "$CARGO_HOME/bin/{tool}"')
elif name in ("install", "mv", "cp", "rm"):
    sys.exit(subprocess.call([f"/usr/bin/{name}", *args]))
# Package managers, cc and setfacl succeed unless explicitly faulted.
