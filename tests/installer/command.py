#!/usr/bin/python3
"""Controlled prerequisites for install.sh, only inside its disposable container."""
import ctypes
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import threading
import time


def record(*entry):
    with open(os.environ["COMMAND_TRACE"], "a") as trace:
        trace.write(json.dumps(list(entry)) + "\n")


# What install.sh clears before anything runs and gives back only to what it
# runs alone: every LD_ variable, and the others of glibc's unsecvars.h.
LOADER = ("GCONV_PATH", "GETCONF_DIR", "GLIBC_TUNABLES", "HOSTALIASES", "LOCALDOMAIN", "LOCPATH",
          "MALLOC_ARENA_MAX", "MALLOC_ARENA_TEST", "MALLOC_MMAP_MAX_", "MALLOC_MMAP_THRESHOLD_",
          "MALLOC_PERTURB_", "MALLOC_TOP_PAD_", "MALLOC_TRACE", "MALLOC_TRIM_THRESHOLD_", "NIS_PATH",
          "NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TMPDIR", "TZDIR")
# Commands planted in your directories, by name: install.sh's own and more.
PLANTED = ("sudo", "sleep", "tee", "dirname", "ln", "tail", "tr", "grep", "sed", "wc", "setsid", "mkdir",
           "cut", "sort", "head", "awk", "df", "uname", "id", "git", "bash", "sh", "env", "cat", "stat",
           "kill", "install", "mv", "cp", "rm", "cc", "setfacl", "apt-get", "curl")


def loader_variables():
    return [f"{name}={value}" for name, value in sorted(os.environ.items())
            if name.startswith("LD_") or name in LOADER]


def plant(directory):
    """Recording commands in DIRECTORY, by the names in PLANTED, that then run the
    fixture's (or the system's) command. Each records whether it ran in the
    installer's session (INSTALLER_SID), where only install.sh's own commands run."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for tool in PLANTED:
        entry = json.dumps(["planted", tool, str(directory)])[:-1]
        planted = directory / tool
        planted.unlink(missing_ok=True)
        planted.write_text(
            "#!/bin/sh\n"
            "where() { set -- $1; [ \"$4\" = \"$INSTALLER_SID\" ] && echo installer || echo own; }\n"
            "read -r stat </proc/self/stat\n"
            "stat=${stat##*) }\n"
            f"printf '%s, \"%s session\"]\\n' '{entry}' \"$(where \"$stat\")\" >>\"$COMMAND_TRACE\"\n"
            f"for real in \"$FIXTURE_BIN/{tool}\" /usr/bin/{tool} /bin/{tool}; do\n"
            "  [ -x \"$real\" ] && exec \"$real\" \"$@\"\n"
            "done\n"
            "exit 127\n")
        planted.chmod(0o755)


def env_file(path):
    """What rustup's env file does, PATH first, plus a recording function for each
    name in PLANTED: what a Rust installer, or an earlier build, could leave."""
    functions = "".join(f"{tool}() {{ printf '[\"env function\", \"{tool}\"]\\n' >>\"$COMMAND_TRACE\"; "
                        f"command {tool} \"$@\"; }}\n" for tool in PLANTED)
    Path(path).write_text(f'export PATH="{Path(path).parent}/bin:$PATH"\n' + functions)


def running(pid):
    """Whether process PID still runs: a zombie only while threads of its process do."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X") or len(os.listdir(f"/proc/{pid}/task")) > 1
    except (OSError, IndexError):
        return False


def third_party(what):
    """Code that is not pqkey's own runs with no password cached, outside the
    installer's session (INSTALLER_SID: the session the test started it in)."""
    if Path(os.environ["SUDO_TICKET"]).exists():
        print(f"fixture: sudo had a password cached while {what} ran", file=sys.stderr)
        sys.exit(18)
    if os.environ.get("INSTALLER_SID") and os.getsid(0) == int(os.environ["INSTALLER_SID"]):
        print(f"fixture: {what} ran in the installer's session", file=sys.stderr)
        sys.exit(19)


def leave_behind(shape, ticket, listed):
    """What a build script could leave running, in the build's session but out of
    its process group, deaf to HUP, INT and TERM, waiting for sudo to cache a
    password, for 30 s at most. Shapes: plain; newline (a name holding a
    newline); thread (its main thread gone, another one waiting); hop (a new PID
    every fork); chain (each process forks the next at once, lingers 5 ms and
    exits, so that several are alive at a time)."""
    os.setpgid(0, 0)
    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(number, signal.SIG_IGN)
    if shape == "newline":
        Path("/proc/self/comm").write_text("left\nbehind")
    if listed:
        with open(listed, "a") as pids:
            pids.write(f"{os.getpid()}\n")

    def wait():
        deadline = time.monotonic() + 30
        while not ticket.exists() and time.monotonic() < deadline:
            if shape in ("hop", "chain") and os.fork():
                time.sleep(0.005 if shape == "chain" else 0)
                os._exit(0)
            time.sleep(0.001 if shape == "hop" else 0 if shape == "chain" else 0.01)
        if ticket.exists():
            record("left running", "found a password cached")
        os._exit(0)

    if shape == "thread":
        threading.Thread(target=wait).start()
        libc = ctypes.CDLL(None)
        libc.syscall({"x86_64": 60, "aarch64": 93}[platform.machine()], 0)  # SYS_exit: this thread only
    wait()


name = Path(sys.argv[0]).name.removesuffix("-source")
args = sys.argv[1:]
# The version rustup last installed as stable; until then rustc reports RUST_VERSION.
stable = Path(os.environ["HOME"], "stable-version")
record(name, *args)
command = " ".join([name, *args])
if loader_variables():
    record("loader", command, *loader_variables())
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
        # Whatever the build started (BUILD_PIDS) must be gone before sudo asks.
        built = Path(os.environ.get("BUILD_PIDS", "/nonexistent"))
        for pid in built.read_text().split() if built.exists() else ():
            if running(pid):
                record("left running", "when sudo asked")
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
    sys.exit(0 if "-v" in options or not args else subprocess.call(args))
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
        record("installer shell", os.readlink(f"/proc/{os.getppid()}/exe"))  # the bash running install.sh
        signal.signal(signal.SIGTERM, lambda *_: (record("cargo", "stopped by TERM"), os._exit(143)))
        built = os.environ.get("BUILD_PIDS")  # where the build's processes are listed
        if built:
            with open(built, "a") as pids:
                pids.write(f"{os.getpid()}\n")
        if os.environ.get("LEAVE_BEHIND") and os.fork() == 0:
            leave_behind(os.environ["LEAVE_BEHIND"], ticket, built)
        # Commands the build plants in your directories (PLANT), recording any run.
        for directory in filter(None, os.environ.get("PLANT", "").split(":")):
            plant(directory)
        if os.environ.get("REWRITE_HOOK"):
            # A file your shell's startup files source, as a DEBUG trap might.
            Path(os.environ["HOME"], ".hook").write_text(
                'printf \'["hook ran"]\\n\' >>"$COMMAND_TRACE"\n')
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
    if os.environ.get("RUST_INSTALLER_PLANTS"):
        # With rustup's env file holding functions, and commands planted in the
        # directories RUST_INSTALLER_PLANTS lists, made yours: rustup's among them.
        for directory in os.environ["RUST_INSTALLER_PLANTS"].split(":"):
            plant(directory)
            os.chown(directory, 1000, 1000)
        env_file(Path(os.environ["CARGO_HOME"], "env"))
    print('mkdir -p "$CARGO_HOME/bin"')
    for tool in ("cargo", "rustup", "rustc"):
        print(f'ln -sf "$FIXTURE_BIN/{tool}-source" "$CARGO_HOME/bin/{tool}"')
elif name in ("install", "mv", "cp", "rm"):
    sys.exit(subprocess.call([f"/usr/bin/{name}", *args]))
# Package managers, cc and setfacl succeed unless explicitly faulted.
