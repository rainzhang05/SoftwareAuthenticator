"""Shared actual installer PTY and HID helpers (no setup implementation)."""
import errno
import os
import pty
import re
import select
import signal
import subprocess
import time

BINARY = '/usr/local/bin/pqkey'


def run(command, env, responses=(), timeout=120):
    """Bound the real installer and its child group; never include private input in errors."""
    master = slave = process = None
    try:
        if not responses:
            process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                output, _ = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                raise TimeoutError('installer timed out; output withheld') from None
            return process.returncode, output.decode(errors='replace')
        master, slave = pty.openpty()
        process = subprocess.Popen(command, env=env, stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True)
        os.close(slave)
        slave = None
        output = dialogue = b''
        pending = list(responses)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([master], [], [], .1)[0]:
                try:
                    chunk = os.read(master, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output += chunk
                dialogue += chunk
                if pending and pending[0][0].encode() in dialogue:
                    _, answer = pending.pop(0)
                    os.write(master, (answer + '\n').encode())
                    dialogue = b''
            elif process.poll() is not None:
                break
        if process.poll() is None:
            # A PTY may close just before the process is reaped.
            try:
                process.wait(timeout=min(1, max(.01, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                raise TimeoutError('installer dialogue timed out; private output withheld') from None
        if pending:
            raise RuntimeError('installer dialogue incomplete; private output withheld')
        if any(answer.encode() in output for _, answer in responses):
            raise RuntimeError('installer echoed private input; output withheld')
        return process.returncode, output.decode(errors='replace')
    finally:
        if process is not None:
            # Every group was created above, including noninteractive installer children.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        for descriptor in (master, slave):
            if descriptor is not None:
                os.close(descriptor)


def node(env):
    status, output = run([BINARY, 'status'], env)
    assert status == 0, output
    found = re.search(r'^Device:\s+(/dev/hidraw\d+)$', output, re.MULTILINE)
    assert found, output
    return found[1]
