"""Calls the installed daemon's system call filter refuses, from kernel audit records.

The shipped unit runs the daemon with SystemCallFilter=@system-service and
SystemCallErrorNumber=EPERM. A refused call fails its operation instead of
killing the daemon, and some refusals only degrade it quietly, so functional
checks can pass while the filter refuses something. Two harnesses judge the
filter's seccomp records (audit type 1326) by the rules here instead: the
installer E2E on every push (test_setup.py, through FilterCheck) and the
manual installed desktop acceptance (desktop_acceptance.py).

Both prepare their disposable host before its user manager starts
(.github/workflows/e2e.yml, scripts/desktop-acceptance.sh):
- the manager runs with SYSTEMD_LOG_SECCOMP=1, which has systemd flag every
  seccomp filter it installs for logging; SystemCallLog= cannot log the calls
  an EPERM filter refuses;
- kernel.printk_ratelimit=0: without auditd, audit records reach the journal
  through the kernel log, which otherwise passes 10 messages per 5 seconds.
A canary refusal before the first daemon starts proves that refusals reach
the journal, and another after the last one stops that every record in
between has been read. No HID imports.
"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

from setup_support import BINARY

UNIT = 'pqkey.service'
# chroot is outside @system-service and fails unprivileged anyway: a harmless
# call the filter refuses, which proves that refusals reach the journal.
CANARY = 'import os\nprint(os.getpid(), flush=True)\ntry:\n    os.chroot("/")\nexcept PermissionError:\n    pass\n'
# The audit record's code is the seccomp action alone, without the errno.
SECCOMP_RET_ERRNO = '0x50000'
# clone3 by audit architecture (x86_64, aarch64). No filter can see clone3's
# flags, so for RestrictNamespaces= systemd's seccomp_restrict_namespaces()
# fails every clone3, with ENOSYS so that glibc falls back to clone(). As the
# filter allows clone3 (unit_filter), these records are ignored, not refused.
CLONE3 = {('c000003e', '435'), ('c00000b7', '435')}
# journald's "Missed N kernel messages".
JOURNAL_MISSED = 'MESSAGE_ID=e9bf28e6e834481bb6f48f548ad13606'
AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
# What unit_filter reads from `systemctl show`.
FILTER_PROPERTIES = '--property=DropInPaths,SystemCallErrorNumber,SystemCallFilter'


def audit_record(line):
    """The fields of a kernel audit record, with hex-encoded comm and exe decoded."""
    fields = {}
    for key, value in AUDIT_FIELD.findall(line.split('): ', 1)[-1]):
        if value.startswith('"'):
            value = value[1:-1]
        elif key in ('comm', 'exe') and re.fullmatch(r'(?:[0-9A-F]{2})+', value):
            value = bytes.fromhex(value).decode(errors='replace')
        fields[key] = value
    return fields


def syscall_names(header=Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')):
    try:
        return {number: name for name, number in re.findall(r'#define __NR_(\w+) (\d+)', header.read_text())}
    except OSError:
        return {}


def seccomp_check(lines, *, daemon_pids, canaries, uid, names=None):
    """Sort the journal's seccomp records (audit type 1326) and audit losses.

    A record names the daemon by its executable, by systemd's executor before
    it executes the daemon ("(pqkey)"), or by a process ID the run observed.
    Its clone3 records (CLONE3) are ignored, not refused. Each row keeps its
    whole record.
    """
    names = names or {}
    found = {'daemon': [], 'ignored': [], 'canaries': {phase: False for phase in canaries}, 'other': [], 'lost': []}
    for line in lines:
        if 'audit_lost=' in line:
            found['lost'].append(line)
        if 'audit: type=1326 ' not in line:
            continue
        record = audit_record(line)
        row = {key: record.get(key) for key in ('pid', 'uid', 'comm', 'exe', 'arch', 'syscall', 'code')}
        if record.get('arch') == 'c000003e':
            row['name'] = names.get(record.get('syscall'))
        row['record'] = line
        canary = next((phase for phase, pid in canaries.items() if pid == record.get('pid')), None)
        if canary:
            found['canaries'][canary] |= record.get('code') == SECCOMP_RET_ERRNO
        elif (record.get('exe') in (BINARY, BINARY + ' (deleted)') or record.get('comm') == '(pqkey)'
              or record.get('pid') in daemon_pids):
            clone3 = (record.get('arch'), record.get('syscall')) in CLONE3 and record.get('code') == SECCOMP_RET_ERRNO
            found['ignored' if clone3 else 'daemon'].append(row)
        elif record.get('uid') == uid:
            found['other'].append(row)
    return found


def problems(found, missed, filters):
    """Why a check fails, naming the offending records: any refusal of the
    daemon, a canary refusal not journaled, lost records or kernel messages
    (missed), or daemons under differing numbers of seccomp filters (filters:
    the distinct counts)."""
    reasons = [f"refused {row.get('name') or 'syscall'} {row.get('syscall')}: {row.get('record')}"
               for row in found['daemon']]
    reasons += [f'canary refusal not journaled: {phase}' for phase, seen in found['canaries'].items() if not seen]
    reasons += [f'audit records lost: {line}' for line in found['lost']]
    reasons += [f'kernel messages lost: {line}' for line in missed]
    if len(filters) != 1:
        reasons.append('daemons ran under differing seccomp filter counts: ' + ', '.join(sorted(filters))
                       if filters else 'no daemon was observed')
    return reasons


# The host commands. `command(argv, check=True)` runs one and returns its
# standard output, stripped; with check=False a failure returns it too.

def require_logging(command, manager_pid, *, proc=Path('/proc')):
    """Fail unless the kernel journals every call the user manager's filters refuse."""
    assert 'errno' in (proc / 'sys/kernel/seccomp/actions_logged').read_text().split(), 'refusals not logged'
    assert (proc / 'sys/kernel/printk_ratelimit').read_text().strip() == '0', 'audit records may be dropped'
    flag = command(['sudo', '-n', 'grep', '-czx', 'SYSTEMD_LOG_SECCOMP=1', str(proc / str(manager_pid) / 'environ')],
                   check=False)
    assert flag == '1', 'user manager does not flag seccomp filters for logging'


def journal_cursor(command):
    """Where the system journal ends, before the check begins."""
    return json.loads(command(['sudo', '-n', 'journalctl', '--system', '-n', '1', '-o', 'json',
                               '--output-fields=__CURSOR']))['__CURSOR']


def kernel_audit(command, cursor):
    """The kernel's seccomp records and audit losses since the cursor."""
    return command(['sudo', '-n', 'journalctl', '-q', '-k', '--no-pager', '-o', 'cat',
                    '--after-cursor=' + cursor, '--grep=^audit: (type=1326 |audit_lost=)'],
                   check=False).splitlines()


def missed_messages(command, cursor):
    """journald's reports, since the cursor, of kernel messages it lost."""
    return command(['sudo', '-n', 'journalctl', '-q', '--system', '--no-pager', '-o', 'cat',
                    '--after-cursor=' + cursor, JOURNAL_MISSED], check=False).splitlines()


def run_canary(command):
    """Have a transient unit under the filter make one refused call; returns its process ID."""
    # --pipe and --wait reach the user manager over the user bus, not over a
    # test's own session bus.
    pid = command(['env', '-u', 'DBUS_SESSION_BUS_ADDRESS', 'systemd-run', '--user', '--pipe', '--wait',
                   '--quiet', '--collect', '-p', 'NoNewPrivileges=yes',
                   '-p', 'SystemCallFilter=@system-service', '-p', 'SystemCallErrorNumber=EPERM',
                   '/usr/bin/python3', '-I', '-c', CANARY])
    assert pid.isdigit(), 'canary did not report its process ID'
    return pid


def await_canary(command, cursor, phase, pid, *, seconds=15, clock=time.monotonic, sleep=time.sleep):
    """The records since the cursor once the canary's refusal is among them, or
    at the deadline; and whether it is."""
    deadline = clock() + seconds
    while True:
        lines = kernel_audit(command, cursor)
        seen = seccomp_check(lines, daemon_pids=(), canaries={phase: pid}, uid=str(os.getuid()))['canaries'][phase]
        if seen or clock() > deadline:
            return lines, seen
        sleep(1)


def unit_filter(shown):
    """The filter in `systemctl show UNIT FILTER_PROPERTIES`: its properties and allowed calls.

    Fails unless refused calls return EPERM, and unless the filter allows
    clone3, so that the daemon's clone3 records come from RestrictNamespaces=.
    """
    properties = dict(line.split('=', 1) for line in shown.splitlines())
    allowed = properties['SystemCallFilter'].split()
    assert properties['SystemCallErrorNumber'] == '1' and 'read' in allowed and 'chroot' not in allowed
    assert 'clone3' in allowed, 'filter refuses clone3; its records would be refusals'
    return properties, allowed


def host(argv, *, check=True):
    """A host command of FilterCheck; nothing private is in its output."""
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, encoding='utf-8',
                            errors='replace', timeout=30)
    if check and result.returncode:
        raise RuntimeError(f'{shlex.join(argv)} exited with status {result.returncode}: {result.stderr.strip()}')
    return result.stdout.strip()


class FilterCheck:
    """The installer E2E's check of the installed service under the shipped unit's filter.

    begin() before the first install, observe() each time the service runs a
    new daemon, and finish() once the service has stopped. A canary's record
    has `seconds` to reach the journal.
    """

    def __init__(self, command=host, *, proc=Path('/proc'), seconds=15):
        self.command, self.proc, self.seconds = command, proc, seconds
        self.uid = str(os.getuid())
        self.cursor = None
        self.canaries = {}
        self.daemons = {}

    def begin(self):
        """Fail unless refusals are journaled, as the start canary's must be."""
        manager = self.command(['systemctl', 'show', f'user@{self.uid}.service', '--property=MainPID', '--value'])
        assert manager.isdigit() and manager != '0', 'the user manager does not run'
        require_logging(self.command, manager, proc=self.proc)
        self.cursor = journal_cursor(self.command)
        assert self.canary('start')[1], 'refused system calls do not reach the journal'

    def canary(self, phase):
        pid = self.canaries[phase] = run_canary(self.command)
        return await_canary(self.command, self.cursor, phase, pid, seconds=self.seconds)

    def observe(self):
        """Name the service's running daemon by its process ID, and keep its seccomp state."""
        unit_filter(self.command(['systemctl', '--user', 'show', UNIT, FILTER_PROPERTIES]))
        pid = self.command(['systemctl', '--user', 'show', UNIT, '--property=MainPID', '--value'])
        assert pid.isdigit() and pid != '0', f'{UNIT} does not run'
        status = dict(line.split(':', 1) for line in (self.proc / pid / 'status').read_text().splitlines()
                      if ':' in line)
        self.daemons[pid] = {key: status.get(key, '').strip() for key in ('Seccomp', 'Seccomp_filters')}
        return pid

    def finish(self):
        """Once the service has stopped: the records since begin(), a summary,
        and why the check fails (nothing if it passes)."""
        lines, _ = self.canary('end')
        missed = missed_messages(self.command, self.cursor)
        found = seccomp_check(lines, daemon_pids=set(self.daemons), canaries=self.canaries, uid=self.uid,
                              names=syscall_names())
        filters = {daemon['Seccomp_filters'] for daemon in self.daemons.values()}
        reasons = problems(found, missed, filters)
        # Seccomp mode 2: the process runs under seccomp filters.
        reasons += [f"daemon {pid} ran without a seccomp filter (Seccomp: {daemon['Seccomp']})"
                    for pid, daemon in self.daemons.items() if daemon['Seccomp'] != '2']
        summary = '; '.join([
            'PASS' if not reasons else 'FAILED',
            f"refused calls for pqkey: {len(found['daemon'])}",
            f"ignored clone3 calls (RestrictNamespaces= ENOSYS): {len(found['ignored'])}",
            'canaries: ' + ', '.join(f"{phase} {'logged' if seen else 'MISSING'}"
                                     for phase, seen in found['canaries'].items()),
            f"lost records: {len(found['lost']) + len(missed)}",
            f'daemons: {len(self.daemons)}, filter counts: ' + '/'.join(sorted(filters)),
        ])
        return lines, summary, reasons
