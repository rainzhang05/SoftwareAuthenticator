"""Offline regressions of the refused-call check shared by the installer E2E
and the desktop acceptance; no installed service, journal or kernel."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'e2e'))
import seccomp_audit as audit

UID = str(os.getuid())
DAEMON = f'"{audit.BINARY}"'
# A replaced binary's executable, which audit logs hex-encoded.
DELETED = (audit.BINARY + ' (deleted)').encode().hex().upper()
LOST = 'audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=64'


def record(pid, comm, exe, *, uid=UID, arch='c000003e', syscall='161', code='0x50000'):
    return (f'audit: type=1326 audit(1793057204.506:129): auid={uid} uid={uid} gid={uid} ses=3 subj=unconfined '
            f'pid={pid} comm={comm} exe={exe} sig=0 arch={arch} syscall={syscall} compat=0 ip=0x7f00 code={code}')


class Host:
    """The host commands of FilterCheck, answered from this state. Each canary
    journals its refusal unless journal_canaries is false."""

    def __init__(self, proc):
        self.proc = proc
        self.manager = '700'
        self.flag = '1'
        self.kernel = []
        self.missed = []
        self.journal_canaries = True
        self.next_canary = 901
        self.allowed = 'clone3 read write'
        self.service = '0'
        self.calls = []

    def start(self, pid, *, seccomp='2', filters='14'):
        """The service runs a new daemon."""
        (self.proc / pid).mkdir()
        (self.proc / pid / 'status').write_text(f'Name:\tpqkey\nSeccomp:\t{seccomp}\nSeccomp_filters:\t{filters}\n')
        self.service = pid

    def __call__(self, argv, check=True):
        self.calls.append(argv)
        if argv[:2] == ['systemctl', 'show']:
            return self.manager
        if argv[:3] == ['sudo', '-n', 'grep']:
            return self.flag
        if argv[:3] == ['sudo', '-n', 'journalctl']:
            if '-k' in argv:
                return '\n'.join(self.kernel)
            if audit.JOURNAL_MISSED in argv:
                return '\n'.join(self.missed)
            return json.dumps({'__CURSOR': 's=cursor;i=1', '__REALTIME_TIMESTAMP': '1'})
        if 'systemd-run' in argv:
            pid = str(self.next_canary)
            self.next_canary += 1
            if self.journal_canaries:
                self.kernel.append(record(pid, '"python3"', '"/usr/bin/python3.12"'))
            return pid
        if argv[:4] == ['systemctl', '--user', 'show', audit.UNIT]:
            if argv[-1] == '--value':
                return self.service
            return f'DropInPaths=\nSystemCallErrorNumber=1\nSystemCallFilter={self.allowed}'
        raise AssertionError(f'unexpected command {argv}')


class Check(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.proc = Path(directory.name)
        (self.proc / 'sys/kernel/seccomp').mkdir(parents=True)
        (self.proc / 'sys/kernel/seccomp/actions_logged').write_text(
            'kill_process kill_thread trap errno user_notif trace log\n')
        (self.proc / 'sys/kernel/printk_ratelimit').write_text('0\n')
        self.host = Host(self.proc)

    def begun(self, **options):
        check = audit.FilterCheck(self.host, proc=self.proc, **options)
        check.begin()
        return check

    def run_daemons(self, check, *pids, **status):
        """Each daemon starts, is observed, and journals its clone3 record."""
        for pid in pids:
            self.host.start(pid, **status)
            self.assertEqual(check.observe(), pid)
            self.host.kernel.append(record(pid, '"pqkey"', DAEMON, syscall='435'))
        self.host.service = '0'

    def test_only_the_daemons_clone3_records_pass(self):
        check = self.begun()
        self.run_daemons(check, '4101', '4102')
        lines, summary, problems = check.finish()
        self.assertEqual(problems, [])
        self.assertEqual(summary, 'PASS; refused calls for pqkey: 0; '
                                  'ignored clone3 calls (RestrictNamespaces= ENOSYS): 2; '
                                  'canaries: start logged, end logged; lost records: 0; daemons: 2, filter counts: 14')
        self.assertEqual(len(lines), 4)
        # Every read follows the journal from where it ended at the beginning.
        reads = [argv for argv in self.host.calls if argv[:3] == ['sudo', '-n', 'journalctl'] and '-q' in argv]
        self.assertTrue(reads and all('--after-cursor=s=cursor;i=1' in argv for argv in reads))
        self.assertIn(['sudo', '-n', 'grep', '-czx', 'SYSTEMD_LOG_SECCOMP=1', str(self.proc / '700/environ')],
                      self.host.calls)

    def test_a_refusal_named_by_executable_executor_or_observed_pid_fails_with_its_record(self):
        check = self.begun()
        self.run_daemons(check, '4101')
        refusals = [record('4102', '"pqkey"', DAEMON),
                    record('4103', '"(pqkey)"', '"/usr/lib/systemd/systemd-executor"', syscall='157'),
                    record('4104', '"ctap"', DELETED, arch='c00000b7', syscall='51'),
                    record('4101', '"worker"', '"/usr/lib/elsewhere"', syscall='435', code='0x80000000')]
        self.host.kernel += refusals + [record('4200', '"dbus-daemon"', '"/usr/bin/dbus-daemon"')]
        with patch.object(audit, 'syscall_names', return_value={'161': 'chroot', '157': 'prctl'}):
            lines, summary, problems = check.finish()
        self.assertEqual(problems, [f'refused chroot 161: {refusals[0]}', f'refused prctl 157: {refusals[1]}',
                                    f'refused syscall 51: {refusals[2]}', f'refused syscall 435: {refusals[3]}'])
        self.assertTrue(summary.startswith('FAILED; refused calls for pqkey: 4; '
                                           'ignored clone3 calls (RestrictNamespaces= ENOSYS): 1;'), summary)
        self.assertEqual(len(lines), 8)

    def test_lost_records_and_missing_canary_records_fail(self):
        check = self.begun(seconds=0)
        self.run_daemons(check, '4101')
        self.host.kernel.append(LOST)
        self.host.missed = ['Missed 3 kernel messages']
        self.host.journal_canaries = False
        _, summary, problems = check.finish()
        self.assertEqual(problems, ['canary refusal not journaled: end', f'audit records lost: {LOST}',
                                    'kernel messages lost: Missed 3 kernel messages'])
        self.assertIn('canaries: start logged, end MISSING; lost records: 2', summary)

    def test_every_daemon_must_run_under_the_same_seccomp_filters(self):
        check = self.begun()
        self.run_daemons(check, '4101', filters='14')
        self.run_daemons(check, '4102', filters='13')
        self.run_daemons(check, '4103', seccomp='0', filters='0')
        _, _, problems = check.finish()
        self.assertEqual(problems, ['daemons ran under differing seccomp filter counts: 0, 13, 14',
                                    'daemon 4103 ran without a seccomp filter (Seccomp: 0)'])
        self.assertEqual(self.begun().finish()[2], ['no daemon was observed'])

    def test_beginning_needs_logged_refusals_and_a_journaled_canary(self):
        self.begun()
        self.assertEqual(self.host.next_canary, 902)
        for change, message in [(lambda: setattr(self.host, 'manager', '0'), 'the user manager does not run'),
                                (lambda: setattr(self.host, 'flag', '0'), 'user manager does not flag'),
                                (lambda: (self.proc / 'sys/kernel/printk_ratelimit').write_text('5\n'),
                                 'audit records may be dropped'),
                                (lambda: (self.proc / 'sys/kernel/seccomp/actions_logged').write_text('log\n'),
                                 'refusals not logged'),
                                (lambda: setattr(self.host, 'journal_canaries', False),
                                 'refused system calls do not reach the journal')]:
            self.setUp()
            change()
            with self.assertRaises(AssertionError) as error:
                self.begun(seconds=0)
            self.assertIn(message, str(error.exception))

    def test_observing_needs_a_running_service_whose_filter_allows_clone3(self):
        check = self.begun()
        with self.assertRaises(AssertionError):
            check.observe()
        self.host.start('4101')
        self.host.allowed = 'read write'
        with self.assertRaises(AssertionError):
            check.observe()
        self.assertEqual(check.daemons, {})


class Rules(unittest.TestCase):
    def test_rows_keep_their_whole_record(self):
        line = record('4101', '"pqkey"', DAEMON)
        found = audit.seccomp_check([line], daemon_pids=set(), canaries={}, uid=UID)
        self.assertEqual([row['record'] for row in found['daemon']], [line])

    def test_only_a_clean_check_has_no_problems(self):
        clean = {'daemon': [], 'canaries': {'start': True, 'end': True}, 'lost': []}
        self.assertEqual(audit.problems(clean, [], ['14']), [])
        self.assertEqual(audit.problems(clean, [], ['13', '14']),
                         ['daemons ran under differing seccomp filter counts: 13, 14'])

    def test_the_unit_must_refuse_with_eperm_and_allow_clone3(self):
        shown = 'DropInPaths=/a.conf /b.conf\nSystemCallErrorNumber=1\nSystemCallFilter=clone3 read write'
        properties, allowed = audit.unit_filter(shown)
        self.assertEqual((properties['DropInPaths'], allowed), ('/a.conf /b.conf', ['clone3', 'read', 'write']))
        for changed in (shown.replace('Number=1', 'Number=38'), shown + ' chroot', shown.replace('clone3 ', '')):
            with self.assertRaises(AssertionError):
                audit.unit_filter(changed)

    def test_a_canary_is_awaited_until_its_refusal_is_journaled_or_the_deadline(self):
        canary = record('901', '"python3"', '"/usr/bin/python3.12"')
        logged = record('901', '"python3"', '"/usr/bin/python3.12"', code='0x7ffc0000')
        polls, sleeps = [[], [logged], [logged, canary]], []
        def command(argv, check=True):
            self.assertIn('--after-cursor=cursor', argv)
            return '\n'.join(polls.pop(0))
        self.assertEqual(audit.await_canary(command, 'cursor', 'start', '901', clock=lambda: 0, sleep=sleeps.append),
                         ([logged, canary], True))
        self.assertEqual(sleeps, [1, 1])
        polls, clock = [[], [logged], [canary]], iter([0, 10, 20])
        self.assertEqual(audit.await_canary(command, 'cursor', 'start', '901', clock=lambda: next(clock),
                                            sleep=lambda _: None), ([logged], False))

    def test_the_canary_reaches_the_user_manager_under_the_filter(self):
        calls = []
        def command(argv, check=True):
            calls.append(argv)
            return '4242'
        self.assertEqual(audit.run_canary(command), '4242')
        argv = calls[0]
        self.assertEqual(argv[:6], ['env', '-u', 'DBUS_SESSION_BUS_ADDRESS', 'systemd-run', '--user', '--pipe'])
        self.assertIn('SystemCallFilter=@system-service', argv)
        self.assertIn('SystemCallErrorNumber=EPERM', argv)
        self.assertEqual(argv[-1], audit.CANARY)
        with self.assertRaises(AssertionError):
            audit.run_canary(lambda argv, check=True: 'Running as unit: run-u1.service')

    def test_host_commands_return_output_and_fail_with_their_error(self):
        self.assertEqual(audit.host([sys.executable, '-c', 'print(" out ")']), 'out')
        failing = [sys.executable, '-c', 'import sys; print("partial"); sys.exit("broken")']
        with self.assertRaises(RuntimeError) as error:
            audit.host(failing)
        self.assertIn('exited with status 1: broken', str(error.exception))
        self.assertEqual(audit.host(failing, check=False), 'partial')


if __name__ == '__main__':
    unittest.main()
