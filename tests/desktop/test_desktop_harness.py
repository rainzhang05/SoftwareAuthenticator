"""Offline regression evidence only: no installed service or notification server."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

E2E = Path(__file__).resolve().parents[1] / 'e2e'
sys.path.insert(0, str(E2E))
import desktop_acceptance as desktop
import desktop_results as results



class Ownership(unittest.TestCase):
    def test_rejected_preflight_never_uninstalls_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
            with patch.object(run, 'command') as command, patch.object(desktop, 'fido_devices') as devices:
                run.cleanup()
            command.assert_not_called()
            devices.assert_not_called()
            self.assertFalse(run.cleanup_ok)

    def test_runner_owned_identity_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            control, ledger = home / 'control', home / 'owner.json'
            user = 'pqd123a1f'
            owner = dict(uid=os.getuid(), user=user, home=str(home), source='a' * 40,
                         baseline=results.BASELINE, scenario='fresh')
            ledger.write_text(json.dumps(owner))
            metadata = MagicMock(st_uid=os.getuid() + 1, st_mode=0o100644)
            account = MagicMock(pw_name=user, pw_dir=str(home))
            with patch.dict(os.environ, PQKEY_OWNER_LEDGER=str(ledger)), \
                 patch.object(desktop.Path, 'stat', return_value=metadata), \
                 patch.object(desktop.Path, 'is_symlink', return_value=False), \
                 patch.object(desktop.Path, 'home', return_value=home), \
                 patch.object(desktop.pwd, 'getpwuid', return_value=account):
                self.assertEqual(desktop.owner_record(control), owner)
                metadata.st_uid = os.getuid()
                with self.assertRaises(AssertionError):
                    desktop.owner_record(control)
                metadata.st_uid += 1
                account.pw_name = 'personal-user'
                with self.assertRaises(AssertionError):
                    desktop.owner_record(control)

    def test_command_timeout_is_retained_without_partial_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
            with patch.object(desktop.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['probe'], 1, output=b'private')):
                with self.assertRaises(RuntimeError):
                    run.command(['probe'], timeout=1)
            text = (Path(directory) / 'commands.jsonl').read_text()
            self.assertNotIn('private', text)
            self.assertEqual(json.loads(text)['status'], 124)

    def test_entrypoint_refuses_non_runner_before_any_sudo(self):
        root = E2E.parents[1]
        env = dict(os.environ, GITHUB_ACTIONS='', RUNNER_ENVIRONMENT='')
        result = subprocess.run(['bash', str(root / 'scripts/desktop-acceptance.sh'), 'cleanup', 'fresh'],
                                env=env, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'UNAVAILABLE', result.stderr)


class Seccomp(unittest.TestCase):
    # A canary's refusal as a 7.0 kernel journaled it, with SYSTEMD_LOG_SECCOMP=1.
    CANARY = ('audit: type=1326 audit(1792823746.791:2): auid=2001 uid=2001 gid=2001 ses=3 pid=1586 '
              'comm="python3" exe="/usr/bin/python3.12" sig=0 arch=c00000b7 syscall=51 compat=0 '
              'ip=0xffff8e4f348c code=0x50000')
    # The daemon's clone3 under RestrictNamespaces= as desktop.yml run 40419494018 journaled it.
    CLONE3 = ('audit: type=1326 audit(1793057204.506:129): auid=2000 uid=2000 gid=2000 ses=3 subj=unconfined '
              'pid=18722 comm="pqkey" exe="/usr/local/bin/pqkey" sig=0 arch=c000003e syscall=435 compat=0 '
              'ip=0x7ffb0e529ebd code=0x50000')
    DELETED = (desktop.BINARY + ' (deleted)').encode().hex().upper()

    def line(self, pid, comm, exe, uid='2001', code='0x50000', arch='c000003e', syscall='161'):
        return (f'audit: type=1326 audit(1792823750.981:8): auid={uid} uid={uid} gid={uid} ses=3 pid={pid} '
                f'comm={comm} exe={exe} sig=0 arch={arch} syscall={syscall} compat=0 ip=0x7f00 code={code}')

    def test_records_decode_quoted_and_hex_encoded_fields(self):
        record = desktop.audit_record(self.CANARY)
        self.assertEqual([record[key] for key in ('pid', 'comm', 'exe', 'syscall', 'code')],
                         ['1586', 'python3', '/usr/bin/python3.12', '51', '0x50000'])
        self.assertEqual(desktop.audit_record(self.line('7', '"pqkey"', self.DELETED))['exe'],
                         desktop.BINARY + ' (deleted)')

    def test_daemon_records_are_named_and_canaries_need_a_refusal(self):
        lines = [self.CANARY,
                 self.line('10', '"pqkey"', f'"{desktop.BINARY}"'),
                 self.line('11', '"(pqkey)"', '"/usr/lib/systemd/systemd-executor"'),
                 self.line('12', '"ctap-app"', self.DELETED),
                 self.line('13', '"elsewhere"', '"/opt/elsewhere"'),
                 self.line('20', '"python3"', '"/usr/bin/python3.12"', code='0x7ffc0000'),
                 self.line('30', '"dunst"', '"/usr/bin/dunst"'),
                 self.line('40', '"sshd"', '"/usr/sbin/sshd"', uid='0'),
                 'audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=64']
        found = desktop.seccomp_check(lines, daemon_pids={'13'}, canaries={'start': '1586', 'end': '20'},
                                      uid='2001', names={'161': 'chroot'})
        self.assertEqual([row['pid'] for row in found['daemon']], ['10', '11', '12', '13'])
        self.assertEqual({row['name'] for row in found['daemon']}, {'chroot'})
        self.assertEqual(found['canaries'], {'start': True, 'end': False})
        self.assertEqual([row['comm'] for row in found['other']], ['dunst'])
        self.assertEqual(len(found['lost']), 1)

    def test_only_the_daemons_clone3_failed_by_restrict_namespaces_is_ignored(self):
        daemon = f'"{desktop.BINARY}"'
        lines = [self.CANARY, self.CLONE3,
                 self.line('10', '"pqkey"', daemon, arch='c00000b7', syscall='435'),
                 self.line('11', '"(pqkey)"', '"/usr/lib/systemd/systemd-executor"', syscall='435'),
                 self.line('12', '"pqkey"', daemon, arch='c00000b7', syscall='51'),
                 self.line('13', '"pqkey"', daemon, arch='40000003', syscall='435'),
                 self.line('14', '"pqkey"', daemon, syscall='435', code='0x80000000'),
                 self.line('15', '"pqkey"', daemon, syscall='436'),
                 self.line('30', '"dunst"', '"/usr/bin/dunst"', syscall='435')]
        found = desktop.seccomp_check(lines, daemon_pids=set(), canaries={'start': '1586'}, uid='2001')
        # x86_64 and aarch64 clone3, also from systemd's executor.
        self.assertEqual([row['pid'] for row in found['ignored']], ['18722', '10', '11'])
        # aarch64 chroot, i386's 435, a killing filter's clone3, and x86_64's 436.
        self.assertEqual([row['pid'] for row in found['daemon']], ['12', '13', '14', '15'])
        self.assertEqual([row['comm'] for row in found['other']], ['dunst'])
        self.assertEqual(found['canaries'], {'start': True})

    def test_syscall_names_come_from_the_kernel_header(self):
        with tempfile.TemporaryDirectory() as directory:
            header = Path(directory) / 'unistd_64.h'
            header.write_text('#define __NR_read 0\n#define __NR_chroot 161\n')
            self.assertEqual(desktop.syscall_names(header), {'0': 'read', '161': 'chroot'})
        self.assertEqual(desktop.syscall_names(Path('/nonexistent/unistd_64.h')), {})

    def finish(self, directory, lines, filters=('11', '11'), end='20', missed=''):
        run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
        run.seccomp = {'cursor': 'cursor', 'canaries': {'start': '1586'}}
        run.metadata['services'] = [{'pid': 10 + index, 'seccomp_filters': count} for index, count in enumerate(filters)]
        def canary(phase):
            run.seccomp['canaries'][phase] = end
            return [self.CANARY, self.line('20', '"python3"', '"/usr/bin/python3.12"'), *lines], True
        with patch.object(run, 'canary', side_effect=canary), patch.object(run, 'command', return_value=missed):
            run.seccomp_finish()
        return run.events[-1]

    def test_a_refusal_for_the_daemon_or_differing_filters_fail_the_check(self):
        with tempfile.TemporaryDirectory() as directory:
            event = self.finish(directory, [])
            self.assertEqual((event['case'], event['status'], event['canaries']),
                             ('seccomp', 'pass', {'start': True, 'end': True}))
            self.assertEqual(len((Path(directory) / 'seccomp.log').read_text().splitlines()), 2)
            event = self.finish(directory, [self.line('11', '"pqkey"', f'"{desktop.BINARY}"')])
            self.assertEqual((event['status'], [row['pid'] for row in event['refused']]), ('fail', ['11']))
            self.assertEqual(self.finish(directory, [], filters=('10', '11'))['status'], 'fail')
            self.assertEqual(self.finish(directory, [], filters=())['status'], 'fail')

    def test_the_daemons_clone3_records_alone_pass_and_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            arm = self.line('11', '"pqkey"', f'"{desktop.BINARY}"', arch='c00000b7', syscall='435')
            elsewhere = self.line('30', '"dunst"', '"/usr/bin/dunst"', uid=str(os.getuid()), syscall='435')
            event = self.finish(directory, [self.CLONE3, arm, elsewhere])
            self.assertEqual((event['status'], event['refused']), ('pass', []))
            self.assertEqual([row['pid'] for row in event['ignored']], ['18722', '11'])
            self.assertEqual([row['comm'] for row in event['other_user_records']], ['dunst'])
            self.assertEqual(len((Path(directory) / 'seccomp.log').read_text().splitlines()), 5)

    def test_clone3_records_hide_no_refusal_missing_canary_or_lost_record(self):
        with tempfile.TemporaryDirectory() as directory:
            event = self.finish(directory, [self.CLONE3, self.line('11', '"pqkey"', f'"{desktop.BINARY}"')])
            self.assertEqual((event['status'], [row['pid'] for row in event['refused']], len(event['ignored'])),
                             ('fail', ['11'], 1))
            event = self.finish(directory, [self.CLONE3], end='21')
            self.assertEqual((event['status'], event['canaries']), ('fail', {'start': True, 'end': False}))
            lost = 'audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=64'
            event = self.finish(directory, [self.CLONE3, lost])
            self.assertEqual((event['status'], len(event['lost'])), ('fail', 1))
            event = self.finish(directory, [self.CLONE3], missed='Missed 2 kernel messages.')
            self.assertEqual((event['status'], len(event['missed_kernel_messages'])), ('fail', 1))

    def test_clone3_records_are_ignored_only_while_the_filter_allows_clone3(self):
        with tempfile.TemporaryDirectory() as directory:
            run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
            run.metadata['seccomp'] = {}
            shown = f'DropInPaths={run.drop_in}\nSystemCallErrorNumber=1\nSystemCallFilter=clone3 read'
            with patch.object(run, 'systemctl', return_value=shown):
                run.seccomp_unit()
            self.assertEqual(run.metadata['seccomp']['allowed_calls'], 2)
            with patch.object(run, 'systemctl', return_value=shown.replace('clone3 ', '')):
                with self.assertRaises(AssertionError):
                    run.seccomp_unit()

    def test_an_unbegun_check_records_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            run = desktop.Acceptance(Path(directory), Path(directory) / 'control')
            with patch.object(run, 'command') as command:
                run.seccomp_finish()
            command.assert_not_called()
            self.assertEqual(run.events, [])



if __name__ == '__main__':
    unittest.main()
