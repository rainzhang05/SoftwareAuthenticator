#!/usr/bin/env python3
"""Installed service acceptance with automated real Dunst/dmenu interaction.

Never constructs notification signals. No physical human presence claim.
Only a runner-owned ledger authorizes setup and cleanup of a fresh test user.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'tests/browser'))
from runtime import OwnedProcesses, fido_devices, public_log  # noqa: E402
from setup_support import BINARY, node, run  # noqa: E402
from desktop_results import BASELINE, scenario_pass  # noqa: E402

RP = 'installed.desktop.example'
# The system call filter under evaluation, for this run only. The owned user
# manager runs with SYSTEMD_LOG_SECCOMP=1 (see desktop-acceptance.sh), so the
# kernel logs every call the filter refuses.
SECCOMP_DROP_IN = ('# Desktop acceptance only: run the daemon under the system call filter\n'
                   '# being evaluated; the kernel logs each call it refuses.\n'
                   '[Service]\nSystemCallFilter=@system-service\nSystemCallErrorNumber=EPERM\n')
# chroot is outside @system-service and fails unprivileged anyway: a harmless
# call the filter refuses, which proves that refusals reach the journal.
CANARY = 'import os\nprint(os.getpid(), flush=True)\ntry:\n    os.chroot("/")\nexcept PermissionError:\n    pass\n'
# The audit record's code is the seccomp action alone, without the errno.
SECCOMP_RET_ERRNO = '0x50000'
# journald's "Missed N kernel messages".
JOURNAL_MISSED = 'MESSAGE_ID=e9bf28e6e834481bb6f48f548ad13606'
AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


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
    """
    names = names or {}
    found = {'daemon': [], 'canaries': {phase: False for phase in canaries}, 'other': [], 'lost': []}
    for line in lines:
        if 'audit_lost=' in line:
            found['lost'].append(line)
        if 'audit: type=1326 ' not in line:
            continue
        record = audit_record(line)
        row = {key: record.get(key) for key in ('pid', 'uid', 'comm', 'exe', 'arch', 'syscall', 'code')}
        if record.get('arch') == 'c000003e':
            row['name'] = names.get(record.get('syscall'))
        canary = next((phase for phase, pid in canaries.items() if pid == record.get('pid')), None)
        if canary:
            found['canaries'][canary] |= record.get('code') == SECCOMP_RET_ERRNO
        elif (record.get('exe') in (BINARY, BINARY + ' (deleted)') or record.get('comm') == '(pqkey)'
              or record.get('pid') in daemon_pids):
            found['daemon'].append(row)
        elif record.get('uid') == uid:
            found['other'].append(row)
    return found


def wait_for(predicate, message, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.05)
    raise TimeoutError(message)


def owner_record(control):
    """Check the runner's immutable ownership declaration, never a user-name guess."""
    ledger = Path(os.environ['PQKEY_OWNER_LEDGER'])
    assert not ledger.is_symlink() and ledger.stat().st_uid != os.getuid(), 'untrusted ownership ledger'
    assert ledger.stat().st_mode & 0o022 == 0, 'writable ownership ledger'
    owner = json.loads(ledger.read_text())
    account = pwd.getpwuid(os.getuid())
    assert owner['uid'] == os.getuid() and owner['user'] == account.pw_name
    assert Path(owner['home']) == Path.home() == control.parent == Path(account.pw_dir)
    assert re.fullmatch(r'pqd[0-9]+a[0-9]+[fu]', account.pw_name)
    assert owner['scenario'] in ('fresh', 'upgrade')
    assert owner['baseline'] == BASELINE
    assert re.fullmatch(r'[0-9a-f]{40}', owner['source'])
    assert owner['source'] != BASELINE or owner['scenario'] == 'fresh', 'upgrade needs two source revisions'
    return owner


class Acceptance:
    def __init__(self, out, control):
        self.out, self.control = out, control
        self.env = dict(os.environ, PATH='/usr/local/bin:/usr/bin:/bin', NO_COLOR='1')
        self.state = Path.home() / '.local/share/pqkey'
        self.prompt = self.state / 'authenticator.prompt'
        self.drop_in = Path.home() / '.config/systemd/user/pqkey.service.d/50-seccomp-evidence.conf'
        self.seccomp = None
        self.pin, self.new_pin = secrets.token_hex(8), secrets.token_hex(8)
        self.private = (self.pin, self.new_pin)
        self.processes = OwnedProcesses()
        self.processes.ledger = control / 'processes.json'
        self.processes.redactions = self.private
        self.events = []
        self.metadata = {'system': platform.platform(), 'python': sys.version, 'uid': os.getuid(),
                         'interaction': 'automated real Dunst/dmenu UI via xdotool; no physical human presence',
                         'native_executed': False}
        self.cleanup_ok = False
        self.authorized = False
        self.dunst = None
        self.counter = None
        self.device = None

    def write(self):
        result = {'metadata': self.metadata, 'events': self.events, 'cleanup': self.cleanup_ok}
        result['acceptance_pass'] = scenario_pass(result)
        temporary = self.out / 'result.tmp'
        temporary.write_text(json.dumps(result, indent=2) + '\n')
        temporary.replace(self.out / 'result.json')

    def record(self, case, **details):
        self.events.append({'case': case, 'status': 'pass', **details})
        self.write()

    def command(self, argv, *, timeout=10, check=True):
        started = time.monotonic()
        try:
            result = subprocess.run(argv, env=self.env, capture_output=True, timeout=timeout)
            status, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            status, stdout, stderr = 124, b'', b'command timeout; partial output withheld'
        row = {'command': argv, 'status': status, 'seconds': round(time.monotonic() - started, 3),
               'stdout': stdout.decode(errors='replace'), 'stderr': stderr.decode(errors='replace')}
        with (self.out / 'commands.jsonl').open('ab') as file:
            file.write(public_log((json.dumps(row) + '\n').encode(), self.private))
        if check and status:
            raise RuntimeError('command failed; see commands.jsonl')
        return stdout.decode(errors='replace').strip()

    def systemctl(self, *args):
        assert self.authorized, 'service management requires successful ownership preflight'
        return self.command(['env', '-u', 'DBUS_SESSION_BUS_ADDRESS', 'systemctl', '--user', *args])

    def manager_identity(self):
        pid = int(self.command(['systemctl', 'show', f'user@{os.getuid()}.service', '--property=MainPID', '--value']))
        assert pid > 1
        proc = Path(f'/proc/{pid}')
        status = (proc / 'status').read_text().splitlines()
        assert next(line.split()[1:] for line in status if line.startswith('Uid:')) == [str(os.getuid())] * 4
        groups = next(line.split()[1:] for line in status if line.startswith('Groups:'))
        return {'pid': pid, 'start': (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19], 'groups': groups}

    def identity(self):
        pid = int(self.systemctl('show', 'pqkey.service', '--property=MainPID', '--value'))
        assert pid > 1
        proc = Path(f'/proc/{pid}')
        status = (proc / 'status').read_text().splitlines()
        uid_fields = next(line.split()[1:] for line in status if line.startswith('Uid:'))
        assert uid_fields == [str(os.getuid())] * 4, 'service belongs to another user'
        def published_header():
            try:
                header = (self.state / 'authenticator.info').read_bytes().split(b'\n', 1)[0].decode().split()
            except FileNotFoundError:
                return None
            return header if len(header) == 5 and header[1] == str(pid) else None
        header = wait_for(published_header, 'service identity not published')
        installed = Path(BINARY).stat()
        # The daemon is non-dumpable. Inspect its owned executable with sudo;
        # never disable the production protection to make acceptance work.
        executable = self.command(['sudo', '-n', 'stat', '-Lc', '%d:%i', str(proc / 'exe')])
        assert executable == f'{installed.st_dev}:{installed.st_ino}'
        argv = self.command(['sudo', '-n', 'cat', str(proc / 'cmdline')]).encode().split(b'\0')
        assert argv == [BINARY.encode(), b'--state-dir', str(self.state).encode(), b'run', b''], 'nondefault service command'
        assert header[:4] == ['pqkey-daemon-v2', str(pid), str(installed.st_dev), str(installed.st_ino)]
        assert header[4] == 'x' + self.env['DBUS_SESSION_BUS_ADDRESS'].encode().hex(), 'service notification bus differs'
        assert self.manager_identity() == self.manager_before, 'user manager changed since login'
        assert os.getgroups() == self.groups_before, 'login groups changed'
        info = {'pid': pid, 'start': (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                'inode': installed.st_ino, 'sha256': hashlib.sha256(Path(BINARY).read_bytes()).hexdigest(),
                'argv': [arg.decode() for arg in argv[:-1]], 'manager': self.manager_before,
                'seccomp_filters': next(line.split()[1] for line in status if line.startswith('Seccomp_filters:'))}
        self.metadata.setdefault('services', []).append(info)
        self.write()
        return info

    def install(self, name, *, source='current', pin=None, change_pin=False, ready=True):
        assert self.authorized
        path = Path.home() / ('source-' + source) / 'install.sh'
        answers = () if pin is None else (('New PIN:', pin), ('Confirm new PIN:', pin))
        if change_pin:
            answers = (('Current PIN:', self.pin), ('New PIN:', self.new_pin), ('Confirm new PIN:', self.new_pin))
        started = time.monotonic()
        try:
            status, output = run([str(path), '--yes'], self.env, answers, timeout=1200)
        except Exception:
            # A failed hidden dialogue withholds PTY output. The installer's log
            # contains output only; retain it only after checking both PINs.
            log = Path.home() / '.cache/pqkey/install.log'
            if log.exists():
                raw = log.read_bytes()
                if not any(value.encode() in raw for value in self.private):
                    (self.out / f'{name}.log').write_bytes(public_log(raw, self.private))
            raise
        raw = output.encode()
        log = Path.home() / '.cache/pqkey/install.log'
        if log.exists():
            raw += log.read_bytes()
        if any(value.encode() in raw for value in self.private):
            raise RuntimeError('PIN leaked by setup; raw output withheld')
        (self.out / f'{name}.log').write_bytes(public_log(raw, self.private))
        with (self.out / 'commands.jsonl').open('a') as file:
            file.write(json.dumps({'command': [str(path), '--yes'], 'status': status,
                                   'source': self.metadata['source'] if source == 'current' else BASELINE,
                                   'seconds': round(time.monotonic() - started, 3),
                                   'interaction': 'hidden terminal input' if answers else 'noninteractive'}) + '\n')
        assert (status == 0) is ready and ('pqkey is ready.' in output) is ready, 'incorrect readiness publication'
        if ready:
            self.identity()
            self.device = node(self.env)
        self.record(name, exit_status=status, ready=ready)
        return output

    def start_dunst(self):
        # Dunst detaches dmenu through a double fork. The owned launcher records
        # its PID/start time before exec of the REAL menu, preserving stdin/stdout.
        # This supplies ownership evidence without process-name discovery/kills.
        launcher = self.control / 'menu.py'
        launcher.write_text('import json, os\nfrom pathlib import Path\n'
                            'pid = os.getpid()\n'
                            'start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]\n'
                            'path = Path(__file__).with_name("menu-identity.json")\n'
                            'temporary = path.with_suffix(".tmp")\n'
                            'temporary.write_text(json.dumps({"pid": pid, "start": start}))\n'
                            'temporary.chmod(0o600)\ntemporary.replace(path)\n'
                            'os.execv("/usr/bin/dmenu", ["dmenu", "-i", "-l", "8", "-p", "pqkey-presence"])\n')
        config = self.control / 'dunstrc'
        config.write_text('[global]\nfont = Monospace 12\nformat = "<b>%s</b>\\n%b"\n'
                          f'dmenu = {sys.executable} {launcher}\n'
                          'history_length = 20\n[urgency_critical]\ntimeout = 0\n')
        self.dunst = self.processes.start(['dunst', '-config', str(config)], self.out / 'dunst.log', env=self.env)
        wait_for(lambda: self.command(['dunstctl', 'is-paused'], check=False) == 'false', 'Dunst not ready')
        def call(destination, path, method, *args):
            return self.command(['gdbus', 'call', '--session', '--dest', destination, '--object-path', path,
                                 '--method', method, *args])
        owner = call('org.freedesktop.DBus', '/org/freedesktop/DBus',
                     'org.freedesktop.DBus.GetConnectionUnixProcessID', 'org.freedesktop.Notifications')
        assert re.fullmatch(r'\(uint32 ' + str(self.dunst.pid) + r',\)', owner), 'Dunst PID differs from bus owner'
        info = call('org.freedesktop.Notifications', '/org/freedesktop/Notifications',
                    'org.freedesktop.Notifications.GetServerInformation')
        caps = call('org.freedesktop.Notifications', '/org/freedesktop/Notifications',
                    'org.freedesktop.Notifications.GetCapabilities')
        assert 'dunst' in info.lower() and "'actions'" in caps and "'body'" in caps
        self.metadata.setdefault('notifications', []).append({'server': info, 'capabilities': caps, 'pid': self.dunst.pid})
        self.write()

    def displayed(self):
        return int(self.command(['dunstctl', 'count', 'displayed']))

    def prompt_shown(self, name, seconds=8):
        wait_for(lambda: self.prompt.exists() and self.displayed() == 1, 'prompt not displayed by Dunst', seconds)
        self.command(['scrot', str(self.out / f'{name}.png')])

    def withdrawn(self):
        wait_for(lambda: not self.prompt.exists() and self.displayed() == 0, 'pending prompt not withdrawn')

    def answer(self, action, name):
        assert action in ('Approve', 'Deny')
        ledger = self.control / 'menu-identity.json'
        ledger.unlink(missing_ok=True)
        self.command(['dunstctl', 'context'])
        windows = wait_for(lambda: self.command(['xdotool', 'search', '--onlyvisible', '--class', '^dmenu$'], check=False),
                           'Dunst did not open its real dmenu UI').splitlines()
        assert len(windows) == 1, 'ambiguous action UI'
        menu = json.loads(ledger.read_text())
        proc = Path(f"/proc/{menu['pid']}")
        assert proc.stat().st_uid == os.getuid()
        assert (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] == menu['start']
        executable, real_menu = (proc / 'exe').stat(), Path('/usr/bin/dmenu').stat()
        assert (executable.st_dev, executable.st_ino) == (real_menu.st_dev, real_menu.st_ino)
        self.processes.adopt_descendants(roots=(menu['pid'],), owner=self.dunst.pid)
        self.command(['xdotool', 'type', '--clearmodifiers', action])
        self.command(['scrot', str(self.out / f'{name}-menu.png')])
        self.command(['xdotool', 'key', '--clearmodifiers', 'Return'])

    def evidence(self, name, row):
        with (self.out / 'ceremonies.jsonl').open('a') as file:
            file.write(json.dumps({'case': name, 'verifier': 'pyca/cryptography', **row}) + '\n')

    def connection(self):
        import ctap as client
        return client.open_device(self.device, timeout=45)

    def request(self, kind, name, target=RP):
        def execute():
            from fido2.ctap2 import ClientPin, Ctap2, PinProtocolV2
            import ctap as client
            with self.connection() as device:
                ctap = Ctap2(device)
                permission = ClientPin.PERMISSION.MAKE_CREDENTIAL if kind == 'registration' else ClientPin.PERMISSION.GET_ASSERTION
                auth = client.pin_uv_auth(ctap, PinProtocolV2(), self.pin, permission, target)
                capture = lambda row: self.evidence(name, row)
                if kind == 'registration':
                    return client.register(ctap, target, client.ES256, uv=True, options={'rk': True}, evidence=capture, **auth)
                return client.authenticate(ctap, self.credential, uv=True, allow_list=False,
                                           evidence=capture, **auth)
        return execute

    def operation(self, name, kind, *, action='Approve', expected=None, target=RP):
        from fido2.ctap import CtapError
        self.withdrawn()
        start = time.monotonic()
        # The connection has an absolute read deadline even if keepalives never stop.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.request(kind, name, target))
            self.prompt_shown(name)
            if action:
                self.answer(action, name)
            try:
                value = future.result(timeout=45)
            except CtapError as error:
                assert expected is not None and error.code == expected, 'incorrect CTAP failure status'
                value = None
            else:
                assert expected is None, 'operation succeeded without approval'
        elapsed = time.monotonic() - start
        self.withdrawn()
        if action is None:
            assert 29 <= elapsed < 40, 'default 30-second presence timeout not exercised'
        self.record(name, ctap_status=0 if expected is None else int(expected), elapsed_seconds=round(elapsed, 3),
                    interaction='automated UI' if action else 'unanswered')
        return value

    def retained(self, name, *, policy=True):
        from fido2.ctap2 import Ctap2
        with self.connection() as device:
            info = Ctap2(device).get_info()
            assert info.options['clientPin']
            if policy:
                assert info.options['alwaysUv'] and info.min_pin_length == 6 and not info.force_pin_change
            assert info.remaining_disc_creds == self.remaining, 'unapproved operation changed credential capacity'
        _, data = self.operation(name, 'assertion')
        assert data.sign_count == self.counter + 1, 'unapproved operation advanced the counter'
        self.counter = data.sign_count

    def pending(self, kind, mode):
        from fido2 import cbor
        from fido2.ctap2 import ClientPin, Ctap2, PinProtocolV2
        import ctap as client
        import ctaphid
        name = f'{mode}-{kind}'
        self.withdrawn()
        with self.connection() as device:
            ctap = Ctap2(device)
            permission = ClientPin.PERMISSION.MAKE_CREDENTIAL if kind == 'registration' else ClientPin.PERMISSION.GET_ASSERTION
            auth = client.pin_uv_auth(ctap, PinProtocolV2(), self.pin, permission, RP)
        if kind == 'registration':
            request = {1: auth['client_data_hash'], 2: {'id': RP}, 3: client.user_entity('unapproved'),
                       4: [{'type': 'public-key', 'alg': client.ES256}], 7: {'rk': True},
                       8: auth['pin_uv_param'], 9: auth['pin_uv_protocol']}
            command = Ctap2.CMD.MAKE_CREDENTIAL
        else:
            request = {1: RP, 2: auth['client_data_hash'], 6: auth['pin_uv_param'], 7: auth['pin_uv_protocol']}
            command = Ctap2.CMD.GET_ASSERTION
        hid = ctaphid.RawHid(self.device)
        try:
            cid = hid.allocate_channel()
            hid.send(cid, ctaphid.CBOR, bytes([command]) + cbor.encode(request))
            self.prompt_shown(name)
            if mode == 'cancel':
                hid.send(cid, ctaphid.CANCEL)
                response = hid.receive(timeout=8)
                assert (response.cid, response.cmd, response.payload) == (cid, ctaphid.CBOR, b'\x2d')
                details = {'ctap_status': 0x2d}
            else:
                before = self.identity()
                old_device = self.device
                self.systemctl('restart', 'pqkey.service')
                # A disconnected HID read must terminate, not a future-result timeout.
                try:
                    packet = hid.read_packet(timeout=8)
                    # Queued keepalives may precede the EOF; drain with an absolute deadline.
                    deadline = time.monotonic() + 8
                    while packet:
                        assert packet[4] == 0x80 | ctaphid.KEEPALIVE, 'response published without approval during restart'
                        packet = hid.read_packet(timeout=max(0, deadline - time.monotonic()))
                except OSError as error:
                    import errno
                    assert error.errno in (errno.ENODEV, errno.EIO, errno.EBADF), 'unexpected transport failure'
                    details = {'transport_errno': error.errno}
                else:
                    details = {'transport': 'EOF'}
                after = self.identity()
                assert (after['pid'], after['start']) != (before['pid'], before['start'])
                self.device = node(self.env)
                details.update(old_device=old_device, new_device=self.device)
        finally:
            hid.close()
        self.withdrawn()
        self.record(name, **details)
        self.retained('recovered-' + name)

    def preflight(self):
        assert platform.system() == 'Linux' and os.getuid() != 0
        assert os.environ.get('PQKEY_DESKTOP_ACCEPTANCE') == '1'
        owner = owner_record(self.control)
        self.metadata.update(source=owner['source'], baseline=BASELINE, scenario=owner['scenario'])
        assert not Path(BINARY).exists() and not self.state.exists(), 'refusing existing installation'
        assert not fido_devices(), 'refusing another FIDO HID device'
        assert stat.S_ISCHR(Path('/dev/uhid').stat().st_mode), 'real UHID required'
        self.session = os.environ['XDG_SESSION_ID']
        for key, expected in [('Active', 'yes'), ('Remote', 'no'), ('Seat', 'seat0'), ('Type', 'x11')]:
            assert self.command(['loginctl', 'show-session', self.session, f'--property={key}', '--value']) == expected
        import grp
        self.plugdev = grp.getgrnam('plugdev').gr_gid
        self.groups_before = os.getgroups()
        self.manager_before = self.manager_identity()
        assert self.plugdev not in self.groups_before and str(self.plugdev) not in self.manager_before['groups']
        assert not os.access('/dev/uhid', os.R_OK | os.W_OK), 'UHID pre-granted to test user'
        self.metadata.update(session=self.session, manager_before=self.manager_before, groups_before=self.groups_before)
        self.metadata['session_paths'] = {
            key: self.env.get(key) for key in ('HOME', 'XDG_RUNTIME_DIR', 'TMPDIR', 'XDG_CONFIG_HOME',
                                              'XDG_DATA_HOME', 'XDG_CACHE_HOME')}
        paths = [Path.home(), Path('/run/user') / str(os.getuid())]
        paths.extend(Path(value) for value in self.metadata['session_paths'].values() if value)
        self.metadata['path_access'] = []
        for path in dict.fromkeys(paths):
            try:
                info = path.stat()
                self.metadata['path_access'].append({'path': str(path), 'uid': info.st_uid,
                                                     'mode': oct(stat.S_IMODE(info.st_mode)),
                                                     'write': os.access(path, os.W_OK),
                                                     'search': os.access(path, os.X_OK)})
            except OSError as error:
                self.metadata['path_access'].append({'path': str(path), 'errno': error.errno})
        self.authorized = True
        self.metadata['native_executed'] = True
        self.metadata['packages'] = self.command(['dpkg-query', '-W', 'dunst', 'lightdm', 'systemd', 'udev', 'acl',
                                                'xserver-xorg-core', 'xserver-xorg-video-dummy', 'suckless-tools', 'xdotool'])
        self.metadata['python_packages'] = {name: importlib.metadata.version(name) for name in ('fido2', 'cryptography')}
        from cryptography.hazmat.backends.openssl.backend import backend
        self.metadata['openssl'] = backend.openssl_version_text()
        self.write()

    def seccomp_begin(self):
        """Run every daemon under the filter being evaluated, once refusals are shown to be journaled."""
        assert 'errno' in Path('/proc/sys/kernel/seccomp/actions_logged').read_text().split(), 'refusals not logged'
        assert Path('/proc/sys/kernel/printk_ratelimit').read_text().strip() == '0', 'audit records may be dropped'
        flag = self.command(['sudo', '-n', 'grep', '-czx', 'SYSTEMD_LOG_SECCOMP=1',
                             f"/proc/{self.manager_before['pid']}/environ"], check=False)
        assert flag == '1', 'user manager does not flag seccomp filters for logging'
        self.drop_in.parent.mkdir(parents=True)
        self.drop_in.write_text(SECCOMP_DROP_IN)
        self.command(['systemd-analyze', 'syscall-filter', '@system-service'])
        cursor = self.command(['sudo', '-n', 'journalctl', '--system', '-n', '1', '-o', 'json',
                               '--output-fields=__CURSOR'])
        self.seccomp = {'cursor': json.loads(cursor)['__CURSOR'], 'canaries': {}}
        self.metadata['seccomp'] = {'drop_in': str(self.drop_in), 'printk_ratelimit': 0, 'manager_flag': True}
        self.write()
        assert self.canary('start')[1], 'refused system calls do not reach the journal'

    def canary(self, phase):
        """One refused call from a transient unit under the filter; returns the audit lines and whether it shows."""
        assert self.authorized
        pid = self.command(['env', '-u', 'DBUS_SESSION_BUS_ADDRESS', 'systemd-run', '--user', '--pipe', '--wait',
                            '--quiet', '--collect', '-p', 'NoNewPrivileges=yes',
                            '-p', 'SystemCallFilter=@system-service', '-p', 'SystemCallErrorNumber=EPERM',
                            '/usr/bin/python3', '-I', '-c', CANARY])
        assert pid.isdigit(), 'canary did not report its process ID'
        self.seccomp['canaries'][phase] = pid
        deadline = time.monotonic() + 15
        while True:
            lines = self.kernel_audit()
            seen = seccomp_check(lines, daemon_pids=(), canaries={phase: pid}, uid=str(os.getuid()))['canaries'][phase]
            if seen or time.monotonic() > deadline:
                return lines, seen
            time.sleep(1)

    def kernel_audit(self):
        """The kernel's seccomp records and audit losses since the run began."""
        return self.command(['sudo', '-n', 'journalctl', '-q', '-k', '--no-pager', '-o', 'cat',
                             '--after-cursor=' + self.seccomp['cursor'], '--grep=^audit: (type=1326 |audit_lost=)'],
                            check=False).splitlines()

    def seccomp_unit(self):
        shown = dict(line.split('=', 1) for line in self.systemctl(
            'show', 'pqkey.service', '--property=DropInPaths,SystemCallErrorNumber,SystemCallFilter').splitlines())
        allowed = shown['SystemCallFilter'].split()
        assert str(self.drop_in) in shown['DropInPaths'].split(), 'system call filter drop-in not loaded'
        assert shown['SystemCallErrorNumber'] == '1' and 'read' in allowed and 'chroot' not in allowed
        self.metadata['seccomp'].update(drop_in_paths=shown['DropInPaths'].split(), allowed_calls=len(allowed))
        self.write()

    def seccomp_finish(self):
        """Once the daemon has stopped: fail if any record names it, or if records may have been lost."""
        if self.seccomp is None:
            return
        # Kernel messages are journaled in order: with the end canary's record,
        # every earlier record has been read.
        lines, _ = self.canary('end')
        missed = self.command(['sudo', '-n', 'journalctl', '-q', '--system', '--no-pager', '-o', 'cat',
                               '--after-cursor=' + self.seccomp['cursor'], JOURNAL_MISSED], check=False).splitlines()
        services = self.metadata.get('services', [])
        found = seccomp_check(lines, daemon_pids={str(service['pid']) for service in services},
                              canaries=self.seccomp['canaries'], uid=str(os.getuid()), names=syscall_names())
        (self.out / 'seccomp.log').write_text(''.join(line + '\n' for line in lines))
        # Every daemon ran with the same filters, the drop-in's included.
        filters = sorted({service['seccomp_filters'] for service in services})
        passed = (not found['daemon'] and all(found['canaries'].values()) and not found['lost'] and not missed
                  and len(filters) == 1)
        self.events.append({'case': 'seccomp', 'status': 'pass' if passed else 'fail',
                            'filter': 'SystemCallFilter=@system-service SystemCallErrorNumber=EPERM',
                            'refused': found['daemon'], 'canaries': found['canaries'],
                            'other_user_records': found['other'], 'lost': found['lost'],
                            'missed_kernel_messages': missed, 'filter_counts': filters})
        self.write()

    def identification(self):
        # CTAPHID_WINK (CTAP 2.3 §11.2.9.2.1): a transient notification without
        # actions names the key and expires after two seconds.
        self.withdrawn()
        with self.connection() as device:
            device.wink()
            wait_for(lambda: self.displayed() == 1, 'identification not displayed by Dunst')
            self.command(['scrot', str(self.out / 'identification.png')])
            assert device.ping(b'identified') == b'identified'
        self.withdrawn()
        self.record('identification')

    def reset(self):
        # authenticatorReset is accepted only within 10 seconds of power-up
        # (CTAP 2.3 §6.6), so `pqkey reset` restarts the service first. It erases
        # the PIN, policy and passkeys, so nothing runs after it.
        from fido2.ctap import CtapError
        from fido2.ctap2 import Ctap2
        before = self.identity()
        self.withdrawn()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.command, [BINARY, 'reset', '--yes'], timeout=60)
            self.prompt_shown('reset', seconds=20)
            self.answer('Approve', 'reset')
            output = future.result(timeout=60)
        self.withdrawn()
        assert 'The key is reset' in output
        after = self.identity()
        assert after['pid'] != before['pid']
        self.device = node(self.env)
        with self.connection() as device:
            ctap = Ctap2(device)
            info = ctap.get_info()
            assert info.options['clientPin'] is False and info.options.get('alwaysUv') is False
            assert info.min_pin_length == 4 and not info.force_pin_change
            assert info.remaining_disc_creds > self.remaining, 'passkeys survived reset'
            try:
                ctap.get_assertion(RP, secrets.token_bytes(32),
                                   [{'type': 'public-key', 'id': self.credential.credential_id}], options={'up': False})
            except CtapError as error:
                assert error.code == CtapError.ERR.NO_CREDENTIALS, 'incorrect CTAP failure status'
            else:
                raise AssertionError('credential survived reset')
        self.record('reset', remaining_disc_creds=info.remaining_disc_creds)

    def exercise(self):
        from fido2.ctap import CtapError
        from fido2.ctap2 import ClientPin, Config, Ctap2, PinProtocolV2
        self.preflight()
        self.seccomp_begin()
        self.processes.start(['openbox'], self.out / 'openbox.log', env=self.env)
        self.env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + str(self.control / 'notifications.bus')
        self.processes.start(['dbus-daemon', '--nofork', '--config-file=' + str(HERE / 'session-bus.conf'),
                              '--address=' + self.env['DBUS_SESSION_BUS_ADDRESS']], self.out / 'bus.log', env=self.env)
        wait_for(lambda: (self.control / 'notifications.bus').exists(), 'owned bus not ready')
        self.start_dunst()
        upgrade = self.metadata['scenario'] == 'upgrade'
        source = 'baseline' if upgrade else 'current'
        if upgrade:
            self.install('pin-missing', source=source, ready=False)
            self.device = node(self.env)
            with self.connection() as device:
                assert Ctap2(device).get_info().options['clientPin'] is False
        self.install('ready', source=source, pin=self.pin)
        self.seccomp_unit()
        assert self.manager_identity() == self.manager_before and os.getgroups() == self.groups_before
        assert self.command(['loginctl', 'show-session', self.session, '--property=Active', '--value']) == 'yes'
        self.command(['getfacl', '-p', '/dev/uhid', self.device])
        self.record('immediate-access', groups_unchanged=True, manager_unchanged=True, hid=self.device)
        self.command([str(Path.home() / '.cargo/bin/rustc'), '+stable', '--version', '--verbose'])
        self.command([BINARY, '--version'])
        self.credential = self.operation('approved-registration', 'registration')
        _, data = self.operation('approved-assertion', 'assertion')
        assert data.sign_count > self.credential.auth_data.sign_count
        self.counter = data.sign_count
        with self.connection() as device:
            ctap = Ctap2(device)
            self.remaining = ctap.get_info().remaining_disc_creds
            assert self.remaining is not None
            protocol = PinProtocolV2()
            token = ClientPin(ctap, protocol).get_pin_token(self.pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
            config = Config(ctap, protocol, token)
            config.set_min_pin_length(6, [RP])
            config.toggle_always_uv()
        self.record('policy-set', min_pin_length=6, always_uv=True, rp_ids=[RP])
        if not upgrade:
            for mode in ('denied', 'timeout'):
                for kind in ('registration', 'assertion'):
                    self.operation(f'{mode}-{kind}', kind, action='Deny' if mode == 'denied' else None,
                                   expected=CtapError.ERR.OPERATION_DENIED,
                                   target=f'{mode}.desktop.example' if kind == 'registration' else RP)
                    self.retained(f'recovered-{mode}-{kind}')
            for mode in ('cancel', 'restart'):
                for kind in ('registration', 'assertion'):
                    self.pending(kind, mode)
        before = self.identity()
        self.install('setup-rerun', source=source)
        after = self.identity()
        assert after['inode'] != before['inode'] and after['pid'] != before['pid']
        self.retained('retained-rerun')
        if upgrade:
            before = after
            self.install('update')
            after = self.identity()
            assert after['inode'] != before['inode'] and after['pid'] != before['pid']
            self.metadata['update_executable_hashes_equal'] = before['sha256'] == after['sha256']
            self.retained('retained-update')
        assert not Path(BINARY + '.previous').exists()
        before = self.identity()
        self.systemctl('restart', 'pqkey.service')
        after = self.identity()
        assert after['pid'] != before['pid']
        self.device = node(self.env)
        self.record('restart')
        self.retained('retained-restart')
        if not upgrade:
            with self.connection() as device:
                ctap = Ctap2(device)
                protocol = PinProtocolV2()
                token = ClientPin(ctap, protocol).get_pin_token(self.pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
                Config(ctap, protocol, token).set_min_pin_length(force_change_pin=True)
            self.install('forced-pin-change-blocked', ready=False)
            self.install('forced-pin-change', change_pin=True)
            self.pin = self.new_pin
            self.retained('retained-pin-change')
            self.processes.stop(self.dunst)
            output = self.install('notification-missing', ready=False)
            assert 'notification' in output.lower()
            self.start_dunst()
            self.install('notification-recovery')
            self.retained('retained-notification-recovery')
        assert not Path(BINARY + '.previous').exists()
        # The minPinLength extension is returned only to the configured RP list.
        self.verify_rp_policy()
        self.record('policy-retained', final_counter=self.counter, discoverable=True,
                    original_pin_through_update_and_restart=True)
        self.identification()
        self.reset()

    def verify_rp_policy(self):
        # A denied registration discloses no extension. Use approved requests and
        # the existing independent verifier, then account for each new credential.
        from fido2.ctap2 import ClientPin, Ctap2, PinProtocolV2
        import ctap as client
        for allowed in (True, False):
            target = RP if allowed else 'unlisted.desktop.example'
            name = 'rp-policy-' + ('allowed' if allowed else 'unlisted')
            def request():
                with self.connection() as device:
                    ctap = Ctap2(device)
                    auth = client.pin_uv_auth(ctap, PinProtocolV2(), self.pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, target)
                    return client.register(ctap, target, client.ES256, uv=True, options={'rk': False},
                                           extensions={'minPinLength': True}, evidence=lambda row: self.evidence(name, row), **auth)
            self.withdrawn()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(request)
                self.prompt_shown(name)
                self.answer('Approve', name)
                credential = future.result(timeout=45)
            self.withdrawn()
            extension = (credential.auth_data.extensions or {}).get('minPinLength')
            assert extension == (6 if allowed else None), 'RP minimum PIN policy changed'
            self.record(name, min_pin_length=extension)
        with self.connection() as device:
            self.remaining = Ctap2(device).get_info().remaining_disc_creds

    def cleanup(self):
        failures = []
        # Preflight rejection cannot authorize uninstall, even if a binary exists.
        if self.authorized:
            try:
                assert owner_record(self.control)['uid'] == os.getuid()
                if Path(BINARY).exists():
                    self.command([BINARY, 'setup', '--uninstall'], timeout=30)
                if self.drop_in.exists():
                    self.drop_in.unlink()
                    self.drop_in.parent.rmdir()
            except Exception:
                failures.append('owned uninstall failed')
        failures.extend(self.processes.cleanup())
        if self.authorized and fido_devices():
            failures.append('owned FIDO device still present')
        self.cleanup_ok = self.authorized and not failures
        if failures:
            self.events.append({'case': 'cleanup', 'status': 'fail', 'details': failures})
        self.write()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--control', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or os.environ.get('PQKEY_DESKTOP_ACCEPTANCE') != '1':
        print('UNAVAILABLE: requires disposable native Linux desktop workflow; no installation managed')
        return 2
    test = Acceptance(args.evidence, args.control)
    def interrupted(signum, _frame):
        raise InterruptedError(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        test.exercise()
    except Exception as error:
        # Stack locations help diagnose failure; never capture CTAP inputs or exception values.
        frames = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                  for frame in traceback.extract_tb(error.__traceback__)]
        test.events.append({'case': 'execution', 'status': 'fail', 'error_type': type(error).__name__, 'stack': frames})
    finally:
        try:
            test.cleanup()
        except Exception as error:
            test.events.append({'case': 'cleanup', 'status': 'fail', 'error_type': type(error).__name__})
            test.cleanup_ok = False
            test.write()
        try:
            test.seccomp_finish()
        except Exception as error:
            test.events.append({'case': 'seccomp', 'status': 'fail', 'error_type': type(error).__name__})
            test.write()
    return 0 if scenario_pass({'metadata': test.metadata, 'events': test.events, 'cleanup': test.cleanup_ok}) else 1


if __name__ == '__main__':
    sys.exit(main())
