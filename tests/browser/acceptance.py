#!/usr/bin/env python3
"""Real Linux UHID browser acceptance. Offline unit tests live in test_*.py."""
from __future__ import annotations

import argparse
import ast
import base64
import configparser
import importlib.metadata
import json
import os
import platform
import re
import select
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from download import digest, install
from results import CONTROL_IDS, GOOD, classify, initial_rows, wait_until, write_report
from runtime import OwnedProcesses, fido_devices, preflight, public_log

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEVICE_GLOB = '/sys/devices/virtual/misc/uhid/0003:1209:0006.*/hidraw/hidraw*'
CEREMONY_SECONDS = 30
SUPPLEMENTAL = [{"id": f"B{i}", "kind": "reg", "label": f"Brainpool {alg} non-discoverable",
                 "username": f"brainpool{i}", "algs": str(alg), "rk": "discouraged"}
                for i, alg in enumerate((-265, -267), 1)]


class RunInterrupted(BaseException):
    def __init__(self, signum):
        super().__init__(f'interrupted by signal {signum}')
        self.signum = signum


def command(argv, *, env=None, timeout=10):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT)
    return {"command": argv, "status": result.returncode, "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()}


def free_port():
    with socket.socket() as endpoint:
        endpoint.bind(('127.0.0.1', 0))
        return endpoint.getsockname()[1]


def peer(script, request, env, *, python=sys.executable, timeout=5):
    # Sensitive stdin is never copied to diagnostics or exception messages.
    response = subprocess.run([python, str(HERE / script)], input=json.dumps(request),
                              text=True, capture_output=True, env=env, timeout=timeout)
    if response.returncode:
        detail = ''
        if script == 'ui.py':
            try:
                diagnostic = json.loads(response.stdout)
                if diagnostic.get('error') == 'NativeUIError':
                    detail = '; ' + diagnostic['reason']
            except (ValueError, KeyError, TypeError):
                pass
        raise RuntimeError(f'{script} failed (status {response.returncode}); native peer/setup failure{detail}')
    return json.loads(response.stdout)


class Run:
    def __init__(self, browser, artifacts, binaries, control=None):
        self.browser = browser
        self.out = artifacts / browser
        self.out.mkdir(parents=True, exist_ok=True)
        self.binaries = binaries
        self.control = control
        self.presets = json.loads((HERE / 'presets.json').read_text()) + SUPPLEMENTAL
        self.rows = initial_rows(self.presets)
        self.metadata = {"system": platform.platform(), "architecture": platform.machine(),
                         "python": sys.version, "source": command(['git', 'rev-parse', 'HEAD']),
                         "dirty": command(['git', 'status', '--porcelain']),
                         "acceptance_executed": False, "initialized_only": False}
        previous_matrix = self.out / 'matrix.json'
        if previous_matrix.exists():
            previous = json.loads(previous_matrix.read_text())['metadata']
            if not previous.get('initialized_only') or previous.get('source', {}).get('stdout') != self.metadata['source']['stdout']:
                raise ValueError(f'prior evidence exists in {self.out}; choose a fresh artifact directory')
        elif any(self.out.iterdir()):
            raise ValueError(f'nonempty artifact directory {self.out}; choose a fresh directory')
        self.failures = []
        self.processes = OwnedProcesses()
        self.driver = None
        self.daemon = None
        self.work = None
        self.pin = secrets.token_hex(6)  # never persisted in artifacts or argv
        self.processes.redactions = (self.pin,)
        self.console_file = self.out / 'browser-console.jsonl'
        self.console_file.touch()
        self.version = ''
        self.counter = 0
        self.env = os.environ.copy()
        self.binary = ROOT / 'target/release/pqkey'
        self.ui_events = []

    def write(self):
        return write_report(self.out, self.browser, self.metadata, self.rows, self.failures)

    def safe_text(self, text):
        return public_log(str(text).encode(), (self.pin,)).decode()

    def setup(self):
        preflight()  # before downloads, state, buses, desktop or daemon startup
        from cryptography.hazmat.backends.openssl.backend import backend
        self.metadata.update({"os_release": Path('/etc/os-release').read_text(),
                              "kernel": command(['uname', '-a']),
                              "rust": command(['rustc', '--version', '--verbose']),
                              "cargo": command(['cargo', '--version']),
                              "daemon": command([str(self.binary), '--version']),
                              "daemon_sha256": digest(self.binary),
                              "openssl": backend.openssl_version_text(),
                              "packages": {d.metadata['Name']: d.version for d in importlib.metadata.distributions()},
                              "desktop_packages": command(['dpkg-query', '-W', 'xvfb', 'openbox', 'python3-pyatspi',
                                                           'at-spi2-core', 'dbus-daemon', 'dunst', 'libglib2.0-bin', 'xdotool', 'scrot',
                                                           'libatspi*', 'libgtk-3*', 'libnss3', 'libudev1', 'udev']),
                              "accessibility_python": command(['/usr/bin/python3', '--version']),
                              "runner": {k: os.environ.get(k) for k in ('ImageOS', 'ImageVersion', 'GITHUB_SHA',
                                        'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_WORKFLOW', 'RUNNER_ARCH')}})
        if self.control:
            self.control.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.work = tempfile.TemporaryDirectory(prefix='pqkey-browser-', dir=self.control)
        if self.control:
            self.processes.ledger = self.control / 'processes.json'
        self.state = Path(self.work.name)
        self.rp_data = self.state / 'rp'
        self.profile = self.state / 'profile'
        self.profile.mkdir()
        if self.binaries is None:
            self.binaries = self.state / 'binaries'
            self.lock = install(self.browser, self.binaries)
        else:
            self.lock = json.loads((HERE / 'toolchain.json').read_text())[self.browser]
        self.browser_binary = self.binaries / self.lock['browser']['executable']
        self.driver_binary = self.binaries / self.lock['driver']['executable']
        self.metadata['toolchain'] = self.lock
        self.metadata['expectations'] = json.loads((HERE / 'expectations.json').read_text())
        receipt = json.loads((self.binaries / 'verified-download.json').read_text())
        if receipt['browser'] != self.browser or receipt['manifest_sha256'] != digest(HERE / 'toolchain.json'):
            raise RuntimeError('browser download receipt does not match the committed lock')
        for kind in ('browser', 'driver'):
            if digest(self.binaries / self.lock[kind]['executable']) != receipt['executables'][kind]:
                raise RuntimeError('downloaded browser/driver changed after checksum verification')
        self.metadata['browser_binary_sha256'] = digest(self.browser_binary)
        self.metadata['driver_binary_sha256'] = digest(self.driver_binary)
        self.metadata['browser_binary_version'] = command([str(self.browser_binary), '--version'])
        self.metadata['driver_binary_version'] = command([str(self.driver_binary), '--version'])
        # Foreground, owned bus; no service activation or personal notification server.
        daemon_env = self.env.copy()
        daemon_env['DBUS_SESSION_BUS_ADDRESS'] = self.bus('daemon-bus')
        daemon_env['RUST_LOG'] = 'info'  # E2E debug payload previews may contain protocol secrets
        self.daemon = self.processes.start([str(self.binary), '--state-dir', str(self.state / 'daemon'),
                                            'run', '--product-id', '0x0006', '--presence', 'auto-approve'],
                                           self.out / 'daemon.log', env=daemon_env)
        def device_ready():
            if self.daemon.poll() is not None:
                raise RuntimeError('daemon exited before HID was ready')
            nodes = list(Path('/').glob(DEVICE_GLOB.lstrip('/')))
            if len(nodes) > 1:
                raise RuntimeError('multiple devices for reserved product ID')
            if nodes:
                node = Path('/dev') / nodes[0].name
                if os.access(node, os.R_OK | os.W_OK):
                    return str(node)
            return None
        self.node = wait_until(device_ready, 30)
        self.metadata['device'] = command(['udevadm', 'info', '--query=all', '--name=' + self.node])
        self.metadata['fixture_setup'] = self.device('setup')
        self.env['DBUS_SESSION_BUS_ADDRESS'] = self.bus('desktop-bus')
        read_fd, write_fd = os.pipe()
        try:
            self.processes.start(['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '1280x960x24',
                                  '-nolisten', 'tcp', '-ac'], self.out / 'xvfb.log', pass_fds=(write_fd,))
            os.close(write_fd)
            write_fd = None
            if not select.select([read_fd], [], [], 10)[0]:
                raise TimeoutError('Xvfb did not allocate a desktop')
            display = os.read(read_fd, 32).decode().strip()
            if not display.isdecimal():
                raise RuntimeError('invalid Xvfb display')
            self.env.update(DISPLAY=':' + display, NO_AT_BRIDGE='0', GTK_MODULES='gail:atk-bridge',
                            ACCESSIBILITY_ENABLED='1', GNOME_ACCESSIBILITY='1', LANG='en_US.UTF-8',
                            LC_ALL='en_US.UTF-8', MOZ_ENABLE_WAYLAND='0')
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
        wm_config = self.state / 'openbox.xml'
        wm_config.write_text('<openbox_config xmlns="http://openbox.org/3.4/rc"><focus><focusNew>yes</focusNew></focus></openbox_config>')
        self.processes.start(['openbox', '--sm-disable', '--config-file', str(wm_config)], self.out / 'desktop.log', env=self.env)
        # WINK needs a real notification service even in auto-approve mode.
        # Run Dunst on only the daemon's private bus, never a mocked notifier.
        notification_config = self.state / 'dunstrc'
        notification_config.write_text('[global]\ntimeout = 2\nnotification_limit = 1\n')
        notification_env = {**self.env, 'DBUS_SESSION_BUS_ADDRESS': daemon_env['DBUS_SESSION_BUS_ADDRESS']}
        self.processes.start(['dunst', '-conf', str(notification_config)], self.out / 'notifications.log', env=notification_env)
        def notification_ready():
            response = command(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.Notifications',
                                '--object-path', '/org/freedesktop/Notifications',
                                '--method', 'org.freedesktop.Notifications.GetServerInformation'], env=notification_env, timeout=2)
            return response if response['status'] == 0 else None
        self.metadata['notification_server'] = wait_until(notification_ready, 10)
        service = configparser.ConfigParser()
        service.read('/usr/share/dbus-1/services/org.a11y.Bus.service')
        launcher = shlex.split(service['D-BUS Service']['Exec'])
        self.processes.start(launcher + ['--launch-immediately'], self.out / 'accessibility.log', env=self.env)
        self.env['AT_SPI_BUS_ADDRESS'] = wait_until(self.accessibility_bus, 10)
        self.metadata['accessibility_registry_ready'] = True
        # Fail if the native accessibility peer cannot reach this isolated desktop.
        peer('ui.py', {"pin": self.pin, "account": None}, self.env, python='/usr/bin/python3')
        self.port = free_port()
        rp_env = {**self.env, 'RP_DATA': str(self.rp_data), 'RP_PORT': str(self.port)}
        self.rp_process = self.processes.start([sys.executable, str(HERE / 'server.py')], self.out / 'rp.log', env=rp_env)
        wait_until(lambda: self.rp_data.exists() and self.endpoint_ready(self.port), 10)
        self.start_browser()
        self.metadata['browser_started'] = True

    def accessibility_bus(self):
        # libatspi can abort if queried before its freshly launched bus and
        # registry own their names. Probe both explicitly before importing it.
        try:
            response = command(['gdbus', 'call', '--session', '--dest', 'org.a11y.Bus',
                                '--object-path', '/org/a11y/bus', '--method', 'org.a11y.Bus.GetAddress'],
                               env=self.env, timeout=2)
            if response['status']:
                return None
            address, = ast.literal_eval(response['stdout'])
            if not isinstance(address, str) or not address.startswith('unix:'):
                return None
            base = ['gdbus', 'call', '--address', address, '--dest', 'org.freedesktop.DBus',
                    '--object-path', '/org/freedesktop/DBus', '--method']
            started = command(base + ['org.freedesktop.DBus.StartServiceByName', 'org.a11y.atspi.Registry', '0'],
                              env=self.env, timeout=2)
            if started['status']:
                return None
            owner = command(base + ['org.freedesktop.DBus.GetNameOwner', 'org.a11y.atspi.Registry'], env=self.env, timeout=2)
            return address if owner['status'] == 0 else None
        except (OSError, subprocess.TimeoutExpired, ValueError, SyntaxError):
            return None

    @staticmethod
    def endpoint_ready(port):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return True
        except OSError:
            return False

    def bus(self, name):
        endpoint = self.state / name
        address = 'unix:path=' + str(endpoint)
        self.processes.start(['dbus-daemon', '--nofork', '--config-file=' + str(ROOT / 'tests/e2e/session-bus.conf'),
                              '--address=' + address], self.out / (name + '.log'))
        wait_until(endpoint.exists, 5)
        return address

    def device(self, operation):
        return peer('device.py', {"node": self.node, "pin": self.pin, "operation": operation}, self.env, timeout=20)

    def console(self, entry):
        # Do not dump protocol frames, log arguments or driver/session tokens.
        with self.console_file.open('a') as output:
            output.write(self.safe_text(json.dumps({k: getattr(entry, k, None) for k in ('level', 'text', 'timestamp')}, default=str)) + '\n')

    def start_browser(self):
        from selenium import webdriver
        from selenium.webdriver.remote.client_config import ClientConfig
        from selenium.webdriver.common.proxy import Proxy, ProxyType
        port = free_port()
        args = [str(self.driver_binary), '--port=' + str(port)] if self.browser == 'chromium' else [str(self.driver_binary), '--host', '127.0.0.1', '--port', str(port), '--log', 'info']
        self.driver_process = self.processes.start(args, self.out / 'driver.log', env=self.env)
        wait_until(lambda: self.endpoint_ready(port), 10)
        if self.browser == 'chromium':
            options = webdriver.ChromeOptions()
            for flag in ('--user-data-dir=' + str(self.profile), '--no-first-run', '--no-default-browser-check',
                         '--disable-search-engine-choice-screen', '--force-renderer-accessibility', '--lang=en-US',
                         '--password-store=basic'):
                options.add_argument(flag)
        else:
            options = webdriver.FirefoxOptions()
            options.add_argument('-no-remote')
            options.add_argument('-profile')
            options.add_argument(str(self.profile))
            options.set_preference('accessibility.force_disabled', -1)
            options.set_preference('intl.accept_languages', 'en-US')
        options.binary_location = str(self.browser_binary)
        options.set_capability('webSocketUrl', True)
        options.set_capability('unhandledPromptBehavior', 'ignore')
        address = f'http://127.0.0.1:{port}'
        config = ClientConfig(address, timeout=10, proxy=Proxy({'proxyType': ProxyType.DIRECT}))
        self.driver = webdriver.Remote(command_executor=address, options=options, client_config=config)
        self.driver.set_page_load_timeout(10)
        self.driver.set_script_timeout(5)
        self.version = self.driver.capabilities['browserVersion']
        browser_pid = self.driver.capabilities.get('goog:processID', self.driver.capabilities.get('moz:processID'))
        roots = []
        if isinstance(browser_pid, int):
            arguments = Path(f'/proc/{browser_pid}/cmdline').read_bytes()
            if str(self.profile).encode() not in arguments:
                raise RuntimeError('driver browser PID does not belong to the disposable profile')
            roots.append(browser_pid)
        self.processes.adopt_descendants(roots, owner=self.driver_process.pid)
        if not self.version.startswith(self.lock['version_prefix']):
            raise RuntimeError('browser version differs from locked expectation range')
        # Keep public capabilities only; BiDi URLs/session identifiers are not artifacts.
        self.metadata['browser_version'] = self.version
        self.metadata['driver_capabilities'] = {k: v for k, v in self.driver.capabilities.items()
                                                if k in ('browserName', 'browserVersion', 'platformName')}
        self.driver.script.add_console_message_handler(self.console)
        self.driver.script.add_javascript_error_handler(self.console)
        self.driver.get(f'http://localhost:{self.port}/')
        wait_until(lambda: self.driver.execute_script('return window.pqkeyReady === true'), 10)
        self.driver.execute_script("document.getElementById('remote').checked = false")
        self.metadata['page_user_agent'] = self.driver.execute_script('return navigator.userAgent')

    def results(self):
        filename = self.rp_data / 'results.jsonl'
        if not filename.exists():
            return []
        # Ignore an append that has not yet written its newline.
        return [json.loads(line) for line in filename.read_text().split('\n')[:-1] if line]

    def screenshot(self, fixture):
        name = ''.join(c if c.isalnum() else '-' for c in fixture)
        result = subprocess.run(['scrot', str(self.out / (name + '.png'))], env=self.env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if result.returncode:
            self.failures.append(f'{fixture}: screenshot failed')

    def check_device_isolation(self):
        if fido_devices() != {self.node}:
            raise RuntimeError('FIDO device inventory changed; refusing browser/PIN actions')

    def transport_events(self, offset=0):
        path = self.out / 'daemon.log'
        data = path.read_bytes()[offset:] if path.exists() else b''
        return [{'command': int(command, 16), 'status': int(status, 16)}
                for command, status in re.findall(rb'CTAP2 cmd=(0x[0-9a-f]+) status=(0x[0-9a-f]+)', data)]

    def ceremony(self, preset, *, account=None, opaque_account=None):
        self.check_device_isolation()
        self.processes.adopt_descendants()
        self.counter += 1
        fixture = f'{preset["id"]}/{self.counter}'
        config = {**preset, 'fixtureId': fixture, 'timeout': 25000}
        daemon_log = self.out / 'daemon.log'
        transport_offset = daemon_log.stat().st_size if daemon_log.exists() else 0
        self.driver.execute_script('window.pqkeyLastResult = null; window.pqkeyLoadForm(arguments[0])', config)
        button = 'btnReg' if preset['kind'] == 'reg' else 'btnLogin'
        self.driver.find_element('id', button).click()
        self.metadata['acceptance_executed'] = True
        ui, actions = [], []
        start = time.monotonic()
        deadline = start + CEREMONY_SECONDS
        last_action = None
        fingerprint = None
        observed_fingerprint = None
        last_action_time = start
        while time.monotonic() < deadline:
            self.check_device_isolation()
            self.processes.adopt_descendants()
            if self.daemon.poll() is not None or self.driver_process.poll() is not None or self.rp_process.poll() is not None:
                raise RuntimeError('daemon, browser driver or RP exited during ceremony')
            entry = next((e for e in reversed(self.results()) if e.get('fixtureId') == fixture), None)
            if entry is not None:
                # A browser's own ceremony timeout is an infrastructure failure too.
                timed_out = entry.get('outcome') not in ('PASS', 'FAIL') and time.monotonic() - start >= 24
                transport = self.transport_events(transport_offset)
                outcome = classify(entry, preset['id'].split('/')[0], self.browser, self.version, ui,
                                   timed_out=timed_out, transport=transport)
                record = {"fixtureId": fixture, "outcome": outcome, "rp": entry, "ui_evidence": ui,
                          "ui_actions": actions, "transport_events": transport, "daemon_log_offset": transport_offset}
                if outcome not in GOOD:
                    self.screenshot(fixture)
                return record
            try:
                observation = peer('ui.py', {"pin": self.pin, "account": account, "opaque_account": opaque_account,
                                            "last_fingerprint": fingerprint}, self.env, python='/usr/bin/python3')
            except RuntimeError:
                # A native accessible can disappear while a fast ceremony
                # completes. Require its matching RP result before accepting
                # that race; otherwise the UI peer failure remains fatal.
                if any(e.get('fixtureId') == fixture for e in self.results()):
                    continue
                raise
            ui.extend(tag for tag in observation['evidence'] if tag not in ui)
            action = observation['action']
            if action:
                prompts = self.metadata.setdefault('native_prompt_actions', [])
                if observation.get('action_kind') not in prompts:
                    prompts.append(observation.get('action_kind'))
                fingerprint = observation['fingerprint']
                actions.append(action)
                # Repeatedly typing the PIN or clicking the same screen is a failure.
                if action == last_action and time.monotonic() - last_action_time > 5:
                    raise RuntimeError('native UI did not advance after repeated action')
                if action != last_action:
                    last_action, last_action_time = action, time.monotonic()
            elif fingerprint == observation['fingerprint'] and time.monotonic() - last_action_time > 10:
                raise TimeoutError('native UI did not advance within 10s of action')
            if observation['fingerprint'] != observed_fingerprint:
                self.ui_events.append({"fixtureId": fixture, **observation})
                observed_fingerprint = observation['fingerprint']
            time.sleep(0.15)
        self.screenshot(fixture)
        return {"fixtureId": fixture, "outcome": "infrastructure_failure", "reason": "bounded ceremony/UI wait expired", "ui_evidence": ui, "ui_actions": actions}

    def db(self):
        return json.loads((self.rp_data / 'db.json').read_text())

    def capability(self, preset, entry):
        # Missing output is measured separately from cryptographic verification.
        extensions = entry['credential'].get('clientExtensionResults', {})
        signed = next((c['detail'] for c in entry['checks'] if c['check'] == 'authenticator extension outputs'), {}) or {}
        if preset.get('prf') and not extensions.get('prf', {}).get('enabled'):
            return 'prf'
        if preset.get('prfSalt1') and not extensions.get('prf', {}).get('results', {}).get('first'):
            return 'prf'
        if preset.get('prfSalt2') and not extensions.get('prf', {}).get('results', {}).get('second'):
            return 'prf'
        if preset.get('credProtect') and 'credProtect' not in signed:
            return 'credProtect'
        if preset.get('att') == 'direct':
            fmt = next(c['detail'] for c in entry['checks'] if c['check'] == 'attestation format')
            if fmt == 'none':
                return 'attestation'
        return None

    def run_presets(self):
        previous_alice = None
        for preset, row in zip(self.presets, self.rows):
            row['attempted'] = True
            row.pop('reason', None)
            try:
                account = 'alice' if preset['id'] == 'L2' else preset['username']
                opaque_account = None
                if self.browser == 'firefox' and preset['id'] == 'L2':
                    # With UV discouraged the key intentionally omits account
                    # names. Firefox labels these ordered CTAP responses by
                    # index. Bind the selected index to read-only enumeration
                    # and require its exact credential in the RP verifier.
                    eligible = [c for c in self.device('enumerate') if c['cred_protect'] == 1]
                    selected = next((i for i, c in enumerate(eligible) if c['user']['name'] == account), None)
                    if selected is None:
                        raise AssertionError('expected unverified discoverable account is unavailable')
                    preset = {**preset, 'expectedCredential': eligible[selected]['id']}
                    opaque_account = {'index': selected, 'count': len(eligible)}
                    row['opaque_account_selection'] = {'index': selected, 'credential': eligible[selected]['id'],
                                                       'enumeration': eligible}
                first = self.ceremony(preset, account=account, opaque_account=opaque_account)
                row['ceremonies'].append(first)
                row['outcome'] = first['outcome']
                if first['outcome'] != 'verified_success':
                    row['reason'] = first.get('rp', {}).get('summary', first.get('reason', 'ceremony did not verify'))
                if first.get('rp', {}).get('outcome') == 'PASS':
                    entry = first['rp']
                    if preset['kind'] == 'reg':
                        if preset['id'] in ('R9', 'R10', 'R11'):
                            wanted = -7 if self.browser == 'firefox' else {'R9': -48, 'R10': -7, 'R11': -50}[preset['id']]
                            if entry['selectedAlgorithm'] != wanted:
                                raise AssertionError('mixed parameter preference differs from pinned client policy')
                        identifier = entry['credentialId']
                        record = next(c for c in self.db()['users'][preset['username']]['credentials'] if c['id'] == identifier)
                        if preset['id'] == 'R1' and len(base64.urlsafe_b64decode(identifier + '===')) != 107:
                            raise AssertionError('R1 must exercise sealed non-discoverable IDs')
                        if preset['id'] == 'R30' and (len(base64.urlsafe_b64decode(identifier + '===')) != 33 or record['disc']):
                            raise AssertionError('R30 must exercise stored non-discoverable IDs')
                        for mode in (['cred:' + identifier, 'empty'] if record['disc'] else ['cred:' + identifier]):
                            followup = {"id": preset['id'] + '/' + ('discoverable' if mode == 'empty' else 'allow'),
                                        "kind": 'login', "label": 'verified companion ' + preset['id'],
                                        "username": preset['username'], "allow": mode,
                                        "uv": 'required' if mode == 'empty' or preset.get('uv') == 'required' or preset['id'] == 'R19' else 'discouraged',
                                        "expectedCredential": identifier}
                            verified = self.ceremony(followup, account=preset['username'])
                            row['ceremonies'].append(verified)
                            if verified['outcome'] != 'verified_success':
                                row['outcome'] = 'unexpected_failure'
                                row['reason'] = 'accepted registration lacks a verified matching assertion'
                        if preset['id'] in ('R2', 'R13'):
                            snapshot = self.device('enumerate')
                            row['credential_management'] = snapshot
                            alice = [item for item in snapshot if item['user']['name'] == 'alice']
                            if len(alice) != 1 or alice[0]['id'] != identifier:
                                raise AssertionError('Alice replacement/enumeration mismatch')
                            if preset['id'] == 'R13' and (previous_alice is None or any(item['id'] == previous_alice for item in snapshot)):
                                raise AssertionError('R13 did not replace R2')
                            previous_alice = identifier
                        if preset['id'] == 'R14':
                            raise AssertionError('exclusion unexpectedly created a credential')
                    capability = self.capability(preset, entry)
                    if capability and row['outcome'] == 'verified_success':
                        row.update(outcome='unsupported_browser_capability', reason=f'{capability}: requested output absent from verified ceremony',
                                   capability=capability, source=json.loads((HERE / 'expectations.json').read_text())['extension_sources'][capability])
                    if preset['id'] in ('L4', 'L5', 'L6', 'L7'):
                        repeated = self.ceremony(preset, account=preset['username'])
                        row['ceremonies'].append(repeated)
                        if repeated['outcome'] != 'verified_success':
                            row['outcome'] = 'unexpected_failure'
                if preset['id'] in CONTROL_IDS and row['outcome'] != 'verified_success':
                    row['reason'] = 'mandatory classic/PIN/discoverable control failed: ' + row.get('reason', '')
            except Exception as error:
                row.update(outcome='infrastructure_failure' if not isinstance(error, AssertionError) else 'unexpected_failure',
                           reason=self.safe_text(f'{type(error).__name__}: {error}'))
                try:
                    self.screenshot(preset['id'])
                except Exception:
                    pass
            finally:
                self.write()
                print(f'{self.browser} {row["preset"]}: {row["outcome"]}', flush=True)
            if row['outcome'] not in GOOD:
                # Abort/dismiss only this browser request, preserve daemon and fixtures.
                try:
                    self.driver.execute_script("document.getElementById('btnAbort').click()")
                    self.driver.get(f'http://localhost:{self.port}/')
                    wait_until(lambda: self.driver.execute_script('return window.pqkeyReady === true'), 5)
                    self.driver.execute_script("document.getElementById('remote').checked = false")
                except Exception:
                    self.failures.append(f'{preset["id"]}: browser recovery failed')
                    self.close_browser()
                    try:
                        self.start_browser()
                    except Exception:
                        self.failures.append(f'{preset["id"]}: browser restart failed; subsequent presets will still be attempted')

    def close_browser(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                self.failures.append('WebDriver quit failed')
            self.driver = None
        if hasattr(self, 'driver_process'):
            self.processes.stop(self.driver_process)
            self.processes.stop_descendants(self.driver_process.pid)

    def cleanup(self):
        try:
            self.processes.adopt_descendants()
        except (OSError, RuntimeError):
            self.failures.append('could not snapshot owned descendants for cleanup')
        try:
            self.close_browser()
        except Exception as error:
            self.failures.append(f'browser cleanup: {type(error).__name__}')
        if self.daemon:
            try:
                if self.daemon.poll() is not None:
                    raise RuntimeError('daemon exited before cleanup')
                stopped = command([str(self.binary), '--state-dir', str(self.state / 'daemon'), 'stop'], timeout=5)
                if stopped['status'] or self.daemon.wait(timeout=5) != 0:
                    raise RuntimeError('daemon stop/exit failed')
                wait_until(lambda: not list(Path('/').glob(DEVICE_GLOB.lstrip('/'))), 5)
                self.metadata['daemon_clean_exit_and_device_removed'] = True
            except Exception as error:
                self.failures.append(f'daemon cleanup: {type(error).__name__}: {error}')
        self.failures.extend(self.processes.cleanup())
        if self.work:
            # Explicit artifact allow-list: never copy db.json, profiles or daemon state.
            source = self.rp_data / 'results.jsonl'
            if source.exists():
                (self.out / 'rp-verifier.jsonl').write_bytes(source.read_bytes())
            (self.out / 'native-ui.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in self.ui_events))
            self.work.cleanup()

    def execute(self):
        self.write()
        try:
            self.setup()
            self.run_presets()
            if not {'pin', 'account'} <= set(self.metadata.get('native_prompt_actions', [])):
                self.failures.append('mandatory native PIN/account prompt automation was not observed')
        except RunInterrupted as error:
            self.failures.append(str(error))
            raise
        except Exception as error:
            self.failures.append(self.safe_text(f'setup/runtime: {type(error).__name__}: {error}'))
            print(self.failures[-1], file=sys.stderr)
        finally:
            self.cleanup()
            ok = self.write()
        print(f'{self.browser}: {"PASS" if ok else "FAIL / incomplete"}; evidence: {self.out}')
        return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('browser', choices=('chromium', 'firefox', 'all'))
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--binaries', type=Path, help='digest-verified download.py output (one browser only)')
    parser.add_argument('--control', type=Path, help='new private directory for workflow cleanup ledger')
    parser.add_argument('--initialize', action='store_true', help='write pending report before workflow setup')
    args = parser.parse_args()
    if args.browser == 'all' and args.binaries:
        parser.error('--binaries requires one browser')
    def interrupted(signum, _frame):
        raise RunInterrupted(signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    artifacts = args.artifacts or Path(tempfile.mkdtemp(prefix='pqkey-browser-evidence-'))
    passed = True
    for browser in (('chromium', 'firefox') if args.browser == 'all' else (args.browser,)):
        run = Run(browser, artifacts.resolve(), args.binaries.resolve() if args.binaries else None,
                  args.control / browser if args.control else None)
        if args.initialize:
            run.metadata['initialized_only'] = True
            run.failures.append('Acceptance not started; inspect workflow setup logs')
            run.write()
        else:
            try:
                passed = run.execute() and passed
            except RunInterrupted as error:
                return 128 + error.signum
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
