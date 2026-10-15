"""Bounded helper and verifier regressions; no native acceptance claim."""
import json
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

E2E = Path(__file__).resolve().parents[1] / 'e2e'
sys.path.insert(0, str(E2E))
import setup_support
import ctaphid


class Pty(unittest.TestCase):
    def test_hidden_input_handles_distinct_prompts_without_echo(self):
        script = "import sys,termios; t=termios.tcgetattr(0); t[3]&=~termios.ECHO; termios.tcsetattr(0,termios.TCSANOW,t); print('New PIN:',flush=True); a=input(); print('Confirm new PIN:',flush=True); b=input(); print('done' if a==b else 'bad')"
        code, text = setup_support.run([sys.executable, '-c', script], os.environ,
                                      (('New PIN:', 'private-test-value'), ('Confirm new PIN:', 'private-test-value')), timeout=5)
        self.assertEqual(code, 0)
        self.assertIn('done', text)
        self.assertNotIn('private-test-value', text)

    def test_echo_and_incomplete_dialogue_withhold_input(self):
        for script in ("print('New PIN:',flush=True); input(); import time; time.sleep(.1)", "print('exited')"):
            with self.assertRaises(RuntimeError) as error:
                setup_support.run([sys.executable, '-c', script], os.environ,
                                  (('New PIN:', 'private-test-value'),), timeout=5)
            self.assertNotIn('private-test-value', str(error.exception))

    def test_noninteractive_timeout_kills_the_owned_group(self):
        process = MagicMock(pid=987654321, stdout=MagicMock())
        process.communicate.side_effect = subprocess.TimeoutExpired(['installer'], .1)
        with patch.object(setup_support.subprocess, 'Popen', return_value=process), \
             patch.object(setup_support.os, 'killpg') as kill:
            with self.assertRaises(TimeoutError):
                setup_support.run(['installer'], os.environ, timeout=.1)
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        process.wait.assert_called_once_with(timeout=5)


class Transport(unittest.TestCase):
    def test_keepalives_cannot_extend_an_absolute_deadline(self):
        hid = object.__new__(ctaphid.RawHid)
        keepalive = struct.pack('>IBH', 7, 0x80 | ctaphid.KEEPALIVE, 1) + b'\x02' + b'\0' * 56
        waits = []
        def read(wait):
            waits.append(wait)
            if wait == 0:
                raise TimeoutError('deadline')
            return keepalive
        hid.read_packet = read
        with patch.object(ctaphid.time, 'monotonic', side_effect=[0, .1, .3]):
            with self.assertRaises(TimeoutError):
                hid.receive(timeout=.2)
        self.assertEqual(waits, [.1])


@unittest.skipUnless(platform.system() == 'Linux', 'E2E client import uses the Linux HID backend')
class Evidence(unittest.TestCase):
    def test_expired_device_deadline_never_reads_ready_packets(self):
        import ctap
        connection = object.__new__(ctap._TimeoutConnection)
        connection.deadline = 10
        with patch.object(ctap.time, 'monotonic', return_value=11), patch.object(ctap.select, 'select') as select:
            with self.assertRaises(TimeoutError):
                connection.read_packet()
        select.assert_not_called()

    def test_verified_public_capture_excludes_authorization_and_large_blob_key(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature
        from fido2 import cbor
        import ctap
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        cose = {1: 2, 3: ctap.ES256, -1: 1, -2: numbers.x.to_bytes(32, 'big'), -3: numbers.y.to_bytes(32, 'big')}
        rp, digest, credential_id = 'evidence.example', b'h' * 32, b'c' * 16
        auth = ctap.sha256(rp.encode()) + b'\x45' + b'\0' * 4 + ctap.DEFAULT_AAGUID + b'\0\x10' + credential_id + cbor.encode(cose)
        response = {1: 'packed', 2: auth, 3: {'alg': -7, 'sig': key.sign(auth + digest, ec.ECDSA(hashes.SHA256()))}, 5: b'private-large-blob'}
        rows = []
        with patch.object(ctap, 'make_credential', return_value=response):
            credential = ctap.register(None, rp, ctap.ES256, uv=True, client_data_hash=digest,
                                       pin_uv_param=b'private-auth', evidence=rows.append)
        self.assertEqual(set(cbor.decode(bytes.fromhex(rows[0]['response_cbor']))), {1, 2, 3})
        data = ctap.sha256(rp.encode()) + b'\x05' + struct.pack('>I', 1)
        assertion = {1: {'id': credential_id, 'type': 'public-key'}, 2: data,
                     3: key.sign(data + digest, ec.ECDSA(hashes.SHA256())), 7: b'private-large-blob'}
        with patch.object(ctap, 'get_assertion', return_value=assertion):
            ctap.authenticate(None, credential, uv=True, client_data_hash=digest, evidence=rows.append)
        self.assertEqual(rows[-1]['counter'], 1)
        self.assertEqual(set(cbor.decode(bytes.fromhex(rows[-1]['response_cbor']))), {1, 2, 3})
        self.assertNotIn(b'private'.hex(), json.dumps(rows))
        assertion[3] = b'bad'
        with patch.object(ctap, 'get_assertion', return_value=assertion):
            with self.assertRaises(InvalidSignature):
                ctap.authenticate(None, credential, uv=True, client_data_hash=digest, evidence=rows.append)
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
