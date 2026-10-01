# Browser test kit

A local WebAuthn relying party for trying pqkey in real browsers, by hand.
Public demo sites rarely offer ML-DSA, and none check everything a key
returns; this one does, twice. Nothing here runs in CI.

`server.py` serves `http://localhost:8080` on the loopback interfaces only.
Its relying party ID is `localhost`, which browsers treat as a secure context.
Every registration and sign-in is verified:

- by python-fido2's `Fido2Server` and its attestation verifier;
- independently, with the end-to-end suite's checks in
  [`tests/e2e/ctap.py`](../e2e/ctap.py): authenticator data and flags, the
  COSE key, the attestation statement and the signature (ES256 and ML-DSA,
  with OpenSSL through pyca/cryptography), the credential ID layout, the
  signature counter, credProtect and PRF outputs.

The page also records what the browser itself makes of the credential:
`getPublicKeyAlgorithm()`, `getPublicKey()` and the public key in `toJSON()`.

## Running it

It needs the end-to-end tests' Python packages:

```bash
python3 -m venv ~/.venvs/pqkey-e2e
~/.venvs/pqkey-e2e/bin/pip install --require-hashes --only-binary :all: -r tests/e2e/requirements.txt
~/.venvs/pqkey-e2e/bin/python tests/browser/server.py
```

Then open `http://localhost:8080` in the browser to test, with pqkey running.
`RP_PORT` changes the port, `RP_DATA` the data directory (by default
`tests/browser/data/`, which git ignores). `db.json` there holds the
registered credentials, and `results.jsonl` every check of every ceremony.

The registrations create real credentials on the key, for `localhost`.
`pqkey passkeys` lists the discoverable ones and `pqkey passkeys delete`
removes them one at a time; non-discoverable ones work until a reset.

## Presets and the form

The presets cover each algorithm alone and in mixed lists (which one does the
key pick?), discoverable and non-discoverable credentials, `excludeCredentials`,
user verification, PRF (`hmac-secret`), credProtect levels 1 to 3, and
attestation. Clicking one fills the form and runs it; the form runs anything
else. The credentials table signs in with one credential, with or without user
verification, and forgets credentials the key no longer has.

## Remote control

With "remote control" ticked, the page polls the server once a second and runs
what is queued for its browser family, one ceremony at a time. That lets a
script drive the tests while a person only approves the prompts and types PINs:

```bash
tests/browser/q.py chrome R1 R3 L4               # presets, in order
tests/browser/q.py firefox signin:-49:disc       # sign in with each discoverable ML-DSA-65 credential
tests/browser/q.py chrome wait:5000 abort:R1:8000  # pause; run R1 and abort it after 8 s
tests/browser/q.py chrome --clear R2             # drop what is still queued first
```

## Tracing what crosses the device

[`contrib/debug/`](../../contrib/debug) decodes an `strace` of the daemon into
CTAPHID and CTAP messages, and verifies every registration and assertion in it
offline with the same checks. Stop the key, run it under `strace`, and start it
again when done:

```bash
pqkey stop
strace -f -tt -e trace=read,write -e signal=none -s 4400 -xx -o /tmp/pqkey.trace pqkey run
# ... use the key, then Ctrl-C ...
python3 contrib/debug/uhid_strace_decode.py /tmp/pqkey.trace
python3 contrib/debug/verify_trace.py /tmp/pqkey.trace
pqkey start
```

Both need python-fido2. A trace holds relying party IDs, user names and the
encrypted PIN messages of every request: keep it private, and delete it.
