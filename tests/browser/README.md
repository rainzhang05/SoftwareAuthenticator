# Browser tests

## Local test kit

A local relying party for trying pqkey in real browsers. Public demo sites
rarely offer ML-DSA, and none check everything a key returns: this one checks
each registration and sign-in with the end-to-end tests' independent
verifier, and with python-fido2's server where it supports the algorithm, and
records what the browser itself reports about each credential.

```bash
scripts/browser.sh
```

Then open `http://localhost:8080` with pqkey running. Registrations create
real credentials on your key, for `localhost`; `pqkey passkeys delete` removes
the discoverable ones one at a time.

- **Presets** cover each algorithm and mixed lists, discoverable and
  non-discoverable credentials, user verification, PRF (`hmac-secret` and
  `hmac-secret-mc`), credProtect and attestation. The form runs anything else.
- **Results** are in `tests/browser/data/`, which git ignores:
  `results.jsonl` has every check of every ceremony, and `db.json` keeps the
  credentials across restarts of the server.
- **Remote control** lets a script queue ceremonies while you approve the
  prompts and type PINs: tick it on the page, then run
  `tests/browser/q.py chrome R1 R3` (or `firefox`).

[`contrib/debug/`](../../contrib/debug) decodes an `strace` of the daemon into
CTAPHID and CTAP messages and checks them offline; the top of each script
there says how to use it.

## Acceptance workflow

The [Browser UHID acceptance workflow](../../.github/workflows/browser.yml)
runs upstream Chromium and Mozilla Firefox, in one native Ubuntu 24.04 x86_64
job each, against a fresh pqkey device built with
`cargo build -p pqkey --locked --release`. Presence is
`--presence auto-approve`, so it measures compatibility, not manual presence.
Push the commits, then dispatch it (Actions → Browser UHID acceptance → Run
workflow); ordinary CI runs only its offline tests. A job has 75 minutes, its
acceptance step 45, each ceremony 30 seconds (25 for WebAuthn) and each native
UI action 10.

The [2026-10-15 run](https://github.com/rainzhang05/SoftwareAuthenticator/actions/runs/38818030676)
passed both jobs at `83837b767bb3c6c35bf6871a8289f88aa8715e6d`, with Rust
1.98.1 and Python 3.14.7, with no infrastructure or unexpected failures:

| Browser | Verified presets and probes | Expected errors | Algorithm limits | Ceremonies |
|---|---:|---:|---:|---:|
| Chromium 158.0.8107.0, snapshot 1719332 | 41 | 3 | 0 | 91 |
| Firefox 158.0 | 34 | 1 | 9 | 83 |

Chromium's expected errors are R14's exclusion and the inconsistent
credProtect inputs of R17 and R19. Firefox's limits are its own: it filters out
algorithms it does not know, and cannot represent the secp256k1 curve. The
[user guide](../../docs/user-guide.md#browsers-and-clients) lists what each
browser supports. Another browser version or source needs a run of its own.

[`toolchain.json`](toolchain.json) pins the official Linux x86_64 downloads:
Chromium snapshot 1719332 (source `087fe41c36241e05f1faa80503f534a454b7e911`)
with its ChromeDriver, and Firefox 158.0, en-US with updates disabled, with
geckodriver 0.37.1. Each download must match its committed SHA-256 digest. A
new version means updating the URLs, digests, source citations, version rules
and UI handling together, and a new run.

### Running it locally

Use an isolated Linux x86_64 host with the `uhid` module, where an
administrator has given the test user UHID and hidraw access, for example:

```udev
KERNEL=="uhid", SUBSYSTEM=="misc", OWNER="YOUR_TEST_USER", MODE="0600"
SUBSYSTEM=="hidraw", DEVPATH=="/devices/virtual/misc/uhid/0003:1209:0006.*", OWNER="YOUR_TEST_USER", MODE="0600"
```

Load `uhid` first, then reload the udev rules and trigger the UHID node. This
is a test-host prerequisite, not part of a normal installation. Install the
packages of the workflow's native-dependencies step (Xvfb,
Openbox, D-Bus, Dunst, AT-SPI with `python3-pyatspi`, xdotool, scrot, udev
and the browsers' libraries), then, from a clean checkout:

```bash
python3.14 -m venv /tmp/pqkey-browser-venv
/tmp/pqkey-browser-venv/bin/python -m pip install --require-hashes --only-binary :all: \
  -r tests/e2e/requirements.txt -r tests/browser/requirements.txt
cargo build -p pqkey --locked --release
export BROWSER_PYTHON=/tmp/pqkey-browser-venv/bin/python
scripts/browser-acceptance.sh all --artifacts /tmp/pqkey-browser-evidence
```

`chromium` or `firefox` instead of `all` runs one browser. The harness checks
`/dev/uhid` before anything else, and reports an unavailable runtime on macOS
or in a container. It never uses sudo, touches an installed key or uses
personal browser profiles, and refuses to run while another FIDO device, an
installed pqkey included, is present. Use a fresh artifact directory for each
run (by default, a new one under `/tmp`); the browser's sandbox must work.

### What it runs

Each browser gets a new daemon (product ID `1209:0006`) with new state, a
generated PIN set before the browser starts, an empty RP database and its own
D-Bus sessions, with a job-owned Dunst for WINK. Selenium fills the page's
forms, and a separate AT-SPI peer operates the browser's own PIN, account and
consent UI through accessibility actions and XTEST keys; no virtual
authenticator, mocked WebAuthn or injected credential is used.

Registrations R1–R35 each need verified companion sign-ins; L1–L7 then sign in
with the kit's allow lists, and B1/B2 probe non-discoverable Brainpool. The
order matters: R2 creates Alice's passkey and R13 replaces it, as read-only
enumeration confirms; R12 adds Bob; R14 expects `InvalidStateError` from
Alice's exclude list; R16 supplies the PRF fixture for L4–L7; and R1
exercises sealed IDs, R30 stored ones. Every preset gets a record, even after an earlier failure, and a
record that never ran a real ceremony, pending or stopped by infrastructure,
never passes.

| Outcome | Meaning |
|---|---|
| `verified_success` | The response passed independent verification, with its companion sign-ins |
| `expected_webauthn_error` | The exact expected error at the expected stage (R14, or Chromium's R17 and R19) |
| `unsupported_browser_capability` | A sourced, version-scoped browser limit matched the observed protocol, or a requested output was absent from an otherwise verified ceremony |
| `unexpected_failure` | Verification, requested behavior or an unrecognized browser error failed: it needs triage, and is not necessarily a defect of the key |
| `infrastructure_failure` | Device access, dependencies, processes, drivers, the RP, native UI or a bounded wait prevented a measurement |

An unsupported result counts only when the classic controls (R1, R2, R12, R13,
R15, R30 and L1–L3) pass, native PIN entry and account selection are observed,
and a rule in [`expectations.json`](expectations.json), drawn from primary
browser sources and the pinned version's behavior, matches; a bare
`NotAllowedError`, cancellation or timeout never counts. The RP checks origin,
challenge, RP hash, credential selection, ID form, UV, flags, signatures,
counters and extension outputs; python-fido2's unsupported algorithms are
noted, but the independent verifier must pass.

`matrix.json` and `summary.md`, which the workflow summary also shows, hold
each preset's ceremonies, UI actions and verifier results, and are kept with
the logs as artifacts for 14 days; download them to keep them longer. PRF
outputs appear only as SHA-256 hashes;
state, profiles, PINs, tokens and keys are never uploaded, and logs redact
automation endpoints, session tokens and the PIN. Cleanup removes only what
the job created, and a cleanup failure fails the job.

### Offline checks

```bash
"$BROWSER_PYTHON" -m unittest discover -s tests/browser -p 'test_*.py' -v
"$BROWSER_PYTHON" -m pytest tests/e2e/test_mldsa_verifier.py -q
actionlint .github/workflows/browser.yml .github/workflows/ci.yml
shellcheck -x scripts/browser-acceptance.sh
```

They use mocked peers and synthetic fixtures, and do not establish browser or
HID acceptance.
