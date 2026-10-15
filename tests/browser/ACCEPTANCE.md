# Reproducible browser / Linux UHID acceptance

The manually dispatched [Browser UHID acceptance workflow](../../.github/workflows/browser.yml)
creates two independent native Ubuntu 24.04 x86_64 jobs. It builds the checked-out
source with Rust 1.98.1 and `cargo build -p pqkey --locked --release`, then runs upstream Chromium
and Mozilla Firefox against a fresh pqkey kernel UHID device. This is the current
Linux release configuration, with explicit `--presence auto-approve`. It tests
automated compatibility, **not manual physical user presence**.

Full execution artifacts are retained with each workflow run; compatibility
summaries link their exact source and browser identities. The historical manual
Chromium 153 / Firefox 154 observations are separate from these measurements.

The [2026-10-15 native run](https://github.com/rainzhang05/SoftwareAuthenticator/actions/runs/38818030676)
passed both jobs at source `83837b767bb3c6c35bf6871a8289f88aa8715e6d`.
Chromium 158.0.8107.0 completed 91 ceremonies: 41 verified presets/probes and
three expected errors. Firefox 158.0 completed 83 ceremonies: 34 verified,
one expected exclusion and nine measured algorithm-limit results. Both covered
all 44 numbered presets/probes, passed every mandatory control, and removed
their owned HID devices cleanly. See the [client results](../../docs/development-notes.md#clients)
for algorithm and expected-error details. A different version or source requires
its own completed run.

## Dispatch and identities

Push the reviewed commits yourself, then select **Actions → Browser UHID
acceptance → Run workflow** on the intended ref. The harness never pushes.
The browser matrix runs only on `workflow_dispatch`; ordinary CI runs offline
harness/RP unit regressions. Each browser job has a 75-minute ceiling and a
45-minute acceptance step; each ceremony has a 30-second outer deadline and
a 25-second WebAuthn timeout. Native UI actions have a 10-second progress limit;
individual driver, accessibility, setup and shutdown operations are bounded too.

[`toolchain.json`](toolchain.json) locks official Linux x86_64 downloads:

| Browser | Identity | Driver |
|---|---|---|
| Upstream Chromium | snapshot 1719332, source `087fe41c36241e05f1faa80503f534a454b7e911` | same snapshot ChromeDriver |
| Mozilla Firefox | 158.0, en-US | geckodriver 0.37.1 |

These are selected test identities, not compatibility claims. Downloads require
committed SHA-256 matches before extraction. Chromium object generations are
pinned as well. Provenance is the official Chromium `REVISIONS`, Mozilla release
checksums and Mozilla geckodriver release asset digest. The lock does not resolve
“latest” at runtime. Update URLs, checksums, source citations, version rules and
native UI handling together when selecting new versions. A version change needs
a new real run; older evidence remains attributable to its recorded identity.
The disposable Firefox download uses an explicit `DisableAppUpdate` policy so
its identity cannot change during a run; upstream browser executables are unchanged.

## Local Linux entry points

Use a suitable isolated **Linux x86_64** desktop/host with a working kernel UHID
module. The entry point probes `/dev/uhid` before downloading browsers or creating
a daemon, bus, profile or authenticator state. macOS and containers without UHID
return a nonzero **unavailable runtime** result. They cannot produce acceptance
passes, even if collection or offline tests succeed.

Prepare the packages listed in the workflow's native-dependencies step. It uses
Xvfb, Openbox, D-Bus, Dunst, gdbus, AT-SPI (`python3-pyatspi` for `/usr/bin/python3`), xdotool,
scrot, udev and normal browser libraries. Browser orchestration and verification
use a separate Python 3.14 environment:

```bash
python3.14 -m venv /tmp/pqkey-browser-venv
/tmp/pqkey-browser-venv/bin/python -m pip install --require-hashes --only-binary :all: \
  -r tests/e2e/requirements.txt -r tests/browser/requirements.txt
cargo build -p pqkey --locked --release
export BROWSER_PYTHON=/tmp/pqkey-browser-venv/bin/python
scripts/browser-acceptance.sh chromium
scripts/browser-acceptance.sh firefox
# Or both, sequentially with separate profiles and authenticator state:
scripts/browser-acceptance.sh all --artifacts /tmp/pqkey-browser-evidence
```

Use a fresh artifact destination for each run. The default creates a unique
directory under `/tmp`; completed or failed evidence is never overwritten.
Only the workflow's same-source pending initialization may be resumed.

Use a clean source checkout and rebuild the release binary before each local
run. The matrix records both source identity/dirty status and the actual daemon
binary hash. A local browser sandbox must work; the harness does not disable it.
The disposable workflow configures upstream Chromium's downloaded setuid sandbox
where the runner's AppArmor policy restricts user namespaces.

An administrator must provision UHID and hidraw access in advance. For example,
load `uhid`, then install an owner-specific udev rule equivalent to the workflow:

```udev
KERNEL=="uhid", SUBSYSTEM=="misc", OWNER="YOUR_TEST_USER", MODE="0600"
SUBSYSTEM=="hidraw", DEVPATH=="/devices/virtual/misc/uhid/0003:1209:0006.*", OWNER="YOUR_TEST_USER", MODE="0600"
```

Reload udev rules and trigger the UHID node after loading the module. This is a
test-host prerequisite, not part of normal pqkey installation. The local harness
never uses sudo, modifies installed services or stops a personal authenticator.
It rejects pre-existing FIDO HID devices, including an already running pqkey;
use an isolated host/session rather than pointing it at credentials that matter.
It rechecks the device inventory before ceremonies and native PIN/UI actions.

## Fixtures and ordering

The page and harness share [`presets.json`](presets.json). Every browser starts
with a new daemon, product ID `1209:0006`, new private state, a generated fixture
PIN and an empty RP database. The PIN is provisioned over only that owned hidraw
node, before the browser starts. No credential is provisioned through a native
client: every acceptance credential comes from the page's real
`navigator.credentials.create` call, and every sign-in uses `get`.

Selenium clicks the existing page forms. A separate distro-Python AT-SPI peer
operates actual browser PIN, account, transport and attestation UI with native
accessibility actions/XTEST keys. WebDriver/CDP virtual-authenticator interfaces,
software authenticators, mocked WebAuthn functions and injected credentials are
not used. Browser and daemon processes have isolated D-Bus sessions; the daemon
bus disables activation of personal notification services. PIN and token input
never travels in argv or diagnostic output.
The daemon's private bus has a real, job-owned Dunst notification server for
WINK identification, which needs notifications even in auto-approve mode.

Registrations run **R1 through R35**, with verified companion sign-ins immediately
after each successful creation: an exact-ID allow list, plus an empty allow list
and explicit expected account/credential for discoverable credentials. A created
credential without its verified companion assertions fails the preset.
Discoverable companion assertions require UV so account names are available and
credProtect does not hide the credential. The numbered presets retain their
original UV settings.

- R2 uses Alice's existing RP user handle. Its assertions happen before R13
  replaces it. Read-only native credential enumeration after R2 and R13 confirms
  the new ID and disappearance of the old ID. Those inspection records are
  distinct from browser assertion results; their PIN tokens are not retained.
- R12 introduces Bob, so later discovery must select among multiple accounts.
  R14 runs after R13 and sends Alice's actual accumulated exclude list. Its
  narrow expected result is `InvalidStateError` from the WebAuthn stage.
- R15 requires signed UV. R16 supplies the PRF fixture for L4–L7. R17–R19 request
  enforced credProtect; missing outputs are recorded separately from a verified
  ceremony, and incorrect returned levels fail verification.
- R9–R11 retain their offered parameter order and check the pinned clients'
  choice: Chromium's ML-DSA preference and Firefox's filtering of unknown IDs.
  R20 requests direct attestation and allows its real browser consent prompt.
- R1 exercises sealed non-discoverable IDs (107 bytes, marker `0x02`); R30 and
  its assertion must exercise stored non-discoverable IDs (33 bytes, `0x00`).
  Discoverable IDs use 33 bytes, `0x01`. B1/B2 additionally probe non-discoverable
  Brainpool -265/-267 through the same forms without adding numbered presets.

**L1 through L7** run after all numbered registrations, with the original kit
allow-list behavior. L1/L3 keep Alice's accumulated list, including replaced
RP-side IDs: lists are not shortened to evade existing client/request limits.
L2 selects Alice via discovery. Firefox omits account names when UV is discouraged;
its native menu then labels responses as `Unknown account (index)`. For this case,
read-only enumeration binds the index to the key's ordered, credProtect-eligible
credentials, and the RP verifier requires the exact selected credential. No
credential is injected and no assertion is performed through that inspection
client. The pinned Firefox prompt helper preserves the CTAP response order:
[`WebAuthnPromptHelper.sys.mjs`](https://hg.mozilla.org/releases/mozilla-release/file/FIREFOX_158_0_RELEASE/toolkit/modules/WebAuthnPromptHelper.sys.mjs).
PRF sign-ins are repeated; the existing verifier
checks repeatability and salt separation, including A/B together. Comparisons
are grouped by the **signed effective UV flag**, not by requested UV wording.
B1/B2 follow the numbered presets and have companion assertions if creation
succeeds. All 42 numbered presets and both probes receive records, even after
an earlier failure. A failure of a prerequisite is not an unsupported skip.

## Outcomes and diagnostics

`matrix.json` contains metadata and one record per preset/probe, with correlated
ceremonies, native UI actions, fixture IDs, actual browser errors and verifier
results. `summary.md` is also published in the workflow summary. `attempted`
means the harness attempted the preset; infrastructure failures can prevent a
WebAuthn call from starting. `acceptance_executed` and ceremony records distinguish
that from a completed real ceremony. Pending/unexecuted records never pass.

| Outcome | Meaning |
|---|---|
| `verified_success` | Browser response passed mandatory independent verification and required companion assertions. |
| `expected_webauthn_error` | Exact expected error, preset and WebAuthn stage matched (R14 exclusion or Chromium's two inconsistent credProtect inputs). |
| `unsupported_browser_capability` | A sourced, version-scoped rejection matched independently observed protocol evidence, or a requested extension/attestation output was measurably absent from an otherwise verified ceremony. |
| `unexpected_failure` | Verification, requested behavior or an unrecognized browser error failed; needs triage and is not automatically an authenticator defect. |
| `infrastructure_failure` | Device/access, dependency, process, driver, RP setup, native UI or bounded-wait failure prevented a valid measurement. |

Unsupported observations require successful mandatory classic controls:
R1, R2, R12, R13, R15, R30 and L1–L3. A complete run must also observe native PIN
entry and account selection. Generic `NotAllowedError`, a cancellation or timeout
alone never establishes unsupported capability. [`expectations.json`](expectations.json)
records rules reviewed against native run `38698509912` and the pinned browser
sources. Firefox's unknown-algorithm rule requires the real key's `0x26`
makeCredential response after browser parameter filtering. Its secp256k1 rule
requires successful makeCredential followed by prompt browser rejection: that
browser's COSE curve parser cannot represent curve 8. Both require exactly one
creation response, successful surrounding CTAP commands, an exact algorithm set
and a non-timeout error within three seconds. Only public command/status metadata
is correlated from the daemon log; request payloads and tokens are not collected.
Chromium's R17/R19 rules require its exact inconsistent-policy error and matching
request parameters before any makeCredential command. Unexplained failures still
fail. Expand rules only from primary browser sources and captured behavior of the
exact pinned version, then dispatch again.

The RP checks origin, challenge, RP hash, credential selection, ID modality,
required UV, flags, signatures, counters and relevant extension relationships.
It retains public options, client data, attestation objects, authData, signatures,
credential identifiers and selected algorithms. Known python-fido2 unsupported
algorithms are explicit `unsupported_library_algorithm` notes; the independent
cryptography verifier must still pass. A failed check is never suppressed as a
library limitation merely because it raised an exception.

Artifacts always include the matrix/summary and available setup, build, browser
console/driver, RP, daemon and native UI logs. Unexpected UI failures capture the
private Xvfb desktop with scrot. PRF outputs are represented only by SHA-256 and
length in public evidence. Daemon state, RP `db.json`, profiles, PINs, tokens and
private keys are excluded by the upload allow-list. Artifacts expire after 14
days; download them for longer-lived compatibility records. Reproduction also
requires the recorded runner image, kernel/system packages, Python libraries,
crypto backend and binary identities; `ubuntu-24.04` alone does not freeze a
hosted runner image forever.

Process output is filtered before writing logs: private automation WebSocket
endpoints, driver session tokens and the fixture PIN are redacted. Public RP
origins, credential identifiers and signed ceremony bytes remain available.

Pinned Chromium [re-arms input protection on WebAuthn sheet transitions](https://chromium.googlesource.com/chromium/src/+/087fe41c36241e05f1faa80503f534a454b7e911/chrome/browser/ui/views/webauthn/authenticator_request_dialog_view.cc)
and rejects early button/key events. Native button input waits one second before
an XTEST click at the named control's accessibility-provided bounds, checked
against the owned Xvfb desktop. Input protection stays enabled. Acknowledged UI
actions alone never establish success; the RP response must verify. Firefox
uses native accessibility actions; its anonymous secondary menu is checked
against the inspected response count before selecting the expected index.
Chromium PIN entry and submission use separate accessibility snapshots, and
control metadata is captured before activation can destroy the control.
Native button motion avoids `xdotool --sync`: Ubuntu's shipped 2016 version
waits for motion even if the pointer already occupies the requested position.
Explicit stale-tree lookup errors permit at most three recorded retries within
the existing deadline. Device, PIN, timeout and account-count failures remain
fatal. Expected exclusion dismissal is limited to R14's exact native screen.

Cleanup closes the owned browser, stops the owned daemon and verifies device
removal, terminates owned buses/desktop processes, and removes temporary state.
An identity-checked private process ledger supports the workflow's cancellation
fallback. Cleanup failures fail the job. Only this job's udev rule and temporary
resources are removed; no process-name-wide kills or installed service control
are used.

## Offline regression checks

```bash
"$BROWSER_PYTHON" -m unittest discover -s tests/browser -p 'test_*.py' -v
"$BROWSER_PYTHON" -m pytest tests/e2e/test_mldsa_verifier.py -q
actionlint .github/workflows/browser.yml .github/workflows/ci.yml
shellcheck -x scripts/browser-acceptance.sh
bash -n scripts/browser-acceptance.sh
```

`test_*.py` uses mocked harness peers and synthetic signed RP fixtures. These
checks, Python/JavaScript syntax, archive downloads/checksums and pytest
collection **do not establish real browser or HID acceptance**. Keep their logs
and unavailable-runtime probes separate from native execution results. Normal
Rust/crypto/store/transport sources and Cargo graphs are outside this change.
