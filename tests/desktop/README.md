# Installed Linux desktop acceptance

[Installed Linux desktop acceptance](../../.github/workflows/desktop.yml) is a
manual `workflow_dispatch` job on a disposable Ubuntu 24.04 x86_64 runner. It has
a 90-minute job limit and a 35-minute native deadline per scenario. It never
runs on ordinary pushes. Push the reviewed commits, then dispatch this workflow
on that revision; local macOS checks cannot establish a native acceptance pass.

The workflow creates two distinct ordinary users and active local LightDM/Xorg
sessions. It uses the shipped udev rule and installer ACL, with no test HID
permission rule. The login and user manager start before plugdev membership is
changed and must keep their identities and group vectors. A private session bus
runs real Dunst, whose bus-owner PID and capabilities are checked. The installed
service retains its default presence command and 30-second timeout. The daemon's
non-dumpable protection stays enabled; sudo reads only its public executable and
command identity.

`install.sh` is the only setup/update path. The shell wrapper provisions the
disposable desktop and dependencies, never a second authenticator setup system.
Its `prepare|run|cleanup fresh|upgrade` commands refuse non-hosted runners,
existing installations, existing desktops and ownership mismatches. Do not
relax these guards or point this harness at a personal installation.

## Scenarios

- **Fresh current revision:** interactive PIN setup and immediate HID access;
  independently verified discoverable ES256 creation and assertions; Deny and
  unanswered registration/assertion (`0x27`, including the default timeout);
  CTAPHID_CANCEL (`0x2d`); restart during both pending operations; approved
  recovery after each failure; installer rerun, restart and policy retention;
  required PIN change and unavailable/recovered notification-server readiness.
- **Baseline update:** a separate fresh account installs
  `5dc4b7c83709a57773724e87fe4781a2f3cd0be5`, first verifies noninteractive
  missing-PIN failure, then configures a PIN and discoverable credential. The
  final revision's installer updates that same state. Original-PIN verification,
  signed assertions and increasing counters must survive rerun/update/restart.

Every failed presence request must leave discoverable capacity unchanged. The
next approved assertion must advance the retained credential's counter by
exactly one. Minimum PIN length, always-UV and the minimum-length RP disclosure
list are verified after lifecycle changes. Approved non-discoverable policy
probes verify disclosure for the allowed RP and its absence for an unlisted RP.

Dunst's real context menu is opened with `dunstctl context`; xdotool selects
Approve or Deny in real dmenu. This is **automated interaction**, not physical
human presence. No fake server, injected ActionInvoked signals or auto-approve
mode establishes these results. The existing fake-server E2E suite and
[exact-version browser results](../browser/README.md) remain separate evidence.
An owned launcher records its PID/start identity before executing real dmenu,
because Dunst detaches the menu process. Its input/output and action selection
remain Dunst's normal menu protocol.

## Results and cleanup

The workflow initializes incomplete results before setup. Final `report.json`
and `summary.md` require all mandatory cases, native execution, successful
workflow stages and both Python and runner cleanup layers. A recorded failure,
missing scenario, unexecuted case or cleanup failure prevents a pass.

Artifacts include source revisions, runner/kernel/package/compiler/Python/crypto
identities, installed executable hashes/inodes and service/session identities,
commands with statuses/timings, public `ceremonies.jsonl`, prompt/menu screenshots
and named diagnostics. Ceremony evidence includes client-data hashes and public
CBOR response fields 1–3; the existing independent pyca/cryptography verifier
checks attestation/assertion signatures, RP binding and UP/UV flags. Unchanged
binary hashes across different source revisions are reported as such.

PINs travel only through hidden terminal input or in-memory CTAP authorization.
Echo/leak checks fail without publishing private output. State directories,
private keys, authorization tokens, browser profiles/control endpoints and X
credentials are excluded. Only allow-listed public files are uploaded, for 14
days; download artifacts outside the repository for longer retention.

An immutable runner-owned ledger names the account/UID/home and revisions before
provisioning. Python teardown and `always()` workflow fallback remove only owned
service/device/process/session/account resources, installed rules and temporary
state. Cleanup failures fail the workflow and retain the ownership ledger for a
safe retry. Runner disposal remains the final boundary after abrupt host loss.

## Offline checks

```bash
scripts/install-tests.sh
python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v
python3 -m unittest discover -s tests/desktop -p 'test_*.py' -v
python3 -m unittest discover -s tests/browser -p 'test_*.py' -v
actionlint .github/workflows/desktop.yml .github/workflows/ci.yml
shellcheck -x -P SCRIPTDIR install.sh scripts/desktop-acceptance.sh scripts/check.sh scripts/lib.sh
bash -n scripts/desktop-acceptance.sh
```

The Linux-specific verifier test also runs in the existing locked E2E Python
environment. Python syntax, collection, offline peers and Docker regressions do
not exercise real Linux UHID or real desktop approval. Record exact commands,
statuses, source/runtime identities and logs in a persistent directory outside
the repository. Mark native execution unavailable when the host lacks the
required kernel/session; never turn that into acceptance success.
