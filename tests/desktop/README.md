# Desktop acceptance

The [installed desktop acceptance workflow](../../.github/workflows/desktop.yml)
installs pqkey with `install.sh` on a disposable Ubuntu 24.04 x86_64 runner, in
real desktop sessions with real Dunst, and checks what a user sees. Push the
commits, then dispatch it on that revision: it never runs on a push, and
nothing on macOS can stand in for it. A job has 90 minutes, each scenario 35,
and the desktop login 2 to start its session. The
[run of 2026-11-16](https://github.com/rainzhang05/SoftwareAuthenticator/actions/runs/43865928812)
passed every case at `d0a4c76`.

## Environment

The workflow creates two ordinary users with active LightDM/Xorg sessions. It
uses the shipped udev rule and the installer's ACL, with no test permission
rule; the login and user manager start before `plugdev` membership changes,
and must keep their identities and groups. A private notification bus runs
real Dunst, whose owner and capabilities are checked, and the installed
service keeps its default presence, its 30-second timeout and its
non-dumpable protection. `install.sh` is the only setup and update path. The
harness's `prepare|run|cleanup fresh|upgrade` commands refuse non-hosted
runners, existing installations and desktops, and ownership mismatches: never
relax them, or point the harness at a personal installation.

## Scenarios

- **Fresh install** of the current revision: interactive PIN setup and
  immediate HID access; verified discoverable ES256 registration and
  assertions; Deny and unanswered requests (`0x27`, the default timeout
  included), CTAPHID_CANCEL (`0x2d`) and restarts during pending operations,
  each followed by an approved recovery; installer reruns, restarts and policy
  retention; a required PIN change; and readiness with the notification server
  gone and back.
- **Update** from baseline `5dc4b7c83709a57773724e87fe4781a2f3cd0be5`, in a
  separate account: a non-interactive install of the baseline must stop at
  the missing PIN, then the account gets a PIN and a discoverable credential,
  and the current installer updates that state. The original PIN, signed
  assertions and increasing counters must survive reruns, the update and
  restarts.

Both end with CTAPHID_WINK, whose notification Dunst shows and expires, and an
approved `pqkey reset`, after which getInfo and an assertion show the PIN,
policy and passkeys erased. Every failed presence request must leave
discoverable capacity unchanged, and the next approved assertion must advance
the counter by exactly one. The minimum PIN length, always-UV and the RP
disclosure list are checked after each lifecycle change, disclosure to an
allowed RP and none to another included.

Approve and Deny are chosen in Dunst's real menu: `dunstctl context`, then
xdotool in dmenu. This is automated interaction, not physical presence, but
no fake notification server, injected signal or auto-approve mode is involved.

## System call evidence

Each scenario runs the installed daemon under the system call filter being
evaluated, from a drop-in with `SystemCallFilter=@system-service` and
`SystemCallErrorNumber=EPERM`, in place from before the first install through
every rerun, update, restart and reset; the shipped unit is not changed.

A refused call returns EPERM silently, and `SystemCallLog=` cannot log it,
since the filter's EPERM outranks its log action. So `prepare` starts the
owned user manager with `SYSTEMD_LOG_SECCOMP=1`, through a drop-in for its
`user@UID.service`, which makes systemd flag every seccomp filter it installs
for logging, and sets `kernel.printk_ratelimit=0`, because without auditd the
records reach the journal through the rate-limited kernel log; cleanup undoes
both. A canary unit under the same filter calls `chroot`, which is outside
the set, before the first install and after the daemon stops. The `seccomp`
case fails if a record other than clone3's names the daemon (its executable,
systemd's `(pqkey)` executor or a service PID), a canary record is missing,
the kernel or journald reports lost messages, or the daemons' seccomp filter
counts differ.

The shipped unit's `RestrictNamespaces=yes` makes systemd fail every clone3
with ENOSYS, since a seccomp filter cannot see its flags, and glibc falls back
to clone(). The run checks that the filter allows clone3, and counts the
daemon's clone3 records (syscall 435 on x86_64 and aarch64) as ignored.
`seccomp.log` keeps the records, and the summary's "System call filter"
section names each refused call. The rules live in
`tests/e2e/seccomp_audit.py`, which the installer E2E in
[e2e.yml](../../.github/workflows/e2e.yml) also applies, on every push, on
x86_64 and arm64, to the shipped unit as installed.

## Results and cleanup

`report.json` and `summary.md` pass only when every mandatory case ran
natively and passed, every workflow stage succeeded and both cleanup layers,
Python's and the runner's, finished. The artifacts, kept 14 days unless you download them, hold the
source revisions; the runner, kernel, package, compiler, Python and crypto
identities; executable hashes and inodes and service and session identities;
commands with their statuses and timings; the public `ceremonies.jsonl`, whose
signatures, RP binding and flags an independent pyca/cryptography verifier
checks; prompt and menu screenshots; and named diagnostics. PINs travel only
through hidden terminal input or in-memory CTAP authorization, and state,
keys, tokens, browser profiles and X credentials are never uploaded.

A runner-owned ledger names the account, home and revisions before anything
is created. Cleanup removes only owned resources; a cleanup failure fails the
workflow and keeps the ledger for a safe retry, and disposing of the runner is
the final boundary.

## Offline checks

```bash
scripts/install-tests.sh
python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v
python3 -m unittest discover -s tests/desktop -p 'test_*.py' -v
python3 -m unittest discover -s tests/browser -p 'test_*.py' -v
actionlint .github/workflows/desktop.yml .github/workflows/ci.yml
shellcheck -x -P SCRIPTDIR install.sh scripts/desktop-acceptance.sh scripts/check.sh scripts/lib.sh
```

They do not exercise real UHID or desktop approval.
