# Browser test kit

A local relying party for trying pqkey in real browsers. Public demo sites
rarely offer ML-DSA, and none check everything a key returns. This kit checks
registrations and sign-ins with python-fido2's server where its algorithm
support permits, and always with the end-to-end suite's independent checks.
It also records what the browser
itself reports about each credential.

For repeatable Chromium/Firefox execution over real Linux UHID, use the
[acceptance workflow and local harness](ACCEPTANCE.md). It runs all R1–R35
and L1–L7 presets with verified companion assertions, native browser prompts,
disposable state and retained diagnostics. It is dispatched manually; offline
harness tests and unavailable macOS/Docker runtimes are not browser passes.

```bash
scripts/browser.sh
```

Then open `http://localhost:8080` with pqkey running. The registrations create
real credentials on your key, for `localhost`; `pqkey passkeys delete`
removes the discoverable ones one at a time.

The acceptance harness instead creates its own isolated key and never uses your
installed service or personal browser profiles. Known python-fido2 algorithm
verification limits are recorded explicitly; the independent verifier remains
mandatory. PRF secret outputs are hashed in public result logs.

- **Presets** cover each algorithm and mixed lists, discoverable and
  non-discoverable credentials, user verification, PRF (`hmac-secret` and
  `hmac-secret-mc`),
  credProtect and attestation. The form runs anything else.
- **Results** are in `tests/browser/data/`, which git ignores:
  `results.jsonl` has every check of every ceremony.
- **Remote control** lets a script queue ceremonies while you approve the
  prompts and type PINs: tick it on the page, then run
  `tests/browser/q.py chrome R1 R3` (or `firefox`).

[`contrib/debug/`](../../contrib/debug) decodes an `strace` of the daemon into
CTAPHID and CTAP messages, and verifies them offline with the same checks. The
top of each script there says how to use it.
