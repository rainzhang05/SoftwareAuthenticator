# Browser test kit

A local relying party for trying pqkey in real browsers. Public demo sites
rarely offer ML-DSA, and none check everything a key returns. This kit checks
every registration and sign-in twice: once with python-fido2's server, and
once with the end-to-end suite's own checks. It also records what the browser
itself reports about each credential.

```bash
scripts/browser.sh
```

Then open `http://localhost:8080` with pqkey running. The registrations create
real credentials on your key, for `localhost`; `pqkey passkeys delete`
removes the discoverable ones one at a time.

- **Presets** cover each algorithm and mixed lists, discoverable and
  non-discoverable credentials, user verification, PRF (`hmac-secret`),
  credProtect and attestation. The form runs anything else.
- **Results** are in `tests/browser/data/`, which git ignores:
  `results.jsonl` has every check of every ceremony.
- **Remote control** lets a script queue ceremonies while you approve the
  prompts and type PINs: tick it on the page, then run
  `tests/browser/q.py chrome R1 R3` (or `firefox`).

[`contrib/debug/`](../../contrib/debug) decodes an `strace` of the daemon into
CTAPHID and CTAP messages, and verifies them offline with the same checks. The
top of each script there says how to use it.
