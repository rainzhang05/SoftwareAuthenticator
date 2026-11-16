# PIN complexity policy

pqkey starts with PIN complexity disabled. `pqkey config pin-complexity`
enables it (`--yes` skips the confirmation), and `pqkey config` shows the
setting.

When it is enabled, every new PIN must contain at least one ASCII letter
(`A`–`Z` or `a`–`z`) and at least one ASCII digit (`0`–`9`). Other Unicode
characters stay permitted, but non-ASCII letters and digits do not meet these
requirements: `Ab12` and `éA12` qualify; `abcd`, `1234` and `é234` do not. The
other requirements still apply: the management client normalizes PIN input to
NFC, and a new PIN must meet the configured minimum length in Unicode code
points (initially four) and be at most 63 bytes in UTF-8.

Enabling complexity while a PIN exists requires one PIN change, even if that
PIN already contains an ASCII letter and digit, since the key stores only a
hash and cannot tell; it also invalidates existing tokens. The current PIN can
still authorize a different, compliant replacement. Repeated enable requests
require no further change, and enabling without a PIN makes the first PIN
subject to the policy.

False or omitted configuration inputs keep the setting and any required PIN
change, and restarting pqkey keeps the policy. Only `pqkey reset` disables it;
reset also erases the PIN, credentials and large blobs and restores the
default configuration.

`authenticatorGetInfo` reports the current setting at key `0x1B`, and this
page's URL, as a CBOR byte string of UTF-8, at key `0x1C`. The
`pinComplexityPolicy` registration extension returns the current setting,
`false` included, only when an RP on the configured `minPinLengthRPIDs` list
requests it with `true`; it produces no output for other RPs, for false or
absent requests, or for assertions. PIN complexity does not restrict U2F,
which `alwaysUv` controls.

The behavior follows [CTAP 2.3 Proposed Standard, February 26,
2026](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html),
§§6.4, 6.11.4, 7.5 and 12.6.
