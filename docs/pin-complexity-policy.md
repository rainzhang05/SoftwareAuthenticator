# PIN complexity policy

pqkey starts with PIN complexity disabled. Enable it with
`pqkey config pin-complexity` (or add `--yes` to skip confirmation).
`pqkey config` shows the current setting.

When enabled, every new PIN must contain at least one ASCII letter (`A`–`Z`
or `a`–`z`) and at least one ASCII digit (`0`–`9`). Other Unicode characters
remain permitted, but non-ASCII letters and digits do not satisfy these two
requirements. For example, `Ab12` and `éA12` qualify; `abcd`, `1234`, and
`é234` do not.

The existing requirements also apply: PIN input is normalized to NFC by the
management client, a new PIN must meet the configured minimum length in
Unicode code points (initially four), and its UTF-8 representation must be
at most 63 bytes.

Enabling complexity while a PIN exists requires one PIN change, even if that
PIN already contains an ASCII letter and digit. The authenticator stores a
hash and cannot establish its composition. Existing tokens are invalidated.
The preceding PIN can still authorize a different, compliant replacement.
Repeated enable requests do not themselves require another change. Enabling
without a PIN makes the first PIN subject to the policy.

False or omitted configuration inputs preserve the setting and any required
PIN change. Only `pqkey reset` disables an enabled policy. Reset also erases
the PIN, credentials and large blobs and restores configuration defaults.
Restarting pqkey preserves the policy.

`authenticatorGetInfo` reports the current boolean at key `0x1B` and this
page's URL as a CBOR byte string of UTF-8 bytes at key `0x1C`. The
`pinComplexityPolicy` credential-creation extension returns the current
boolean only when requested with `true` by an RP on the configured
`minPinLengthRPIDs` list. This includes `false` when disabled. It produces
no output for unauthorized RPs, false or absent requests, or assertions.
PIN complexity does not independently restrict U2F; `alwaysUv` controls
U2F availability.

The protocol behavior follows [CTAP 2.3 Proposed Standard, February 26,
2026](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html),
§§6.4, 6.11.4, 7.5 and 12.6.
