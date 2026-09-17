#!/usr/bin/env bash
# End-to-end checks of the virtual security key with libfido2's command-line
# tools (Debian/Ubuntu package fido2-tools).
#
# Usage: tests/e2e/libfido2.sh /dev/hidrawN
#
# libfido2 only knows ES256, ES384, RS256 and EdDSA credentials, so ML-DSA is
# covered by the Python suite instead; `fido2-token -I` prints ML-DSA
# algorithms as "unknown", and the Python suite checks their exact COSE IDs.
# The tests do not reset the authenticator: each registers a non-discoverable
# credential and asserts with that credential's ID in the allow list, so they do
# not depend on anything else stored on the key.

set -euo pipefail

device=${1:?usage: $0 /dev/hidrawN}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0

run_test() {
  local name=$1
  shift
  echo "::group::$name"
  # Not inside `if`: errexit is ignored in a condition, even in a subshell.
  local status=0
  set +e
  (set -euo pipefail; "$@")
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "::endgroup::"
    echo "PASS $name"
  else
    echo "::endgroup::"
    echo "::error::FAIL $name"
    failures=$((failures + 1))
  fi
}

fail() {
  echo "$*" >&2
  return 1
}

random_b64() {
  head -c "$1" /dev/urandom | base64 -w0
}

test_token_list() {
  local listing
  listing=$(fido2-token -L)
  echo "$listing"
  grep -qE "^${device}: vendor=0x1209, product=0x0001" <<<"$listing" \
    || fail "fido2-token -L does not list $device as 1209:0001"
}

test_token_info() {
  local info
  info=$(fido2-token -I "$device")
  echo "$info"
  grep -qE '^version strings: .*FIDO_2_1' <<<"$info" || fail "FIDO_2_1 is not advertised"
  grep -qE '^version strings: .*FIDO_2_0' <<<"$info" || fail "FIDO_2_0 is not advertised"
  # libfido2 names only the algorithms it implements; the three ML-DSA
  # parameter sets show up as unknown public-key algorithms.
  local expected='algorithms: es256 (public-key), unknown (public-key), unknown (public-key), unknown (public-key)'
  grep -qxF "$expected" <<<"$info" || fail "expected '$expected'"
  grep -qE '^aaguid: 5931e805a1664eb7845a7f6aa93d9cd8$' <<<"$info" || fail "unexpected AAGUID"
  grep -qE '^pin protocols: .*\b1\b' <<<"$info" || fail "PIN/UV auth protocol 1 is not advertised"
  grep -qE '^pin protocols: .*\b2\b' <<<"$info" || fail "PIN/UV auth protocol 2 is not advertised"
}

test_es256_register_and_assert() {
  local rp=libfido2.e2e.example
  local cred="$work/cred" pubkey="$work/pubkey.pem" assertion="$work/assertion"

  printf '%s\n%s\n%s\n%s\n' "$(random_b64 32)" "$rp" alice "$(random_b64 16)" \
    | fido2-cred -M -q "$device" es256 >"$cred"
  cat "$cred"

  # Verifies the packed attestation signature (with the x5c certificate if
  # there is one, else as self attestation with the credential key), the
  # RP ID hash and the UP flag, and extracts the credential public key.
  fido2-cred -V -o "$work/verified" es256 <"$cred"
  sed -n 1p "$work/verified" | cmp -s - <(sed -n 5p "$cred") \
    || fail "fido2-cred -V returned a different credential ID"
  sed -n '2,$p' "$work/verified" >"$pubkey"
  cat "$pubkey"

  local cred_id
  cred_id=$(sed -n 5p "$cred")
  printf '%s\n%s\n%s\n' "$(random_b64 32)" "$rp" "$cred_id" \
    | fido2-assert -G -p "$device" >"$assertion"
  cat "$assertion"

  # Checks the signature over authData || clientDataHash, the RP ID hash and
  # the UP flag.
  fido2-assert -V -p "$pubkey" es256 <"$assertion"

  # A different client data hash must not verify with the same signature.
  { printf '%s\n' "$(random_b64 32)"; sed -n '2,4p' "$assertion"; } >"$work/tampered"
  if fido2-assert -V -p "$pubkey" es256 <"$work/tampered" 2>/dev/null; then
    fail "fido2-assert -V accepted a signature over a different client data hash"
  fi
}

run_test "fido2-token -L lists the virtual key" test_token_list
run_test "fido2-token -I reports FIDO 2.1, four algorithms and both PIN protocols" test_token_info
run_test "ES256 fido2-cred -M / -V and fido2-assert -G / -V" test_es256_register_and_assert

if [ "$failures" -ne 0 ]; then
  echo "$failures libfido2 test(s) failed"
  exit 1
fi
echo "All libfido2 tests passed"
