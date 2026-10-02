#!/usr/bin/env bash
# The end-to-end tests, as CI runs them: four test keys, driven through their
# devices by libfido2's tools and by python-fido2.
#
#   scripts/e2e.sh
#
# Needs fido2-tools, dbus-daemon and python3-venv, and access to /dev/uhid,
# which install.sh sets up. The first run adds a udev rule that gives you the
# test keys' devices (sudo). Your own key is stopped while the tests run, as
# one test key takes its USB IDs, and started again afterwards.
# The output is in target/scripts/e2e.log.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

heading "End-to-end tests"

missing=()
have fido2-token || missing+=(fido2-tools)
have dbus-daemon || missing+=(dbus-daemon)
python3 -c 'import ensurepip' 2>/dev/null || missing+=(python3-venv)
[ ${#missing[@]} = 0 ] || die "needs ${missing[*]}; on Debian or Ubuntu: sudo apt install ${missing[*]}"
{ [ -r /dev/uhid ] && [ -w /dev/uhid ]; } || die "needs access to /dev/uhid; run ./install.sh first"

# The shipped rules hand a key's device to the desktop session's user, and
# only for product ID 0001; the test keys use 0001 to 0005.
rule=/etc/udev/rules.d/99-pqkey-e2e.rules
wanted="SUBSYSTEM==\"hidraw\", DEVPATH==\"/devices/virtual/misc/uhid/0003:1209:000[1-5].*\", OWNER=\"$(id -un)\", MODE=\"0600\""
if [ "$(cat "$rule" 2>/dev/null)" != "$wanted" ]; then
  sudo -v -p "  Password for sudo (%p), for the test keys' udev rule: " || die "the udev rule needs sudo"
  install_rule() { printf '%s\n' "$wanted" | sudo tee "$rule" >/dev/null && sudo udevadm control --reload-rules; }
  step "udev rule for the test keys" install_rule || finish
fi

export PQKEY="$root/target/release/pqkey"
E2E_WORK=$(mktemp -d)
export E2E_WORK
keys=("auto-approve 0001" "certificate 0002" "notify 0003" "unanswered 0004")
own_key_stopped=false

# Stop the test keys and the session bus, and start your own key again.
cleanup() {
  for key in "${keys[@]}"; do
    # shellcheck disable=SC2086
    [ -d "$E2E_WORK/${key% *}-state" ] && tests/e2e/daemon.sh stop $key >>"$log" 2>&1
  done
  [ -e "$E2E_WORK/session-bus.pid" ] && kill "$(cat "$E2E_WORK/session-bus.pid")" 2>/dev/null
  rm -rf "$E2E_WORK"
  if $own_key_stopped; then
    own_key_stopped=false
    step "Your key started again" pqkey start
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step "Build" cargo build -p pqkey --locked --release || finish

if have pqkey && pqkey status 2>/dev/null | grep -q '^Key: *running'; then
  step "Your key stopped for the tests" pqkey stop || finish
  own_key_stopped=true
fi

start_keys() {
  E2E_HIDRAW=$(tests/e2e/daemon.sh start auto-approve 0001 --presence auto-approve --allow-late-reset) &&
    E2E_CERTIFICATE_HIDRAW=$(tests/e2e/daemon.sh start certificate 0002 --presence auto-approve \
      --allow-late-reset --attestation certificate --manufacturer "pqkey E2E" --product "pqkey E2E key" \
      --country US) &&
    DBUS_SESSION_BUS_ADDRESS="unix:path=$E2E_WORK/session-bus" &&
    dbus-daemon --config-file=tests/e2e/session-bus.conf --address="$DBUS_SESSION_BUS_ADDRESS" \
      --fork --print-pid >"$E2E_WORK/session-bus.pid" &&
    E2E_NOTIFY_HIDRAW=$(tests/e2e/daemon.sh start notify 0003 --presence notify --presence-timeout 3 \
      --allow-late-reset) &&
    E2E_UNANSWERED_HIDRAW=$(tests/e2e/daemon.sh start unanswered 0004 --presence unanswered)
}
step "Test keys started" start_keys || finish
export E2E_HIDRAW E2E_CERTIFICATE_HIDRAW E2E_NOTIFY_HIDRAW E2E_UNANSWERED_HIDRAW DBUS_SESSION_BUS_ADDRESS

step "libfido2 tests" tests/e2e/libfido2.sh "$E2E_HIDRAW"
step "Python test packages" python_env &&
  step "python-fido2 tests" "$python" -m pytest tests/e2e -q

cleanup
finish
