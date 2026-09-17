#!/usr/bin/env bash
# Start and stop a pc-hid-runner instance for the end-to-end tests.
#
#   tests/e2e/daemon.sh start NAME PRODUCT_ID [ATTACH_ARGUMENTS...]
#   tests/e2e/daemon.sh stop NAME PRODUCT_ID
#
# NAME keeps the state directory, log and exit status of instances apart;
# PRODUCT_ID (four hex digits, e.g. 0858) tells their virtual keys apart. Each
# instance must use a different one. `start` runs `pc-hid-runner attach
# --foreground` in the background and prints the key's hidraw node once it is
# accessible. `stop` detaches the instance and checks that it exited with
# status 0 and that its device is gone.
#
# Everything goes under $E2E_WORK: NAME-state/, NAME.status and
# e2e-diagnostics/NAME.log. The binary is $PC_HID_RUNNER, by default
# target/release/pc-hid-runner.

set -euo pipefail

usage() {
  echo "usage: $0 start NAME PRODUCT_ID [ATTACH_ARGUMENTS...] | stop NAME PRODUCT_ID" >&2
  exit 2
}

[ $# -ge 3 ] || usage
command=$1
name=$2
product_id=${3^^}
shift 3
[[ $product_id =~ ^[0-9A-F]{4}$ ]] || usage

work=${E2E_WORK:?E2E_WORK must name a work directory}
binary=${PC_HID_RUNNER:-target/release/pc-hid-runner}
state_dir="$work/$name-state"
status_file="$work/$name.status"
diagnostics="$work/e2e-diagnostics"
log="$diagnostics/$name.log"
device_glob="/sys/devices/virtual/misc/uhid/0003:096E:$product_id.*"

start() {
  mkdir -p "$diagnostics"
  rm -f "$status_file"

  # The subshell records the daemon's exit status for `stop`. All standard
  # streams are redirected so the caller does not wait for the background
  # process to close them.
  (
    status=0
    RUST_LOG=info,pc_hid_runner=debug "$binary" attach --foreground \
      --product-id "0x$product_id" --state-dir "$state_dir" "$@" || status=$?
    echo "$status" > "$status_file"
  ) </dev/null >"$log" 2>&1 &

  # Poll for the hidraw node the kernel creates for the device, and for udev
  # to hand it to this user.
  local deadline=$((SECONDS + 60)) node= sys
  while :; do
    if [ -e "$status_file" ]; then
      echo "::error::pc-hid-runner ($name) exited with status $(cat "$status_file") before the device was ready" >&2
      cat "$log" >&2
      return 1
    fi
    if [ -z "$node" ]; then
      for sys in $device_glob/hidraw/hidraw*; do
        [ -e "$sys" ] && node="/dev/${sys##*/}"
      done
    fi
    if [ -n "$node" ] && [ -r "$node" ] && [ -w "$node" ]; then
      break
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::error::no accessible hidraw node for the $name key after 60s (node: ${node:-none})" >&2
      ls -l /dev/hidraw* >&2 || true
      cat "$log" >&2
      return 1
    fi
    sleep 0.1
  done

  echo "Virtual security key ($name): $node" >&2
  ls -l "$node" >&2
  udevadm info --query=all --name="$node" > "$diagnostics/udevadm-$name.txt"
  echo "$node"
}

stop() {
  local started=$SECONDS
  "$binary" detach --state-dir "$state_dir"

  # detach returns once the daemon has released its lock; its exit status
  # follows immediately.
  local deadline=$((started + 5))
  until [ -e "$status_file" ]; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::error::pc-hid-runner ($name) did not exit within 5s of detach"
      return 1
    fi
    sleep 0.1
  done
  local status
  status=$(cat "$status_file")
  echo "pc-hid-runner ($name) exited with status $status after $((SECONDS - started))s"
  if [ "$status" != 0 ]; then
    echo "::error::pc-hid-runner ($name) exited with status $status"
    return 1
  fi

  until ! compgen -G "$device_glob" >/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::error::the $name key's device is still present after detach"
      ls -l /dev/hidraw* || true
      return 1
    fi
    sleep 0.1
  done
  echo "The $name key's device is gone"
}

case $command in
  start) start "$@" ;;
  stop) [ $# -eq 0 ] || usage; stop ;;
  *) usage ;;
esac
