#!/usr/bin/env bash
# The state of pqkey on this computer, for when something does not work: the
# installed binary against this clone, the key, its service, its devices and
# its recent log. It changes nothing.
#
#   scripts/diagnose.sh
set -uo pipefail
. "$(dirname "$0")/lib.sh"

indent() { sed 's/^/  /'; }

heading "pqkey"
if binary=$(command -v pqkey); then
  real=$(readlink -f "$binary")
  [ "$real" = "$binary" ] || binary="$binary -> $real"
  echo "  Binary:   $binary ($(pqkey --version 2>&1)), built $(date -r "$real" '+%F %R')"
else
  echo "  Binary:   not installed; run ./install.sh"
fi
echo "  Clone:    $(git log -1 --format='%h %s (%cs)' 2>/dev/null)"
changes=$(git status --porcelain 2>/dev/null | wc -l)
[ "$changes" = 0 ] || echo "            $changes uncommitted change(s)"

if [ -n "${binary:-}" ]; then
  heading "Key"
  pqkey status 2>&1 | indent
fi

heading "Service"
echo "  pqkey.service: $(systemctl --user is-enabled pqkey 2>&1), $(systemctl --user is-active pqkey 2>&1)"
exec_start=$(systemctl --user show -p ExecStart --value pqkey 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p')
[ -z "$exec_start" ] || echo "  Runs:          $exec_start"

heading "Devices"
if [ -e /sys/class/misc/uhid ]; then
  echo "  uhid module:   loaded"
else
  echo "  uhid module:   not loaded"
fi
echo "  /dev/uhid:     $(stat -c '%A %U:%G' /dev/uhid 2>&1)"
if [ ! -e /etc/udev/rules.d/70-pqkey.rules ]; then
  echo "  udev rules:    not installed"
elif cmp -s /etc/udev/rules.d/70-pqkey.rules contrib/udev/70-pqkey.rules; then
  echo "  udev rules:    installed, as in this clone"
else
  echo "  udev rules:    installed, but not as in this clone"
fi
found=false
for sys in /sys/devices/virtual/misc/uhid/0003:1209:*/hidraw/hidraw*; do
  [ -e "$sys" ] || continue
  found=true
  node=/dev/${sys##*/}
  echo "  Key device:    $node, $(stat -c '%A %U:%G' "$node") ($(basename "$(dirname "$(dirname "$sys")")"))"
done
$found || echo "  Key device:    none"
if have fido2-token; then
  echo "  FIDO devices:"
  fido2-token -L 2>&1 | indent | indent
fi

heading "Recent log"
journalctl --user -u pqkey -n 12 --no-pager -o short 2>&1 | indent
