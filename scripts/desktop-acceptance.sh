#!/usr/bin/env bash
# Disposable GitHub-hosted runner only. The installer is the sole setup/update path.
# LightDM gives our fresh user a real active logind seat, so the shipped uaccess
# rule is tested. No test HID ownership/permission rule is installed.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-}
scenario=${2:-}
[ "$#" = 2 ] || { echo 'usage: scripts/desktop-acceptance.sh prepare|run|cleanup fresh|upgrade' >&2; exit 2; }
case "$scenario" in fresh) suffix=f ;; upgrade) suffix=u ;; *) echo 'scenario must be fresh or upgrade' >&2; exit 2 ;; esac
case "$mode" in prepare | run | cleanup) ;; *) echo 'usage: scripts/desktop-acceptance.sh prepare|run|cleanup fresh|upgrade' >&2; exit 2 ;; esac
if [ "$(uname -s)" != Linux ] || [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  echo 'UNAVAILABLE: only a disposable native GitHub-hosted Linux runner may manage this acceptance installation' >&2
  exit 2
fi
[[ ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[0-9]+$ ]] || exit 2
run_root=/var/tmp/pqkey-desktop-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}
[ "${PQKEY_DESKTOP_ROOT:-$run_root}" = "$run_root" ] || exit 2
test -d "$run_root" && test ! -L "$run_root" && test -O "$run_root"
[ "$(stat -c %a "$run_root")" = 755 ] || exit 2
work=$run_root/control-$scenario
evidence=$run_root/evidence/$scenario
user=pqd${GITHUB_RUN_ID}a${GITHUB_RUN_ATTEMPT}${suffix}
owned_home=/home/$user
unit=pqkey-desktop-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-$scenario.service
sudoers=/etc/sudoers.d/$user
rule=/etc/udev/rules.d/70-pqkey.rules
module=/etc/modules-load.d/pqkey.conf

owned() {
  [ -f "$work/owner" ] && [ "$(cat "$work/owner")" = "$user" ] || return 1
  if id "$user" >/dev/null 2>&1; then
    [ -f "$work/uid" ] && [ "$(id -u "$user")" = "$(cat "$work/uid")" ] || return 1
    [ "$(getent passwd "$user" | cut -d: -f6)" = "$owned_home" ] || return 1
  fi
}

if [ "$mode" = prepare ]; then
  # Refuse all existing installations, desktops and device clients before mutation.
  test ! -e "$work"
  test ! -L "$work"
  test ! -e "$owned_home"
  test ! -L "$owned_home"
  test "$(systemctl show "$unit" --property=LoadState --value)" = not-found
  test -z "$(find /usr/local/bin -maxdepth 1 -name 'pqkey.install-*' -print)"
  if id "$user" >/dev/null 2>&1; then exit 1; fi
  for path in /usr/local/bin/pqkey /usr/local/bin/pqkey.previous "$rule" "$module" "$sudoers"; do
    test ! -e "$path" && test ! -L "$path"
  done
  test -d /run/systemd/system
  if systemctl is-active --quiet display-manager.service || systemctl is-active --quiet lightdm.service; then exit 1; fi
  test ! -L /etc/systemd/system/lightdm.service
  # No existing desktop session may be displaced. The SSH runner session is fine.
  while read -r session _rest; do
    [ -n "$session" ] || continue
    kind=$(loginctl show-session "$session" --property=Type --value)
    case "$kind" in x11 | wayland) echo 'Existing desktop; refusing acceptance provisioning' >&2; exit 1 ;; esac
  done < <(loginctl list-sessions --no-legend)
  test -z "$(find /sys/devices/virtual/misc/uhid -name 'hidraw*' -print 2>/dev/null || true)"
  mkdir -p "$work" "$evidence"
  echo "$user" > "$work/owner"
  # Reserve the numeric identity before useradd; partial preparation is recoverable.
  uid=$(python3 -c 'import pwd; used={p.pw_uid for p in pwd.getpwall()}; print(next(i for i in range(2000, 60000) if i not in used))')
  echo "$uid" > "$work/uid"
  python3 - "$work/owner.json" "$user" "$uid" "$owned_home" "$scenario" "$(git rev-parse HEAD)" <<'PY_OWNER'
import json, sys
path, user, uid, home, scenario, source = sys.argv[1:]
with open(path, 'w') as file:
    json.dump(dict(user=user, uid=int(uid), home=home, scenario=scenario, source=source,
                   baseline='5dc4b7c83709a57773724e87fe4781a2f3cd0be5'), file)
PY_OWNER
  chmod 644 "$work/owner.json"
  # The runner account owns this ledger; the test user can only read it.
  chmod 755 "$work"
  git rev-parse HEAD > "$evidence/source.txt"
  git status --porcelain > "$evidence/source-status.txt"
  test ! -s "$evidence/source-status.txt"
  uname -a > "$evidence/kernel.txt"
  if [ -d /sys/module/uhid ]; then touch "$work/uhid-was-loaded"; fi
  # Do not let package installation start a second, unowned display manager.
  touch "$work/masked-lightdm"
  sudo systemctl mask lightdm.service
  sudo env DEBIAN_FRONTEND=noninteractive apt-get update
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    lightdm xserver-xorg-core xserver-xorg-video-dummy xauth x11-xserver-utils \
    openbox dunst suckless-tools xdotool scrot fonts-liberation dbus-daemon \
    dbus-user-session libpam-systemd libglib2.0-bin udev acl curl build-essential
  touch "$work/module-managed"
  if ! sudo modprobe uhid; then
    sudo apt-get install -y "linux-modules-extra-$(uname -r)"
    sudo modprobe uhid
  fi
  test -c /dev/uhid
  sudo useradd --uid "$uid" --create-home --shell /bin/bash "$user"
  owned
  # Sudo is ordinary installer escalation, only for this disposable user.
  echo "$user ALL=(ALL) NOPASSWD: ALL" | sudo tee "$sudoers" >/dev/null
  sudo chmod 440 "$sudoers"
  sudo visudo -cf "$sudoers"
  sudo mkdir "$owned_home/source-current" "$owned_home/source-baseline" "$owned_home/control"
  sudo chown -R "$user:$user" "$owned_home"
  # Keep the runner as evidence owner. Both actors need to write diagnostics;
  # default ACLs also cover files the test user creates during its session.
  chmod 755 "$evidence"
  sudo setfacl -m "u:$user:rwx,d:u:$user:rwx,d:u:$(id -un):rwx" "$evidence"
  git archive --format=tar HEAD | sudo -u "$user" tar -xm -C "$owned_home/source-current"
  if [ "$scenario" = upgrade ]; then
    git archive --format=tar 5dc4b7c83709a57773724e87fe4781a2f3cd0be5 | sudo -u "$user" tar -xm -C "$owned_home/source-baseline"
  fi
  sudo -u "$user" "${DESKTOP_PYTHON:?}" -m venv "$owned_home/venv"
  sudo -u "$user" "$owned_home/venv/bin/python" -m pip install --require-hashes --only-binary :all: \
    -r "$owned_home/source-current/tests/e2e/requirements.txt"
  # A real login creates the user manager BEFORE setup changes plugdev membership.
  # It stays alive through every rerun; the test checks its PID and group vector.
  mkdir "$work/sessions"
  cat > "$work/sessions/pqkey-acceptance.desktop" <<EOF
[Desktop Entry]
Name=pqkey disposable acceptance
Type=Application
Exec=/bin/bash $work/session.sh
EOF
  cat > "$work/session.sh" <<EOF
#!/usr/bin/env bash
export PATH=/usr/local/bin:/usr/bin:/bin
export PQKEY_DESKTOP_ACCEPTANCE=1
export PQKEY_OWNER_LEDGER=$work/owner.json
unset CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME
cd $owned_home/source-current || exit 1
# The hosted image's Xsession can restore the runner's runtime directory.
# Use this authenticated user's actual logind runtime; never create or chmod it.
runtime=\$(loginctl show-user $uid --property=RuntimePath --value) || exit 1
[ "\$runtime" = /run/user/$uid ] || exit 1
[ "\$(stat -c %u:%a "\$runtime")" = $uid:700 ] || exit 1
test -w "\$runtime" && test -x "\$runtime" || exit 1
printf 'inherited=%s\\nlogind=%s\\n' "\${XDG_RUNTIME_DIR:-}" "\$runtime" > $evidence/session-runtime.txt
export XDG_RUNTIME_DIR=\$runtime
printf 'started\n' > $owned_home/control/session-started
$owned_home/venv/bin/python tests/e2e/desktop_acceptance.py --evidence $evidence --control $owned_home/control > $evidence/session-controller.log 2>&1
status=\$?
printf '%s\n' "\$status" > $owned_home/control/exit-status
# Keep this login/seat intact until the workflow's owned-resource cleanup.
while :; do sleep 10; done
EOF
  chmod 755 "$work/session.sh"
  cat > "$work/xorg.conf" <<'EOF'
Section "ServerFlags"
  Option "AutoAddDevices" "false"
  Option "DontVTSwitch" "false"
EndSection
Section "Device"
  Identifier "owned-dummy"
  Driver "dummy"
  VideoRam 256000
EndSection
Section "Monitor"
  Identifier "owned-monitor"
  HorizSync 5.0-1000.0
  VertRefresh 5.0-200.0
  Modeline "1280x800" 83.5 1280 1352 1480 1680 800 803 809 831
EndSection
Section "Screen"
  Identifier "owned-screen"
  Device "owned-dummy"
  Monitor "owned-monitor"
  DefaultDepth 24
  SubSection "Display"
    Depth 24
    Modes "1280x800"
  EndSubSection
EndSection
EOF
  cat > "$work/lightdm.conf" <<EOF
[LightDM]
start-default-seat=true
minimum-display-number=80
minimum-vt=8
logind-check-graphical=false
log-directory=$work/log
run-directory=$work/run
cache-directory=$work/cache
sessions-directory=$work/sessions
dbus-service=false
[Seat:*]
xserver-command=/usr/lib/xorg/Xorg -nolisten tcp -noreset
xserver-config=$work/xorg.conf
session-wrapper=/etc/X11/Xsession
user-session=pqkey-acceptance
autologin-session=pqkey-acceptance
autologin-user=$user
autologin-user-timeout=0
allow-guest=false
allow-user-switching=false
exit-on-failure=true
EOF
  exit 0
fi

# Cleanup can run after a failed prepare before anything was provisioned.
if [ ! -e "$work/owner" ] && [ "$mode" = cleanup ]; then
  mkdir -p "$evidence"
  echo 0 > "$evidence/runner-cleanup-status"
  exit 0
fi
owned || { echo 'Ownership ledger mismatch; refusing service/user management' >&2; exit 1; }
if [ "$mode" = run ]; then
  sudo systemd-run --unit="$unit" --property=KillMode=control-group \
    /usr/sbin/lightdm --config="$work/lightdm.conf"
  systemctl show "$unit" --property=MainPID,ExecStart,ActiveState > "$evidence/desktop-unit.txt"
  deadline=$((SECONDS + 2100))
  startup_deadline=$((SECONDS + 120))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if sudo test -f "$owned_home/control/exit-status"; then
      status=$(sudo cat "$owned_home/control/exit-status")
      [[ $status =~ ^[0-9]+$ ]] || exit 1
      exit "$status"
    fi
    if [ "$SECONDS" -ge "$startup_deadline" ] && ! sudo test -f "$owned_home/control/session-started"; then
      echo 'Owned desktop login did not start the acceptance session within two minutes; see desktop diagnostics' >&2
      exit 1
    fi
    systemctl is-active --quiet "$unit" || { echo 'Owned desktop exited; see diagnostics' >&2; exit 1; }
    sleep 2
  done
  echo 'Native acceptance exceeded 35 minutes' >&2
  exit 124
fi

failed=0
# Cleanup commands contain only owned resource identities; trace them so a
# partial preparation failure retains the exact failing cleanup operation.
set -x
# Keep a cleanup ledger and diagnostics even when the session failed before Python.
# Diagnostic files are owned by the runner; sudo only supplies the read/process access.
# shellcheck disable=SC2024
# Uninstall while the owned user manager still exists; the Python finally block
# normally already did this. Keep the workflow fallback for failure/cancellation.
if id "$user" >/dev/null 2>&1; then
  uid=$(id -u "$user")
  if [ -x /usr/local/bin/pqkey ]; then
    # shellcheck disable=SC2024
    sudo -u "$user" env HOME="$owned_home" XDG_RUNTIME_DIR="/run/user/$uid" \
      /usr/local/bin/pqkey setup --uninstall > "$evidence/fallback-uninstall.log" 2>&1 || failed=1
  fi
  # shellcheck disable=SC2024
  sudo -u "$user" env XDG_RUNTIME_DIR="/run/user/$uid" \
    journalctl --user -u pqkey.service --no-pager > "$evidence/service-journal.log" 2>&1 || true
  if [ -d "$owned_home/control" ]; then
    # shellcheck disable=SC2024
    sudo -u "$user" /usr/bin/python3 "$owned_home/source-current/tests/browser/runtime.py" "$owned_home/control" \
      > "$evidence/process-cleanup.log" 2>&1 || failed=1
  fi
fi
if systemctl cat "$unit" >/dev/null 2>&1; then sudo systemctl stop "$unit" || failed=1; fi
# Only named LightDM and Xorg text logs are retained; auth files and the user's
# state, PIN, credentials, tokens and .Xauthority are never copied.
if [ -d "$work/log" ]; then
  # Open public diagnostics as the runner; copying a 0600 root log would mask
  # its inherited ACL and prevent artifact upload.
  # shellcheck disable=SC2024
  sudo cat "$work/log/lightdm.log" > "$evidence/desktop.log" 2>/dev/null || true
  # shellcheck disable=SC2024
  sudo cat "$work/log/x-80.log" > "$evidence/xorg.log" 2>/dev/null || true
fi
# shellcheck disable=SC2024
sudo journalctl -u "$unit" --no-pager > "$evidence/desktop-journal.log" 2>&1 || true
# Preserve startup diagnostics in the workflow log even if artifact upload fails.
if ! sudo test -f "$owned_home/control/session-started"; then
  tail -n 100 "$evidence/desktop.log" "$evidence/xorg.log" "$evidence/desktop-journal.log" || true
fi
if id "$user" >/dev/null 2>&1; then
  if loginctl show-user "$user" --property=UID --value >/dev/null 2>&1; then
    sudo loginctl terminate-user "$user" || failed=1
  fi
  # logind closes the session asynchronously; wait before removing its account.
  for _attempt in $(seq 1 40); do
    if ! pgrep -u "$uid" >/dev/null; then break; fi
    sleep 0.25
  done
  if [ -c /dev/uhid ]; then sudo setfacl -x "u:$(cat "$work/uid")" /dev/uhid || failed=1; fi
  # shellcheck disable=SC2024
  sudo userdel --remove "$user" > "$evidence/user-cleanup.log" 2>&1 || failed=1
fi
# Fixed installer resources were required absent before this owned installation.
# A failed installer can leave its recovery executable or root setup steps.
sudo rm -f /usr/local/bin/pqkey /usr/local/bin/pqkey.previous /usr/local/bin/pqkey.install-* "$rule" "$module" "$sudoers" || failed=1
sudo udevadm control --reload-rules || failed=1
if [ -f "$work/module-managed" ] && [ ! -f "$work/uhid-was-loaded" ]; then sudo modprobe -r uhid || failed=1; fi
if [ -f "$work/masked-lightdm" ]; then sudo systemctl unmask lightdm.service || failed=1; fi
if [ -n "$(find /sys/devices/virtual/misc/uhid -name 'hidraw*' -print 2>/dev/null || true)" ]; then failed=1; fi
# Confirm every owned global resource was actually removed.
for path in /usr/local/bin/pqkey /usr/local/bin/pqkey.previous "$owned_home" "$rule" "$module" "$sudoers"; do
  if sudo test -e "$path" || sudo test -L "$path"; then failed=1; fi
done
if id "$user" >/dev/null 2>&1; then failed=1; fi
if systemctl is-active --quiet "$unit"; then failed=1; fi
printf '%s\n' "$failed" > "$evidence/runner-cleanup-status"
if [ "$failed" = 0 ]; then sudo rm -rf -- "$work"; fi
exit "$failed"
