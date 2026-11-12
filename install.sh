#!/usr/bin/env bash
# Install pqkey from this clone and set it up, in one go:
#
#   ./install.sh          asks to go ahead, then does everything
#   ./install.sh --yes    does not ask to go ahead (a PIN it still asks for)
#
# 1. Installs what building needs and is missing: a C linker, curl and ACL tools, with
#    the system's package manager (sudo), and Rust, with rustup.
# 2. Builds pqkey from this clone, in a session of its own and after sudo
#    has forgotten your password, then asks sudo for it again and installs
#    pqkey in /usr/local/bin, where every shell finds it, this one included.
# 3. Runs `pqkey setup`: the udev rules and the uhid module (sudo), and a
#    systemd user service that starts the key with your session. It ends by
#    setting the key's PIN.
# When it ends, it has sudo forget the password again; only a signal that
# kills it before then, such as kill -9, keeps it from doing so (see cleanup).
#
# It trusts the system's commands, in directories only root can change
# (trusted); the Rust toolchain that rustup installs: the Rust installer,
# rustup, rustc and cargo; and the pqkey it builds, which holds the code of
# pqkey's dependencies. It does not trust the code the build runs, the build
# scripts and procedural macros of those dependencies, nor what that code
# writes or leaves running; alone says what such code can still do.
#
# Nothing needs a new terminal or a new login afterwards. Run it again after
# `git pull` to update: it rebuilds pqkey and restarts the key with it.

# Bash reads a script as it runs it. This one it reads to the closing brace
# at the end before it runs any of it, so that what the build writes into this
# file, which you can change, does not change this run.
# shellcheck disable=SC2329 # functions run through traps and step's "$@"
{
set -euo pipefail

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

# trusted PATH-LIST: the directories of PATH-LIST whose entries only root can
# change, so the build, which runs as you, cannot have put commands there.
# Each is owned by root and writable by root alone, as is every directory
# above it (or sticky, like /tmp). None of them is on a FUSE filesystem, whose
# daemon reports whatever owner it likes, and no mount they are on is nosuid,
# as every mount you can make yourself is (FUSE, udisks, fstab's user option)
# unless root's fstab says otherwise. A directory that does not exist yet is
# left out, so one made later is never searched.
trusted() {
  local dir real d uid mode type mount options trust lines list=''
  local -a dirs chain
  IFS=: read -ra dirs <<<"$1"
  for dir in "${dirs[@]}"; do
    real=$(CDPATH='' cd -P -- "$dir" 2>/dev/null && pwd -P) || continue
    case :$list: in *:"$real":*) continue ;; esac
    chain=("$real") d=$real
    while [ "$d" != / ]; do
      d=${d%/*} d=${d:-/}
      chain+=("$d")
    done
    trust=yes lines=0
    while read -r uid mode; do
      if [ "$uid" != 0 ]; then
        trust=no
      elif ((8#$mode & 8#22)) && { [ "$lines" = 0 ] || ! ((8#$mode & 8#1000)); }; then
        trust=no
      fi
      lines=$((lines + 1))
    done < <(command -p stat -Lc '%u %a' -- "${chain[@]}" 2>/dev/null)
    [ "$lines" = ${#chain[@]} ] || trust=no
    lines=0
    while read -r type; do
      [ "$type" != 65735546 ] || trust=no # FUSE_SUPER_MAGIC, fuse and fuseblk
      lines=$((lines + 1))
    done < <(command -p stat -fc %t -- "${chain[@]}" 2>/dev/null)
    [ "$lines" = ${#chain[@]} ] || trust=no
    # The mounts of the directory and of those above it, with their options.
    while read -r _ _ _ _ mount options _; do
      # The kernel writes a space as \040, a tab, newline or backslash as \011,
      # \012 or \134: three octal digits, which %b reads exactly after \0.
      printf -v mount %b "${mount//\\/\\0}"
      case $real/ in "${mount%/}"/*) case ,$options, in *,nosuid,*) trust=no ;; esac ;; esac
    done </proc/self/mountinfo || trust=no
    [ "$trust" = no ] || list+=${list:+:}$real
  done
  printf '%s\n' "$list"
}

# Before anything else, start again, once, in a clean shell, since what is in
# the shell that started this script would last past the build, which can
# change the files it names. Whatever that shell was (bash -i, which reads
# ~/.bashrc; bash -l, which reads ~/.bash_profile; bash -m) and whatever it
# read or ran, its functions, aliases, traps, options and loaded libraries end
# with the exec. The new shell is:
# - the bash of those directories, not one of yours, in privileged mode (-p),
#   neither interactive nor a login shell: it reads no startup file and no
#   BASH_ENV file, imports no function from the environment, and ignores
#   SHELLOPTS, BASHOPTS and CDPATH there;
# - without every LD_ variable, such as LD_PRELOAD and LD_LIBRARY_PATH, with
#   which a program loads code from files they name, and without the other
#   variables glibc removes for set-user-ID programs (unsecvars.h in glibc
#   2.39 and later). Each is kept as PQKEY_INSTALL_ENV_<name>, and only what
#   runs alone gets it back.
# The exec keeps the PID, and PQKEY_INSTALL_PID passes it on, so the new shell
# knows not to start again; whatever shell goes on checks that it is clean, or
# stops.
trusted_path=$(trusted "$PATH")
if [ -z "$trusted_path" ]; then
  [ "$(uname -s)" = Linux ] || fail "pqkey runs on Linux only"
  fail "no directory on PATH is safe from the build: owned by root and writable by root alone"
fi
clean_bash=$(PATH=$trusted_path type -P bash) || fail "no bash in a directory on PATH that only root can change"
cleared=()
for name in "${!LD_@}" GCONV_PATH GETCONF_DIR GLIBC_TUNABLES HOSTALIASES LOCALDOMAIN LOCPATH \
  MALLOC_ARENA_MAX MALLOC_ARENA_TEST MALLOC_MMAP_MAX_ MALLOC_MMAP_THRESHOLD_ MALLOC_PERTURB_ \
  MALLOC_TOP_PAD_ MALLOC_TRACE MALLOC_TRIM_THRESHOLD_ NIS_PATH NLSPATH RESOLV_HOST_CONF RES_OPTIONS \
  TMPDIR TZDIR; do
  [ -z "${!name+set}" ] || cleared+=("$name")
done
if [ "${PQKEY_INSTALL_PID:-}" != $$ ]; then
  for name in "${cleared[@]}"; do
    export "PQKEY_INSTALL_ENV_$name=${!name}"
    unset -v "$name"
  done
  PQKEY_INSTALL_PID=$$ exec "$clean_bash" -p -- "$0" "$@"
fi
unset PQKEY_INSTALL_PID
if [[ $- != *p* || $- == *i* ]] || shopt -q login_shell || [ ${#cleared[@]} != 0 ] ||
  ! [ "$BASH" -ef "$clean_bash" ]; then
  fail "cannot start again in a clean shell (the system's bash, with -p, neither interactive nor a login shell, without the variables it clears)"
fi
# From here on, this script looks commands up in those directories only. Your
# PATH, as you started it, serves Rust and the build, which run with it (with
# rustup's directory first), the lookups of what they will run, and the check
# at the end that your shell finds pqkey.
original_path=$PATH
PATH=$trusted_path
# No job control: without it a background job stays in this script's process
# group (see alone). The new shell has none; this keeps it so.
set +m

cd "$(dirname "$0")"

[ "$#" -le 1 ] || { echo "usage: $0 [--yes]" >&2; exit 2; }
yes=false
case "${1:-}" in
  "") ;;
  -y | --yes) yes=true ;;
  *)
    echo "usage: $0 [--yes]" >&2
    exit 2
    ;;
esac

[ "$(uname -s)" = Linux ] || fail "pqkey runs on Linux only"
[ "$(id -u)" != 0 ] || fail "run it as the user who will use the key, not as root; it asks for sudo when it needs to"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  bold=$'\e[1m' green=$'\e[1;32m' red=$'\e[1;31m' reset=$'\e[0m'
else
  bold='' green='' red='' reset=''
fi

# What the commands print goes here, and is shown only when one fails.
log=${XDG_CACHE_HOME:-$HOME/.cache}/pqkey/install.log

duration() { # duration SECONDS: 1m 05s, or 12s
  if [ "$1" -ge 60 ]; then
    printf '%dm %02ds' $(($1 / 60)) $(($1 % 60))
  else
    printf '%ds' "$1"
  fi
}

# The progress of the whole installation, one line redrawn in place: a bar,
# the percentage, the step under way and its time so far. Steps weigh what
# they usually take; done_weight of total_weight is behind us.
total_weight=0 done_weight=0 drawer=''
bar() { # bar PERCENT
  local i filled=$(($1 / 5)) full='' empty=''
  for ((i = 0; i < 20; i++)); do
    if [ "$i" -lt "$filled" ]; then full+='█'; else empty+='░'; fi
  done
  printf '%s%s%s%s' "$green" "$full" "$reset" "$empty"
}
draw_progress() { # draw_progress WEIGHT EXPECTED DOING: until killed
  local weight=$1 expected=$2 doing=$3 start=$SECONDS elapsed per_mille counts detail
  while :; do
    elapsed=$((SECONDS - start)) detail=''
    if [ "$expected" = cargo ]; then
      # Cargo's own count of what it has compiled, from its progress line.
      counts=$(tail -c 4096 "$log" | tr '\r' '\n' |
        grep -oE 'Building \[[^]]*\] +[0-9]+/[0-9]+' | tail -n 1 | grep -oE '[0-9]+/[0-9]+$' || true)
      if [ -n "$counts" ]; then
        per_mille=$((${counts%/*} * 1000 / ${counts#*/})) detail=" · compiled $counts"
      else
        per_mille=0 detail=' · getting the sources'
      fi
    else
      # How far a step usually is by now, short of done.
      per_mille=$((elapsed * 1000 / expected))
      [ "$per_mille" -le 950 ] || per_mille=950
    fi
    local percent=$(((done_weight * 1000 + weight * per_mille) / total_weight / 10))
    printf '\r\e[K  %s %3d%%  %s%s · %s' "$(bar "$percent")" "$percent" "$doing" "$detail" "$(duration "$elapsed")"
    sleep 0.2
  done
}

# step WEIGHT EXPECTED DOING DONE COMMAND...: run COMMAND, its output to the
# log, with the progress line while it runs (EXPECTED is how many seconds it
# usually takes, or "cargo") and DONE once it is done. If it fails, the end of
# its output, and exit.
step() {
  local weight=$1 expected=$2 doing=$3 done=$4 start=$SECONDS from status=0 took=''
  shift 4
  printf '\n==> %s\n' "$doing" >>"$log"
  from=$(($(wc -l <"$log") + 1))
  if [ -t 1 ]; then
    draw_progress "$weight" "$expected" "$doing" &
    drawer=$!
  fi
  "$@" >>"$log" 2>&1 || status=$?
  if [ -n "$drawer" ]; then
    kill "$drawer" 2>/dev/null || true
    wait "$drawer" 2>/dev/null || true
    drawer=''
    printf '\r\e[K'
  fi
  done_weight=$((done_weight + weight))
  [ $((SECONDS - start)) -lt 10 ] || took=" ($(duration $((SECONDS - start))))"
  if [ "$status" = 0 ]; then
    printf '  %s✓%s %s%s\n' "$green" "$reset" "$done" "$took"
  else
    printf '  %s✗%s %s\n\n' "$red" "$reset" "$doing"
    tail -n +"$from" "$log" | tr '\r' '\n' | grep -vE '\] +[0-9]+/[0-9]+' | tail -n 20 | sed 's/^/    /'
    printf '\nThat failed. The whole output is in %s\n' "$log"
    exit 1
  fi
}

cargo_home=${CARGO_HOME:-$HOME/.cargo}
# The PATH Rust and the build run with: yours, with rustup's directory first,
# where the Rust installer puts rustup. rustup's env file is never sourced.
your_path=$cargo_home/bin:$original_path
pqkey=/usr/local/bin/pqkey
have_rust() { PATH=$your_path command -v cargo >/dev/null; }
recovery=$pqkey.previous
staged=$pqkey.install-$$
recovery_hint() {
  if [ -f "$recovery" ]; then
    printf 'Previous executable: %s. If it supports the current credential format, restore it with: sudo mv -f %s %s && pqkey setup\n' "$recovery" "$recovery" "$pqkey" >&2
    printf 'Older binaries require a matching complete state backup; see the README recovery notes.\n' >&2
  fi
}

missing=()
PATH=$your_path command -v cc >/dev/null || missing+=(linker)
command -v setfacl >/dev/null || missing+=(acl)
have_rust || PATH=$your_path command -v curl >/dev/null || missing+=(curl)

# Disk space in MB, as measured on Ubuntu: the build tools, Rust with rustup,
# and the build (about 400 in target/, 100 of crate sources in ~/.cargo).
mb_tools=0 mb_rust=0 mb_build=500
case " ${missing[*]} " in *" linker "*) mb_tools=250 ;; *" curl "*) mb_tools=5 ;; esac
have_rust || mb_rust=500
[ ! -x target/release/pqkey ] || mb_build=50 # an update reuses the build
mb_needed=$((mb_tools + mb_rust + mb_build))
mb_free=$(df -Pm "$PWD" "$HOME" | awk 'NR > 1 { print $4 }' | sort -n | head -n 1)
size() { # size MB: MB, readably
  if [ "$1" -ge 1000 ]; then
    printf '%d.%d GB' $(($1 / 1000)) $(($1 % 1000 / 100))
  else
    printf '%d MB' "$1"
  fi
}
[ "$mb_free" -ge "$mb_needed" ] ||
  fail "pqkey needs about $(size "$mb_needed") of disk space, but only $(size "$mb_free") is free"

# Whether this commit passed CI, from this clone's own refs (no network):
# stable only ever moves to main commits whose CI, E2E and Security runs
# passed. Nothing to say without git, or in a copy that is not a clone.
ci_note=''
if command -v git >/dev/null && [ "$(git rev-parse --show-toplevel 2>/dev/null)" -ef . ]; then
  if ! git rev-parse --quiet --verify refs/remotes/origin/stable >/dev/null 2>&1; then
    ci_note='Note: without a stable branch, this clone cannot tell whether this commit passed CI.'
  elif ! git merge-base --is-ancestor HEAD refs/remotes/origin/stable 2>/dev/null; then
    ci_note='Warning: this commit is not on the stable branch, so it has not passed CI yet.'
  fi
fi

tools=("${missing[@]/linker/a C linker}")
tools=("${tools[@]/acl/device ACL tools}")
have_rust || tools+=("Rust")
printf '\n%spqkey%s, a FIDO2 security key in software\n\n' "$bold" "$reset"
echo "This sets it up for $(id -un), using about $(size "$mb_needed") of disk ($(size "$mb_free") free):"
[ ${#tools[@]} = 0 ] ||
  echo "  - what building needs: $(printf '%s, ' "${tools[@]}" | sed 's/, $//') (about $(size $((mb_tools + mb_rust))))"
echo "  - pqkey, built in this clone (about $(size "$mb_build")) and installed in $(dirname "$pqkey")"
echo "  - access to /dev/uhid for the key: udev rules and the uhid module"
echo "  - the key, started now and with every login, and its PIN"
echo
[ -z "$ci_note" ] ||
  printf '%s%s%s\nTo install stable: git fetch origin && git switch stable && ./install.sh\n\n' "$bold" "$ci_note" "$reset"
if [ ${#missing[@]} = 0 ]; then
  echo "It needs your password for sudo once, after building pqkey."
else
  echo "It needs your password for sudo twice: to install what building needs, and after building pqkey."
fi
if ! $yes; then
  [ -t 0 ] || fail "no terminal to ask on; run it with --yes"
  read -r -p "Continue? [Y/n] " answer || { echo "Installation cancelled; nothing was installed."; exit 0; }
  case $answer in [Nn]*) exit 0 ;; esac
fi

mkdir -p "$(dirname "$log")" || fail "cannot create the installation log directory"
: >"$log" || fail "cannot write $log"
[ -z "$ci_note" ] || echo "$ci_note" >>"$log"

command -v sudo >/dev/null || fail "installing pqkey needs sudo"
command -v setsid >/dev/null || fail "installing pqkey needs setsid, from util-linux"

# What runs alone runs in a session of its own (see alone), whose ID is
# $session while it runs. end_session kills, pass after pass until one finds
# nothing, every process of that session that /proc shows, with its process
# group, sparing the caller's own group; it fails if 50 passes (about 5 s)
# still find some. That is best effort: a process that forks and exits faster
# than the passes find it can outrun it, and one that leaves the session is
# out of its reach (what either can still do: see alone).
session=''
# readstat PID: all of /proc/PID/stat (a process's name may hold a newline)
# into $stat, its fields after the name from "${stat##*) }"; fails once PID is
# gone. Not $(<file): on bash 5.2, under set -e, a failed one ends the
# script, || or not, and in cleanup, the EXIT trap, ends cleanup there.
readstat() {
  stat=''
  { read -r -d '' stat || [ -n "$stat" ]; } 2>/dev/null <"/proc/$1/stat"
}
end_session() {
  local pass proc pid stat state pgrp sid own tasks found
  local -a pids
  [ -n "$session" ] || return 0
  readstat "$BASHPID" || return 1
  read -r _ _ own _ <<<"${stat##*) }"
  for ((pass = 0; pass < 50; pass++)); do
    # Newest first (an array's indices come out in numeric order), so that a
    # process that forks and exits, again and again, is still there to read.
    pids=() found=''
    for proc in /proc/[0-9]*; do pids[${proc#/proc/}]=1; done
    pids=("${!pids[@]}")
    for ((pid = ${#pids[@]} - 1; pid >= 0; pid--)); do
      readstat "${pids[pid]}" || continue
      read -r state _ pgrp sid _ <<<"${stat##*) }"
      [ "$sid" = "$session" ] && [ "$pgrp" != "$own" ] || continue
      # Its whole process group at once, even a zombie's: what it forked lives on.
      kill -KILL -- "-$pgrp" "${pids[pid]}" 2>/dev/null || true
      # A zombie counts while threads of its process still run.
      if [ "$state" = Z ] || [ "$state" = X ]; then
        tasks=(/proc/"${pids[pid]}"/task/*)
        [ ${#tasks[@]} -gt 1 ] || continue
      fi
      found=yes
    done
    [ -n "$found" ] || return 0
    sleep 0.1
  done
  return 1
}
# forward: on Ctrl-C, kill or a closed terminal, TERM to that session's first
# process group (not INT, which a background job starts with ignored), and up
# to 2 s for its leader to end; cleanup's end_session then kills whatever is
# left.
forward() {
  local tries stat state
  [ -n "$session" ] || return 0
  kill -TERM -- "-$session" 2>/dev/null || true
  for ((tries = 0; tries < 20; tries++)); do
    readstat "$session" || return 0
    read -r state _ <<<"${stat##*) }"
    [ "$state" != Z ] && [ "$state" != X ] || return 0
    sleep 0.1
  done
}

sudo_keeper=''
# ignore_signals: ignore every signal that would end or pause this script and
# that bash can ignore: all of them but KILL and STOP, which no process can,
# and 32 and 33, the real-time signals glibc keeps for itself (CHLD, CONT, URG
# and WINCH do neither).
ignore_signals() {
  trap '' HUP INT QUIT ILL TRAP ABRT BUS FPE USR1 SEGV USR2 PIPE ALRM TERM STKFLT TSTP TTIN TTOU \
    XCPU XFSZ VTALRM PROF IO PWR SYS RTMIN RTMIN+{1..15} RTMAX-{14..1} RTMAX 2>/dev/null || true
}
# cleanup [STATUS], the EXIT trap: stop the keeper and what runs alone, remove
# a staged pqkey, and have sudo forget the password as before the build, never
# asking for one; the exit status stays STATUS, else the script's. It ignores
# signals first, so that none that comes after that ends or pauses it before
# it is done, but those ignore_signals cannot ignore.
cleanup() {
  local status=${1:-$?}
  ignore_signals
  kill ${sudo_keeper:+"$sudo_keeper"} ${drawer:+"$drawer"} 2>/dev/null || true
  end_session || true
  [ ! -e "$staged" ] || sudo -n rm -f "$staged" || true
  sudo -k </dev/null >/dev/null 2>&1 || true
  if sudo -n -v </dev/null >/dev/null 2>&1; then
    sudo -K </dev/null >/dev/null 2>&1 || true
  fi
  if [ "$status" != 0 ]; then
    printf 'Installation did not finish. Fix the reported problem and rerun ./install.sh. Log: %s\n' "$log" >&2 || true
    recovery_hint || true
  fi
}
# quit STATUS, on a closed terminal (HUP, often twice), Ctrl-C (INT) or kill
# (TERM): ignore signals, forward, then run cleanup and exit with STATUS.
# cleanup runs here, not through exit's EXIT trap: bash runs a pending trap
# before any command, the EXIT trap's first included, and exit in a trap ends
# the EXIT trap. So from here on, one of these signals ends this script
# through cleanup whenever it comes, even as the script ends for another
# reason (unless the script started with it ignored, as nohup does with HUP).
quit() {
  ignore_signals
  forward
  trap - EXIT
  cleanup "$1"
  exit "$1"
}
trap cleanup EXIT
trap 'quit 129' HUP
trap 'quit 130' INT
trap 'quit 143' TERM
# Any other signal that ends this script from here on ends it after cleanup
# (bash runs the EXIT trap first), but for kill -9, one bash does not handle
# (PROF, PWR, IO, STKFLT, the real-time ones), and one that comes as an ending
# begins, before cleanup ignores it. After these, a password sudo has cached
# stays cached for sudo's timestamp_timeout (15 minutes on Debian and Ubuntu,
# 5 on Fedora, by default) after it was last asked for or refreshed (the
# keeper refreshes it every minute).

# What each step weighs in the progress bar.
[ ${#missing[@]} = 0 ] || total_weight=$((total_weight + 15))
have_rust || total_weight=$((total_weight + 20))
total_weight=$((total_weight + 60 + 5))

echo
if [ ${#missing[@]} != 0 ]; then
  packages() { # packages LINKER_PACKAGE: the packages for what is missing
    for item in "${missing[@]}"; do
      case $item in
        linker) echo "$1" ;;
        curl) echo curl ;;
        acl) echo acl ;;
      esac
    done
  }
  install_packages() {
    if command -v apt-get >/dev/null; then
      sudo -n apt-get update || return $?
      # shellcheck disable=SC2046
      sudo -n apt-get install -y $(packages build-essential)
    elif command -v dnf >/dev/null; then
      # shellcheck disable=SC2046
      sudo -n dnf install -y $(packages gcc)
    elif command -v pacman >/dev/null; then
      # shellcheck disable=SC2046
      sudo -n pacman -S --needed --noconfirm $(packages gcc)
    elif command -v zypper >/dev/null; then
      # shellcheck disable=SC2046
      sudo -n zypper --non-interactive install $(packages gcc)
    else
      echo "no apt-get, dnf, pacman or zypper: install the missing C compiler/linker (cc), curl and acl tools yourself"
      return 1
    fi
  }
  sudo -v -p "Password for sudo (%p), to install what building needs: " || fail "installing pqkey needs sudo"
  step 15 90 "Installing the build tools" "Build tools installed" install_packages
fi

# From here until pqkey is built, Rust runs, which this script trusts: its
# installer, rustup, rustc and cargo. With the build, so do the build scripts
# and procedural macros of pqkey's dependencies, which it does not trust.
# Those could use a password sudo has cached, with sudo -n, and none of this
# code needs one, so sudo forgets it now. -k clears it for this terminal; if
# sudo still validates without asking (timestamp_type=kernel on Linux, which
# -k misses in sudo 1.9.17p2 and earlier, or no password needed at all), -K
# clears it for every terminal.
sudo -k || fail "cannot make sudo forget a cached password (sudo -k failed)"
if sudo -n -v 2>/dev/null; then
  sudo -K || fail "cannot make sudo forget cached passwords (sudo -K failed)"
fi

# alone COMMAND...: run COMMAND with your PATH, rustup's directory first, and
# with the variables cleared at the start, in a session of its own that has
# no controlling terminal and reads /dev/null, then end_session. The session's
# shell (bash -p, as this one) stops before COMMAND if the session is not its
# own. What COMMAND leaves running cannot make this terminal its controlling
# one, so its sudo cannot use what sudo caches for this terminal (tty, the
# default, or kernel) or for this script (ppid). But COMMAND runs as you: it
# can change your files (shell startup files, commands in directories on your
# PATH that you can write, this clone, the pqkey it builds) and, where
# kernel.yama.ptrace_scope is 0 or Yama is absent, run code in this script.
# What survives end_session or leaves the session first (setsid, at,
# systemd-run) can go on with that after the build, and also use the
# password typed after it where sudo caches one for all of your terminals
# (timestamp_type=global), read that password from this terminal, opened by
# its name, as you type it, and change the script pqkey setup hands to sudo.
# Under global, what COMMAND changed can use that password too, if it runs
# while that is cached: a drop-in for pqkey's user service, say, which pqkey
# setup starts, or the startup files of a terminal you open.
# Ctrl-C, kill and a closed terminal reach COMMAND as TERM (forward); if this
# script dies, even by kill -9, the watchdog in the session runs end_session.
alone() {
  local status=0 caller=$BASHPID # (in the & job below, $BASHPID is the job's)
  # shellcheck disable=SC2016 # expanded by the session's own shell
  setsid --wait "$BASH" -p -c "$(declare -f readstat end_session)"'
    session=$$ installer=$1 caller=$2 path=$3
    shift 3
    # The session is the one this shell leads, known to the caller as $!, only
    # if setsid did not fork (it forks for a process-group leader).
    readstat $$
    read -r _ _ _ sid _ <<<"${stat##*) }"
    if [ "$PPID" != "$caller" ] || [ "$sid" != "$$" ]; then
      echo "cannot run $1 in a session of its own, so sudo is not asked for your password" >&2
      exit 125
    fi
    # The watchdog, in a process group of its own, which its end_session spares.
    set -m
    {
      trap "" INT TERM HUP
      while kill -0 "$installer" 2>/dev/null; do sleep 1; done
      end_session
    } </dev/null >/dev/null 2>&1 &
    set +m
    PATH=$path
    for saved in "${!PQKEY_INSTALL_ENV_@}"; do
      export "${saved#PQKEY_INSTALL_ENV_}=${!saved}"
      unset -v "$saved"
    done
    exec "$@"' alone "$$" "$caller" "$your_path" "$@" </dev/null &
  session=$!
  wait "$session" || status=$?
  end_session || { echo "cannot stop what $1 left running"; return 1; }
  session=''
  return "$status"
}

if ! have_rust; then
  install_rust() {
    alone "$BASH" -c "set -o pipefail
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"
  }
  step 20 60 "Installing Rust" "Rust installed" install_rust
fi
have_rust || fail "cargo is unavailable; check CARGO_HOME or install Rust from https://rustup.rs, then rerun $0"

# The oldest Rust that builds pqkey. With an older one, cargo stops the
# build and suggests changing Cargo.lock.
required=$(sed -nE 's/^rust-version *= *"([^"]+)".*/\1/p' Cargo.toml)
older() { # older VERSION: whether that Rust is older than the one pqkey needs
  [ "$(printf '%s\n%s\n' "$required" "$1" | sort -V | head -1)" != "$required" ]
}

# rustup and rustc are found with your PATH, as the build finds them, and run
# here, outside a session of their own, only to say which Rust there is.
# Without rustup, the system's Rust has to be new enough itself.
if ! PATH=$your_path command -v rustup >/dev/null; then
  PATH=$your_path command -v rustc >/dev/null || fail "Cargo is available but rustc is missing; install Rust with rustup and rerun $0"
  have=$(PATH=$your_path rustc --version | cut -d' ' -f2)
  if older "$have"; then
    fail "Rust $have is older than the $required pqkey needs; install Rust with rustup (https://rustup.rs) and run $0 again"
  fi
# With rustup, an older stable toolchain is updated first; the build installs
# a missing one. The check installs nothing: in this clone, rustup 1.28 and
# later would install what rust-toolchain.toml names even to list toolchains.
# What rustup and rustc print goes to the log.
elif RUSTUP_AUTO_INSTALL=0 PATH=$your_path rustup toolchain list 2>>"$log" | grep -q '^stable'; then
  have=$(PATH=$your_path rustc +stable --version 2>>"$log" | cut -d' ' -f2)
  if older "$have"; then
    update_rust() {
      if alone rustup toolchain install stable --profile minimal --no-self-update; then
        have=$(PATH=$your_path rustc +stable --version | cut -d' ' -f2) || return
      fi
      older "$have" || return 0
      echo "Rust $have is older than the $required pqkey needs; update it with: rustup update stable, then run $0 again"
      return 1
    }
    total_weight=$((total_weight + 20)) # weighed like installing Rust, once known
    step 20 60 "Updating Rust $have" "Rust updated" update_rust
  fi
fi

cargo=(cargo)
if PATH=$your_path command -v rustup >/dev/null; then
  # The stable toolchain, without the components rust-toolchain.toml adds
  # for development.
  cargo=(cargo +stable)
fi
build() {
  if PATH=$your_path command -v rustup >/dev/null &&
    ! RUSTUP_AUTO_INSTALL=0 PATH=$your_path rustup toolchain list | grep -q '^stable'; then
    alone rustup toolchain install stable --profile minimal || return $?
  fi
  # Its progress line goes to the log too, for the progress bar to read.
  CARGO_TERM_PROGRESS_WHEN=always CARGO_TERM_PROGRESS_WIDTH=100 \
    alone "${cargo[@]}" build --release --locked -p pqkey --target-dir target
}
step 60 cargo "Building pqkey" "pqkey built" build

# The password for sudo again, now that the build is over and what it left
# running in its session is gone. sudo asks for it on this terminal only,
# never through a helper program (SUDO_ASKPASS, or askpass in sudo.conf),
# which would run as you, in a desktop session the build can change. sudo
# runs one only when it cannot open the terminal, /dev/tty; so without one
# this script asks for no password, and goes on only if sudo needs none, as
# with a NOPASSWD rule on CI runners. Then sudo under pqkey setup needs none
# either; otherwise it too asks on this terminal.
unset SUDO_ASKPASS
if { true <>/dev/tty; } 2>/dev/null; then
  sudo -v -p "Password for sudo (%p), to install pqkey: " || fail "installing pqkey needs sudo"
elif ! sudo -n -v 2>/dev/null; then
  fail "installing pqkey needs your password for sudo, and there is no terminal to ask on: run ./install.sh in a terminal"
fi
# Kept fresh until the script ends, however it ends, so that the steps below
# do not ask again, not even while setup waits for the PIN. (With
# timestamp_type=ppid, sudo caches a password for each parent process: the
# keeper's refresh finds none, so the keeper stops, and sudo under pqkey
# setup asks again.)
keep_sudo() { # every minute while this script runs, and never after
  local seconds=0
  while sleep 1 && kill -0 "$$" 2>/dev/null; do
    if ((++seconds % 60 == 0)); then
      sudo -n -v 2>/dev/null || return
    fi
  done
}
keep_sudo </dev/null >/dev/null 2>&1 &
sudo_keeper=$!
install_binary() {
  # Never truncate a running executable. Keep the first recovery copy across
  # failed reruns until a complete setup establishes the new version is usable.
  sudo -n install -D -m 755 target/release/pqkey "$staged" || return $?
  if [ -f "$pqkey" ] && [ ! -e "$recovery" ]; then
    sudo -n cp -p "$pqkey" "$recovery" || return $?
  fi
  sudo -n mv -f "$staged" "$pqkey"
}
step 5 3 "Installing $pqkey" "pqkey installed in $(dirname "$pqkey")" install_binary
# Keep the known legacy path usable, including shells that cached it.
old=${CARGO_INSTALL_ROOT:-$cargo_home}/bin/pqkey
if [ -f "$old" ] && [ ! -L "$old" ] && ! [ "$old" -ef "$pqkey" ]; then
  ln -sf "$pqkey" "$old" || fail "cannot repair the old pqkey at $old"
fi

# Check the caller's PATH, not the one this script uses.
resolved=$(PATH="$original_path" command -v pqkey || true)
if [ -z "$resolved" ]; then
  # shellcheck disable=SC2016 # Show the literal command the user should run.
  fail 'pqkey is not on the terminal PATH; run export PATH="/usr/local/bin:$PATH", then ./install.sh again'
elif ! [ "$resolved" -ef "$pqkey" ]; then
  fail "pqkey resolves to $resolved; remove that older installation or run export PATH=\"/usr/local/bin:\$PATH\", then ./install.sh again"
fi

# The left side retains terminal stdin for hidden PIN input. pipefail also
# reports logging failures, and tee captures output, never terminal input.
# pqkey setup is the pqkey just built, run with the password cached. It holds
# the code of pqkey's dependencies, and the build, or what it left running,
# could have changed it: the trust any installer puts in what it installs,
# beyond what this script can check.
# Its PATH: these directories, then pqkey's own last when it is not among
# them, since setup checks that the first pqkey on its PATH is itself. Setup
# runs only sudo and systemctl by name, and finds them before. If you can
# write pqkey's directory (Debian can let its staff group write
# /usr/local/bin), Debian's secure_path already puts it before /usr/bin for
# root, so the build could act as root through it anyway.
setup_path=$trusted_path
case :$trusted_path: in *:"${pqkey%/*}":*) ;; *) setup_path+=:${pqkey%/*} ;; esac
printf '\n==> Setting up pqkey\n' >>"$log"
PATH=$setup_path "$pqkey" setup --yes 2>&1 | tee -a "$log"
sudo -n rm -f "$recovery"
exit
}
