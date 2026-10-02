#!/usr/bin/env bash
# Install pqkey from this clone and set it up, in one go:
#
#   ./install.sh          asks once, then does everything
#   ./install.sh --yes    does not ask to go ahead (a PIN it still asks for)
#
# 1. Installs what building needs and is missing: a C linker and curl, with
#    the system's package manager (sudo), and Rust, with rustup.
# 2. Builds pqkey from this clone and installs it in /usr/local/bin (sudo),
#    where every shell finds it, this one included.
# 3. Runs `pqkey setup`: the udev rules and the uhid module (sudo), and a
#    systemd user service that starts the key with your session. It ends by
#    setting the key's PIN.
#
# Nothing needs a new terminal or a new login afterwards. Run it again after
# `git pull` to update: it rebuilds pqkey and restarts the key with it.
set -euo pipefail

cd "$(dirname "$0")"

yes=false
case "${1:-}" in
  "") ;;
  -y | --yes) yes=true ;;
  *)
    echo "usage: $0 [--yes]" >&2
    exit 2
    ;;
esac

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

[ "$(uname -s)" = Linux ] || fail "pqkey runs on Linux only"
[ "$(id -u)" != 0 ] || fail "run it as the user who will use the key, not as root; it asks for sudo when it needs to"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  bold=$'\e[1m' green=$'\e[1;32m' red=$'\e[1;31m' reset=$'\e[0m'
else
  bold='' green='' red='' reset=''
fi

# What the commands print goes here, and is shown only when one fails.
log=${XDG_CACHE_HOME:-$HOME/.cache}/pqkey/install.log
mkdir -p "$(dirname "$log")"
: >"$log"

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
pqkey=/usr/local/bin/pqkey
have_rust() { command -v cargo >/dev/null || [ -x "$cargo_home/bin/cargo" ]; }

missing=()
command -v cc >/dev/null || missing+=(linker)
have_rust || command -v curl >/dev/null || missing+=(curl)

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

tools=("${missing[@]/linker/a C linker}")
have_rust || tools+=("Rust")
printf '\n%spqkey%s, a FIDO2 security key in software\n\n' "$bold" "$reset"
echo "This sets it up for $(id -un), using about $(size "$mb_needed") of disk ($(size "$mb_free") free):"
[ ${#tools[@]} = 0 ] ||
  echo "  - what building needs: $(printf '%s, ' "${tools[@]}" | sed 's/, $//') (about $(size $((mb_tools + mb_rust))))"
echo "  - pqkey, built in this clone (about $(size "$mb_build")) and installed in $(dirname "$pqkey")"
echo "  - access to /dev/uhid for the key: udev rules and the uhid module"
echo "  - the key, started now and with every login, and its PIN"
echo
echo "It needs your password once, for sudo."
if ! $yes; then
  [ -t 0 ] || fail "no terminal to ask on; run it with --yes"
  read -r -p "Continue? [Y/n] " answer
  case $answer in [Nn]*) exit 0 ;; esac
fi

# The sudo password once, now, kept fresh until the script ends: the steps
# below that need root then never stop to ask, not even after a long build.
command -v sudo >/dev/null || fail "installing pqkey needs sudo"
sudo -v -p "Password for sudo (%p): " || fail "installing pqkey needs sudo"
while sleep 60; do sudo -n -v 2>/dev/null || exit; done &
sudo_keeper=$!
trap 'kill "$sudo_keeper" ${drawer:+"$drawer"} 2>/dev/null || true' EXIT

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
      esac
    done
  }
  install_packages() {
    if command -v apt-get >/dev/null; then
      sudo apt-get update
      # shellcheck disable=SC2046
      sudo apt-get install -y $(packages build-essential)
    elif command -v dnf >/dev/null; then
      # shellcheck disable=SC2046
      sudo dnf install -y $(packages gcc)
    elif command -v pacman >/dev/null; then
      # shellcheck disable=SC2046
      sudo pacman -S --needed --noconfirm $(packages gcc)
    elif command -v zypper >/dev/null; then
      # shellcheck disable=SC2046
      sudo zypper --non-interactive install $(packages gcc)
    else
      echo "no apt-get, dnf, pacman or zypper: install a C compiler and linker (cc) and curl yourself"
      return 1
    fi
  }
  step 15 90 "Installing the build tools" "Build tools installed" install_packages
fi

if ! have_rust; then
  install_rust() {
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  }
  step 20 60 "Installing Rust" "Rust installed" install_rust
fi
if [ -f "$cargo_home/env" ]; then
  # shellcheck source=/dev/null
  . "$cargo_home/env"
fi
command -v cargo >/dev/null || fail "cargo is not on the PATH; open a new terminal and run $0 again"

# Without rustup, the system's Rust has to be new enough itself.
if ! command -v rustup >/dev/null; then
  required=$(sed -nE 's/^rust-version *= *"([^"]+)".*/\1/p' Cargo.toml)
  have=$(rustc --version | cut -d' ' -f2)
  if [ "$(printf '%s\n%s\n' "$required" "$have" | sort -V | head -1)" != "$required" ]; then
    fail "Rust $have is older than the $required pqkey needs; install Rust with rustup (https://rustup.rs) and run $0 again"
  fi
fi

cargo=(cargo)
if command -v rustup >/dev/null; then
  # The stable toolchain, without the components rust-toolchain.toml adds
  # for development.
  cargo=(cargo +stable)
fi
build() {
  if command -v rustup >/dev/null && ! rustup toolchain list | grep -q '^stable'; then
    rustup toolchain install stable --profile minimal
  fi
  # Its progress line goes to the log too, for the progress bar to read.
  CARGO_TERM_PROGRESS_WHEN=always CARGO_TERM_PROGRESS_WIDTH=100 \
    "${cargo[@]}" build --release --locked -p pqkey --target-dir target
}
step 60 cargo "Building pqkey" "pqkey built" build
step 5 3 "Installing $pqkey" "pqkey installed in $(dirname "$pqkey")" \
  sudo install -D -m 755 target/release/pqkey "$pqkey"
# An earlier install.sh installed pqkey with `cargo install`, in a directory
# that comes first on the PATH. A link in its place keeps a shell that
# remembers that path working.
old=${CARGO_INSTALL_ROOT:-$cargo_home}/bin/pqkey
if [ -f "$old" ] && [ ! -L "$old" ]; then
  "${cargo[@]}" uninstall -q pqkey 2>/dev/null || rm -f "$old"
  ln -sf "$pqkey" "$old"
fi

"$pqkey" setup --yes
