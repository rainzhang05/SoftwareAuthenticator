#!/usr/bin/env bash
# Install pqkey from this clone and set it up, in one go:
#
#   ./install.sh          asks once, then does everything
#   ./install.sh --yes    does not ask (it still offers to set a PIN)
#
# 1. Installs what building needs and is missing: a C linker and curl, with
#    the system's package manager (sudo), and Rust, with rustup.
# 2. Builds pqkey from this clone and installs it in /usr/local/bin (sudo),
#    where every shell finds it, this one included.
# 3. Runs `pqkey setup`: the udev rules and the uhid module (sudo), and a
#    systemd user service that starts the key with your session. It ends by
#    offering to set the key's PIN.
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
step() { printf '\n==> %s\n' "$*"; }

[ "$(uname -s)" = Linux ] || fail "pqkey runs on Linux only"
[ "$(id -u)" != 0 ] || fail "run it as the user who will use the key, not as root; it asks for sudo when it needs to"

cargo_home=${CARGO_HOME:-$HOME/.cargo}
pqkey=/usr/local/bin/pqkey
have_rust() { command -v cargo >/dev/null || [ -x "$cargo_home/bin/cargo" ]; }

missing=()
command -v cc >/dev/null || missing+=(linker)
have_rust || command -v curl >/dev/null || missing+=(curl)

echo "This installs pqkey, a FIDO2 security key in software, for $(id -un):"
[ ${#missing[@]} = 0 ] || echo "  - with your package manager (sudo): ${missing[*]/linker/a C linker}"
have_rust || echo "  - Rust, with rustup (https://rustup.rs), in $cargo_home"
echo "  - pqkey, built from this clone (a few minutes), in $pqkey (sudo)"
echo "  - if not done yet, with sudo: udev rules for the key, and the uhid module at boot"
echo "  - a systemd user service that starts the key with your session"
if ! $yes; then
  [ -t 0 ] || fail "no terminal to ask on; run it with --yes"
  read -r -p "Go ahead? [Y/n] " answer
  case $answer in [Nn]*) exit 0 ;; esac
fi

if [ ${#missing[@]} != 0 ]; then
  step "Installing ${missing[*]/linker/a C linker}"
  packages() { # packages LINKER_PACKAGE: the packages for what is missing
    for item in "${missing[@]}"; do
      case $item in
        linker) echo "$1" ;;
        curl) echo curl ;;
      esac
    done
  }
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
    fail "install a C compiler and linker (cc) and curl, then run $0 again"
  fi
fi

if ! have_rust; then
  step "Installing Rust with rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
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

step "Building pqkey"
cargo=(cargo)
if command -v rustup >/dev/null; then
  # The stable toolchain, without the components rust-toolchain.toml adds
  # for development.
  rustup toolchain list | grep -q '^stable' || rustup toolchain install stable --profile minimal
  cargo=(cargo +stable)
fi
"${cargo[@]}" build --release --locked -p pqkey --target-dir target

step "Installing $pqkey"
sudo install -D -m 755 target/release/pqkey "$pqkey"
# An earlier install.sh installed pqkey with `cargo install`, in a directory
# that comes first on the PATH. A link in its place keeps a shell that
# remembers that path working.
old=${CARGO_INSTALL_ROOT:-$cargo_home}/bin/pqkey
if [ -f "$old" ] && [ ! -L "$old" ]; then
  "${cargo[@]}" uninstall -q pqkey 2>/dev/null || rm -f "$old"
  ln -sf "$pqkey" "$old"
fi

step "Setting up pqkey"
"$pqkey" setup --yes
