# Shared by the scripts in this directory; sourced, not run.
#
# Each step prints one line, ✓ or ✗, and its output goes to a log that is
# shown only when it fails.

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  bold=$'\e[1m' green=$'\e[1;32m' yellow=$'\e[1;33m' red=$'\e[1;31m' reset=$'\e[0m'
else
  bold='' green='' yellow='' red='' reset=''
fi

# The log of this script: target/scripts/<script>.log.
log="$root/target/scripts/$(basename "$0" .sh).log"
mkdir -p "$(dirname "$log")"
: >"$log"

failed=()

heading() { printf '\n%s%s%s\n' "$bold" "$*" "$reset"; }
ok() { printf '  %s✓%s %s\n' "$green" "$reset" "$*"; }
skipped() { printf '  %s–%s %s\n' "$yellow" "$reset" "$*"; }
die() {
  printf '  %s✗%s %s\n' "$red" "$reset" "$*" >&2
  exit 1
}

# step LABEL COMMAND...: run COMMAND, its output to the log. Prints LABEL
# marked ✓ or ✗; after ✗ the end of COMMAND's output, and LABEL is added to
# $failed. Returns COMMAND's status.
step() {
  local label=$1 start=$SECONDS from status=0 took=''
  shift
  [ -t 1 ] && printf '  … %s' "$label"
  printf '\n==> %s\n' "$label" >>"$log"
  from=$(($(wc -l <"$log") + 1))
  "$@" >>"$log" 2>&1 || status=$?
  [ $((SECONDS - start)) -lt 10 ] || took=" ($((SECONDS - start))s)"
  [ -t 1 ] && printf '\r\e[K'
  if [ "$status" = 0 ]; then
    ok "$label$took"
  else
    printf '  %s✗%s %s\n' "$red" "$reset" "$label"
    tail -n +"$from" "$log" | tail -n 15 | sed 's/^/      /'
    failed+=("$label")
  fi
  return "$status"
}

# finish: the summary, and the exit status: 1 if any step failed.
finish() {
  echo
  if [ ${#failed[@]} = 0 ]; then
    printf '%sAll passed.%s\n' "$green" "$reset"
  else
    printf '%s%d failed:%s %s\n' "$red" ${#failed[@]} "$reset" "$(printf '%s; ' "${failed[@]}" | sed 's/; $//')"
    echo "The whole output is in ${log#"$root"/}"
    exit 1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# The python of a virtual environment with the pinned packages of the
# end-to-end tests and the browser kit; python_env sets it up.
venv="$root/target/python"
python="$venv/bin/python"
python_env() {
  if [ ! -x "$python" ] || [ tests/e2e/requirements.txt -nt "$venv/.installed" ]; then
    python3 -m venv "$venv" &&
      "$python" -m pip install --require-hashes --only-binary :all: -r tests/e2e/requirements.txt &&
      touch "$venv/.installed"
  fi
}
