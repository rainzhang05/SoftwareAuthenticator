#!/usr/bin/env bash
# Real browser/UHID acceptance only. Never manages an installed pqkey service.
set -euo pipefail
case "${1:-}" in
  chromium|firefox|all) ;;
  *) echo "usage: $0 chromium|firefox|all [--artifacts DIRECTORY] [--binaries DIRECTORY]" >&2; exit 2 ;;
esac
root=$(cd "$(dirname "$0")/.." && pwd)
exec "${BROWSER_PYTHON:-python3}" "$root/tests/browser/acceptance.py" "$@"
