#!/usr/bin/env bash
# The browser test kit: a local relying party at http://localhost:8080 that
# checks everything the key returns (see tests/browser/README.md).
#
#   scripts/browser.sh
#
# Needs python3-venv. RP_PORT changes the port. Ctrl-C stops it.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

python3 -c 'import ensurepip' 2>/dev/null ||
  die "needs python3-venv; on Debian or Ubuntu: sudo apt install python3-venv"
heading "Browser test kit"
step "Python packages" python_env || finish
ok "Open http://localhost:${RP_PORT:-8080} with pqkey running; Ctrl-C stops the server"
exec "$python" tests/browser/server.py
