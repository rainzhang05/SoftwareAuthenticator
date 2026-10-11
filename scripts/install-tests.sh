#!/usr/bin/env bash
# Execute install.sh in disposable Linux filesystems; no host sudo or devices.
# Requires Docker. INSTALL_TEST_IMAGE may name a preloaded compatible image.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo 'Installer checks need Docker; install/start Docker and rerun scripts/install-tests.sh' >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Installer checks need a running Docker daemon' >&2; exit 1; }
# Send source only, with no build artifacts or macOS metadata. No host directory
# is writable from the container, whose marker is required by the test driver.
COPYFILE_DISABLE=1 tar --no-xattrs -cf - install.sh tests/installer | docker run --rm -i \
  "${INSTALL_TEST_IMAGE:-rust:1.89-bookworm}" bash -euo pipefail -c \
  'mkdir /fixture-source; tar -xm -C /fixture-source; touch /pqkey-installer-fixture; python3 /fixture-source/tests/installer/test_install.py -v'
