#!/usr/bin/env python3
"""Compare two Cargo.lock files and fail on Cargo-semver-incompatible changes.

Usage: cargo_semver_check.py BASE_LOCK HEAD_LOCK

Prints a one-line summary of compatible changes on stdout. Exits 1 and lists the
incompatible changes on stderr if any package gained a version that is not
Cargo-compatible with a version it already had.

Cargo's rule is that the leftmost non-zero component must match, so
0.12.4 -> 0.13.0 is breaking even though generic semver tooling (including
Dependabot's `update-type`) calls it a minor bump.
"""

import sys
import tomllib


def parse(version):
    core = version.split("+", 1)[0].split("-", 1)[0]
    return [int(part) for part in core.split(".")]


def compatible(old, new):
    # Never auto-accept a pre-release: they carry no compatibility promise.
    if "-" in new.split("+", 1)[0]:
        return False
    a, b = parse(old), parse(new)
    if a[0] != 0 or b[0] != 0:
        return a[0] == b[0] and b >= a
    if a[1] != 0 or b[1] != 0:
        return a[1] == b[1] and b >= a
    return a == b


def versions(path):
    with open(path, "rb") as handle:
        packages = tomllib.load(handle).get("package", [])
    found = {}
    for package in packages:
        found.setdefault(package["name"], set()).add(package["version"])
    return found


def main(base_path, head_path):
    before, after = versions(base_path), versions(head_path)
    changes, breaking = [], []
    for name in sorted(after):
        old = before.get(name)
        for new in sorted(after[name] - (old or set())):
            if not old:
                changes.append(f"+{name} {new}")
            elif any(compatible(o, new) for o in old):
                changes.append(f"{name} {'/'.join(sorted(old))} -> {new}")
            else:
                breaking.append(f"{name} {'/'.join(sorted(old))} -> {new}")
    print("; ".join(changes) or "no version changes")
    if breaking:
        print("incompatible: " + "; ".join(breaking), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
