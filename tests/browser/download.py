"""Install only digest-locked test browsers into a disposable directory."""
import hashlib
import json
import os
import ssl
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path


def digest(filename):
    with open(filename, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def install(browser, destination):
    import certifi
    lock = json.loads(Path(__file__).with_name("toolchain.json").read_text())[browser]
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for kind in ("browser", "driver"):
        item = lock[kind]
        archive = destination / (kind + (".zip" if ".zip" in item["url"] else ".tar"))
        deadline = time.monotonic() + 300
        with urllib.request.urlopen(item["url"], context=ssl.create_default_context(cafile=certifi.where()), timeout=30) as response:
            with archive.open("wb") as target:
                while block := response.read(1024 * 1024):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("bounded browser download expired")
                    target.write(block)
        if digest(archive) != item["sha256"]:
            raise ValueError(f"{browser} {kind} SHA-256 mismatch")
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as source:
                for member in source.infolist():
                    target = (destination / member.filename).resolve()
                    if not target.is_relative_to(destination.resolve()):
                        raise ValueError("unsafe ZIP path")
                    source.extract(member, destination)
                    if not member.is_dir():
                        os.chmod(target, (member.external_attr >> 16 & 0o777) or 0o600)
        else:
            with tarfile.open(archive) as source:
                source.extractall(destination, filter="data")
        executable = destination / item["executable"]
        executable.chmod(executable.stat().st_mode | 0o100)
        archive.unlink()
    receipt = {"manifest_sha256": digest(Path(__file__).with_name("toolchain.json")), "browser": browser,
               "executables": {kind: digest(destination / lock[kind]["executable"]) for kind in ("browser", "driver")}}
    (destination / "verified-download.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return lock


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("browser", choices=("chromium", "firefox"))
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    install(arguments.browser, arguments.destination)
