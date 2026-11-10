#!/usr/bin/env python3
"""Apply the versioned Watch overlay to the pinned, otherwise unmodified submodules."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DEPENDENCIES = {
    "SideSign": "752d1ef602aa792a432ffa1e71646dc1ecf7363c",
    "minimuxer": "12be70dc2627307a16bfd2dc7a009080d5bec909",
}


def git(directory, *args):
    return subprocess.run(["git", "-C", str(directory), *args], capture_output=True, text=True, encoding="utf-8")


def prepare():
    pending = []
    for name, revision in DEPENDENCIES.items():
        directory = ROOT / "Dependencies" / name
        result = git(directory, "rev-parse", "HEAD")
        if result.returncode or result.stdout.strip() != revision:
            raise RuntimeError(f"{name} must be initialized at {revision}. Run git submodule update --init --recursive.")
        patch = HERE / f"{name}.patch"
        if git(directory, "apply", "--reverse", "--check", str(patch)).returncode == 0:
            print(f"{name}: Watch patch already applied")
        else:
            result = git(directory, "apply", "--check", str(patch))
            if result.returncode:
                raise RuntimeError(f"{name}: patch conflicts with local changes; no files overwritten.\n{result.stderr}")
            pending.append((directory, patch))

    copies = [(HERE / "WatchGateway.swift", ROOT / "Dependencies/minimuxer/DeviceGateway/idevice/WatchGateway.swift")]
    for source, target in copies:
        if target.exists() and hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(target.read_bytes()).digest():
            raise RuntimeError(f"{target}: existing overlay differs; preserve/review its changes before replacing it.")

    for directory, patch in pending:
        result = git(directory, "apply", str(patch))
        if result.returncode:
            raise RuntimeError(result.stderr)
        print(f"{directory.name}: applied Watch patch")
    for source, target in copies:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(source, target)
    print("Watch dependencies ready")


if __name__ == "__main__":
    try:
        prepare()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
