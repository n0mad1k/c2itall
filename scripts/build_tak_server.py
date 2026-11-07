#!/usr/bin/env python3
"""Build the pinned public TAK Server package used by c2itall chat."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = "https://github.com/TAK-Product-Center/Server.git"
SOURCE_TAG = "5.7-RELEASE-14"
SOURCE_COMMIT = "5187abd46d827d37cfc5708805eced197a837e49"
VERSION = "5.7-RELEASE14"
PATCH = ROOT / "modules/chat-server/patches/takserver-5.7-tool-ui-eslint.patch"
PATCH_SHA256 = "78f053c359cf45616a72c0cb7c57cf381a06d175b405277d8cbfd62fe2c26f29"
DEB_NAME = f"takserver_{VERSION}_all.deb"
DEFAULT_OUTPUT = Path.home() / ".cache/c2itall/takserver" / VERSION


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(args, cwd=None, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def validate_patch():
    actual = sha256(PATCH)
    if actual != PATCH_SHA256:
        raise RuntimeError(f"TAK build patch checksum mismatch: {actual}")


def write_manifest(output, artifact_hash):
    manifest = {
        "artifact": DEB_NAME,
        "artifact_sha256": artifact_hash,
        "source_url": SOURCE_URL,
        "source_tag": SOURCE_TAG,
        "source_commit": SOURCE_COMMIT,
        "patch": PATCH.name,
        "patch_sha256": PATCH_SHA256,
    }
    path = output / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    return path


def import_artifact(source, output, expected_hash=None):
    source = Path(source).expanduser().resolve()
    if not source.is_file():
        raise ValueError(f"TAK package does not exist: {source}")
    artifact_hash = sha256(source)
    if expected_hash and artifact_hash != expected_hash:
        raise ValueError("TAK package checksum does not match --expected-sha256")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = output / DEB_NAME
    if source != target:
        shutil.copy2(source, target)
    target.chmod(0o600)
    return target, write_manifest(output, artifact_hash)


def build(output, java_home):
    validate_patch()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="c2itall-tak-") as temporary:
        source = Path(temporary) / "Server"
        run(["git", "clone", "--branch", SOURCE_TAG, "--depth", "1",
             SOURCE_URL, str(source)])
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
        if commit != SOURCE_COMMIT:
            raise RuntimeError(f"TAK source commit mismatch: {commit}")
        run(["git", "apply", "--check", str(PATCH)], cwd=source)
        run(["git", "apply", str(PATCH)], cwd=source)
        environment = os.environ.copy()
        environment["JAVA_HOME"] = str(java_home)
        environment["PATH"] = str(Path(java_home) / "bin") + os.pathsep + environment["PATH"]
        run([str(source / "gradlew"), "-p", str(source),
             "takserver-package:takserver:buildDeb", "-x", "test"],
            cwd=source, env=environment)
        artifact = source / "src/takserver-package/takserver/build/distributions" / DEB_NAME
        return import_artifact(artifact, output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--java-home", type=Path,
                        default=Path("/usr/lib/jvm/java-17-openjdk"))
    parser.add_argument("--import-deb", type=Path,
                        help="record an already-built package without rebuilding")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    if args.import_deb:
        artifact, manifest = import_artifact(
            args.import_deb, output, args.expected_sha256)
    else:
        artifact, manifest = build(output, args.java_home)
        if args.expected_sha256 and sha256(artifact) != args.expected_sha256:
            raise ValueError("built TAK package checksum does not match --expected-sha256")
    print(artifact)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
