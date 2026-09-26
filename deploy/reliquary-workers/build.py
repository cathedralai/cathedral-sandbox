#!/usr/bin/env python3
"""Build and export the pinned executor. No workload or qualification is run."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

REVISION = "0be0cda0c9a73dc3f08e3af2a07dda9407635aa7"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_id(source: Path) -> str:
    digest = hashlib.sha256()
    root = source / "reliquary/environment/grader"
    for relative in ("worker.py", "bundle/config.json"):
        data = (root / relative).read_bytes()
        digest.update(relative.encode("ascii"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return "grader-sha256:" + digest.hexdigest()



def portable_image_id(archive: Path) -> str:
    """Docker Engine loads the config digest, not BuildKit's OCI index digest."""
    with tarfile.open(archive) as tar:
        def read(name: str) -> bytes:
            matches = [member for member in tar.getmembers() if member.name == name]
            if len(matches) != 1 or not matches[0].isreg() or matches[0].size > 1024 * 1024:
                raise ValueError("invalid executor image metadata")
            return tar.extractfile(matches[0]).read()

        images = json.loads(read("manifest.json"))
        if not isinstance(images, list) or len(images) != 1:
            raise ValueError("executor archive must contain one image")
        raw = read(images[0]["Config"])
        config = json.loads(raw)
        if (config.get("architecture") != "amd64" or config.get("os") != "linux"
                or config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != REVISION):
            raise ValueError("executor image platform or source revision differs")
        return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--docker-context", required=True, help="Explicit approved build daemon")
    parser.add_argument("--output", type=Path, required=True, help="New artifact directory")
    args = parser.parse_args()
    source = args.source.resolve()
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if head != REVISION:
        parser.error("source HEAD is not the reviewed Reliquary revision")
    dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    if dirty:
        parser.error("source must be clean")
    output = args.output.expanduser().absolute()
    output.mkdir(parents=True, exist_ok=False)
    docker = ["docker", "--context", args.docker_context]
    with tempfile.TemporaryDirectory(prefix="reliquary-build-", dir=output) as temporary:
        stage = Path(temporary)
        archive = stage / "source.tar"
        subprocess.run(["git", "-C", str(source), "archive", "--format=tar", "--output", str(archive), REVISION], check=True)
        context = stage / "context"
        context.mkdir()
        with tarfile.open(archive) as tar:
            # The archive is produced from the explicit local pinned revision.
            # Reject paths and links which would leave the fresh build context.
            members = tar.getmembers()
            for member in members:
                target = (context / member.name).resolve()
                if not target.is_relative_to(context):
                    raise SystemExit("source archive contains an unsafe path")
                if member.issym() or member.islnk():
                    raise SystemExit("source archive contains a link; review it before building")
            tar.extractall(context, members=members)
        subprocess.run([
            *docker, "buildx", "build", "--platform", "linux/amd64", "--load",
            "--iidfile", str(output / "builder-image-id.txt"), "--build-arg", f"RELIQUARY_BUILD_REVISION={REVISION}",
            "-f", str(context / "docker/Dockerfile.cpu-executor"), str(context),
        ], check=True)
        builder_image_id = (output / "builder-image-id.txt").read_text().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", builder_image_id):
            raise SystemExit("builder did not return an immutable image ID")
        subprocess.run([*docker, "image", "save", "--output", str(output / "executor-image.tar"), builder_image_id], check=True)
        image_id = portable_image_id(output / "executor-image.tar")
        (output / "image-id.txt").write_text(image_id + "\n")
        manifest = {
            "schema": "cathedral_reliquary_build_v1", "source_revision": REVISION,
            "platform": "linux/amd64", "image_id": image_id, "builder_image_id": builder_image_id, "runtime_id": runtime_id(context),
            "archive": "executor-image.tar", "archive_sha256": sha256_file(output / "executor-image.tar"),
            "dockerfile_sha256": sha256_file(context / "docker/Dockerfile.cpu-executor"),
            "dependencies_sha256": sha256_file(context / "docker/cpu-executor-requirements.lock"),
            "qualification": "NOT_RUN",
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(output / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
