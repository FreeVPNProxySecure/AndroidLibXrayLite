#!/usr/bin/env python3
"""Build the locked Android AAR without mutating source inputs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from validate_build_contract import ContractError, validate
from verify_aar import verify_archive


def run(
    command: list[str],
    *,
    root: Path,
    env: dict[str, str],
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=root,
        env=env,
        check=False,
        text=True,
        capture_output=capture,
    )
    if result.returncode != 0:
        details = result.stderr.strip() if capture else "see command output"
        raise ContractError(f"command failed ({' '.join(command)}): {details}")
    return result


def require_clean_source(root: Path, env: dict[str, str]) -> str:
    status = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        root=root,
        env=env,
        capture=True,
    ).stdout.strip()
    if status:
        raise ContractError(f"native build requires a clean checkout:\n{status}")
    return run(["git", "rev-parse", "HEAD"], root=root, env=env, capture=True).stdout.strip()


def require_gomobile(binary: Path, lock: dict, root: Path, env: dict[str, str]) -> None:
    metadata = run(
        ["go", "version", "-m", str(binary)],
        root=root,
        env=env,
        capture=True,
    ).stdout
    tool = lock["gomobile"]
    expected = f"mod\t{tool['module']}\t{tool['version']}\t{tool['moduleSum']}"
    if expected not in metadata:
        raise ContractError(
            "gomobile binary does not match the locked module/version/checksum"
        )


def build(root: Path, output: Path) -> Path:
    ndk_raw = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if not ndk_raw:
        raise ContractError("ANDROID_NDK_HOME must point to the locked NDK")
    ndk_home = Path(ndk_raw).resolve()
    lock = validate(root, check_toolchain=True, ndk_home=ndk_home)

    if output.exists():
        raise ContractError(f"output directory already exists: {output}")
    output.mkdir(parents=True)

    env = {
        **os.environ,
        "ANDROID_NDK_HOME": str(ndk_home),
        "ANDROID_NDK_ROOT": str(ndk_home),
        "GOFLAGS": "-mod=readonly",
        "TZ": "UTC",
        "LANG": "C",
        "LC_ALL": "C",
    }
    source_sha = require_clean_source(root, env)
    source_epoch = run(
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        root=root,
        env=env,
        capture=True,
    ).stdout.strip()
    env["SOURCE_DATE_EPOCH"] = source_epoch

    run(["go", "mod", "verify"], root=root, env=env)
    tidy = run(["go", "mod", "tidy", "-diff"], root=root, env=env, capture=True)
    if tidy.stdout.strip():
        raise ContractError(f"go.mod/go.sum have tidy drift:\n{tidy.stdout}")

    gomobile_raw = shutil.which("gomobile", path=env.get("PATH"))
    if not gomobile_raw:
        raise ContractError("gomobile is not installed")
    gomobile = Path(gomobile_raw).resolve()
    require_gomobile(gomobile, lock, root, env)
    run([str(gomobile), "init"], root=root, env=env)

    artifact = output / lock["release"]["artifactName"]
    targets = ",".join(target["gomobile"] for target in lock["android"]["targets"])
    command = [
        str(gomobile),
        "bind",
        "-v",
        "-trimpath",
        f"-androidapi={lock['android']['minimumApi']}",
        f"-target={targets}",
        "-ldflags",
        lock["android"]["ldflags"],
        "-o",
        str(artifact),
        "./",
    ]
    run(command, root=root, env=env)

    manifest = verify_archive(artifact, root, [str(root)])
    manifest["source"] = {
        "repository": lock["canonicalRepository"],
        "commitSha": source_sha,
        "sourceDateEpoch": int(source_epoch),
    }
    manifest_path = output / "artifact-manifest.json"
    import json

    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return artifact


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        artifact = build(args.root.resolve(), args.output.resolve())
    except ContractError as error:
        print(f"native AAR build failed: {error}", file=sys.stderr)
        return 1
    print(f"native AAR build passed: {artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
