#!/usr/bin/env python3
"""Validate immutable native build inputs and workflow boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


LOCK_PATH = Path("config/native-build-lock.json")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ACTION_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)


class ContractError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_lock(root: Path) -> dict[str, Any]:
    path = root / LOCK_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read {LOCK_PATH}: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"{LOCK_PATH} must contain a JSON object")
    return value


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    return value


def require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{name} must be a non-empty string")
    return value


def parse_go_mod(path: Path) -> tuple[str, str]:
    module = ""
    directive = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            module = line.removeprefix("module ").strip()
        elif line.startswith("go "):
            directive = line.removeprefix("go ").strip()
    if not module or not directive:
        raise ContractError("go.mod must declare module and go directives")
    return module, directive


def validate_lock_shape(lock: dict[str, Any]) -> None:
    if lock.get("schemaVersion") != 1:
        raise ContractError("schemaVersion must be 1")
    if lock.get("contract") != "androidlibxraylite-native-build-v1":
        raise ContractError("unexpected native build contract")
    if lock.get("canonicalRepository") != "FreeVPNProxySecure/AndroidLibXrayLite":
        raise ContractError("canonicalRepository must name the organization fork")
    if lock.get("modulePath") != "github.com/FreeVPNProxySecure/AndroidLibXrayLite":
        raise ContractError("modulePath must name the canonical organization module")
    if lock.get("legacyModulePath") != "github.com/tim06/AndroidLibXrayLite":
        raise ContractError("legacyModulePath must preserve the historical identity")

    go = require_object(lock.get("go"), "go")
    require_string(go.get("version"), "go.version")
    require_string(go.get("directive"), "go.directive")
    if not SHA256_RE.fullmatch(
        require_string(go.get("linuxAmd64ArchiveSha256"), "go archive SHA-256")
    ):
        raise ContractError("go archive SHA-256 must be lowercase hex")

    for tool_name in ("gomobile", "govulncheck"):
        tool = require_object(lock.get(tool_name), tool_name)
        require_string(tool.get("package"), f"{tool_name}.package")
        require_string(tool.get("version"), f"{tool_name}.version")
        if not COMMIT_RE.fullmatch(
            require_string(tool.get("commitSha"), f"{tool_name}.commitSha")
        ):
            raise ContractError(f"{tool_name}.commitSha must be a full commit SHA")
        require_string(tool.get("moduleSum"), f"{tool_name}.moduleSum")
        require_string(tool.get("goModSum"), f"{tool_name}.goModSum")

    android = require_object(lock.get("android"), "android")
    if not isinstance(android.get("minimumApi"), int) or android["minimumApi"] < 21:
        raise ContractError("android.minimumApi must be an integer >= 21")
    ndk = require_object(android.get("ndk"), "android.ndk")
    require_string(ndk.get("release"), "android.ndk.release")
    require_string(ndk.get("revision"), "android.ndk.revision")
    targets = android.get("targets")
    if not isinstance(targets, list) or len(targets) != 4:
        raise ContractError("android.targets must contain exactly four targets")
    abis: set[str] = set()
    gomobile_targets: set[str] = set()
    for index, target_value in enumerate(targets):
        target = require_object(target_value, f"android.targets[{index}]")
        abis.add(require_string(target.get("abi"), f"android.targets[{index}].abi"))
        gomobile_targets.add(
            require_string(target.get("gomobile"), f"android.targets[{index}].gomobile")
        )
    if abis != {"armeabi-v7a", "arm64-v8a", "x86", "x86_64"}:
        raise ContractError(f"unexpected Android ABI set: {sorted(abis)}")
    if len(gomobile_targets) != 4:
        raise ContractError("gomobile targets must be unique")
    if android.get("pageSizeBytes") != 16384:
        raise ContractError("android.pageSizeBytes must remain 16384")

    source_inputs = require_object(lock.get("sourceInputs"), "sourceInputs")
    required_inputs = {
        "go.mod",
        "go.sum",
        "assets/geoip.dat",
        "assets/geosite.dat",
        "config/android-api-baseline.json",
    }
    if set(source_inputs) != required_inputs:
        raise ContractError(
            f"sourceInputs must be exactly {sorted(required_inputs)}, got {sorted(source_inputs)}"
        )
    for relative_path, raw_input in source_inputs.items():
        source_input = require_object(raw_input, f"sourceInputs.{relative_path}")
        if not SHA256_RE.fullmatch(
            require_string(source_input.get("sha256"), f"{relative_path}.sha256")
        ):
            raise ContractError(f"{relative_path}.sha256 must be lowercase hex")
        if relative_path.startswith("assets/"):
            if not isinstance(source_input.get("size"), int) or source_input["size"] <= 0:
                raise ContractError(f"{relative_path}.size must be a positive integer")
            for field in ("sourceRepository", "sourceRelease", "sourceUrl"):
                require_string(source_input.get(field), f"{relative_path}.{field}")

    actions = require_object(lock.get("actions"), "actions")
    if not actions:
        raise ContractError("actions must not be empty")
    for action, commit in actions.items():
        require_string(action, "action name")
        if not COMMIT_RE.fullmatch(require_string(commit, f"actions.{action}")):
            raise ContractError(f"actions.{action} must use a full commit SHA")


def validate_source_inputs(root: Path, lock: dict[str, Any]) -> None:
    for relative_path, raw_input in lock["sourceInputs"].items():
        source_input = require_object(raw_input, f"sourceInputs.{relative_path}")
        path = root / relative_path
        if not path.is_file():
            raise ContractError(f"missing locked input: {relative_path}")
        actual_hash = sha256_file(path)
        if actual_hash != source_input["sha256"]:
            raise ContractError(
                f"locked input digest mismatch for {relative_path}: "
                f"expected {source_input['sha256']}, got {actual_hash}"
            )
        expected_size = source_input.get("size")
        if expected_size is not None and path.stat().st_size != expected_size:
            raise ContractError(
                f"locked input size mismatch for {relative_path}: "
                f"expected {expected_size}, got {path.stat().st_size}"
            )

    module, directive = parse_go_mod(root / "go.mod")
    if module != lock["modulePath"]:
        raise ContractError(f"module path drift: expected {lock['modulePath']}, got {module}")
    if directive != lock["go"]["directive"]:
        raise ContractError(
            f"Go directive drift: expected {lock['go']['directive']}, got {directive}"
        )


def validate_workflows(root: Path, lock: dict[str, Any]) -> None:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        raise ContractError("missing .github/workflows")
    action_lock: dict[str, str] = lock["actions"]
    found_actions: set[str] = set()
    for path in sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for match in ACTION_RE.finditer(text):
            reference = match.group(1).strip("'\"")
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                raise ContractError(f"invalid action reference in {path}: {reference}")
            action, revision = reference.rsplit("@", 1)
            expected = action_lock.get(action)
            if expected is None:
                raise ContractError(f"unlocked action in {path}: {action}")
            if revision != expected:
                raise ContractError(
                    f"action revision drift in {path}: {action}@{revision}, expected {expected}"
                )
            found_actions.add(action)

        forbidden = ("@latest", "/releases/latest", "gen_assets.sh download")
        for token in forbidden:
            if token in text:
                raise ContractError(f"mutable build token in {path}: {token}")

    missing = set(action_lock) - found_actions
    if missing:
        raise ContractError(f"locked actions are unused: {sorted(missing)}")

    release = lock["release"]
    build_path = workflows / release["buildWorkflow"]
    release_path = workflows / release["releaseWorkflow"]
    if not build_path.is_file() or not release_path.is_file():
        raise ContractError("locked build and release workflows must exist")
    build_text = build_path.read_text(encoding="utf-8")
    release_text = release_path.read_text(encoding="utf-8")
    if re.search(r"\bgh\s+release\b|\bgit\s+tag\b", build_text):
        raise ContractError("build workflow must not create a tag or release")
    if re.search(r"\bgomobile\s+bind\b|\bgo\s+build\b", release_text):
        raise ContractError("release workflow must not compile native artifacts")


def parse_properties(path: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def validate_ndk(ndk_home: Path, lock: dict[str, Any]) -> None:
    properties_path = ndk_home / "source.properties"
    if not properties_path.is_file():
        raise ContractError(f"missing NDK source.properties: {properties_path}")
    properties = parse_properties(properties_path)
    expected = lock["android"]["ndk"]
    if properties.get("Pkg.Revision") != expected["revision"]:
        raise ContractError(
            f"NDK revision mismatch: expected {expected['revision']}, "
            f"got {properties.get('Pkg.Revision')}"
        )
    if properties.get("Pkg.ReleaseName") != expected["release"]:
        raise ContractError(
            f"NDK release mismatch: expected {expected['release']}, "
            f"got {properties.get('Pkg.ReleaseName')}"
        )


def command_output(command: list[str], root: Path) -> str:
    result = subprocess.run(
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        raise ContractError(
            f"command failed ({' '.join(command)}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def validate_toolchain(root: Path, lock: dict[str, Any]) -> None:
    version = command_output(["go", "version"], root)
    expected = f"go version go{lock['go']['version']} "
    if not version.startswith(expected):
        raise ContractError(f"Go version mismatch: expected prefix {expected!r}, got {version!r}")


def validate_source_sha(root: Path, expected: str) -> None:
    if not COMMIT_RE.fullmatch(expected):
        raise ContractError("source SHA must be a full lowercase commit SHA")
    actual = command_output(["git", "rev-parse", "HEAD"], root)
    if actual != expected:
        raise ContractError(f"source SHA mismatch: expected {expected}, got {actual}")


def validate(
    root: Path,
    *,
    check_toolchain: bool = False,
    ndk_home: Path | None = None,
    source_sha: str | None = None,
) -> dict[str, Any]:
    lock = load_lock(root)
    validate_lock_shape(lock)
    validate_source_inputs(root, lock)
    validate_workflows(root, lock)
    if check_toolchain:
        validate_toolchain(root, lock)
    if ndk_home is not None:
        validate_ndk(ndk_home, lock)
    if source_sha is not None:
        validate_source_sha(root, source_sha)
    return lock


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check-toolchain", action="store_true")
    parser.add_argument("--ndk-home", type=Path)
    parser.add_argument("--source-sha")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        lock = validate(
            args.root.resolve(),
            check_toolchain=args.check_toolchain,
            ndk_home=args.ndk_home.resolve() if args.ndk_home else None,
            source_sha=args.source_sha,
        )
    except ContractError as error:
        print(f"native build contract failed: {error}", file=sys.stderr)
        return 1
    print(
        "native build contract passed: "
        f"Go {lock['go']['version']}, NDK {lock['android']['ndk']['revision']}, "
        f"{len(lock['android']['targets'])} ABIs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
