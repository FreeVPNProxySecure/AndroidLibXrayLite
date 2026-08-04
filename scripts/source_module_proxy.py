#!/usr/bin/env python3
"""Create a deterministic local Go module proxy entry for the exact commit."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import stat
import subprocess
from typing import Any
import zipfile

try:
    from .validate_build_contract import ContractError
except ImportError:
    from validate_build_contract import ContractError


def escape_module_path(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        if "A" <= character <= "Z":
            escaped.extend(("!", character.lower()))
        elif character == "!":
            escaped.extend(("!", "!"))
        else:
            escaped.append(character)
    return "".join(escaped)


def source_version(source_sha: str, source_epoch: int) -> str:
    timestamp = dt.datetime.fromtimestamp(source_epoch, tz=dt.timezone.utc).strftime(
        "%Y%m%d%H%M%S"
    )
    return f"v0.0.0-{timestamp}-{source_sha[:12]}"


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise ContractError("cannot enumerate tracked source files")
    files: list[Path] = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(raw_path.decode("utf-8"))
        path = root / relative
        if path.is_symlink():
            raise ContractError(f"source module cannot contain a symlink: {relative}")
        if path.is_file():
            files.append(relative)
    return sorted(files, key=lambda value: value.as_posix())


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_source_module_proxy(
    root: Path,
    destination: Path,
    module_path: str,
    source_sha: str,
    source_epoch: int,
) -> dict[str, Any]:
    version = source_version(source_sha, source_epoch)
    escaped = escape_module_path(module_path)
    version_root = destination / escaped / "@v"
    version_root.mkdir(parents=True)
    prefix = f"{module_path}@{version}/"
    zip_path = version_root / f"{version}.zip"
    files = tracked_files(root)
    if Path("go.mod") not in files:
        raise ContractError("tracked source module is missing go.mod")

    with zipfile.ZipFile(
        zip_path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for relative in files:
            source_path = root / relative
            info = zipfile.ZipInfo(prefix + relative.as_posix(), (1980, 1, 1, 0, 0, 0))
            mode = source_path.stat().st_mode
            permissions = 0o755 if mode & stat.S_IXUSR else 0o644
            info.external_attr = (stat.S_IFREG | permissions) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            archive.writestr(info, source_path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)

    (version_root / f"{version}.mod").write_bytes((root / "go.mod").read_bytes())
    source_time = dt.datetime.fromtimestamp(source_epoch, tz=dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    (version_root / f"{version}.info").write_text(
        json.dumps({"Version": version, "Time": source_time}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (version_root / "list").write_text(version + "\n", encoding="utf-8")
    return {
        "modulePath": module_path,
        "version": version,
        "zipSha256": file_sha256(zip_path),
        "zipSize": zip_path.stat().st_size,
        "fileCount": len(files),
        "proxyRoot": destination,
    }
