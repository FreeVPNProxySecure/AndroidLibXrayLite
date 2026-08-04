#!/usr/bin/env python3
"""Build and verify the pinned Android tunnel native bundle."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any
import zipfile

try:
    from .validate_build_contract import ContractError, load_lock, sha256_file
    from .verify_aar import KNOWN_PATH_PREFIXES, parse_elf_load_alignment
except ImportError:
    from validate_build_contract import ContractError, load_lock, sha256_file
    from verify_aar import KNOWN_PATH_PREFIXES, parse_elf_load_alignment


ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def run(command: list[str], root: Path, env: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd=root,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip()
        raise ContractError(f"command failed ({' '.join(command)}): {details}")
    return result.stdout.strip()


def verify_sources(root: Path, lock: dict[str, Any], env: dict[str, str]) -> None:
    for source in lock["tunnels"]["sources"]:
        path = root / source["path"]
        if not path.is_dir():
            raise ContractError(f"missing tunnel source: {source['path']}")
        actual = run(["git", "rev-parse", "HEAD"], path, env)
        if actual != source["commitSha"]:
            raise ContractError(
                f"tunnel source revision mismatch for {source['id']}: "
                f"expected {source['commitSha']}, got {actual}"
            )
        status = run(
            ["git", "status", "--porcelain=v1", "--untracked-files=no"], path, env
        )
        if status:
            raise ContractError(f"tunnel source is dirty: {source['id']}")
        for license_file in source["licenseFiles"]:
            candidate = path / license_file["path"]
            if not candidate.is_file() or sha256_file(candidate) != license_file["sha256"]:
                raise ContractError(
                    f"tunnel license evidence mismatch: {source['id']}/{license_file['path']}"
                )


def verify_binary(
    payload: bytes,
    abi: str,
    required_page_size: int,
    forbidden_paths: list[bytes],
) -> dict[str, Any]:
    for marker in forbidden_paths:
        if marker and marker in payload:
            raise ContractError(
                "forbidden absolute build path in tunnel binary: "
                + marker.decode("utf-8", errors="replace")
            )
    elf = parse_elf_load_alignment(payload, abi)
    if min(elf["loadAlignments"]) < required_page_size:
        raise ContractError(
            f"{abi} tunnel PT_LOAD alignment is below {required_page_size}: "
            f"{elf['loadAlignments']}"
        )
    return elf


def expected_tunnel_entries(lock: dict[str, Any]) -> set[str]:
    return {
        f"jni/{target['abi']}/{library}"
        for target in lock["android"]["targets"]
        for library in ("libhev-socks5-tunnel.so", "libtun2socks.so")
    }


def verify_tunnel_archive(
    artifact: Path,
    root: Path,
    forbidden_paths: list[str] | None = None,
) -> dict[str, Any]:
    lock = load_lock(root)
    tunnel = lock["tunnels"]
    expected = expected_tunnel_entries(lock)
    forbidden = [*KNOWN_PATH_PREFIXES]
    forbidden.extend(
        value.encode("utf-8") for value in forbidden_paths or [] if value
    )
    try:
        archive = zipfile.ZipFile(artifact)
    except (OSError, zipfile.BadZipFile) as error:
        raise ContractError(f"cannot open tunnel bundle {artifact}: {error}") from error

    records: list[dict[str, Any]] = []
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ContractError("tunnel bundle contains duplicate ZIP entries")
        unsafe = [name for name in names if name.startswith("/") or ".." in Path(name).parts]
        if unsafe:
            raise ContractError(f"tunnel bundle contains unsafe ZIP paths: {unsafe}")
        if set(names) != expected:
            raise ContractError(
                "tunnel bundle entry mismatch: "
                f"missing={sorted(expected - set(names))}, "
                f"extra={sorted(set(names) - expected)}"
            )
        for info in infos:
            if info.is_dir() or info.date_time != ZIP_TIMESTAMP:
                raise ContractError(
                    f"invalid deterministic ZIP entry metadata for {info.filename}"
                )
            payload = archive.read(info)
            abi = info.filename.split("/", 2)[1]
            elf = verify_binary(
                payload,
                abi,
                tunnel["pageSizeBytes"],
                forbidden,
            )
            records.append(
                {
                    "path": info.filename,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "elf": elf,
                }
            )
    return {
        "artifact": {
            "name": artifact.name,
            "size": artifact.stat().st_size,
            "sha256": sha256_file(artifact),
        },
        "entries": sorted(records, key=lambda value: value["path"]),
    }


def build_tunnel_bundle(
    root: Path,
    output: Path,
    ndk_home: Path,
    source_sha: str,
) -> tuple[Path, dict[str, Any]]:
    lock = load_lock(root)
    tunnel = lock["tunnels"]
    output.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "ANDROID_NDK_HOME": str(ndk_home),
        "ANDROID_NDK_ROOT": str(ndk_home),
        "TZ": "UTC",
        "LANG": "C",
        "LC_ALL": "C",
    }
    verify_sources(root, lock, env)
    ndk_build = ndk_home / "ndk-build"
    if not ndk_build.is_file():
        raise ContractError(f"missing locked ndk-build: {ndk_build}")

    abis = [target["abi"] for target in lock["android"]["targets"]]
    with tempfile.TemporaryDirectory(prefix="xray-tunnel-build-") as temporary:
        build_root = Path(temporary)
        tun_output = build_root / "tun"
        hev_output = build_root / "hev"
        run(
            [
                str(ndk_build),
                "NDK_PROJECT_PATH=.",
                "APP_BUILD_SCRIPT=./native/tun2socks.mk",
                f"APP_ABI={' '.join(abis)}",
                f"APP_PLATFORM=android-{tunnel['minimumApi']}",
                f"NDK_LIBS_OUT={tun_output / 'libs'}",
                f"NDK_OUT={tun_output / 'obj'}",
                "APP_SHORT_COMMANDS=false",
                "LOCAL_SHORT_COMMANDS=false",
                "-B",
                "-j4",
            ],
            root,
            env,
        )
        hev_source = root / "third_party/hev-socks5-tunnel"
        run(
            [
                str(ndk_build),
                "NDK_PROJECT_PATH=.",
                "APP_BUILD_SCRIPT=./Android.mk",
                f"APP_ABI={' '.join(abis)}",
                f"APP_PLATFORM=android-{tunnel['minimumApi']}",
                f"NDK_LIBS_OUT={hev_output / 'libs'}",
                f"NDK_OUT={hev_output / 'obj'}",
                "APP_CFLAGS=-O3 -DPKGNAME=com/v2ray/ang/service",
                "APP_LDFLAGS=-Wl,--build-id=none "
                "-Wl,-z,common-page-size=16384 -Wl,-z,max-page-size=16384",
                "-B",
                "-j4",
            ],
            hev_source,
            env,
        )

        inputs: list[tuple[str, Path]] = []
        for abi in abis:
            inputs.extend(
                (
                    (f"jni/{abi}/libhev-socks5-tunnel.so", hev_output / "libs" / abi / "libhev-socks5-tunnel.so"),
                    (f"jni/{abi}/libtun2socks.so", tun_output / "libs" / abi / "libtun2socks.so"),
                )
            )
        if any(not path.is_file() for _, path in inputs):
            missing = [name for name, path in inputs if not path.is_file()]
            raise ContractError(f"tunnel build outputs are missing: {missing}")

        artifact = output / tunnel["artifactName"]
        forbidden = [*KNOWN_PATH_PREFIXES, str(root).encode(), temporary.encode()]
        with zipfile.ZipFile(
            artifact,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name, path in sorted(inputs):
                payload = path.read_bytes()
                abi = name.split("/", 2)[1]
                verify_binary(
                    payload,
                    abi,
                    tunnel["pageSizeBytes"],
                    forbidden,
                )
                info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100755 << 16
                archive.writestr(info, payload)

    verified = verify_tunnel_archive(
        artifact,
        root,
        [str(root), temporary],
    )

    manifest = {
        "schemaVersion": 1,
        "contract": "androidlibxraylite-tunnel-manifest-v1",
        "artifact": verified["artifact"],
        "source": {
            "repository": lock["canonicalRepository"],
            "commitSha": source_sha,
        },
        "upstreamSources": tunnel["sources"],
        "toolchain": {
            "androidNdk": lock["android"]["ndk"],
            "minimumApi": tunnel["minimumApi"],
            "pageSizeBytes": tunnel["pageSizeBytes"],
        },
        "entries": verified["entries"],
    }
    manifest_path = output / tunnel["manifestName"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return artifact, manifest
