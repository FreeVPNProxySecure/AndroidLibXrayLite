#!/usr/bin/env python3
"""Verify the deterministic structure and native invariants of libv2ray.aar."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import Any
import zipfile

from validate_build_contract import ContractError, load_lock, sha256_file


ELF_MACHINE_BY_ABI = {
    "armeabi-v7a": 40,
    "arm64-v8a": 183,
    "x86": 3,
    "x86_64": 62,
}
FIXED_ZIP_TIMESTAMP = (1980, 0, 0, 0, 0, 0)
KNOWN_PATH_PREFIXES = (
    b"/home/runner/work/",
    b"/Users/",
    b"/private/tmp/",
    b"\\Users\\",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_elf_load_alignment(payload: bytes, abi: str) -> dict[str, Any]:
    if payload[:4] != b"\x7fELF":
        raise ContractError(f"{abi} native library is not ELF")
    elf_class = payload[4]
    data_encoding = payload[5]
    if data_encoding != 1:
        raise ContractError(f"{abi} ELF must use little-endian encoding")
    endian = "<"
    if elf_class == 1:
        machine = struct.unpack_from(endian + "H", payload, 18)[0]
        program_offset = struct.unpack_from(endian + "I", payload, 28)[0]
        entry_size = struct.unpack_from(endian + "H", payload, 42)[0]
        entry_count = struct.unpack_from(endian + "H", payload, 44)[0]
        align_offset = 28
        file_offset_offset = 4
        virtual_offset = 8
        value_format = "I"
    elif elf_class == 2:
        machine = struct.unpack_from(endian + "H", payload, 18)[0]
        program_offset = struct.unpack_from(endian + "Q", payload, 32)[0]
        entry_size = struct.unpack_from(endian + "H", payload, 54)[0]
        entry_count = struct.unpack_from(endian + "H", payload, 56)[0]
        align_offset = 48
        file_offset_offset = 8
        virtual_offset = 16
        value_format = "Q"
    else:
        raise ContractError(f"{abi} ELF has unsupported class {elf_class}")

    expected_machine = ELF_MACHINE_BY_ABI[abi]
    if machine != expected_machine:
        raise ContractError(
            f"{abi} ELF machine mismatch: expected {expected_machine}, got {machine}"
        )

    alignments: list[int] = []
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        if offset + entry_size > len(payload):
            raise ContractError(f"{abi} ELF program header exceeds payload")
        program_type = struct.unpack_from(endian + "I", payload, offset)[0]
        if program_type != 1:
            continue
        file_offset = struct.unpack_from(
            endian + value_format, payload, offset + file_offset_offset
        )[0]
        virtual_address = struct.unpack_from(
            endian + value_format, payload, offset + virtual_offset
        )[0]
        alignment = struct.unpack_from(
            endian + value_format, payload, offset + align_offset
        )[0]
        alignments.append(alignment)
        if alignment == 0 or virtual_address % alignment != file_offset % alignment:
            raise ContractError(f"{abi} ELF has an invalid PT_LOAD alignment relation")
    if not alignments:
        raise ContractError(f"{abi} ELF has no PT_LOAD segments")
    return {
        "classBits": 32 if elf_class == 1 else 64,
        "machine": machine,
        "loadAlignments": alignments,
    }


def verify_archive(
    artifact: Path,
    root: Path,
    forbidden_paths: list[str] | None = None,
) -> dict[str, Any]:
    lock = load_lock(root)
    android = lock["android"]
    library_name = android["nativeLibrary"]
    expected_abis = [target["abi"] for target in android["targets"]]
    required_entries = {
        "AndroidManifest.xml",
        "classes.jar",
        "assets/geoip.dat",
        "assets/geosite.dat",
        *(f"jni/{abi}/{library_name}" for abi in expected_abis),
    }
    forbidden = list(KNOWN_PATH_PREFIXES)
    for value in forbidden_paths or []:
        if value:
            forbidden.append(value.encode("utf-8"))

    try:
        archive = zipfile.ZipFile(artifact)
    except (OSError, zipfile.BadZipFile) as error:
        raise ContractError(f"cannot open AAR {artifact}: {error}") from error

    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ContractError("AAR contains duplicate ZIP entries")
        unsafe = [name for name in names if name.startswith("/") or ".." in Path(name).parts]
        if unsafe:
            raise ContractError(f"AAR contains unsafe ZIP paths: {unsafe}")
        missing = required_entries - set(names)
        if missing:
            raise ContractError(f"AAR is missing required entries: {sorted(missing)}")
        unexpected_native = sorted(
            name
            for name in names
            if name.startswith("jni/")
            and name not in {f"jni/{abi}/{library_name}" for abi in expected_abis}
        )
        if unexpected_native:
            raise ContractError(f"AAR contains unexpected native entries: {unexpected_native}")

        entry_records: list[dict[str, Any]] = []
        native_records: dict[str, Any] = {}
        for info in infos:
            if info.date_time != FIXED_ZIP_TIMESTAMP:
                raise ContractError(
                    f"non-deterministic ZIP timestamp for {info.filename}: {info.date_time}"
                )
            if info.is_dir():
                entry_records.append(
                    {"path": info.filename, "size": 0, "sha256": sha256_bytes(b"")}
                )
                continue
            payload = archive.read(info)
            for marker in forbidden:
                if marker in payload:
                    raise ContractError(
                        f"forbidden absolute build path in {info.filename}: "
                        f"{marker.decode('utf-8', errors='replace')}"
                    )
            entry_records.append(
                {"path": info.filename, "size": len(payload), "sha256": sha256_bytes(payload)}
            )
            if info.filename.startswith("jni/"):
                abi = info.filename.split("/", 2)[1]
                elf = parse_elf_load_alignment(payload, abi)
                required_page_size = android["pageSizeBytes"]
                if min(elf["loadAlignments"]) < required_page_size:
                    raise ContractError(
                        f"{abi} PT_LOAD alignment is below {required_page_size}: "
                        f"{elf['loadAlignments']}"
                    )
                native_records[abi] = elf

        for asset in ("assets/geoip.dat", "assets/geosite.dat"):
            payload = archive.read(asset)
            locked = lock["sourceInputs"][asset]
            if len(payload) != locked["size"] or sha256_bytes(payload) != locked["sha256"]:
                raise ContractError(f"embedded locked asset mismatch: {asset}")

    return {
        "schemaVersion": 1,
        "contract": "androidlibxraylite-aar-manifest-v1",
        "artifact": {
            "name": artifact.name,
            "size": artifact.stat().st_size,
            "sha256": sha256_file(artifact),
        },
        "entries": sorted(entry_records, key=lambda value: value["path"]),
        "native": {abi: native_records[abi] for abi in sorted(native_records)},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--forbidden-path", action="append", default=[])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--source-epoch", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        manifest = verify_archive(
            args.artifact.resolve(),
            args.root.resolve(),
            args.forbidden_path,
        )
    except ContractError as error:
        print(f"AAR verification failed: {error}", file=sys.stderr)
        return 1
    if args.source_sha:
        manifest["source"] = {
            "repository": load_lock(args.root.resolve())["canonicalRepository"],
            "commitSha": args.source_sha,
            "sourceDateEpoch": args.source_epoch,
        }
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(
        f"AAR verification passed: {manifest['artifact']['sha256']}, "
        f"{len(manifest['native'])} ABIs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
