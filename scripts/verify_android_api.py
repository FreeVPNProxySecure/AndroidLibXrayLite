#!/usr/bin/env python3
"""Verify generated Java and JNI surfaces against the reviewed Android API."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import xml.etree.ElementTree as ET
import zipfile

try:
    from .validate_build_contract import ContractError, load_lock, sha256_file
except ImportError:
    from validate_build_contract import ContractError, load_lock, sha256_file


BASELINE_PATH = Path("config/android-api-baseline.json")
ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"


def load_baseline(root: Path) -> dict[str, Any]:
    try:
        baseline = json.loads((root / BASELINE_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read {BASELINE_PATH}: {error}") from error
    if baseline.get("schemaVersion") != 1:
        raise ContractError("Android API baseline schemaVersion must be 1")
    if baseline.get("contract") != "androidlibxraylite-android-api-v1":
        raise ContractError("unexpected Android API baseline contract")
    signatures = baseline.get("publicClassSignatures")
    exports = baseline.get("jniExports")
    if not isinstance(signatures, dict) or not signatures:
        raise ContractError("Android API baseline must contain class signatures")
    if not isinstance(exports, list) or not exports:
        raise ContractError("Android API baseline must contain JNI exports")
    if exports != sorted(set(exports)):
        raise ContractError("Android API baseline JNI exports must be sorted and unique")
    return baseline


def verify_manifest(payload: bytes, baseline: dict[str, Any]) -> None:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise ContractError(f"cannot parse AndroidManifest.xml: {error}") from error
    expected = baseline["manifest"]
    if root.tag != "manifest" or root.get("package") != expected["package"]:
        raise ContractError("generated Android manifest package drift")
    children = list(root)
    if len(children) != 1 or children[0].tag != "uses-sdk":
        raise ContractError("generated Android manifest surface drift")
    minimum_api = children[0].get(f"{{{ANDROID_NAMESPACE}}}minSdkVersion")
    if minimum_api != str(expected["minimumApi"]):
        raise ContractError("generated Android manifest minimum API drift")


def class_signatures(classes_jar: bytes) -> dict[str, str]:
    javap = shutil.which("javap")
    if not javap:
        raise ContractError("javap is required for Android API verification")
    with tempfile.NamedTemporaryFile(suffix=".jar") as temporary:
        temporary.write(classes_jar)
        temporary.flush()
        with zipfile.ZipFile(temporary.name) as archive:
            classes = sorted(
                name.removesuffix(".class").replace("/", ".")
                for name in archive.namelist()
                if name.endswith(".class")
            )
        signatures: dict[str, str] = {}
        for class_name in classes:
            result = subprocess.run(
                [javap, "-public", "-s", "-constants", "-classpath", temporary.name, class_name],
                check=False,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )
            if result.returncode != 0:
                raise ContractError(f"javap failed for {class_name}: {result.stderr.strip()}")
            signatures[class_name] = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
    return signatures


def find_llvm_nm(ndk_home: Path) -> Path:
    candidates = sorted((ndk_home / "toolchains/llvm/prebuilt").glob("*/bin/llvm-nm"))
    if len(candidates) != 1 or not candidates[0].is_file():
        raise ContractError(f"cannot locate one llvm-nm under {ndk_home}")
    return candidates[0]


def jni_exports(payload: bytes, llvm_nm: Path) -> list[str]:
    with tempfile.NamedTemporaryFile(suffix=".so") as temporary:
        temporary.write(payload)
        temporary.flush()
        result = subprocess.run(
            [str(llvm_nm), "--dynamic", "--defined-only", temporary.name],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise ContractError(f"llvm-nm failed: {result.stderr.strip()}")
    return sorted(
        fields[-1]
        for line in result.stdout.splitlines()
        if (fields := line.split()) and fields[-1].startswith("Java_")
    )


def verify_android_api(artifact: Path, root: Path, ndk_home: Path) -> dict[str, Any]:
    baseline = load_baseline(root)
    lock = load_lock(root)
    llvm_nm = find_llvm_nm(ndk_home)
    try:
        archive = zipfile.ZipFile(artifact)
    except (OSError, zipfile.BadZipFile) as error:
        raise ContractError(f"cannot open AAR {artifact}: {error}") from error
    with archive:
        verify_manifest(archive.read("AndroidManifest.xml"), baseline)
        actual_signatures = class_signatures(archive.read("classes.jar"))
        expected_signatures = baseline["publicClassSignatures"]
        if actual_signatures != expected_signatures:
            missing = sorted(set(expected_signatures) - set(actual_signatures))
            added = sorted(set(actual_signatures) - set(expected_signatures))
            changed = sorted(
                name
                for name in set(actual_signatures) & set(expected_signatures)
                if actual_signatures[name] != expected_signatures[name]
            )
            raise ContractError(
                f"generated public API drift: missing={missing}, added={added}, changed={changed}"
            )
        expected_exports = baseline["jniExports"]
        export_counts: dict[str, int] = {}
        for target in lock["android"]["targets"]:
            abi = target["abi"]
            payload = archive.read(f"jni/{abi}/{lock['android']['nativeLibrary']}")
            actual_exports = jni_exports(payload, llvm_nm)
            if actual_exports != expected_exports:
                raise ContractError(f"generated JNI export drift for {abi}")
            export_counts[abi] = len(actual_exports)
    return {
        "contract": baseline["contract"],
        "baselineSha256": sha256_file(root / BASELINE_PATH),
        "publicClassCount": len(actual_signatures),
        "jniExportCounts": export_counts,
        "manifest": baseline["manifest"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--ndk-home", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_android_api(
            args.artifact.resolve(), args.root.resolve(), args.ndk_home.resolve()
        )
    except (ContractError, KeyError, OSError, zipfile.BadZipFile) as error:
        print(f"Android API verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "Android API verification passed: "
        f"{report['publicClassCount']} classes, "
        f"{next(iter(report['jniExportCounts'].values()))} JNI exports"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
