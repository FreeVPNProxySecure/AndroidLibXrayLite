#!/usr/bin/env python3
"""Verify a downloaded release bundle before tag or release creation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from validate_build_contract import ContractError, load_lock
from verify_aar import verify_archive


SHA_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FILES = {
    "libv2ray.aar",
    "artifact-manifest.json",
    "components.cdx.json",
    "licenses.json",
    "advisory-summary.json",
    "govulncheck.json",
    "module-graph.json",
    "package-graph.json",
    "module-edges.txt",
    "provenance.json",
    "THIRD_PARTY_NOTICES.md",
    "RELEASE_NOTES.md",
    "github-attestation.jsonl",
    "checksums.txt",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_checksums(bundle: Path) -> None:
    checksum_path = bundle / "checksums.txt"
    expected: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        fields = line.split("  ", 1)
        if len(fields) != 2 or not SHA_RE.fullmatch(fields[0]):
            raise ContractError(f"invalid checksum row: {line!r}")
        relative = fields[1]
        if relative in expected or relative == "checksums.txt":
            raise ContractError(f"invalid duplicate/self checksum row: {relative}")
        path = bundle / relative
        if not path.is_file() or path.resolve().parent != bundle.resolve() and bundle.resolve() not in path.resolve().parents:
            raise ContractError(f"unsafe or missing checksummed file: {relative}")
        expected[relative] = fields[0]
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() and path.name != "checksums.txt"
    }
    if set(expected) != actual_files:
        raise ContractError(
            f"checksum coverage mismatch: missing={sorted(actual_files - set(expected))}, "
            f"extra={sorted(set(expected) - actual_files)}"
        )
    for relative, expected_hash in expected.items():
        actual = digest(bundle / relative)
        if actual != expected_hash:
            raise ContractError(f"checksum mismatch for {relative}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    root = args.root.resolve()
    try:
        missing = REQUIRED_FILES - {
            path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()
        }
        if missing:
            raise ContractError(f"release bundle is missing files: {sorted(missing)}")
        verify_checksums(bundle)
        lock = load_lock(root)
        manifest = json.loads((bundle / "artifact-manifest.json").read_text(encoding="utf-8"))
        if manifest.get("source", {}).get("repository") != lock["canonicalRepository"]:
            raise ContractError("artifact manifest repository mismatch")
        if manifest.get("source", {}).get("commitSha") != args.source_sha:
            raise ContractError("artifact manifest source SHA mismatch")
        verified = verify_archive(bundle / lock["release"]["artifactName"], root)
        if verified["artifact"]["sha256"] != manifest.get("artifact", {}).get("sha256"):
            raise ContractError("artifact manifest AAR digest mismatch")
        provenance = json.loads((bundle / "provenance.json").read_text(encoding="utf-8"))
        if provenance.get("source", {}).get("commitSha") != args.source_sha:
            raise ContractError("provenance source SHA mismatch")
        advisory = json.loads((bundle / "advisory-summary.json").read_text(encoding="utf-8"))
        if advisory.get("scannerExitCode") != 0 or advisory.get("reachableFindingCount") != 0:
            raise ContractError("advisory evidence is not release-clean")
    except (ContractError, OSError, json.JSONDecodeError) as error:
        print(f"release bundle verification failed: {error}", file=sys.stderr)
        return 1
    print(f"release bundle verification passed for {args.source_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
