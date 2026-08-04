#!/usr/bin/env python3
"""Verify a downloaded release bundle before tag or release creation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from .build_tunnel_bundle import verify_tunnel_archive
    from .generate_evidence import validate_tunnel_evidence
    from .validate_build_contract import ContractError, load_lock
    from .verify_aar import verify_archive
except ImportError:
    from build_tunnel_bundle import verify_tunnel_archive
    from generate_evidence import validate_tunnel_evidence
    from validate_build_contract import ContractError, load_lock
    from verify_aar import verify_archive


SHA_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_FILES = {
    "libv2ray.aar",
    "artifact-manifest.json",
    "xray-tunnel-binaries.zip",
    "tunnel-manifest.json",
    "tunnel-advisories.json",
    "components.cdx.json",
    "licenses.json",
    "license-texts.zip",
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
        if not path.is_file() or (
            path.resolve().parent != bundle.resolve()
            and bundle.resolve() not in path.resolve().parents
        ):
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
        tunnel_manifest = json.loads(
            (bundle / lock["tunnels"]["manifestName"]).read_text(encoding="utf-8")
        )
        verified_tunnel = verify_tunnel_archive(
            bundle / lock["tunnels"]["artifactName"], root
        )
        expected_tunnel_manifest = {
            "schemaVersion": 1,
            "contract": "androidlibxraylite-tunnel-manifest-v1",
            "artifact": verified_tunnel["artifact"],
            "source": {
                "repository": lock["canonicalRepository"],
                "commitSha": args.source_sha,
            },
            "upstreamSources": lock["tunnels"]["sources"],
            "toolchain": {
                "androidNdk": lock["android"]["ndk"],
                "minimumApi": lock["tunnels"]["minimumApi"],
                "pageSizeBytes": lock["tunnels"]["pageSizeBytes"],
            },
            "entries": verified_tunnel["entries"],
        }
        if tunnel_manifest != expected_tunnel_manifest:
            raise ContractError("tunnel manifest does not describe the release artifact")
        tunnel_advisories = json.loads(
            (bundle / "tunnel-advisories.json").read_text(encoding="utf-8")
        )
        validate_tunnel_evidence(
            lock,
            tunnel_manifest,
            tunnel_advisories,
            args.source_sha,
        )
        provenance = json.loads((bundle / "provenance.json").read_text(encoding="utf-8"))
        if provenance.get("source", {}).get("commitSha") != args.source_sha:
            raise ContractError("provenance source SHA mismatch")
        if (
            provenance.get("output") != verified["artifact"]
            or provenance.get("tunnelOutput") != verified_tunnel["artifact"]
            or provenance.get("tunnelSources") != lock["tunnels"]["sources"]
        ):
            raise ContractError("provenance output closure mismatch")
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
