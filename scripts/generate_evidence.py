#!/usr/bin/env python3
"""Generate release evidence from the locked source, module graph, and AAR."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Iterator
from urllib.parse import quote
import zipfile

try:
    from .validate_build_contract import ContractError, load_lock
except ImportError:
    from validate_build_contract import ContractError, load_lock


LICENSE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def decode_json_stream(path: Path) -> Iterator[dict[str, Any]]:
    content = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(content):
        while offset < len(content) and content[offset].isspace():
            offset += 1
        if offset >= len(content):
            return
        value, offset = decoder.raw_decode(content, offset)
        if isinstance(value, dict):
            yield value


def spdx_from_text(text: str) -> str | None:
    normalized = " ".join(text.lower().split())
    if "gnu lesser general public license" in normalized and "version 3" in normalized:
        return "LGPL-3.0-only"
    if (
        "gnu general public license" in normalized
        and "either version 3 of the license, or (at your option) any later version"
        in normalized
    ):
        return "GPL-3.0-or-later"
    if "apache license" in normalized and "version 2.0" in normalized:
        return "Apache-2.0"
    if "mozilla public license" in normalized and "version 2.0" in normalized:
        return "MPL-2.0"
    if "permission is hereby granted, free of charge" in normalized:
        return "MIT"
    if "redistribution and use in source and binary forms" in normalized:
        if (
            "neither the name" in normalized
            or "contributors may be used to endorse" in normalized
            or "name of the author may not be used to endorse" in normalized
        ):
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "permission to use, copy, modify, and/or distribute this software" in normalized:
        return "ISC"
    if "this is free and unencumbered software released into the public domain" in normalized:
        return "Unlicense"
    if "creative commons zero" in normalized and "1.0" in normalized:
        return "CC0-1.0"
    return None


def license_files(module_dir: Path) -> list[Path]:
    result: list[Path] = []
    if not module_dir.is_dir():
        return result
    for child in sorted(module_dir.iterdir()):
        upper = child.name.upper()
        if child.is_file() and any(upper.startswith(name) for name in LICENSE_NAMES):
            result.append(child)
    return result


def h1_to_sha256(value: str | None) -> str | None:
    if not value or not value.startswith("h1:"):
        return None
    try:
        return base64.b64decode(value.removeprefix("h1:")).hex()
    except ValueError:
        return None


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def load_dispositions(root: Path) -> dict[str, Any]:
    path = root / "config/license-dispositions.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read license dispositions: {error}") from error
    if value.get("schemaVersion") != 1 or not isinstance(value.get("components"), dict):
        raise ContractError("invalid license disposition contract")
    return value["components"]


def component_key(module: dict[str, Any]) -> str:
    return f"{module.get('Path')}@{module.get('Version') or '(main)'}"


def generate_components_and_licenses(
    root: Path,
    output: Path,
    modules_path: Path,
    packages_path: Path,
    edges_path: Path,
    artifact_manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    all_modules = list(decode_json_stream(modules_path))
    if not all_modules:
        raise ContractError("module graph JSON is empty")
    used_module_keys: set[str] = set()
    for package in decode_json_stream(packages_path):
        module = package.get("Module")
        if isinstance(module, dict):
            used_module_keys.add(component_key(module))
    main_module = all_modules[0]
    used_module_keys.add(component_key(main_module))
    modules = [module for module in all_modules if component_key(module) in used_module_keys]
    missing_used = used_module_keys - {component_key(module) for module in modules}
    if missing_used:
        raise ContractError(f"package graph references missing modules: {sorted(missing_used)}")
    dispositions = load_dispositions(root)
    license_output = output / "licenses"
    license_output.mkdir()
    license_rows: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    bom_refs: dict[str, str] = {}
    unknown: list[str] = []

    for index, module in enumerate(modules):
        path = module.get("Path")
        version = module.get("Version") or artifact_manifest["source"]["commitSha"]
        if not isinstance(path, str):
            raise ContractError("module entry is missing Path")
        key = component_key(module)
        effective = module.get("Replace") if isinstance(module.get("Replace"), dict) else module
        module_dir_raw = effective.get("Dir")
        candidates = license_files(Path(module_dir_raw)) if module_dir_raw else []
        detected: set[str] = set()
        copied: list[dict[str, Any]] = []
        for candidate in candidates:
            payload = candidate.read_bytes()
            license_id = spdx_from_text(payload.decode("utf-8", errors="replace"))
            if license_id:
                detected.add(license_id)
            target_name = f"{index:03d}-{safe_name(path)}-{safe_name(candidate.name)}"
            target = license_output / target_name
            shutil.copyfile(candidate, target)
            copied.append(
                {
                    "path": f"licenses/{target_name}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "detectedSpdx": license_id,
                }
            )

        disposition = dispositions.get(key)
        if detected:
            expression = " AND ".join(sorted(detected))
            source = "detected-root-license"
        elif isinstance(disposition, dict):
            expression = disposition.get("licenseExpression")
            if not isinstance(expression, str) or not expression:
                raise ContractError(f"invalid license disposition for {key}")
            for field in ("evidenceUrl", "rationale", "reviewedAt"):
                if not isinstance(disposition.get(field), str) or not disposition[field]:
                    raise ContractError(f"license disposition {key} is missing {field}")
            source = "reviewed-disposition"
        else:
            expression = "NOASSERTION"
            source = "missing"
            unknown.append(key)

        bom_ref = f"pkg:golang/{quote(path, safe='/')}@{quote(str(version), safe='.+-')}"
        bom_refs[key] = bom_ref
        hashes = []
        module_hash = h1_to_sha256(effective.get("Sum"))
        if module_hash:
            hashes.append({"alg": "SHA-256", "content": module_hash})
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": path,
            "version": str(version),
            "purl": bom_ref,
            "licenses": [{"expression": expression}],
            "properties": [
                {"name": "androidlibxraylite:license-source", "value": source},
                {"name": "androidlibxraylite:go-module-sum", "value": str(effective.get("Sum", ""))},
                {"name": "androidlibxraylite:go-mod-sum", "value": str(effective.get("GoModSum", ""))},
            ],
        }
        if hashes:
            component["hashes"] = hashes
        if module.get("Replace"):
            component["properties"].append(
                {
                    "name": "androidlibxraylite:replacement",
                    "value": component_key(module["Replace"]),
                }
            )
        components.append(component)
        license_rows.append(
            {
                "component": key,
                "licenseExpression": expression,
                "source": source,
                "files": copied,
                "disposition": disposition,
            }
        )

    lock = load_lock(root)
    for source_index, source in enumerate(lock["tunnels"]["sources"], start=len(modules)):
        key = f"git:{source['repository']}@{source['commitSha']}"
        bom_ref = (
            f"pkg:generic/{quote(source['repository'], safe='/')}@{source['commitSha']}"
        )
        bom_refs[key] = bom_ref
        copied: list[dict[str, Any]] = []
        detected_expressions: set[str] = set()
        for license_file in source["licenseFiles"]:
            candidate = root / source["path"] / license_file["path"]
            payload = candidate.read_bytes()
            if hashlib.sha256(payload).hexdigest() != license_file["sha256"]:
                raise ContractError(f"tunnel license evidence mismatch for {key}")
            target_name = (
                f"{source_index:03d}-{safe_name(source['repository'])}-"
                f"{safe_name(license_file['path'])}"
            )
            target = license_output / target_name
            shutil.copyfile(candidate, target)
            detected = spdx_from_text(payload.decode("utf-8", errors="replace"))
            if detected:
                detected_expressions.add(detected)
            copied.append(
                {
                    "path": f"licenses/{target_name}",
                    "sha256": license_file["sha256"],
                    "detectedSpdx": detected,
                }
            )
        if detected_expressions != set(source["licenseExpression"].split(" AND ")):
            raise ContractError(f"tunnel license expression mismatch for {key}")
        components.append(
            {
                "type": "library",
                "bom-ref": bom_ref,
                "name": source["repository"],
                "version": source["commitSha"],
                "purl": bom_ref,
                "licenses": [{"expression": source["licenseExpression"]}],
                "properties": [
                    {
                        "name": "androidlibxraylite:license-source",
                        "value": "pinned-source-license",
                    },
                    {
                        "name": "androidlibxraylite:source-path",
                        "value": source["path"],
                    },
                ],
            }
        )
        license_rows.append(
            {
                "component": key,
                "licenseExpression": source["licenseExpression"],
                "source": "pinned-source-license",
                "files": copied,
                "disposition": None,
            }
        )

    if unknown:
        raise ContractError(
            "license evidence is incomplete; add reviewed dispositions for: "
            + ", ".join(sorted(unknown))
        )

    dependencies: dict[str, set[str]] = {reference: set() for reference in bom_refs.values()}
    for line in edges_path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        source_ref = bom_refs.get(fields[0])
        target_ref = bom_refs.get(fields[1])
        if source_ref and target_ref:
            dependencies[source_ref].add(target_ref)

    artifact = artifact_manifest["artifact"]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{artifact['sha256'][0:8]}-{artifact['sha256'][8:12]}-4{artifact['sha256'][13:16]}-a{artifact['sha256'][17:20]}-{artifact['sha256'][20:32]}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": artifact["name"],
                "version": artifact_manifest["source"]["commitSha"],
                "hashes": [{"alg": "SHA-256", "content": artifact["sha256"]}],
            },
            "properties": [
                {"name": "androidlibxraylite:source-repository", "value": artifact_manifest["source"]["repository"]},
                {"name": "androidlibxraylite:source-commit", "value": artifact_manifest["source"]["commitSha"]},
            ],
        },
        "components": sorted(components, key=lambda value: value["bom-ref"]),
        "dependencies": [
            {"ref": reference, "dependsOn": sorted(targets)}
            for reference, targets in sorted(dependencies.items())
        ],
    }
    license_inventory = {
        "schemaVersion": 1,
        "contract": "androidlibxraylite-license-inventory-v1",
        "reviewedDispositionCount": sum(
            1 for row in license_rows if row["source"] == "reviewed-disposition"
        ),
        "components": sorted(license_rows, key=lambda value: value["component"]),
    }
    return bom, license_inventory


def generate_advisory_summary(
    path: Path, exit_code: int, main_module: str
) -> dict[str, Any]:
    config: dict[str, Any] | None = None
    osv: dict[str, dict[str, Any]] = {}
    affected_ids: set[str] = set()
    reachable: dict[str, dict[str, Any]] = {}
    for event in decode_json_stream(path):
        if isinstance(event.get("config"), dict):
            config = event["config"]
        if isinstance(event.get("osv"), dict):
            osv_entry = event["osv"]
            osv_id = osv_entry.get("id")
            if isinstance(osv_id, str):
                osv[osv_id] = osv_entry
        if isinstance(event.get("finding"), dict):
            finding = event["finding"]
            osv_id = finding.get("osv")
            if not isinstance(osv_id, str):
                continue
            affected_ids.add(osv_id)
            trace = finding.get("trace")
            if not isinstance(trace, list) or not any(
                isinstance(frame, dict)
                and frame.get("module") == main_module
                and isinstance(frame.get("function"), str)
                for frame in trace
            ):
                continue
            row = reachable.setdefault(
                osv_id,
                {
                    "id": osv_id,
                    "fixedVersion": finding.get("fixed_version"),
                    "affectedModule": trace[0].get("module") if trace else None,
                    "rootSymbols": set(),
                },
            )
            for frame in trace:
                if (
                    isinstance(frame, dict)
                    and frame.get("module") == main_module
                    and isinstance(frame.get("function"), str)
                ):
                    row["rootSymbols"].add(frame["function"])
    provider = config or {}
    summary = {
        "schemaVersion": 1,
        "contract": "androidlibxraylite-go-advisory-evidence-v1",
        "provider": {
            "name": "Go vulnerability database",
            "database": provider.get("db"),
            "databaseLastModified": provider.get("db_last_modified"),
            "scanner": provider.get("scanner_name"),
            "scannerVersion": provider.get("scanner_version"),
        },
        "providerLimitations": [
            "Coverage is limited to vulnerabilities published in the selected Go vulnerability database.",
            "Static reachability does not replace connected Android runtime validation or non-Go binary review."
        ],
        "scannerExitCode": exit_code,
        "reportedOsvIds": sorted(osv),
        "affectedOsvIds": sorted(affected_ids),
        "reachableFindingCount": len(reachable),
        "reachableFindings": [
            {
                **{key: value for key, value in row.items() if key != "rootSymbols"},
                "summary": osv.get(osv_id, {}).get("summary"),
                "rootSymbols": sorted(row["rootSymbols"]),
            }
            for osv_id, row in sorted(reachable.items())
        ],
    }
    if exit_code not in (0, 3):
        raise ContractError(f"govulncheck failed operationally with exit code {exit_code}")
    if reachable or exit_code == 3:
        raise ContractError(
            f"govulncheck reported {len(reachable)} reachable vulnerability ID(s); "
            "release is blocked"
        )
    return summary


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def archive_license_texts(output: Path) -> Path:
    source = output / "licenses"
    if not source.is_dir():
        raise ContractError("license text directory is missing")
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if not files:
        raise ContractError("license text inventory is empty")
    destination = output / "license-texts.zip"
    with zipfile.ZipFile(
        destination, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in files:
            relative = path.relative_to(output).as_posix()
            info = zipfile.ZipInfo(relative, ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, path.read_bytes())
    shutil.rmtree(source)
    return destination


def validate_tunnel_evidence(
    lock: dict[str, Any],
    tunnel_manifest: dict[str, Any],
    tunnel_advisories: dict[str, Any],
    source_sha: str,
) -> None:
    tunnel = lock["tunnels"]
    expected_records = [
        {
            "identity": f"git:{source['repository']}@{source['commitSha']}",
            "query": {"commit": source["commitSha"]},
            "status": "complete",
            "advisoryIds": [],
        }
        for source in tunnel["sources"]
    ]
    if (
        tunnel_manifest.get("schemaVersion") != 1
        or tunnel_manifest.get("contract")
        != "androidlibxraylite-tunnel-manifest-v1"
        or tunnel_manifest.get("artifact", {}).get("name")
        != tunnel["artifactName"]
        or tunnel_manifest.get("source")
        != {"repository": lock["canonicalRepository"], "commitSha": source_sha}
        or tunnel_manifest.get("upstreamSources") != tunnel["sources"]
        or tunnel_manifest.get("toolchain")
        != {
            "androidNdk": lock["android"]["ndk"],
            "minimumApi": tunnel["minimumApi"],
            "pageSizeBytes": tunnel["pageSizeBytes"],
        }
    ):
        raise ContractError("tunnel manifest is inconsistent with the build lock")
    if (
        tunnel_advisories.get("schemaVersion") != 1
        or tunnel_advisories.get("contract")
        != "androidlibxraylite-tunnel-advisory-evidence-v1"
        or tunnel_advisories.get("provider")
        != {"name": "OSV", "endpoint": "https://api.osv.dev/v1/querybatch"}
        or tunnel_advisories.get("reviewedAt") != lock["reviewedAt"]
        or tunnel_advisories.get("findingCount") != 0
        or tunnel_advisories.get("records") != expected_records
    ):
        raise ContractError("tunnel advisory evidence is incomplete or inconsistent")


def copy_evidence_input(source: Path, output: Path, name: str) -> None:
    destination = output / name
    if source.resolve() != destination.resolve():
        shutil.copyfile(source, destination)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifact-manifest", type=Path, required=True)
    parser.add_argument("--module-graph", type=Path, required=True)
    parser.add_argument("--package-graph", type=Path, required=True)
    parser.add_argument("--module-edges", type=Path, required=True)
    parser.add_argument("--govulncheck", type=Path, required=True)
    parser.add_argument("--govulncheck-exit-code", type=int, required=True)
    parser.add_argument("--tunnel-manifest", type=Path, required=True)
    parser.add_argument("--tunnel-advisories", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    try:
        lock = load_lock(root)
        artifact_manifest = json.loads(args.artifact_manifest.read_text(encoding="utf-8"))
        bom, licenses = generate_components_and_licenses(
            root,
            output,
            args.module_graph,
            args.package_graph,
            args.module_edges,
            artifact_manifest,
        )
        advisory = generate_advisory_summary(
            args.govulncheck, args.govulncheck_exit_code, lock["modulePath"]
        )
        tunnel_manifest = json.loads(args.tunnel_manifest.read_text(encoding="utf-8"))
        tunnel_advisories = json.loads(
            args.tunnel_advisories.read_text(encoding="utf-8")
        )
        validate_tunnel_evidence(
            lock,
            tunnel_manifest,
            tunnel_advisories,
            artifact_manifest["source"]["commitSha"],
        )
        copy_evidence_input(
            args.tunnel_manifest,
            output,
            lock["tunnels"]["manifestName"],
        )
        copy_evidence_input(
            args.tunnel_advisories,
            output,
            "tunnel-advisories.json",
        )
        provenance = {
            "schemaVersion": 1,
            "contract": "androidlibxraylite-build-provenance-v1",
            "source": artifact_manifest["source"],
            "toolchains": {
                "go": lock["go"],
                "jdk": lock["jdk"],
                "gomobile": lock["gomobile"],
                "androidNdk": lock["android"]["ndk"],
            },
            "inputs": lock["sourceInputs"],
            "build": {
                "minimumApi": lock["android"]["minimumApi"],
                "targets": lock["android"]["targets"],
                "pageSizeBytes": lock["android"]["pageSizeBytes"],
                "independentRebuilds": 2,
                "comparison": "byte-identical",
            },
            "output": artifact_manifest["artifact"],
            "tunnelOutput": tunnel_manifest["artifact"],
            "tunnelSources": tunnel_manifest["upstreamSources"],
            "tunnelAdvisoryEvidence": {
                "contract": tunnel_advisories["contract"],
                "findingCount": tunnel_advisories["findingCount"],
                "recordCount": len(tunnel_advisories["records"]),
            },
        }
        write_json(output / "components.cdx.json", bom)
        write_json(output / "licenses.json", licenses)
        write_json(output / "advisory-summary.json", advisory)
        write_json(output / "provenance.json", provenance)
        archive_license_texts(output)

        notices = [
            "# Third-Party Notices",
            "",
            "This release contains the following Go modules and recorded license expressions.",
            "The corresponding detected root license texts are included in "
            "`license-texts.zip` under `licenses/`.",
            "",
        ]
        for row in licenses["components"]:
            notices.append(f"- `{row['component']}`: `{row['licenseExpression']}`")
        (output / "THIRD_PARTY_NOTICES.md").write_text(
            "\n".join(notices) + "\n", encoding="utf-8"
        )
        release_notes = (
            "# AndroidLibXrayLite native release\n\n"
            f"Source commit: `{artifact_manifest['source']['commitSha']}`\n\n"
            f"AAR SHA-256: `{artifact_manifest['artifact']['sha256']}`\n\n"
            f"Tunnel bundle SHA-256: `{tunnel_manifest['artifact']['sha256']}`\n\n"
            "The release includes independent rebuild, dependency, license, advisory, "
            "native compatibility, checksum, and GitHub build provenance evidence.\n"
        )
        (output / "RELEASE_NOTES.md").write_text(release_notes, encoding="utf-8")
    except (ContractError, OSError, json.JSONDecodeError) as error:
        print(f"evidence generation failed: {error}", file=sys.stderr)
        return 1
    print(f"release evidence generated in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
