#!/usr/bin/env python3
"""Capture fail-closed OSV evidence for every pinned tunnel source commit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

try:
    from .validate_build_contract import ContractError, load_lock
except ImportError:
    from validate_build_contract import ContractError, load_lock


ENDPOINT = "https://api.osv.dev/v1/querybatch"


def capture(root: Path) -> dict:
    lock = load_lock(root)
    sources = lock["tunnels"]["sources"]
    queries = [{"commit": source["commitSha"]} for source in sources]
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps({"queries": queries}, separators=(",", ":")).encode(),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "androidlibxraylite-tunnel-advisory-evidence",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise ContractError("OSV tunnel advisory query failed") from error
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(sources):
        raise ContractError("OSV tunnel advisory response is incomplete")

    records = []
    finding_count = 0
    for source, result in zip(sources, results, strict=True):
        if not isinstance(result, dict) or result.get("next_page_token"):
            raise ContractError(f"OSV tunnel result is malformed: {source['id']}")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise ContractError(f"OSV tunnel result is malformed: {source['id']}")
        advisory_ids = sorted(
            advisory["id"]
            for advisory in vulnerabilities
            if isinstance(advisory, dict) and isinstance(advisory.get("id"), str)
        )
        if len(advisory_ids) != len(vulnerabilities):
            raise ContractError(f"OSV tunnel advisory lacks an identity: {source['id']}")
        finding_count += len(advisory_ids)
        records.append(
            {
                "identity": f"git:{source['repository']}@{source['commitSha']}",
                "query": {"commit": source["commitSha"]},
                "status": "complete",
                "advisoryIds": advisory_ids,
            }
        )
    if finding_count:
        raise ContractError(f"OSV reported {finding_count} tunnel advisory finding(s)")
    return {
        "schemaVersion": 1,
        "contract": "androidlibxraylite-tunnel-advisory-evidence-v1",
        "provider": {
            "name": "OSV",
            "endpoint": ENDPOINT,
        },
        "reviewedAt": lock["reviewedAt"],
        "findingCount": finding_count,
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = capture(args.root.resolve())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (ContractError, OSError) as error:
        print(f"tunnel advisory capture failed: {error}", file=sys.stderr)
        return 1
    print(f"tunnel advisory evidence passed: {len(evidence['records'])} sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
