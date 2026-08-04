#!/usr/bin/env python3
"""Require byte-identical AARs and manifests from independent source roots."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def zip_content(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        return {
            info.filename: hashlib.sha256(archive.read(info)).hexdigest()
            for info in archive.infolist()
            if not info.is_dir()
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()

    first_hash = digest(args.first)
    second_hash = digest(args.second)
    if first_hash != second_hash:
        first_entries = zip_content(args.first)
        second_entries = zip_content(args.second)
        changed = sorted(
            name
            for name in set(first_entries) | set(second_entries)
            if first_entries.get(name) != second_entries.get(name)
        )
        print(
            json.dumps(
                {
                    "status": "different",
                    "firstSha256": first_hash,
                    "secondSha256": second_hash,
                    "changedEntries": changed,
                    "contentIdentical": not changed,
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1
    print(f"independent rebuilds are byte-identical: {first_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
