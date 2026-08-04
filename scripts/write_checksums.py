#!/usr/bin/env python3
"""Write a complete deterministic SHA-256 manifest for a release bundle."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    output = bundle / "checksums.txt"
    files = sorted(
        path for path in bundle.rglob("*") if path.is_file() and path != output
    )
    output.write_text(
        "".join(f"{sha256(path)}  {path.relative_to(bundle).as_posix()}\n" for path in files),
        encoding="utf-8",
    )
    print(f"wrote checksums for {len(files)} release files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
