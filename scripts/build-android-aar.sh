#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /absolute/output/directory" >&2
  exit 2
fi

exec python3 "$root/scripts/build_android_aar.py" --root "$root" "$1"
