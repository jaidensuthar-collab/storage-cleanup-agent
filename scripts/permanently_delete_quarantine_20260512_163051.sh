#!/usr/bin/env bash
set -euo pipefail

if [[ "${CONFIRM_DELETE:-}" != "1" ]]; then
  echo "Set CONFIRM_DELETE=1 to permanently delete this quarantine run." >&2
  exit 1
fi

TARGET="/Users/Jaiden/StorageCleanupAgent/quarantine/20260512_163051"
MANIFEST="/Users/Jaiden/StorageCleanupAgent/manifests/quarantine_manifest_20260512_163051.csv"

if [[ ! -d "$TARGET" ]]; then
  echo "Quarantine directory not found: $TARGET" >&2
  exit 1
fi

rows=0
if [[ -f "$MANIFEST" ]]; then
  rows=$(( $(wc -l < "$MANIFEST") - 1 ))
fi

echo "About to permanently delete $TARGET ($rows manifest rows)"
rm -rf "$TARGET"
echo "Deleted quarantine directory: $TARGET"
