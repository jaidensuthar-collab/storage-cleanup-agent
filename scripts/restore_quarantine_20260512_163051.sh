#!/usr/bin/env bash
set -euo pipefail

MANIFEST="/Users/Jaiden/StorageCleanupAgent/manifests/quarantine_manifest_20260512_163051.csv"
restored=0
bytes=0

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest not found: $MANIFEST" >&2
  exit 1
fi

tail -n +2 "$MANIFEST" | while IFS=, read -r original quarantine size category reason sha modified; do
  original="${original%$'\r'}"
  quarantine="${quarantine%$'\r'}"
  if [[ -z "$original" || -z "$quarantine" ]]; then
    continue
  fi
  if [[ ! -e "$quarantine" ]]; then
    echo "Missing quarantined file: $quarantine"
    continue
  fi
  if [[ -e "$original" ]]; then
    echo "Conflict, destination exists: $original"
    continue
  fi
  mkdir -p "$(dirname "$original")"
  mv "$quarantine" "$original"
  restored=$((restored + 1))
  bytes=$((bytes + size))
  echo "Restored: $original"
done

echo "Restore complete. Files restored: $restored, bytes: $bytes"
