#!/usr/bin/env python3
"""Live terminal dashboard for the storage cleanup agent."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def format_bytes(value: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{value} B"


def read_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def render(state: dict | None, stale: bool) -> None:
    sys.stdout.write("\033[2J\033[H")
    print("STORAGE CLEANUP AGENT")
    print("=" * 60)
    if state is None:
        print("Status: waiting for agent")
        print("Current phase: n/a")
        print("Files scanned: 0")
        print("Potential junk found: 0")
        print("Duplicate candidates: 0")
        print("Safe cleanup size: 0 B")
        print("Quarantined size: 0 B")
        print("Skipped risky files: 0")
        print("Current folder being scanned: n/a")
        print("Errors:")
        print("  (none)")
        sys.stdout.flush()
        return

    status = state.get("status", "unknown")
    if stale:
        status = f"{status} (state stale)"

    print(f"Status: {status}")
    print(f"Current phase: {state.get('current_phase', 'n/a')}")
    print(f"Files scanned: {state.get('files_scanned', 0)}")
    print(f"Potential junk found: {state.get('potential_junk_found', 0)}")
    print(f"Duplicate candidates: {state.get('duplicate_candidates', 0)}")
    print(f"Safe cleanup size: {format_bytes(int(state.get('safe_cleanup_bytes', 0)))}")
    print(f"Quarantined size: {format_bytes(int(state.get('quarantined_bytes', 0)))}")
    print(f"Skipped risky files: {state.get('skipped_risky', 0)}")
    print(f"Current folder being scanned: {state.get('current_folder', 'n/a')}")
    print("Errors:")
    errors = state.get("errors", [])
    if not errors:
        print("  (none)")
    else:
        for line in errors[-8:]:
            print(f"  {line}")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="Storage cleanup live dashboard")
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--refresh-seconds", type=float, default=2.0)
    parser.add_argument("--hold-seconds", type=float, default=30.0)
    args = parser.parse_args()

    state_path = Path(args.state_file).expanduser()
    refresh = max(0.5, args.refresh_seconds)
    hold = max(0.0, args.hold_seconds)

    completed_at: float | None = None
    while True:
        state = read_state(state_path)
        stale = False
        if state is not None:
            updated = float(state.get("updated_at", 0))
            stale = (time.time() - updated) > 30.0
        render(state, stale)

        status = (state or {}).get("status")
        if status in {"completed", "failed"}:
            if completed_at is None:
                completed_at = time.time()
            elif time.time() - completed_at >= hold:
                break
        else:
            completed_at = None

        time.sleep(refresh)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
