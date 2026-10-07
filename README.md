# Storage Cleanup Agent

A quarantine-first macOS storage cleanup agent written in Python 3 and shell.
It scans only user-accessible locations, moves clearly safe junk into a
timestamped quarantine folder instead of deleting it, writes a manifest and
restore script for every run, and shows a live terminal dashboard while it
works. Nothing is permanently deleted by the agent itself.

Run `scripts/run_cleanup.sh` to start a pass. Logs, reports, manifests, and the
quarantine folder are created next to the scripts and are ignored by git.
