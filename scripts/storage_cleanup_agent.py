#!/usr/bin/env python3
"""Conservative, quarantine-first Mac storage cleanup agent."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore

SECONDS_PER_DAY = 86400
CHUNK_SIZE = 4 * 1024 * 1024
HASH_SIZE_LIMIT = 2 * 1024 * 1024 * 1024
HASHABLE_LARGE_EXTENSIONS = {".dmg", ".pkg", ".zip", ".mp4", ".mov"}

RECENT_MODIFY_CATEGORIES = {
    "cache",
    "temp",
    "old_log",
    "download_leftover",
    "ds_store",
    "crash_report",
}

DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".pages", ".txt", ".md", ".tex", ".rtf"}

PROJECT_DIR_NAMES = {
    ".git",
    "node_modules",
    ".svn",
    ".hg",
    ".venv",
    "venv",
    "__pycache__",
}

DAW_EXTENSIONS = {".fcpbundle", ".logicx", ".band"}

DENY_DIR_NAMES = {
    "Safari",
    "Google",
    "Chrome",
    "Firefox",
    "Brave",
    "Microsoft Edge",
    "Arc",
    "Mail",
    "Messages",
    "Group Containers",
    "Mobile Documents",
    "CloudDocs",
    "Keychains",
    "Accounts",
    "Calendars",
    "Reminders",
    "Notes",
    "Photos",
    "Music",
    "TV",
    "HomeKit",
    "IdentityServices",
    "Cookies",
    "Saved Application State",
}

BROWSER_CACHE_DENY = {
    "com.apple.Safari",
    "com.google.Chrome",
    "com.google.Chrome.helper",
    "org.mozilla.firefox",
    "com.brave.Browser",
    "com.microsoft.edgemac",
    "company.thebrowser.Browser",
}

APP_SUPPORT_CACHE_PATTERNS = re.compile(
    r"(cache|tmp|temp|logs?|crashreporter)",
    re.IGNORECASE,
)

DUPLICATE_NAME_PATTERN = re.compile(
    r"(?i)(?:\s+copy(?:\s+\d+)?|\s+\(\d+\)|\s+duplicate)$"
)

MEETING_INSTALLER_PATTERN = re.compile(
    r"(?i)(zoom|webex|teams).+\.(dmg|pkg)$"
)

SCREENSHOT_PATTERN = re.compile(r"(?i)^(screen[\s_-]?shot|screenshot)")

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}


@dataclass
class FileMeta:
    path: Path
    size: int
    mtime: float
    suffix: str
    parent_root: str
    is_dir: bool = False
    sha256: str = ""
    category: str = ""
    reason: str = ""


@dataclass
class RunContext:
    root: Path
    run_id: str
    state_file: Path
    home: Path
    quarantine_dir: Path
    manifest_path: Path
    baseline_path: Path
    final_report_path: Path
    restore_script_path: Path
    delete_script_path: Path
    log_path: Path
    allow_roots: list[Path] = field(default_factory=list)
    starting_free_bytes: int = 0
    files_scanned: int = 0
    potential_junk_found: int = 0
    duplicate_candidates: int = 0
    safe_cleanup_bytes: int = 0
    quarantined_bytes: int = 0
    skipped_risky: int = 0
    errors: list[str] = field(default_factory=list)
    quarantine_rows: list[dict[str, str]] = field(default_factory=list)
    large_old_review: list[FileMeta] = field(default_factory=list)
    duplicate_groups: int = 0
    manifest_writer: Optional[csv.DictWriter] = None
    manifest_file: Optional[object] = None
    state_counter: int = 0

    def log_error(self, message: str) -> None:
        if len(self.errors) >= 200:
            self.errors.pop(0)
        self.errors.append(message)
        logging.error(message)

    def update_state(self, phase: str, folder: str = "") -> None:
        self.state_counter += 1
        if self.state_counter % 25 != 0 and folder == "":
            return
        payload = {
            "status": "running",
            "current_phase": phase,
            "files_scanned": self.files_scanned,
            "potential_junk_found": self.potential_junk_found,
            "duplicate_candidates": self.duplicate_candidates,
            "safe_cleanup_bytes": self.safe_cleanup_bytes,
            "quarantined_bytes": self.quarantined_bytes,
            "skipped_risky": self.skipped_risky,
            "current_folder": folder or "n/a",
            "errors": self.errors[-20:],
            "updated_at": time.time(),
            "run_id": self.run_id,
        }
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.state_file)

    def set_status(self, status: str, phase: str) -> None:
        payload = {
            "status": status,
            "current_phase": phase,
            "files_scanned": self.files_scanned,
            "potential_junk_found": self.potential_junk_found,
            "duplicate_candidates": self.duplicate_candidates,
            "safe_cleanup_bytes": self.safe_cleanup_bytes,
            "quarantined_bytes": self.quarantined_bytes,
            "skipped_risky": self.skipped_risky,
            "current_folder": "n/a",
            "errors": self.errors[-20:],
            "updated_at": time.time(),
            "run_id": self.run_id,
        }
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )


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


def du_size(path: Path, timeout: int = 45) -> int:
    try:
        result = subprocess.run(
            ["du", "-sk", str(path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.split()[0]) * 1024
    except (OSError, subprocess.TimeoutExpired):
        pass
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    return 0


def collect_baseline(home: Path, ctx: Optional[RunContext] = None) -> dict:
    usage = shutil.disk_usage(home)
    children: list[tuple[str, int]] = []
    try:
        entries = sorted(
            (entry for entry in home.iterdir() if not entry.name.startswith(".")),
            key=lambda entry: entry.name.lower(),
        )
    except OSError as exc:
        entries = []
        children.append((f"error listing home: {exc}", 0))
    for entry in entries:
        if ctx is not None:
            ctx.update_state("baseline", str(entry))
        children.append((entry.name, du_size(entry)))
    children.sort(key=lambda item: item[1], reverse=True)
    targets = {
        "Downloads": home / "Downloads",
        "Desktop": home / "Desktop",
        "Documents": home / "Documents",
        "Movies": home / "Movies",
        "Pictures": home / "Pictures",
        "Music": home / "Music",
        "Library/Caches": home / "Library" / "Caches",
        "Trash": home / ".Trash",
    }
    target_sizes: dict[str, int] = {}
    for name, path in targets.items():
        if ctx is not None:
            ctx.update_state("baseline", str(path))
        target_sizes[name] = du_size(path)
    return {
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "top_children": children[:20],
        "target_sizes": target_sizes,
    }


def write_baseline_report(ctx: RunContext, baseline: dict) -> None:
    lines = [
        f"Storage baseline for run {ctx.run_id}",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"Total: {format_bytes(baseline['total_bytes'])}",
        f"Used:  {format_bytes(baseline['used_bytes'])}",
        f"Free:  {format_bytes(baseline['free_bytes'])}",
        "",
        "Top home folders:",
    ]
    for name, size in baseline["top_children"]:
        lines.append(f"  {name:30s} {format_bytes(size)}")
    lines.append("")
    lines.append("Key locations:")
    for name, size in baseline["target_sizes"].items():
        lines.append(f"  {name:30s} {format_bytes(size)}")
    ctx.baseline_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def is_under(path: Path, roots: Iterable[Path]) -> bool:
    resolved = path.resolve()
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def is_denied_path(path: Path) -> bool:
    parts = set(path.parts)
    if "/System" in str(path) or "/Applications" in str(path):
        return True
    if path.suffix.lower() in DAW_EXTENSIONS:
        return True
    if path.name.endswith(".photoslibrary") or path.name.endswith(".musiclibrary"):
        return True
    if path.name in {"Photo Booth Library", "Photos Library.photoslibrary"}:
        return True
    for part in path.parts:
        if part.endswith(".app"):
            return True
        if part in PROJECT_DIR_NAMES:
            return True
        if part in DENY_DIR_NAMES:
            return True
    if path.name.endswith(".icloud"):
        return True
    return False


def should_check_cloud(path: Path) -> bool:
    lowered = str(path).lower()
    if path.name.endswith(".icloud"):
        return True
    return any(token in lowered for token in ("mobile documents", "clouddocs", "icloud"))


def has_cloud_xattr(path: Path) -> bool:
    if not should_check_cloud(path):
        return False
    try:
        result = subprocess.run(
            ["xattr", "-l", str(path)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return False
        lowered = result.stdout.decode("utf-8", errors="ignore").lower()
        return "com.apple.icloud" in lowered or "com.apple.fileprovider" in lowered
    except OSError:
        return False


def build_allow_roots(home: Path) -> list[Path]:
    roots = [
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        home / "Movies",
        home / "Pictures",
        home / "Music",
        home / "Library" / "Caches",
        home / "Library" / "Logs",
        home / ".Trash",
        home / "Library" / "Developer" / "Xcode" / "DerivedData",
        home / "Library" / "Developer" / "CoreSimulator" / "Caches",
        home / "Library" / "Developer" / "Xcode" / "iOS DeviceSupport",
    ]
    app_support = home / "Library" / "Application Support"
    if app_support.is_dir():
        try:
            for entry in app_support.iterdir():
                if APP_SUPPORT_CACHE_PATTERNS.search(entry.name):
                    if entry.name in DENY_DIR_NAMES or entry.name == "Saved Application State":
                        continue
                    roots.append(entry)
        except OSError:
            pass
    return [path for path in roots if path.exists()]


def prune_dirnames(dirpath: Path, names: list[str]) -> list[str]:
    kept: list[str] = []
    for name in sorted(names):
        if name in PROJECT_DIR_NAMES:
            continue
        candidate = dirpath / name
        if is_denied_path(candidate):
            continue
        if name.endswith(".app"):
            continue
        kept.append(name)
    return kept


def iter_files(ctx: RunContext) -> Iterator[FileMeta]:
    for root in ctx.allow_roots:
        ctx.update_state("scanning", str(root))
        stack = [root]
        while stack:
            current = stack.pop()
            ctx.update_state("scanning", str(current))
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                target = Path(entry.path).resolve()
                                if not is_under(target, ctx.allow_roots):
                                    continue
                            path = Path(entry.path)
                            if entry.is_dir(follow_symlinks=False):
                                if is_denied_path(path):
                                    continue
                                stack.append(path)
                                yield FileMeta(
                                    path=path,
                                    size=0,
                                    mtime=entry.stat(follow_symlinks=False).st_mtime,
                                    suffix="",
                                    parent_root=str(root),
                                    is_dir=True,
                                )
                            elif entry.is_file(follow_symlinks=False):
                                stat = entry.stat(follow_symlinks=False)
                                if has_cloud_xattr(path):
                                    ctx.skipped_risky += 1
                                    continue
                                yield FileMeta(
                                    path=path,
                                    size=stat.st_size,
                                    mtime=stat.st_mtime,
                                    suffix=path.suffix.lower(),
                                    parent_root=str(root),
                                    is_dir=False,
                                )
                        except OSError as exc:
                            ctx.log_error(f"scan {entry.path}: {exc}")
                            continue
            except OSError as exc:
                ctx.log_error(f"scan dir {current}: {exc}")
                continue


def age_days(timestamp: float) -> float:
    return (time.time() - timestamp) / SECONDS_PER_DAY


def has_extracted_copy(archive: Path) -> bool:
    stem = archive.stem
    parent = archive.parent
    candidates = [parent / stem, parent / f"{stem} 2"]
    try:
        for child in parent.iterdir():
            if child == archive:
                continue
            if child.stem == stem and child.is_dir():
                return True
            if child.name.startswith(stem) and child.suffix != archive.suffix:
                return True
    except OSError:
        return False
    return any(candidate.exists() for candidate in candidates)


def normalize_name(name: str) -> str:
    base = Path(name).stem
    return DUPLICATE_NAME_PATTERN.sub("", base).strip().lower()


def classify_meta(meta: FileMeta, now: float) -> Optional[str]:
    path = meta.path
    name = path.name
    suffix = meta.suffix
    parent = str(path.parent).lower()
    days = age_days(meta.mtime)

    if meta.is_dir:
        return "empty_dir"

    if name == ".DS_Store":
        return "ds_store"
    if suffix in {".crdownload", ".part"}:
        return "download_leftover"
    if suffix in {".tmp", ".temp"}:
        return "temp"
    if suffix == ".log" and ("cache" in parent or "log" in parent):
        return "old_log"
    if suffix in {".crash", ".ips"} and ("crash" in parent or "log" in parent):
        return "crash_report"
    if suffix in {".dmg", ".pkg", ".mpkg"} and days > 30:
        if "downloads" in parent or "desktop" in parent:
            if MEETING_INSTALLER_PATTERN.search(name):
                return "meeting_installer"
            return "old_installer"
    if suffix in ARCHIVE_EXTENSIONS and "downloads" in parent and days > 60:
        if has_extracted_copy(path):
            return "old_archive_with_extracted_copy"
    if DUPLICATE_NAME_PATTERN.search(path.stem):
        return "filename_duplicate_pattern"
    if SCREENSHOT_PATTERN.match(name) and suffix in {".png", ".jpg", ".jpeg"}:
        if ("downloads" in parent or "desktop" in parent) and days > 90:
            return "old_screenshot"
    if "deriveddata" in parent or "coresimulator/caches" in parent or "ios devicesupport" in parent:
        return "xcode_sim_cache"
    if "library/caches" in parent and days > 14:
        if any(token in parent for token in ("shipit", ".download", "update")):
            return "app_update_leftover"
        return "cache"
    if meta.size > 500 * 1024 * 1024 and days > 90:
        if suffix in DOCUMENT_EXTENSIONS and meta.category != "duplicate_extra":
            return "large_old_review"
        if suffix in {".dmg", ".pkg", ".zip", ".tar", ".gz", ".mov", ".mp4"}:
            return "large_old_review"
    return None


def file_hash(path: Path, size: int) -> str:
    if size == 0:
        return "0" * 64
    if size > HASH_SIZE_LIMIT and path.suffix.lower() not in HASHABLE_LARGE_EXTENSIONS:
        return ""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        logging.debug("hash skipped %s: %s", path, exc)
        return ""
    return digest.hexdigest()


def location_score(path: Path) -> int:
    text = str(path).lower()
    if "downloads" in text:
        return 10
    if "desktop" in text:
        return 20
    if "documents" in text:
        return 30
    return 100


def name_score(path: Path) -> int:
    if DUPLICATE_NAME_PATTERN.search(path.stem):
        return -40
    return 50


def choose_duplicate_extras(metas: list[FileMeta]) -> list[FileMeta]:
    ranked = sorted(
        metas,
        key=lambda item: (
            location_score(item.path) + name_score(item.path) + int(item.mtime),
        ),
        reverse=True,
    )
    keeper = ranked[0]
    extras = [item for item in ranked[1:] if item.path != keeper.path]
    for item in extras:
        item.category = "duplicate_extra"
        item.reason = f"duplicate of {keeper.path}"
    return extras


def detect_duplicates(ctx: RunContext, metas: list[FileMeta]) -> list[FileMeta]:
    by_size: dict[int, list[FileMeta]] = defaultdict(list)
    for meta in metas:
        if meta.is_dir or meta.size <= 0:
            continue
        by_size[meta.size].append(meta)

    extras: list[FileMeta] = []
    for size, group in by_size.items():
        if len(group) < 2:
            continue
        ctx.update_state("duplicate hashing")
        hash_groups: dict[str, list[FileMeta]] = defaultdict(list)
        for meta in group:
            if not meta.path.exists():
                continue
            digest = file_hash(meta.path, size)
            if not digest:
                continue
            meta.sha256 = digest
            hash_groups[digest].append(meta)

        for digest, items in hash_groups.items():
            if len(items) < 2:
                continue
            ext_groups: dict[str, list[FileMeta]] = defaultdict(list)
            for item in items:
                ext_groups[item.suffix].append(item)
            for ext_items in ext_groups.values():
                if len(ext_items) < 2:
                    continue
                name_groups: dict[str, list[FileMeta]] = defaultdict(list)
                for item in ext_items:
                    name_groups[normalize_name(item.path.name)].append(item)
                for similar in name_groups.values():
                    if len(similar) < 2:
                        continue
                    ctx.duplicate_groups += 1
                    ctx.duplicate_candidates += len(similar) - 1
                    extras.extend(choose_duplicate_extras(similar))
    return extras


def is_file_in_use(path: Path) -> bool:
    if fcntl is not None:
        try:
            with path.open("rb") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return False
        except OSError:
            return True
    try:
        probe = path.with_name(f".cleanup_probe_{os.getpid()}")
        os.rename(path, probe)
        os.rename(probe, path)
        return False
    except OSError:
        return True


def should_quarantine(ctx: RunContext, meta: FileMeta, category: str) -> tuple[bool, str]:
    if not meta.path.exists():
        return False, "missing"
    if meta.is_dir and category != "empty_dir":
        return False, "not_a_file"
    if not is_under(meta.path, ctx.allow_roots):
        return False, "outside_allowlist"
    if is_denied_path(meta.path):
        return False, "denylist"
    if category not in RECENT_MODIFY_CATEGORIES and age_days(meta.mtime) < 7:
        return False, "recently_modified"
    if not meta.is_dir and is_file_in_use(meta.path):
        return False, "in_use"
    if (
        meta.suffix in DOCUMENT_EXTENSIONS
        and category not in {"duplicate_extra", "old_installer", "old_archive_with_extracted_copy", "temp", "download_leftover"}
    ):
        return False, "protected_document"
    if category == "filename_duplicate_pattern" and not meta.sha256:
        return False, "needs_hash_proof"
    return True, "approved"


def sanitize_relative(path: Path, home: Path) -> str:
    try:
        rel = path.resolve().relative_to(home.resolve())
    except ValueError:
        rel = path.name
    return str(rel).replace(os.sep, "__")


def ensure_manifest(ctx: RunContext) -> None:
    if ctx.manifest_writer is not None:
        return
    ctx.manifest_path.parent.mkdir(parents=True, exist_ok=True)
    handle = ctx.manifest_path.open("w", encoding="utf-8", newline="")
    writer = csv.DictWriter(
        handle,
        fieldnames=[
            "original_path",
            "quarantine_path",
            "size_bytes",
            "category",
            "reason",
            "sha256",
            "modified_date",
        ],
    )
    writer.writeheader()
    ctx.manifest_file = handle
    ctx.manifest_writer = writer


def quarantine_meta(ctx: RunContext, meta: FileMeta, category: str, reason: str) -> bool:
    ok, gate_reason = should_quarantine(ctx, meta, category)
    if not ok:
        ctx.skipped_risky += 1
        logging.info("skip %s (%s): %s", meta.path, category, gate_reason)
        return False

    ensure_manifest(ctx)
    digest = meta.sha256 or file_hash(meta.path, meta.size)
    prefix = digest[:12] if digest else "nohash"
    relative = sanitize_relative(meta.path, ctx.home)
    destination = ctx.quarantine_dir / f"{prefix}__{relative}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination = destination.with_name(f"{destination.name}.{int(time.time())}")

    try:
        shutil.move(str(meta.path), str(destination))
    except OSError:
        try:
            shutil.copy2(meta.path, destination)
            size_after = destination.stat().st_size
            if size_after != meta.size:
                destination.unlink(missing_ok=True)
                raise
            post_hash = file_hash(destination, meta.size)
            if digest and post_hash and post_hash != digest:
                destination.unlink(missing_ok=True)
                raise ValueError("hash mismatch after copy")
            meta.path.unlink()
        except OSError as exc:
            ctx.log_error(f"quarantine failed {meta.path}: {exc}")
            ctx.skipped_risky += 1
            return False

    row = {
        "original_path": str(meta.path),
        "quarantine_path": str(destination),
        "size_bytes": str(meta.size),
        "category": category,
        "reason": reason or category,
        "sha256": digest,
        "modified_date": datetime.fromtimestamp(meta.mtime, tz=timezone.utc).isoformat(),
    }
    assert ctx.manifest_writer is not None
    ctx.manifest_writer.writerow(row)
    if ctx.manifest_file is not None:
        ctx.manifest_file.flush()
    ctx.quarantine_rows.append(row)
    ctx.quarantined_bytes += meta.size
    ctx.update_state("quarantining", str(meta.path.parent))
    logging.info("quarantined %s -> %s", meta.path, destination)
    return True


def dir_is_empty(path: Path) -> bool:
    try:
        next(path.iterdir())
    except StopIteration:
        return True
    except OSError:
        return False
    return False


def process_candidates(ctx: RunContext, metas: Iterable[FileMeta], categories: set[str]) -> None:
    for meta in metas:
        category = meta.category or classify_meta(meta, time.time())
        if category not in categories:
            continue
        if category == "empty_dir":
            if meta.path.exists() and meta.path.is_dir() and dir_is_empty(meta.path):
                meta.size = 0
                quarantine_meta(ctx, meta, category, "empty directory")
            continue
        if category == "large_old_review":
            ctx.large_old_review.append(meta)
            continue
        ctx.potential_junk_found += 1
        ctx.safe_cleanup_bytes += meta.size
        if category == "filename_duplicate_pattern":
            meta.sha256 = file_hash(meta.path, meta.size)
        quarantine_meta(ctx, meta, category, meta.reason or category)


def process_trash(ctx: RunContext) -> None:
    trash = ctx.home / ".Trash"
    if not trash.is_dir():
        ctx.log_error("Trash unavailable or unreadable")
        return
    ctx.update_state("trash cleanup", str(trash))
    try:
        for entry in trash.iterdir():
            try:
                stat = entry.stat()
            except OSError as exc:
                ctx.log_error(f"trash stat {entry}: {exc}")
                continue
            if age_days(stat.st_mtime) <= 30:
                continue
            meta = FileMeta(
                path=entry,
                size=du_size(entry),
                mtime=stat.st_mtime,
                suffix=entry.suffix.lower(),
                parent_root=str(trash),
                is_dir=entry.is_dir(),
            )
            quarantine_meta(ctx, meta, "trash_old", "trash item older than 30 days")
    except OSError as exc:
        ctx.log_error(f"trash cleanup failed: {exc}")


def cache_subdir_active(path: Path) -> bool:
    now = time.time()
    try:
        for root, _, files in os.walk(path):
            for name in files[:200]:
                try:
                    mtime = (Path(root) / name).stat().st_mtime
                except OSError:
                    continue
                if now - mtime < SECONDS_PER_DAY:
                    return True
    except OSError:
        return True
    return False


def process_cache(ctx: RunContext) -> None:
    cache_root = ctx.home / "Library" / "Caches"
    if not cache_root.is_dir():
        return
    ctx.update_state("cache cleanup", str(cache_root))
    try:
        for entry in cache_root.iterdir():
            if entry.name in BROWSER_CACHE_DENY:
                continue
            if "cookies" in entry.name.lower() or "gpucache" in entry.name.lower():
                continue
            if entry.is_dir() and cache_subdir_active(entry):
                continue
            if entry.is_file():
                try:
                    stat = entry.stat()
                except OSError:
                    continue
                if age_days(stat.st_mtime) <= 14:
                    continue
                meta = FileMeta(
                    path=entry,
                    size=stat.st_size,
                    mtime=stat.st_mtime,
                    suffix=entry.suffix.lower(),
                    parent_root=str(cache_root),
                )
                quarantine_meta(ctx, meta, "cache", "old cache file")
                continue
            if not entry.is_dir():
                continue
            for root, dirnames, filenames in os.walk(entry):
                dirnames[:] = prune_dirnames(Path(root), dirnames)
                for name in filenames:
                    path = Path(root) / name
                    if "cookies" in str(path).lower() or "gpucache" in str(path).lower():
                        continue
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    if age_days(stat.st_mtime) <= 14:
                        continue
                    meta = FileMeta(
                        path=path,
                        size=stat.st_size,
                        mtime=stat.st_mtime,
                        suffix=path.suffix.lower(),
                        parent_root=str(cache_root),
                    )
                    quarantine_meta(ctx, meta, "cache", "old cache file")
    except OSError as exc:
        ctx.log_error(f"cache cleanup failed: {exc}")


def write_restore_script(ctx: RunContext) -> None:
    content = f"""#!/usr/bin/env bash
set -euo pipefail

MANIFEST="{ctx.manifest_path}"
restored=0
bytes=0

if [[ ! -f "$MANIFEST" ]]; then
  echo "Manifest not found: $MANIFEST" >&2
  exit 1
fi

tail -n +2 "$MANIFEST" | while IFS=, read -r original quarantine size category reason sha modified; do
  original="${{original%$'\\r'}}"
  quarantine="${{quarantine%$'\\r'}}"
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
"""
    ctx.restore_script_path.write_text(content, encoding="utf-8")
    ctx.restore_script_path.chmod(0o755)


def write_delete_script(ctx: RunContext) -> None:
    content = f"""#!/usr/bin/env bash
set -euo pipefail

if [[ "${{CONFIRM_DELETE:-}}" != "1" ]]; then
  echo "Set CONFIRM_DELETE=1 to permanently delete this quarantine run." >&2
  exit 1
fi

TARGET="{ctx.quarantine_dir}"
MANIFEST="{ctx.manifest_path}"

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
"""
    ctx.delete_script_path.write_text(content, encoding="utf-8")
    ctx.delete_script_path.chmod(0o755)


def write_final_report(ctx: RunContext, ending_free: int) -> None:
  top_quarantined = sorted(
      ctx.quarantine_rows,
      key=lambda row: int(row.get("size_bytes", 0)),
      reverse=True,
  )[:25]
  top_review = sorted(ctx.large_old_review, key=lambda item: item.size, reverse=True)[:25]
  lines = [
      f"# Final Storage Cleanup Report ({ctx.run_id})",
      "",
      f"- Starting free space: {format_bytes(ctx.starting_free_bytes)}",
      f"- Ending free space: {format_bytes(ending_free)}",
      f"- Estimated quarantined space: {format_bytes(ctx.quarantined_bytes)}",
      f"- Disk delta may differ because moves within the same volume affect used/free accounting gradually.",
      "",
      "## Counts",
      f"- Files scanned: {ctx.files_scanned}",
      f"- Files quarantined: {len(ctx.quarantine_rows)}",
      f"- Duplicate groups: {ctx.duplicate_groups}",
      f"- Duplicate candidates: {ctx.duplicate_candidates}",
      f"- Skipped risky files: {ctx.skipped_risky}",
      f"- Errors logged: {len(ctx.errors)}",
      "",
      "## Quarantine",
      f"- Location: `{ctx.quarantine_dir}`",
      f"- Manifest: `{ctx.manifest_path}`",
      f"- Restore script: `{ctx.restore_script_path}`",
      "",
      "## Restore instructions",
      f"Run `{ctx.restore_script_path}` to move quarantined files back to their original paths.",
      "",
      "## Top quarantined items",
  ]
  for row in top_quarantined:
      lines.append(
          f"- {format_bytes(int(row['size_bytes']))} | {row['category']} | {row['original_path']}"
      )
  lines.append("")
  lines.append("## Top large files left for manual review")
  for meta in top_review:
      lines.append(f"- {format_bytes(meta.size)} | {meta.path}")
  lines.append("")
  lines.append("## Errors")
  if not ctx.errors:
      lines.append("- None")
  else:
      for err in ctx.errors[:50]:
          lines.append(f"- {err}")
  ctx.final_report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def setup_run(args: argparse.Namespace) -> RunContext:
    root = Path(args.root).expanduser()
    run_id = args.run_id
    home = Path.home()
    ctx = RunContext(
        root=root,
        run_id=run_id,
        state_file=Path(args.state_file).expanduser(),
        home=home,
        quarantine_dir=root / "quarantine" / run_id,
        manifest_path=root / "manifests" / f"quarantine_manifest_{run_id}.csv",
        baseline_path=root / "reports" / f"storage_baseline_{run_id}.txt",
        final_report_path=root / "reports" / f"final_report_{run_id}.md",
        restore_script_path=root / "scripts" / f"restore_quarantine_{run_id}.sh",
        delete_script_path=root / "scripts" / f"permanently_delete_quarantine_{run_id}.sh",
        log_path=root / "logs" / f"run_{run_id}.log",
    )
    for path in (
        root / "logs",
        root / "reports",
        root / "quarantine",
        root / "scripts",
        root / "manifests",
        ctx.quarantine_dir,
    ):
        path.mkdir(parents=True, exist_ok=True)

    setup_logging(ctx.log_path)
    ctx.allow_roots = build_allow_roots(home)
    ctx.set_status("starting", "setup")
    logging.info("run_id=%s python=%s macos=%s", run_id, platform.python_version(), platform.mac_ver())
    logging.info("allow_roots=%s", [str(path) for path in ctx.allow_roots])
    return ctx


def main() -> int:
    parser = argparse.ArgumentParser(description="Storage cleanup agent")
    parser.add_argument("--root", default=str(Path.home() / "StorageCleanupAgent"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--state-file", required=True)
    args = parser.parse_args()

    ctx = setup_run(args)
    try:
        ctx.update_state("baseline")
        baseline = collect_baseline(ctx.home, ctx)
        ctx.starting_free_bytes = int(baseline["free_bytes"])
        write_baseline_report(ctx, baseline)

        scanned: list[FileMeta] = []
        for meta in iter_files(ctx):
            ctx.files_scanned += 1
            category = classify_meta(meta, time.time())
            if category:
                meta.category = category
                if category == "large_old_review":
                    ctx.large_old_review.append(meta)
                elif category != "empty_dir":
                    ctx.potential_junk_found += 1
                    ctx.safe_cleanup_bytes += meta.size
            scanned.append(meta)

        try:
            duplicate_extras = detect_duplicates(ctx, scanned)
        except OSError as exc:
            ctx.log_error(f"duplicate detection failed: {exc}")
            duplicate_extras = []
        for meta in duplicate_extras:
            ctx.potential_junk_found += 1
            ctx.safe_cleanup_bytes += meta.size

        category_a = {
            "cache",
            "temp",
            "old_log",
            "ds_store",
            "crash_report",
            "download_leftover",
            "old_installer",
            "old_archive_with_extracted_copy",
            "app_update_leftover",
            "xcode_sim_cache",
            "meeting_installer",
            "old_screenshot",
        }
        process_candidates(ctx, scanned, category_a)
        process_candidates(ctx, duplicate_extras, {"duplicate_extra"})
        process_candidates(ctx, scanned, {"empty_dir"})

        process_trash(ctx)
        process_cache(ctx)

        if ctx.manifest_file is not None:
            ctx.manifest_file.close()

        ending_free = shutil.disk_usage(ctx.home).free
        write_restore_script(ctx)
        write_delete_script(ctx)
        write_final_report(ctx, ending_free)
        ctx.set_status("completed", "done")
        logging.info(
            "completed scanned=%s quarantined=%s bytes=%s",
            ctx.files_scanned,
            len(ctx.quarantine_rows),
            ctx.quarantined_bytes,
        )
        return 0
    except Exception as exc:  # pragma: no cover
        ctx.log_error(str(exc))
        ctx.set_status("failed", "error")
        logging.exception("agent failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
