# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import contextlib
import ctypes
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import signal
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import development_layout  # noqa: E402

CONTROL_ROOT = development_layout.control_source_root(ROOT)
LEGACY_NAMES = {"build", "out", "tmp", "tasks", ".worktrees", ".validation"}
LEGACY_PREFIXES = ("universal-setup", "usk-", ".usk")
SHARED_PRUNABLE_ROOT_NAMES = {".archives", ".backups", ".evidence"}
IN_TREE_OUTPUT_NAMES = ("build", "dist", "out", "tmp", ".worktrees")
RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
FORBIDDEN_BRANCH_PREFIXES = (
    "backup/",
    "proof/",
    "safety/",
    "tmp/",
    "overnight/",
    "copy/",
)
DEFAULT_BRANCH_TARGETS = {
    "task/": "origin/dev",
    "release/": "origin/main",
    "hotfix/": "origin/main",
}
DEFAULT_BRANCH_STARTS = {
    "task/": "origin/dev",
    "release/": "origin/dev",
    "hotfix/": "origin/main",
}
DEFAULT_MAX_WORKTREES = 1
GIB = 1024 ** 3
DEFAULT_DISK_RESERVE = 10 * GIB
DEFAULT_RAM_RESERVE = 2 * GIB


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(detail or f"git {' '.join(args)} failed")
    return completed


def gh(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["gh", *args],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(detail or f"gh {' '.join(args)} failed")
    return completed


def default_target_for_branch(branch: str) -> str | None:
    for prefix, target in DEFAULT_BRANCH_TARGETS.items():
        if branch.startswith(prefix):
            return target
    return None


def default_start_for_branch(branch: str) -> str | None:
    for prefix, start in DEFAULT_BRANCH_STARTS.items():
        if branch.startswith(prefix):
            return start
    return None


def target_branch_name(target_ref: str) -> str:
    value = target_ref.removeprefix("refs/remotes/").removeprefix("refs/heads/")
    return value.removeprefix("origin/")


def github_pr_observation(branch: str, target_ref: str, head: str) -> dict[str, Any]:
    repository = gh(
        "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"
    ).stdout.strip()
    if not repository:
        raise ValueError("GitHub repository identity is unavailable")
    target_branch = target_branch_name(target_ref)
    merged = json.loads(
        gh(
            "pr",
            "list",
            "--repo",
            repository,
            "--head",
            branch,
            "--state",
            "merged",
            "--limit",
            "100",
            "--json",
            "number,baseRefName,headRefOid,mergedAt,url",
        ).stdout
        or "[]"
    )
    exact = [
        item
        for item in merged
        if item.get("baseRefName") == target_branch and item.get("headRefOid") == head
    ]
    dependents = json.loads(
        gh(
            "pr",
            "list",
            "--repo",
            repository,
            "--base",
            branch,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,headRefName,url",
        ).stdout
        or "[]"
    )
    return {
        "repository": repository,
        "target_branch": target_branch,
        "exact_merged_pr": exact[-1] if exact else None,
        "open_dependent_prs": dependents,
    }


def is_reparse_or_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def directory_inventory(path: Path) -> tuple[int, int, list[Path]]:
    if is_reparse_or_link(path):
        return 0, 0, [path]
    if any(is_reparse_or_link(parent) for parent in path.parents if parent.exists()):
        raise ValueError(f"inventory root crosses a link: {path}")
    def raise_walk_error(error: OSError) -> None:
        raise error

    files = 0
    total = 0
    links: list[Path] = []
    for current, directories, names in os.walk(
        path, followlinks=False, onerror=raise_walk_error
    ):
        current_path = Path(current)
        linked_directories = [
            current_path / name
            for name in directories
            if is_reparse_or_link(current_path / name)
        ]
        links.extend(linked_directories)
        directories[:] = [
            name for name in directories if current_path / name not in linked_directories
        ]
        for name in names:
            candidate = current_path / name
            if is_reparse_or_link(candidate):
                links.append(candidate)
                continue
            try:
                total += candidate.stat().st_size
                files += 1
            except OSError:
                raise
    return files, total, links


def directory_size(path: Path) -> tuple[int, int]:
    files, total, _ = directory_inventory(path)
    return files, total


def storage_inventory(extra_roots: list[str] | None = None) -> dict[str, Any]:
    """One streaming walk of the entire repository store plus explicit legacy roots.

    This is observation, never deletion authority. Linked roots are not traversed.
    Allocated sizes exclude duplicate hard links; they are not reclaimability claims.
    """
    area = development_layout.repository_root(CONTROL_ROOT)
    candidates = [area, CONTROL_ROOT]
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        candidates.append(Path(os.environ["LOCALAPPDATA"]) / "FacMan" / "Development" / "repositories" / development_layout.repository_key(CONTROL_ROOT))
    candidates += [Path(name).expanduser() for name in extra_roots or []]
    roots: list[Path] = []
    for path in sorted(set(candidates), key=lambda value: len(value.parts)):
        if not path.is_absolute() or path == Path(path.anchor) or ".." in path.parts:
            raise ValueError(f"storage observation requires an exact non-volume root: {path}")
        if not any(path.is_relative_to(parent) for parent in roots):
            roots.append(path)
    categories: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    skipped: list[str] = []
    hardlinks: set[tuple[int, int]] = set()
    allocated = None
    if os.name == "nt":
        from ctypes import wintypes
        class StandardInfo(ctypes.Structure):
            _fields_ = [("allocation", ctypes.c_longlong), ("end", ctypes.c_longlong),
                        ("links", wintypes.DWORD), ("delete_pending", ctypes.c_byte), ("directory", ctypes.c_byte)]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        def allocated(file: Path) -> int:
            handle = kernel.CreateFileW(str(file), 0x80, 7, None, 3, 0x80, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                standard = StandardInfo()
                if not kernel.GetFileInformationByHandleEx(handle, 1, ctypes.byref(standard), ctypes.sizeof(standard)):
                    raise ctypes.WinError(ctypes.get_last_error())
                return standard.allocation
            finally:
                kernel.CloseHandle(handle)
    for root in roots:
        if not os.path.lexists(root):
            continue
        if any(is_reparse_or_link(parent) for parent in (root, *root.parents) if parent.exists()):
            skipped.append(str(root))
            continue
        def walk_error(exc: OSError) -> None:
            errors.append(str(exc))
        for current, directories, names in os.walk(root, followlinks=False, onerror=walk_error):
            current_path = Path(current)
            for name in list(directories):
                child = current_path / name
                if is_reparse_or_link(child):
                    skipped.append(str(child))
                    directories.remove(name)
            for name in names:
                file = current_path / name
                try:
                    if is_reparse_or_link(file):
                        skipped.append(str(file))
                        continue
                    info = file.stat()
                    relative = file.relative_to(area) if file.is_relative_to(area) else None
                    category = str(area / relative.parts[0]) if relative and len(relative.parts) > 1 else str(root)
                    row = categories.setdefault(category, {"path": category, "logical_bytes": 0, "allocated_bytes": 0, "files": 0})
                    row["logical_bytes"] += info.st_size
                    row["files"] += 1
                    identity = (info.st_dev, info.st_ino)
                    if info.st_nlink > 1 and identity in hardlinks:
                        continue
                    if info.st_nlink > 1:
                        hardlinks.add(identity)
                    if allocated is not None:
                        row["allocated_bytes"] += allocated(file)
                    else:
                        row["allocated_bytes"] += getattr(info, "st_blocks", (info.st_size + 511) // 512) * 512
                except OSError as exc:
                    errors.append(f"{file}: {exc}")
    return {"roots": [str(path) for path in roots], "categories": sorted(categories.values(), key=lambda row: row["logical_bytes"], reverse=True),
            "logical_bytes": sum(row["logical_bytes"] for row in categories.values()),
            "allocated_bytes": sum(row["allocated_bytes"] for row in categories.values()),
            "errors": errors, "skipped_links": skipped, "complete": not errors and not skipped}


def process_observation() -> list[dict[str, Any]]:
    if os.name != "nt":
        # No portable process working-directory observation: refuse retirement.
        return [{"pid": None, "command": "", "observation_unavailable": True}]
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
        "Get-CimInstance Win32_Process | Select-Object @{n='pid';e={$_.ProcessId}},@{n='command';e={$_.CommandLine}},CreationDate | ConvertTo-Json -Compress"],
        capture_output=True, text=True, check=True)
    rows = json.loads(result.stdout or "[]")
    return rows if isinstance(rows, list) else [rows]


def worktree_material(path: Path, processes: list[dict[str, Any]]) -> dict[str, Any]:
    nested: list[str] = []
    links: list[str] = []
    errors: list[str] = []
    if not path.exists() or any(is_reparse_or_link(parent) for parent in (path, *path.parents) if parent.exists()):
        return {"material_checked": False, "material_error": "missing or linked root"}
    def walk_error(exc: OSError) -> None:
        errors.append(str(exc))
    for current, directories, names in os.walk(path, followlinks=False, onerror=walk_error):
        current_path = Path(current)
        if current_path != path and ".git" in directories + names:
            nested.append(str(current_path))
            directories[:] = []
            continue
        for name in list(directories):
            if is_reparse_or_link(current_path / name):
                links.append(str(current_path / name))
                directories.remove(name)
        links.extend(str(current_path / name) for name in names if is_reparse_or_link(current_path / name))
    normalized = str(path).replace("\\", "/").casefold()
    users = [row["pid"] for row in processes if row.get("pid") != os.getpid() and normalized in str(row.get("command") or "").replace("\\", "/").casefold()]
    available = not any(row.get("observation_unavailable") for row in processes)
    return {"material_checked": available and not errors, "nested_repositories": nested, "contained_links": links,
            "active_processes": users, "material_errors": errors}


def remove_tree(path: Path) -> None:
    if not path.is_absolute() or path == Path(path.anchor) or any(is_reparse_or_link(parent) for parent in (path, *path.parents) if parent.exists()):
        raise ValueError(f"refusing recursive removal through a link or volume root: {path}")
    def clear_readonly_and_retry(function: Any, candidate: str, exc_info: Any) -> None:
        error = exc_info[1]
        if not isinstance(error, PermissionError):
            raise error
        os.chmod(candidate, stat.S_IWRITE)
        function(candidate)

    _, _, links = directory_inventory(path)
    for link in sorted(links, key=lambda item: len(item.parts), reverse=True):
        if not os.path.lexists(link):
            continue
        try:
            link.unlink()
        except (IsADirectoryError, PermissionError):
            os.rmdir(link)
        if os.path.lexists(link):
            raise ValueError(f"failed to unlink contained reparse point: {link}")
    shutil.rmtree(path, onerror=clear_readonly_and_retry)


def task_roots(source_root: Path) -> list[Path]:
    parent = development_layout.repository_root(source_root) / "tasks"
    if not parent.is_dir():
        return []
    return sorted(path for path in parent.iterdir() if path.is_dir())


def task_root_record(path: Path, *, measure: bool) -> dict[str, Any]:
    record: dict[str, Any] = {"path": str(path.resolve()), "owned": False}
    if is_reparse_or_link(path):
        record.update({"linked": True, "error": "linked task root is refused"})
        return record
    try:
        marker = development_layout.read_marker(path, CONTROL_ROOT)
    except ValueError as exc:
        record["error"] = str(exc)
        return record
    record.update(
        {
            "owned": True,
            "task_id": marker.get("task_id"),
            "created_at": marker.get("created_at"),
            "last_used_at": marker.get("last_used_at"),
        }
    )
    if measure:
        files, size = directory_size(path)
        record.update({"files": files, "bytes": size})
    return record


def worktree_records(base: str, *, only_path: Path | None = None) -> list[dict[str, Any]]:
    processes = process_observation()
    output = git("worktree", "list", "--porcelain").stdout.splitlines()
    raw: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in [*output, ""]:
        if not line:
            if current:
                raw.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        current[key] = value
    records: list[dict[str, Any]] = []
    managed_root = development_layout.worktree_root(CONTROL_ROOT).resolve()
    for item in raw:
        path = Path(item["worktree"]).resolve()
        if only_path is not None and path != only_path.resolve():
            continue
        head = item.get("HEAD", "")
        branch = item.get("branch", "detached").removeprefix("refs/heads/")
        primary = path == CONTROL_ROOT
        managed = primary or path.is_relative_to(managed_root)
        owned = primary
        marker_error: str | None = None
        target_ref: str | None = base if primary else None
        if not primary and managed and branch != "detached":
            try:
                marker = development_layout.read_worktree_record(
                    CONTROL_ROOT, path, branch
                )
                owned = True
                target_ref = str(marker["target_ref"])
            except ValueError as exc:
                marker_error = str(exc)
        contained = primary or bool(
            target_ref
            and git("rev-parse", "--verify", f"{target_ref}^{{commit}}", check=False).returncode
            == 0
            and git(
                "merge-base", "--is-ancestor", head, target_ref, check=False
            ).returncode
            == 0
        )
        status = [] if not path.exists() else git(
            "-C", str(path), "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"
        ).stdout.splitlines()
        material = {} if primary else worktree_material(path, processes)
        branch_head_matches = primary or bool(
            branch != "detached"
            and git("rev-parse", "--verify", branch, check=False).returncode == 0
            and git("rev-parse", branch).stdout.strip() == head
        )
        locked = "locked" in item
        local_ready = bool(
            not primary
            and path.exists()
            and managed
            and owned
            and target_ref
            and contained
            and not status
            and branch_head_matches
            and not locked
            and branch != "detached"
            and material.get("material_checked")
            and not material.get("nested_repositories")
            and not material.get("contained_links")
            and not material.get("active_processes")
        )
        records.append(
            {
                "path": str(path),
                "head": head,
                "branch": branch,
                "primary": primary,
                "managed_location": managed,
                "owned": owned,
                "marker_error": marker_error,
                "declared_target": target_ref,
                "contained_in_target": contained,
                "contained_in_base": contained,
                "clean": not status,
                "status_entries": status,
                **material,
                "branch_head_matches": branch_head_matches,
                "locked": locked,
                "lock_reason": item.get("locked") or None,
                "local_retirement_ready": local_ready,
                "cleanup_eligible": False,
            }
        )
    return records


def retirement_record(record: dict[str, Any]) -> dict[str, Any]:
    observed = dict(record)
    reasons: list[str] = []
    if observed["primary"]:
        observed["retirement_reasons"] = ["primary_control_checkout"]
        return observed
    required = {
        "managed_location": "unmanaged_location",
        "owned": "missing_or_invalid_ownership_record",
        "clean": "dirty_worktree",
        "branch_head_matches": "branch_head_mismatch",
        "material_checked": "material_or_process_observation_incomplete",
    }
    for key, reason in required.items():
        if not observed.get(key):
            reasons.append(reason)
    if observed.get("locked"):
        reasons.append("worktree_locked")
    for key in ("nested_repositories", "contained_links", "active_processes"):
        if observed.get(key):
            reasons.append(key)
    if observed.get("branch") == "detached":
        reasons.append("detached_disposable_receipt_required")
    if Path(str(observed["path"])).resolve() == ROOT.resolve():
        reasons.append("active_command_worktree")
    if not observed.get("declared_target"):
        reasons.append("declared_target_missing")
    if not observed.get("contained_in_target"):
        reasons.append("head_not_contained_in_declared_target")
    if not Path(str(observed["path"])).exists():
        reasons.append("worktree_path_missing")
    pr_observation: dict[str, Any] | None = None
    if not reasons:
        try:
            pr_observation = github_pr_observation(
                str(observed["branch"]),
                str(observed["declared_target"]),
                str(observed["head"]),
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            reasons.append(f"github_pr_observation_failed:{exc}")
    if pr_observation is not None:
        if pr_observation["exact_merged_pr"] is None:
            reasons.append("exact_head_pr_not_merged_to_declared_target")
        if pr_observation["open_dependent_prs"]:
            reasons.append("open_dependent_pr_uses_branch_as_base")
    observed["github"] = pr_observation
    observed["no_unpushed_commit"] = bool(
        observed.get("contained_in_target")
        and pr_observation
        and pr_observation["exact_merged_pr"] is not None
    )
    observed["cleanup_eligible"] = not reasons
    observed["retirement_reasons"] = reasons or ["eligible"]
    return observed


def ref_records(base: str) -> dict[str, Any]:
    current = git("branch", "--show-current").stdout.strip()
    local_names = [
        line.strip()
        for line in git(
            "for-each-ref", "--format=%(refname:short)", "refs/heads"
        ).stdout.splitlines()
        if line.strip()
    ]
    remote_names = [
        line.strip()
        for line in git(
            "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"
        ).stdout.splitlines()
        if line.strip() and line.strip() not in {"origin", "origin/HEAD"}
    ]
    tags = [
        line.strip()
        for line in git("tag", "--list").stdout.splitlines()
        if line.strip()
    ]
    local: list[dict[str, Any]] = []
    for name in local_names:
        target = default_target_for_branch(name)
        effective_target = target or base
        target_exists = (
            git(
                "rev-parse",
                "--verify",
                f"{effective_target}^{{commit}}",
                check=False,
            ).returncode
            == 0
        )
        contained = bool(
            target_exists
            and git(
                "merge-base", "--is-ancestor", name, effective_target, check=False
            ).returncode
            == 0
        )
        task_like = target is not None
        local.append(
            {
                "name": name,
                "current": name == current,
                "core": name in {"main", "dev"},
                "declared_target": target,
                "contained_in_target": contained,
                "contained_in_base": contained,
                "cleanup_candidate": bool(
                    task_like
                    and name != current
                    and name not in {"main", "dev"}
                    and contained
                ),
                "forbidden_prefix": name.startswith(FORBIDDEN_BRANCH_PREFIXES),
            }
        )
    return {
        "current_branch": current or None,
        "local_branches": local,
        "remote_branches": remote_names,
        "tags": [
            {"name": name, "release_tag": bool(RELEASE_TAG.fullmatch(name))}
            for name in tags
        ],
    }


def command_paths(args: argparse.Namespace) -> int:
    task_id = development_layout.current_task_id(ROOT)
    payload = {
        "schema": "facman.development_layout.v1",
        "source_root": str(ROOT.resolve()),
        "control_source_root": str(CONTROL_ROOT),
        "development_base": str(development_layout.development_base()),
        "repository_root": str(development_layout.repository_root(ROOT)),
        "task_id": task_id,
        "task_root": str(development_layout.task_root(ROOT, task_id)),
        "worktree_root": str(development_layout.worktree_root(ROOT)),
        "retention_days": development_layout.DEFAULT_RETENTION_DAYS,
        "max_task_roots": development_layout.DEFAULT_MAX_TASK_ROOTS,
        "max_bytes": development_layout.DEFAULT_MAX_BYTES,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def memory_headroom() -> tuple[int, int]:
    if os.name == "nt":
        from ctypes import wintypes
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD),
                        *[(name, ctypes.c_ulonglong) for name in ("physical", "available", "commit", "commit_available", "virtual", "virtual_available", "extended")]]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise OSError("GlobalMemoryStatusEx failed")
        return status.available, status.commit_available
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, _, value = line.partition(":")
        values[name] = int(value.split()[0]) * 1024
    return values["MemAvailable"], max(0, values["CommitLimit"] - values["Committed_AS"])


def observation_roots(args: argparse.Namespace) -> list[str]:
    roots = list(args.extra_root or [])
    file = getattr(args, "extra_roots_file", None)
    if file:
        rows = json.loads(Path(file).read_text(encoding="utf-8-sig"))
        if not isinstance(rows, list):
            raise ValueError("extra roots receipt must contain an array")
        for row in rows:
            value = row if isinstance(row, str) else row.get("path") if isinstance(row, dict) else None
            if not isinstance(value, str) or not value:
                raise ValueError("extra roots receipt has an invalid path")
            roots.append(value)
    return roots


def resource_violations(storage: dict[str, Any], demand: int, ram: int, volumes: dict[str, int], available: tuple[int, int],
                        max_bytes: int, disk_reserve: int, ram_reserve: int) -> list[str]:
    reasons = []
    if demand <= 0 or ram <= 0:
        reasons.append("positive_disk_and_ram_estimates_required")
    if not storage["complete"]:
        reasons.append("storage_observation_incomplete")
    if storage["logical_bytes"] + demand > max_bytes:
        reasons.append("campaign_storage_quota_exceeded")
    # Charge the entire estimate to each affected volume, conservatively.
    if any(free < disk_reserve + demand for free in volumes.values()):
        reasons.append("volume_free_space_reserve_exhausted")
    if min(available) < ram_reserve + ram:
        reasons.append("ram_or_commit_reserve_exhausted")
    return reasons


@contextlib.contextmanager
def resource_lock(path: Path):
    """Kernel-released lock: one admitted heavy job, including across workers.

    A crashed runner leaves a harmless file, not a stale admission reservation.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("another resource-budgeted job is active") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def stop_owned_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass  # Non-console children still have the owned job/tree termination path.
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], check=True, capture_output=True)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


@contextlib.contextmanager
def owned_process_job(process: subprocess.Popen[bytes], ram_limit: int):
    """Windows Job Object also closes persistent build-server descendants."""
    if os.name != "nt":
        try:
            yield
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        return
    from ctypes import wintypes
    class BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t), ("max_working_set", ctypes.c_size_t),
                    ("active_processes", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                    ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("basic", BasicLimits), ("io", ctypes.c_ulonglong * 6),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        stop_owned_process(process)
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000 | 0x200  # KILL_ON_JOB_CLOSE | JOB_MEMORY
        limits.job_memory = ram_limit
        if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle, int(process._handle)):
            stop_owned_process(process)
            raise ctypes.WinError(ctypes.get_last_error())
        # Popen created the initial thread suspended. Assign before any child code
        # runs, so short-lived launchers cannot leave uncontained descendants.
        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("thread", wintypes.DWORD),
                        ("process", wintypes.DWORD), ("base_priority", wintypes.LONG),
                        ("delta_priority", wintypes.LONG), ("flags", wintypes.DWORD)]
        kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel.Thread32Next.argtypes = kernel.Thread32First.argtypes
        kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenThread.restype = wintypes.HANDLE
        kernel.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel.ResumeThread.restype = wintypes.DWORD
        snapshot = kernel.CreateToolhelp32Snapshot(4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        resumed = False
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = kernel.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.process == process.pid:
                    thread = kernel.OpenThread(2, False, entry.thread)
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if kernel.ResumeThread(thread) == 0xffffffff:
                            raise ctypes.WinError(ctypes.get_last_error())
                        resumed = True
                    finally:
                        kernel.CloseHandle(thread)
                    break
                found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snapshot)
        if not resumed:
            raise OSError("owned suspended child thread could not be resumed")
        yield
    finally:
        kernel.CloseHandle(handle)


def command_run(args: argparse.Namespace) -> int:
    base = development_layout.require_configured_development_base()
    command = args.program[1:] if args.program[:1] == ["--"] else args.program
    if not command:
        raise ValueError("run requires an executable and arguments after --")
    if args.max_bytes > development_layout.DEFAULT_MAX_BYTES or args.disk_reserve < DEFAULT_DISK_RESERVE or args.ram_reserve < DEFAULT_RAM_RESERVE:
        raise ValueError("campaign quota/reserves may not be weakened by a job")
    task_id = development_layout.current_task_id(ROOT)
    task_path = development_layout.default_task_root(ROOT, task_id)
    with resource_lock(base / ".resource-job.lock"):
        storage = storage_inventory(observation_roots(args))
        paths = [base, *[Path(root) for root in storage["roots"] if Path(root).exists()]]
        volumes = {str(Path(path).anchor): shutil.disk_usage(path).free for path in paths}
        available = memory_headroom()
        reasons = resource_violations(storage, args.disk_bytes, args.ram_bytes, volumes, available,
                                      args.max_bytes, args.disk_reserve, args.ram_reserve)
        if len([record for record in worktree_records(args.base) if not record["primary"]]) > DEFAULT_MAX_WORKTREES:
            reasons.append("secondary_worktree_limit_exceeded")
        if len(task_roots(CONTROL_ROOT)) + int(not task_path.exists()) > development_layout.DEFAULT_MAX_TASK_ROOTS:
            reasons.append("task_root_limit_exceeded")
        if reasons:
            print(json.dumps({"result": "refused", "reasons": reasons, "storage_bytes": storage["logical_bytes"], "volume_free_bytes": volumes,
                              "ram_available_bytes": available[0], "commit_available_bytes": available[1]}, sort_keys=True))
            return 2
        task = development_layout.ensure_task_root(task_path, CONTROL_ROOT, task_id)
        run = task / "runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S-%f")
        run.mkdir(parents=True)
        temporary = run / "tmp"
        cache = run / "cache"
        temporary.mkdir()
        cache.mkdir()
        env = {**os.environ, "FACMAN_DEV_ROOT": str(base), "FACMAN_TASK_ROOT": str(task),
               "TMP": str(temporary), "TEMP": str(temporary), "TMPDIR": str(temporary),
               "XDG_CACHE_HOME": str(cache), "PIP_CACHE_DIR": str(cache / "pip"),
               "CMAKE_BUILD_PARALLEL_LEVEL": "2", "PYTHONDONTWRITEBYTECODE": "1"}
        env["MSBUILDDISABLENODEREUSE"] = "1"
        receipt = {"schema": "facman.resource_job.v1", "command": command, "cwd": str(ROOT), "task_root": str(task),
                   "disk_estimate_bytes": args.disk_bytes, "ram_estimate_bytes": args.ram_bytes, "max_bytes": args.max_bytes,
                   "disk_reserve_bytes": args.disk_reserve, "ram_reserve_bytes": args.ram_reserve,
                   "started_at": development_layout.utc_now(), "state": "starting", "volume_free_before": volumes}
        receipt_path = run / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | 0x4) if os.name == "nt" else 0,
                                   start_new_session=os.name != "nt")
        receipt.update(pid=process.pid, state="running")
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        tail: deque[bytes] = deque(maxlen=32)  # At most 128 KiB, regardless of test duration.
        def read_log() -> None:
            assert process.stdout is not None
            while data := process.stdout.read(4096):
                tail.append(data)
        reader = threading.Thread(target=read_log, daemon=True)
        reader.start()
        reason = None
        job = contextlib.ExitStack()
        try:
            job.enter_context(owned_process_job(process, args.ram_bytes))
            while process.poll() is None:
                time.sleep(2)
                free = {str(Path(path).anchor): shutil.disk_usage(path).free for path in paths}
                growth = sum(max(0, volumes[volume] - value) for volume, value in free.items())
                available = memory_headroom()
                if growth > args.disk_bytes:
                    reason = "disk_estimate_exceeded"
                elif storage["logical_bytes"] + growth > args.max_bytes:
                    reason = "campaign_quota_exceeded"
                elif any(value < args.disk_reserve for value in free.values()) or min(available) < args.ram_reserve:
                    reason = "host_reserve_exhausted"
                if reason:
                    stop_owned_process(process)
                    break
        except (KeyboardInterrupt, OSError):
            reason = "runner_interrupted_or_observation_failed"
            stop_owned_process(process)
        finally:
            job.close()
            reader.join(timeout=5)
            if reader.is_alive():
                reason = reason or "child_log_stream_still_open"
            elif process.stdout is not None:
                process.stdout.close()
            (run / "last-output.log").write_bytes(b"".join(tail))
            success = process.returncode == 0 and reason is None
            if success:
                remove_tree(temporary)
                remove_tree(cache)
            receipt.update(state="passed" if success else "failed_or_cancelled", exit_code=process.returncode,
                           stop_reason=reason, ended_at=development_layout.utc_now(), disposable_output_retained=not success)
            receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"result": receipt["state"], "exit_code": process.returncode, "stop_reason": reason,
                          "receipt": str(receipt_path), "log": str(run / "last-output.log")}, sort_keys=True))
        return 0 if success else 1


def command_doctor(args: argparse.Namespace) -> int:
    if args.max_bytes > development_layout.DEFAULT_MAX_BYTES or args.max_task_roots > development_layout.DEFAULT_MAX_TASK_ROOTS or args.max_worktrees > DEFAULT_MAX_WORKTREES:
        raise ValueError("campaign limits may be tightened, not raised")
    roots = [
        task_root_record(path, measure=False)
        for path in task_roots(CONTROL_ROOT)
    ]
    worktrees = worktree_records(args.base)
    refs = ref_records(args.base)
    in_tree_outputs = [
        str((ROOT / name).resolve())
        for name in IN_TREE_OUTPUT_NAMES
        if (ROOT / name).exists()
    ]
    violations: list[str] = []
    if len(roots) > args.max_task_roots:
        violations.append(f"task_root_count_exceeds_{args.max_task_roots}")
    unowned = [record["path"] for record in roots if not record["owned"]]
    if unowned:
        violations.append("unowned_task_roots_present")
    if args.measure:
        storage = storage_inventory(observation_roots(args))
        total = storage["logical_bytes"]
        if total > args.max_bytes:
            violations.append(f"campaign_storage_bytes_exceed_{args.max_bytes}")
        if not storage["complete"]:
            violations.append("campaign_storage_observation_incomplete")
    else:
        total = None
        storage = None
    secondary = [record for record in worktrees if not record["primary"]]
    if len(secondary) > args.max_worktrees:
        violations.append(f"secondary_worktree_count_exceeds_{args.max_worktrees}")
    if any(not record["managed_location"] for record in secondary):
        violations.append("unmanaged_secondary_worktrees_present")
    if in_tree_outputs:
        violations.append("in_tree_output_roots_present")
    if any(record["cleanup_candidate"] for record in refs["local_branches"]):
        violations.append("merged_local_task_branches_present")
    if any(record["forbidden_prefix"] for record in refs["local_branches"]):
        violations.append("forbidden_permanent_branch_prefix_present")
    if any(not record["release_tag"] for record in refs["tags"]):
        violations.append("nonrelease_tags_present")
    payload = {
        "schema": "facman.workspace_hygiene_report.v1",
        "result": "pass" if not violations else "fail",
        "violations": violations,
        "task_roots": roots,
        "campaign_storage_bytes": total,
        "storage": storage,
        "worktrees": worktrees,
        "refs": refs,
        "in_tree_output_roots": in_tree_outputs,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not violations else 1


def parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("development marker has no last_used_at timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def command_clean(args: argparse.Namespace) -> int:
    current = development_layout.task_root(
        CONTROL_ROOT, development_layout.current_task_id(ROOT)
    ).resolve()
    active = {
        development_layout.task_root(CONTROL_ROOT, str(record["branch"])).resolve()
        for record in worktree_records("origin/main")
        if not record["primary"]
        and record["branch"] != "detached"
        and Path(str(record["path"])).exists()
    }
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.max_age_days)
    candidates: list[dict[str, Any]] = []
    for path in task_roots(CONTROL_ROOT):
        if is_reparse_or_link(path):
            candidates.append(
                {
                    "path": str(path.resolve()),
                    "eligible": False,
                    "reason": "linked_root_refused",
                }
            )
            continue
        marker = development_layout.read_marker(path, CONTROL_ROOT)
        eligible = parse_time(marker.get("last_used_at")) < cutoff
        reason = "expired" if eligible else "retained_recent"
        if path.resolve() in active:
            eligible = False
            reason = "retained_active_worktree"
        elif path.resolve() == current and not args.include_current:
            eligible = False
            reason = "retained_current"
        record = {"path": str(path.resolve()), "eligible": eligible, "reason": reason}
        if eligible and args.apply:
            development_layout.read_marker(path, CONTROL_ROOT)
            remove_tree(path)
            record["removed"] = True
        candidates.append(record)
    print(
        json.dumps(
            {
                "schema": "facman.workspace_hygiene_cleanup.v1",
                "mode": "apply" if args.apply else "plan",
                "candidates": candidates,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_worktrees(args: argparse.Namespace) -> int:
    records = [retirement_record(record) for record in worktree_records(args.base)]
    for record in records:
        if not record["cleanup_eligible"] or not args.apply:
            continue
        path = Path(str(record["path"]))
        if is_reparse_or_link(path):
            raise ValueError(f"refusing linked worktree: {path}")
        # Recheck local state and GitHub dependencies immediately before mutation.
        fresh = next((item for item in worktree_records(args.base, only_path=path) if item["path"] == str(path)), None)
        if fresh is None or fresh["head"] != record["head"] or not retirement_record(fresh)["cleanup_eligible"]:
            record["removed"] = False
            record["retirement_reasons"] = ["state_changed_before_removal"]
            continue
        branch = str(record["branch"])
        git("worktree", "remove", str(path))
        development_layout.remove_worktree_record(CONTROL_ROOT, branch)
        record["removed"] = True
    print(
        json.dumps(
            {
                "schema": "facman.workspace_hygiene_worktrees.v1",
                "mode": "apply" if args.apply else "plan",
                "fallback_base": args.base,
                "worktrees": records,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_worktree_add(args: argparse.Namespace) -> int:
    if args.max_worktrees > DEFAULT_MAX_WORKTREES:
        raise ValueError("secondary worktree limit may not be raised")
    base = development_layout.require_configured_development_base()
    with resource_lock(base / ".resource-job.lock"):
        storage = storage_inventory(observation_roots(args))
        volumes = {str(path.anchor): shutil.disk_usage(path).free for path in [base, *[Path(root) for root in storage["roots"] if Path(root).exists()]]}
        reasons = resource_violations(storage, 256 * 1024 ** 2, 128 * 1024 ** 2, volumes, memory_headroom(),
                                      development_layout.DEFAULT_MAX_BYTES, DEFAULT_DISK_RESERVE, DEFAULT_RAM_RESERVE)
        if reasons:
            raise ValueError("worktree admission refused: " + ", ".join(reasons))
        return admitted_worktree_add(args)


def admitted_worktree_add(args: argparse.Namespace) -> int:
    development_layout.require_configured_development_base()
    branch = args.branch.strip()
    target_ref = (args.target or default_target_for_branch(branch) or "").strip()
    start_ref = (args.start or default_start_for_branch(branch) or "").strip()
    supported = branch.startswith(tuple(DEFAULT_BRANCH_TARGETS)) or branch.startswith(
        "evidence/"
    )
    if not supported:
        raise ValueError(
            "managed worktree branches must use task/, release/, hotfix/, or evidence/"
        )
    if branch.startswith("evidence/") and not args.target:
        raise ValueError("evidence worktrees require an exact --target")
    if not target_ref:
        raise ValueError("managed worktree retirement target is required")
    if not start_ref:
        raise ValueError("managed worktree start ref is required")
    if git("check-ref-format", "--branch", branch, check=False).returncode:
        raise ValueError(f"invalid managed branch name: {branch}")
    if git("show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0:
        raise ValueError(f"local branch already exists: {branch}")
    git("rev-parse", "--verify", f"{start_ref}^{{commit}}")
    git("rev-parse", "--verify", f"{target_ref}^{{commit}}")
    secondary = [record for record in worktree_records(args.base) if not record["primary"]]
    if len(secondary) >= args.max_worktrees:
        raise ValueError(
            f"secondary worktree limit {args.max_worktrees} is already reached"
        )
    target = development_layout.canonical_worktree_path(CONTROL_ROOT, branch).resolve()
    managed_root = development_layout.ensure_worktree_store(CONTROL_ROOT)
    if not target.is_relative_to(managed_root) or target == managed_root:
        raise ValueError(f"managed worktree target escaped its root: {target}")
    if os.path.lexists(target):
        raise ValueError(f"managed worktree target already exists: {target}")
    git("worktree", "add", "-b", branch, str(target), start_ref)
    head = git("-C", str(target), "rev-parse", "HEAD").stdout.strip()
    record_path = development_layout.write_worktree_record(
        CONTROL_ROOT, target, branch, target_ref, head
    )
    print(
        json.dumps(
            {
                "schema": "facman.workspace_hygiene_worktree_add.v1",
                "branch": branch,
                "start": start_ref,
                "declared_target": target_ref,
                "path": str(target),
                "ownership_record": str(record_path),
                "max_worktrees": args.max_worktrees,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_worktree_register(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser().resolve()
    if path == CONTROL_ROOT:
        raise ValueError("the primary control checkout does not require registration")
    if is_reparse_or_link(path):
        raise ValueError(f"refusing linked worktree path: {path}")
    listed = {
        Path(str(record["path"])).resolve(): record
        for record in worktree_records(args.base)
    }
    if path not in listed:
        raise ValueError(f"path is not a registered Git worktree: {path}")
    observed = listed[path]
    branch = str(observed["branch"])
    if branch == "detached":
        raise ValueError("detached worktrees require a separate disposable receipt")
    target_ref = (args.target or default_target_for_branch(branch) or "").strip()
    if branch.startswith("evidence/") and not args.target:
        raise ValueError("evidence worktrees require an exact --target")
    if not target_ref:
        raise ValueError(f"no default retirement target exists for {branch}")
    git("rev-parse", "--verify", f"{target_ref}^{{commit}}")
    record_path = development_layout.write_worktree_record(
        CONTROL_ROOT,
        path,
        branch,
        target_ref,
        str(observed["head"]),
        acknowledge_existing_unowned_store=args.acknowledge_existing_unowned_store,
    )
    print(
        json.dumps(
            {
                "schema": "facman.workspace_hygiene_worktree_register.v1",
                "branch": branch,
                "declared_target": target_ref,
                "head": observed["head"],
                "path": str(path),
                "ownership_record": str(record_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def recognized_legacy_name(path: Path) -> bool:
    name = path.name.lower()
    return name in LEGACY_NAMES or name.startswith(LEGACY_PREFIXES)


def validate_legacy_path(
    path: Path,
    allowed_roots: list[Path],
    allow_filesystem_root: bool,
    *,
    allow_shared_prunable_root: bool = False,
) -> Path:
    unresolved = Path(os.path.abspath(path.expanduser()))
    if not os.path.lexists(unresolved):
        raise ValueError(f"legacy target does not exist: {unresolved}")
    if is_reparse_or_link(unresolved):
        raise ValueError(f"legacy target is a link or reparse point: {unresolved}")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"legacy target is not a directory: {resolved}")
    if is_reparse_or_link(resolved):
        raise ValueError(f"legacy target is a link or reparse point: {resolved}")
    protected = [ROOT.resolve(), Path.home().resolve()]
    if any(resolved == item or item.is_relative_to(resolved) for item in protected):
        raise ValueError(f"legacy target is protected or contains a protected root: {resolved}")
    accepted = False
    for allowed in allowed_roots:
        root = allowed.resolve(strict=True)
        if root == Path(root.anchor) and not allow_filesystem_root:
            raise ValueError(f"filesystem-root allowlist requires --allow-filesystem-root: {root}")
        if resolved != root and resolved.is_relative_to(root):
            accepted = True
            break
    if not accepted:
        raise ValueError(f"legacy target is outside the exact allowed roots: {resolved}")
    shared_prunable = (
        allow_shared_prunable_root
        and resolved.name.casefold() in SHARED_PRUNABLE_ROOT_NAMES
    )
    if not recognized_legacy_name(resolved) and not shared_prunable:
        raise ValueError(f"legacy target name is not recognized as disposable: {resolved}")
    return resolved


def command_legacy_clean(args: argparse.Namespace) -> int:
    if args.apply and not args.acknowledge_unowned:
        raise ValueError("--apply requires --acknowledge-unowned")
    allowed = [Path(value).expanduser() for value in args.allowed_root]
    if not args.path and not args.discover_direct_children:
        raise ValueError("provide --path or --discover-direct-children")
    targets = [
        validate_legacy_path(Path(value).expanduser(), allowed, args.allow_filesystem_root)
        for value in (args.path or [])
    ]
    errors: list[dict[str, str]] = []
    excluded = {value.casefold() for value in args.exclude_name}
    if args.discover_direct_children:
        for allowed_root in allowed:
            root = allowed_root.resolve(strict=True)
            if root == Path(root.anchor) and not args.allow_filesystem_root:
                raise ValueError(
                    f"filesystem-root allowlist requires --allow-filesystem-root: {root}"
                )
            for child in root.iterdir():
                if child.name.casefold() in excluded or not recognized_legacy_name(child):
                    continue
                try:
                    if is_reparse_or_link(child):
                        raise ValueError(
                            f"legacy target is a link or reparse point: {child}"
                        )
                    if not child.is_dir():
                        continue
                    targets.append(
                        validate_legacy_path(child, allowed, args.allow_filesystem_root)
                    )
                except (OSError, ValueError) as exc:
                    errors.append({"path": str(child), "error": str(exc)})
    targets = sorted(set(targets), key=lambda item: str(item).casefold())
    records: list[dict[str, Any]] = []
    for target in targets:
        record: dict[str, Any] = {"path": str(target), "removed": False}
        try:
            files, size, links = directory_inventory(target)
            record.update(
                {
                    "files": files,
                    "bytes": size,
                    "contained_reparse_points": [str(path) for path in links],
                }
            )
            if args.apply:
                remove_tree(target)
                record["removed"] = not os.path.lexists(target)
        except (OSError, ValueError) as exc:
            record["error"] = str(exc)
            errors.append({"path": str(target), "error": str(exc)})
        records.append(record)
    print(
        json.dumps(
            {
                "schema": "facman.workspace_hygiene_legacy_cleanup.v1",
                "mode": "apply" if args.apply else "plan",
                "acknowledged_unowned": args.acknowledge_unowned,
                "result": "pass" if not errors else "partial",
                "summary": {
                    "target_count": len(records),
                    "removed_count": sum(bool(record["removed"]) for record in records),
                    "file_count": sum(int(record.get("files", 0)) for record in records),
                    "bytes": sum(int(record.get("bytes", 0)) for record in records),
                    "error_count": len(errors),
                },
                "errors": errors,
                "targets": records,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not errors else 1


def command_legacy_prune(args: argparse.Namespace) -> int:
    if args.apply and not args.acknowledge_unowned:
        raise ValueError("--apply requires --acknowledge-unowned")
    allowed = [Path(value).expanduser() for value in args.allowed_root]
    root = validate_legacy_path(
        Path(args.path).expanduser(),
        allowed,
        args.allow_filesystem_root,
        allow_shared_prunable_root=True,
    )
    preserved = {value.casefold() for value in args.preserve_child_name}
    existing = {child.name.casefold() for child in root.iterdir()}
    missing = sorted(preserved - existing)
    if missing:
        raise ValueError(
            "preserved direct child does not exist: " + ", ".join(missing)
        )
    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for child in sorted(root.iterdir(), key=lambda item: item.name.casefold()):
        record: dict[str, Any] = {
            "path": str(child),
            "preserved": child.name.casefold() in preserved,
            "removed": False,
        }
        try:
            if is_reparse_or_link(child):
                raise ValueError(f"legacy child is a link or reparse point: {child}")
            if child.is_dir():
                files, size, links = directory_inventory(child)
                record.update(
                    {
                        "files": files,
                        "bytes": size,
                        "contained_reparse_points": [str(path) for path in links],
                    }
                )
                if args.apply and not record["preserved"]:
                    remove_tree(child)
            else:
                record.update({"files": 1, "bytes": child.stat().st_size})
                if args.apply and not record["preserved"]:
                    try:
                        child.unlink()
                    except PermissionError:
                        os.chmod(child, stat.S_IWRITE)
                        child.unlink()
            if args.apply and not record["preserved"]:
                record["removed"] = not os.path.lexists(child)
        except (OSError, ValueError) as exc:
            record["error"] = str(exc)
            errors.append({"path": str(child), "error": str(exc)})
        records.append(record)
    removable = [record for record in records if not record["preserved"]]
    payload = {
        "schema": "facman.workspace_hygiene_legacy_prune.v1",
        "mode": "apply" if args.apply else "plan",
        "result": "pass" if not errors else "partial",
        "root": str(root),
        "preserved_child_names": sorted(args.preserve_child_name),
        "summary": {
            "child_count": len(records),
            "preserved_count": len(records) - len(removable),
            "removable_count": len(removable),
            "removed_count": sum(bool(record["removed"]) for record in removable),
            "removable_bytes": sum(int(record.get("bytes", 0)) for record in removable),
            "error_count": len(errors),
        },
        "errors": errors,
        "children": records,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not errors else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Plan and apply bounded Universal Setup workspace hygiene"
    )
    commands = result.add_subparsers(dest="command", required=True)
    paths = commands.add_parser("paths", help="show the canonical portable development layout")
    paths.set_defaults(handler=command_paths)
    doctor = commands.add_parser("doctor", help="audit task roots, quotas, and Git worktrees")
    doctor.add_argument("--base", default="origin/main")
    doctor.add_argument("--measure", action="store_true")
    doctor.add_argument(
        "--max-task-roots",
        type=int,
        default=development_layout.DEFAULT_MAX_TASK_ROOTS,
    )
    doctor.add_argument("--max-worktrees", type=int, default=DEFAULT_MAX_WORKTREES)
    doctor.add_argument("--max-bytes", type=int, default=development_layout.DEFAULT_MAX_BYTES)
    doctor.add_argument("--extra-root", action="append", default=[], help="exact attributable legacy output root to include in observation")
    doctor.add_argument("--extra-roots-file", help="existing JSON array of exact legacy paths or inventory rows")
    doctor.set_defaults(handler=command_doctor)
    clean = commands.add_parser("clean", help="remove expired marker-owned task roots")
    clean.add_argument(
        "--max-age-days",
        type=int,
        default=development_layout.DEFAULT_RETENTION_DAYS,
    )
    clean.add_argument("--include-current", action="store_true")
    clean.add_argument("--apply", action="store_true")
    clean.set_defaults(handler=command_clean)
    worktrees = commands.add_parser(
        "worktrees", help="retire owned worktrees merged to their declared targets"
    )
    worktrees.add_argument("--base", default="origin/main")
    worktrees.add_argument("--apply", action="store_true")
    worktrees.set_defaults(handler=command_worktrees)
    add = commands.add_parser(
        "worktree-add", help="create one branch in the canonical worktree store"
    )
    add.add_argument("branch")
    add.add_argument("--start")
    add.add_argument("--target")
    add.add_argument("--base", default="origin/main", help=argparse.SUPPRESS)
    add.add_argument("--max-worktrees", type=int, default=DEFAULT_MAX_WORKTREES)
    add.add_argument("--extra-root", action="append", default=[])
    add.add_argument("--extra-roots-file")
    add.set_defaults(handler=command_worktree_add)
    register = commands.add_parser(
        "worktree-register",
        help="adopt one existing canonical worktree into the owned store",
    )
    register.add_argument("--path", required=True)
    register.add_argument("--target")
    register.add_argument("--base", default="origin/main", help=argparse.SUPPRESS)
    register.add_argument(
        "--acknowledge-existing-unowned-store", action="store_true"
    )
    register.set_defaults(handler=command_worktree_register)
    legacy = commands.add_parser(
        "legacy-clean", help="explicit one-time cleanup for unmarked old roots"
    )
    legacy.add_argument("--path", action="append")
    legacy.add_argument("--allowed-root", action="append", required=True)
    legacy.add_argument("--discover-direct-children", action="store_true")
    legacy.add_argument("--exclude-name", action="append", default=[])
    legacy.add_argument("--allow-filesystem-root", action="store_true")
    legacy.add_argument("--acknowledge-unowned", action="store_true")
    legacy.add_argument("--apply", action="store_true")
    legacy.set_defaults(handler=command_legacy_clean)
    prune = commands.add_parser(
        "legacy-prune", help="remove direct children from one explicit old root"
    )
    prune.add_argument("--path", required=True)
    prune.add_argument("--allowed-root", action="append", required=True)
    prune.add_argument("--preserve-child-name", action="append", default=[])
    prune.add_argument("--allow-filesystem-root", action="store_true")
    prune.add_argument("--acknowledge-unowned", action="store_true")
    prune.add_argument("--apply", action="store_true")
    prune.set_defaults(handler=command_legacy_prune)
    run = commands.add_parser("run", help="admit and monitor one resource-budgeted build/test command")
    run.add_argument("--base", default="origin/dev")
    run.add_argument("--disk-bytes", type=int, required=True)
    run.add_argument("--ram-bytes", type=int, required=True)
    run.add_argument("--max-bytes", type=int, default=development_layout.DEFAULT_MAX_BYTES)
    run.add_argument("--disk-reserve", type=int, default=DEFAULT_DISK_RESERVE)
    run.add_argument("--ram-reserve", type=int, default=DEFAULT_RAM_RESERVE)
    run.add_argument("--extra-root", action="append", default=[])
    run.add_argument("--extra-roots-file")
    run.add_argument("program", nargs=argparse.REMAINDER)
    run.set_defaults(handler=command_run)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError) as exc:
        print(f"workspace-hygiene: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
