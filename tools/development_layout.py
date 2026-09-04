# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

MARKER_NAME = ".facman-development-root.v1.json"
MARKER_SCHEMA = "facman.development_root.v1"
WORKTREE_STORE_MARKER_NAME = ".facman-worktree-store.v1.json"
WORKTREE_STORE_SCHEMA = "facman.worktree_store.v1"
WORKTREE_RECORD_SCHEMA = "facman.worktree_record.v1"
WORKTREE_RECORD_DIRECTORY = ".records"
DEFAULT_RETENTION_DAYS = 7
DEFAULT_MAX_TASK_ROOTS = 8
DEFAULT_MAX_BYTES = 20 * 1024 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def control_source_root(source_root: Path) -> Path:
    resolved = source_root.expanduser().resolve()
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(resolved),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode:
        return resolved
    common = Path(completed.stdout.strip()).resolve()
    if common.name.casefold() == ".git":
        return common.parent.resolve()
    return resolved


def repository_key(source_root: Path) -> str:
    resolved = control_source_root(source_root)
    digest = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:12]
    name = slug(resolved.name, fallback="repository", limit=32)
    return f"{name}-{digest}"


def current_task_id(source_root: Path) -> str:
    for name in ("FACMAN_TASK_ID", "FACMAN_WORK_ITEM"):
        configured = os.environ.get(name, "").strip()
        if configured:
            return configured
    completed = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=source_root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    branch = completed.stdout.strip()
    if branch:
        return branch
    completed = subprocess.run(
        ["git", "rev-parse", "--short=12", "HEAD"],
        cwd=source_root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    revision = completed.stdout.strip() or "unknown"
    return f"detached-{revision}"


def slug(value: str, *, fallback: str = "local", limit: int = 64) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower()
    normalized = normalized or fallback
    if len(normalized) <= limit:
        return normalized
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{normalized[: limit - 11]}-{digest}"


def development_base() -> Path:
    configured = os.environ.get("FACMAN_DEV_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
        if local_app_data:
            return (Path(local_app_data) / "FacMan" / "Development").resolve()
    cache = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(cache).expanduser() if cache else Path.home() / ".cache"
    return (base / "facman" / "development").resolve()


def repository_root(source_root: Path) -> Path:
    return development_base() / "repositories" / repository_key(source_root)


def task_root(source_root: Path, task_id: str | None = None) -> Path:
    identity = task_id or current_task_id(source_root)
    return repository_root(source_root) / "tasks" / slug(identity)


def default_task_root(source_root: Path, task_id: str | None = None) -> Path:
    configured = os.environ.get("FACMAN_TASK_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return task_root(source_root, task_id)


def worktree_root(source_root: Path) -> Path:
    return repository_root(source_root) / "worktrees"


def canonical_worktree_path(source_root: Path, branch: str) -> Path:
    return worktree_root(source_root) / slug(branch)


def worktree_record_path(source_root: Path, branch: str) -> Path:
    digest = hashlib.sha256(branch.encode("utf-8")).hexdigest()[:10]
    name = f"{slug(branch, limit=48)}-{digest}.json"
    return worktree_root(source_root) / WORKTREE_RECORD_DIRECTORY / name


def ensure_worktree_store(
    source_root: Path, *, acknowledge_existing_unowned: bool = False
) -> Path:
    root = worktree_root(source_root).expanduser().resolve()
    source = control_source_root(source_root)
    if root == source or root.is_relative_to(source) or source.is_relative_to(root):
        raise ValueError(f"development worktree store overlaps source checkout: {root}")
    if root.exists() and not root.is_dir():
        raise ValueError(f"development worktree store is not a directory: {root}")
    marker = root / WORKTREE_STORE_MARKER_NAME
    if (
        root.exists()
        and not marker.is_file()
        and any(root.iterdir())
        and not acknowledge_existing_unowned
    ):
        raise ValueError(
            f"refusing unowned development worktree store with content: {root}"
        )
    root.mkdir(parents=True, exist_ok=True)
    now = utc_now()
    expected = {
        "schema": WORKTREE_STORE_SCHEMA,
        "owner": "facman-development",
        "kind": "worktree-store",
        "repository_key": repository_key(source),
        "source_root": str(source),
        "canonical_path": str(root),
    }
    created_at = now
    if marker.is_file():
        try:
            current = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid development worktree marker {marker}: {exc}") from exc
        for key, value in expected.items():
            if current.get(key) != value:
                raise ValueError(f"development worktree marker mismatch for {key}: {marker}")
        created_at = str(current.get("created_at", now))
    payload = {**expected, "created_at": created_at, "last_used_at": now}
    marker.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / WORKTREE_RECORD_DIRECTORY).mkdir(exist_ok=True)
    return root


def read_worktree_store(source_root: Path) -> Path:
    root = worktree_root(source_root).expanduser().resolve()
    source = control_source_root(source_root)
    marker = root / WORKTREE_STORE_MARKER_NAME
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid development worktree marker {marker}: {exc}") from exc
    expected = {
        "schema": WORKTREE_STORE_SCHEMA,
        "owner": "facman-development",
        "kind": "worktree-store",
        "repository_key": repository_key(source),
        "source_root": str(source),
        "canonical_path": str(root),
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise ValueError(f"development worktree marker mismatch for {key}: {marker}")
    return root


def write_worktree_record(
    source_root: Path,
    path: Path,
    branch: str,
    target_ref: str,
    registered_head: str,
    *,
    acknowledge_existing_unowned_store: bool = False,
) -> Path:
    root = ensure_worktree_store(
        source_root,
        acknowledge_existing_unowned=acknowledge_existing_unowned_store,
    )
    resolved = path.expanduser().resolve()
    if not branch.strip():
        raise ValueError("worktree branch must not be empty")
    if not registered_head.strip():
        raise ValueError("worktree registered head must not be empty")
    if not resolved.is_dir():
        raise ValueError(f"worktree path is not a directory: {resolved}")
    expected_path = canonical_worktree_path(source_root, branch).resolve()
    if resolved != expected_path or not resolved.is_relative_to(root):
        raise ValueError(f"worktree path is not canonical for {branch}: {resolved}")
    if not target_ref.strip():
        raise ValueError("worktree retirement target must not be empty")
    record_path = worktree_record_path(source_root, branch)
    now = utc_now()
    expected = {
        "schema": WORKTREE_RECORD_SCHEMA,
        "owner": "facman-development",
        "kind": "worktree",
        "repository_key": repository_key(source_root),
        "source_root": str(control_source_root(source_root)),
        "worktree_path": str(resolved),
        "branch": branch,
        "target_ref": target_ref,
    }
    created_at = now
    recorded_head = registered_head
    if record_path.is_file():
        try:
            current = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid worktree ownership record {record_path}: {exc}") from exc
        for key, value in expected.items():
            if current.get(key) != value:
                raise ValueError(f"worktree ownership record mismatch for {key}: {record_path}")
        created_at = str(current.get("created_at", now))
        recorded_head = str(current.get("registered_head", registered_head))
    payload = {
        **expected,
        "registered_head": recorded_head,
        "created_at": created_at,
        "last_observed_at": now,
    }
    record_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return record_path


def read_worktree_record(source_root: Path, path: Path, branch: str) -> dict[str, object]:
    root = read_worktree_store(source_root)
    record_path = worktree_record_path(source_root, branch)
    try:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid worktree ownership record {record_path}: {exc}") from exc
    expected = {
        "schema": WORKTREE_RECORD_SCHEMA,
        "owner": "facman-development",
        "kind": "worktree",
        "repository_key": repository_key(source_root),
        "source_root": str(control_source_root(source_root)),
        "worktree_path": str(path.expanduser().resolve()),
        "branch": branch,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise ValueError(f"worktree ownership record mismatch for {key}: {record_path}")
    resolved = path.expanduser().resolve()
    if not resolved.is_relative_to(root) or resolved != canonical_worktree_path(
        source_root, branch
    ).resolve():
        raise ValueError(f"worktree ownership record path is not canonical: {record_path}")
    target_ref = payload.get("target_ref")
    if not isinstance(target_ref, str) or not target_ref.strip():
        raise ValueError(f"worktree ownership record has no target ref: {record_path}")
    return payload


def remove_worktree_record(source_root: Path, branch: str) -> None:
    record_path = worktree_record_path(source_root, branch)
    record_path.unlink()


def ensure_task_root(path: Path, source_root: Path, task_id: str) -> Path:
    resolved = path.expanduser().resolve()
    source = control_source_root(source_root)
    if resolved == source or resolved.is_relative_to(source):
        raise ValueError(f"development task root must be outside source checkout: {resolved}")
    if source.is_relative_to(resolved):
        raise ValueError(f"development task root must not contain source checkout: {resolved}")
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"development task root is not a directory: {resolved}")
    marker = resolved / MARKER_NAME
    if resolved.exists() and not marker.is_file() and any(resolved.iterdir()):
        raise ValueError(f"refusing unowned development task root with content: {resolved}")
    resolved.mkdir(parents=True, exist_ok=True)
    now = utc_now()
    expected = {
        "schema": MARKER_SCHEMA,
        "owner": "facman-development",
        "kind": "task-root",
        "repository_key": repository_key(source),
        "source_root": str(source),
        "task_id": task_id,
    }
    created_at = now
    if marker.is_file():
        try:
            current = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid development ownership marker {marker}: {exc}") from exc
        for key, value in expected.items():
            if current.get(key) != value:
                raise ValueError(f"development ownership marker mismatch for {key}: {marker}")
        created_at = str(current.get("created_at", now))
    payload = {**expected, "created_at": created_at, "last_used_at": now}
    marker.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return resolved


def read_marker(path: Path, source_root: Path | None = None) -> dict[str, object]:
    marker = path.resolve() / MARKER_NAME
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid development ownership marker {marker}: {exc}") from exc
    if payload.get("schema") != MARKER_SCHEMA or payload.get("owner") != "facman-development":
        raise ValueError(f"unrecognized development ownership marker: {marker}")
    if payload.get("kind") != "task-root":
        raise ValueError(f"development marker does not authorize task-root cleanup: {marker}")
    if source_root is not None:
        source = control_source_root(source_root)
        expected = {
            "repository_key": repository_key(source),
            "source_root": str(source),
        }
        for key, value in expected.items():
            if payload.get(key) != value:
                raise ValueError(f"development ownership marker mismatch for {key}: {marker}")
        task_id = payload.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError(f"development ownership marker has no task identity: {marker}")
        expected_path = task_root(source, task_id).resolve()
        if path.resolve() != expected_path:
            raise ValueError(f"development ownership marker path mismatch: {marker}")
    return payload


