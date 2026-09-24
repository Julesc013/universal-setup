# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Measure one isolated native lifecycle scenario in a child process."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time


def windows_peak_working_set(process: subprocess.Popen[str]) -> int | None:
    import ctypes
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("page_fault_count", wintypes.DWORD),
            ("peak_working_set_size", ctypes.c_size_t),
            ("working_set_size", ctypes.c_size_t),
            ("quota_peak_paged_pool_usage", ctypes.c_size_t),
            ("quota_paged_pool_usage", ctypes.c_size_t),
            ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
            ("quota_non_paged_pool_usage", ctypes.c_size_t),
            ("pagefile_usage", ctypes.c_size_t),
            ("peak_pagefile_usage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    library = ctypes.WinDLL("psapi", use_last_error=True)
    library.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD
    ]
    library.GetProcessMemoryInfo.restype = wintypes.BOOL
    if not library.GetProcessMemoryInfo(
        wintypes.HANDLE(process._handle), ctypes.byref(counters), counters.cb
    ):
        return None
    return int(counters.peak_working_set_size)


def filesystem_profile(path: Path) -> str:
    if os.name != "nt":
        return "host temporary filesystem (see platform and temporary_root)"
    import ctypes
    from ctypes import wintypes

    root = str(path.anchor)
    name = ctypes.create_unicode_buffer(256)
    serial = wintypes.DWORD()
    max_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    kind = ctypes.create_unicode_buffer(256)
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD,
    ]
    library.GetVolumeInformationW.restype = wintypes.BOOL
    if not library.GetVolumeInformationW(
        root, name, len(name), ctypes.byref(serial), ctypes.byref(max_component),
        ctypes.byref(flags), kind, len(kind)
    ):
        raise OSError(ctypes.get_last_error(), "cannot identify probe filesystem")
    return f"{root} {kind.value} serial={serial.value:08x}"


def source_identity() -> dict:
    root = Path(__file__).resolve().parents[1]
    def git(*args: str) -> str:
        result = subprocess.run(["git", *args], cwd=root, check=True,
                                capture_output=True, text=True)
        return result.stdout.strip()
    return {
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "working_tree_dirty": bool(git("status", "--porcelain")),
    }


def measure(binary: Path, operation: str, payload_bytes: int, entries: int, materialized: bool) -> dict:
    if not binary.is_file() or payload_bytes < 1 or entries < 1:
        raise ValueError("binary and positive scenario dimensions are required")
    command = [str(binary), "--memory-scenario", operation, str(payload_bytes), str(entries)]
    if materialized:
        command.append("materialized")
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sampled_peak = 0
    samples = 0
    if os.name == "nt":
        while process.poll() is None:
            value = windows_peak_working_set(process)
            if value is not None:
                sampled_peak = max(sampled_peak, value)
                samples += 1
            time.sleep(0.005)
        metric = "windows_peak_working_set_bytes"
        peak_bytes = sampled_peak
    else:
        import resource

        process.wait()
        observed = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        metric = "posix_child_maxrss_bytes"
        peak_bytes = int(observed if platform.system() == "Darwin" else observed * 1024)
        samples = 1
    stdout, stderr = process.communicate()
    elapsed_ms = round((time.monotonic() - started) * 1000)
    if process.returncode != 0 or not stdout.startswith("memory-scenario-pass ") or peak_bytes == 0:
        raise RuntimeError(
            f"scenario failed: exit={process.returncode} peak={peak_bytes} "
            f"stdout={stdout!r} stderr={stderr!r}"
        )
    return {
        "schema": "usk.lifecycle_memory_observation.v1",
        "operation": operation,
        "requested_payload_bytes": payload_bytes,
        "entries": entries,
        "source_kind": "materialized" if materialized else "streaming",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "platform": platform.platform(),
        "temporary_root": tempfile.gettempdir(),
        "filesystem_profile": filesystem_profile(Path(tempfile.gettempdir())),
        "source": source_identity(),
        "fixture": "usk_lifecycle_smoke memory_scenario v1; repeated x-byte source",
        "metric": metric,
        "peak_bytes": peak_bytes,
        "samples": samples,
        "elapsed_ms": elapsed_ms,
        "exit_code": process.returncode,
        "stdout": stdout.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("operation", choices=["install", "verify", "repair", "move", "update", "recovery"])
    parser.add_argument("payload_bytes", type=int)
    parser.add_argument("entries", type=int)
    parser.add_argument("--materialized", action="store_true")
    args = parser.parse_args()
    print(json.dumps(measure(args.binary, args.operation, args.payload_bytes, args.entries,
                             args.materialized),
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
