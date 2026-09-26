# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import contextlib
import ctypes
import io
import json
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import development_layout, workspace_hygiene


class DevelopmentLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        # These fixtures select their own isolated development roots; the
        # parent runner's task binding belongs to the real campaign checkout.
        environment = mock.patch.dict(os.environ, {"FACMAN_TASK_ROOT": ""})
        environment.start()
        self.addCleanup(environment.stop)

    @contextlib.contextmanager
    def budgeted_fixture(self, base: Path, child: str, *, disk: int = 10485760):
        source = base / "source"
        source.mkdir()
        args = workspace_hygiene.parser().parse_args(["run", "--disk-bytes", str(disk), "--ram-bytes", "134217728", "--", sys.executable, "-c", child])
        with (mock.patch.dict(os.environ, {"FACMAN_DEV_ROOT": str(base / "development"), "FACMAN_TASK_ROOT": ""}),
              mock.patch.object(workspace_hygiene, "ROOT", source), mock.patch.object(workspace_hygiene, "CONTROL_ROOT", source),
              mock.patch.object(development_layout, "current_task_id", return_value="fixture"),
              mock.patch.object(workspace_hygiene, "memory_headroom", return_value=(100 * workspace_hygiene.GIB, 100 * workspace_hygiene.GIB)),
              mock.patch.object(workspace_hygiene, "worktree_records", return_value=[]),
              mock.patch.object(workspace_hygiene, "task_roots", return_value=[]),
              mock.patch.object(workspace_hygiene.shutil, "disk_usage", return_value=mock.Mock(free=100 * workspace_hygiene.GIB))):
            yield args

    def test_canonical_task_junction_refuses_without_writing_outside(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            outside = base / "outside"
            outside.mkdir()
            with mock.patch.dict(os.environ, {"FACMAN_DEV_ROOT": str(base / "development"), "FACMAN_TASK_ROOT": ""}):
                link = development_layout.task_root(base / "source", "fixture")
                link.parent.mkdir(parents=True)
                try:
                    link.symlink_to(outside, target_is_directory=True)
                except OSError:
                    if os.name != "nt":
                        self.skipTest("directory links unavailable")
                    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "New-Item -ItemType Junction -Path $env:FACMAN_TEST_LINK -Target $env:FACMAN_TEST_TARGET | Out-Null"],
                        env={**os.environ, "FACMAN_TEST_LINK": str(link), "FACMAN_TEST_TARGET": str(outside)}, check=True, capture_output=True)
                with self.assertRaisesRegex(ValueError, "crosses a link"):
                    development_layout.ensure_task_root(development_layout.default_task_root(base / "source", "fixture"), base / "source", "fixture")
                self.assertEqual(list(outside.iterdir()), [])

    def test_missing_process_command_line_refuses_retirement(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows CIM observation")
        rows = [{"pid": 0, "Name": "System Idle Process", "command": None},
                {"pid": 4, "Name": "System", "command": None},
                {"pid": 4321, "Name": "unknown.exe", "command": None}]
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(workspace_hygiene.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(rows))):
                observed = workspace_hygiene.process_observation()
            self.assertFalse(observed[0]["observation_unavailable"])
            self.assertFalse(observed[1]["observation_unavailable"])
            self.assertFalse(workspace_hygiene.worktree_material(Path(temporary), observed)["material_checked"])

    def test_headroom_loss_during_material_observation_prevents_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.budgeted_fixture(Path(temporary), "raise RuntimeError('must not launch')") as args:
                with (mock.patch.object(workspace_hygiene, "worktree_records", side_effect=lambda _base: []),
                      mock.patch.object(workspace_hygiene, "memory_headroom", side_effect=[(100 * workspace_hygiene.GIB,) * 2, (0, 0)]),
                      mock.patch.object(workspace_hygiene.subprocess, "Popen", wraps=subprocess.Popen) as launch,
                      contextlib.redirect_stdout(io.StringIO())):
                    self.assertEqual(workspace_hygiene.command_run(args), 2)
                    self.assertFalse(any(call.args[0][0] == sys.executable for call in launch.call_args_list))

    def test_fast_child_disk_growth_is_not_reported_as_passed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            child = "import os,pathlib; p=pathlib.Path(os.environ['TEMP'])/'rapid'; f=p.open('wb'); f.seek(2*1024*1024); f.write(b'x'); f.close()"
            with self.budgeted_fixture(Path(temporary), child, disk=1048576) as args:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(workspace_hygiene.command_run(args), 1)
                result = json.loads(output.getvalue())
                self.assertEqual(result["stop_reason"], "disk_estimate_exceeded")
                receipt = json.loads(Path(result["receipt"]).read_text())
                self.assertGreater(receipt["storage_bytes_after"], 1048576)
                self.assertTrue(receipt["disposable_output_retained"])

    def test_log_thread_setup_failure_reaps_owned_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.budgeted_fixture(Path(temporary), "import time; time.sleep(60)") as args:
                output = io.StringIO()
                spawned = []
                original_popen = subprocess.Popen
                def launch(*arguments, **keywords):
                    child = original_popen(*arguments, **keywords)
                    if arguments[0][0] == sys.executable:
                        spawned.append(child)
                    return child
                with (mock.patch.object(workspace_hygiene.subprocess, "Popen", side_effect=launch),
                      mock.patch.object(workspace_hygiene.threading.Thread, "start", side_effect=RuntimeError("injected setup failure")),
                      contextlib.redirect_stdout(output)):
                    self.assertEqual(workspace_hygiene.command_run(args), 1)
                self.assertEqual(len(spawned), 1)
                self.assertIsNotNone(spawned[0].poll())
                self.assertEqual(json.loads(output.getvalue())["stop_reason"], "runner_interrupted_or_observation_failed")

    def test_unrelated_prelaunch_consumption_cannot_hide_logical_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            child = "import os,pathlib; p=pathlib.Path(os.environ['TEMP'])/'rapid'; f=p.open('wb'); f.seek(2*1024*1024); f.write(b'x'); f.close()"
            with self.budgeted_fixture(Path(temporary), child, disk=1048576) as args:
                calls = 0
                def free(_path):
                    nonlocal calls
                    calls += 1
                    return mock.Mock(free=(100 if calls <= 2 else 99) * workspace_hygiene.GIB)
                output = io.StringIO()
                with (mock.patch.object(workspace_hygiene.shutil, "disk_usage", side_effect=free), contextlib.redirect_stdout(output)):
                    self.assertEqual(workspace_hygiene.command_run(args), 1)
                self.assertEqual(json.loads(output.getvalue())["stop_reason"], "disk_estimate_exceeded")

    def test_output_creation_requires_explicit_root(self) -> None:
        with mock.patch.dict(os.environ, {"FACMAN_DEV_ROOT": ""}):
            with self.assertRaisesRegex(ValueError, "FACMAN_DEV_ROOT is required"):
                development_layout.ensure_worktree_store(Path.cwd())

    def test_root_link_is_not_walked_or_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "unrelated"
            target.mkdir()
            (target / "preserve").write_text("user material")
            link = base / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                if os.name != "nt":
                    self.skipTest(f"symlink facility unavailable: {exc}")
                junction = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "New-Item -ItemType Junction -Path $env:FACMAN_TEST_LINK -Target $env:FACMAN_TEST_TARGET | Out-Null"],
                    env={**os.environ, "FACMAN_TEST_LINK": str(link), "FACMAN_TEST_TARGET": str(target)}, capture_output=True)
                if junction.returncode:
                    self.skipTest("neither symlink nor junction creation is available")
            self.assertEqual(workspace_hygiene.directory_inventory(link), (0, 0, [link]))
            with self.assertRaisesRegex(ValueError, "refusing recursive removal"):
                workspace_hygiene.remove_tree(link)
            with mock.patch.dict(os.environ, {"FACMAN_DEV_ROOT": str(link)}):
                with self.assertRaisesRegex(ValueError, "crosses a link"):
                    development_layout.ensure_worktree_store(base / "source")
            self.assertTrue((target / "preserve").is_file())

    def test_whole_store_inventory_counts_labs_builds_and_external_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            area = base / "area"
            legacy = base / "legacy"
            for directory, count in ((area / "tasks" / "task", 3), (area / "labs" / "vm", 17), (area / "build-one", 11), (legacy, 5)):
                directory.mkdir(parents=True)
                (directory / "payload").write_bytes(b"x" * count)
            with (mock.patch.object(development_layout, "repository_root", return_value=area),
                  mock.patch.object(workspace_hygiene, "CONTROL_ROOT", base / "source")):
                observed = workspace_hygiene.storage_inventory([str(legacy), str(area / "labs")])
            self.assertTrue(observed["complete"])
            self.assertEqual(observed["logical_bytes"], 36)  # Overlapping roots counted once.
            reasons = workspace_hygiene.resource_violations(observed, 1, 1, {"volume": 100}, (100, 100), 30, 10, 10)
            self.assertIn("campaign_storage_quota_exceeded", reasons)

    def test_ignored_source_and_nested_repository_refuse_retirement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
            (path / ".gitignore").write_text("ignored/\n")
            ignored = path / "ignored"
            ignored.mkdir()
            (ignored / "unique.py").write_text("print('preserve')\n")
            subprocess.run(["git", "init", str(ignored / "nested")], check=True, capture_output=True)
            observed = workspace_hygiene.worktree_material(path, [{"pid": 12345, "command": str(path / "writer.py")}])
            self.assertTrue(observed["nested_repositories"])
            self.assertEqual(observed["active_processes"], [12345])
            status = subprocess.run(["git", "-C", str(path), "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"], check=True, capture_output=True, text=True).stdout
            self.assertIn("!! ignored/", status)
            record = {"path": str(path), "head": "a" * 40, "branch": "task/test", "primary": False,
                      "managed_location": True, "owned": True, "declared_target": "origin/dev", "contained_in_target": True,
                      "branch_head_matches": True, "clean": not status, **observed}
            with mock.patch.object(workspace_hygiene, "github_pr_observation") as github:
                result = workspace_hygiene.retirement_record(record)
            self.assertFalse(result["cleanup_eligible"])
            github.assert_not_called()
            self.assertTrue((ignored / "unique.py").is_file())

    def test_concurrent_job_reservation_refuses_and_releases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock"
            with workspace_hygiene.resource_lock(path):
                with self.assertRaisesRegex(ValueError, "another resource-budgeted job"):
                    with workspace_hygiene.resource_lock(path):
                        self.fail("second job admitted")
            with workspace_hygiene.resource_lock(path):
                pass

    def test_low_resource_admission_refuses_each_reserve(self) -> None:
        storage = {"logical_bytes": 10, "complete": True}
        reasons = workspace_hygiene.resource_violations(storage, 20, 20, {"C": 29, "D": 100}, (29, 100), 100, 10, 10)
        self.assertIn("volume_free_space_reserve_exhausted", reasons)
        self.assertIn("ram_or_commit_reserve_exhausted", reasons)
        reasons = workspace_hygiene.resource_violations(storage, 0, 0, {"D": 100}, (100, 100), 100, 10, 10)
        self.assertIn("positive_disk_and_ram_estimates_required", reasons)

    def test_real_child_temp_is_contained_log_bounded_and_success_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            # Windows CI may spell TEMP through an 8.3 alias. Child output is
            # canonical; construct the expected descendants from the same root.
            base = Path(temporary).resolve(strict=True)
            source = base / "source"
            source.mkdir()
            storage = {"logical_bytes": 0, "complete": True, "roots": []}
            child = "import os,pathlib,json,subprocess,sys; server=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); p=pathlib.Path(os.environ['TEMP']); (p/'fixture').write_text('reproducible'); print('x'*300000); print(json.dumps({'tmp':str(p),'task':os.environ['FACMAN_TASK_ROOT'],'server_pid':server.pid}))"
            args = workspace_hygiene.parser().parse_args(["run", "--disk-bytes", "10485760", "--ram-bytes", "134217728", "--", sys.executable, "-c", child])
            output = io.StringIO()
            with (mock.patch.dict(os.environ, {"FACMAN_DEV_ROOT": str(base / "development"), "FACMAN_TASK_ROOT": ""}),
                  mock.patch.object(workspace_hygiene, "ROOT", source), mock.patch.object(workspace_hygiene, "CONTROL_ROOT", source),
                  mock.patch.object(development_layout, "current_task_id", return_value="fixture"),
                  mock.patch.object(workspace_hygiene, "storage_inventory", return_value=storage),
                  mock.patch.object(workspace_hygiene, "memory_headroom", return_value=(100 * workspace_hygiene.GIB, 100 * workspace_hygiene.GIB)),
                  mock.patch.object(workspace_hygiene, "worktree_records", return_value=[]),
                  mock.patch.object(workspace_hygiene, "task_roots", return_value=[]),
                  mock.patch.object(workspace_hygiene.shutil, "disk_usage", return_value=mock.Mock(free=100 * workspace_hygiene.GIB)),
                  contextlib.redirect_stdout(output)):
                self.assertEqual(workspace_hygiene.command_run(args), 0)
                first_result = json.loads(output.getvalue())
                output.seek(0)
                output.truncate()
                with (mock.patch.object(workspace_hygiene, "memory_headroom", return_value=(0, 0)),
                      mock.patch.object(workspace_hygiene.subprocess, "Popen", wraps=subprocess.Popen) as launch):
                    self.assertEqual(workspace_hygiene.command_run(args), 2)
                    self.assertFalse(any(call.args[0][0] == sys.executable for call in launch.call_args_list))
                self.assertIn("ram_or_commit_reserve_exhausted", json.loads(output.getvalue())["reasons"])
            result = first_result
            receipt = json.loads(Path(result["receipt"]).read_text())
            run = Path(result["receipt"]).parent
            self.assertLessEqual((run / "last-output.log").stat().st_size, 131072)
            child_paths = json.loads((run / "last-output.log").read_text().splitlines()[-1])
            self.assertTrue(Path(child_paths["tmp"]).is_relative_to(base / "development"),
                            {"actual": child_paths["tmp"], "expected_root": str(base / "development")})
            self.assertFalse((run / "tmp").exists())
            self.assertFalse(receipt["disposable_output_retained"])
            if os.name == "nt":
                from ctypes import wintypes
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                kernel.OpenProcess.restype = wintypes.HANDLE
                kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                server = kernel.OpenProcess(0x100000, False, child_paths["server_pid"])
                if server:
                    try:
                        self.assertEqual(kernel.WaitForSingleObject(server, 5000), 0)
                    finally:
                        kernel.CloseHandle(server)

    def test_linked_worktree_uses_control_checkout_repository_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "source"
            linked = Path(temporary) / "linked"
            repository.mkdir()
            subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "Fixture"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "fixture@example.invalid",
                ],
                check=True,
            )
            (repository / "tracked.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repository), "add", "tracked.txt"], check=True
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-m", "fixture"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "worktree",
                    "add",
                    "-b",
                    "task/fixture",
                    str(linked),
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(
                development_layout.control_source_root(linked), repository.resolve()
            )
            self.assertEqual(
                development_layout.repository_key(linked),
                development_layout.repository_key(repository),
            )

    def test_task_root_is_external_and_branch_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            external = Path(temporary) / "development"
            with mock.patch.dict("os.environ", {"FACMAN_DEV_ROOT": str(external)}, clear=False):
                first = development_layout.task_root(source, "task/alpha")
                second = development_layout.task_root(source, "task/beta")
            self.assertNotEqual(first, second)
            self.assertFalse(first.is_relative_to(source))
            self.assertTrue(first.is_relative_to(external.resolve()))

    def test_explicit_task_root_cannot_escape_canonical_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            configured = Path(temporary) / "explicit-task"
            source.mkdir()
            with mock.patch.dict(
                "os.environ", {"FACMAN_TASK_ROOT": str(configured), "FACMAN_DEV_ROOT": str(Path(temporary) / "development")}, clear=False
            ):
                with self.assertRaisesRegex(ValueError, "canonical task root"):
                    development_layout.default_task_root(source)

    def test_marker_refuses_existing_unowned_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            with mock.patch.dict("os.environ", {"FACMAN_DEV_ROOT": str(Path(temporary) / "development")}, clear=False):
                target = development_layout.task_root(source, "TASK-01")
                target.mkdir(parents=True)
                (target / "unknown.txt").write_text("preserve", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "unowned development task root"):
                    development_layout.ensure_task_root(target, source, "TASK-01")

    def test_marker_binds_repository_and_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            with mock.patch.dict("os.environ", {"FACMAN_DEV_ROOT": str(Path(temporary) / "development")}, clear=False):
                target = development_layout.task_root(source, "TASK-01")
                development_layout.ensure_task_root(target, source, "TASK-01")
                marker = json.loads((target / development_layout.MARKER_NAME).read_text(encoding="utf-8"))
                self.assertEqual(marker["schema"], development_layout.MARKER_SCHEMA)
                self.assertEqual(marker["task_id"], "TASK-01")
                marker["task_id"] = "substituted"
                (target / development_layout.MARKER_NAME).write_text(json.dumps(marker))
                with self.assertRaisesRegex(ValueError, "marker mismatch"):
                    development_layout.ensure_task_root(target, source, "TASK-01")

    def test_cleanup_marker_must_remain_at_its_canonical_task_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            external = Path(temporary) / "development"
            source.mkdir()
            with mock.patch.dict(
                "os.environ", {"FACMAN_DEV_ROOT": str(external)}, clear=False
            ):
                original = development_layout.task_root(source, "TASK-01")
                moved = development_layout.task_root(source, "TASK-02")
                development_layout.ensure_task_root(original, source, "TASK-01")
                original.rename(moved)
                with self.assertRaisesRegex(ValueError, "path mismatch"):
                    development_layout.read_marker(moved, source)

    def test_worktree_store_requires_explicit_adoption_of_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            external = Path(temporary) / "development"
            source.mkdir()
            with mock.patch.dict(
                "os.environ", {"FACMAN_DEV_ROOT": str(external)}, clear=False
            ):
                root = development_layout.worktree_root(source)
                (root / "task-existing").mkdir(parents=True)
                with self.assertRaisesRegex(ValueError, "unowned development worktree"):
                    development_layout.ensure_worktree_store(source)
                development_layout.ensure_worktree_store(
                    source, acknowledge_existing_unowned=True
                )
                self.assertTrue(
                    (root / development_layout.WORKTREE_STORE_MARKER_NAME).is_file()
                )

    def test_worktree_record_binds_canonical_path_branch_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            external = Path(temporary) / "development"
            source.mkdir()
            branch = "task/FACMAN-TEST-01"
            with mock.patch.dict(
                "os.environ", {"FACMAN_DEV_ROOT": str(external)}, clear=False
            ):
                development_layout.ensure_worktree_store(source)
                path = development_layout.canonical_worktree_path(source, branch)
                path.mkdir(parents=True)
                record_path = development_layout.write_worktree_record(
                    source,
                    path,
                    branch,
                    "origin/dev",
                    "a" * 40,
                )
                record = development_layout.read_worktree_record(
                    source, path, branch
                )
                self.assertEqual(record["target_ref"], "origin/dev")
                self.assertEqual(record["registered_head"], "a" * 40)
                self.assertTrue(record_path.is_file())
                with self.assertRaisesRegex(ValueError, "not canonical"):
                    development_layout.write_worktree_record(
                        source,
                        path,
                        "task/OTHER-01",
                        "origin/dev",
                        "b" * 40,
                    )

    def test_branch_classes_select_target_and_start_independently(self) -> None:
        self.assertEqual(
            workspace_hygiene.default_target_for_branch("task/example"),
            "origin/dev",
        )
        self.assertEqual(
            workspace_hygiene.default_target_for_branch("release/0.1"),
            "origin/main",
        )
        self.assertEqual(
            workspace_hygiene.default_start_for_branch("release/0.1"),
            "origin/dev",
        )
        self.assertEqual(
            workspace_hygiene.default_target_for_branch("hotfix/example"),
            "origin/main",
        )
        self.assertIsNone(
            workspace_hygiene.default_target_for_branch("evidence/example")
        )

    def test_retirement_requires_exact_merged_pr_and_no_dependents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            record = {
                "path": str(path),
                "head": "a" * 40,
                "branch": "task/example",
                "primary": False,
                "managed_location": True,
                "owned": True,
                "declared_target": "origin/dev",
                "contained_in_target": True,
                "clean": True,
                "material_checked": True,
                "branch_head_matches": True,
                "locked": False,
            }
            merged = {
                "repository": "owner/repository",
                "target_branch": "dev",
                "exact_merged_pr": {"number": 1},
                "open_dependent_prs": [],
            }
            with mock.patch.object(
                workspace_hygiene, "github_pr_observation", return_value=merged
            ):
                observed = workspace_hygiene.retirement_record(record)
            self.assertTrue(observed["cleanup_eligible"])
            self.assertTrue(observed["no_unpushed_commit"])

            merged["open_dependent_prs"] = [{"number": 2}]
            with mock.patch.object(
                workspace_hygiene, "github_pr_observation", return_value=merged
            ):
                observed = workspace_hygiene.retirement_record(record)
            self.assertFalse(observed["cleanup_eligible"])
            self.assertIn(
                "open_dependent_pr_uses_branch_as_base",
                observed["retirement_reasons"],
            )

    def test_worktree_apply_does_not_force_remove_or_prune(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            record = {
                "path": str(path),
                "head": "a" * 40,
                "branch": "task/example",
                "primary": False,
                "cleanup_eligible": True,
            }
            args = mock.Mock(apply=True, base="origin/main")
            output = io.StringIO()
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(
                    workspace_hygiene, "worktree_records", return_value=[record]
                ),
                mock.patch.object(
                    workspace_hygiene,
                    "retirement_record",
                    side_effect=lambda item: item,
                ),
                mock.patch.object(
                    workspace_hygiene, "git", return_value=completed
                ) as git_mock,
                mock.patch.object(
                    development_layout, "remove_worktree_record"
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(workspace_hygiene.command_worktrees(args), 0)
            git_mock.assert_called_once_with("worktree", "remove", str(path))

    def test_cleanup_retains_root_for_active_worktree_even_when_expired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            active_root = Path(temporary) / "active-root"
            active_root.mkdir()
            args = mock.Mock(max_age_days=7, include_current=False, apply=False)
            worktrees = [
                {
                    "primary": True,
                    "branch": "dev",
                    "path": str(Path(temporary) / "control"),
                },
                {
                    "primary": False,
                    "branch": "task/example",
                    "path": str(Path(temporary) / "linked-worktree"),
                },
            ]
            Path(worktrees[1]["path"]).mkdir()
            old_marker = {"last_used_at": "2000-01-01T00:00:00Z"}
            output = io.StringIO()
            with (
                mock.patch.object(
                    workspace_hygiene, "task_roots", return_value=[active_root]
                ),
                mock.patch.object(
                    workspace_hygiene, "worktree_records", return_value=worktrees
                ),
                mock.patch.object(
                    development_layout,
                    "task_root",
                    side_effect=lambda _root, task: (
                        active_root
                        if task == "task/example"
                        else Path(temporary) / "current-root"
                    ),
                ),
                mock.patch.object(
                    development_layout, "current_task_id", return_value="dev"
                ),
                mock.patch.object(
                    development_layout, "read_marker", return_value=old_marker
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(workspace_hygiene.command_clean(args), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(
                payload["candidates"][0]["reason"], "retained_active_worktree"
            )
            self.assertFalse(payload["candidates"][0]["eligible"])

    def test_legacy_cleanup_refuses_source_and_unrecognized_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed = Path(temporary)
            unknown = allowed / "important-project"
            unknown.mkdir()
            with self.assertRaisesRegex(ValueError, "not recognized as disposable"):
                workspace_hygiene.validate_legacy_path(unknown, [allowed], False)
            with self.assertRaisesRegex(ValueError, "protected"):
                workspace_hygiene.validate_legacy_path(
                    workspace_hygiene.ROOT,
                    [workspace_hygiene.ROOT.parent],
                    False,
                )

    def test_legacy_cleanup_requires_acknowledgement_before_apply(self) -> None:
        args = mock.Mock(
            apply=True,
            acknowledge_unowned=False,
            allowed_root=[],
            path=[],
            allow_filesystem_root=False,
        )
        with self.assertRaisesRegex(ValueError, "acknowledge-unowned"):
            workspace_hygiene.command_legacy_clean(args)

    def test_legacy_discovery_is_direct_recognized_and_excludable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed = Path(temporary)
            disposable = allowed / "usk-old-build"
            excluded = allowed / "USKPrivateRoute"
            unrelated = allowed / "important-project"
            disposable.mkdir()
            excluded.mkdir()
            unrelated.mkdir()
            args = mock.Mock(
                apply=False,
                acknowledge_unowned=False,
                allowed_root=[str(allowed)],
                path=[],
                discover_direct_children=True,
                exclude_name=[excluded.name],
                allow_filesystem_root=False,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(workspace_hygiene.command_legacy_clean(args), 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(
                [record["path"] for record in payload["targets"]],
                [str(disposable.resolve())],
            )

    def test_legacy_prune_preserves_named_direct_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed = Path(temporary)
            root = allowed / "usk-old-root"
            preserved = root / "USKRoute"
            disposable = root / "old-build"
            preserved.mkdir(parents=True)
            disposable.mkdir()
            (preserved / "input.zip").write_text("keep", encoding="utf-8")
            (disposable / "output.zip").write_text("remove", encoding="utf-8")
            args = mock.Mock(
                apply=True,
                acknowledge_unowned=True,
                allowed_root=[str(allowed)],
                path=str(root),
                preserve_child_name=[preserved.name],
                allow_filesystem_root=False,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(workspace_hygiene.command_legacy_prune(args), 0)
            self.assertTrue(preserved.is_dir())
            self.assertFalse(disposable.exists())

    def test_legacy_prune_refuses_a_missing_preservation_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            allowed = Path(temporary)
            root = allowed / "usk-old-root"
            disposable = root / "old-build"
            disposable.mkdir(parents=True)
            args = mock.Mock(
                apply=True,
                acknowledge_unowned=True,
                allowed_root=[str(allowed)],
                path=str(root),
                preserve_child_name=["USKRoute"],
                allow_filesystem_root=False,
            )
            with self.assertRaisesRegex(ValueError, "does not exist"):
                workspace_hygiene.command_legacy_prune(args)
            self.assertTrue(disposable.is_dir())


if __name__ == "__main__":
    unittest.main()
