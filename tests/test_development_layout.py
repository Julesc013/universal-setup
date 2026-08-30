# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import development_layout, workspace_hygiene


class DevelopmentLayoutTests(unittest.TestCase):
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

    def test_explicit_task_root_overrides_portable_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            configured = Path(temporary) / "explicit-task"
            source.mkdir()
            with mock.patch.dict(
                "os.environ", {"FACMAN_TASK_ROOT": str(configured)}, clear=False
            ):
                self.assertEqual(
                    development_layout.default_task_root(source),
                    configured.resolve(),
                )

    def test_marker_refuses_existing_unowned_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            target = Path(temporary) / "target"
            source.mkdir()
            target.mkdir()
            (target / "unknown.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unowned development task root"):
                development_layout.ensure_task_root(target, source, "TASK-01")

    def test_marker_binds_repository_and_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            target = Path(temporary) / "target"
            source.mkdir()
            development_layout.ensure_task_root(target, source, "TASK-01")
            marker = json.loads(
                (target / development_layout.MARKER_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(marker["schema"], development_layout.MARKER_SCHEMA)
            self.assertEqual(marker["task_id"], "TASK-01")
            with self.assertRaisesRegex(ValueError, "marker mismatch"):
                development_layout.ensure_task_root(target, source, "TASK-02")

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
