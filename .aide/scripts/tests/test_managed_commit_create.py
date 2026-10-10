from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True

SOURCE = Path(__file__).resolve().parents[3]
CLI = SOURCE / ".aide/scripts/aide_lite.py"

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result

lite = module("aide_commit_fixture_lite", CLI)
managed = module("aide_commit_fixture_core", SOURCE / "core/apply/managed_commit.py")

class PublicGitFixture:
    """Public dummy Git data uses the authenticated existing fixture owner."""
    def __init__(self):
        self.context = lite.public_archive_fixture("aide-public-release-test-")
        self.name = self.context.__enter__()
        self.closed = False

    def __enter__(self):
        return self.name

    def __exit__(self, *exc):
        self.cleanup()

    def cleanup(self):
        if not self.closed:
            self.closed = True
            self.context.__exit__(None, None, None)


class ManagedCommitTests(unittest.TestCase):
    def setUp(self):
        self.temp = PublicGitFixture()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git("init", "-q", "-b", "task/fixture")
        self.git("config", "user.name", "AIDE fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.fsmonitor", "false")
        (self.root / "one.txt").write_text("base\n", encoding="utf-8")
        self.git("add", "one.txt")
        self.git("commit", "-qm", "fixture baseline")
        self.parent = self.git("rev-parse", "HEAD").strip()
        (self.root / "one.txt").write_text("staged\n", encoding="utf-8")
        self.git("add", "one.txt")
        self.tree = self.git("write-tree").strip()
        self.message = (lite.COMMIT_GOOD_EXAMPLE.rstrip("\n") + "\n").encode("utf-8")
        self.options = dict(
            message=self.message,
            expected_message_sha256=hashlib.sha256(self.message).hexdigest(),
            expected_ref="refs/heads/task/fixture", expected_head=self.parent,
            expected_tree=self.tree, allowed_paths=["one.txt"],
            validator=lambda text: [c.message for c in lite.validate_commit_message_text(text)
                                    if c.severity == "FAIL"], apply=True,
        )
        self.index = self.root / ".git/index"
        self.index_before = self.index.read_bytes()

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.root, capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        if result.returncode:
            self.fail("fixture Git failed: " + result.stderr)
        return result.stdout

    def create(self, **overrides):
        return managed.create_commit(self.root, **{**self.options, **overrides})

    def assert_refused(self, result, reason=""):
        self.assertEqual("REFUSED", result["status"], result)
        self.assertEqual(self.parent, self.git("rev-parse", "HEAD").strip())
        self.assertEqual(self.index_before, self.index.read_bytes())
        if reason:
            self.assertIn(reason, result["reason"])

    def test_invalid_message_creates_no_object_or_ref(self):
        objects_before = self.git("count-objects", "-v")
        bad = b"update\n"
        self.assert_refused(self.create(message=bad,
            expected_message_sha256=hashlib.sha256(bad).hexdigest()), "strict checks")
        self.assertEqual(objects_before, self.git("count-objects", "-v"))
        self.assertFalse((self.root / ".git/index.lock").exists())

    def test_dry_run_has_no_candidate_or_ref_effect(self):
        result = self.create(apply=False)
        self.assertEqual("DRY_RUN", result["status"])
        self.assertEqual("", result["candidate_commit"])
        self.assertEqual(self.parent, self.git("rev-parse", "HEAD").strip())
        self.assertEqual(self.index_before, self.index.read_bytes())

    def test_success_exact_object_and_unstaged_bytes_preserved(self):
        (self.root / "one.txt").write_text("later unstaged\n", encoding="utf-8")
        result = self.create()
        self.assertEqual("COMMITTED", result["status"], result)
        candidate = self.git("rev-parse", "HEAD").strip()
        self.assertEqual(result["candidate_commit"], candidate)
        raw = subprocess.check_output(["git", "cat-file", "commit", candidate], cwd=self.root)
        headers, body = raw.split(b"\n\n", 1)
        self.assertEqual(self.message, body)
        self.assertIn(b"tree " + self.tree.encode(), headers.splitlines())
        self.assertEqual([b"parent " + self.parent.encode()],
                         [p for p in headers.splitlines() if p.startswith(b"parent ")])
        self.assertEqual(self.index_before, self.index.read_bytes())
        self.assertEqual("later unstaged\n", (self.root / "one.txt").read_text())
        self.assertFalse((self.root / ".git/index.lock").exists())

    def test_message_digest_refuses_changed_input(self):
        self.assert_refused(self.create(expected_message_sha256="0" * 64), "digest")

    def test_expected_parent_refuses_stale_head(self):
        self.assert_refused(self.create(expected_head="f" * 40), "expected parent")

    def test_expected_tree_refuses_changed_stage(self):
        old = self.git("rev-parse", "HEAD^{tree}").strip()
        self.assert_refused(self.create(expected_tree=old), "staged tree")

    def test_ref_mismatch_refuses(self):
        self.assert_refused(self.create(expected_ref="refs/heads/task/other"), "expected ref")

    def test_extra_staged_path_refuses(self):
        self.assert_refused(self.create(allowed_paths=["other.txt"]), "scope")

    def test_rename_requires_both_declared_paths(self):
        self.git("mv", "one.txt", "renamed.txt")
        self.index_before = self.index.read_bytes()
        self.tree = self.git("write-tree").strip()
        self.index_before = self.index.read_bytes()
        self.assert_refused(self.create(expected_tree=self.tree,
                            allowed_paths=["renamed.txt"]), "scope")

    def stage_hidden_gitlink(self):
        self.git("update-index", "--add", "--cacheinfo", "160000," + self.parent + ",hidden-sub")
        self.git("config", "diff.ignoreSubmodules", "all")
        self.index_before = self.index.read_bytes()
        tree = self.git("write-tree").strip()
        self.index_before = self.index.read_bytes()
        return tree

    def test_hidden_gitlink_cannot_evade_exact_tree(self):
        self.stage_hidden_gitlink()
        self.assert_refused(self.create(allowed_paths=["one.txt", "hidden-sub"]), "staged tree")

    def test_hidden_gitlink_cannot_evade_path_scope(self):
        tree = self.stage_hidden_gitlink()
        self.assert_refused(self.create(expected_tree=tree), "scope")

    def test_declared_gitlink_can_commit_exact_tree(self):
        tree = self.stage_hidden_gitlink()
        result = self.create(expected_tree=tree, allowed_paths=["one.txt", "hidden-sub"])
        self.assertEqual("COMMITTED", result["status"], result)
        self.assertEqual(tree, self.git("rev-parse", "HEAD^{tree}").strip())
        self.assertEqual(self.index_before, self.index.read_bytes())

    def test_non_relative_scope_refuses(self):
        self.assert_refused(self.create(allowed_paths=["../one.txt"]), "relative")

    def test_short_object_identity_refuses(self):
        self.assert_refused(self.create(expected_head=self.parent[:8]), "full object")

    def test_existing_lock_preserved(self):
        lock = self.root / ".git/index.lock"
        lock.write_bytes(b"another owner")
        self.assert_refused(self.create(), "lock already exists")
        self.assertEqual(b"another owner", lock.read_bytes())

    def test_active_hook_refused_without_execution_or_reconfiguration(self):
        hook = self.root / ".git/hooks/commit-msg"
        hook.write_text("#!/bin/sh\necho reached > hook-ran\n", encoding="utf-8")
        hook.chmod(0o755)
        self.assert_refused(self.create(), "active Git hook")
        self.assertFalse((self.root / "hook-ran").exists())
        self.assertIn("echo reached", hook.read_text())

    def test_signing_refused_without_changing_configuration(self):
        self.git("config", "commit.gpgsign", "true")
        self.assert_refused(self.create(), "signing")
        self.assertEqual("true", self.git("config", "--bool", "--get", "commit.gpgsign").strip())

    def test_merge_state_refused(self):
        (self.root / ".git/MERGE_HEAD").write_text(self.parent + "\n")
        self.assert_refused(self.create(), "non-normal")

    def test_git_redirection_refused(self):
        with patch.dict(os.environ, {"GIT_INDEX_FILE": "outside-index"}):
            result = self.create()
        self.assert_refused(result, "redirection")

    def runtime_config(self, entries, count=None):
        context = patch.dict(os.environ)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        for name in list(os.environ):
            if name == "GIT_CONFIG_COUNT" or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                del os.environ[name]
        os.environ["GIT_CONFIG_COUNT"] = str(len(entries) if count is None else count)
        for index, (key, value) in enumerate(entries):
            os.environ[f"GIT_CONFIG_KEY_{index}"] = key
            os.environ[f"GIT_CONFIG_VALUE_{index}"] = value
        return context

    def test_runner_null_global_pair_preserved_and_succeeds(self):
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}):
            before = dict(os.environ)
            result = self.create()
            self.assertEqual("COMMITTED", result["status"], result)
            self.assertEqual(before, dict(os.environ))

    @unittest.skipUnless(os.name == "nt", "Windows null-device spelling")
    def test_windows_null_device_case_preserves_setting(self):
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull.upper(), "GIT_CONFIG_NOSYSTEM": "1"}):
            result = self.create()
            self.assertEqual("COMMITTED", result["status"], result)
            self.assertEqual(os.devnull.upper(), os.environ["GIT_CONFIG_GLOBAL"])

    def test_arbitrary_global_config_override_refused(self):
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": "outside-config", "GIT_CONFIG_NOSYSTEM": "1"}):
            result = self.create()
        self.assert_refused(result, "config isolation")

    def test_partial_runner_config_isolation_refused(self):
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull}):
            os.environ.pop("GIT_CONFIG_NOSYSTEM", None)
            result = self.create()
        self.assert_refused(result, "config isolation")

    def test_runtime_safe_directory_preserved_and_succeeds(self):
        self.runtime_config([("safe.directory", str(self.root))])
        before = dict(os.environ)
        result = self.create()
        self.assertEqual("COMMITTED", result["status"], result)
        self.assertEqual(before, dict(os.environ))
        self.assertEqual(self.tree, self.git("rev-parse", "HEAD^{tree}").strip())

    def test_runtime_unsupported_configuration_refused(self):
        self.runtime_config([("core.hooksPath", "outside-hooks")])
        self.assert_refused(self.create(), "runtime Git configuration")
        self.assertEqual("outside-hooks", os.environ["GIT_CONFIG_VALUE_0"])

    def test_runtime_malformed_configuration_refused(self):
        for count in ("invalid", 17, 1):
            with self.subTest(count=count):
                context = self.runtime_config([], count=count)
                result = self.create()
                context.__exit__(None, None, None)
                self.assert_refused(result, "runtime Git configuration")

    def test_runtime_count_missing_refuses_remaining_pairs(self):
        context = self.runtime_config([("safe.directory", str(self.root))])
        del os.environ["GIT_CONFIG_COUNT"]
        result = self.create()
        context.__exit__(None, None, None)
        self.assert_refused(result, "lack a count")

    def test_runtime_unexpected_indices_refused(self):
        context = self.runtime_config([("safe.directory", str(self.root))])
        os.environ["GIT_CONFIG_KEY_2"] = "safe.directory"
        os.environ["GIT_CONFIG_VALUE_2"] = "unused"
        result = self.create()
        context.__exit__(None, None, None)
        self.assert_refused(result, "declared count")

    def test_git_config_file_redirection_refused(self):
        with patch.dict(os.environ, {"GIT_CONFIG": "outside-config"}):
            result = self.create()
        self.assert_refused(result, "redirection")

    def test_runtime_settings_rechecked_before_each_git_call(self):
        original = managed._git
        def intercept(root, *args, **kw):
            if args[0] == "commit-tree":
                self.runtime_config([("core.hooksPath", "changed-hooks")])
            return original(root, *args, **kw)
        with patch.object(managed, "_git", side_effect=intercept):
            self.assert_refused(self.create(), "runtime Git configuration")

    def test_owned_lock_exact_lf_bytes_verified_and_retired(self):
        lock = self.index.with_name("index.lock")
        with managed._index_lock(self.index) as verify:
            data = lock.read_bytes()
            self.assertTrue(data.startswith(b"AIDE managed commit "))
            self.assertTrue(data.endswith(b"\n"))
            self.assertNotIn(b"\r", data)
            self.assertEqual(len(data), lock.stat().st_size)
            verify()
        self.assertFalse(lock.exists())
        self.assertEqual(self.index_before, self.index.read_bytes())

    def test_owned_lock_blocks_cooperating_git_staging(self):
        original = managed._git
        observed = []
        def intercept(root, *args, **kw):
            if args[0] == "commit-tree":
                (self.root / "other.txt").write_text("outside staged scope\n")
                p = subprocess.run(["git", "add", "other.txt"], cwd=self.root, capture_output=True)
                observed.append(p.returncode)
            return original(root, *args, **kw)
        with patch.object(managed, "_git", side_effect=intercept):
            result = self.create()
        self.assertEqual("COMMITTED", result["status"], result)
        self.assertEqual(1, len(observed))
        self.assertNotEqual(0, observed[0])
        self.assertEqual("", self.git("ls-files", "other.txt").strip())

    def test_created_wrong_object_cannot_advance_branch(self):
        original = managed._git
        def intercept(root, *args, **kw):
            if args[0] == "commit-tree":
                return (self.parent + "\n").encode("ascii")
            return original(root, *args, **kw)
        with patch.object(managed, "_git", side_effect=intercept):
            self.assert_refused(self.create(), "created commit object")

    def test_changed_lock_preserved_before_ref_advance(self):
        original = managed._git
        def intercept(root, *args, **kw):
            result = original(root, *args, **kw)
            if args[0] == "commit-tree":
                (self.root / ".git/index.lock").write_bytes(b"changed owner")
            return result
        with patch.object(managed, "_git", side_effect=intercept):
            self.assert_refused(self.create(), "owned index lock changed")
        self.assertEqual(b"changed owner", (self.root / ".git/index.lock").read_bytes())

    def test_head_switch_is_not_silently_followed(self):
        original = managed._advance_ref
        self.git("branch", "other", self.parent)
        def intercept(root, *args, **kw):
            self.git("symbolic-ref", "HEAD", "refs/heads/other")
            return original(root, *args, **kw)
        with patch.object(managed, "_advance_ref", side_effect=intercept):
            result = self.create()
        self.assertEqual("UNCERTAIN", result["status"], result)
        self.assertEqual(self.parent, self.git("rev-parse", "refs/heads/task/fixture").strip())
        self.assertEqual("refs/heads/other", self.git("symbolic-ref", "HEAD").strip())
        self.assertEqual(self.parent, self.git("rev-parse", "refs/heads/other").strip())

    def test_prepared_git_locks_block_branch_and_head_changes(self):
        original = managed._prepared_inputs
        self.git("branch", "other", self.parent)
        observed = []
        def intercept(root, *args, **kw):
            for command in (("symbolic-ref", "HEAD", "refs/heads/other"),
                            ("update-ref", "refs/heads/task/fixture", self.parent)):
                result = subprocess.run(["git", *command], cwd=self.root,
                                        capture_output=True, timeout=30)
                observed.append(result.returncode)
            return original(root, *args, **kw)
        with patch.object(managed, "_prepared_inputs", side_effect=intercept):
            result = self.create()
        self.assertEqual("COMMITTED", result["status"], result)
        self.assertTrue(all(observed), observed)
        self.assertEqual(2, len(observed))
        self.assertEqual("refs/heads/task/fixture", self.git("symbolic-ref", "HEAD").strip())
        self.assertEqual(result["candidate_commit"], self.git("reflog", "-1", "--format=%H", "HEAD").strip())
        self.assertEqual(result["candidate_commit"], self.git("reflog", "-1", "--format=%H", "refs/heads/task/fixture").strip())

    def test_prepared_input_refusal_aborts_without_ref_change(self):
        with patch.object(managed, "_prepared_inputs", side_effect=managed.CommitRefusal("fixture prepared refusal")):
            result = self.create()
        self.assertEqual("UNCERTAIN", result["status"], result)
        self.assertEqual(self.parent, self.git("rev-parse", "HEAD").strip())
        self.assertFalse((self.root / ".git/HEAD.lock").exists())
        self.assertFalse((self.root / ".git/refs/heads/task/fixture.lock").exists())
        self.assertFalse((self.root / ".git/index.lock").exists())

    def test_unproven_git_reaping_preserves_owned_index_lock(self):
        original = subprocess.Popen
        def intercepted(*args, **kw):
            process = original(*args, **kw)
            if args[0][:2] == ["git", "update-ref"]:
                wait = process.wait
                def lost_wait_ack(timeout=None):
                    wait(timeout=timeout)  # Reap the real fixture child first.
                    raise subprocess.TimeoutExpired("fixture lost Git wait acknowledgement", timeout)
                process.wait = lost_wait_ack
            return process
        with patch.object(managed.subprocess, "Popen", side_effect=intercepted):
            result = self.create()
        self.assertEqual("UNCERTAIN", result["status"], result)
        self.assertIsNone(result["branch_advanced"])
        self.assertIn("reaping unproven", result["reason"])
        self.assertEqual(result["candidate_commit"], self.git("rev-parse", "HEAD").strip())
        self.assertNotEqual(self.parent, result["candidate_commit"])
        self.assertTrue((self.root / ".git/index.lock").exists())
        self.assertTrue(result["candidate_commit"])

    def test_symbolic_expected_branch_refused(self):
        self.git("symbolic-ref", "refs/heads/task/alias", "refs/heads/task/fixture")
        self.git("symbolic-ref", "HEAD", "refs/heads/task/alias")
        self.assert_refused(self.create(expected_ref="refs/heads/task/alias"), "direct ref")

    @unittest.skipUnless(os.name == "nt" and os.environ.get("AIDE_JOB_ID"), "requires authenticated Windows job")
    def test_public_fixture_bounded_active_read_retry(self):
        from core.execution import managed_workspace as owner
        original = owner.read_json
        active = Path(os.environ["AIDE_JOB_CONTROL"]) / "active.json"
        denials = []
        def intercept(path):
            if Path(path) == active and len(denials) < 2:
                denials.append(str(path))
                raise PermissionError(13, "fixture metadata read window", str(path))
            return original(path)
        with patch.object(owner, "read_json", side_effect=intercept):
            with lite.public_archive_fixture("aide-public-release-test-") as directory:
                allocated = Path(directory)
                self.assertTrue(allocated.is_dir())
        self.assertEqual(2, len(denials))
        self.assertFalse(allocated.exists())

    @unittest.skipUnless(os.name == "nt" and os.environ.get("AIDE_JOB_ID"), "requires authenticated Windows job")
    def test_public_fixture_persistent_active_denial_fails_closed(self):
        from core.execution import managed_workspace as owner
        active = Path(os.environ["AIDE_JOB_CONTROL"]) / "active.json"
        parent = Path(os.environ["AIDE_JOB_TMP"])
        before = set(parent.iterdir())
        with patch.object(owner, "read_json", side_effect=PermissionError(13, "fixture persistent denial", str(active))) as read:
            with self.assertRaises(PermissionError):
                with lite.public_archive_fixture("aide-public-release-test-"):
                    self.fail("denied metadata must not allocate a fixture")
        self.assertEqual(3, read.call_count)
        self.assertEqual(before, set(parent.iterdir()))

    @unittest.skipUnless(os.name == "nt" and os.environ.get("AIDE_JOB_ID"), "requires authenticated Windows job")
    def test_public_fixture_other_permission_error_has_no_retry(self):
        from core.execution import managed_workspace as owner
        with patch.object(owner, "read_json", side_effect=PermissionError(13, "unrelated dummy denial", "other-dummy-record")) as read:
            with self.assertRaises(PermissionError):
                with lite.public_archive_fixture("aide-public-release-test-"):
                    self.fail("unrelated denied path must not allocate a fixture")
        self.assertEqual(1, read.call_count)

    @unittest.skipUnless(os.name == "nt" and os.environ.get("AIDE_JOB_ID"), "requires authenticated Windows job")
    def test_public_fixture_retries_authentication_read_then_authenticates(self):
        from core.execution import managed_workspace as owner
        original = owner.current_context
        active = Path(os.environ["AIDE_JOB_CONTROL"]) / "active.json"
        calls = []
        def intercept(root):
            calls.append(root)
            if len(calls) == 1:
                raise PermissionError(13, "fixture authentication read window", str(active))
            return original(root)
        with patch.object(owner, "current_context", side_effect=intercept):
            with lite.public_archive_fixture("aide-public-release-test-") as directory:
                self.assertTrue(Path(directory).is_dir())
        self.assertEqual(2, len(calls))

    @unittest.skipUnless(os.name == "nt" and os.environ.get("AIDE_JOB_ID"), "requires authenticated Windows job")
    def test_public_fixture_authentication_refusal_has_no_retry_or_allocation(self):
        from core.execution import managed_workspace as owner
        parent = Path(os.environ["AIDE_JOB_TMP"])
        before = set(parent.iterdir())
        with patch.object(owner, "current_context", side_effect=owner.WorkspaceRefused("fixture identity mismatch")) as authenticate:
            with self.assertRaises(owner.WorkspaceRefused):
                with lite.public_archive_fixture("aide-public-release-test-"):
                    self.fail("authentication refusal must not allocate")
        self.assertEqual(1, authenticate.call_count)
        self.assertEqual(before, set(parent.iterdir()))

    def test_lost_ref_result_keeps_uncertainty_and_candidate(self):
        original = managed._advance_ref
        def intercept(root, *args, **kw):
            original(root, *args, **kw)
            raise subprocess.TimeoutExpired("git update-ref", 30)
        with patch.object(managed, "_advance_ref", side_effect=intercept):
            result = self.create()
        self.assertEqual("UNCERTAIN", result["status"], result)
        self.assertIsNone(result["branch_advanced"])
        self.assertEqual(result["candidate_commit"], self.git("rev-parse", "HEAD").strip())
        self.assertFalse((self.root / ".git/index.lock").exists())

    def test_postcondition_failure_keeps_advanced_candidate(self):
        original = managed._advance_ref
        def intercept(root, *args, **kw):
            result = original(root, *args, **kw)
            with self.index.open("ab") as stream:
                stream.write(b"changed after ref effect")
            return result
        with patch.object(managed, "_advance_ref", side_effect=intercept):
            result = self.create()
        self.assertEqual("UNCERTAIN", result["status"], result)
        self.assertTrue(result["branch_advanced"])
        self.assertEqual(result["candidate_commit"], self.git("rev-parse", "HEAD").strip())
        self.assertNotEqual(self.parent, result["candidate_commit"])

    def cli(self, message, apply=False, **expected):
        (self.root / "MESSAGE").write_bytes(message)
        args = [sys.executable, "-B", str(CLI), "--repo-root", str(self.root),
                "commit", "create", "--message-file", "MESSAGE",
                "--expect-message-sha256", expected.get("message_sha256", hashlib.sha256(message).hexdigest()),
                "--expect-ref", expected.get("ref", self.options["expected_ref"]),
                "--expect-head", expected.get("head", self.parent),
                "--expect-tree", expected.get("tree", self.tree),
                "--path", expected.get("path", "one.txt")]
        if apply:
            args.append("--apply")
        return subprocess.run(args, cwd=self.root, capture_output=True, text=True,
                              encoding="utf-8", timeout=60)

    def test_public_cli_invalid_message_cannot_advance(self):
        result = self.cli(b"update\n", apply=True)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("result: REFUSED", result.stdout)
        self.assertEqual(self.parent, self.git("rev-parse", "HEAD").strip())
        self.assertEqual(self.index_before, self.index.read_bytes())

    def test_public_cli_changed_inputs_cannot_advance(self):
        objects_before = self.git("count-objects", "-v")
        for expected in ({"head": "f" * 40},
                         {"tree": self.git("rev-parse", "HEAD^{tree}").strip()},
                         {"message_sha256": "0" * 64}, {"path": "outside.txt"},
                         {"ref": "refs/heads/task/other"}):
            with self.subTest(expected=expected):
                result = self.cli(self.message, apply=True, **expected)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertIn("result: REFUSED", result.stdout)
                self.assertEqual(self.parent, self.git("rev-parse", "HEAD").strip())
                self.assertEqual(self.index_before, self.index.read_bytes())
                self.assertEqual(objects_before, self.git("count-objects", "-v"))
                self.assertFalse((self.root / ".git/index.lock").exists())

    def test_public_cli_preview_then_normal_commit(self):
        preview = self.cli(self.message)
        self.assertEqual(0, preview.returncode, preview.stderr)
        self.assertIn("result: DRY_RUN", preview.stdout)
        self.assertEqual(self.parent, self.git("rev-parse", "HEAD").strip())
        applied = self.cli(self.message, apply=True)
        self.assertEqual(0, applied.returncode, applied.stderr)
        data = json.loads(applied.stdout.splitlines()[-1])
        self.assertEqual("COMMITTED", data["status"])
        self.assertEqual(data["candidate_commit"], self.git("rev-parse", "HEAD").strip())
        self.assertEqual(self.tree, self.git("rev-parse", "HEAD^{tree}").strip())
        self.assertFalse((self.root / ".git/index.lock").exists())

if __name__ == "__main__":
    count = os.environ.get("GIT_CONFIG_COUNT", "absent")
    observed_count = int(count) if count.isascii() and count.isdigit() and len(count) <= 2 else None
    print(json.dumps({"runner_null_config_pair": os.environ.get("GIT_CONFIG_GLOBAL") == os.devnull and os.environ.get("GIT_CONFIG_NOSYSTEM") == "1",
                      "git_runtime_config_count": count if observed_count is not None else "absent_or_invalid",
                      "git_runtime_config_keys": ["safe.directory" if os.environ.get(f"GIT_CONFIG_KEY_{i}") == "safe.directory" else "unsupported_or_missing"
                                                  for i in range(min(observed_count or 0, 16))]}, sort_keys=True))
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ManagedCommitTests)
    old = module("aide_commit_existing_q27", SOURCE / ".aide/scripts/tests/test_q27_commit_recovery.py")
    # Keep original Q27 assertions/source intact; only its module-local public
    # dummy fixture factory uses the already qualified managed retirement path.
    old.tempfile = SimpleNamespace(TemporaryDirectory=PublicGitFixture)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(old))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({"tests_run":result.testsRun,"failures":len(result.failures),
                      "errors":len(result.errors),"skipped":len(result.skipped),
                      "new_fixture_count":len(unittest.defaultTestLoader.getTestCaseNames(ManagedCommitTests)),
                      "success":result.wasSuccessful()},sort_keys=True))
    sys.exit(0 if result.wasSuccessful() else 1)
