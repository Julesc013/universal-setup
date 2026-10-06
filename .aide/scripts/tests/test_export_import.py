from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import importlib.util
import json
import hashlib
import shutil
import os
import zipfile
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class ExportImportTests(unittest.TestCase):
    def make_source_repo(self, *, minimal_recovery: bool = False) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "source"
        root.mkdir()
        source_files = [*aide_lite.PORTABLE_SOURCE_FILES, *aide_lite.Q21_REQUIRED_FILES]
        if minimal_recovery:
            # Intent/ownership boundary tests need a valid multi-file pack,
            # not repeated durable installation of every exported design family.
            # Full export/archive/consumer tests retain the complete fixture.
            source_files = [*aide_lite.Q21_REQUIRED_FILES, *aide_lite.PORTABLE_TEMPLATE_MAP,
                '.aide/scripts/aide_lite.py', '.aide/prompts/compact-task.md',
                '.aide/policies/token-budget.yaml', '.aide/policies/commit-messages.yaml',
                '.aide/policies/task-resumption.yaml', '.aide/policies/work-units.yaml',
                '.aide/policies/recovery.yaml', '.aide/policies/verification.yaml',
                '.aide/policies/token-ledger.yaml', '.aide/policies/evals.yaml',
                '.aide/policies/controller.yaml', '.aide/policies/routing.yaml',
                '.aide/policies/cache.yaml', '.aide/policies/local-state.yaml']
        for rel in source_files:
            source = REPO_ROOT / rel
            if source.exists() and source.is_file():
                self.copy_file(source, root / rel)
        for directory in ([] if minimal_recovery else [*aide_lite.PORTABLE_SOURCE_DIRS, ".aide/import"]):
            source_root = REPO_ROOT / directory
            if not source_root.exists():
                continue
            for source in sorted(source_root.rglob("*")):
                if source.is_file():
                    self.copy_file(source, root / source.relative_to(REPO_ROOT))
        aide_lite.write_text(root / "README.md", "# Source Fixture\n")
        aide_lite.write_text(root / "AGENTS.md", "# Source Agents\n")
        aide_lite.write_text(root / ".gitignore", ".aide.local/\n.aide.local/**\n.env\n")
        return root

    def copy_file(self, source: Path, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())

    def build_pack(self, source_root: Path) -> Path:
        pack_root, report = aide_lite.build_export_pack(source_root)
        self.assertGreater(len(report["included_files"]), 20)
        self.assertEqual(report["boundary_violations"], [])
        return pack_root

    def freeze_pack(self, source_root: Path, name: str) -> Path:
        pack_root = self.build_pack(source_root)
        frozen = source_root.parent / name
        shutil.copytree(pack_root, frozen)
        return frozen

    def set_manifest_scalars(self, pack_root: Path, updates: dict[str, str]) -> None:
        lines = []
        for line in aide_lite.read_text(pack_root / "manifest.yaml").splitlines():
            key = line.split(":", 1)[0] if ":" in line else ""
            if key in updates:
                lines.append(f"{key}: {updates[key]}")
            else:
                lines.append(line)
        aide_lite.write_text(pack_root / "manifest.yaml", "\n".join(lines) + "\n")

    def test_export_policy_has_required_anchors(self) -> None:
        policy = aide_lite.read_text(REPO_ROOT / aide_lite.EXPORT_IMPORT_POLICY_PATH)
        for anchor in [
            "portable_pack_only",
            "no_external_repo_mutation",
            "no_network",
            "no_provider_calls",
            "aide-lite-pack-v0",
            "never_copy_aide_self_hosting_queue: true",
            "never_copy_aide_generated_context: true",
            "never_copy_aide_local_state: true",
            "never_copy_provider_credentials: true",
        ]:
            self.assertIn(anchor, policy)

    def test_generated_install_guides_describe_bounded_removal_apply(self) -> None:
        pack_guide = aide_lite.pack_install_text()
        release_guide = aide_lite.release_install_notes_text(REPO_ROOT, "fixture", "PASS")
        for guide in [pack_guide, release_guide]:
            self.assertIn("plan-removal", guide)
            self.assertIn("apply-removal", guide)
            self.assertIn("--expect-plan", guide)
            self.assertIn("Windows", guide)
            self.assertIn("PARTIAL_REMOVAL", guide)
            self.assertIn("authored", guide.lower())
            self.assertIn("managed section", guide)
            self.assertIn("apply_allowed: false", guide)
            self.assertIn("RECOVERY_REQUIRED", guide)
            self.assertNotIn("uninstall are planning models only", guide)
        self.assertIn("apply_mode_available: true", release_guide)
        self.assertIn("Non-Windows apply", pack_guide)

    def test_export_includes_required_portable_files_and_manifest(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        self.assertTrue((pack_root / "manifest.yaml").exists())
        self.assertTrue((pack_root / "checksums.json").exists())
        for rel in [
            "files/.aide/scripts/aide_lite.py",
            "files/.aide/policies/token-budget.yaml",
            "files/.aide/policies/export-import.yaml",
            "files/.aide/prompts/compact-task.md",
            "files/.aide/profile.template.yaml",
            "files/.aide/memory/project-state.template.md",
            "files/AGENTS.md.template",
            "files/.aide.local.example/secrets/README.md",
        ]:
            self.assertTrue((pack_root / rel).exists(), rel)
        manifest = aide_lite.read_text(pack_root / "manifest.yaml")
        self.assertIn("included_files:", manifest)
        self.assertIn("excluded_classes:", manifest)
        self.assertIn("raw_prompt_storage: false", manifest)

    def test_extracted_export_pack_waits_and_runs_job_without_source_checkout(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        self.assertTrue(aide_lite.validate_pack_checksums(pack_root)[0])
        archive = source_root.parent / "lite-efficiency-fixture.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(pack_root.rglob("*")):
                if path.is_file():
                    bundle.write(path, f"{pack_root.name}/{path.relative_to(pack_root).as_posix()}")
        consumer = source_root.parent / "consumer"
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(consumer)
        delivered = consumer / pack_root.name / "files"
        script = delivered / ".aide/scripts/aide_lite.py"
        self.assertEqual(script.read_bytes(), MODULE_PATH.read_bytes())
        self.assertTrue(aide_lite.source_maintainer_job_guard(delivered))

        job_id = "a" * 32
        job = {"source_commit": "b" * 40, "source_tree": "c" * 40}
        manifest = hashlib.sha256(json.dumps(job, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        control = consumer / "control"
        retained = consumer / "retained"
        control.mkdir()
        (retained / job_id).mkdir(parents=True)
        config = consumer / "execution.json"
        config.write_text(json.dumps({"schema": "aide.managed-workspace.local.v1",
                                      "roots": {"control": str(control), "retained": str(retained)}}), encoding="utf-8")
        (retained / job_id / "owner.json").write_text(
            json.dumps({"job_id": job_id, "manifest_digest": manifest}), encoding="utf-8")
        (retained / job_id / "receipt.json").write_text(json.dumps({
            "job_id": job_id, "manifest_digest": manifest, "job": job,
            "phase": "retired", "scratch_absent": True, "reservation_released": True,
            "result": {"job_id": job_id, "reason": "exited", "exit_code": 0, "quiescent": True},
            "collected_manifest": {"output": "d" * 64, "logs": "e" * 64},
        }), encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(script), "--repo-root", str(delivered),
             "job", "wait", "--config", str(config), "--job-id", job_id,
             "--manifest-digest", manifest, "--timeout-seconds", "0"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr[-500:])
        outcome = json.loads(completed.stdout)
        self.assertEqual(outcome["status"], "PASS")
        self.assertEqual(outcome["model_requests_started_by_observer"], 0)
        self.assertEqual(outcome["host_model_requests"], "unknown")
        events = consumer / "codex-events.jsonl"
        events.write_text("\n".join(json.dumps(event) for event in [
            {"type": "thread.started", "thread_id": "00000000-0000-0000-0000-000000000001"},
            {"type": "turn.started"},
            {"type": "turn.completed", "usage": {"input_tokens": 10, "cached_input_tokens": 2,
              "output_tokens": 3, "reasoning_output_tokens": 1}},
        ]) + "\n", encoding="utf-8")
        imported = subprocess.run(
            [sys.executable, "-I", "-B", str(script), "--repo-root", str(delivered),
             "job", "usage", "--stream", str(events)],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(imported.returncode, 0, imported.stderr[-500:])
        usage = json.loads(imported.stdout)
        self.assertEqual(usage["status"], "COMPLETE")
        self.assertEqual(usage["usage_totals"]["input_tokens"], 10)

        secret_marker = "AIDE-private-prompt-marker"
        prompt_input = json.dumps([
            {"type": "message", "role": "system", "content": [
                {"type": "input_text", "text": "system context"}]},
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": secret_marker}]},
        ]).encode("utf-8")
        observed = subprocess.run(
            [sys.executable, "-I", "-B", str(script), "--repo-root", str(delivered),
             "job", "context"],
            input=prompt_input, capture_output=True, timeout=15)
        self.assertEqual(observed.returncode, 0, observed.stderr[-500:])
        context = json.loads(observed.stdout)
        self.assertEqual(context["status"], "COMPLETE")
        self.assertEqual(context["visible_text_utf8_bytes"],
                         len("system context".encode()) + len(secret_marker.encode()))
        self.assertEqual(context["roles"]["user"]["text_utf8_bytes"], len(secret_marker.encode()))
        self.assertEqual(context["model_requests_started_by_parser"], 0)
        self.assertFalse(context["raw_prompt_or_response_retained"])
        self.assertNotIn(secret_marker.encode(), observed.stdout + observed.stderr)

        # The delivered CLI reuses the existing bounded Windows owner. Its
        # source identity is the disposable target's Git commit, not this
        # development checkout or an invented identity for extracted bytes.
        target = consumer / "job-target"
        target.mkdir()
        fixture = target / "fixture.py"
        fixture.write_text("print('delivered owner ran')\n", encoding="utf-8")
        packet = target / "task-packet.txt"
        packet.write_text("Return one bounded fixture result.\n", encoding="utf-8")
        schema = target / "result-schema.json"
        schema.write_text('{"type":"object","properties":{"status":{"type":"string"}}}\n', encoding="utf-8")
        (target / ".gitignore").write_text(".aide.local/\n", encoding="utf-8")
        for command in (["init", "-q"], ["add", "fixture.py", "task-packet.txt",
                        "result-schema.json", ".gitignore"],
                        ["-c", "user.name=AIDE fixture", "-c", "user.email=fixture@example.invalid",
                         "commit", "-qm", "test(fixture): pin delivered job input"]):
            subprocess.run(["git", "-C", str(target), *command], check=True,
                           capture_output=True, timeout=15)
        git = lambda ref: subprocess.run(["git", "-C", str(target), "rev-parse", ref],
               check=True, capture_output=True, text=True, timeout=15).stdout.strip()
        pool = consumer / "execution"
        pool.mkdir()
        roots = {name: str(pool / name) for name in ("scratch", "retained", "control")}
        selection = consumer / "selection.json"
        selection.write_text(json.dumps({
            "schema": "aide.managed-workspace.local.v1", "roots": roots,
            "working_roots": [str(target)],
            "limits": {"disk_reserve_bytes": 10 * 1024**3,
                       "physical_reserve_bytes": 4 * 1024**3,
                       "commit_reserve_bytes": 4 * 1024**3,
                       "scratch_bytes": 8 * 1024**2,
                       "retained_bytes": 1024**2,
                       "canonical_bytes": 1024**2,
                       "memory_bytes": 256 * 1024**2,
                       "log_bytes": 64 * 1024,
                       "runtime_seconds": 30, "processes": 4, "max_files": 1000},
        }), encoding="utf-8")
        config_path = target / ".aide.local/execution.json"
        base = [sys.executable, "-I", "-B", str(script), "--repo-root", str(delivered), "job"]
        setup = subprocess.run([*base, "setup", "--config", str(config_path),
                                "--selection", str(selection), "--approved-parent", str(pool)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(setup.returncode, 0, setup.stdout[-500:] + setup.stderr[-500:])
        self.assertEqual(json.loads(setup.stdout)["result"], "CONFIGURED")
        fake_codex = consumer / "codex.exe"
        fake_codex.write_bytes(b"MZ synthetic executable; admission only")
        codex_job = {"schema": "aide.maintainer-job.v1", "owner": "extracted_fixture",
                     "workunit": "AIDE-LITE-EFFICIENCY-01", "cwd": str(target),
                     "source_commit": git("HEAD"), "source_tree": git("HEAD^{tree}"),
                     "adapter": "codex_exec", "argv": [str(fake_codex)],
                     "executable_sha256": hashlib.sha256(fake_codex.read_bytes()).hexdigest(),
                     "inputs": {name: hashlib.sha256((target / name).read_bytes()).hexdigest()
                                for name in ("task-packet.txt", "result-schema.json")},
                     "prompt_file": "task-packet.txt", "schema_file": "result-schema.json",
                     "model": "gpt-6-sol", "effort": "medium"}
        codex_manifest = consumer / "codex-job.json"
        codex_manifest.write_text(json.dumps(codex_job), encoding="utf-8")
        refused = subprocess.run([*base, "run", "--config", str(config_path),
                                  "--manifest", str(codex_manifest)],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(refused.returncode, 1, refused.stdout[-500:] + refused.stderr[-500:])
        self.assertEqual(json.loads(refused.stdout)["result"], "REFUSED")
        self.assertIn("local model permission", json.loads(refused.stdout)["reason"])
        self.assertEqual(list(Path(roots["scratch"]).iterdir()), [])
        job = {"schema": "aide.maintainer-job.v1", "owner": "extracted_fixture",
               "workunit": "AIDE-LITE-EFFICIENCY-01", "cwd": str(target),
               "source_commit": git("HEAD"), "source_tree": git("HEAD^{tree}"),
               "adapter": "python", "argv": [sys.executable, str(fixture)],
               "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
               "inputs": {"fixture.py": hashlib.sha256(fixture.read_bytes()).hexdigest()},
               "canonical_outputs": {}}
        manifest_path = consumer / "job.json"
        manifest_path.write_text(json.dumps(job), encoding="utf-8")
        inspect = subprocess.run([*base, "inspect", "--config", str(config_path),
                                  "--manifest", str(manifest_path)],
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(inspect.returncode, 0, inspect.stdout[-500:] + inspect.stderr[-500:])
        self.assertIsNone(json.loads(inspect.stdout)["active"])
        run = subprocess.run([*base, "run", "--config", str(config_path),
                              "--manifest", str(manifest_path)],
                             capture_output=True, text=True, timeout=40)
        self.assertEqual(run.returncode, 0, run.stdout[-500:] + run.stderr[-500:])
        result = json.loads(run.stdout)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["source_commit"], git("HEAD"))
        self.assertFalse((Path(roots["scratch"]) / result["job_id"]).exists())
        self.assertFalse((Path(roots["control"]) / "active.json").exists())
        attached = subprocess.run(
            [*base, "wait", "--config", str(config_path),
             "--job-id", result["job_id"], "--manifest-digest", result["manifest_digest"],
             "--timeout-seconds", "0"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(attached.returncode, 0, attached.stdout[-500:] + attached.stderr[-500:])
        attached_view = json.loads(attached.stdout)
        self.assertEqual(attached_view["status"], "PASS")
        self.assertEqual(attached_view["receipt_sha256"], result["receipt_sha256"])
        self.assertEqual(attached_view["source_commit"], git("HEAD"))
        self.assertEqual(attached_view["model_requests_started_by_observer"], 0)
        changed = subprocess.run(
            [*base, "wait", "--config", str(config_path),
             "--job-id", result["job_id"], "--manifest-digest", "f" * 64,
             "--timeout-seconds", "0"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(changed.returncode, 1, changed.stdout[-500:] + changed.stderr[-500:])
        self.assertEqual(json.loads(changed.stdout)["status"], "EVIDENCE_UNAVAILABLE")

    def test_source_checkout_missing_queue_index_cannot_bypass_job_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".aide").mkdir()
            (root / ".aide/profile.yaml").write_text("schema_version: fixture\n", encoding="utf-8")
            (root / "core/execution").mkdir(parents=True)
            (root / "core/execution/managed_workspace.py").write_text("# fixture\n", encoding="utf-8")
            self.assertFalse(aide_lite.source_maintainer_job_guard(root))

    def test_export_excludes_source_state_and_generated_artifacts(self) -> None:
        source_root = self.make_source_repo()
        for rel in [
            ".aide/profile.yaml",
            ".aide/queue/index.yaml",
            ".aide/context/latest-task-packet.md",
            ".aide/reports/token-ledger.jsonl",
            ".aide/cache/latest-cache-keys.json",
            ".aide/routing/latest-route-decision.json",
            ".aide/gateway/latest-gateway-status.json",
            ".aide/providers/latest-provider-status.json",
            ".aide.local/state.json",
            ".env",
        ]:
            aide_lite.write_text(source_root / rel, "source-only\n")
        pack_root = self.build_pack(source_root)
        for rel in [
            "files/.aide/profile.yaml",
            "files/.aide/queue/index.yaml",
            "files/.aide/context/latest-task-packet.md",
            "files/.aide/reports/token-ledger.jsonl",
            "files/.aide/cache/latest-cache-keys.json",
            "files/.aide/routing/latest-route-decision.json",
            "files/.aide/gateway/latest-gateway-status.json",
            "files/.aide/providers/latest-provider-status.json",
            "files/.aide.local/state.json",
            "files/.env",
        ]:
            self.assertFalse((pack_root / rel).exists(), rel)

    def test_export_checksums_match_and_are_deterministic(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        ok, problems = aide_lite.validate_pack_checksums(pack_root)
        self.assertTrue(ok, problems)
        checksum_data = json.loads(aide_lite.read_text(pack_root / "checksums.json"))
        self.assertEqual(checksum_data["checksum_scope"], "payload-and-static-pack-docs")
        self.assertIn("manifest.yaml", checksum_data["excluded_from_checksums"])
        self.assertNotIn("manifest.yaml", checksum_data["checksums"])
        self.assertNotIn("checksums.json", checksum_data["checksums"])
        self.assertNotIn("export-report.md", checksum_data["checksums"])
        first = aide_lite.read_text(pack_root / "checksums.json")
        self.build_pack(source_root)
        second = aide_lite.read_text(pack_root / "checksums.json")
        self.assertEqual(first, second)

    def test_pack_status_fails_for_payload_mismatch_not_manifest_metadata(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        aide_lite.write_text(pack_root / "manifest.yaml", aide_lite.read_text(pack_root / "manifest.yaml") + "# metadata note\n")
        ok, problems = aide_lite.validate_pack_checksums(pack_root)
        self.assertTrue(ok, problems)
        aide_lite.write_text(pack_root / "files/.aide/scripts/aide_lite.py", "# tampered payload\n")
        ok, problems = aide_lite.validate_pack_checksums(pack_root)
        self.assertFalse(ok)
        self.assertTrue(any("checksum mismatch: files/.aide/scripts/aide_lite.py" in problem for problem in problems))

    def test_pack_status_fails_for_unchecksummed_payload_file(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        aide_lite.write_text(pack_root / "files/.aide/untracked-payload.txt", "untracked\n")
        ok, problems = aide_lite.validate_pack_checksums(pack_root)
        self.assertFalse(ok)
        self.assertIn("unchecksummed pack file: files/.aide/untracked-payload.txt", problems)

    def test_export_manifest_records_provenance_fields(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        manifest = aide_lite.read_text(pack_root / "manifest.yaml")
        self.assertIn("source_commit:", manifest)
        self.assertIn("source_dirty_state:", manifest)
        self.assertIn("checksum_scope:", manifest)
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root)
        self.assertFalse(problems)
        self.assertIn(status, {"PASS", "DIRTY_SOURCE_RECORDED", "UNKNOWN_GIT_UNAVAILABLE"})

    def test_export_records_clean_source_before_writing_generated_pack(self) -> None:
        source_root = self.make_source_repo()
        subprocess.run(["git", "init", "--quiet", str(source_root)], check=True)
        subprocess.run(["git", "-C", str(source_root), "config", "user.name", "AIDE Fixture"], check=True)
        subprocess.run(["git", "-C", str(source_root), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(source_root), "config", "core.autocrlf", "false"], check=True)
        subprocess.run(["git", "-C", str(source_root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(source_root), "commit", "--quiet", "-m", "fixture"], check=True)
        source_commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()

        pack_root = self.build_pack(source_root)
        scalars = aide_lite.pack_manifest_scalars(pack_root)
        self.assertEqual(scalars["source_commit"], source_commit)
        self.assertEqual(scalars["source_dirty_state"], "false")
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root)
        self.assertEqual(status, "PASS", problems)
        self.assertFalse(problems)

        subprocess.run(["git", "-C", str(source_root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(source_root), "commit", "--quiet", "-m",
                        "build(fixture): commit source-bound pack"], check=True)
        self.build_pack(source_root)
        self.assertEqual(aide_lite.pack_manifest_scalars(pack_root)["source_commit"], source_commit)
        replay_status = subprocess.run(["git", "-C", str(source_root), "status", "--porcelain"],
                                       check=True, capture_output=True, text=True)
        self.assertEqual(replay_status.stdout, "")

    def test_pack_provenance_fails_stale_clean_manifest(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        self.set_manifest_scalars(
            pack_root,
            {
                "source_commit": "old-commit",
                "source_dirty_state": "false",
            },
        )
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root, current_commit="new-commit")
        self.assertEqual(status, "FAIL")
        self.assertTrue(any("does not match current HEAD" in problem for problem in problems))

    def test_pack_provenance_allows_explicit_dirty_manifest(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        self.set_manifest_scalars(
            pack_root,
            {
                "source_commit": "old-commit",
                "source_dirty_state": "true",
            },
        )
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root, current_commit="new-commit")
        self.assertEqual(status, "DIRTY_SOURCE_RECORDED")
        self.assertFalse(problems)

    def test_pack_provenance_allows_only_artifact_commit_changes(self) -> None:
        source_root = self.make_source_repo()
        subprocess.run(["git", "init", "--quiet", str(source_root)], check=True)
        subprocess.run(["git", "-C", str(source_root), "config", "user.name", "AIDE Fixture"], check=True)
        subprocess.run(["git", "-C", str(source_root), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(source_root), "config", "core.autocrlf", "false"], check=True)
        subprocess.run(["git", "-C", str(source_root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(source_root), "commit", "--quiet", "-m", "source"], check=True)

        pack_root = self.build_pack(source_root)
        subprocess.run(["git", "-C", str(source_root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(source_root), "commit", "--quiet", "-m", "artifacts"], check=True)
        artifact_commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root)
        self.assertEqual(status, "PASS_SOURCE_ANCESTOR", problems)
        self.assertFalse(problems)

        portable_script = source_root / ".aide/scripts/aide_lite.py"
        portable_script.write_text(portable_script.read_text(encoding="utf-8") + "\n# changed input\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source_root), "add", ".aide/scripts/aide_lite.py"], check=True)
        subprocess.run(["git", "-C", str(source_root), "commit", "--quiet", "-m", "input changed"], check=True)
        input_commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root)
        self.assertEqual(status, "FAIL")
        self.assertTrue(any("does not match current HEAD" in problem for problem in problems))

        subprocess.run(["git", "-C", str(source_root), "replace", input_commit, artifact_commit], check=True)
        self.addCleanup(
            subprocess.run,
            ["git", "-C", str(source_root), "replace", "-d", input_commit],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        status, problems = aide_lite.validate_pack_provenance(pack_root, source_root)
        self.assertEqual(status, "FAIL")
        self.assertTrue(any("does not match current HEAD" in problem for problem in problems))

    def test_import_dry_run_reports_without_writing(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        target = source_root.parent / "target-dry-run"
        aide_lite.write_text(target / "README.md", "# Target\n")
        result = aide_lite.apply_import_pack(pack_root, target, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["mode"], "safe")
        self.assertGreater(result["operation_count"], 10)
        self.assertTrue(result["operations"])
        self.assertTrue(result["skipped"])
        self.assertFalse((target / ".aide").exists())

    def test_import_fixture_creates_templates_and_preserves_agents(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        target = source_root.parent / "target"
        aide_lite.write_text(target / "README.md", "# Target\n")
        aide_lite.write_text(target / "AGENTS.md", "# Target Agents\n\nManual guidance.\n")
        result = aide_lite.apply_import_pack(pack_root, target, dry_run=False)
        self.assertFalse(result["conflicts"])
        agents = aide_lite.read_text(target / "AGENTS.md")
        self.assertIn("Manual guidance.", agents)
        self.assertIn("AIDE-PORTABLE:BEGIN", agents)
        for rel in [
            ".aide/profile.template.yaml",
            ".aide/profile.yaml",
            ".aide/memory/project-state.template.md",
            ".aide/memory/project-state.md",
            ".aide/memory/decisions.template.md",
            ".aide/memory/open-risks.template.md",
        ]:
            self.assertTrue((target / rel).exists(), rel)
        self.assertTrue(aide_lite.gitignore_has_local_state_rules(target))
        self.assertFalse((target / ".aide.local").exists())
        self.assertFalse((target / ".aide/queue/index.yaml").exists())
        self.assertFalse((target / aide_lite.LATEST_PACKET_PATH).exists())
        self.assertFalse((target / "core").exists())
        self.assertTrue((target / "docs/reference/commit-discipline.md").exists())
        self.assertFalse((target / "docs/roadmap").exists())

    def test_import_preserves_authored_agents_bytes_outside_portable_section(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        target = source_root.parent / "target-agents-bytes"
        target.mkdir()
        authored = b"# Target Agents\r\n\r\nManual guidance with spaces  \r\n"
        (target / "AGENTS.md").write_bytes(authored)

        result = aide_lite.apply_import_pack(pack_root, target)
        self.assertEqual(result["status"], "APPLIED")
        installed = (target / "AGENTS.md").read_bytes()
        self.assertTrue(installed.startswith(authored), installed[: len(authored) + 20])
        self.assertIn(b"AIDE-PORTABLE:BEGIN", installed)
        rerun = aide_lite.apply_import_pack(pack_root, target)
        self.assertEqual(rerun["status"], "NO_CHANGES")
        self.assertEqual((target / "AGENTS.md").read_bytes(), installed)

    def test_import_safe_mode_skips_broad_source_roots(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        target = source_root.parent / "target-safe-scope"
        aide_lite.write_text(target / "README.md", "# Target\n")
        result = aide_lite.apply_import_pack(pack_root, target, dry_run=True)
        skipped_sources = {item["source"] for item in result["skipped"]}
        planned_targets = {item["target"] for item in result["operations"]}
        self.assertTrue(any(source.startswith("core/") for source in skipped_sources), skipped_sources)
        self.assertFalse(any(target.startswith("core/") for target in planned_targets), planned_targets)
        self.assertTrue(any(target.startswith("docs/reference/") for target in planned_targets), planned_targets)
        self.assertFalse(any(target.startswith("docs/roadmap/") for target in planned_targets), planned_targets)

    def test_import_full_mode_is_explicit_for_optional_broad_roots(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        target = source_root.parent / "target-full-scope"
        aide_lite.write_text(target / "README.md", "# Target\n")
        result = aide_lite.apply_import_pack(pack_root, target, dry_run=True, mode="full")
        planned_targets = {item["target"] for item in result["operations"]}
        self.assertFalse(result["skipped"])
        self.assertTrue(any(target.startswith("core/") for target in planned_targets), planned_targets)
        self.assertTrue(any(target.startswith("docs/reference/") for target in planned_targets), planned_targets)

    def test_imported_aide_lite_doctor_snapshot_and_pack_run(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.build_pack(source_root)
        target = source_root.parent / "target-smoke"
        aide_lite.write_text(target / "README.md", "# Target Smoke\n")
        aide_lite.apply_import_pack(pack_root, target, dry_run=False)
        script = target / ".aide/scripts/aide_lite.py"
        commands = [
            ["doctor"],
            ["snapshot"],
            ["index"],
            ["pack", "--task", "Fixture target smoke task"],
        ]
        for command in commands:
            result = subprocess.run(
                [sys.executable, str(script), "--repo-root", str(target), *command],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((target / aide_lite.SNAPSHOT_PATH).exists())
        self.assertTrue((target / aide_lite.LATEST_PACKET_PATH).exists())

    def test_import_records_baseline_and_updates_only_unchanged_owned_bytes(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "pack-v1")
        target = source_root.parent / "target-owned-update"
        first = aide_lite.apply_import_pack(pack_v1, target)
        self.assertEqual(first["status"], "APPLIED")
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())

        aide_lite.write_text(source_root / managed_rel, "# Compact Task v2\n")
        pack_v2 = self.freeze_pack(source_root, "pack-v2")
        without_predecessor = aide_lite.apply_import_pack(pack_v2, target, dry_run=True)
        self.assertEqual(without_predecessor["status"], "PLANNED_CONFLICT")
        self.assertIn(managed_rel, without_predecessor["conflicts"])
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        operation = next(item for item in preview["operations"] if item["target"] == managed_rel)
        self.assertEqual(operation["action"], "update_owned")
        self.assertEqual(operation["ownership_basis"], "installed_receipt")

        updated = aide_lite.apply_import_pack(
            pack_v2,
            target,
            predecessor_pack=pack_v1,
            expected_plan_digest=preview["plan_digest"],
        )
        self.assertEqual(updated["status"], "APPLIED")
        self.assertEqual(aide_lite.read_text(target / managed_rel), "# Compact Task v2\n")
        rerun = aide_lite.apply_import_pack(pack_v2, target)
        self.assertEqual(rerun["status"], "NO_CHANGES")
        self.assertFalse(rerun["written"])

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_redigested_receipt_cannot_relabel_direct_edit_as_owned_update(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "forged-owned-v1")
        target = source_root.parent / "forged-owned-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        managed_path = target / managed_rel
        direct_edit = b"# Direct project edit\n"
        managed_path.write_bytes(direct_edit)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        forged = aide_lite.load_portable_import_receipt(target)
        entry = forged["managed"][managed_rel]
        entry["source_digest"] = aide_lite.digest_bytes(direct_edit)
        entry["installed_digest"] = aide_lite.digest_bytes(direct_edit)
        entry["ownership"] = "aide_portable_managed"
        entry["local_overlay"] = False
        forged["receipt_digest"] = aide_lite.portable_import_record_digest(forged, "receipt_digest")
        receipt_path.write_text(aide_lite.stable_json_text(forged), encoding="utf-8")
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["managed"][managed_rel]["source_digest"], entry["source_digest"])

        aide_lite.write_text(source_root / managed_rel, "# Changed upstream\n")
        pack_v2 = self.freeze_pack(source_root, "forged-owned-v2")
        for prior in (pack_v1, None):
            with self.subTest(predecessor=prior is not None):
                preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=prior)
                operation = next(item for item in preview["operations"] if item["target"] == managed_rel)
                self.assertEqual(operation["action"], "conflict")
                self.assertEqual(preview["status"], "PLANNED_CONFLICT")
                self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=prior)["status"], "CONFLICT")
                self.assertEqual(managed_path.read_bytes(), direct_edit)

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_manual_three_way_resolution_keeps_local_overlay_across_updates(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        aide_lite.write_text(source_root / managed_rel, "# Task\ninstruction: base\n")
        pack_v1 = self.freeze_pack(source_root, "three-way-v1")
        target = source_root.parent / "target-three-way"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")

        local_v1 = b"# Task\ninstruction: project\n"
        (target / managed_rel).write_bytes(local_v1)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt_v1 = receipt_path.read_bytes()
        aide_lite.write_text(source_root / managed_rel, "# Task\ninstruction: upstream-v2\n")
        pack_v2 = self.freeze_pack(source_root, "three-way-v2")
        refused = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)
        self.assertEqual(refused["status"], "CONFLICT")
        self.assertEqual(refused["written"], [])
        self.assertIn(managed_rel, refused["conflicts"])
        self.assertEqual((target / managed_rel).read_bytes(), local_v1)
        self.assertEqual(receipt_path.read_bytes(), receipt_v1)
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())

        resolved_v2 = source_root.parent / "resolved-v2.md"
        merged_v2 = b"# Task\ninstruction: project + upstream-v2\n"
        resolved_v2.write_bytes(merged_v2)
        preview_v2 = aide_lite.apply_import_pack(
            pack_v2, target, dry_run=True, predecessor_pack=pack_v1,
            resolutions={managed_rel: resolved_v2},
        )
        self.assertEqual(preview_v2["status"], "PLANNED")
        applied_v2 = aide_lite.apply_import_pack(
            pack_v2, target, predecessor_pack=pack_v1,
            resolutions={managed_rel: resolved_v2},
            expected_plan_digest=preview_v2["plan_digest"],
        )
        self.assertEqual(applied_v2["status"], "APPLIED")
        self.assertEqual((target / managed_rel).read_bytes(), merged_v2)
        receipt_v2 = json.loads(receipt_path.read_text(encoding="utf-8"))
        entry_v2 = receipt_v2["managed"][managed_rel]
        self.assertEqual(entry_v2["installed_digest"], aide_lite.digest_bytes(merged_v2))
        self.assertEqual(entry_v2["source_digest"], aide_lite.digest_bytes((pack_v2 / "files" / managed_rel).read_bytes()))
        self.assertNotEqual(entry_v2["installed_digest"], entry_v2["source_digest"])
        self.assertEqual(entry_v2["ownership"], "project_overlay_on_aide_managed")
        removal_row = next(item for item in aide_lite.build_portable_removal_plan(target)["operations"] if item["target"] == managed_rel)
        self.assertEqual(removal_row["action"], "preserve_project_overlay")
        self.assertFalse(removal_row["removal_candidate"])
        with self.assertRaisesRegex(ValueError, "receipt-owned"):
            aide_lite.apply_portable_owned_repair(pack_v2, target, managed_rel, dry_run=True)
        with self.assertRaises(ValueError):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)

        aide_lite.write_text(source_root / managed_rel, "# Task\ninstruction: upstream-v3\n")
        pack_v3 = self.freeze_pack(source_root, "three-way-v3")
        receipt_before_v3 = receipt_path.read_bytes()
        refused_v3 = aide_lite.apply_import_pack(pack_v3, target, predecessor_pack=pack_v2)
        self.assertEqual(refused_v3["status"], "CONFLICT")
        self.assertEqual(refused_v3["written"], [])
        self.assertEqual((target / managed_rel).read_bytes(), merged_v2)
        self.assertEqual(receipt_path.read_bytes(), receipt_before_v3)

        resolved_v3 = source_root.parent / "resolved-v3.md"
        merged_v3 = b"# Task\ninstruction: project + upstream-v3\n"
        resolved_v3.write_bytes(merged_v3)
        cli = [sys.executable, "-I", "-B", str(pack_v3 / "files/.aide/scripts/aide_lite.py"), "--repo-root", str(target), "import-pack", "--pack", str(pack_v3), "--target", str(target), "--from-pack", str(pack_v2), "--resolve", managed_rel, str(resolved_v3)]
        preview_cli = subprocess.run([*cli, "--dry-run", "--explain"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(preview_cli.returncode, 0, preview_cli.stderr)
        self.assertIn("status: PLANNED", preview_cli.stdout)
        self.assertIn("resolve_owned", preview_cli.stdout)
        self.assertIn("rationale_status=unknown", preview_cli.stdout)
        self.assertNotIn(str(resolved_v3), preview_cli.stdout)
        preview_digest = next(line.partition(": ")[2] for line in preview_cli.stdout.splitlines() if line.startswith("plan_digest: "))
        applied_cli = subprocess.run([*cli, "--expect-plan", preview_digest], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(applied_cli.returncode, 0, applied_cli.stderr)
        self.assertIn("status: APPLIED", applied_cli.stdout)
        self.assertEqual((target / managed_rel).read_bytes(), merged_v3)
        entry_v3 = json.loads(receipt_path.read_text(encoding="utf-8"))["managed"][managed_rel]
        self.assertEqual(entry_v3["installed_digest"], aide_lite.digest_bytes(merged_v3))
        self.assertNotEqual(entry_v3["installed_digest"], entry_v3["source_digest"])

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_missing_receipt_owned_file_refuses_implicit_recreation(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "missing-owned-v1")
        target = source_root.parent / "target-missing-owned"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt_before = receipt_path.read_bytes()
        (target / managed_rel).unlink()
        aide_lite.write_text(source_root / managed_rel, "# Incoming changed prompt\n")
        pack_v2 = self.freeze_pack(source_root, "missing-owned-v2")

        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        operation = next(item for item in preview["operations"] if item["target"] == managed_rel)
        self.assertEqual(preview["status"], "PLANNED_CONFLICT")
        self.assertEqual(operation["action"], "conflict")
        self.assertIn(managed_rel, preview["conflicts"])
        applied = aide_lite.apply_import_pack(
            pack_v2, target, predecessor_pack=pack_v1,
            expected_plan_digest=preview["plan_digest"],
        )
        self.assertEqual(applied["status"], "CONFLICT")
        self.assertEqual(applied["written"], [])
        self.assertFalse((target / managed_rel).exists())
        self.assertEqual(receipt_path.read_bytes(), receipt_before)
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_resolution_preview_binds_bytes_and_predecessor_without_leaking_path(self) -> None:
        source_root = self.make_source_repo()
        rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "resolution-bound-v1")
        target = source_root.parent / "resolution-bound-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        (target / rel).write_bytes(b"project edit\n")
        aide_lite.write_text(source_root / rel, "upstream v2\n")
        pack_v2 = self.freeze_pack(source_root, "resolution-bound-v2")
        resolved = source_root.parent / "private-resolution.txt"
        resolved.write_bytes(b"project and upstream v2\n")
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        before = receipt_path.read_bytes()
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1, resolutions={rel: resolved})
        self.assertEqual(preview["status"], "PLANNED")
        self.assertNotIn(str(resolved), json.dumps(preview))
        with self.assertRaisesRegex(ValueError, "predecessor pack"):
            aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v2, resolutions={rel: resolved})
        resolved.write_bytes(b"changed after preview\n")
        stale = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, resolutions={rel: resolved}, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(stale["status"], "STALE_PLAN")
        self.assertEqual(receipt_path.read_bytes(), before)
        self.assertEqual((target / rel).read_bytes(), b"project edit\n")
        hard_link = source_root.parent / "hard-link-resolution.txt"
        os.link(target / rel, hard_link)
        with self.assertRaisesRegex(ValueError, "hard-linked"):
            aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1, resolutions={rel: hard_link})

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_resolution_change_after_intent_refuses_and_recovery_preserves_local(self) -> None:
        source_root = self.make_source_repo()
        rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "resolution-race-v1")
        target = source_root.parent / "resolution-race-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        (target / rel).write_bytes(b"local bytes\n")
        aide_lite.write_text(source_root / rel, "incoming bytes\n")
        pack_v2 = self.freeze_pack(source_root, "resolution-race-v2")
        resolved = source_root.parent / "resolution-race.txt"
        resolved.write_bytes(b"approved combination\n")
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1, resolutions={rel: resolved})
        original_write = aide_lite.portable_import_write_exact
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        before = receipt_path.read_bytes()

        def swap_after_intent(root: Path, target_rel: str, data: bytes, preimage: str, backup_rel: str | None = None):
            result = original_write(root, target_rel, data, preimage, backup_rel)
            if target_rel == aide_lite.PORTABLE_IMPORT_INTENT_PATH:
                resolved.write_bytes(b"rival combination\n")
            return result

        with mock.patch.object(aide_lite, "portable_import_write_exact", side_effect=swap_after_intent):
            stopped = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, resolutions={rel: resolved}, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(stopped["status"], "INTERRUPTED")
        self.assertEqual(stopped["written"], [])
        self.assertEqual((target / rel).read_bytes(), b"local bytes\n")
        self.assertEqual(receipt_path.read_bytes(), before)
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
        retry = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, resolutions={rel: resolved}, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(retry["status"], "STALE_PLAN")
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_v2_optional_disable_persists_and_legacy_guards_refuse_skipped_path(self) -> None:
        source_root = self.make_source_repo()
        optional = ".aide.local.example/secrets/README.md"
        pack_v1 = self.freeze_pack(source_root, "disabled-v1")
        target = source_root.parent / "disabled-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        controls_path = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
        aide_lite.write_text(controls_path, aide_lite.stable_json_text({
            "schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2,
            "entries": {},
            "disabled_features": [{"feature_id": "local_state_examples", "rationale": "The project maintains its own examples."}],
        }))
        aide_lite.write_text(source_root / optional, "upstream optional v2\n")
        pack_v2 = self.freeze_pack(source_root, "disabled-v2")
        before = (target / optional).read_bytes()
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        optional_op = next(op for op in preview["operations"] if op["target"] == optional)
        self.assertEqual(optional_op["action"], "preserve_disabled")
        explained = next(item for item in aide_lite.explain_import_result(preview, target) if item["target"] == optional)
        self.assertEqual(explained["project_rationale"], "The project maintains its own examples.")
        aide_lite.write_text(controls_path, aide_lite.stable_json_text({"schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2, "entries": {}, "disabled_features": [{"feature_id": "local_state_examples"}]}))
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, expected_plan_digest=preview["plan_digest"])["status"], "STALE_PLAN")
        self.assertEqual((target / optional).read_bytes(), before)
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        unexplained = next(item for item in aide_lite.explain_import_result(preview, target) if item["target"] == optional)
        self.assertEqual(unexplained["project_rationale"], "unknown")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, expected_plan_digest=preview["plan_digest"])["status"], "APPLIED")
        self.assertEqual((target / optional).read_bytes(), before)
        receipt = aide_lite.load_portable_import_receipt(target)
        self.assertEqual(receipt["disabled_features"], ["local_state_examples"])
        self.assertNotIn(optional, receipt["managed"])
        self.assertNotIn(optional, [op["target"] for op in aide_lite.build_portable_removal_plan(target)["operations"]])
        with self.assertRaisesRegex(ValueError, "receipt-owned"):
            aide_lite.apply_portable_owned_repair(pack_v2, target, optional, dry_run=True)
        with self.assertRaises(ValueError):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        aide_lite.write_text(source_root / optional, "upstream optional v3\n")
        pack_v3 = self.freeze_pack(source_root, "disabled-v3")
        preview_v3 = aide_lite.apply_import_pack(pack_v3, target, dry_run=True, predecessor_pack=pack_v2)
        self.assertEqual(aide_lite.apply_import_pack(pack_v3, target, predecessor_pack=pack_v2, expected_plan_digest=preview_v3["plan_digest"])["status"], "APPLIED")
        self.assertEqual((target / optional).read_bytes(), before)
        controls_path.unlink()
        with self.assertRaisesRegex(ValueError, "disabled-feature controls missing"):
            aide_lite.apply_import_pack(pack_v3, target, dry_run=True)
        aide_lite.write_text(controls_path, aide_lite.stable_json_text({"schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2, "entries": {}, "disabled_features": [{"feature_id": "unknown", "rationale": "x"}]}))
        with self.assertRaisesRegex(ValueError, "unknown or duplicate disabled feature"):
            aide_lite.apply_import_pack(pack_v3, target, dry_run=True)

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_v1_receipt_crlf_agents_is_read_as_managed_not_project_overlay(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "v1-crlf-pack")
        target = source_root.parent / "v1-crlf-target"
        target.mkdir()
        (target / "AGENTS.md").write_bytes(b"# Authored\r\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt = aide_lite.load_portable_import_receipt(target)
        agents = receipt["managed"]["AGENTS.md"]
        self.assertNotEqual(agents["installed_digest"], agents["source_digest"])
        self.assertEqual(agents["ownership"], "aide_portable_managed")
        self.assertFalse(agents["local_overlay"])
        receipt["schema_version"] = aide_lite.PORTABLE_IMPORT_RECEIPT_SCHEMA
        receipt.pop("disabled_features")
        receipt.pop("project_controls_digest")
        for entry in receipt["managed"].values():
            entry.pop("local_overlay")
        receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
        path.write_text(aide_lite.stable_json_text(receipt), encoding="utf-8")
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]["ownership"], "aide_portable_managed")
        plan = aide_lite.build_portable_removal_plan(target)
        agents_row = next(item for item in plan["operations"] if item["target"] == "AGENTS.md")
        self.assertTrue(agents_row["removal_candidate"])

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_receipt_owned_crlf_agents_section_updates_when_upstream_changes(self) -> None:
        source_root = self.make_source_repo()
        pack_v1 = self.freeze_pack(source_root, "agents-crlf-v1")
        pack_v2 = source_root.parent / "agents-crlf-v2"
        shutil.copytree(pack_v1, pack_v2)
        template = pack_v2 / "files/AGENTS.md.template"
        before = template.read_bytes()
        heading = b"## AIDE Lite Portable Guidance"
        self.assertEqual(before.count(heading), 1)
        template.write_bytes(before.replace(heading, b"## AIDE Lite Portable Guidance changed upstream", 1))
        aide_lite.write_text(pack_v2 / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack_v2)))
        self.assertTrue(aide_lite.validate_pack_checksums(pack_v2)[0])
        pack_v3 = source_root.parent / "agents-crlf-v3"
        shutil.copytree(pack_v2, pack_v3)
        prompt = pack_v3 / "files/.aide/prompts/compact-task.md"
        prompt.write_bytes(prompt.read_bytes() + b"\n# Changed upstream outside AGENTS\n")
        aide_lite.write_text(pack_v3 / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack_v3)))
        self.assertTrue(aide_lite.validate_pack_checksums(pack_v3)[0])

        for receipt_version in ("v1", "v2"):
            with self.subTest(receipt_version=receipt_version):
                target = source_root.parent / f"agents-crlf-target-{receipt_version}"
                target.mkdir()
                agents_path = target / "AGENTS.md"
                authored = b"# Authored project guidance\r\n"
                agents_path.write_bytes(authored)
                self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
                receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
                receipt = aide_lite.load_portable_import_receipt(target)
                agents_entry = receipt["managed"]["AGENTS.md"]
                self.assertNotEqual(agents_entry["installed_digest"], agents_entry["source_digest"])
                self.assertFalse(agents_entry["local_overlay"])
                authored_suffix = b"\r\n# Authored closing guidance\r\n"
                agents_path.write_bytes(agents_path.read_bytes() + authored_suffix)
                if receipt_version == "v1":
                    receipt["schema_version"] = aide_lite.PORTABLE_IMPORT_RECEIPT_SCHEMA
                    receipt.pop("disabled_features")
                    receipt.pop("project_controls_digest")
                    for entry in receipt["managed"].values():
                        entry.pop("local_overlay")
                    receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
                    receipt_path.write_text(aide_lite.stable_json_text(receipt), encoding="utf-8")

                preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
                agents_operation = next(item for item in preview["operations"] if item["target"] == "AGENTS.md")
                self.assertEqual(agents_operation["action"], "update_owned")
                self.assertEqual(preview["status"], "PLANNED")
                self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, expected_plan_digest=preview["plan_digest"])["status"], "APPLIED")
                updated = agents_path.read_bytes()
                self.assertTrue(updated.startswith(authored))
                self.assertTrue(updated.endswith(authored_suffix))
                self.assertIn(b"Portable Guidance changed upstream", updated)
                self.assertIn(b"\r\n", updated)
                self.assertFalse(aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]["local_overlay"])

                unrelated_preview = aide_lite.apply_import_pack(pack_v3, target, dry_run=True, predecessor_pack=pack_v2)
                unrelated_agents = next(item for item in unrelated_preview["operations"] if item["target"] == "AGENTS.md")
                self.assertEqual(unrelated_agents["action"], "unchanged")
                self.assertEqual(aide_lite.apply_import_pack(pack_v3, target, predecessor_pack=pack_v2, expected_plan_digest=unrelated_preview["plan_digest"])["status"], "APPLIED")
                self.assertEqual(agents_path.read_bytes(), updated)
                self.assertFalse(aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]["local_overlay"])

                if receipt_version == "v2":
                    edited = updated.replace(b"Portable Guidance changed upstream", b"Project-edited portable guidance", 1)
                    agents_path.write_bytes(edited)
                    pack_v4 = source_root.parent / "agents-crlf-v4"
                    shutil.copytree(pack_v3, pack_v4)
                    prompt_v4 = pack_v4 / "files/.aide/prompts/compact-task.md"
                    prompt_v4.write_bytes(prompt_v4.read_bytes() + b"# Another upstream prompt change\n")
                    aide_lite.write_text(pack_v4 / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack_v4)))
                    overlay_preview = aide_lite.apply_import_pack(pack_v4, target, dry_run=True, predecessor_pack=pack_v3)
                    overlay_agents = next(item for item in overlay_preview["operations"] if item["target"] == "AGENTS.md")
                    self.assertEqual(overlay_agents["action"], "preserve_local")
                    self.assertEqual(aide_lite.apply_import_pack(pack_v4, target, predecessor_pack=pack_v3, expected_plan_digest=overlay_preview["plan_digest"])["status"], "APPLIED")
                    self.assertEqual(agents_path.read_bytes(), edited)
                    self.assertTrue(aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]["local_overlay"])
                    pack_v5 = source_root.parent / "agents-crlf-v5"
                    shutil.copytree(pack_v4, pack_v5)
                    template_v5 = pack_v5 / "files/AGENTS.md.template"
                    template_v5.write_bytes(template_v5.read_bytes().replace(b"Portable Guidance changed upstream", b"Portable Guidance changed upstream again", 1))
                    aide_lite.write_text(pack_v5 / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack_v5)))
                    overlay_receipt = receipt_path.read_bytes()
                    conflict_preview = aide_lite.apply_import_pack(pack_v5, target, dry_run=True, predecessor_pack=pack_v4)
                    conflict_agents = next(item for item in conflict_preview["operations"] if item["target"] == "AGENTS.md")
                    self.assertEqual(conflict_agents["action"], "conflict")
                    self.assertEqual(conflict_preview["status"], "PLANNED_CONFLICT")
                    self.assertEqual(aide_lite.apply_import_pack(pack_v5, target, predecessor_pack=pack_v4)["status"], "CONFLICT")
                    self.assertEqual(agents_path.read_bytes(), edited)
                    self.assertEqual(receipt_path.read_bytes(), overlay_receipt)

                    forged = json.loads(overlay_receipt.decode("utf-8"))
                    forged_agents = forged["managed"]["AGENTS.md"]
                    forged_agents["ownership"] = "aide_portable_managed"
                    forged_agents["local_overlay"] = False
                    forged["receipt_digest"] = aide_lite.portable_import_record_digest(forged, "receipt_digest")
                    receipt_path.write_text(aide_lite.stable_json_text(forged), encoding="utf-8")
                    self.assertEqual(aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]["installed_digest"], forged_agents["installed_digest"])
                    for prior in (pack_v4, None):
                        with self.subTest(forged_receipt_predecessor=prior is not None):
                            forged_preview = aide_lite.apply_import_pack(pack_v5, target, dry_run=True, predecessor_pack=prior)
                            forged_operation = next(item for item in forged_preview["operations"] if item["target"] == "AGENTS.md")
                            self.assertEqual(forged_operation["action"], "conflict")
                            self.assertEqual(forged_preview["status"], "PLANNED_CONFLICT")
                            self.assertEqual(aide_lite.apply_import_pack(pack_v5, target, predecessor_pack=prior)["status"], "CONFLICT")
                            self.assertEqual(agents_path.read_bytes(), edited)

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_disabled_controls_swap_at_receipt_effect_keeps_intent_for_reconciliation(self) -> None:
        source_root = self.make_source_repo()
        pack_v1 = self.freeze_pack(source_root, "controls-race-v1")
        target = source_root.parent / "controls-race-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        controls = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
        enabled = {"schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2, "entries": {}, "disabled_features": [{"feature_id": "local_state_examples"}]}
        controls.write_text(aide_lite.stable_json_text(enabled), encoding="utf-8")
        pack_v2 = self.freeze_pack(source_root, "controls-race-v2")
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        original_write = aide_lite.portable_import_write_exact

        def swap_after_receipt(root: Path, target_rel: str, data: bytes, preimage: str, backup_rel: str | None = None):
            result = original_write(root, target_rel, data, preimage, backup_rel)
            if target_rel == aide_lite.PORTABLE_IMPORT_RECEIPT_PATH:
                controls.write_text(aide_lite.stable_json_text({**enabled, "disabled_features": []}), encoding="utf-8")
            return result

        with mock.patch.object(aide_lite, "portable_import_write_exact", side_effect=swap_after_receipt):
            stopped = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(stopped["status"], "INTERRUPTED")
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).is_file())
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target)["status"], "RECOVERY_REQUIRED")
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).is_file())

    @unittest.skipUnless(sys.platform == "win32", "anchored portable import apply is Windows only")
    def test_malformed_v2_controls_refuse_while_v1_bad_rationale_stays_advisory(self) -> None:
        source_root = self.make_source_repo()
        optional = ".aide.local.example/secrets/README.md"
        pack_v1 = self.freeze_pack(source_root, "controls-malformed-v1")
        target = source_root.parent / "controls-malformed-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt_before = receipt_path.read_bytes()
        optional_before = (target / optional).read_bytes()
        controls = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
        controls.write_bytes(b'{"schema_version":"aide.project-customizations.v2","disabled_features":[')
        aide_lite.write_text(source_root / optional, "changed optional example\n")
        pack_v2 = self.freeze_pack(source_root, "controls-malformed-v2")
        with self.assertRaisesRegex(ValueError, "invalid project customizations JSON"):
            aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        with self.assertRaisesRegex(ValueError, "invalid project customizations JSON"):
            aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)
        self.assertEqual((target / optional).read_bytes(), optional_before)
        self.assertEqual(receipt_path.read_bytes(), receipt_before)
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
        controls.write_text(aide_lite.stable_json_text({"schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA, "entries": {optional: {"observed_digest": "invalid", "rationale": ""}}}), encoding="utf-8")
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "NO_CHANGES")
        preview = aide_lite.apply_import_pack(pack_v1, target, dry_run=True)
        with self.assertRaisesRegex(ValueError, "invalid project customization digest"):
            aide_lite.explain_import_result(preview, target)

    def test_validated_predecessor_pack_can_prove_an_unrecorded_baseline(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "predecessor-v1")
        target = source_root.parent / "target-predecessor-update"
        aide_lite.apply_import_pack(pack_v1, target)
        (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).unlink()

        aide_lite.write_text(source_root / managed_rel, "# Proven predecessor v2\n")
        pack_v2 = self.freeze_pack(source_root, "predecessor-v2")
        preview = aide_lite.apply_import_pack(
            pack_v2,
            target,
            dry_run=True,
            predecessor_pack=pack_v1,
        )
        operation = next(item for item in preview["operations"] if item["target"] == managed_rel)
        self.assertEqual(operation["action"], "update_owned")
        self.assertEqual(operation["ownership_basis"], "validated_predecessor_pack")
        result = aide_lite.apply_import_pack(
            pack_v2,
            target,
            predecessor_pack=pack_v1,
            expected_plan_digest=preview["plan_digest"],
        )
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(aide_lite.read_text(target / managed_rel), "# Proven predecessor v2\n")

    def test_tampered_predecessor_pack_is_rejected_before_target_writes(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "tampered-predecessor-v1")
        target = source_root.parent / "target-tampered-predecessor"
        aide_lite.apply_import_pack(pack_v1, target)
        (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).unlink()
        target_before = (target / managed_rel).read_bytes()

        aide_lite.write_text(source_root / managed_rel, "# Tampered predecessor incoming\n")
        pack_v2 = self.freeze_pack(source_root, "tampered-predecessor-v2")
        aide_lite.write_text(pack_v1 / "files" / managed_rel, "# Invalid predecessor bytes\n")
        with self.assertRaisesRegex(ValueError, "invalid predecessor pack checksums"):
            aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)
        self.assertEqual((target / managed_rel).read_bytes(), target_before)
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())

    def test_locally_edited_portable_agents_section_is_preserved_when_upstream_unchanged(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "agents-section-v1")
        target = source_root.parent / "target-agents-section"
        aide_lite.write_text(target / "AGENTS.md", "# Target Agents\n\nManual guidance.\n")
        aide_lite.apply_import_pack(pack, target)
        agents = aide_lite.read_text(target / "AGENTS.md")
        aide_lite.write_text(target / "AGENTS.md", agents.replace("## AIDE Lite Portable Guidance", "## Locally edited portable guidance"))
        edited = (target / "AGENTS.md").read_bytes()

        result = aide_lite.apply_import_pack(pack, target)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["written"], [])
        self.assertEqual(result["conflicts"], [])
        self.assertEqual((target / "AGENTS.md").read_bytes(), edited)
        self.assertIn("Manual guidance.", aide_lite.read_text(target / "AGENTS.md"))
        self.assertIn("Locally edited portable guidance", aide_lite.read_text(target / "AGENTS.md"))
        entry = aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]
        self.assertEqual(entry["ownership"], "project_overlay_on_aide_managed")
        self.assertTrue(entry["local_overlay"])
        removal = next(item for item in aide_lite.build_portable_removal_plan(target)["operations"] if item["target"] == "AGENTS.md")
        self.assertEqual(removal["action"], "preserve_project_overlay")

    def test_local_edits_and_unknown_ownership_refuse_before_any_payload_write(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        second_rel = ".aide/policies/token-budget.yaml"
        pack_v1 = self.freeze_pack(source_root, "conflict-v1")
        target = source_root.parent / "target-local-edit"
        aide_lite.apply_import_pack(pack_v1, target)
        receipt_before = (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes()
        aide_lite.write_text(target / managed_rel, "# User-owned local edit\n")
        second_before = (target / second_rel).read_bytes()
        aide_lite.write_text(source_root / managed_rel, "# Incoming v2\n")
        aide_lite.write_text(source_root / second_rel, "version: incoming-v2\n")
        pack_v2 = self.freeze_pack(source_root, "conflict-v2")

        result = aide_lite.apply_import_pack(pack_v2, target)
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(result["written"], [])
        self.assertIn(managed_rel, result["conflicts"])
        self.assertEqual(aide_lite.read_text(target / managed_rel), "# User-owned local edit\n")
        self.assertEqual((target / second_rel).read_bytes(), second_before)
        self.assertEqual((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_before)

        unknown = source_root.parent / "target-unknown-ownership"
        aide_lite.write_text(unknown / managed_rel, "# Existing unknown bytes\n")
        unknown_result = aide_lite.apply_import_pack(pack_v2, unknown)
        self.assertEqual(unknown_result["status"], "CONFLICT")
        self.assertEqual(unknown_result["written"], [])
        self.assertFalse((unknown / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())

    def test_customization_explains_project_owned_and_conflicting_direct_edits(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "customization-v1")
        target = source_root.parent / "target-customized"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        profile = target / ".aide/profile.yaml"
        aide_lite.write_text(profile, aide_lite.read_text(profile) + "project_adapter: local\n")
        aide_lite.write_text(target / managed_rel, "# Direct project edit\n")
        profile_bytes = profile.read_bytes()
        managed_bytes = (target / managed_rel).read_bytes()
        receipt_bytes = (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes()
        aide_lite.write_text(source_root / managed_rel, "# Conflicting upstream revision\n")
        pack_v2 = self.freeze_pack(source_root, "customization-v2")

        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        self.assertEqual(preview["status"], "PLANNED_CONFLICT")
        unknown = {item["target"]: item for item in aide_lite.explain_import_result(preview, target)}
        self.assertEqual(unknown[".aide/profile.yaml"]["action"], "preserve")
        self.assertEqual(unknown[".aide/profile.yaml"]["project_rationale"], "unknown")
        self.assertEqual(unknown[managed_rel]["action"], "conflict")
        self.assertEqual(unknown[managed_rel]["rationale_status"], "unknown")
        self.assertEqual(unknown[managed_rel]["observed_digest"], aide_lite.digest_bytes(managed_bytes))

        aide_lite.write_text(target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH, json.dumps({
            "schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA,
            "entries": {
                ".aide/profile.yaml": {"observed_digest": aide_lite.digest_bytes(profile_bytes), "rationale": "Keep the project adapter active."},
                managed_rel: {"observed_digest": aide_lite.digest_bytes(managed_bytes), "rationale": "Project command wording is intentional."},
            },
        }))
        known = {item["target"]: item for item in aide_lite.explain_import_result(preview, target)}
        self.assertEqual(known[".aide/profile.yaml"]["project_rationale"], "Keep the project adapter active.")
        self.assertEqual(known[managed_rel]["project_rationale"], "Project command wording is intentional.")
        aide_lite.write_text(profile, aide_lite.read_text(profile) + "intervening_edit: true\n")
        changed_after_preview = {item["target"]: item for item in aide_lite.explain_import_result(preview, target)}
        self.assertEqual(changed_after_preview[".aide/profile.yaml"]["project_rationale"], "unknown")
        profile.write_bytes(profile_bytes)
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target)["status"], "CONFLICT")
        self.assertEqual(profile.read_bytes(), profile_bytes)
        self.assertEqual((target / managed_rel).read_bytes(), managed_bytes)
        self.assertEqual((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_bytes)

        aide_lite.write_text(profile, aide_lite.read_text(profile) + "local_note: changed_again\n")
        stale_preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True)
        stale = {item["target"]: item for item in aide_lite.explain_import_result(stale_preview, target)}
        self.assertEqual(stale[".aide/profile.yaml"]["project_rationale"], "unknown")
        self.assertEqual(stale[".aide/profile.yaml"]["rationale_status"], "unknown")

    def test_feedback_is_explicit_local_and_malformed_rationale_refuses_explanation(self) -> None:
        source_root = self.make_source_repo()
        pack_root = self.freeze_pack(source_root, "feedback-pack")
        target = source_root.parent / "target-feedback"
        self.assertEqual(aide_lite.apply_import_pack(pack_root, target)["status"], "APPLIED")
        script = source_root / ".aide/scripts/aide_lite.py"
        feedback = source_root.parent / "feedback.json"
        command = [sys.executable, str(script), "--repo-root", str(source_root), "import-pack", "--pack", str(pack_root), "--target", str(target)]

        ordinary = subprocess.run([*command, "--dry-run"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(ordinary.returncode, 0, ordinary.stdout + ordinary.stderr)
        self.assertFalse(feedback.exists())
        requested = subprocess.run([*command, "--dry-run", "--explain", "--feedback-out", str(feedback)], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(requested.returncode, 0, requested.stdout + requested.stderr)
        packet = json.loads(aide_lite.read_text(feedback))
        self.assertEqual(packet["sharing"], "manual_only")
        self.assertFalse(packet["network_calls"])
        self.assertTrue(all("observed_digest" in item and "incoming_digest" in item for item in packet["explanations"]))
        self.assertTrue(any(item["target"] == ".aide/profile.yaml" for item in packet["explanations"]))
        self.assertTrue(all(item["project_rationale"] == "unknown" for item in packet["explanations"]))
        self.assertFalse((target / "feedback.json").exists())
        self.assertEqual(aide_lite.apply_import_pack(pack_root, target)["status"], "NO_CHANGES")

        refused = subprocess.run([*command, "--feedback-out", str(source_root.parent / "forbidden.json")], capture_output=True, text=True, encoding="utf-8")
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((source_root.parent / "forbidden.json").exists())
        aide_lite.write_text(target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH, '{"schema_version": "wrong", "entries": {}}')
        with self.assertRaisesRegex(ValueError, "invalid project customizations schema"):
            aide_lite.explain_import_result(aide_lite.apply_import_pack(pack_root, target, dry_run=True), target)
        self.assertEqual(aide_lite.apply_import_pack(pack_root, target)["status"], "NO_CHANGES")

    def test_feedback_boundary_cli_refuses_each_input_root(self) -> None:
        # Real output checks and packet identity; only the costly plan is injected.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            incoming, previous, target = (root / name for name in ("incoming", "previous", "target"))
            for directory in (incoming, previous, target):
                directory.mkdir()
                (directory / "manifest.yaml").write_text("pack_id: tiny-boundary\n", encoding="utf-8")
                (directory / "checksums.json").write_text("{}\n", encoding="utf-8")
            before = {p: p.read_bytes() for directory in (incoming, previous, target) for p in directory.iterdir()}
            result = {"status": "PLANNED", "plan_digest": "a" * 64, "mode": "safe",
                      "operation_count": 0, "operations": [], "conflicts": [], "skipped": [], "written": []}
            parser = aide_lite.build_parser(REPO_ROOT)
            for directory in (previous, incoming, target):
                with self.subTest(directory=directory):
                    output = directory / "feedback.json"
                    args = parser.parse_args(["import-pack", "--pack", str(incoming), "--target", str(target),
                        "--from-pack", str(previous), "--dry-run", "--feedback-out", str(output)])
                    with mock.patch.object(aide_lite, "apply_import_pack", return_value=result), mock.patch("builtins.print"):
                        with self.assertRaisesRegex(ValueError, "outside"):
                            args.handler(args)
                    self.assertFalse(output.exists())
            self.assertEqual({p: p.read_bytes() for directory in (incoming, previous, target) for p in directory.iterdir()}, before)
            output = root / "external-feedback.json"
            args = parser.parse_args(["import-pack", "--pack", str(incoming), "--target", str(target),
                "--from-pack", str(previous), "--dry-run", "--feedback-out", str(output)])
            with mock.patch.object(aide_lite, "apply_import_pack", return_value=result), mock.patch("builtins.print"):
                self.assertEqual(args.handler(args), 0)
            self.assertEqual(json.loads(output.read_bytes())["sharing"], "manual_only")
            self.assertEqual({p: p.read_bytes() for directory in (incoming, previous, target) for p in directory.iterdir()}, before)

    def test_feedback_boundary_external_packet_and_no_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            incoming, target = root / "incoming", root / "target"
            incoming.mkdir(); target.mkdir()
            (incoming / "manifest.yaml").write_text("pack_id: tiny-boundary\n", encoding="utf-8")
            (incoming / "checksums.json").write_text("{}\n", encoding="utf-8")
            result = {"status": "PLANNED", "plan_digest": "a" * 64}
            output = root / "feedback.json"
            # Preserve callers that do not supply a predecessor.
            aide_lite.write_import_feedback(output, incoming, target, result, [])
            original = output.read_bytes()
            packet = json.loads(original)
            self.assertEqual(packet["pack"], aide_lite.import_pack_identity(incoming))
            self.assertEqual(packet["sharing"], "manual_only")
            self.assertFalse(packet["network_calls"])
            with self.assertRaisesRegex(ValueError, "new file"):
                aide_lite.write_import_feedback(output, incoming, target, result, [])
            self.assertEqual(output.read_bytes(), original)
            with self.assertRaisesRegex(ValueError, "existing directory"):
                aide_lite.write_import_feedback(root / "missing" / "feedback.json", incoming, target, result, [])
            self.assertFalse((root / "missing").exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows junction boundary")
    def test_feedback_boundary_predecessor_junction_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            previous, incoming, target = (root / name for name in ("previous", "incoming", "target"))
            for directory in (previous, incoming, target): directory.mkdir()
            alias = root / "alias"
            created = subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(previous)],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(created.returncode, 0, created.stderr)
            try:
                with self.assertRaisesRegex(ValueError, "outside"):
                    aide_lite.write_import_feedback(alias / "feedback.json", incoming, target,
                        {"status": "PLANNED", "plan_digest": "a" * 64}, [], predecessor_pack=previous)
                self.assertFalse((previous / "feedback.json").exists())
            finally:
                # Retire only the fixture junction; do not traverse its target.
                if alias.is_junction(): alias.rmdir()

    def test_changed_target_refuses_an_exact_preview_identity(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "stale-v1")
        target = source_root.parent / "target-stale-plan"
        aide_lite.apply_import_pack(pack_v1, target)
        aide_lite.write_text(source_root / managed_rel, "# Stale preview incoming\n")
        pack_v2 = self.freeze_pack(source_root, "stale-v2")
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True, predecessor_pack=pack_v1)
        receipt_before = (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes()
        aide_lite.write_text(target / managed_rel, "# Changed after preview\n")

        result = aide_lite.apply_import_pack(
            pack_v2,
            target,
            predecessor_pack=pack_v1,
            expected_plan_digest=preview["plan_digest"],
        )
        self.assertEqual(result["status"], "STALE_PLAN")
        self.assertEqual(result["written"], [])
        self.assertEqual(aide_lite.read_text(target / managed_rel), "# Changed after preview\n")
        self.assertEqual((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_before)

    def test_interrupted_update_retains_exact_partial_state_and_refuses_replay(self) -> None:
        source_root = self.make_source_repo()
        first_rel = ".aide/prompts/compact-task.md"
        second_rel = ".aide/policies/token-budget.yaml"
        pack_v1 = self.freeze_pack(source_root, "interrupt-v1")
        target = source_root.parent / "target-interrupted-update"
        aide_lite.apply_import_pack(pack_v1, target)
        aide_lite.write_text(source_root / first_rel, "# Interrupted incoming one\n")
        aide_lite.write_text(source_root / second_rel, "version: interrupted-two\n")
        pack_v2 = self.freeze_pack(source_root, "interrupt-v2")

        interrupted = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, fail_after_writes=1)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).is_file())
        self.assertEqual(len(interrupted["written"]), 1)

        resumed = aide_lite.apply_import_pack(pack_v2, target)
        self.assertEqual(resumed["status"], "RECOVERY_REQUIRED")
        self.assertEqual(resumed["recovery"]["classification"], "partial")
        self.assertEqual(resumed["written"], [])
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).is_file())

    @unittest.skipUnless(sys.platform == "win32", "anchored partial import recovery is Windows only")
    def test_explicit_partial_recovery_finishes_fresh_and_predecessor_update(self) -> None:
        source_root = self.make_source_repo(minimal_recovery=True)
        first_rel = ".aide/prompts/compact-task.md"
        second_rel = ".aide/policies/token-budget.yaml"
        pack_v1 = self.freeze_pack(source_root, "partial-recover-v1")
        target = source_root.parent / "partial-recover-target"
        target.mkdir()
        authored = target / "project-owned.txt"
        authored.write_bytes(b"Keep project bytes.\r\n")

        first = aide_lite.apply_import_pack(pack_v1, target, fail_after_writes=1)
        self.assertEqual(first["status"], "INTERRUPTED")
        self.assertEqual(first["recovery"]["classification"], "partial")
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "RECOVERY_REQUIRED")
        original_apply = aide_lite.apply_import_operation
        attempted = 0
        def interrupt_recovery(*args: object, **kwargs: object) -> bool:
            nonlocal attempted
            attempted += 1
            if attempted == 2:
                raise RuntimeError("simulated second interruption")
            return original_apply(*args, **kwargs)
        with mock.patch.object(aide_lite, "apply_import_operation", side_effect=interrupt_recovery):
            second_interruption = aide_lite.apply_import_pack(
                pack_v1, target, expected_plan_digest=first["plan_digest"], recover_partial=True
            )
        self.assertEqual(second_interruption["status"], "RECOVERY_REQUIRED")
        self.assertEqual(second_interruption["recovery"]["classification"], "partial")
        resumed = aide_lite.apply_import_pack(
            pack_v1, target, expected_plan_digest=first["plan_digest"], recover_partial=True
        )
        self.assertEqual(resumed["status"], "RECOVERED")
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["pack"], aide_lite.import_pack_identity(pack_v1))
        self.assertEqual(authored.read_bytes(), b"Keep project bytes.\r\n")

        aide_lite.write_text(source_root / first_rel, "# Changed by successor one\n")
        aide_lite.write_text(source_root / second_rel, "version: successor-two\n")
        pack_v2 = self.freeze_pack(source_root, "partial-recover-v2")
        second = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, fail_after_writes=1)
        self.assertEqual(second["status"], "INTERRUPTED")
        self.assertEqual(second["recovery"]["classification"], "partial")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "RECOVERY_REQUIRED")
        resumed_update = aide_lite.apply_import_pack(
            pack_v2, target, predecessor_pack=pack_v1,
            expected_plan_digest=second["plan_digest"], recover_partial=True,
        )
        self.assertEqual(resumed_update["status"], "RECOVERED")
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["pack"], aide_lite.import_pack_identity(pack_v2))
        self.assertEqual((target / first_rel).read_text(encoding="utf-8"), "# Changed by successor one\n")
        self.assertEqual((target / second_rel).read_text(encoding="utf-8"), "version: successor-two\n")
        self.assertEqual(authored.read_bytes(), b"Keep project bytes.\r\n")

    @unittest.skipUnless(sys.platform == "win32", "anchored partial import recovery is Windows only")
    def test_partial_recovery_refuses_wrong_inputs_rivals_and_old_intent(self) -> None:
        source_root = self.make_source_repo(minimal_recovery=True)
        pack_v1 = self.freeze_pack(source_root, "partial-refusal-v1")
        target = source_root.parent / "partial-refusal-target"
        aide_lite.apply_import_pack(pack_v1, target)
        aide_lite.write_text(source_root / ".aide/prompts/compact-task.md", "# Incoming one\n")
        aide_lite.write_text(source_root / ".aide/policies/token-budget.yaml", "version: incoming-two\n")
        pack_v2 = self.freeze_pack(source_root, "partial-refusal-v2")
        interrupted = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, fail_after_writes=1)
        self.assertEqual(interrupted["recovery"]["classification"], "partial")

        def state() -> dict[str, str]:
            return {item.relative_to(target).as_posix(): aide_lite.sha256_file(item)
                for item in target.rglob("*") if item.is_file()}

        before = state()
        for label, current, previous, digest, mode in (
            ("wrong-plan", pack_v2, pack_v1, "0" * 64, "safe"),
            ("wrong-pack", pack_v1, None, interrupted["plan_digest"], "safe"),
            ("missing-predecessor", pack_v2, None, interrupted["plan_digest"], "safe"),
            ("wrong-mode", pack_v2, pack_v1, interrupted["plan_digest"], "full"),
        ):
            with self.subTest(label=label):
                refused = aide_lite.apply_import_pack(current, target, mode=mode,
                    predecessor_pack=previous, expected_plan_digest=digest, recover_partial=True)
                self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
                self.assertEqual(state(), before)

        unwritten = next(item["target"] for item in interrupted["operations"]
            if item["action"] in {"copy", "update_owned"} and item["target"] not in interrupted["written"]
            and item["preimage_digest"] != item["postimage_digest"])
        rival = target / unwritten
        original = rival.read_bytes() if rival.exists() else None
        rival.parent.mkdir(parents=True, exist_ok=True)
        rival.write_bytes(b"# Rival project edit\n")
        rival_state = state()
        refused = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1,
            expected_plan_digest=interrupted["plan_digest"], recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertEqual(state(), rival_state)
        if original is None:
            rival.unlink()
        else:
            rival.write_bytes(original)

        controls = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
        aide_lite.write_text(controls, aide_lite.stable_json_text({
            "schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2,
            "entries": {}, "disabled_features": [],
        }))
        control_state = state()
        refused = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1,
            expected_plan_digest=interrupted["plan_digest"], recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertEqual(state(), control_state)
        controls.unlink()

        already_written = target / interrupted["written"][0]
        second_link = target / "project-hardlink-copy"
        os.link(already_written, second_link)
        linked_state = state()
        refused = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1,
            expected_plan_digest=interrupted["plan_digest"], recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertEqual(state(), linked_state)
        second_link.unlink()

        intent_path = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        old_intent = aide_lite.load_portable_import_intent(target)
        old_intent.pop("plan_snapshot")
        old_intent["intent_digest"] = aide_lite.portable_import_record_digest(old_intent, "intent_digest")
        intent_path.write_text(aide_lite.stable_json_text(old_intent), encoding="utf-8")
        legacy_state = state()
        refused = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1,
            expected_plan_digest=interrupted["plan_digest"], recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertEqual(state(), legacy_state)

    @unittest.skipUnless(sys.platform == "win32", "anchored partial import recovery is Windows only")
    def test_partial_recovery_requires_exact_manual_resolution_bytes(self) -> None:
        source_root = self.make_source_repo(minimal_recovery=True)
        resolved_rel = ".aide/prompts/compact-task.md"
        other_rel = ".aide/policies/token-budget.yaml"
        pack_v1 = self.freeze_pack(source_root, "partial-resolution-v1")
        target = source_root.parent / "partial-resolution-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        (target / resolved_rel).write_bytes(b"project edit\n")
        aide_lite.write_text(source_root / resolved_rel, "upstream edit\n")
        aide_lite.write_text(source_root / other_rel, "version: other-edit\n")
        pack_v2 = self.freeze_pack(source_root, "partial-resolution-v2")
        merged = source_root.parent / "manual-merge.txt"
        merged.write_bytes(b"project and upstream\n")
        resolution = {resolved_rel: merged}
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True,
            predecessor_pack=pack_v1, resolutions=resolution)
        self.assertEqual(preview["status"], "PLANNED")
        interrupted = aide_lite.apply_import_pack(pack_v2, target,
            predecessor_pack=pack_v1, resolutions=resolution,
            expected_plan_digest=preview["plan_digest"], fail_after_writes=1)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        self.assertEqual(interrupted["recovery"]["classification"], "partial")
        receipt_before = (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes()
        merged.write_bytes(b"rival merged bytes\n")
        refused = aide_lite.apply_import_pack(pack_v2, target,
            predecessor_pack=pack_v1, resolutions=resolution,
            expected_plan_digest=preview["plan_digest"], recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertEqual((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_before)
        merged.write_bytes(b"project and upstream\n")
        original_delete = aide_lite.portable_import_delete_exact
        resolution_blocked = False
        def change_resolution_at_retirement(*args: object, **kwargs: object) -> None:
            nonlocal resolution_blocked
            try:
                merged.write_bytes(b"changed during retirement\n")
            except OSError:
                resolution_blocked = True
            original_delete(*args, **kwargs)
        with mock.patch.object(aide_lite, "portable_import_delete_exact", side_effect=change_resolution_at_retirement):
            recovered = aide_lite.apply_import_pack(pack_v2, target,
                predecessor_pack=pack_v1, resolutions=resolution,
                expected_plan_digest=preview["plan_digest"], recover_partial=True)
        self.assertEqual(recovered["status"], "RECOVERED")
        self.assertTrue(resolution_blocked)
        self.assertEqual(merged.read_bytes(), b"project and upstream\n")
        self.assertEqual((target / resolved_rel).read_bytes(), b"project and upstream\n")
        self.assertEqual((target / other_rel).read_text(encoding="utf-8"), "version: other-edit\n")

    @unittest.skipUnless(sys.platform == "win32", "anchored partial import recovery is Windows only")
    def test_redigested_partial_intent_cannot_relabel_authored_file_as_owned(self) -> None:
        source_root = self.make_source_repo(minimal_recovery=True)
        pack = self.freeze_pack(source_root, "forged-partial")
        target = source_root.parent / "forged-partial-target"
        first = aide_lite.apply_import_pack(pack, target, fail_after_writes=1)
        self.assertEqual(first["recovery"]["classification"], "partial")
        intent_path = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        intent = aide_lite.load_portable_import_intent(target)
        snapshot = intent["plan_snapshot"]
        operation = next(item for item in snapshot["operations"]
            if item["kind"] == "managed_file" and item["action"] == "copy"
            and item["target"] not in first["written"])
        authored = target / operation["target"]
        authored.parent.mkdir(parents=True, exist_ok=True)
        authored.write_bytes(b"authored after interruption\n")
        authored_digest = aide_lite.sha256_file(authored)
        operation["action"] = "update_owned"
        operation["ownership_basis"] = "installed_receipt"
        operation["preimage_digest"] = authored_digest
        forged_plan = aide_lite.import_plan_digest(pack, target, "safe",
            snapshot["operations"], [], snapshot["skipped"], None)
        intent["plan_digest"] = forged_plan
        intent["next_receipt"] = aide_lite.build_portable_import_receipt(
            pack, "safe", snapshot["operations"], forged_plan, None)
        intent["receipt_postimage_digest"] = aide_lite.digest_bytes(
            aide_lite.stable_json_text(intent["next_receipt"]).encode("utf-8"))
        pending_operation = next(item for item in intent["operations"] if item["target"] == operation["target"])
        pending_operation["preimage_digest"] = authored_digest
        relative = Path(operation["target"])
        pending_operation["backup_rel"] = (relative.parent /
            f".{relative.name}.aide-import-backup-{forged_plan[:20]}").as_posix()
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        intent_path.write_text(aide_lite.stable_json_text(intent), encoding="utf-8")
        self.assertEqual(aide_lite.classify_portable_import_recovery(target, intent)["classification"], "partial")

        refused = aide_lite.apply_import_pack(pack, target,
            expected_plan_digest=forged_plan, recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertEqual(authored.read_bytes(), b"authored after interruption\n")
        self.assertTrue(intent_path.exists())

    @unittest.skipUnless(sys.platform == "win32", "anchored partial import recovery is Windows only")
    def test_partial_recovery_blocks_controls_change_during_publication_and_retirement(self) -> None:
        source_root = self.make_source_repo(minimal_recovery=True)
        pack = self.freeze_pack(source_root, "partial-controls-race")
        for boundary in ("receipt", "retirement"):
            with self.subTest(boundary=boundary):
                target = source_root.parent / f"partial-controls-{boundary}-target"
                interrupted = aide_lite.apply_import_pack(pack, target, fail_after_writes=1)
                self.assertEqual(interrupted["recovery"]["classification"], "partial")
                controls = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
                original_write = aide_lite.portable_import_write_exact
                original_delete = aide_lite.portable_import_delete_exact
                attempted = blocked = False
                def change_controls() -> None:
                    nonlocal attempted, blocked
                    attempted = True
                    try:
                        aide_lite.write_text(controls, aide_lite.stable_json_text({
                            "schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2,
                            "entries": {}, "disabled_features": [],
                        }))
                    except OSError:
                        blocked = True
                def receipt_write(root: Path, target_rel: str, data: bytes, preimage: str,
                    backup_rel: str | None = None):
                    result = original_write(root, target_rel, data, preimage, backup_rel)
                    if boundary == "receipt" and target_rel == aide_lite.PORTABLE_IMPORT_RECEIPT_PATH:
                        change_controls()
                    return result
                def intent_delete(*args: object, **kwargs: object) -> None:
                    if boundary == "retirement":
                        change_controls()
                    original_delete(*args, **kwargs)
                with mock.patch.object(aide_lite, "portable_import_write_exact", side_effect=receipt_write), \
                    mock.patch.object(aide_lite, "portable_import_delete_exact", side_effect=intent_delete):
                    result = aide_lite.apply_import_pack(pack, target,
                        expected_plan_digest=interrupted["plan_digest"], recover_partial=True)
                self.assertTrue(attempted)
                self.assertTrue(blocked)
                self.assertEqual(result["status"], "RECOVERED")
                self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
                self.assertFalse(controls.exists())
                self.assertEqual(aide_lite.load_portable_import_receipt(target)["project_controls_digest"], "missing")

    @unittest.skipUnless(sys.platform == "win32", "Windows missing-controls handle reservation")
    def test_missing_controls_guard_blocks_writer_and_cleans_after_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            (target / ".aide").mkdir(parents=True)
            controls = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
            with aide_lite.portable_import_guard_missing_controls(target):
                rival = subprocess.run([sys.executable, "-I", "-B", "-c",
                    "import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(b'rival')",
                    str(controls)], capture_output=True, text=True, check=False)
                self.assertNotEqual(rival.returncode, 0)
            self.assertFalse(controls.exists())
            child_code = """import importlib.util, sys, os
from pathlib import Path
spec = importlib.util.spec_from_file_location('aide_lite', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules['aide_lite'] = module
spec.loader.exec_module(module)
with module.portable_import_guard_missing_controls(Path(sys.argv[2])):
    os._exit(77)
"""
            child = subprocess.run([sys.executable, "-I", "-B", "-c", child_code,
                str(MODULE_PATH), str(target)], capture_output=True, text=True, check=False)
            self.assertEqual(child.returncode, 77, child.stderr)
            self.assertFalse(controls.exists())

    @unittest.skipUnless(sys.platform == "win32", "anchored partial import recovery is Windows only")
    def test_redigested_partial_intent_cannot_omit_payload_coverage(self) -> None:
        source_root = self.make_source_repo(minimal_recovery=True)
        pack = self.freeze_pack(source_root, "omitted-partial")
        target = source_root.parent / "omitted-partial-target"
        interrupted = aide_lite.apply_import_pack(pack, target, fail_after_writes=1)
        self.assertEqual(interrupted["recovery"]["classification"], "partial")
        intent_path = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        intent = aide_lite.load_portable_import_intent(target)
        snapshot = intent["plan_snapshot"]
        omitted = next(item for item in snapshot["operations"]
            if item["kind"] == "managed_file" and item["action"] == "copy"
            and item["target"] not in interrupted["written"])
        snapshot["operations"].remove(omitted)
        intent["operations"] = [item for item in intent["operations"]
            if item["target"] != omitted["target"]]
        forged_plan = aide_lite.import_plan_digest(pack, target, "safe",
            snapshot["operations"], [], snapshot["skipped"], None)
        intent["plan_digest"] = forged_plan
        intent["next_receipt"] = aide_lite.build_portable_import_receipt(
            pack, "safe", snapshot["operations"], forged_plan, None)
        intent["receipt_postimage_digest"] = aide_lite.digest_bytes(
            aide_lite.stable_json_text(intent["next_receipt"]).encode("utf-8"))
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        intent_path.write_text(aide_lite.stable_json_text(intent), encoding="utf-8")
        self.assertEqual(aide_lite.classify_portable_import_recovery(target, intent)["classification"], "partial")
        refused = aide_lite.apply_import_pack(pack, target,
            expected_plan_digest=forged_plan, recover_partial=True)
        self.assertEqual(refused["status"], "RECOVERY_REQUIRED")
        self.assertTrue(intent_path.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows junction boundary")
    def test_rollback_pack_rejects_reparse_payload_and_pack_roots(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        pack = root / "pack"
        payload = root / "external-payload"
        pack.mkdir()
        payload.mkdir()
        (payload / "a.txt").write_bytes(b"fixture bytes")
        (pack / "manifest.yaml").write_text("included_files:\n  - files/a.txt\n", encoding="utf-8")
        files_root = pack / "files"
        pack_alias = root / "pack-alias"
        try:
            junction = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(files_root), str(payload)],
                capture_output=True, text=True, encoding="utf-8", check=False,
            )
            self.assertEqual(junction.returncode, 0, junction.stderr)
            aide_lite.write_text(pack / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack)))
            self.assertEqual(aide_lite.validate_pack_checksums(pack), (True, []))
            with self.assertRaisesRegex(ValueError, "reparse"):
                aide_lite.portable_safe_pack_targets(pack)

            junction = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(pack_alias), str(pack)],
                capture_output=True, text=True, encoding="utf-8", check=False,
            )
            self.assertEqual(junction.returncode, 0, junction.stderr)
            with self.assertRaisesRegex(ValueError, "reparse"):
                aide_lite.portable_safe_pack_targets(pack_alias)
            target = root / "target"
            target.mkdir()
            with self.assertRaisesRegex(ValueError, "reparse"):
                aide_lite.build_portable_rollback_plan(pack_alias, pack, target)
            cli = subprocess.run(
                [sys.executable, "-B", str(MODULE_PATH), "--repo-root", str(target),
                 "rollback-pack", "--current-pack", str(pack_alias),
                 "--previous-pack", str(pack), "--target", str(target),
                 "--dry-run", "--json"],
                capture_output=True, text=True, encoding="utf-8", timeout=15)
            self.assertNotEqual(cli.returncode, 0)
            self.assertIn("reparse", cli.stderr)
        finally:
            if pack_alias.is_junction():
                pack_alias.rmdir()
            if files_root.is_junction():
                files_root.rmdir()

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_exact_predecessor_rollback_restores_owned_bytes_and_receipt(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "rollback-v1")
        target = source_root.parent / "target-rollback"
        aide_lite.write_text(target / "README.md", "# Project authored\n")
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        old_bytes = (target / managed_rel).read_bytes()
        aide_lite.write_text(source_root / managed_rel, "# Upstream v2\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-v2")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "APPLIED")
        self.assertNotEqual((target / managed_rel).read_bytes(), old_bytes)

        preview = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual(preview["status"], "PLANNED")
        installed_cli = target / ".aide/scripts/aide_lite.py"
        command = [sys.executable, str(installed_cli), "--repo-root", str(target), "rollback-pack", "--current-pack", str(pack_v2), "--previous-pack", str(pack_v1), "--target", str(target), "--json"]
        cli_preview = subprocess.run([*command, "--dry-run"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(cli_preview.returncode, 0, cli_preview.stderr)
        self.assertEqual(json.loads(cli_preview.stdout)["plan_digest"], preview["plan_digest"])
        cli_apply = subprocess.run([*command, "--expect-plan", preview["plan_digest"]], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(cli_apply.returncode, 0, cli_apply.stderr)
        result = json.loads(cli_apply.stdout)
        self.assertEqual(result["status"], "ROLLED_BACK")
        self.assertEqual((target / managed_rel).read_bytes(), old_bytes)
        self.assertEqual(aide_lite.read_text(target / "README.md"), "# Project authored\n")
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["pack"], aide_lite.import_pack_identity(pack_v1))

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_rollback_preserves_authored_crlf_agents_and_rejects_changed_section(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "rollback-crlf-v1")
        target = source_root.parent / "target-rollback-crlf"
        target.mkdir()
        authored_prefix = b"# Authored project policy\r\n"
        authored_suffix = b"\r\n# Authored closing policy\r\n"
        agents_path = target / "AGENTS.md"
        agents_path.write_bytes(authored_prefix)
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        v1_payload = (target / managed_rel).read_bytes()
        agents_path.write_bytes(agents_path.read_bytes() + authored_suffix)

        aide_lite.write_text(source_root / managed_rel, "# Changed upstream in v2\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-crlf-v2")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "APPLIED")
        v2_agents = agents_path.read_bytes()
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt_bytes = receipt_path.read_bytes()
        receipt = aide_lite.load_portable_import_receipt(target)
        entry = receipt["managed"]["AGENTS.md"]
        source_block = aide_lite.portable_managed_block(aide_lite.read_text(pack_v2 / "files/AGENTS.md.template"))
        installed_block = aide_lite.portable_managed_block(v2_agents.decode("utf-8"))
        self.assertIsNotNone(source_block)
        self.assertIsNotNone(installed_block)
        self.assertNotEqual(entry["installed_digest"], entry["source_digest"])
        self.assertEqual(entry["source_digest"], aide_lite.digest_bytes(source_block.encode("utf-8")))
        self.assertEqual(entry["installed_digest"], aide_lite.digest_bytes(installed_block.encode("utf-8")))
        self.assertEqual(installed_block.replace("\r\n", "\n"), source_block)

        preview = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual(preview["status"], "PLANNED")
        marker = b"<!-- AIDE-PORTABLE:END section=aide-lite-pack-v0 -->"
        self.assertEqual(v2_agents.count(marker), 1)
        changed_agents = v2_agents.replace(marker, b"# Direct managed-block edit\r\n" + marker, 1)
        agents_path.write_bytes(changed_agents)
        stale = aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, preview["plan_digest"])
        self.assertEqual(stale["status"], "STALE_PLAN")
        self.assertEqual(aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)["status"], "CONFLICT")
        self.assertEqual(agents_path.read_bytes(), changed_agents)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

        forged = json.loads(receipt_bytes.decode("utf-8"))
        forged_block = aide_lite.portable_managed_block(changed_agents.decode("utf-8"))
        self.assertIsNotNone(forged_block)
        forged["managed"]["AGENTS.md"]["installed_digest"] = aide_lite.digest_bytes(forged_block.encode("utf-8"))
        forged["receipt_digest"] = aide_lite.portable_import_record_digest(forged, "receipt_digest")
        aide_lite.write_text(receipt_path, aide_lite.stable_json_text(forged))
        with self.assertRaisesRegex(ValueError, "baseline differs from current pack"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)

        receipt_path.write_bytes(receipt_bytes)
        agents_path.write_bytes(v2_agents)
        rolled = aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, preview["plan_digest"])
        self.assertEqual(rolled["status"], "ROLLED_BACK")
        self.assertEqual((target / managed_rel).read_bytes(), v1_payload)
        after_agents = agents_path.read_bytes()
        self.assertTrue(after_agents.startswith(authored_prefix))
        self.assertTrue(after_agents.endswith(authored_suffix))
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["pack"], aide_lite.import_pack_identity(pack_v1))

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_rollback_preserves_authored_edit_and_refuses_stale_or_wrong_lineage(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "rollback-edits-v1")
        target = source_root.parent / "target-rollback-edits"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        aide_lite.write_text(source_root / managed_rel, "# Upstream changed bytes\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-edits-v2")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "APPLIED")
        preview = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt_bytes = receipt_path.read_bytes()
        authored = b"# Project changed after v2\n"
        (target / managed_rel).write_bytes(authored)
        stale = aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, preview["plan_digest"])
        self.assertEqual(stale["status"], "STALE_PLAN")
        conflicted = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual(conflicted["status"], "CONFLICT")
        self.assertEqual(aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, conflicted["plan_digest"])["status"], "CONFLICT")
        self.assertEqual((target / managed_rel).read_bytes(), authored)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        wrong_previous = source_root.parent / "rollback-wrong-predecessor"
        shutil.copytree(pack_v1, wrong_previous)
        aide_lite.write_text(wrong_previous / "files" / managed_rel, "# Similar paths, different predecessor\n")
        aide_lite.write_text(wrong_previous / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(wrong_previous)))
        self.assertEqual(aide_lite.validate_pack_checksums(wrong_previous), (True, []))
        with self.assertRaisesRegex(ValueError, "exact receipt lineage"):
            aide_lite.build_portable_rollback_plan(pack_v2, wrong_previous, target)
        with self.assertRaisesRegex(ValueError, "exact receipt lineage"):
            aide_lite.build_portable_rollback_plan(pack_v1, pack_v2, target)
        forged_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        forged_receipt["managed"][managed_rel]["installed_digest"] = aide_lite.digest_bytes(authored)
        forged_receipt["managed"][managed_rel]["ownership"] = "project_overlay_on_aide_managed"
        forged_receipt["managed"][managed_rel]["local_overlay"] = True
        forged_receipt["receipt_digest"] = aide_lite.portable_import_record_digest(forged_receipt, "receipt_digest")
        aide_lite.write_text(receipt_path, aide_lite.stable_json_text(forged_receipt))
        with self.assertRaisesRegex(ValueError, "baseline differs from current pack"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual((target / managed_rel).read_bytes(), authored)

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_rollback_refuses_changed_payload_path_set(self) -> None:
        source_root = self.make_source_repo()
        pack_v1 = self.freeze_pack(source_root, "rollback-paths-v1")
        added_rel = ".aide/prompts/compact-task.md"
        (pack_v1 / "files" / added_rel).unlink()
        manifest = aide_lite.read_text(pack_v1 / "manifest.yaml")
        aide_lite.write_text(pack_v1 / "manifest.yaml", manifest.replace(f"  - files/{added_rel}\n", ""))
        aide_lite.write_text(pack_v1 / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack_v1)))
        self.assertEqual(aide_lite.validate_pack_checksums(pack_v1), (True, []))
        target = source_root.parent / "target-rollback-paths"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        aide_lite.write_text(source_root / ".aide/policies/token-budget.yaml", "version: changed-budget\n")
        aide_lite.write_text(source_root / ".aide/policies/recovery.yaml", "version: changed-recovery\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-paths-v2")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "APPLIED")
        receipt_before = (target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes()
        with self.assertRaisesRegex(ValueError, "payload paths differ"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertTrue((target / added_rel).is_file())
        self.assertEqual((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_before)
        generic_reverse = aide_lite.apply_import_pack(pack_v1, target,
            predecessor_pack=pack_v2, fail_after_writes=1)
        self.assertEqual(generic_reverse["status"], "INTERRUPTED")
        self.assertEqual(generic_reverse["recovery"]["classification"], "partial")
        intent_path = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        intent_before = intent_path.read_bytes()
        target_before = (target / generic_reverse["written"][0]).read_bytes()
        with self.assertRaisesRegex(ValueError, "payload paths differ"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        with self.assertRaisesRegex(ValueError, "payload paths differ"):
            aide_lite.apply_portable_rollback(pack_v2, pack_v1, target,
                generic_reverse["plan_digest"], recover_partial=True)
        self.assertEqual(intent_path.read_bytes(), intent_before)
        self.assertEqual((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_before)
        self.assertEqual((target / generic_reverse["written"][0]).read_bytes(), target_before)

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_interrupted_rollback_retains_intent_and_requires_reconciliation(self) -> None:
        source_root = self.make_source_repo()
        first_rel = ".aide/prompts/compact-task.md"
        second_rel = ".aide/policies/token-budget.yaml"
        pack_v1 = self.freeze_pack(source_root, "rollback-interrupt-v1")
        target = source_root.parent / "target-rollback-interrupt"
        aide_lite.write_text(target / "README.md", "# Authored\n")
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        aide_lite.write_text(source_root / first_rel, "# Second release one\n")
        aide_lite.write_text(source_root / second_rel, "version: second-release\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-interrupt-v2")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "APPLIED")
        preview = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        interrupted = aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, preview["plan_digest"], fail_after_writes=1)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        self.assertEqual(len(interrupted["written"]), 1)
        intent_path = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        self.assertTrue(intent_path.is_file())
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["pack"], aide_lite.import_pack_identity(pack_v2))
        intent_bytes, receipt_bytes = intent_path.read_bytes(), receipt_path.read_bytes()
        retry = aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, preview["plan_digest"])
        self.assertEqual(retry["status"], "RECOVERY_REQUIRED")
        self.assertEqual(intent_path.read_bytes(), intent_bytes)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        self.assertEqual(aide_lite.read_text(target / "README.md"), "# Authored\n")

        recovery_preview = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual(recovery_preview["status"], "RECOVERY_REQUIRED")
        self.assertEqual(recovery_preview["recovery"]["classification"], "partial")
        recovery_digest = recovery_preview["recovery_plan_digest"]
        self.assertRegex(recovery_digest, r"^[0-9a-f]{64}$")
        reversed_pair = aide_lite.apply_portable_rollback(
            pack_v1, pack_v2, target, recovery_digest, recover_partial=True)
        self.assertEqual(reversed_pair["status"], "RECOVERY_REQUIRED")
        wrong_digest = aide_lite.apply_portable_rollback(
            pack_v2, pack_v1, target, "0" * 64, recover_partial=True)
        self.assertEqual(wrong_digest["status"], "STALE_PLAN")
        changed_path = target / interrupted["written"][0]
        written_bytes = changed_path.read_bytes()
        changed_path.write_bytes(b"rival project edit\n")
        rival = aide_lite.apply_portable_rollback(
            pack_v2, pack_v1, target, recovery_digest, recover_partial=True)
        self.assertEqual(rival["status"], "RECOVERY_REQUIRED")
        self.assertEqual(intent_path.read_bytes(), intent_bytes)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)
        changed_path.write_bytes(written_bytes)
        installed_cli = pack_v2 / "files/.aide/scripts/aide_lite.py"
        command = [sys.executable, "-B", str(installed_cli), "--repo-root", str(target),
            "rollback-pack", "--current-pack", str(pack_v2), "--previous-pack", str(pack_v1),
            "--target", str(target), "--recover-partial", "--expect-plan", recovery_digest, "--json"]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "ROLLED_BACK_RECOVERED")
        self.assertFalse(intent_path.exists())
        self.assertEqual(aide_lite.load_portable_import_receipt(target)["pack"], aide_lite.import_pack_identity(pack_v1))
        self.assertEqual(aide_lite.read_text(target / "README.md"), "# Authored\n")

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_rollback_refuses_pending_prior_update_without_touching_intent(self) -> None:
        source_root = self.make_source_repo()
        first_rel = ".aide/prompts/compact-task.md"
        second_rel = ".aide/policies/token-budget.yaml"
        pack_v1 = self.freeze_pack(source_root, "rollback-prior-intent-v1")
        target = source_root.parent / "target-rollback-prior-intent"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        aide_lite.write_text(source_root / first_rel, "# Pending release one\n")
        aide_lite.write_text(source_root / second_rel, "version: pending-release\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-prior-intent-v2")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, fail_after_writes=1)["status"], "INTERRUPTED")
        intent_path = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        intent_bytes, receipt_bytes = intent_path.read_bytes(), receipt_path.read_bytes()
        preview = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual(preview["status"], "RECOVERY_REQUIRED")
        with self.assertRaisesRegex(ValueError, "exact preview digest"):
            aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, "")
        self.assertEqual(intent_path.read_bytes(), intent_bytes)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

    @unittest.skipUnless(sys.platform == "win32", "anchored portable rollback apply is Windows only")
    def test_rollback_refuses_pending_removal_before_receipt_or_target_reinterpretation(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "rollback-removal-v1")
        aide_lite.write_text(source_root / managed_rel, "# Updated before removal\n")
        pack_v2 = self.freeze_pack(source_root, "rollback-removal-v2")

        target = source_root.parent / "rollback-removal-pending"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1)["status"], "APPLIED")
        prior_rollback = aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        removal = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(aide_lite.apply_portable_removal(target, removal["plan_digest"], fail_after_removals=1)["status"], "INTERRUPTED")
        intent_path = target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        intent_bytes, receipt_bytes = intent_path.read_bytes(), receipt_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "removal recovery must complete before rollback"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        with self.assertRaisesRegex(ValueError, "removal recovery must complete before rollback"):
            aide_lite.apply_portable_rollback(pack_v2, pack_v1, target, prior_rollback["plan_digest"])
        self.assertEqual(intent_path.read_bytes(), intent_bytes)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

        intent_path.write_bytes(b"{malformed")
        with self.assertRaisesRegex(ValueError, "invalid portable removal intent"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, target)
        self.assertEqual(intent_path.read_bytes(), b"{malformed")

        retired_target = source_root.parent / "rollback-removal-retired"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, retired_target)["status"], "APPLIED")
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, retired_target, predecessor_pack=pack_v1)["status"], "APPLIED")
        retired_plan = aide_lite.build_portable_removal_plan(retired_target)
        self.assertEqual(aide_lite.apply_portable_removal(retired_target, retired_plan["plan_digest"], fail_after_receipt=True)["status"], "INTERRUPTED")
        retired_intent = retired_target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        retired_bytes = retired_intent.read_bytes()
        self.assertFalse((retired_target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        with self.assertRaisesRegex(ValueError, "removal recovery must complete before rollback"):
            aide_lite.build_portable_rollback_plan(pack_v2, pack_v1, retired_target)
        self.assertEqual(retired_intent.read_bytes(), retired_bytes)

    def test_dry_run_never_reconciles_a_pending_import_intent(self) -> None:
        source_root = self.make_source_repo()
        managed_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "recovery-dry-v1")
        target = source_root.parent / "target-recovery-dry"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target)["status"], "APPLIED")
        receipt = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        intent = target / aide_lite.PORTABLE_IMPORT_INTENT_PATH

        aide_lite.write_text(source_root / managed_rel, "# Recovery candidate two\n")
        pack_v2 = self.freeze_pack(source_root, "recovery-dry-v2")
        interrupted = aide_lite.apply_import_pack(pack_v2, target, predecessor_pack=pack_v1, fail_after_writes=1)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        self.assertEqual(interrupted["recovery"]["classification"], "completed")
        intent_before = intent.read_bytes()
        receipt_before = receipt.read_bytes()
        target_before = (target / managed_rel).read_bytes()
        preview = aide_lite.apply_import_pack(pack_v2, target, dry_run=True)
        self.assertEqual(preview["status"], "RECOVERY_REQUIRED")
        self.assertTrue(preview["dry_run"])
        self.assertEqual(preview["recovery"]["classification"], "completed")
        self.assertEqual(intent.read_bytes(), intent_before)
        self.assertEqual(receipt.read_bytes(), receipt_before)

        self.assertEqual((target / managed_rel).read_bytes(), target_before)

        script = source_root / ".aide/scripts/aide_lite.py"
        feedback = source_root.parent / "recovery-feedback.json"
        command = [sys.executable, str(script), "--repo-root", str(source_root), "import-pack", "--pack", str(pack_v2), "--target", str(target), "--dry-run", "--feedback-out", str(feedback)]
        refused = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(feedback.exists())
        self.assertEqual(intent.read_bytes(), intent_before)
        self.assertEqual(receipt.read_bytes(), receipt_before)
        self.assertEqual(aide_lite.apply_import_pack(pack_v2, target)["status"], "RECOVERED")

        aide_lite.write_text(source_root / managed_rel, "# Recovery candidate three\n")
        pack_v3 = self.freeze_pack(source_root, "recovery-dry-v3")
        preimage = (target / managed_rel).read_bytes()
        interrupted = aide_lite.apply_import_pack(pack_v3, target, predecessor_pack=pack_v2, fail_after_writes=1)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        (target / managed_rel).write_bytes(preimage)
        intent_before = intent.read_bytes()
        receipt_before = receipt.read_bytes()
        preview = aide_lite.apply_import_pack(pack_v3, target, dry_run=True)
        self.assertEqual(preview["status"], "RECOVERY_REQUIRED")
        self.assertEqual(preview["recovery"]["classification"], "no_effect")
        self.assertEqual(intent.read_bytes(), intent_before)
        self.assertEqual(receipt.read_bytes(), receipt_before)

    def test_pack_cannot_supply_project_owned_customization_metadata(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "reserved-project-metadata")
        payload = pack / "files" / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
        aide_lite.write_text(payload, '{"schema_version":"aide.project-customizations.v1","entries":{}}\n')
        checksums_path = pack / "checksums.json"
        checksums = json.loads(aide_lite.read_text(checksums_path))
        checksums["checksums"]["files/" + aide_lite.PROJECT_CUSTOMIZATIONS_PATH] = aide_lite.sha256_file(payload)
        aide_lite.write_text(checksums_path, json.dumps(checksums, sort_keys=True) + "\n")
        self.assertTrue(aide_lite.validate_pack_checksums(pack)[0])
        target = source_root.parent / "reserved-project-target"
        original = b'{"project":"owned"}\n'
        authored = target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH
        authored.parent.mkdir(parents=True)
        authored.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "reserved project/import state"):
            aide_lite.apply_import_pack(pack, target)
        self.assertEqual(authored.read_bytes(), original)
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
        payload.unlink()
        checksums["checksums"].pop("files/" + aide_lite.PROJECT_CUSTOMIZATIONS_PATH)
        alias_rel = ".aide/CUSTOMIZATIONS.JSON"
        alias_payload = pack / "files" / alias_rel
        aide_lite.write_text(alias_payload, '{"schema_version":"aide.project-customizations.v1","entries":{}}\n')
        checksums["checksums"]["files/" + alias_rel] = aide_lite.sha256_file(alias_payload)
        aide_lite.write_text(checksums_path, json.dumps(checksums, sort_keys=True) + "\n")
        self.assertTrue(aide_lite.validate_pack_checksums(pack)[0])
        with self.assertRaisesRegex(ValueError, "reserved project/import state"):
            aide_lite.apply_import_pack(pack, target)
        self.assertEqual(authored.read_bytes(), original)

    def test_import_payload_does_not_follow_a_swapped_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target_root = root / "target"
            parent = target_root / ".aide" / "prompts"
            parent.mkdir(parents=True)
            parked = target_root / ".aide" / "prompts-parked"
            outside = root / "outside"
            outside.mkdir()
            self.assertEqual(parent.resolve().parent, (target_root / ".aide").resolve())
            self.assertEqual(parked.parent.resolve(), (target_root / ".aide").resolve())

            source_rel = ".aide/prompts/compact-task.md"
            payload = b"# Portable managed content\n"
            pack_root = root / "pack"
            source = pack_root / "files" / source_rel
            source.parent.mkdir(parents=True)
            source.write_bytes(payload)
            operation = {
                "action": "copy",
                "target": source_rel,
                "source": source_rel,
                "kind": "managed_file",
                "preimage_digest": "missing",
                "postimage_digest": aide_lite.digest_bytes(payload),
            }

            original_mkstemp = tempfile.mkstemp
            attempted = False

            def swap_before_staging(*args: object, **kwargs: object) -> tuple[int, str]:
                nonlocal attempted
                if Path(str(kwargs.get("dir"))) == parent and not attempted:
                    attempted = True
                    try:
                        parent.rename(parked)
                    except PermissionError:
                        # A pinned ancestor that denies deletion has already
                        # closed this interleaving; staging can continue.
                        pass
                    else:
                        if sys.platform == "win32":
                            junction = subprocess.run(
                                ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
                                capture_output=True,
                                text=True,
                                encoding="utf-8",
                            )
                            self.assertEqual(junction.returncode, 0, junction.stderr)
                        else:
                            parent.symlink_to(outside, target_is_directory=True)
                return original_mkstemp(*args, **kwargs)

            try:
                with mock.patch.object(aide_lite.tempfile, "mkstemp", side_effect=swap_before_staging):
                    try:
                        aide_lite.apply_import_operation(pack_root, target_root, operation)
                    except (OSError, RuntimeError, ValueError):
                        pass
                outside_entries = list(outside.iterdir())
            finally:
                if parent.is_symlink():
                    parent.unlink()
                elif getattr(parent, "is_junction", lambda: False)():
                    parent.rmdir()
                if parked.exists():
                    parked.rename(parent)

            self.assertTrue(attempted, "the importer must exercise the staging boundary")
            self.assertEqual(outside_entries, [], "import wrote through a swapped parent")

    def test_import_payload_does_not_clobber_a_racing_leaf(self) -> None:
        for initial in (None, b"# Previously managed content\n"):
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                target_root = root / "target"
                target = target_root / ".aide" / "prompts" / "compact-task.md"
                target.parent.mkdir(parents=True)
                if initial is not None:
                    target.write_bytes(initial)
                pack_root = root / "pack"
                source_rel = ".aide/prompts/compact-task.md"
                source = pack_root / "files" / source_rel
                source.parent.mkdir(parents=True)
                source.write_bytes(b"# Updated managed content\n")
                operation = {
                    "action": "copy" if initial is None else "update_owned",
                    "target": source_rel,
                    "source": source_rel,
                    "kind": "managed_file",
                    "preimage_digest": "missing" if initial is None else aide_lite.digest_bytes(initial),
                    "postimage_digest": aide_lite.digest_bytes(source.read_bytes()),
                }
                competing = b"# Concurrent project edit\n"
                original_mkstemp = tempfile.mkstemp
                attempted = False

                def change_leaf_after_preimage(*args: object, **kwargs: object) -> tuple[int, str]:
                    nonlocal attempted
                    descriptor, temporary_name = original_mkstemp(*args, **kwargs)
                    if Path(str(kwargs.get("dir"))) == target.parent and not attempted:
                        attempted = True
                        target.write_bytes(competing)
                    return descriptor, temporary_name

                with mock.patch.object(aide_lite.tempfile, "mkstemp", side_effect=change_leaf_after_preimage):
                    try:
                        aide_lite.apply_import_operation(pack_root, target_root, operation)
                    except (OSError, RuntimeError, ValueError):
                        pass
                self.assertTrue(attempted, "the importer must exercise the staging boundary")
                self.assertEqual(target.read_bytes(), competing, "import replaced a concurrent project edit")

    @unittest.skipUnless(sys.platform == "win32", "requires Windows guarded staging")
    def test_atomic_create_staged_bytes_deny_rival_writer(self) -> None:
        for relative in (".aide/install/aide-lite-pack-v0.repair-intent.json", ".aide/prompts/compact-task.md"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                target = Path(raw) / relative
                target.parent.mkdir(parents=True)
                original_link = aide_lite.windows_link_from_handle
                attempted = False

                def rival_before_publication(descriptor: int, directory_handle: int, leaf_name: str) -> None:
                    nonlocal attempted
                    stage = list(target.parent.glob(f".{target.name}.*.tmp"))
                    self.assertEqual(len(stage), 1)
                    attempted = True
                    with self.assertRaises(OSError):
                        stage[0].write_bytes(b"rival bytes")
                    original_link(descriptor, directory_handle, leaf_name)

                with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=rival_before_publication):
                    aide_lite.atomic_create_bytes_no_clobber(target, b"expected bytes")
                self.assertTrue(attempted)
                self.assertEqual(target.read_bytes(), b"expected bytes")
                self.assertEqual(list(target.parent.iterdir()), [target])

    @unittest.skipUnless(sys.platform == "win32", "requires Windows guarded staging")
    def test_import_staged_bytes_refuse_rival_before_guard(self) -> None:
        for relative in (".aide/install/aide-lite-pack-v0.repair-intent.json", ".aide/prompts/compact-task.md"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                target = Path(raw) / relative
                target.parent.mkdir(parents=True)
                original_verified = aide_lite.portable_import_verified_leaf
                attempted = False

                def rival_before_guard(path: Path, expected: str, *, writable: bool = False) -> tuple[object, object]:
                    nonlocal attempted
                    if writable and not attempted:
                        attempted = True
                        path.write_bytes(b"rival bytes")
                    return original_verified(path, expected, writable=writable)

                with mock.patch.object(aide_lite, "portable_import_verified_leaf", side_effect=rival_before_guard):
                    with self.assertRaises(RuntimeError):
                        aide_lite.portable_import_write_exact(Path(raw), relative, b"expected bytes", "missing")
                self.assertTrue(attempted)
                self.assertFalse(target.exists())
                stages = list(target.parent.glob(f".{target.name}.*.tmp"))
                self.assertEqual(len(stages), 1)
                self.assertEqual(stages[0].read_bytes(), b"rival bytes")

    @unittest.skipUnless(sys.platform == "win32", "requires Windows guarded staging")
    def test_import_staged_bytes_deny_rival_writer(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target_root = Path(raw) / "target"
            target_root.mkdir()
            target = target_root / "managed.txt"
            original_link = aide_lite.windows_link_from_handle
            attempted = False

            def rival_before_publication(descriptor: int, directory_handle: int, leaf_name: str) -> None:
                nonlocal attempted
                stage = list(target.parent.glob(f".{target.name}.*.tmp"))
                self.assertEqual(len(stage), 1)
                attempted = True
                with self.assertRaises(OSError):
                    stage[0].write_bytes(b"rival bytes")
                original_link(descriptor, directory_handle, leaf_name)

            with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=rival_before_publication):
                aide_lite.portable_import_write_exact(target_root, "managed.txt", b"expected bytes", "missing")
            self.assertTrue(attempted)
            self.assertEqual(target.read_bytes(), b"expected bytes")
            self.assertEqual(list(target.parent.iterdir()), [target])

    @unittest.skipUnless(sys.platform == "win32", "requires Windows no-replace publication")
    def test_import_update_preserves_preimage_backup_when_rival_wins_publish_gap(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target_root = root / "target"
            target = target_root / ".aide" / "prompts" / "compact-task.md"
            target.parent.mkdir(parents=True)
            original = b"# Previously managed content\n"
            competing = b"# Concurrent project edit\n"
            target.write_bytes(original)
            backup_rel = ".aide/prompts/.compact-task.md.aide-import-backup-test"
            backup = target_root / backup_rel
            original_link = aide_lite.windows_link_from_handle
            attempted = False

            def rival_at_publication(descriptor: int, directory_handle: int, leaf_name: str) -> None:
                nonlocal attempted
                if leaf_name == target.name and not attempted:
                    attempted = True
                    self.assertFalse(target.exists(), "the verified old leaf must be held under its backup")
                    target.write_bytes(competing)
                original_link(descriptor, directory_handle, leaf_name)

            with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=rival_at_publication):
                with self.assertRaises((OSError, RuntimeError)):
                    aide_lite.portable_import_write_exact(
                        target_root,
                        ".aide/prompts/compact-task.md",
                        b"# Incoming managed content\n",
                        aide_lite.digest_bytes(original),
                        backup_rel,
                    )
            self.assertTrue(attempted)
            self.assertEqual(target.read_bytes(), competing)
            self.assertEqual(backup.read_bytes(), original)

    @unittest.skipUnless(sys.platform == "win32", "requires Windows no-replace publication")
    def test_import_recovery_reports_backup_and_refuses_rival_replay(self) -> None:
        source_root = self.make_source_repo()
        source_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "backup-gap-v1")
        target_root = source_root.parent / "backup-gap-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target_root)["status"], "APPLIED")
        target = target_root / source_rel
        original = target.read_bytes()
        competing = b"# Concurrent project edit during publish\n"
        aide_lite.write_text(source_root / source_rel, "# Incoming managed content\n")
        pack_v2 = self.freeze_pack(source_root, "backup-gap-v2")
        original_link = aide_lite.windows_link_from_handle
        attempted = False

        def rival_at_publication(descriptor: int, directory_handle: int, leaf_name: str) -> None:
            nonlocal attempted
            if leaf_name == target.name and not attempted:
                attempted = True
                self.assertFalse(target.exists())
                target.write_bytes(competing)
            original_link(descriptor, directory_handle, leaf_name)

        with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=rival_at_publication):
            result = aide_lite.apply_import_pack(pack_v2, target_root, predecessor_pack=pack_v1)
        self.assertTrue(attempted)
        self.assertEqual(result["status"], "INTERRUPTED")
        self.assertEqual(result["recovery"]["classification"], "unknown")
        intent = aide_lite.load_portable_import_intent(target_root)
        self.assertIsNotNone(intent)
        item = next(item for item in intent["operations"] if item["target"] == source_rel)
        backup_rel = item["backup_rel"]
        self.assertIn(backup_rel, result["recovery"]["outstanding_backups"])
        self.assertEqual((target_root / backup_rel).read_bytes(), original)
        self.assertEqual(target.read_bytes(), competing)
        resumed = aide_lite.apply_import_pack(pack_v2, target_root)
        self.assertEqual(resumed["status"], "RECOVERY_REQUIRED")
        self.assertEqual(resumed["recovery"]["classification"], "unknown")
        self.assertEqual(target.read_bytes(), competing)
        self.assertEqual((target_root / backup_rel).read_bytes(), original)

    def test_import_receipt_only_transition_uses_an_intent(self) -> None:
        source_root = self.make_source_repo()
        pack_v1 = self.freeze_pack(source_root, "receipt-only-v1")
        target_root = source_root.parent / "receipt-only-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target_root)["status"], "APPLIED")
        pack_v2 = self.freeze_pack(source_root, "receipt-only-v2")
        self.set_manifest_scalars(pack_v2, {"source_commit": "a" * 40})
        self.assertTrue(aide_lite.validate_pack_checksums(pack_v2)[0])
        preview = aide_lite.apply_import_pack(pack_v2, target_root, dry_run=True)
        self.assertFalse(any(item["preimage_digest"] != item["postimage_digest"] for item in preview["operations"] if item["action"] != "conflict"))
        original_write = aide_lite.portable_import_write_exact
        saw_intent = False

        def observe_receipt_write(root: Path, rel: str, data: bytes, expected: str, backup_rel: str | None = None) -> aide_lite.WriteResult:
            nonlocal saw_intent
            if rel == aide_lite.PORTABLE_IMPORT_RECEIPT_PATH:
                saw_intent = (target_root / aide_lite.PORTABLE_IMPORT_INTENT_PATH).is_file()
            return original_write(root, rel, data, expected, backup_rel)

        if sys.platform == "win32":
            with mock.patch.object(aide_lite, "portable_import_write_exact", side_effect=observe_receipt_write):
                result = aide_lite.apply_import_pack(pack_v2, target_root)
            self.assertTrue(saw_intent)
        else:
            result = aide_lite.apply_import_pack(pack_v2, target_root)
        self.assertEqual(result["status"], "APPLIED")
        self.assertTrue(result["receipt_written"])
        self.assertEqual(result["written"], [])
        self.assertFalse((target_root / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())

    @unittest.skipUnless(sys.platform == "win32", "requires Windows anchored intent cleanup")
    def test_import_recovers_after_receipt_commit_before_intent_cleanup(self) -> None:
        source_root = self.make_source_repo()
        source_rel = ".aide/prompts/compact-task.md"
        pack_v1 = self.freeze_pack(source_root, "receipt-commit-v1")
        target_root = source_root.parent / "receipt-commit-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target_root)["status"], "APPLIED")
        aide_lite.write_text(source_root / source_rel, "# Updated managed content\n")
        pack_v2 = self.freeze_pack(source_root, "receipt-commit-v2")
        with mock.patch.object(aide_lite, "portable_import_delete_exact", side_effect=OSError("simulated interruption after receipt")):
            with self.assertRaisesRegex(OSError, "simulated interruption"):
                aide_lite.apply_import_pack(pack_v2, target_root, predecessor_pack=pack_v1)
        intent_path = target_root / aide_lite.PORTABLE_IMPORT_INTENT_PATH
        self.assertTrue(intent_path.is_file())
        receipt_before = (target_root / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes()
        target_before = (target_root / source_rel).read_bytes()
        recovered = aide_lite.apply_import_pack(pack_v2, target_root)
        self.assertEqual(recovered["status"], "RECOVERED")
        self.assertFalse(intent_path.exists())
        self.assertEqual((target_root / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).read_bytes(), receipt_before)
        self.assertEqual((target_root / source_rel).read_bytes(), target_before)

    @unittest.skipUnless(sys.platform == "win32", "requires Windows junction and pinned handles")
    def test_import_receipt_does_not_follow_a_swapped_parent(self) -> None:
        source_root = self.make_source_repo()
        pack_v1 = self.freeze_pack(source_root, "receipt-parent-v1")
        target_root = source_root.parent / "receipt-parent-target"
        self.assertEqual(aide_lite.apply_import_pack(pack_v1, target_root)["status"], "APPLIED")
        pack_v2 = self.freeze_pack(source_root, "receipt-parent-v2")
        self.set_manifest_scalars(pack_v2, {"source_commit": "b" * 40})
        parent = target_root / ".aide" / "install"
        parked = target_root / ".aide" / "install-parked"
        outside = source_root.parent / "receipt-parent-outside"
        outside.mkdir()
        original_mkstemp = tempfile.mkstemp
        attempted = False

        def swap_before_receipt_staging(*args: object, **kwargs: object) -> tuple[int, str]:
            nonlocal attempted
            if Path(str(kwargs.get("dir"))) == parent and str(kwargs.get("prefix", "")).startswith(".aide-lite-pack-v0.receipt.json.") and not attempted:
                attempted = True
                try:
                    parent.rename(parked)
                except PermissionError:
                    pass
                else:
                    junction = subprocess.run(["cmd", "/c", "mklink", "/J", str(parent), str(outside)], capture_output=True, text=True, encoding="utf-8")
                    self.assertEqual(junction.returncode, 0, junction.stderr)
            return original_mkstemp(*args, **kwargs)

        try:
            with mock.patch.object(aide_lite.tempfile, "mkstemp", side_effect=swap_before_receipt_staging):
                try:
                    aide_lite.apply_import_pack(pack_v2, target_root)
                except (OSError, RuntimeError, ValueError):
                    pass
            outside_entries = list(outside.iterdir())
        finally:
            if parent.is_symlink():
                parent.unlink()
            elif getattr(parent, "is_junction", lambda: False)():
                parent.rmdir()
            if parked.exists():
                parked.rename(parent)
        self.assertTrue(attempted)
        self.assertEqual(outside_entries, [], "import wrote a receipt through a swapped parent")

    def test_import_intent_does_not_follow_a_swapped_parent(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "intent-parent-pack")
        target_root = source_root.parent / "intent-parent-target"
        parent = target_root / ".aide" / "install"
        parent.mkdir(parents=True)
        parked = target_root / ".aide" / "install-parked"
        outside = source_root.parent / "intent-parent-outside"
        outside.mkdir()
        original_mkstemp = tempfile.mkstemp
        attempted = False

        def swap_before_intent_staging(*args: object, **kwargs: object) -> tuple[int, str]:
            nonlocal attempted
            if Path(str(kwargs.get("dir"))) == parent and not attempted:
                attempted = True
                try:
                    parent.rename(parked)
                except PermissionError:
                    pass
                else:
                    if sys.platform == "win32":
                        junction = subprocess.run(
                            ["cmd", "/c", "mklink", "/J", str(parent), str(outside)],
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                        )
                        self.assertEqual(junction.returncode, 0, junction.stderr)
                    else:
                        parent.symlink_to(outside, target_is_directory=True)
            return original_mkstemp(*args, **kwargs)

        try:
            with mock.patch.object(aide_lite.tempfile, "mkstemp", side_effect=swap_before_intent_staging):
                try:
                    aide_lite.apply_import_pack(pack, target_root)
                except (OSError, RuntimeError, ValueError):
                    pass
            outside_entries = list(outside.iterdir())
        finally:
            if parent.is_symlink():
                parent.unlink()
            elif getattr(parent, "is_junction", lambda: False)():
                parent.rmdir()
            if parked.exists():
                parked.rename(parent)

        self.assertTrue(attempted, "the importer must exercise the intent staging boundary")
        self.assertEqual(outside_entries, [], "import wrote an intent through a swapped parent")

    def test_removal_plan_requires_an_exact_valid_receipt(self) -> None:
        source_root = self.make_source_repo()
        target = source_root.parent / "target-removal-receipt"
        target.mkdir()

        with self.assertRaisesRegex(ValueError, "portable import receipt missing"):
            aide_lite.build_portable_removal_plan(target)

        aide_lite.write_text(target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH, "not json\n")
        with self.assertRaisesRegex(ValueError, "invalid portable import receipt"):
            aide_lite.build_portable_removal_plan(target)

        pack = self.freeze_pack(source_root, "removal-receipt-pack")
        shutil.rmtree(target)
        aide_lite.apply_import_pack(pack, target)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["plan_digest"] = "tampered"
        aide_lite.write_text(receipt_path, aide_lite.stable_json_text(receipt))
        with self.assertRaisesRegex(ValueError, "portable import receipt digest mismatch"):
            aide_lite.build_portable_removal_plan(target)

    def test_removal_plan_is_read_only_and_preserves_non_owned_bytes(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-plan-pack")
        target = source_root.parent / "target-removal-plan"
        aide_lite.write_text(target / "AGENTS.md", "# Target Agents\n\nAuthored guidance.\n")
        applied = aide_lite.apply_import_pack(pack, target)
        self.assertEqual(applied["status"], "APPLIED")
        aide_lite.write_text(target / "unknown.txt", "target owned\n")

        before = {
            aide_lite.normalize_rel(path.relative_to(target)): path.read_bytes()
            for path in sorted(target.rglob("*"))
            if path.is_file()
        }
        plan = aide_lite.build_portable_removal_plan(target)
        after = {
            aide_lite.normalize_rel(path.relative_to(target)): path.read_bytes()
            for path in sorted(target.rglob("*"))
            if path.is_file()
        }

        self.assertEqual(plan["status"], "PLANNED")
        self.assertTrue(plan["read_only"])
        self.assertFalse(plan["apply_allowed"])
        self.assertFalse(plan["delete_allowed"])
        self.assertEqual(before, after)
        self.assertEqual(plan["candidate_count"], len(plan["operations"]))
        self.assertNotIn("unknown.txt", {item["target"] for item in plan["operations"]})
        agents = next(item for item in plan["operations"] if item["target"] == "AGENTS.md")
        self.assertEqual(agents["action"], "remove_managed_section_future")
        self.assertTrue(agents["preserves_authored_content"])
        self.assertIn("Authored guidance.", aide_lite.read_text(target / "AGENTS.md"))
        for rel in [
            ".aide/profile.yaml",
            ".aide/memory/project-state.md",
            ".aide/memory/decisions.md",
            ".aide/memory/open-risks.md",
            ".gitignore",
            "unknown.txt",
        ]:
            self.assertNotIn(rel, plan["candidate_targets"])

        managed_rel = ".aide/prompts/compact-task.md"
        aide_lite.write_text(target / managed_rel, "# Local edit\n")
        edited = aide_lite.build_portable_removal_plan(target)
        operation = next(item for item in edited["operations"] if item["target"] == managed_rel)
        self.assertEqual(edited["status"], "PRESERVATION_REQUIRED")
        self.assertEqual(operation["action"], "preserve_local_or_unknown")
        self.assertFalse(operation["removal_candidate"])
        self.assertNotEqual(edited["plan_digest"], plan["plan_digest"])
        self.assertEqual(aide_lite.read_text(target / managed_rel), "# Local edit\n")

    def test_removal_plan_identity_changes_with_receipt_or_managed_state(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-identity-pack")
        target = source_root.parent / "target-removal-identity"
        aide_lite.apply_import_pack(pack, target)
        original = aide_lite.build_portable_removal_plan(target)

        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["plan_digest"] = "f" * 64
        receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
        aide_lite.write_text(receipt_path, aide_lite.stable_json_text(receipt))
        changed_receipt = aide_lite.build_portable_removal_plan(target)
        self.assertNotEqual(changed_receipt["plan_digest"], original["plan_digest"])

        managed_rel = next(
            item["target"]
            for item in changed_receipt["operations"]
            if item["kind"] == "managed_file"
        )
        (target / managed_rel).unlink()
        missing = aide_lite.build_portable_removal_plan(target)
        operation = next(item for item in missing["operations"] if item["target"] == managed_rel)
        self.assertEqual(operation["action"], "preserve_already_absent")
        self.assertFalse(operation["removal_candidate"])
        self.assertNotEqual(missing["plan_digest"], changed_receipt["plan_digest"])

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_apply_requires_exact_plan_and_preserves_authored_state(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-apply-pack")
        target = source_root.parent / "target-removal-apply"
        aide_lite.write_text(target / "AGENTS.md", "# Project guidance\n\nKeep my authored words.\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        managed_rel = ".aide/prompts/compact-task.md"
        changed_rel = ".aide/policies/token-budget.yaml"
        aide_lite.write_text(target / changed_rel, "# Direct target edit\n")
        aide_lite.write_text(target / "unknown.txt", "target owned\n")
        receipt = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt_bytes = receipt.read_bytes()
        agents_bytes = (target / "AGENTS.md").read_bytes()
        expected_agents = aide_lite.portable_agents_section_postimage(
            agents_bytes, aide_lite.load_portable_import_receipt(target)["managed"]["AGENTS.md"]["installed_digest"]
        )
        self.assertIsNotNone(expected_agents)
        original_plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(aide_lite.apply_portable_removal(target, "f" * 64)["status"], "STALE_PLAN")
        self.assertTrue((target / managed_rel).is_file())

        result = aide_lite.apply_portable_removal(target, original_plan["plan_digest"])
        self.assertEqual(result["status"], "PARTIAL_REMOVAL")
        self.assertIn(managed_rel, result["removed"])
        self.assertFalse((target / managed_rel).exists())
        self.assertEqual((target / changed_rel).read_text(encoding="utf-8"), "# Direct target edit\n")
        self.assertEqual((target / "unknown.txt").read_text(encoding="utf-8"), "target owned\n")
        self.assertEqual((target / "AGENTS.md").read_bytes(), expected_agents)
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).is_file())
        self.assertEqual(receipt.read_bytes(), receipt_bytes)
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())
        self.assertEqual(aide_lite.apply_portable_removal(target, original_plan["plan_digest"])["status"], "STALE_PLAN")
        remaining = aide_lite.build_portable_removal_plan(target)
        self.assertGreater(remaining["preservation_count"], 0)
        self.assertEqual(aide_lite.apply_portable_removal(target, remaining["plan_digest"])["status"], "PRESERVATION_REQUIRED")
        installed_plan = subprocess.run(
            [sys.executable, str(target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH), "--repo-root", str(target),
             "plan-removal", "--target", str(target), "--json"],
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertIn(installed_plan.returncode, (0, 2), installed_plan.stderr)
        self.assertEqual(json.loads(installed_plan.stdout)["plan_digest"], remaining["plan_digest"])
        self.assertEqual(receipt.read_bytes(), receipt_bytes)

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_detaches_brownfield_agents_section_preserving_authored_bytes(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-section-pack")
        target = source_root.parent / "target-removal-brownfield-section"
        authored_prefix = b"# Project guidance\r\n\r\nKeep my authored words.\r\n"
        aide_lite.write_text(target / "README.md", "# Project data\n")
        (target / "AGENTS.md").write_bytes(authored_prefix)
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        authored_suffix = b"\r\n# Project tail\r\n"
        agents_path = target / "AGENTS.md"
        agents_path.write_bytes(agents_path.read_bytes() + authored_suffix)
        before = agents_path.read_bytes()
        begin = before.index(b"<!-- AIDE-PORTABLE:BEGIN section=aide-lite-pack-v0")
        end_marker = b"<!-- AIDE-PORTABLE:END section=aide-lite-pack-v0 -->"
        end = before.index(end_marker, begin) + len(end_marker)
        expected = before[:begin] + before[end:]
        plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(plan["status"], "PLANNED")
        result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(result["status"], "DETACHED")
        self.assertEqual(agents_path.read_bytes(), expected)
        self.assertTrue(expected.startswith(authored_prefix))
        self.assertTrue(expected.endswith(authored_suffix))
        self.assertEqual(aide_lite.read_text(target / "README.md"), "# Project data\n")
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())
        with self.assertRaisesRegex(ValueError, "receipt missing"):
            aide_lite.apply_portable_removal(target, plan["plan_digest"])

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_changed_or_duplicated_is_preserved(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-edited-pack")
        target = source_root.parent / "target-removal-brownfield-edited"
        aide_lite.write_text(target / "AGENTS.md", "# Authored project guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        agents = target / "AGENTS.md"
        preview = aide_lite.build_portable_removal_plan(target)
        edited = agents.read_bytes().replace(b"AIDE Lite Portable Guidance", b"Project changed this section")
        agents.write_bytes(edited)
        self.assertEqual(aide_lite.apply_portable_removal(target, preview["plan_digest"])["status"], "STALE_PLAN")
        changed_plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(changed_plan["status"], "PRESERVATION_REQUIRED")
        result = aide_lite.apply_portable_removal(target, changed_plan["plan_digest"])
        self.assertEqual(result["status"], "PARTIAL_REMOVAL")
        self.assertEqual(agents.read_bytes(), edited)
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())

        second = source_root.parent / "target-removal-duplicated-marker"
        aide_lite.write_text(second / "AGENTS.md", "# Authored project guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, second)["status"], "APPLIED")
        duplicate_agents = second / "AGENTS.md"
        duplicate_agents.write_bytes(duplicate_agents.read_bytes() + b"\n<!-- AIDE-PORTABLE:BEGIN section=aide-lite-pack-v0 duplicate -->\n")
        duplicate_before = duplicate_agents.read_bytes()
        duplicate_plan = aide_lite.build_portable_removal_plan(second)
        self.assertEqual(aide_lite.apply_portable_removal(second, duplicate_plan["plan_digest"])["status"], "PARTIAL_REMOVAL")
        self.assertEqual(duplicate_agents.read_bytes(), duplicate_before)
        self.assertTrue((second / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_interruption_resume_and_unknown_postimage(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-interrupt-pack")
        def prepare(name):
            target = source_root.parent / name
            aide_lite.write_text(target / "AGENTS.md", "# Authored project guidance\n")
            self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
            plan = aide_lite.build_portable_removal_plan(target)
            prior = sum(path < "AGENTS.md" and path != aide_lite.PORTABLE_REMOVAL_RUNNER_PATH for path in plan["candidate_targets"])
            return target, plan, prior + 1

        target, plan, threshold = prepare("target-removal-section-resume")
        stopped = aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_removals=threshold)
        self.assertEqual(stopped["status"], "INTERRUPTED")
        self.assertIn("AGENTS.md", stopped["removed"])
        agents = target / "AGENTS.md"
        expected = agents.read_bytes()
        self.assertNotIn(b"AIDE-PORTABLE:BEGIN", expected)
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())
        self.assertEqual(aide_lite.apply_portable_removal(target, plan["plan_digest"])["status"], "DETACHED")
        self.assertEqual(agents.read_bytes(), expected)
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())

        unknown_target, unknown_plan, unknown_threshold = prepare("target-removal-section-unknown")
        self.assertEqual(aide_lite.apply_portable_removal(unknown_target, unknown_plan["plan_digest"], fail_after_removals=unknown_threshold)["status"], "INTERRUPTED")
        unknown_agents = unknown_target / "AGENTS.md"
        authored = unknown_agents.read_bytes() + b"# New authored note after interruption\n"
        unknown_agents.write_bytes(authored)
        self.assertEqual(aide_lite.apply_portable_removal(unknown_target, unknown_plan["plan_digest"])["status"], "RECOVERY_REQUIRED")
        self.assertEqual(unknown_agents.read_bytes(), authored)
        self.assertTrue((unknown_target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())
        self.assertTrue((unknown_target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_competing_writer_preserves_receipt_and_bytes(self) -> None:
        import ctypes
        from ctypes import wintypes

        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-writer-pack")
        target = source_root.parent / "target-removal-brownfield-writer"
        aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        agents = target / "AGENTS.md"
        before = agents.read_bytes()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        original = aide_lite.portable_import_write_exact
        attempted = []
        def hold_writer(root, target_rel, data, expected_digest, backup_rel=None):
            if target_rel != "AGENTS.md":
                return original(root, target_rel, data, expected_digest, backup_rel)
            writer = kernel.CreateFileW(str(agents), 0x40000000, 0x1 | 0x2 | 0x4, None, 3, 0, None)
            self.assertNotEqual(writer, ctypes.c_void_p(-1).value)
            attempted.append(True)
            try:
                return original(root, target_rel, data, expected_digest, backup_rel)
            finally:
                kernel.CloseHandle(writer)
        with mock.patch.object(aide_lite, "portable_import_write_exact", side_effect=hold_writer):
            result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(attempted, [True])
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(agents.read_bytes(), before)
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_postimage_is_held_through_receipt_retirement(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-terminal-race-pack")
        target = source_root.parent / "target-removal-brownfield-terminal-race"
        aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        agents = target / "AGENTS.md"
        receipt = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        original = aide_lite.windows_unlink_exact_portable_file
        blocked = []
        def try_write_at_receipt(path, digest, before_disposition=None):
            if path == receipt:
                with self.assertRaises(OSError):
                    agents.write_bytes(b"# Concurrent project edit\n")
                blocked.append(True)
            return original(path, digest, before_disposition=before_disposition)
        with mock.patch.object(aide_lite, "windows_unlink_exact_portable_file", side_effect=try_write_at_receipt):
            result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(result["status"], "DETACHED")
        self.assertEqual(blocked, [True])
        self.assertIn(b"# Authored guidance", agents.read_bytes())
        self.assertFalse(receipt.exists())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_backup_cleanup_and_tamper_recovery(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "removal-brownfield-backup-recovery-pack")
        for name in ("exact", "tampered", "same-byte-substitution"):
            with self.subTest(name=name):
                target = source.parent / f"target-removal-backup-{name}"
                aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
                self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
                plan = aide_lite.build_portable_removal_plan(target)
                agents = target / "AGENTS.md"
                preimage = agents.read_bytes()
                backup = target / f".AGENTS.md.aide-import-backup-{plan['plan_digest'][:20]}"
                original_delete = aide_lite.portable_import_delete_open_leaf
                injected = []
                def fail_after_publish(kernel, handle):
                    if not injected and backup.exists() and agents.exists():
                        injected.append(True)
                        raise OSError("injected original backup disposition failure")
                    return original_delete(kernel, handle)
                with mock.patch.object(aide_lite, "portable_import_delete_open_leaf", side_effect=fail_after_publish):
                    first = aide_lite.apply_portable_removal(target, plan["plan_digest"])
                self.assertEqual(first["status"], "RECOVERY_REQUIRED")
                self.assertEqual(injected, [True])
                self.assertEqual(backup.read_bytes(), preimage)
                self.assertNotIn(b"AIDE-PORTABLE:BEGIN", agents.read_bytes())
                if name == "tampered":
                    backup.write_bytes(b"# Unknown replacement backup\n")
                elif name == "same-byte-substitution":
                    parked = target / "original-backup-preserved-for-test"
                    backup.rename(parked)
                    backup.write_bytes(preimage)
                second = aide_lite.apply_portable_removal(target, plan["plan_digest"])
                if name != "exact":
                    self.assertEqual(second["status"], "RECOVERY_REQUIRED")
                    self.assertEqual(backup.read_bytes(), b"# Unknown replacement backup\n" if name == "tampered" else preimage)
                    if name == "same-byte-substitution":
                        self.assertEqual(parked.read_bytes(), preimage)
                    self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
                    self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())
                else:
                    self.assertEqual(second["status"], "DETACHED")
                    self.assertFalse(os.path.lexists(backup))
                    self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
                    self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_interrupted_rename_before_link_restores_exact_backup(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "removal-brownfield-rename-gap-pack")
        target = source.parent / "target-removal-rename-gap"
        aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        agents = target / "AGENTS.md"
        preimage = agents.read_bytes()
        receipt = aide_lite.load_portable_import_receipt(target)
        expected_postimage = aide_lite.portable_agents_section_postimage(
            preimage, receipt["managed"]["AGENTS.md"]["installed_digest"])
        self.assertIsNotNone(expected_postimage)
        backup = target / f".AGENTS.md.aide-import-backup-{plan['plan_digest'][:20]}"
        original_link = aide_lite.windows_link_from_handle
        original_rename = aide_lite.portable_import_rename_open_leaf
        injected = []
        def fail_link(descriptor, directory_handle, leaf_name):
            if leaf_name == "AGENTS.md" and backup.exists():
                injected.append(True)
                raise OSError("injected post-rename pre-link interruption")
            return original_link(descriptor, directory_handle, leaf_name)
        def fail_restore(kernel, handle, directory_handle, destination):
            if injected and str(destination) == str(agents):
                raise OSError("injected restore interruption")
            return original_rename(kernel, handle, directory_handle, destination)
        with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=fail_link), mock.patch.object(aide_lite, "portable_import_rename_open_leaf", side_effect=fail_restore):
            first = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(first["status"], "RECOVERY_REQUIRED")
        self.assertEqual(injected, [True])
        self.assertFalse(os.path.lexists(agents))
        self.assertEqual(backup.read_bytes(), preimage)
        intent_path = target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        operation = next(item for item in intent["operations"] if item["kind"] == "managed_agents_section")
        identity = operation.pop("preimage_file_identity")
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        aide_lite.write_text(intent_path, aide_lite.stable_json_text(intent))
        legacy_retry = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(legacy_retry["status"], "RECOVERY_REQUIRED")
        self.assertFalse(os.path.lexists(agents))
        self.assertEqual(backup.read_bytes(), preimage)
        self.assertTrue(intent_path.is_file())
        operation["preimage_file_identity"] = identity
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        aide_lite.write_text(intent_path, aide_lite.stable_json_text(intent))
        self.assertEqual(aide_lite.apply_portable_removal(target, plan["plan_digest"])["status"], "DETACHED")
        self.assertEqual(agents.read_bytes(), expected_postimage)
        self.assertFalse(os.path.lexists(backup))
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_rename_gap_refuses_changed_backup_or_rival(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "removal-rename-gap-adversarial-pack")
        for case in ("changed", "same-byte-substitution", "rival-target"):
            with self.subTest(case=case):
                target = source.parent / f"target-removal-gap-{case}"
                aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
                self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
                plan = aide_lite.build_portable_removal_plan(target)
                agents = target / "AGENTS.md"
                backup = target / f".AGENTS.md.aide-import-backup-{plan['plan_digest'][:20]}"
                original_link = aide_lite.windows_link_from_handle
                original_rename = aide_lite.portable_import_rename_open_leaf
                interrupted = []

                def fail_link(descriptor, directory_handle, leaf_name):
                    if leaf_name == "AGENTS.md" and backup.exists():
                        interrupted.append(True)
                        raise OSError("injected post-rename pre-link interruption")
                    return original_link(descriptor, directory_handle, leaf_name)

                def fail_restore(kernel, handle, directory_handle, destination):
                    if interrupted and str(destination) == str(agents):
                        raise OSError("injected restore interruption")
                    return original_rename(kernel, handle, directory_handle, destination)

                with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=fail_link), mock.patch.object(aide_lite, "portable_import_rename_open_leaf", side_effect=fail_restore):
                    first = aide_lite.apply_portable_removal(target, plan["plan_digest"])
                self.assertEqual(first["status"], "RECOVERY_REQUIRED")
                self.assertEqual(interrupted, [True])
                self.assertFalse(os.path.lexists(agents))
                original = backup.read_bytes()
                if case == "changed":
                    backup.write_bytes(b"# Changed backup\n")
                elif case == "same-byte-substitution":
                    parked = target / "original-backup-preserved-for-test"
                    backup.rename(parked)
                    backup.write_bytes(original)
                else:
                    agents.write_bytes(b"# Rival project guidance\n")
                second = aide_lite.apply_portable_removal(target, plan["plan_digest"])
                self.assertEqual(second["status"], "RECOVERY_REQUIRED")
                self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())
                self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())
                if case == "rival-target":
                    self.assertEqual(agents.read_bytes(), b"# Rival project guidance\n")
                    self.assertEqual(backup.read_bytes(), original)
                if case == "same-byte-substitution":
                    self.assertEqual(parked.read_bytes(), original)

    def test_removal_rename_gap_legacy_intent_without_file_identity_refuses(self) -> None:
        self.assertFalse(aide_lite.portable_removal_restore_agents_preimage(
            Path("unused"), {"kind": "managed_agents_section", "backup_rel": ".AGENTS.md.aide-import-backup-old"}
        ))

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_rechecksummed_intent_cannot_change_preview_bytes(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-intent-pack")
        target = source_root.parent / "target-removal-brownfield-intent"
        aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_removals=1)["status"], "INTERRUPTED")
        intent_path = target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        operation = next(item for item in intent["operations"] if item["kind"] == "managed_agents_section")
        agents = target / "AGENTS.md"
        authored = b"# Later authored preface\n" + agents.read_bytes()
        agents.write_bytes(authored)
        operation["preimage_digest"] = aide_lite.digest_bytes(authored)
        operation["postimage_digest"] = aide_lite.digest_bytes(aide_lite.portable_agents_section_postimage(authored, operation["installed_digest"]))
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        aide_lite.write_text(intent_path, aide_lite.stable_json_text(intent))
        with self.assertRaisesRegex(ValueError, "preimage differs from exact preview"):
            aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(agents.read_bytes(), authored)
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_brownfield_section_root_junction_refuses_before_effect(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-brownfield-junction-pack")
        target = source_root.parent / "target-removal-brownfield-junction"
        outside = source_root.parent / "outside-removal-brownfield"
        outside.mkdir()
        aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        outside_agents = b"# Unrelated outside guidance\n"
        (outside / "AGENTS.md").write_bytes(outside_agents)
        parked = target.with_name(target.name + "-parked")
        original = aide_lite.windows_pinned_directory
        invoked = False
        def swap_then_pin(path):
            nonlocal invoked
            if not invoked and path == target:
                invoked = True
                target.rename(parked)
                linked = subprocess.run(["cmd", "/c", "mklink", "/J", str(target), str(outside)], capture_output=True, text=True)
                if linked.returncode:
                    parked.rename(target)
                    self.skipTest("junction creation unavailable: " + linked.stderr)
            return original(path)
        try:
            with mock.patch.object(aide_lite, "windows_pinned_directory", side_effect=swap_then_pin):
                with self.assertRaises((OSError, ValueError)):
                    aide_lite.apply_portable_removal(target, plan["plan_digest"])
            self.assertTrue(invoked)
            self.assertEqual((outside / "AGENTS.md").read_bytes(), outside_agents)
            self.assertTrue((parked / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())
        finally:
            if target.is_junction():
                os.rmdir(target)
            if parked.exists() and not target.exists():
                parked.rename(target)

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_interruption_keeps_intent_and_reconciles_exact_bytes(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-recovery-pack")
        target = source_root.parent / "target-removal-recovery"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        interrupted = aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_removals=1)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        intent = target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        self.assertTrue(intent.is_file())
        self.assertEqual(len(interrupted["removed"]), 1)
        with self.assertRaisesRegex(ValueError, "removal recovery"):
            aide_lite.build_portable_removal_plan(target)
        with self.assertRaisesRegex(ValueError, "removal recovery"):
            aide_lite.apply_import_pack(pack, target)
        resumed = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(resumed["status"], "DETACHED")
        self.assertFalse(intent.exists())
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).exists())
        self.assertFalse((target / "AGENTS.md").exists())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_rejects_rechecksummed_intent_for_later_authored_managed_file(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-forged-managed-intent-pack")
        target = source_root.parent / "target-removal-forged-managed-intent"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_removals=1)["status"], "INTERRUPTED")
        intent_path = target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        operation = next(item for item in intent["operations"] if item["kind"] == "managed_file" and (target / item["target"]).is_file())
        authored = b"project's later authored bytes\n"
        (target / operation["target"]).write_bytes(authored)
        operation["preimage_digest"] = aide_lite.digest_bytes(authored)
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        aide_lite.write_text(intent_path, aide_lite.stable_json_text(intent))
        receipt_bytes = receipt_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "preimage differs from installed bytes"):
            aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual((target / operation["target"]).read_bytes(), authored)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_rejects_rechecksummed_intent_for_authored_agents_file(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-forged-agents-intent-pack")
        target = source_root.parent / "target-removal-forged-agents-intent"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_removals=1)["status"], "INTERRUPTED")
        intent_path = target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        operation = next(item for item in intent["operations"] if item["kind"] == "standalone_managed_agents")
        agents_path = target / "AGENTS.md"
        authored = b"# Project authored preface\n" + agents_path.read_bytes()
        agents_path.write_bytes(authored)
        operation["preimage_digest"] = aide_lite.digest_bytes(authored)
        intent["intent_digest"] = aide_lite.portable_import_record_digest(intent, "intent_digest")
        aide_lite.write_text(intent_path, aide_lite.stable_json_text(intent))
        receipt_bytes = receipt_path.read_bytes()
        result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(agents_path.read_bytes(), authored)
        self.assertEqual(receipt_path.read_bytes(), receipt_bytes)

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_recovers_after_receipt_retirement_before_intent_cleanup(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-retirement-pack")
        target = source_root.parent / "target-removal-retirement"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        aide_lite.write_text(target / "unknown.txt", "keep target data\n")
        plan = aide_lite.build_portable_removal_plan(target)
        stopped = aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_receipt=True)
        self.assertEqual(stopped["status"], "INTERRUPTED")
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).exists())
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())
        self.assertEqual(aide_lite.read_text(target / "unknown.txt"), "keep target data\n")
        recovered = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(recovered["status"], "DETACHED_RECOVERED")
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())
        self.assertEqual(aide_lite.read_text(target / "unknown.txt"), "keep target data\n")

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_retains_receipt_when_one_owned_file_is_already_absent(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-already-absent-pack")
        target = source_root.parent / "target-removal-already-absent"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        missing = target / ".aide/prompts/compact-task.md"
        missing.unlink()
        plan = aide_lite.build_portable_removal_plan(target)
        self.assertEqual(plan["status"], "PRESERVATION_REQUIRED")
        self.assertIn(".aide/prompts/compact-task.md", plan["preserved_recorded_targets"])
        result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(result["status"], "PARTIAL_REMOVAL")
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).exists())
        self.assertFalse((target / "AGENTS.md").exists())
        self.assertFalse(missing.exists())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_does_not_retire_receipt_at_absent_path_race_boundary(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-absent-race-pack")
        target = source_root.parent / "target-removal-absent-race"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        missing = target / ".aide/prompts/compact-task.md"
        missing.unlink()
        plan = aide_lite.build_portable_removal_plan(target)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        original_unlink = aide_lite.windows_unlink_exact_portable_file
        receipt_attempts = []
        def intercept_receipt(path, expected_digest):
            if path == receipt_path:
                receipt_attempts.append(path)
                missing.write_bytes(b"project created this at retirement boundary\n")
            return original_unlink(path, expected_digest)
        with mock.patch.object(aide_lite, "windows_unlink_exact_portable_file", side_effect=intercept_receipt):
            result = aide_lite.apply_portable_removal(target, plan["plan_digest"], fail_after_receipt=True)
        self.assertEqual(result["status"], "PARTIAL_REMOVAL")
        self.assertEqual(receipt_attempts, [])
        self.assertTrue(receipt_path.is_file())
        new_bytes = b"project created this after partial removal\n"
        missing.write_bytes(new_bytes)
        self.assertEqual(aide_lite.apply_portable_removal(target, plan["plan_digest"])["status"], "STALE_PLAN")
        self.assertEqual(missing.read_bytes(), new_bytes)
        self.assertTrue(receipt_path.is_file())
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_preview_refuses_changed_receipt_or_managed_bytes(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-stale-pack")
        target = source_root.parent / "target-removal-stale"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        preview = aide_lite.build_portable_removal_plan(target)
        managed_rel = next(item["target"] for item in preview["operations"] if item["kind"] == "managed_file" and item["removal_candidate"])
        original = (target / managed_rel).read_bytes()
        changed = b"project's later edit\n"
        (target / managed_rel).write_bytes(changed)
        self.assertEqual(aide_lite.apply_portable_removal(target, preview["plan_digest"])["status"], "STALE_PLAN")
        self.assertEqual((target / managed_rel).read_bytes(), changed)
        (target / managed_rel).write_bytes(original)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["plan_digest"] = "a" * 64
        receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
        aide_lite.write_text(receipt_path, aide_lite.stable_json_text(receipt))
        self.assertEqual(aide_lite.apply_portable_removal(target, preview["plan_digest"])["status"], "STALE_PLAN")
        self.assertEqual((target / managed_rel).read_bytes(), original)
        self.assertFalse((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).exists())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_leaf_change_before_handle_open_is_preserved(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-leaf-race-pack")
        target = source_root.parent / "target-removal-leaf-race"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        first = next(item for item in plan["operations"] if item["removal_candidate"] and item["kind"] == "managed_file")
        original = aide_lite.windows_unlink_exact_portable_file
        altered = b"project wrote during removal\n"
        def replace_leaf(path: Path, digest: str) -> None:
            if path == target / first["target"]:
                path.write_bytes(altered)
            original(path, digest)
        with mock.patch.object(aide_lite, "windows_unlink_exact_portable_file", side_effect=replace_leaf):
            result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual((target / first["target"]).read_bytes(), altered)
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_fresh_agents_edit_at_effect_time_is_preserved_with_receipt(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "removal-agents-race-pack")
        target = source_root.parent / "target-removal-agents-race"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        plan = aide_lite.build_portable_removal_plan(target)
        agents = target / "AGENTS.md"
        original = aide_lite.windows_unlink_exact_portable_file
        authored = b"# Newly authored guidance\n\n" + agents.read_bytes()
        attempted = False
        def change_agents(path: Path, digest: str, before_disposition=None) -> None:
            nonlocal attempted
            if path == agents:
                attempted = True
                path.write_bytes(authored)
            original(path, digest, before_disposition=before_disposition)
        with mock.patch.object(aide_lite, "windows_unlink_exact_portable_file", side_effect=change_agents):
            result = aide_lite.apply_portable_removal(target, plan["plan_digest"])
        self.assertTrue(attempted)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(agents.read_bytes(), authored)
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).is_file())
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_INTENT_PATH).is_file())
        self.assertTrue((target / aide_lite.PORTABLE_REMOVAL_RUNNER_PATH).is_file())

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_rejects_parent_junction_swapped_at_handle_open(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        parent = root / "target" / "owned"
        outside = root / "outside"
        parent.mkdir(parents=True)
        outside.mkdir()
        leaf = parent / "payload.txt"
        data = b"exact recorded bytes\n"
        leaf.write_bytes(data)
        (outside / leaf.name).write_bytes(data)
        parked = parent.with_name("parked-owned")
        original = aide_lite.windows_pinned_directory
        invoked = False
        def swap_then_pin(path: Path):
            nonlocal invoked
            if not invoked:
                invoked = True
                parent.rename(parked)
                linked = subprocess.run(["cmd", "/c", "mklink", "/J", str(parent), str(outside)], capture_output=True, text=True)
                if linked.returncode:
                    parked.rename(parent)
                    self.skipTest("junction creation unavailable: " + linked.stderr)
            return original(path)
        try:
            with mock.patch.object(aide_lite, "windows_pinned_directory", side_effect=swap_then_pin):
                with self.assertRaises((ValueError, OSError)):
                    aide_lite.windows_unlink_exact_portable_file(leaf, aide_lite.digest_bytes(data))
            self.assertTrue(invoked)
            self.assertEqual((outside / leaf.name).read_bytes(), data)
            self.assertEqual((parked / leaf.name).read_bytes(), data)
        finally:
            if parent.is_junction():
                os.rmdir(parent)

    @unittest.skipUnless(os.name == "nt", "anchored portable removal apply is Windows only")
    def test_removal_handle_refuses_a_competing_writer_or_hard_link(self) -> None:
        import ctypes
        from ctypes import wintypes

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        leaf = root / "owned.txt"
        data = b"receipt-owned bytes\n"
        leaf.write_bytes(data)
        digest = aide_lite.digest_bytes(data)

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        writer = kernel.CreateFileW(str(leaf), 0x40000000, 0x1 | 0x2 | 0x4, None, 3, 0, None)
        self.assertNotEqual(writer, ctypes.c_void_p(-1).value)
        try:
            with self.assertRaises(OSError):
                aide_lite.windows_unlink_exact_portable_file(leaf, digest)
        finally:
            kernel.CloseHandle(writer)
        self.assertEqual(leaf.read_bytes(), data)

        alias = root / "project-owned-alias.txt"
        os.link(leaf, alias)
        with self.assertRaisesRegex(ValueError, "multiple hard links"):
            aide_lite.windows_unlink_exact_portable_file(leaf, digest)
        self.assertEqual(leaf.read_bytes(), data)
        self.assertEqual(alias.read_bytes(), data)
        alias.unlink()

        attempted = []
        def competing_opens() -> None:
            for access in (0x40000000, 0x00010000):  # write, delete
                competing = kernel.CreateFileW(str(leaf), access, 0x1 | 0x2 | 0x4, None, 3, 0, None)
                attempted.append((access, competing))
                if competing != ctypes.c_void_p(-1).value:
                    kernel.CloseHandle(competing)
        aide_lite.windows_unlink_exact_portable_file(leaf, digest, before_disposition=competing_opens)
        self.assertEqual(len(attempted), 2)
        self.assertTrue(all(handle == ctypes.c_void_p(-1).value for _, handle in attempted))
        self.assertFalse(leaf.exists())

    def test_fake_secret_source_file_is_not_exported(self) -> None:
        source_root = self.make_source_repo()
        aide_lite.write_text(source_root / ".aide/prompts/compact-task.md", "api_key = \"abcdefghijklmnop\"\n")
        self.assertFalse(aide_lite.is_exportable_file(source_root, ".aide/prompts/compact-task.md"))
        pack_root = self.build_pack(source_root)
        self.assertFalse((pack_root / "files/.aide/prompts/compact-task.md").exists())

    def test_owned_repair_restores_missing_file_from_extracted_pack(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-pack")
        target = source_root.parent / "repair-consumer"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        expected = managed.read_bytes()
        managed.unlink()
        cli = pack / "files/.aide/scripts/aide_lite.py"
        command = [sys.executable, "-I", "-B", str(cli), "--repo-root", str(target), "repair-owned-file", "--pack", str(pack), "--target", str(target), "--path", rel]
        preview = subprocess.run([*command, "--dry-run"], text=True, capture_output=True)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("status: PLANNED", preview.stdout)
        plan_digest = next(line.partition(": ")[2] for line in preview.stdout.splitlines() if line.startswith("plan_digest: "))
        self.assertFalse((target / aide_lite.PORTABLE_REPAIR_INTENT_PATH).exists())
        applied = subprocess.run([*command, "--expect-plan", plan_digest], text=True, capture_output=True)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertIn("status: APPLIED", applied.stdout)
        self.assertEqual(managed.read_bytes(), expected)
        self.assertFalse((target / aide_lite.PORTABLE_REPAIR_INTENT_PATH).exists())
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)["status"], "CONFLICT")

    @unittest.skipUnless(os.name == "nt", "anchored repair health inspection is Windows only")
    def test_repair_health_extracted_cli_classifies_missing_edit_and_unknown_without_writes(self) -> None:
        source = self.make_source_repo()
        original_pack = self.freeze_pack(source, "repair-health-pack")
        archive = source.parent / "repair-health-pack.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for file in sorted(original_pack.rglob("*")):
                if file.is_file():
                    zipped.write(file, "aide-lite-pack-v0/" + file.relative_to(original_pack).as_posix())
        extracted = source.parent / "extracted-repair-health"
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(extracted)
        pack = extracted / "aide-lite-pack-v0"
        target = source.parent / "repair-health-consumer"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        cli = pack / "files/.aide/scripts/aide_lite.py"
        def inspect():
            before = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
            run = subprocess.run([sys.executable, "-I", "-B", str(cli), "--repo-root", str(target), "repair-health", "--pack", str(pack), "--target", str(target), "--json"], text=True, capture_output=True)
            after = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
            self.assertEqual(before, after)
            self.assertEqual(run.returncode, 0, run.stderr)
            return json.loads(run.stdout)
        missing = inspect()
        item = next(row for row in missing["observations"] if row["path"] == rel)
        self.assertEqual(missing["status"], "REPAIRABLE")
        self.assertEqual(item["state"], "MISSING_OWNED")
        self.assertTrue(item["repair_eligible"])
        self.assertEqual(item["repair_plan_digest"], aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)["plan_digest"])
        managed.write_bytes(b"authored edit\n")
        changed = inspect()
        item = next(row for row in changed["observations"] if row["path"] == rel)
        self.assertEqual(item["state"], "CHANGED")
        self.assertFalse(item["repair_eligible"])
        managed.unlink()
        other = target / "authored-other"
        other.write_bytes(b"authored edit\n")
        os.link(other, managed)
        unknown = inspect()
        item = next(row for row in unknown["observations"] if row["path"] == rel)
        self.assertEqual(item["state"], "UNKNOWN")
        self.assertFalse(item["repair_eligible"])

    @unittest.skipUnless(os.name == "nt", "anchored repair health inspection is Windows only")
    def test_repair_health_invalid_receipt_and_pending_intent_fail_closed(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "repair-health-refusals-pack")
        target = source.parent / "repair-health-refusals"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        rel = ".aide/prompts/compact-task.md"
        (target / rel).unlink()
        repair_intent = target / aide_lite.PORTABLE_REPAIR_INTENT_PATH
        repair_intent.write_bytes(b"not valid json\n")
        pending = aide_lite.inspect_portable_repair_health(pack, target)
        self.assertEqual(pending["status"], "RECOVERY_REQUIRED")
        self.assertEqual(pending["pending_intents"], ["repair"])
        self.assertFalse(any(item["repair_eligible"] for item in pending["observations"]))
        repair_intent.unlink()
        receipt = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt.write_bytes(b"{invalid")
        invalid = aide_lite.inspect_portable_repair_health(pack, target)
        self.assertEqual(invalid["status"], "INVALID_RECEIPT")
        self.assertEqual(invalid["observations"], [])

    @unittest.skipUnless(os.name == "nt", "anchored repair health inspection is Windows only")
    def test_repair_health_rejects_redigested_receipt_baseline_and_wrong_source_mapping(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "repair-health-forged-receipt-pack")
        target = source.parent / "repair-health-forged-receipt-target"
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        rel = ".aide/prompts/compact-task.md"
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        original_receipt = receipt_path.read_bytes()
        managed = target / rel
        managed.write_bytes(b"direct project edit with unknown rationale\n")
        receipt = aide_lite.load_portable_import_receipt(target)
        edited_digest = aide_lite.digest_bytes(managed.read_bytes())
        receipt["managed"][rel]["source_digest"] = edited_digest
        receipt["managed"][rel]["installed_digest"] = edited_digest
        receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
        receipt_path.write_text(aide_lite.stable_json_text(receipt), encoding="utf-8")
        before = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        forged = aide_lite.inspect_portable_repair_health(pack, target)
        after = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        self.assertEqual(before, after)
        row = next(item for item in forged["observations"] if item["path"] == rel)
        self.assertEqual(forged["status"], "PRESERVATION_REQUIRED")
        self.assertEqual(row["state"], "UNKNOWN")
        self.assertFalse(row["repair_eligible"])
        receipt_path.write_bytes(original_receipt)
        managed.write_bytes((pack / "files" / rel).read_bytes())
        authored_rel = "authored-project-file.md"
        authored = target / authored_rel
        authored.write_bytes(managed.read_bytes())
        receipt = aide_lite.load_portable_import_receipt(target)
        receipt["managed"][authored_rel] = dict(receipt["managed"][rel])
        receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
        receipt_path.write_text(aide_lite.stable_json_text(receipt), encoding="utf-8")
        before = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        wrong_mapping = aide_lite.inspect_portable_repair_health(pack, target)
        after = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        self.assertEqual(before, after)
        row = next(item for item in wrong_mapping["observations"] if item["path"] == authored_rel)
        self.assertEqual(wrong_mapping["status"], "PRESERVATION_REQUIRED")
        self.assertEqual(row["state"], "UNKNOWN")
        self.assertFalse(row["repair_eligible"])

    @unittest.skipUnless(os.name == "nt", "anchored repair health inspection is Windows only")
    def test_repair_health_accepts_raw_crlf_pack_agents_baseline(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "repair-health-crlf-template-pack")
        agents_template = pack / "files/AGENTS.md.template"
        agents_template.write_bytes(agents_template.read_bytes().replace(b"\n", b"\r\n"))
        aide_lite.write_text(pack / "checksums.json", aide_lite.stable_json_text(aide_lite.build_pack_checksums(pack)))
        self.assertEqual(aide_lite.validate_pack_checksums(pack), (True, []))
        target = source.parent / "repair-health-crlf-template-target"
        (target / "AGENTS.md").parent.mkdir(parents=True, exist_ok=True)
        (target / "AGENTS.md").write_bytes(b"# Authored project guidance\r\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        before = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        health = aide_lite.inspect_portable_repair_health(pack, target)
        after = sorted((str(path.relative_to(target)), path.read_bytes()) for path in target.rglob("*") if path.is_file())
        self.assertEqual(before, after)
        agents = next(item for item in health["observations"] if item["path"] == "AGENTS.md")
        self.assertEqual(agents["state"], "MATCHING")
        self.assertEqual(health["status"], "HEALTHY")

    @unittest.skipUnless(os.name == "nt", "anchored repair health inspection is Windows only")
    def test_repair_health_v1_section_overlay_disabled_and_pending_intents(self) -> None:
        source = self.make_source_repo()
        pack = self.freeze_pack(source, "repair-health-receipts-pack")
        target = source.parent / "repair-health-v1"
        aide_lite.write_text(target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "APPLIED")
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        receipt = aide_lite.load_portable_import_receipt(target)
        receipt["schema_version"] = aide_lite.PORTABLE_IMPORT_RECEIPT_SCHEMA
        receipt.pop("disabled_features")
        receipt.pop("project_controls_digest")
        for entry in receipt["managed"].values():
            entry.pop("local_overlay")
        receipt["receipt_digest"] = aide_lite.portable_import_record_digest(receipt, "receipt_digest")
        receipt_path.write_text(aide_lite.stable_json_text(receipt), encoding="utf-8")
        health = aide_lite.inspect_portable_repair_health(pack, target)
        agents = next(item for item in health["observations"] if item["path"] == "AGENTS.md")
        self.assertEqual(agents["state"], "MATCHING")
        self.assertFalse(agents["repair_eligible"])
        for name, rel in (("import", aide_lite.PORTABLE_IMPORT_INTENT_PATH), ("removal", aide_lite.PORTABLE_REMOVAL_INTENT_PATH)):
            intent = target / rel
            intent.write_bytes(b"unknown intent\n")
            pending = aide_lite.inspect_portable_repair_health(pack, target)
            self.assertEqual(pending["status"], "RECOVERY_REQUIRED")
            self.assertIn(name, pending["pending_intents"])
            self.assertFalse(any(item["repair_eligible"] for item in pending["observations"]))
            intent.unlink()
        overlay_target = source.parent / "repair-health-overlay"
        aide_lite.write_text(overlay_target / "AGENTS.md", "# Authored guidance\n")
        self.assertEqual(aide_lite.apply_import_pack(pack, overlay_target)["status"], "APPLIED")
        agents_path = overlay_target / "AGENTS.md"
        agents_path.write_text(agents_path.read_text(encoding="utf-8").replace("## AIDE Lite Portable Guidance", "## Locally edited guidance"), encoding="utf-8")
        self.assertEqual(aide_lite.apply_import_pack(pack, overlay_target)["status"], "APPLIED")
        overlay = next(item for item in aide_lite.inspect_portable_repair_health(pack, overlay_target)["observations"] if item["path"] == "AGENTS.md")
        self.assertTrue(overlay["local_overlay"])
        self.assertFalse(overlay["repair_eligible"])
        disabled_target = source.parent / "repair-health-disabled"
        aide_lite.write_text(disabled_target / aide_lite.PROJECT_CUSTOMIZATIONS_PATH, aide_lite.stable_json_text({
            "schema_version": aide_lite.PROJECT_CUSTOMIZATIONS_SCHEMA_V2,
            "entries": {}, "disabled_features": [{"feature_id": "local_state_examples"}],
        }))
        disabled_preview = aide_lite.apply_import_pack(pack, disabled_target, dry_run=True)
        self.assertEqual(aide_lite.apply_import_pack(pack, disabled_target, expected_plan_digest=disabled_preview["plan_digest"])["status"], "APPLIED")
        disabled = aide_lite.inspect_portable_repair_health(pack, disabled_target)
        self.assertEqual(disabled["disabled_features"], ["local_state_examples"])
        self.assertFalse(any(item["path"].startswith(".aide.local.example/") for item in disabled["observations"]))

    def test_owned_repair_rejects_edits_stale_plan_and_tampered_pack(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-adversarial-pack")
        target = source_root.parent / "repair-adversarial-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest="0" * 64)["status"], "STALE_PLAN")
        self.assertFalse(managed.exists())
        managed.write_bytes(b"project edit\n")
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])["status"], "CONFLICT")
        self.assertEqual(managed.read_bytes(), b"project edit\n")
        managed.unlink()
        with self.assertRaises(ValueError):
            aide_lite.apply_portable_owned_repair(pack, target, "../escape", dry_run=True)
        (pack / "files" / rel).write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "invalid pack checksums"):
            aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])

    def test_owned_repair_interruption_blocks_import_and_recovers_exact_postimage(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-interruption-pack")
        target = source_root.parent / "repair-interruption-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        interrupted = aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"], fail_after_write=True)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        intent = target / aide_lite.PORTABLE_REPAIR_INTENT_PATH
        before = intent.read_bytes()
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)["status"], "RECOVERY_REQUIRED")
        self.assertEqual(intent.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, "repair recovery"):
            aide_lite.apply_import_pack(pack, target)
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])["status"], "RECOVERED")
        self.assertFalse(intent.exists())

    def test_owned_repair_rejects_wrong_pack_receipt_and_unknown_interruption(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-receipt-pack")
        target = source_root.parent / "repair-receipt-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        other_pack = source_root.parent / "repair-other-pack"
        shutil.copytree(pack, other_pack)
        aide_lite.write_text(other_pack / "README.md", aide_lite.read_text(other_pack / "README.md") + "different\n")
        checksums = json.loads(aide_lite.read_text(other_pack / "checksums.json"))
        checksums["checksums"]["README.md"] = aide_lite.sha256_file(other_pack / "README.md")
        aide_lite.write_text(other_pack / "checksums.json", json.dumps(checksums, sort_keys=True) + "\n")
        with self.assertRaisesRegex(ValueError, "exact pack"):
            aide_lite.apply_portable_owned_repair(other_pack, target, rel, dry_run=True)
        receipt_path = target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH
        saved_receipt = receipt_path.read_bytes()
        receipt = json.loads(saved_receipt)
        receipt["managed"][rel]["ownership"] = "unknown"
        aide_lite.write_text(receipt_path, json.dumps(receipt) + "\n")
        with self.assertRaisesRegex(ValueError, "receipt digest"):
            aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        receipt_path.write_bytes(saved_receipt)
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"], fail_after_write=True)
        managed.write_bytes(b"unexpected project edit\n")
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])["status"], "CONFLICT")
        self.assertEqual(managed.read_bytes(), b"unexpected project edit\n")
        self.assertTrue((target / aide_lite.PORTABLE_REPAIR_INTENT_PATH).exists())

    def test_owned_repair_atomic_creation_preserves_competing_file(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-race-pack")
        target = source_root.parent / "repair-race-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        real_link = aide_lite.windows_link_from_handle

        def competing_creation(descriptor: int, directory_handle: int, leaf_name: str) -> None:
            managed.write_bytes(b"competing project bytes\n")
            real_link(descriptor, directory_handle, leaf_name)

        with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=competing_creation):
            result = aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(managed.read_bytes(), b"competing project bytes\n")
        self.assertTrue((target / aide_lite.PORTABLE_REPAIR_INTENT_PATH).exists())
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])["status"], "CONFLICT")
        self.assertEqual(managed.read_bytes(), b"competing project bytes\n")

    @unittest.skipUnless(sys.platform == "win32", "requires Windows file sharing")
    def test_owned_repair_stage_denies_second_process_writer(self) -> None:
        for rel in (".aide/install/aide-lite-pack-v0.repair-intent.json", ".aide/prompts/compact-task.md"):
            with self.subTest(path=rel), tempfile.TemporaryDirectory() as raw:
                target = Path(raw) / rel
                target.parent.mkdir(parents=True)
                original_link = aide_lite.windows_link_from_handle
                attempted = []

                def rival_before_link(descriptor: int, directory_handle: int, leaf_name: str) -> None:
                    stages = list(target.parent.glob(f".{target.name}.*.tmp"))
                    self.assertEqual(len(stages), 1)
                    child = subprocess.run(
                        [
                            sys.executable, "-I", "-B", "-c",
                            "import sys\ntry:\n with open(sys.argv[1], 'r+b') as handle: handle.write(b'ATTACKED bytes')\nexcept PermissionError:\n sys.exit(23)\n",
                            str(stages[0]),
                        ],
                        capture_output=True, text=True, timeout=10,
                    )
                    attempted.append(child.returncode)
                    self.assertEqual(child.returncode, 23, child.stderr)
                    original_link(descriptor, directory_handle, leaf_name)

                with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=rival_before_link):
                    aide_lite.atomic_create_bytes_no_clobber(target, b"expected bytes")
                self.assertEqual(attempted, [23])
                self.assertEqual(target.read_bytes(), b"expected bytes")
                self.assertEqual(list(target.parent.iterdir()), [target])

    @unittest.skipUnless(sys.platform == "win32", "requires Windows file sharing")
    def test_owned_repair_stage_setup_failure_cleans_owned_link(self) -> None:
        for stage in ("descriptor", "file-object"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as raw:
                target = Path(raw) / "victim.bin"
                if stage == "descriptor":
                    context = mock.patch("msvcrt.open_osfhandle", side_effect=OSError("descriptor setup failed"))
                else:
                    context = mock.patch.object(aide_lite.os, "fdopen", side_effect=OSError("file-object setup failed"))
                with context, self.assertRaisesRegex(OSError, "setup failed"):
                    aide_lite.atomic_create_bytes_no_clobber(target, b"expected bytes")
                self.assertFalse(target.exists())
                self.assertEqual(list(target.parent.iterdir()), [])

    def test_owned_repair_prepublication_failure_retries_from_missing(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-prepublish-pack")
        target = source_root.parent / "repair-prepublish-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        real_link = aide_lite.windows_link_from_handle

        def fail_payload(descriptor: int, directory_handle: int, leaf_name: str) -> None:
            if leaf_name == managed.name:
                raise OSError("simulated prepublication failure")
            real_link(descriptor, directory_handle, leaf_name)

        with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=fail_payload):
            with self.assertRaisesRegex(OSError, "prepublication"):
                aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])
        self.assertFalse(managed.exists())
        intent = target / aide_lite.PORTABLE_REPAIR_INTENT_PATH
        self.assertTrue(intent.exists())
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)["status"], "RECOVERY_REQUIRED")
        self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])["status"], "APPLIED")
        self.assertFalse(intent.exists())

    def test_owned_repair_serializes_concurrent_repair_and_import(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-concurrent-pack")
        target = source_root.parent / "repair-concurrent-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        (target / rel).unlink()
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        real_link = aide_lite.windows_link_from_handle
        blocked = []

        def overlapping_publish(descriptor: int, directory_handle: int, leaf_name: str) -> None:
            if leaf_name != (target / rel).name:
                real_link(descriptor, directory_handle, leaf_name)
                return
            for operation in (
                lambda: aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"]),
                lambda: aide_lite.apply_import_pack(pack, target),
            ):
                with self.assertRaisesRegex(ValueError, "already in progress"):
                    operation()
                blocked.append(True)
            real_link(descriptor, directory_handle, leaf_name)

        with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=overlapping_publish):
            result = aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(blocked, [True, True])
        self.assertFalse((target / aide_lite.PORTABLE_REPAIR_INTENT_PATH).exists())

    def test_owned_repair_blocks_parent_substitution_at_publish(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-junction-pack")
        target = source_root.parent / "repair-junction-consumer"
        aide_lite.apply_import_pack(pack, target)
        rel = ".aide/prompts/compact-task.md"
        managed = target / rel
        managed.unlink()
        preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
        parent = managed.parent
        moved = parent.with_name("prompts-moved")
        outside = source_root.parent / "outside-junction-target"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_bytes(b"outside unchanged\n")
        real_link = aide_lite.windows_link_from_handle
        blocked = []

        def attempt_swap(descriptor: int, directory_handle: int, leaf_name: str) -> None:
            if leaf_name == managed.name:
                with self.assertRaises(OSError):
                    parent.rename(moved)
                blocked.append(True)
            real_link(descriptor, directory_handle, leaf_name)

        with mock.patch.object(aide_lite, "windows_link_from_handle", side_effect=attempt_swap):
            result = aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(blocked, [True])
        self.assertFalse(moved.exists())
        self.assertEqual(sentinel.read_bytes(), b"outside unchanged\n")
        self.assertFalse((outside / managed.name).exists())

    def test_fresh_import_serializes_second_import_and_repair_without_lock_file(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "fresh-import-overlap-pack")
        target = source_root.parent / "fresh-import-overlap-consumer"
        self.assertEqual(aide_lite.apply_import_pack(pack, target, dry_run=True)["status"], "PLANNED")
        self.assertFalse(target.exists())
        real_operation = aide_lite.apply_import_operation
        checked = []

        def overlap(pack_root: Path, target_root: Path, operation: dict[str, str]) -> bool:
            if not checked:
                with self.assertRaisesRegex(ValueError, "already in progress"):
                    aide_lite.apply_import_pack(pack, target)
                with self.assertRaisesRegex(ValueError, "already in progress"):
                    aide_lite.apply_portable_owned_repair(pack, target, ".aide/prompts/compact-task.md")
                cli = pack / "files/.aide/scripts/aide_lite.py"
                other = subprocess.run([sys.executable, "-I", "-B", str(cli), "--repo-root", str(target), "import-pack", "--pack", str(pack), "--target", str(target)], text=True, capture_output=True, timeout=30)
                self.assertNotEqual(other.returncode, 0)
                self.assertIn("already in progress", other.stderr)
                self.assertFalse((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
                checked.append(True)
            return real_operation(pack_root, target_root, operation)

        with mock.patch.object(aide_lite, "apply_import_operation", side_effect=overlap):
            first = aide_lite.apply_import_pack(pack, target)
        self.assertEqual(first["status"], "APPLIED")
        self.assertEqual(checked, [True])
        self.assertTrue((target / aide_lite.PORTABLE_IMPORT_RECEIPT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_IMPORT_INTENT_PATH).exists())
        self.assertFalse((target / aide_lite.PORTABLE_LIFECYCLE_LOCK_PATH).exists())
        self.assertEqual(aide_lite.apply_import_pack(pack, target)["status"], "NO_CHANGES")

    def test_owned_repair_cleanup_rejects_junction_swap_on_success_and_recovery(self) -> None:
        source_root = self.make_source_repo()
        pack = self.freeze_pack(source_root, "repair-cleanup-junction-pack")
        rel = ".aide/prompts/compact-task.md"
        for scenario in ("success", "recovery"):
            with self.subTest(scenario=scenario):
                target = source_root.parent / f"repair-cleanup-{scenario}-consumer"
                aide_lite.apply_import_pack(pack, target)
                managed = target / rel
                managed.unlink()
                preview = aide_lite.apply_portable_owned_repair(pack, target, rel, dry_run=True)
                if scenario == "recovery":
                    interrupted = aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"], fail_after_write=True)
                    self.assertEqual(interrupted["status"], "INTERRUPTED")
                install = (target / aide_lite.PORTABLE_REPAIR_INTENT_PATH).parent
                moved = install.with_name("install-before-junction-swap")
                outside = source_root.parent / f"repair-cleanup-{scenario}-outside"
                outside.mkdir()
                outside_same_name = outside / Path(aide_lite.PORTABLE_REPAIR_INTENT_PATH).name
                outside_same_name.write_bytes(b"outside project-owned intent name\n")
                observed_intent = []
                real_cleanup = aide_lite.delete_portable_repair_intent_anchored

                def swap_at_cleanup(root: Path, intent: dict[str, object]) -> None:
                    observed_intent.append((install / Path(aide_lite.PORTABLE_REPAIR_INTENT_PATH).name).read_bytes())
                    install.rename(moved)
                    junction = subprocess.run(["cmd", "/c", "mklink", "/J", str(install), str(outside)], text=True, capture_output=True, timeout=10)
                    self.assertEqual(junction.returncode, 0, junction.stderr)
                    self.assertTrue(install.is_junction())
                    real_cleanup(root, intent)

                try:
                    with mock.patch.object(aide_lite, "delete_portable_repair_intent_anchored", side_effect=swap_at_cleanup):
                        with self.assertRaisesRegex(ValueError, "reparse point"):
                            aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])
                    self.assertEqual(outside_same_name.read_bytes(), b"outside project-owned intent name\n")
                    self.assertEqual(len(observed_intent), 1)
                finally:
                    if install.is_junction():
                        install.rmdir()
                    if moved.exists():
                        moved.rename(install)
                intent_path = target / aide_lite.PORTABLE_REPAIR_INTENT_PATH
                self.assertEqual(intent_path.read_bytes(), observed_intent[0])
                if scenario == "success":
                    original_intent = observed_intent[0]
                    intent_record = json.loads(original_intent)
                    altered = bytearray(original_intent)
                    altered[0] ^= 1
                    intent_path.write_bytes(altered)
                    with self.assertRaisesRegex(ValueError, "bytes changed"):
                        aide_lite.delete_portable_repair_intent_anchored(target, intent_record)
                    self.assertEqual(intent_path.read_bytes(), altered)
                    intent_path.write_bytes(original_intent)
                    second_link = intent_path.with_name("intent-second-link")
                    aide_lite.os.link(intent_path, second_link)
                    try:
                        with self.assertRaisesRegex(ValueError, "single-link"):
                            aide_lite.delete_portable_repair_intent_anchored(target, intent_record)
                    finally:
                        second_link.unlink()
                    self.assertEqual(intent_path.read_bytes(), original_intent)
                self.assertEqual(aide_lite.apply_portable_owned_repair(pack, target, rel, expected_plan_digest=preview["plan_digest"])["status"], "RECOVERED")
                self.assertFalse(intent_path.exists())


if __name__ == "__main__":
    unittest.main()
