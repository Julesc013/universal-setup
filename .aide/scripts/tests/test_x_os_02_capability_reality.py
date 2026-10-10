from __future__ import annotations

import importlib.util
import argparse
import contextlib
import hashlib
import io
import json
import os
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_x_os_02", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_x_os_02"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


COMMAND_VECTORS = [
    ["capability", "status"],
    ["capability", "scan"],
    ["capability", "ledger"],
    ["capability", "overclaim-report"],
    ["capability", "validate"],
]


def write_fixture(root: Path) -> None:
    (root / ".aide/capabilities").mkdir(parents=True)
    (root / ".aide/reports").mkdir(parents=True)
    (root / ".aide/scripts").mkdir(parents=True)
    (root / ".aide/scripts/tests").mkdir(parents=True)
    (root / ".aide/evals/golden-tasks/capability_command_surface_golden").mkdir(parents=True)
    (root / "docs/reference").mkdir(parents=True)
    (root / ".aide/scripts/aide_lite.py").write_text("# command surface fixture\n", encoding="utf-8")
    (root / ".aide/scripts/tests/test_fixture.py").write_text("# test fixture\n", encoding="utf-8")
    (root / ".aide/evals/golden-tasks/capability_command_surface_golden/task.yaml").write_text("id: capability_command_surface_golden\n", encoding="utf-8")
    (root / "docs/reference/capability-reality-ledger.md").write_text("# Capability Reality Ledger\n", encoding="utf-8")
    (root / ".aide/capabilities/capability-seeds.yaml").write_text(
        "\n".join(
            [
                "schema_version: aide.capability-seeds.v0",
                "seeds:",
                "  - capability_id: fixture_report_command",
                "    title: Fixture Report Command",
                "    description: Fixture report-only command.",
                "    expected_state: exposed",
                "    expected_modifiers:",
                "      - report_only",
                "      - no_call",
                "    expected_evidence_hints:",
                "      - .aide/scripts/aide_lite.py",
                "      - docs/reference/capability-reality-ledger.md",
                "      - .aide/scripts/tests/test_fixture.py",
                "      - .aide/evals/golden-tasks/capability_command_surface_golden/task.yaml",
                "    known_limits:",
                "      - command is report-only",
                "  - capability_id: fixture_unknown",
                "    title: Fixture Unknown",
                "    description: Fixture unknown state.",
                "    expected_state: unknown",
                "    expected_modifiers:",
                "      - unknown",
                "    expected_evidence_hints:",
                "      - missing/evidence.md",
                "    known_limits:",
                "      - intentionally unverified",
                "",
            ]
        ),
        encoding="utf-8",
    )


class XOS02CapabilityRealityTests(unittest.TestCase):
    def test_parser_accepts_capability_commands(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        for command in COMMAND_VECTORS:
            parsed = parser.parse_args(command)
            self.assertTrue(callable(getattr(parsed, "handler", None)), command)

    def test_fixture_ledger_generation_is_no_apply(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            aide_lite.write_capability_scan(root)
            aide_lite.write_capability_ledger(root)
            ledger = json.loads((root / aide_lite.CAPABILITY_LEDGER_JSON_PATH).read_text(encoding="utf-8"))
            self.assertEqual(ledger["schema_version"], "aide.capability-ledger.v0")
            self.assertEqual(ledger["mode"], "report_only")
            self.assertIs(ledger["no_apply_boundary"]["task_execution"], False)
            self.assertIs(ledger["no_apply_boundary"]["repair_execution"], False)
            self.assertIs(ledger["no_apply_boundary"]["branch_mutation"], False)
            self.assertIs(ledger["no_apply_boundary"]["target_mutation"], False)
            self.assertEqual(ledger["no_apply_boundary"]["provider_or_model_calls"], "none")
            self.assertEqual(ledger["no_apply_boundary"]["network_calls"], "none")
            states = {record["dominant_state"] for record in ledger["records"]}
            self.assertIn("exposed", states)
            self.assertIn("unknown", states)
            markdown = (root / aide_lite.CAPABILITY_LEDGER_MD_PATH).read_text(encoding="utf-8")
            for marker in ["report_only", "target_mutation: false", "provider_or_model_calls: none", "network_calls: none"]:
                self.assertIn(marker, markdown)

    def test_changed_source_evidence_invalidates_retained_ledger(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            aide_lite.write_capability_ledger(root)
            (root / ".aide/scripts/aide_lite.py").write_text(
                "# changed command surface fixture\n", encoding="utf-8")
            status = aide_lite.capability_command_status_data(root)
            validity = status.get("ledger_evidence_validity", {})
            self.assertEqual(validity.get("state"), "STALE")

    def test_missing_implementation_evidence_stays_unknown(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            record = aide_lite.capability_record_from_seed(root, {
                "capability_id": "missing_implementation",
                "expected_state": "implemented",
                "expected_evidence_hints": ["core/missing.py"],
                "expected_modifiers": ["report_only"],
            }, 1)
            self.assertEqual(record["dominant_state"], "unknown")

    def test_explicit_refresh_and_unrelated_changes(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            # Complete this small fixture's declared dependencies.
            policy = root / aide_lite.CAPABILITY_POLICY_PATH
            policy.parent.mkdir(parents=True)
            policy.write_text("# public policy\n", encoding="utf-8")
            for rel in aide_lite.CAPABILITY_REQUIRED_FILES:
                path = root / rel
                if not path.exists():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("{}\n", encoding="utf-8")
            (root / "missing").mkdir()
            (root / "missing/evidence.md").write_text("# source hint\n", encoding="utf-8")
            aide_lite.write_capability_ledger(root)
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "CURRENT")
            (root / "unrelated.txt").write_text("authored\n", encoding="utf-8")
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "CURRENT")
            source = root / ".aide/scripts/aide_lite.py"
            source.write_text("# changed source\n", encoding="utf-8")
            old_binding = (root / aide_lite.CAPABILITY_BINDINGS_PATH).read_bytes()
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = aide_lite.command_capability_validate(argparse.Namespace(repo_root=root))
            self.assertEqual(exit_code, 1)
            self.assertEqual((root / aide_lite.CAPABILITY_BINDINGS_PATH).read_bytes(), old_binding)
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "STALE")
            aide_lite.write_capability_ledger(root)
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "CURRENT")
            self.assertEqual((root / "unrelated.txt").read_text(encoding="utf-8"), "authored\n")

    def test_legacy_incomplete_and_tampered_bindings(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "UNKNOWN")

            aide_lite.write_capability_ledger(root)
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "UNKNOWN")
            ledger_path = root / aide_lite.CAPABILITY_LEDGER_JSON_PATH
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            ledger["records"][0]["title"] = "tampered retained record"
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "STALE")
            binding = root / aide_lite.CAPABILITY_BINDINGS_PATH
            binding.write_text('{"schema_version":true}\n', encoding="utf-8")
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "UNKNOWN")
            binding.write_text('{"inputs":[],"inputs":[]}\n', encoding="utf-8")
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "UNKNOWN")

    def test_input_mutation_during_generation_cannot_be_current(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            seed_path = root / aide_lite.CAPABILITY_SEEDS_PATH
            original_seed_hash = hashlib.sha256(seed_path.read_bytes()).hexdigest()
            original = aide_lite.capability_ledger_data
            def mutate(*args, **kwargs):
                data = original(*args, **kwargs)
                seed_path.write_text(seed_path.read_text(encoding="utf-8").replace(
                    "expected_state: exposed", "expected_state: documented"), encoding="utf-8")
                return data
            with mock.patch.object(aide_lite, "capability_ledger_data", mutate):
                aide_lite.write_capability_ledger(root)
            binding = json.loads((root / aide_lite.CAPABILITY_BINDINGS_PATH).read_text(encoding="utf-8"))
            bound_seed = next(entry for entry in binding["inputs"]
                              if entry["path"] == aide_lite.CAPABILITY_SEEDS_PATH)
            self.assertEqual(bound_seed["sha256"], original_seed_hash)
            ledger = json.loads((root / aide_lite.CAPABILITY_LEDGER_JSON_PATH).read_text(encoding="utf-8"))
            self.assertEqual(ledger["records"][0]["dominant_state"], "exposed")
            self.assertEqual(aide_lite.capability_ledger_evidence_validity(root)["state"], "STALE")

    def test_public_reader_excludes_private_external_and_redirected(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            for rel in [".env", ".env.example", "secrets/fixture.txt", ".aide.local/fixture.txt"]:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("harmless exclusion fixture\n", encoding="utf-8")
            for rel in [".env", ".env.example", "secrets/fixture.txt", ".aide.local/fixture.txt",
                        "../outside.txt", "https://example.invalid/fixture", "C:/fixture.txt"]:
                with mock.patch.object(Path, "open", side_effect=AssertionError("excluded content read")):
                    entry, content = aide_lite.capability_evidence_read(root, rel)
                self.assertIsNone(content, rel)
                self.assertEqual(entry["state"], "unknown")
                self.assertFalse(aide_lite.capability_path_exists(root, rel))
            target = root / "public.txt"
            target.write_text("harmless public fixture\n", encoding="utf-8")
            real_lstat = Path.lstat
            def redirected(path):
                info = real_lstat(path)
                if path == target:
                    return argparse.Namespace(st_mode=info.st_mode, st_file_attributes=1024)
                return info
            with mock.patch.object(Path, "lstat", redirected), mock.patch.object(
                    Path, "open", side_effect=AssertionError("redirected content read")):
                entry, content = aide_lite.capability_evidence_read(root, "public.txt")
            self.assertEqual(entry["reason"], "redirected")
            self.assertIsNone(content)

    def test_ignored_evidence_is_not_read(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            (root / "ignored.txt").write_text("harmless ignored fixture\n", encoding="utf-8")
            (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
            with mock.patch.object(Path, "open", side_effect=AssertionError("ignored content read")):
                entry, content = aide_lite.capability_evidence_read(root, "ignored.txt")
            self.assertIsNone(content)
            self.assertEqual(entry["reason"], "ignored")

    def test_hard_linked_public_alias_is_not_read(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            private = root / ".aide.local/harmless.txt"
            private.parent.mkdir()
            private.write_text("harmless private-path fixture\n", encoding="utf-8")
            alias = root / "public-alias.txt"
            os.link(private, alias)
            identity = (private.stat().st_dev, private.stat().st_ino)
            try:
                with mock.patch.object(Path, "open", side_effect=AssertionError("shared alias content read")):
                    entry, content = aide_lite.capability_evidence_read(root, "public-alias.txt")
                self.assertIsNone(content)
                self.assertEqual(entry["reason"], "shared_or_unstable_identity")
            finally:
                info = alias.lstat()
                self.assertEqual((info.st_dev, info.st_ino), identity)
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertFalse(alias.is_symlink())
                self.assertEqual(alias.resolve(strict=True).parent, root.resolve(strict=True))
                alias.unlink()
            self.assertEqual(private.stat().st_nlink, 1)
            self.assertEqual(private.read_text(encoding="utf-8"), "harmless private-path fixture\n")

    def test_bounded_reader_and_truncated_dependencies_remain_unknown(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            (root / "bounded.txt").write_bytes(b"12345")
            with mock.patch.object(Path, "open", side_effect=AssertionError("over-budget content read")):
                entry, content = aide_lite.capability_evidence_read(root, "bounded.txt", maximum=4)
            self.assertIsNone(content)
            self.assertEqual(entry["reason"], "read_budget")
            for rel in [aide_lite.CAPABILITY_BINDINGS_SCHEMA_PATH,
                        aide_lite.CAPABILITY_OBSERVATION_SCHEMA_PATH]:
                (root / rel).write_text("{}\n", encoding="utf-8")
            admitted_reads = []
            original_read = aide_lite.capability_evidence_read
            def count_reads(*args, **kwargs):
                entry, content = original_read(*args, **kwargs)
                if content is not None:
                    admitted_reads.append(entry["path"])
                return entry, content
            with mock.patch.object(aide_lite, "CAPABILITY_EVIDENCE_MAX_REFS", 2), mock.patch.object(
                    aide_lite, "capability_evidence_read", count_reads):
                snapshot = aide_lite.capability_evidence_snapshot(root)
            self.assertEqual(len(snapshot["inputs"]), 2)
            self.assertEqual(len(admitted_reads), 2)
            self.assertIn(aide_lite.CAPABILITY_SEEDS_PATH, admitted_reads)
            self.assertEqual([entry["path"] for entry in snapshot["inputs"]], sorted(admitted_reads))
            self.assertTrue(snapshot["truncated"])
            self.assertFalse(snapshot["complete"])
            with mock.patch.object(aide_lite, "CAPABILITY_EVIDENCE_MAX_TOTAL_BYTES", 1):
                snapshot = aide_lite.capability_evidence_snapshot(root)
            self.assertFalse(snapshot["complete"])

    def test_test_source_presence_does_not_add_executed_test_state(self) -> None:
        seed = {"expected_state": "documented"}
        states = aide_lite.capability_observed_states(seed, [".aide/scripts/tests/test_fixture.py"])
        self.assertNotIn("tested", states)

    def test_scan_and_ledger_agree_when_code_evidence_is_missing(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            write_fixture(root)
            (root / ".aide/scripts/aide_lite.py").unlink()
            ledger = aide_lite.capability_ledger_data(root)
            self.assertEqual(ledger["records"][0]["dominant_state"], "unknown")
            observations = [row for row in aide_lite.capability_observation_records(root)
                            if row["capability_id"] == "fixture_report_command"]
            self.assertTrue(observations)
            self.assertEqual({row["observed_state"] for row in observations}, {"unknown"})

    def test_changed_read_consumes_budget_and_remains_unknown(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            (root / "public.txt").write_bytes(b"12345")
            original = os.fstat
            calls = []
            def changing(fd):
                info = original(fd)
                calls.append(fd)
                return argparse.Namespace(st_dev=info.st_dev, st_ino=info.st_ino,
                    st_mode=info.st_mode, st_nlink=info.st_nlink,
                    st_size=info.st_size, st_mtime_ns=info.st_mtime_ns + (len(calls) == 2))
            budget = [5]
            with mock.patch.object(os, "fstat", changing):
                entry, content = aide_lite.capability_evidence_read(root, "public.txt", budget=budget)
            self.assertIsNone(content)
            self.assertEqual(entry["reason"], "changed_during_read")
            self.assertEqual(budget, [0])

    def test_public_cli_stale_validation_and_explicit_refresh(self) -> None:
        with aide_lite.public_archive_fixture("aide-public-release-test-") as temp:
            root = Path(temp)
            refs = {".aide/scripts/aide_lite.py", aide_lite.CAPABILITY_POLICY_PATH,
                    aide_lite.GOLDEN_TASK_CATALOG_PATH, aide_lite.CAPABILITY_BINDINGS_SCHEMA_PATH,
                    *aide_lite.CAPABILITY_REQUIRED_FILES}
            for seed in aide_lite.capability_seed_records(REPO_ROOT):
                refs.update(seed.get("expected_evidence_hints", []))
            for task_id in aide_lite.CAPABILITY_GOLDEN_TASK_IDS:
                refs.update(f"{aide_lite.GOLDEN_TASK_ROOT}/{task_id}/{name}"
                            for name in ("task.yaml", "acceptance.md"))
            self.assertLessEqual(len(refs), 128)
            copied = []
            for rel in sorted(refs):
                entry, content = aide_lite.capability_evidence_read(REPO_ROOT, rel)
                self.assertIsNotNone(content, f"public fixture dependency {rel}: {entry}")
                destination = root / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                copied.append({"path": rel, "sha256": entry["sha256"]})
            authored = root / "AUTHORED.txt"
            authored.write_text("preserve this authored fixture\n", encoding="utf-8")
            invocations = []
            def invoke(command, expected, marker=None):
                process = subprocess.run([sys.executable, "-I", "-B",
                    str(root / ".aide/scripts/aide_lite.py"), "--repo-root", str(root),
                    "capability", command], cwd=root, capture_output=True, text=True, timeout=90)
                print(f"\n=== capability CLI {command} exit={process.returncode} ===\n"
                      + process.stdout + process.stderr, flush=True)
                self.assertEqual(process.returncode, expected)
                if marker:
                    self.assertIn(marker, process.stdout)
                invocations.append({"command": command, "exit_code": process.returncode,
                    "stdout_sha256": hashlib.sha256(process.stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(process.stderr.encode()).hexdigest()})
            invoke("scan", 0)
            invoke("ledger", 0)
            invoke("overclaim-report", 0)
            invoke("status", 0, "ledger_evidence_validity: CURRENT")
            invoke("validate", 0, "result: PASS")
            binding = root / aide_lite.CAPABILITY_BINDINGS_PATH
            ledger = root / aide_lite.CAPABILITY_LEDGER_JSON_PATH
            retained = (binding.read_bytes(), ledger.read_bytes())
            changed = root / aide_lite.CAPABILITY_DOC_PATH
            with changed.open("a", encoding="utf-8") as stream:
                stream.write("\nHarmless bound source change for qualification.\n")
            invoke("status", 0, "ledger_evidence_validity: STALE")
            invoke("validate", 1, "Capability ledger evidence validity: STALE")
            self.assertEqual((binding.read_bytes(), ledger.read_bytes()), retained)
            invoke("ledger", 0)
            invoke("status", 0, "ledger_evidence_validity: CURRENT")
            invoke("validate", 0, "result: PASS")
            self.assertEqual(authored.read_text(encoding="utf-8"), "preserve this authored fixture\n")
            proof = {"copied_inputs": copied, "invocations": invocations,
                     "authored_preserved": True, "stale_validation_did_not_rebind": True}
            if os.environ.get("AIDE_JOB_OUTPUT"):
                (Path(os.environ["AIDE_JOB_OUTPUT"]) / "capability-cli-proof.json").write_text(
                    json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_overclaim_detector_flags_bad_claim(self) -> None:
        ledger = {
            "records": [
                {
                    "capability_id": "bad_docs_claim",
                    "dominant_state": "implemented",
                    "modifiers": ["docs_only"],
                    "evidence_classes": ["docs_only"],
                    "evidence_refs": ["docs/reference/example.md"],
                    "limitations": [],
                }
            ]
        }
        records = aide_lite.capability_overclaim_records(ledger)
        self.assertEqual(records[0]["overclaim_class"], "docs_only_claimed_as_implemented")
        self.assertIs(records[0]["blocking"], True)

    def test_current_repo_validation_registration_passes_without_reports(self) -> None:
        checks = aide_lite.validate_capability_files(REPO_ROOT, require_reports=False)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_x_os_02_golden_runners_are_registered(self) -> None:
        definitions = {task.task_id for task in aide_lite.parse_golden_task_catalog(REPO_ROOT)}
        for task_id in aide_lite.CAPABILITY_GOLDEN_TASK_IDS:
            self.assertIn(task_id, definitions)


if __name__ == "__main__":
    unittest.main()
