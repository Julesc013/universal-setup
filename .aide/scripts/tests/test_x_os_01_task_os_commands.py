from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_x_os_01", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_x_os_01"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


COMMAND_VECTORS = [
    ["task", "status"],
    ["task", "classify"],
    ["task", "repair-plan"],
    ["task", "requeue-plan"],
    ["task", "resume-plan"],
    ["task", "next-plan"],
    ["blocker", "status"],
    ["blocker", "classify"],
    ["wave", "status"],
    ["wave", "plan"],
    ["checkpoint", "status"],
    ["checkpoint", "plan"],
]


def write_fixture(root: Path) -> None:
    (root / ".aide/queue/FIXTURE-TASK/evidence").mkdir(parents=True)
    (root / ".aide/context").mkdir(parents=True)
    (root / ".aide/reports").mkdir(parents=True)
    (root / ".aide/queue/index.yaml").write_text(
        "\n".join(
            [
                "schema_version: aide.queue-index.v0",
                "items:",
                "  - id: FIXTURE-TASK",
                "    title: Fixture Task",
                "    status: running",
                "    planning_state: planned",
                "    path: .aide/queue/FIXTURE-TASK",
                "    evidence:",
                "      - .aide/queue/FIXTURE-TASK/evidence/validation.md",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / ".aide/queue/FIXTURE-TASK/task.yaml").write_text(
        "\n".join(
            [
                "schema_version: aide.task.v1",
                "id: FIXTURE-TASK",
                "title: Fixture Task",
                "status: running",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / ".aide/queue/FIXTURE-TASK/status.yaml").write_text(
        "\n".join(
            [
                "schema_version: aide.task-status.v1",
                "id: FIXTURE-TASK",
                "status: running",
                "result: pending",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / ".aide/queue/FIXTURE-TASK/evidence/validation.md").write_text("# Validation\n\n- pending\n", encoding="utf-8")
    (root / ".aide/context/latest-task-packet.md").write_text("# Task Packet\n\n- task_id: FIXTURE-TASK\n", encoding="utf-8")


def add_queue_task(
    root: Path,
    task_id: str,
    status: str = "needs_review",
    title: str | None = None,
    planning_state: str = "implemented",
) -> None:
    title = title or task_id
    index = root / ".aide/queue/index.yaml"
    index.write_text(
        index.read_text(encoding="utf-8")
        + "\n".join(
            [
                f"  - id: {task_id}",
                f"    title: {title}",
                f"    status: {status}",
                f"    planning_state: {planning_state}",
                f"    task: .aide/queue/{task_id}/task.yaml",
                f"    exec_plan: .aide/queue/{task_id}/ExecPlan.md",
                f"    prompt: .aide/queue/{task_id}/prompt.md",
                f"    evidence: .aide/queue/{task_id}/evidence",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / ".aide/queue" / task_id / "evidence").mkdir(parents=True)
    (root / ".aide/queue" / task_id / "task.yaml").write_text(
        "\n".join(["schema_version: aide.queue-task.v0", f"id: {task_id}", f"title: {title}", ""]),
        encoding="utf-8",
    )
    write_queue_status(root, task_id, status)


def write_queue_status(root: Path, task_id: str, status: str, result: str = "PASS") -> None:
    (root / ".aide/queue" / task_id).mkdir(parents=True, exist_ok=True)
    (root / ".aide/queue" / task_id / "status.yaml").write_text(
        "\n".join(
            [
                "schema_version: aide.queue-status.v0",
                f"task_id: {task_id}",
                f"status: {status}",
                f"result: {result}",
                "",
            ]
        ),
        encoding="utf-8",
    )


class XOS01TaskOSCommandTests(unittest.TestCase):
    def test_parser_accepts_report_only_commands(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        for command in COMMAND_VECTORS:
            parsed = parser.parse_args(command)
            self.assertTrue(callable(getattr(parsed, "handler", None)), command)

    def test_next_plan_inspects_without_rewriting_report_by_default(self) -> None:
        parser = aide_lite.build_parser(REPO_ROOT)
        self.assertFalse(parser.parse_args(["task", "next-plan"]).write_report)
        self.assertTrue(parser.parse_args(["task", "next-plan", "--write-report"]).write_report)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            report = root / aide_lite.TASK_OS_NEXT_PLAN_REPORT_PATH
            report.write_text("older retained snapshot\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = aide_lite.command_task_next_plan(argparse.Namespace(repo_root=root, write_report=False))
            self.assertEqual(exit_code, 0)
            self.assertEqual(report.read_text(encoding="utf-8"), "older retained snapshot\n")
            self.assertIn("non_mutating: true", output.getvalue())
            self.assertNotIn("report:", output.getvalue())

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = aide_lite.command_task_next_plan(argparse.Namespace(repo_root=root, write_report=True))
            self.assertEqual(exit_code, 0)
            self.assertIn("selected_next_workunit:", report.read_text(encoding="utf-8"))

    def test_fixture_report_generation_is_no_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            aide_lite.write_all_task_os_reports(root)
            for rel in aide_lite.TASK_OS_COMMAND_REPORT_FILES:
                path = root / rel
                self.assertTrue(path.exists(), rel)
                if rel.endswith(".json"):
                    data = json.loads(path.read_text(encoding="utf-8"))
                    self.assertIn("schema_version", data)
                    boundary = data["no_apply_boundary"]
                    self.assertIs(boundary["task_execution"], False)
                    self.assertIs(boundary["repair_execution"], False)
                    self.assertIs(boundary["branch_mutation"], False)
                    self.assertIs(boundary["target_mutation"], False)
                    self.assertEqual(boundary["provider_or_model_calls"], "none")
                    self.assertEqual(boundary["network_calls"], "none")
                    continue
                text = path.read_text(encoding="utf-8")
                for marker in [
                    "report_only",
                    "task_execution: false",
                    "repair_execution: false",
                    "branch_mutation: false",
                    "target_mutation: false",
                    "provider_or_model_calls: none",
                    "network_calls: none",
                ]:
                    self.assertIn(marker, text, rel)
                for forbidden in ["apply_allowed: true", "target_mutation: true", "checkpoint_branch_created: true"]:
                    self.assertNotIn(forbidden, text, rel)

    def test_task_and_blocker_classification_json_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            aide_lite.write_task_os_task_classification(root)
            aide_lite.write_task_os_blocker_classification(root)
            task_data = json.loads((root / aide_lite.TASK_OS_TASK_CLASSIFICATION_JSON_PATH).read_text(encoding="utf-8"))
            blocker_data = json.loads((root / aide_lite.TASK_OS_BLOCKER_CLASSIFICATION_JSON_PATH).read_text(encoding="utf-8"))
            self.assertEqual(task_data["schema_version"], "aide.task-os-task-classification.v0")
            self.assertIn(task_data["lifecycle_state"], [*aide_lite.TASK_OS_LIFECYCLE_STATES, "unknown"])
            self.assertEqual(blocker_data["schema_version"], "aide.task-os-blocker-classification.v0")
            self.assertIsInstance(blocker_data["blockers"], list)

    def test_latest_task_parser_preserves_aide_fix_os_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            repair_id = "AIDE-FIX-OS-03-task-os-checkpoint-report-consistency-repair"
            add_queue_task(root, "X-OS-01-aide-task-os-report-only-commands")
            add_queue_task(root, "X-OS-02-capability-reality-ledger-v0")
            add_queue_task(root, "AIDE-CHECK-OS-01-task-os-validation-telemetry-checkpoint")
            add_queue_task(root, repair_id, status="running")
            (root / ".aide/context/latest-task-packet.md").write_text(
                "\n".join(
                    [
                        "# AIDE Latest Task Packet",
                        "",
                        "## PHASE",
                        "",
                        "UNSPECIFIED - AIDE-FIX-OS-03 - Task OS checkpoint report consistency repair after X-OS-02 and AIDE-CHECK-OS-01.",
                        "",
                        "## GOAL",
                        "",
                        "Repair AIDE-FIX-OS-03 without reducing it to X-OS-03.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            raw, resolved = aide_lite.task_os_latest_task_ref(root)
            self.assertEqual(raw, "AIDE-FIX-OS-03")
            self.assertEqual(resolved, repair_id)
            context = aide_lite.task_os_context(root)
            self.assertEqual(context["latest_task_id"], repair_id)
            self.assertEqual(context["latest_task_status"], "running")

    def test_empty_target_packet_does_not_promote_context_to_task_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".aide/queue").mkdir(parents=True)
            (root / ".aide/context").mkdir(parents=True)
            (root / ".aide/queue/index.yaml").write_text(
                "schema_version: aide.queue-index.v0\nitems:\n", encoding="utf-8"
            )
            (root / ".aide/context/latest-task-packet.md").write_text(
                "\n".join(
                    [
                        "# AIDE Latest Task Packet",
                        "",
                        "## PHASE",
                        "",
                        "UNSPECIFIED - Disposable installed AIDE context evidence smoke task",
                        "Prior Q17 and X-OS-01 are background only.",
                        "",
                        "## GOAL",
                        "",
                        "Disposable installed AIDE context evidence smoke task",
                        "AIDE-APPLY-00 appears here only as explanatory text.",
                        "",
                        "## CONTEXT_REFS",
                        "",
                        "- run route explain after Q17",
                        "- source X-OS-01 is background context only",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            self.assertEqual(aide_lite.task_os_latest_task_ref(root), ("", ""))
            context = aide_lite.task_os_context(root)
            self.assertEqual(context["task_count"], 0)
            self.assertEqual(context["latest_task_id"], "")
            selection = aide_lite.task_os_next_selection(context)
            self.assertEqual(selection["task"], "No queued WorkUnit selected")
            self.assertFalse(selection["aide_apply_00_next_packet_ready"])
            self.assertFalse(selection["lifecycle_apply_authorized"])
            report = aide_lite.task_os_render_task_status(context)
            self.assertIn("latest_task_packet_id: `none`", report)
            self.assertIn("selected_next_workunit: No queued WorkUnit selected", report)
            self.assertNotIn("selected_next_workunit: X-OS-01", report)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = aide_lite.command_task_status(argparse.Namespace(repo_root=root))
            self.assertEqual(exit_code, 1)
            self.assertIn("task_count: 0", output.getvalue())
            self.assertIn("latest_task_id: none", output.getvalue())

    def test_nonempty_target_queue_does_not_select_aide_source_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            context = aide_lite.task_os_context(root)
            self.assertEqual(context["task_count"], 1)
            self.assertEqual(context["latest_task_id"], "FIXTURE-TASK")
            selection = aide_lite.task_os_next_selection(context)
            self.assertEqual(selection["task"], "Review target-owned queue WorkUnits")
            self.assertFalse(selection["aide_apply_00_next_packet_ready"])
            self.assertFalse(selection["lifecycle_apply_authorized"])
            task_status = aide_lite.task_os_render_task_status(context)
            self.assertIn("selected_next_workunit: Review target-owned queue WorkUnits", task_status)
            self.assertIn("`FIXTURE-TASK`: status=running", task_status)
            aide_lite.write_task_os_next_plan(root)
            next_plan = (root / aide_lite.TASK_OS_NEXT_PLAN_REPORT_PATH).read_text(encoding="utf-8")
            self.assertIn("selected_next_workunit: Review target-owned queue WorkUnits", next_plan)
            self.assertNotIn("- `X-OS-01 - Task OS Report-Only Commands`", next_plan)
            self.assertNotIn("x_os_01_status:", next_plan)

    def test_target_profile_overrides_colliding_aide_source_task_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            add_queue_task(root, "X-OS-01-aide-task-os-report-only-commands")
            (root / ".aide/profile.yaml").write_text(
                "schema_version: aide.profile.template.v0\n"
                "profile_id: fixture-target\n"
                "status: target_template\n",
                encoding="utf-8",
            )
            context = aide_lite.task_os_context(root)
            selection = aide_lite.task_os_next_selection(context)
            self.assertEqual(selection["task"], "Review target-owned queue WorkUnits")
            self.assertIn("this repository's queue status and evidence", selection["reason"])
            self.assertNotIn("no AIDE self-hosting routing WorkUnit", selection["reason"])
            aide_lite.write_task_os_next_plan(root)
            next_plan = (root / aide_lite.TASK_OS_NEXT_PLAN_REPORT_PATH).read_text(encoding="utf-8")
            self.assertNotIn("x_os_01_status:", next_plan)
            self.assertNotIn("selecting AIDE-APPLY-00", next_plan)

    def test_checkpoint_and_next_plan_use_queue_truth_after_x_os_02(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            repair_id = "AIDE-FIX-OS-03-task-os-checkpoint-report-consistency-repair"
            add_queue_task(root, "X-OS-01-aide-task-os-report-only-commands")
            add_queue_task(root, "X-OS-02-capability-reality-ledger-v0")
            add_queue_task(root, "AIDE-CHECK-OS-01-task-os-validation-telemetry-checkpoint")
            add_queue_task(root, repair_id, status="running")

            aide_lite.write_task_os_checkpoint_status(root)
            checkpoint_text = (root / aide_lite.TASK_OS_CHECKPOINT_STATUS_REPORT_PATH).read_text(encoding="utf-8")
            self.assertIn("x_os_02_status: needs_review", checkpoint_text)
            self.assertIn("aide_fix_os_03_status: running", checkpoint_text)
            self.assertNotIn("missing_or_not_done", checkpoint_text)

            aide_lite.write_task_os_next_plan(root)
            next_text = (root / aide_lite.TASK_OS_NEXT_PLAN_REPORT_PATH).read_text(encoding="utf-8")
            self.assertIn("AIDE-FIX-OS-03 - Task OS checkpoint report consistency repair", next_text)
            self.assertNotIn("`X-OS-02 - Capability Reality Ledger v0`", next_text)

            write_queue_status(root, repair_id, "needs_review")
            aide_lite.write_task_os_next_plan(root)
            repaired_next_text = (root / aide_lite.TASK_OS_NEXT_PLAN_REPORT_PATH).read_text(encoding="utf-8")
            self.assertIn("AIDE-APPLY-00 - Transaction Model", repaired_next_text)
            self.assertIn("aide_apply_00_next_packet_ready: true", repaired_next_text)
            self.assertIn("no apply behavior is authorized by this next plan", repaired_next_text)

            (root / ".aide/context/latest-task-packet.md").write_text(
                "# AIDE Latest Task Packet\n\n## PHASE\n\nAIDE-APPLY-00 - Transaction Model\n",
                encoding="utf-8",
            )
            _json_result, _md_result, data = aide_lite.write_task_os_task_classification(root)
            self.assertEqual(data["latest_task_id"], "AIDE-APPLY-00")
            self.assertEqual(data["latest_task_status"], "missing")
            self.assertEqual(data["lifecycle_state"], "proposed")

    def test_post_apply_status_repair_truth_selects_lifecycle_plan_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_fixture(root)
            apply_id = "AIDE-APPLY-02-scoped-transaction-executor-v0"
            apply_repair_id = "AIDE-APPLY-02-REPAIR-01"
            recheck_id = "AIDE-CHECK-APPLY-02-RECHECK-01"
            closure_id = "AIDE-QUEUE-CLOSURE-02"
            status_repair_id = "AIDE-TASK-OS-STATUS-REPAIR-01"

            add_queue_task(root, apply_id, planning_state="accepted_with_notes")
            add_queue_task(root, apply_repair_id, planning_state="accepted_with_notes")
            add_queue_task(root, recheck_id, planning_state="accepted_with_notes")
            add_queue_task(root, closure_id, planning_state="report_only_completed")
            add_queue_task(root, status_repair_id, status="running", planning_state="report_truth_repair_needs_review")
            (root / ".aide/context/latest-task-packet.md").write_text(
                "\n".join(
                    [
                        "# AIDE Latest Task Packet",
                        "",
                        "## PHASE",
                        "",
                        "AIDE-TASK-OS-STATUS-REPAIR-01 - Task OS Current and Latest-Task Reporting Repair",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            context = aide_lite.task_os_context(root)
            self.assertEqual(context["current_toml_state"], "absent")
            self.assertEqual(context["latest_indexed_task_id"], status_repair_id)
            self.assertEqual(context["latest_task_id"], status_repair_id)
            self.assertEqual(context["latest_task_status"], "running")
            selection = aide_lite.task_os_next_selection(context)
            self.assertIn("AIDE-TASK-OS-STATUS-REPAIR-01", str(selection["task"]))
            self.assertFalse(selection["aide_apply_lifecycle_plan_ready"])
            self.assertFalse(selection["lifecycle_apply_authorized"])

            write_queue_status(root, status_repair_id, "needs_review", "PASS_WITH_WARNINGS")
            context = aide_lite.task_os_context(root)
            selection = aide_lite.task_os_next_selection(context)
            self.assertIn("AIDE-APPLY-LIFECYCLE-PLAN-01", str(selection["task"]))
            self.assertTrue(selection["aide_apply_lifecycle_plan_ready"])
            self.assertFalse(selection["lifecycle_apply_authorized"])

            task_status_text = aide_lite.task_os_render_task_status(context)
            self.assertIn("current_toml_state: absent", task_status_text)
            self.assertIn(f"latest_indexed_task_id: `{status_repair_id}`", task_status_text)
            self.assertIn(f"latest_task_packet_id: `{status_repair_id}`", task_status_text)
            self.assertIn("selected_next_workunit: AIDE-APPLY-LIFECYCLE-PLAN-01", task_status_text)
            self.assertNotIn("latest_task_id: `AIDE-APPLY-02`", task_status_text)
            self.assertNotIn("latest_task_status: `missing`", task_status_text)

            aide_lite.write_task_os_next_plan(root)
            next_text = (root / aide_lite.TASK_OS_NEXT_PLAN_REPORT_PATH).read_text(encoding="utf-8")
            self.assertIn("AIDE-APPLY-LIFECYCLE-PLAN-01", next_text)
            self.assertIn("aide_apply_lifecycle_plan_ready: true", next_text)
            self.assertIn("lifecycle_apply_authorized: false", next_text)
            self.assertIn("authorizes only planning, not lifecycle apply execution", next_text)

            lifecycle_id = "AIDE-APPLY-LIFECYCLE-PLAN-01"
            add_queue_task(root, lifecycle_id, status="pending", planning_state="planned")
            selection = aide_lite.task_os_next_selection(aide_lite.task_os_context(root))
            self.assertIn(lifecycle_id, str(selection["task"]))
            self.assertTrue(selection["aide_apply_lifecycle_plan_ready"])

            write_queue_status(root, lifecycle_id, "needs_review", "PASS_WITH_WARNINGS")
            context = aide_lite.task_os_context(root)
            selection = aide_lite.task_os_next_selection(context)
            self.assertEqual(selection["task"], "Review current AIDE queue WorkUnits")
            self.assertIn("already needs_review", str(selection["reason"]))
            self.assertFalse(selection["aide_apply_lifecycle_plan_ready"])
            self.assertFalse(selection["lifecycle_apply_authorized"])
            self.assertNotIn(
                "selected_next_workunit: AIDE-APPLY-LIFECYCLE-PLAN-01",
                aide_lite.task_os_render_task_status(context),
            )

    def test_current_repo_validation_registration_passes(self) -> None:
        self.assertEqual(aide_lite.task_os_profile_role(REPO_ROOT), "aide_source")
        checks = aide_lite.validate_task_os_command_files(REPO_ROOT)
        failures = [check.message for check in checks if check.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_x_os_01_golden_runners_pass(self) -> None:
        definitions = {task.task_id for task in aide_lite.parse_golden_task_catalog(REPO_ROOT)}
        report_paths = tuple(aide_lite.TASK_OS_COMMAND_REPORT_FILES)

        def source_report_state() -> dict:
            return {
                rel: (path.read_bytes(), path.stat().st_mtime_ns) if path.exists() else None
                for rel in report_paths
                for path in [REPO_ROOT / rel]
            }

        before = source_report_state()
        # Keep the real source context and every golden assertion. Only report
        # destinations change; the runner pins tempfile to admitted scratch.
        with tempfile.TemporaryDirectory(prefix="task-os-golden-") as temporary:
            destinations = {rel: str(Path(temporary) / rel) for rel in report_paths}
            constants = {
                name: value for name, value in vars(aide_lite).items()
                if name.startswith("TASK_OS_") and isinstance(value, str)
                and value in destinations
            }
            self.assertEqual(set(constants.values()), set(report_paths))
            with contextlib.ExitStack() as patches:
                for name, value in constants.items():
                    patches.enter_context(mock.patch.object(aide_lite, name, destinations[value]))
                patches.enter_context(mock.patch.object(
                    aide_lite, "TASK_OS_COMMAND_REPORT_FILES",
                    [destinations[rel] for rel in report_paths],
                ))
                for task_id in aide_lite.XOS01_GOLDEN_TASK_IDS:
                    self.assertIn(task_id, definitions)
                    result = aide_lite.run_golden_task(REPO_ROOT, task_id)
                    self.assertEqual(result.result, "PASS", result.errors)
        self.assertEqual(source_report_state(), before)


if __name__ == "__main__":
    unittest.main()
