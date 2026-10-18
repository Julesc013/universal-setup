# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import ast
import itertools
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class NativeCiProofTests(unittest.TestCase):
    def test_standalone_ci_builds_and_runs_native_tests(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        required = [
            "actions/checkout@v6",
            "actions/setup-python@v6",
            "python tools/adversarial_coverage_check.py",
            "cmake -S . -B build/smoke",
            "cmake --build build/smoke",
            "ctest --test-dir build/smoke -C Release --output-on-failure",
            "python tools/strict_check.py",
        ]
        positions = [workflow.index(command) for command in required]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("actions/checkout@v4", workflow)
        self.assertNotIn("actions/setup-python@v5", workflow)
        for runner in ("ubuntu-24.04", "macos-15-intel", "windows-2022"):
            self.assertIn(runner, workflow)
        self.assertIn("Bind macOS fixtures to the real no-link temporary root", workflow)
        self.assertIn("os.path.realpath(tempfile.gettempdir())", workflow)
        self.assertIn("native-windows-win32", workflow)
        self.assertIn("cmake -S . -B build/win32 -A Win32", workflow)
        self.assertIn("cppcheck --project=build/smoke/compile_commands.json", workflow)
        self.assertIn("--parallel 4", workflow)

    def test_independent_maintenance_cohorts_require_build_and_trusted_context(self) -> None:
        qualification = WORKFLOW.read_text(encoding="utf-8").split(
            "  publisher-qualification:\n", 1)[1].split("  windows-win32:\n", 1)[0]
        build = "      - run: cmake --build build/smoke --config Release --parallel\n        id: publisher_build\n"
        self.assertEqual(qualification.count(build), 1)
        self.assertLess(qualification.index("id: controller_actor"), qualification.index(build))
        self.assertNotIn("continue-on-error", qualification)

        def value(node: ast.AST):
            # Evaluate only the Boolean/string subset used by the selected actual
            # conditions. This is a data test, not a general Actions interpreter.
            if isinstance(node, ast.Constant) and type(node.value) in (bool, str):
                return node.value
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                return not value(node.operand)
            if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
                values = [value(item) for item in node.values]
                return all(values) if isinstance(node.op, ast.And) else any(values)
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
                return value(node.left) == value(node.comparators[0])
            raise AssertionError("Unsupported cohort condition syntax: " + ast.dump(node))

        cohort_ids = (
            "install_reconnect_verify_and_recover_through_the_ordinary_publisher_client",
            "recover_ordinary_public_requests_after_prepared_and_visible_production_loss",
            "retain_ordinary_public_state_after_payload_drift_and_metadata_collision",
            "qualify_standard_account_public_installation_and_source_free_reentry",
            "observe_original_shared_initial_maintenance_intent_before_staging",
            "qualify_registered_bootstrap_process_loss_takeover_and_preservation",
            "qualify_registered_reentry_after_interruption_of_bootstrap_preservation",
            "qualify_native_recovery_of_constructed_ordered_bootstrap_prefixes",
            "qualify_recovery_of_constructed_durable_bootstrap_states",
            "qualify_native_installation_mutex_through_the_authenticated_public_client",
            "fresh_untraced",
            "observe_standard_account_fresh_repair_move_and_uninstall",
            "recovery_untraced",
            "recover_a_genuinely_interrupted_repair_without_its_source_archive",
        )
        for identity in cohort_ids:
            block = qualification.split("        id: " + identity + "\n", 1)[1].split("      - ", 1)[0]
            condition = next(line.strip()[4:] for line in block.splitlines() if line.strip().startswith("if: "))
            expression = condition.removeprefix("$" + "{{").removesuffix("}}").strip()
            self.assertIn("cancelled()", expression)  # Explicit status check prevents implicit success().
            for cancelled, outcome, windows, pull, same_repo, earlier_failed in itertools.product(
                (False, True), ("success", "failure", "skipped", "cancelled"),
                (False, True), (False, True), (False, True), (False, True)
            ):
                replacements = {
                    "cancelled()": cancelled, "success()": not earlier_failed,
                    "failure()": earlier_failed, "always()": True,
                    "steps.publisher_build.outcome": outcome,
                    "runner.os": "Windows" if windows else "Linux",
                    "github.event_name": "pull_request" if pull else "push",
                    "github.event.pull_request.head.repo.full_name": "owner/setup" if same_repo else "fork/setup",
                    "github.repository": "owner/setup",
                }
                actual = expression
                for token, replacement in replacements.items():
                    actual = actual.replace(token, repr(replacement))
                actual = actual.replace("&&", " and ").replace("||", " or ").replace("!", "not ").strip()
                admitted = value(ast.parse(actual, mode="eval").body)
                expected = not cancelled and outcome == "success" and windows and pull and same_repo
                with self.subTest(cohort=identity, context=replacements):
                    self.assertEqual(admitted, expected)

    def test_publisher_qualification_does_not_hide_core_ctest_or_skip_main(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        core = workflow.split("  test:\n", 1)[1].split("  publisher-qualification:\n", 1)[0]
        qualification = workflow.split("  publisher-qualification:\n", 1)[1].split("  windows-win32:\n", 1)[0]
        self.assertIn("ctest --test-dir build/smoke", core)
        self.assertIn("--label-exclude '^publisher-qualification$'", core)
        self.assertNotIn("windows_publisher_lab_probe.ps1", core)
        self.assertIn("-DUSK_QUALIFICATION_DIAGNOSTICS=OFF", core)
        self.assertIn("-DUSK_QUALIFICATION_DIAGNOSTICS=ON", qualification)
        self.assertIn("|| github.base_ref == 'main'", qualification)
        self.assertLess(qualification.index("Require the admitted same-repository"),
                        qualification.index("actions/checkout@v6"))
        self.assertIn("run: throw 'Publisher qualification requires", qualification)
        self.assertNotIn("continue-on-error", qualification)
        self.assertIn("--label-regex '^publisher-qualification$' --no-tests=error", qualification)
        self.assertIn("id: publisher_hosted", qualification)
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        for name, timeout in (
            ("usk_machine_registered_candidate_hosted", 420),
            ("usk_controller_registered_apply_hosted", 420),
            ("usk_publisher_service_absence_hosted", 15),
        ):
            properties = cmake.split("set_tests_properties(" + name, 1)[1].split(")", 1)[0]
            self.assertIn(f"RUN_SERIAL TRUE TIMEOUT {timeout} LABELS publisher-qualification", properties)
        self.assertEqual(cmake.count("LABELS publisher-qualification"), 3)
        self.assertIn("COMMAND usk_publisher_service_absence_hosted --trusted-hosted-scm-fixture", cmake)
        self.assertNotIn("Retain packaged machine service observation", core)
        self.assertIn("Retain packaged machine service observation", qualification)
        # Recovery must remain an executed qualification step on promotion even
        # though the promotion head is dev, rather than a task-named branch.
        recovery = qualification.split("name: Qualify untraced genuinely interrupted repair", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("startsWith", recovery)
        self.assertIn("windows_publisher_lab_probe.ps1", recovery)
        self.assertIn("-PublicStandardMaintenanceRecoveryQualification", recovery)


if __name__ == "__main__":
    unittest.main()
