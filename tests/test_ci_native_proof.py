# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

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

    def test_publisher_qualification_does_not_hide_core_ctest_or_skip_main(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        core = workflow.split("  test:\n", 1)[1].split("  publisher-qualification:\n", 1)[0]
        qualification = workflow.split("  publisher-qualification:\n", 1)[1].split("  windows-win32:\n", 1)[0]
        self.assertIn("ctest --test-dir build/smoke", core)
        self.assertNotIn("windows_publisher_lab_probe.ps1", core)
        self.assertIn("-DUSK_QUALIFICATION_DIAGNOSTICS=OFF", core)
        self.assertIn("-DUSK_QUALIFICATION_DIAGNOSTICS=ON", qualification)
        self.assertIn("|| github.base_ref == 'main'", qualification)
        self.assertLess(qualification.index("Require the admitted same-repository"),
                        qualification.index("actions/checkout@v6"))
        self.assertIn("run: throw 'Publisher qualification requires", qualification)
        self.assertNotIn("continue-on-error", qualification)
        # Recovery must remain an executed qualification step on promotion even
        # though the promotion head is dev, rather than a task-named branch.
        recovery = qualification.split("name: Qualify untraced genuinely interrupted repair", 1)[1].split("      - name:", 1)[0]
        self.assertNotIn("startsWith", recovery)
        self.assertIn("windows_publisher_lab_probe.ps1", recovery)
        self.assertIn("-PublicStandardMaintenanceRecoveryQualification", recovery)


if __name__ == "__main__":
    unittest.main()
