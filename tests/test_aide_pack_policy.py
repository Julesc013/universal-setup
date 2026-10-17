# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import aide_pack_policy_check as policy


class AidePackPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sandbox = tempfile.TemporaryDirectory(prefix="usk-aide-policy-")
        cls.root = Path(cls.sandbox.name)
        receipt = json.loads((policy.ROOT / policy.RECEIPT).read_bytes())
        paths = set(receipt["managed"]) | {
            policy.RECEIPT, ".aide/profile.yaml",
            "external/aide/provenance.v1.json", "external/aide/LICENSE", "external/aide/NOTICE",
        }
        for relative in paths:
            target = cls.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(policy.ROOT / relative, target)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.sandbox.cleanup()

    def test_pinned_pack_grants_only_registered_optional_tooling(self) -> None:
        problems, licensed = policy.validate(self.root)
        self.assertEqual([], problems)
        self.assertEqual(819, len(licensed))
        self.assertIn(Path(".aide/scripts/aide_lite.py"), licensed)
        self.assertNotIn(Path("runtime/setup/kernel/usk_api.c"), licensed)
        self.assertNotIn(Path(".aide/unregistered.py"), licensed)

    def test_managed_inputs_survive_normal_git_publication(self) -> None:
        receipt = json.loads((policy.ROOT / policy.RECEIPT).read_bytes())
        names = sorted(receipt["managed"]) + [policy.RECEIPT, ".aide/profile.yaml"]
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "-z", "--stdin"],
            cwd=policy.ROOT, input=("\0".join(names) + "\0").encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertIn(result.returncode, (0, 1), result.stderr.decode())
        self.assertEqual(b"", result.stdout, "receipt-managed inputs must be publishable")

    def test_modified_upstream_script_revokes_all_exceptions(self) -> None:
        path = self.root / ".aide/scripts/aide_lite.py"
        before = path.read_bytes()
        try:
            path.write_bytes(before + b"\n# changed\n")
            problems, licensed = policy.validate(self.root)
            self.assertTrue(any("managed file drifted" in p for p in problems), problems)
            self.assertEqual(set(), licensed)
        finally:
            path.write_bytes(before)

    def test_forged_receipt_cannot_register_runtime_source(self) -> None:
        path = self.root / policy.RECEIPT
        before = path.read_bytes()
        try:
            forged = json.loads(before)
            forged["managed"]["runtime/setup/kernel/usk_api.c"] = next(
                value for value in forged["managed"].values() if value["kind"] == "managed_file")
            path.write_text(json.dumps(forged), encoding="utf-8")
            problems, licensed = policy.validate(self.root)
            self.assertEqual(["AIDE import receipt drifted"], problems)
            self.assertEqual(set(), licensed)
        finally:
            path.write_bytes(before)

    def test_project_guidance_outside_managed_section_is_preserved(self) -> None:
        path = self.root / "AGENTS.md"
        before = path.read_bytes()
        try:
            path.write_bytes(before + b"\nAdditional project-owned guidance.\n")
            self.assertEqual([], policy.validate(self.root)[0])
        finally:
            path.write_bytes(before)


if __name__ == "__main__":
    unittest.main()
