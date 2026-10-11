# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_bundle_author import MAX_SOURCE_BYTES, compile_bundle
from usk_bundle_plan import PlanCompositionError, compose_plan, host_target
from usk_bundle_selection import finalize_selection
from tests.test_bundle_author import project, write_project


class BundlePlanTests(unittest.TestCase):
    def _bundle(self, root: Path) -> Path:
        value = project()
        value["components"][0]["variants"][0]["target"] = host_target()
        source = write_project(root / "product", value)
        output = root / "bundle"
        output.mkdir()
        compile_bundle(source, host_target(), output)
        return output / "product.bundle.json"

    def _compose(self, path: Path, root: Path) -> dict:
        return compose_plan(path, root / "target", request_id="plan.1",
                            install_id="install.1", created_at="2026-09-25T00:00:00Z",
                            entrypoint_id="main", entrypoint_kind="application",
                            entrypoint_path="bin/app.bin")

    def test_exact_verified_bundle_composes_strict_read_only_machine_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root)
            request = self._compose(bundle, root)
            payload = request["payload"]
            self.assertEqual(request["command"], "install_local.plan")
            self.assertIs(request["dry_run"], True)
            self.assertEqual(payload["required_commit_authority"], "staged_child_bound_v1")
            self.assertEqual(payload["archive"]["strip_prefix"], "")
            self.assertEqual(payload["archive"]["budgets"]["max_entries"], 1)
            self.assertEqual(payload["recipe"]["components"], ["core"])
            self.assertEqual(payload["recipe"]["entrypoints"][0]["relative_path"],
                             "bin/app.bin")
            self.assertFalse((root / "target").exists())
            self.assertEqual(request, self._compose(bundle, root))

    def test_unselected_component_requires_finalization_and_unknown_entrypoint_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_project(root / "product", project())
            optional = {
                "id": "addon", "required": False, "default_selected": False,
                "requires": [], "conflicts": [],
                "variants": [{"target": host_target(), "files": [
                    {"source": "final/addon.bin", "path": "bin/addon.bin"}]}],
            }
            value = project()
            value["components"][0]["variants"][0]["target"] = host_target()
            value["components"].append(optional)
            source.write_text(json.dumps(value), encoding="utf-8")
            (source.parent / "final" / "addon.bin").write_bytes(b"addon\n")
            compiled = root / "compiled"
            compiled.mkdir()
            compile_bundle(source, host_target(), compiled)
            bundle = compiled / "product.bundle.json"
            with self.assertRaisesRegex(PlanCompositionError, "finalize selection"):
                self._compose(bundle, root)
            final = root / "final"
            final.mkdir()
            finalize_selection(bundle, ["addon"], final)
            final_bundle = final / "product.bundle.json"
            self.assertEqual(set(self._compose(final_bundle, root)["payload"]["recipe"]["components"]),
                             {"core", "addon"})
            with self.assertRaisesRegex(PlanCompositionError, "entrypoint is not a file"):
                compose_plan(final_bundle, root / "target", request_id="plan.1",
                             install_id="install.1", created_at="2026-09-25T00:00:00Z",
                             entrypoint_id="missing", entrypoint_kind="application",
                             entrypoint_path="bin/missing.exe")

    def test_cli_writes_one_request_and_refuses_relative_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root)
            cli = Path(__file__).resolve().parents[1] / "tools" / "usk_bundle_plan.py"
            args = [sys.executable, str(cli), "--bundle", str(bundle),
                    "--target-root", str(root / "target"), "--request-id", "plan.1",
                    "--install-id", "install.1", "--created-at", "2026-09-25T00:00:00Z",
                    "--entrypoint-id", "main", "--entrypoint-kind", "application",
                    "--entrypoint-path", "bin/app.bin"]
            result = subprocess.run(args, capture_output=True, check=True)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout.count(b"\n"), 1)
            self.assertEqual(json.loads(result.stdout), self._compose(bundle, root))
            args[args.index(str(root / "target"))] = "relative-target"
            refused = subprocess.run(args, capture_output=True)
            self.assertEqual(refused.returncode, 2)
            self.assertEqual(refused.stdout, b"")

    def test_scope_target_kind_and_oversized_metadata_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root)
            original = bundle.read_bytes()
            data = json.loads(original)
            data["allowed_scopes"] = ["machine"]
            bundle.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(PlanCompositionError, "portable plan scope"):
                self._compose(bundle, root)
            data["allowed_scopes"] = ["portable"]
            data["target"] = "other-target"
            bundle.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(PlanCompositionError, "target differs"):
                self._compose(bundle, root)
            bundle.write_bytes(original)
            with self.assertRaisesRegex(PlanCompositionError, "entrypoint kind"):
                compose_plan(bundle, root / "target", request_id="plan.1",
                             install_id="install.1", created_at="2026-09-25T00:00:00Z",
                             entrypoint_id="main", entrypoint_kind="driver",
                             entrypoint_path="bin/app.bin")
            bundle.write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
            with self.assertRaisesRegex(PlanCompositionError, "byte budget"):
                self._compose(bundle, root)


if __name__ == "__main__":
    unittest.main()
