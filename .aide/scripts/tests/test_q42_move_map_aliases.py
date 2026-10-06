from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / ".aide/scripts/aide_lite.py"
SPEC = importlib.util.spec_from_file_location("aide_lite_q42", MODULE_PATH)
aide_lite = importlib.util.module_from_spec(SPEC)
sys.modules["aide_lite_q42"] = aide_lite
assert SPEC.loader is not None
SPEC.loader.exec_module(aide_lite)


class Q42MoveMapAliasTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for rel in [*aide_lite.Q42_POLICY_FILES, *aide_lite.Q42_SCHEMA_FILES, aide_lite.PATH_ALIASES_TEMPLATE_PATH]:
            source = REPO_ROOT / rel
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        self.write(root, "README.md", "# Fixture\n\nSee old/path.py for stale docs.\n")
        self.write(root, "scripts/validate_repo.py", "print('validate')\n")
        self.write_json(
            root,
            aide_lite.DOC_LINK_MAP_JSON_PATH,
            {"records": [{"doc_path": "README.md", "stale_candidates": ["old/path.py"]}]},
        )
        self.write_json(
            root,
            aide_lite.TOOL_WRAP_PLAN_JSON_PATH,
            {
                "wrapper_plans": [
                    {
                        "source_tool": "scripts/validate_repo.py",
                        "capability_family": "validate",
                        "target_aide_command_hint": "aide validate",
                    }
                ]
            },
        )
        return root

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def write_json(self, root: Path, rel: str, data: object) -> None:
        self.write(root, rel, json.dumps(data, indent=2, sort_keys=True) + "\n")

    def run_cmd(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write_all_map_outputs(self, root: Path) -> None:
        bundle = aide_lite.build_refactor_map_bundle(root)
        aide_lite.write_refactor_map_outputs(root, bundle)

    def move_entry(self) -> dict[str, object]:
        return {
            "entry_id": "move-src-tool",
            "source_path": "scripts/validate_repo.py",
            "target_path": ".aide/tools/wrappers/validate_repo.py",
            "status": "candidate",
            "reason": "fixture candidate only",
            "owner": "AIDE test fixture",
            "source_kind": "tool",
            "target_owner_hint": "AIDE control plane",
            "identity_sensitive": False,
            "build_sensitive": False,
            "authority_sensitive": False,
            "generated_sensitive": False,
            "reference_rewrite_required": True,
            "alias_required": True,
            "validators_required": ["refactor validate-map"],
            "rollback_hint": "no apply in Q42",
            "review_required": True,
            "apply_allowed": False,
        }

    def alias_entry(self) -> dict[str, object]:
        return {
            "alias_id": "alias-src-tool",
            "old_path": "scripts/validate_repo.py",
            "new_path": ".aide/tools/wrappers/validate_repo.py",
            "alias_type": "compatibility_alias",
            "status": "candidate",
            "owner": "AIDE test fixture",
            "reason": "fixture candidate only",
            "consumers": ["README.md"],
            "validation": ["refactor validate-map"],
            "created_in": "Q42",
            "retire_after": "future reviewed condition",
            "apply_allowed": False,
        }

    def test_map_policy_anchors(self) -> None:
        root = self.make_repo()
        checks = aide_lite.validate_refactor_map_files(root, require_latest=False)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")
        move_policy = (root / aide_lite.MOVE_MAP_POLICY_PATH).read_text(encoding="utf-8")
        self.assertIn("candidate_only", move_policy)
        self.assertIn("no_apply_in_q42", move_policy)
        self.assertIn("no_file_moves", move_policy)
        self.assertIn("no_file_deletes", move_policy)

    def test_valid_move_map_fixture_passes(self) -> None:
        root = self.make_repo()
        move_map = aide_lite.build_current_move_map(root)
        move_map["entries"] = [self.move_entry()]
        checks = aide_lite.validate_move_map_data(root, move_map)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_invalid_move_map_with_apply_allowed_true_fails(self) -> None:
        root = self.make_repo()
        move_map = aide_lite.build_current_move_map(root)
        entry = self.move_entry()
        entry["apply_allowed"] = True
        move_map["entries"] = [entry]
        checks = aide_lite.validate_move_map_data(root, move_map)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_invalid_salvage_map_with_drop_candidate_delete_approval_fails(self) -> None:
        root = self.make_repo()
        salvage_map = aide_lite.build_current_salvage_map(root)
        salvage_map["entries"] = [
            {
                "entry_id": "salvage-bad",
                "source_path": "old/tool.py",
                "item_kind": "tool_candidate",
                "item_description": "bad deletion language",
                "recommended_fate": "drop_candidate",
                "target_hint": "",
                "reason": "deletion approved",
                "preservation_notes": ["safe_to_delete"],
                "validators_required": ["refactor validate-map"],
                "review_required": True,
                "apply_allowed": False,
            }
        ]
        checks = aide_lite.validate_salvage_map_data(root, salvage_map)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_valid_path_alias_fixture_passes(self) -> None:
        root = self.make_repo()
        move_map = aide_lite.build_current_move_map(root)
        move_map["entries"] = [self.move_entry()]
        aliases = aide_lite.build_current_path_aliases(root, move_map)
        checks = aide_lite.validate_path_alias_plan_data(root, aliases)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_invalid_alias_with_active_apply_fails(self) -> None:
        root = self.make_repo()
        aliases = aide_lite.build_current_path_aliases(root, {})
        entry = self.alias_entry()
        entry["status"] = "active_future"
        entry["apply_allowed"] = True
        aliases["aliases"] = [entry]
        checks = aide_lite.validate_path_alias_plan_data(root, aliases)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_reference_rewrite_plan_fixture_validates(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_reference_rewrite_plan(root)
        self.assertEqual(len(plan["entries"]), 1)
        checks = aide_lite.validate_reference_rewrite_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "PASS")

    def test_invalid_rewrite_plan_with_active_rewrite_fails(self) -> None:
        root = self.make_repo()
        plan = aide_lite.build_reference_rewrite_plan(root)
        plan["entries"][0]["status"] = "future_applied"
        plan["entries"][0]["apply_allowed"] = True
        checks = aide_lite.validate_reference_rewrite_plan_data(root, plan)
        self.assertEqual(aide_lite.result_from_checks(checks), "FAIL")

    def test_map_command_writes_candidate_artifacts_and_validate_map_passes(self) -> None:
        root = self.make_repo()
        source = root / "scripts/validate_repo.py"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        result = self.run_cmd(root, "refactor", "map")
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertTrue((root / aide_lite.CURRENT_MOVE_MAP_JSON_PATH).exists())
        self.assertTrue((root / aide_lite.CURRENT_SALVAGE_MAP_JSON_PATH).exists())
        self.assertTrue((root / aide_lite.CURRENT_PATH_ALIASES_YAML_PATH).exists())
        self.assertTrue((root / aide_lite.REFERENCE_REWRITE_PLAN_JSON_PATH).exists())
        validate = self.run_cmd(root, "refactor", "validate-map")
        self.assertEqual(validate.returncode, 0, validate.stderr or validate.stdout)
        after = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertTrue(source.exists())

    def test_generated_maps_are_not_portable_export_truth(self) -> None:
        generated = set(aide_lite.Q42_GENERATED_OUTPUT_FILES)
        portable = set(aide_lite.Q42_PORTABLE_SOURCE_FILES)
        self.assertFalse(generated & portable)
        self.assertIn(aide_lite.PATH_ALIASES_TEMPLATE_PATH, portable)


if __name__ == "__main__":
    unittest.main()
