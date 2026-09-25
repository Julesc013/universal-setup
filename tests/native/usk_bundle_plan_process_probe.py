#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Exercise an authored bundle plan through the native one-shot host."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from tests.test_bundle_author import project, write_project
from usk_bundle_author import compile_bundle
from usk_bundle_plan import host_target
from usk_bundle_selection import finalize_selection


def main(executable: str) -> None:
    with tempfile.TemporaryDirectory(prefix="usk-authored-plan-") as directory:
        root = Path(directory)
        definition = project()
        definition["components"][0]["variants"][0]["target"] = host_target()
        for name in ("addon", "alternative"):
            definition["components"].append({
                "id": name, "required": False, "default_selected": False,
                "requires": [], "conflicts": [],
                "variants": [{"target": host_target(), "files": [{
                    "source": f"final/{name}.bin", "path": f"bin/{name}.bin"}]}],
            })
        source = write_project(root / "product", definition)
        for name in ("addon", "alternative"):
            (source.parent / "final" / f"{name}.bin").write_bytes(name.encode("ascii"))
        compiled = root / "compiled"
        compiled.mkdir()
        compile_bundle(source, host_target(), compiled)
        selected = root / "selected"
        selected.mkdir()
        finalize_selection(compiled / "product.bundle.json", ["addon"], selected)
        final_bundle = json.loads((selected / "product.bundle.json").read_text(encoding="utf-8"))
        target = root / "installed-product"
        request_file = root / "request.json"
        cli = ROOT / "tools" / "usk_bundle_plan.py"
        command = [sys.executable, str(cli), "--bundle",
                   str(selected / "product.bundle.json"),
                   "--target-root", str(target), "--request-id", "authored-plan-1",
                   "--install-id", "org.example.hello.install.1",
                   "--created-at", "2026-09-25T00:00:00Z",
                   "--entrypoint-id", "main", "--entrypoint-kind", "application",
                   "--entrypoint-path", "bin/app.bin"]
        generated = subprocess.run(command, capture_output=True, timeout=20, check=True)
        request_file.write_bytes(generated.stdout)
        request = json.loads(generated.stdout)
        context = root / "context.json"
        context.write_text(json.dumps({
            "schema": "usk.oneshot_context.v1",
            "state_root": str((root / "setup-state").resolve(strict=False)),
            "authorized_acceptance_root": str(root.resolve(strict=True)),
            "target_policy_activation": "operator_acceptance_candidate",
        }), encoding="utf-8")
        planned = subprocess.run([executable, "--machine", "--request-file",
                                  str(request_file), "--context-file", str(context)],
                                 capture_output=True, timeout=30, check=False)
        assert planned.returncode == 0, planned.stdout + planned.stderr
        assert not planned.stderr, planned.stderr
        response = json.loads(planned.stdout)
        assert response["schema"] == "usk.oneshot_response.v1", response
        assert response["status"] == "ok", response
        result = response["result"]
        assert result["status"] == "ok", result
        assert result["payload"]["required_commit_authority"] == \
            "staged_child_bound_v1", result
        plan = result["payload"]
        assert plan["commit_authority_available"] is False, plan
        assert plan["source"]["sha256"] == final_bundle["payload"]["sha256"], plan
        assert plan["component_selection"] == request["payload"]["recipe"]["components"], plan
        assert set(plan["component_selection"]) == {"core", "addon"}, plan
        assert plan["target"]["root"].replace("\\", "/") == \
            str(target).replace("\\", "/"), plan
        identity = plan["input_identity"]
        recipe = request["payload"]["recipe"]
        assert identity["provider_revision"] == recipe["provider_revision"], plan
        assert identity["recipe_digest"] == recipe["recipe_digest"], plan
        expected_files = {item["path"]: item["sha256"]
                          for component in final_bundle["components"]
                          for item in component["files"]}
        planned_files = {item["relative_path"]: item["sha256"]
                         for item in plan["planned_entries"]
                         if item["entry_type"] == "file"}
        assert planned_files == expected_files, plan
        assert "bin/alternative.bin" not in planned_files, plan
        assert not target.exists() and not (root / "setup-state").exists()
        print("authored-bundle-native-plan-pass")


if __name__ == "__main__":
    main(sys.argv[1])
