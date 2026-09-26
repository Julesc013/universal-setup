# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Create tiny selected, prefixed inputs using the public authoring tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from usk_bundle_author import compile_bundle
from usk_bundle_plan import compose_plan, host_target
from usk_bundle_selection import finalize_selection


def create_inputs(root: Path, target: Path, request_id: str) -> dict:
    # The caller creates one fresh owned directory. Never overwrite inputs.
    if any(root.iterdir()):
        raise ValueError("metadata fixture directory must be empty")
    product = root / "product"
    product.mkdir()
    files = {"core": b"selected core payload\r\n" * 7000,
             "addon": b"selected addon payload\r\n" * 4000,
             "alternative": b"must not be selected\r\n"}
    components = []
    for name, data in files.items():
        (product / f"{name}.bin").write_bytes(data)
        components.append({
            "id": name, "required": name == "core",
            "default_selected": name == "core", "requires": [], "conflicts": [],
            "variants": [{"target": host_target(), "files": [{
                "source": f"{name}.bin", "path": f"bin/{name}.bin"}]}],
        })
    definition = product / "product.json"
    definition.write_text(json.dumps({
        "schema": "usk.authoring_project.v1", "product_id": "org.example.metadata",
        "publisher_id": "org.example", "product_version": "1.2.3",
        "allowed_scopes": ["portable"], "components": components,
    }), encoding="utf-8")
    compiled, selected = root / "compiled", root / "selected"
    compiled.mkdir()
    selected.mkdir()
    compile_bundle(definition, host_target(), compiled)
    finalize_selection(compiled / "product.bundle.json", ["addon"], selected)
    request = compose_plan(
        selected / "product.bundle.json", target, request_id=request_id,
        install_id="org.example.metadata.probe", created_at="2026-09-26T00:00:00Z",
        entrypoint_id="main", entrypoint_kind="application",
        entrypoint_path="bin/core.bin")
    # Exercise the accepted source-prefix contract, preserving exact selected
    # payload bytes. The resulting archive is separately hashed and reviewed
    # by the native planner; the intermediate bundle is not a signed product.
    prefixed = root / "prefixed.zip"
    with zipfile.ZipFile(selected / "payload.zip") as source:
        with zipfile.ZipFile(prefixed, "w", compression=zipfile.ZIP_STORED) as output:
            for item in source.infolist():
                info = zipfile.ZipInfo("pkg/" + item.filename, (2026, 1, 1, 0, 0, 0))
                output.writestr(info, source.read(item))
    request["payload"]["archive"].update({
        "path": str(prefixed), "strip_prefix": "pkg",
        "expected_sha256": hashlib.sha256(prefixed.read_bytes()).hexdigest(),
    })
    request["payload"]["archive"]["budgets"]["max_depth"] += 1
    destination = root / "request.json"
    destination.write_text(json.dumps(request) + "\n", encoding="utf-8")
    return {"request_file": str(destination), "archive_file": str(prefixed),
            "archive_sha256": request["payload"]["archive"]["expected_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args()
    print(json.dumps(create_inputs(args.output, args.target, args.request_id)))
