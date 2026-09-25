# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Build an external C product and exercise actual packaged machine hosts."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from usk_bundle_author import compile_bundle, inspect_bundle
from usk_bundle_selection import finalize_selection, inspect_selection
from usk_component_resolver import resolve_component_ids
from usk_prefab_envelope import build_envelope, inspect_envelope


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def run(runtime: Path, runtime_source_commit: str, runtime_cmake_cache: Path) -> dict:
    if _git("status", "--porcelain"):
        raise RuntimeError("external probe requires a clean source checkout")
    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("GCC is required for the external C product probe")
    runtime = runtime.resolve(strict=True)
    runtime_cmake_cache = runtime_cmake_cache.resolve(strict=True)
    runtime_source_tree = subprocess.check_output(
        ["git", "show", "-s", "--format=%T", runtime_source_commit],
        cwd=ROOT, text=True).strip()
    compiler_version = subprocess.check_output([compiler, "--version"], text=True).splitlines()[0]
    request = (b'{"schema":"usk.oneshot_request.v1","request_id":"external-probe",'
               b'"command":"command_graph.inspect","payload":{},"dry_run":true}')
    observations = []
    with tempfile.TemporaryDirectory(prefix="usk-prefab-external-") as directory:
        base = Path(directory)
        product = base / "external product"
        final = product / "final"
        final.mkdir(parents=True)
        program = product / "hello.c"
        program.write_bytes(b"int main(void) { return 0; }\n")
        application = final / "hello.exe"
        subprocess.run([compiler, str(program), "-o", str(application)],
                       check=True, capture_output=True)
        for name in ("addon", "alternative", "library"):
            (final / f"{name}.txt").write_text(name + "\n", encoding="utf-8")
        project = {
            "schema": "usk.authoring_project.v1", "product_id": "org.example.hello",
            "publisher_id": "org.example", "product_version": "1.0.0",
            "allowed_scopes": ["portable"],
            "components": [
                {"id": "core", "required": True, "default_selected": True,
                 "requires": [], "conflicts": [], "variants": [{
                     "target": "windows-x64", "files": [{
                         "source": "final/hello.exe", "path": "bin/hello.exe"}]}]},
                {"id": "library", "required": False, "default_selected": False,
                 "requires": [], "conflicts": [], "variants": [{
                     "target": "windows-x64", "files": [{
                         "source": "final/library.txt", "path": "docs/library.txt"}]}]},
                {"id": "addon", "required": False, "default_selected": False,
                 "requires": ["library"], "conflicts": ["alternative"], "variants": [{
                     "target": "windows-x64", "files": [{
                         "source": "final/addon.txt", "path": "docs/addon.txt"}]}]},
                {"id": "alternative", "required": False, "default_selected": False,
                 "requires": [], "conflicts": [], "variants": [{
                     "target": "windows-x64", "files": [{
                         "source": "final/alternative.txt", "path": "docs/alternative.txt"}]}]},
            ],
        }
        definition = product / "project.json"
        definition.write_text(json.dumps(project), encoding="utf-8")
        compiled = base / "compiled"
        compiled.mkdir()
        bundle = compile_bundle(definition, "windows-x64", compiled)
        if inspect_bundle(compiled / "product.bundle.json") != bundle:
            raise RuntimeError("external compiled bundle failed inspection")
        selected_root = base / "selected"
        selected_root.mkdir()
        selection_receipt = finalize_selection(
            compiled / "product.bundle.json", ["addon"], selected_root)
        if inspect_selection(compiled / "product.bundle.json", selected_root) != \
                selection_receipt:
            raise RuntimeError("external finalized selection failed inspection")
        selected_bundle = inspect_bundle(selected_root / "product.bundle.json")
        if ([entry["id"] for entry in selected_bundle["components"]] !=
                ["addon", "core", "library"] or
                selection_receipt["selected_components"] != ["core", "library", "addon"]):
            raise RuntimeError("external selected component closure changed")
        with zipfile.ZipFile(selected_root / "payload.zip") as selected_archive:
            if selected_archive.namelist() != [
                    "bin/hello.exe", "docs/addon.txt", "docs/library.txt"]:
                raise RuntimeError("external selected payload retained an unselected file")
        selected_envelope = base / "selected-sidecar"
        selected_envelope.mkdir()
        build_envelope(selected_root / "product.bundle.json", runtime,
                       "sidecar", selected_envelope)
        selected_host = selected_envelope / "usk_machine.exe"
        selected_info = subprocess.run(
            [str(selected_host), "--product-info",
             str(selected_envelope / "product.bundle.json")],
            capture_output=True, timeout=30)
        if selected_info.returncode or selected_info.stderr:
            raise RuntimeError("packaged selected product failed native inspection")
        native_selected_info = json.loads(selected_info.stdout)
        if (native_selected_info.get("component_ids") != ["addon", "core", "library"] or
                native_selected_info.get("file_count") != 3 or
                native_selected_info.get("payload_sha256") !=
                selected_bundle["payload"]["sha256"]):
            raise RuntimeError("packaged native selection differs from finalized bytes")
        finalized_observation = {
            "requested_components": ["addon"],
            "selected_components": selection_receipt["selected_components"],
            "receipt_sha256": _sha256(selected_root / "selection.receipt.json"),
            "payload_sha256": selected_bundle["payload"]["sha256"],
            "packaged_native_info_sha256": hashlib.sha256(selected_info.stdout).hexdigest(),
            "unselected_payload_excluded": True,
        }
        for profile in ("sidecar", "one_file_carrier"):
            output = base / profile
            output.mkdir()
            manifest = build_envelope(compiled / "product.bundle.json", runtime, profile, output)
            carrier = output if profile == "sidecar" else output / "setup.carrier.zip"
            if inspect_envelope(carrier) != manifest:
                raise RuntimeError("packaged envelope failed inspection")
            if profile == "one_file_carrier":
                extracted = base / "extracted"
                extracted.mkdir()
                with zipfile.ZipFile(carrier) as archive:
                    archive.extractall(extracted)
                if inspect_bundle(extracted / "product.bundle.json") != bundle:
                    raise RuntimeError("extracted carrier changed the product graph")
                host = extracted / "usk_machine.exe"
            else:
                host = carrier / "usk_machine.exe"
            result = subprocess.run([str(host), "--machine"], input=request,
                                    capture_output=True, timeout=15)
            if result.returncode or result.stderr or not result.stdout.startswith(b"{"):
                raise RuntimeError(f"packaged host failed in {profile}")
            response = json.loads(result.stdout)
            if response.get("request_id") != "external-probe":
                raise RuntimeError("packaged host response does not bind request")
            product_path = (extracted if profile == "one_file_carrier" else carrier)
            product_info = subprocess.run(
                [str(host), "--product-info", str(product_path / "product.bundle.json")],
                capture_output=True, timeout=30)
            if product_info.returncode or product_info.stderr:
                raise RuntimeError(f"packaged host did not inspect product in {profile}")
            info = json.loads(product_info.stdout)
            if (info.get("schema") != "usk.product_info.v1" or
                    info.get("status") != "verified_read_only" or
                    info.get("installation_mode") != "inspect_only" or
                    info.get("product_id") != bundle["product_id"] or
                    info.get("prefab_profile") != profile or
                    info.get("component_ids") != ["addon", "alternative", "core", "library"] or
                    info.get("bundle_sha256") != _sha256(product_path / "product.bundle.json") or
                    info.get("payload_sha256") != bundle["payload"]["sha256"] or
                    info.get("file_count") != 4):
                raise RuntimeError(f"packaged host product inventory differs in {profile}")
            selected = subprocess.run(
                [str(host), "--product-select",
                 str(product_path / "product.bundle.json"), "--select", "addon"],
                capture_output=True, timeout=30)
            if selected.returncode or selected.stderr:
                raise RuntimeError(f"packaged host could not resolve selection in {profile}")
            selection = json.loads(selected.stdout)
            if (selection.get("schema") != "usk.product_selection.v1" or
                    selection.get("status") != "verified_read_only" or
                    selection.get("installation_mode") != "inspect_only" or
                    selection.get("requested_component_ids") != ["addon"] or
                    selection.get("selected_component_ids") !=
                    list(resolve_component_ids(bundle["components"], ["addon"])) or
                    selection.get("bundle_sha256") != info["bundle_sha256"] or
                    selection.get("payload_sha256") != info["payload_sha256"]):
                raise RuntimeError(f"native and authoring selection differ in {profile}")
            default = subprocess.run(
                [str(host), "--product-select",
                 str(product_path / "product.bundle.json")],
                capture_output=True, timeout=30)
            if (default.returncode or default.stderr or
                    json.loads(default.stdout).get("selected_component_ids") !=
                    list(resolve_component_ids(bundle["components"]))):
                raise RuntimeError(f"default native selection differs in {profile}")
            conflict = subprocess.run(
                [str(host), "--product-select",
                 str(product_path / "product.bundle.json"),
                 "--select", "addon", "--select", "alternative"],
                capture_output=True, timeout=30)
            if conflict.returncode != 2 or conflict.stdout:
                raise RuntimeError(f"packaged host accepted conflicting selection in {profile}")
            unknown = subprocess.run(
                [str(host), "--product-select",
                 str(product_path / "product.bundle.json"), "--select", "missing"],
                capture_output=True, timeout=30)
            if unknown.returncode != 2 or unknown.stdout:
                raise RuntimeError(f"packaged host accepted unknown selection in {profile}")
            tampered = base / f"{profile}-tampered"
            tampered.mkdir()
            shutil.copy2(product_path / "product.bundle.json", tampered)
            shutil.copy2(product_path / "prefab.manifest.json", tampered)
            shutil.copy2(product_path / "usk_machine.exe", tampered)
            changed = bytearray((product_path / "payload.zip").read_bytes())
            changed[0] ^= 1
            (tampered / "payload.zip").write_bytes(changed)
            refused = subprocess.run(
                [str(host), "--product-info", str(tampered / "product.bundle.json")],
                capture_output=True, timeout=30)
            if refused.returncode != 2 or refused.stdout:
                raise RuntimeError(f"packaged host accepted altered payload in {profile}")
            refused_selection = subprocess.run(
                [str(host), "--product-select",
                 str(tampered / "product.bundle.json"), "--select", "addon"],
                capture_output=True, timeout=30)
            if refused_selection.returncode != 2 or refused_selection.stdout:
                raise RuntimeError(f"packaged host selected altered payload in {profile}")
            observations.append({
                "profile": profile,
                "manifest": manifest,
                "carrier_sha256": _sha256(carrier) if carrier.is_file() else None,
                "host_binary_sha256": _sha256(host),
                "host_response_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "host_exit_code": result.returncode,
                "product_info_response_sha256": hashlib.sha256(product_info.stdout).hexdigest(),
                "product_info_status": info["status"],
                "native_selection_sha256": hashlib.sha256(selected.stdout).hexdigest(),
                "native_selection_matches_authoring": True,
                "conflicting_selection_refused": True,
                "unknown_selection_refused": True,
                "altered_payload_selection_refused": True,
                "payload_tamper_refused": True,
                "extracted_product_reinspection": profile == "one_file_carrier",
            })
    return {
        "schema": "usk.prefab_external_source_probe.v1",
        "source_commit": _git("rev-parse", "HEAD"),
        "source_tree": _git("show", "-s", "--format=%T", "HEAD"),
        "platform": platform.platform(),
        "compiler_version": compiler_version,
        "runtime_build": {
            "declared_source_commit": runtime_source_commit,
            "declared_source_tree": runtime_source_tree,
            "cmake_cache_sha256": _sha256(runtime_cmake_cache),
            "binary_sha256": _sha256(runtime),
            "configuration": (runtime.parent.name if runtime.parent.name in
                              {"Debug", "Release", "RelWithDebInfo", "MinSizeRel"}
                              else "unverified"),
        },
        "product": "external single-file C program, compiled outside the USK source tree",
        "qualification": "inspect-only envelope, native bundle byte inventory and machine-host startup; no installation or release acceptance",
        "finalized_selection": finalized_observation,
        "observations": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--runtime-source-commit", required=True)
    parser.add_argument("--runtime-cmake-cache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.runtime, args.runtime_source_commit, args.runtime_cmake_cache)
    args.output.write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
    print(f"external-prefab-probe: PASS {result['source_commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
