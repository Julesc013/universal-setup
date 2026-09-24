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
from usk_prefab_envelope import build_envelope, inspect_envelope


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def run(runtime: Path) -> dict:
    if _git("status", "--porcelain"):
        raise RuntimeError("external probe requires a clean source checkout")
    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("GCC is required for the external C product probe")
    runtime = runtime.resolve(strict=True)
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
        project = {
            "schema": "usk.authoring_project.v1", "product_id": "org.example.hello",
            "publisher_id": "org.example", "product_version": "1.0.0",
            "allowed_scopes": ["portable"],
            "components": [{"id": "core", "required": True, "default_selected": True,
                            "requires": [], "conflicts": [], "variants": [{
                                "target": "windows-x64", "files": [{
                                    "source": "final/hello.exe", "path": "bin/hello.exe"}]}]}],
        }
        definition = product / "project.json"
        definition.write_text(json.dumps(project), encoding="utf-8")
        compiled = base / "compiled"
        compiled.mkdir()
        bundle = compile_bundle(definition, "windows-x64", compiled)
        if inspect_bundle(compiled / "product.bundle.json") != bundle:
            raise RuntimeError("external compiled bundle failed inspection")
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
            observations.append({
                "profile": profile,
                "manifest": manifest,
                "carrier_sha256": _sha256(carrier) if carrier.is_file() else None,
                "host_binary_sha256": _sha256(host),
                "host_response_sha256": hashlib.sha256(result.stdout).hexdigest(),
                "host_exit_code": result.returncode,
                "extracted_product_reinspection": profile == "one_file_carrier",
            })
    return {
        "schema": "usk.prefab_external_source_probe.v1",
        "source_commit": _git("rev-parse", "HEAD"),
        "source_tree": _git("show", "-s", "--format=%T", "HEAD"),
        "platform": platform.platform(),
        "compiler_version": compiler_version,
        "runtime_binary_sha256": _sha256(runtime),
        "product": "external single-file C program, compiled outside the USK source tree",
        "qualification": "inspect-only envelope and machine-host startup; no installation or release acceptance",
        "observations": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.runtime)
    args.output.write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
    print(f"external-prefab-probe: PASS {result['source_commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
