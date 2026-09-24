# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_bundle_author import AuthoringError, compile_bundle, inspect_bundle, validate_project
from usk_component_resolver import resolve_component_ids


PAYLOAD = b"neutral finalized one-file payload\r\n"


def project() -> dict:
    return {
        "schema": "usk.authoring_project.v1", "product_id": "org.example.hello",
        "publisher_id": "org.example", "product_version": "1.2.3",
        "allowed_scopes": ["portable", "per_user"],
        "components": [{"id": "core", "required": True, "default_selected": True,
                        "requires": [], "conflicts": [],
                        "variants": [{"target": "windows-x64", "files": [
                            {"source": "final/app.bin", "path": "bin/app.bin"}]}]}],
    }


def write_project(root: Path, value: dict) -> Path:
    (root / "final").mkdir(parents=True)
    (root / "final" / "app.bin").write_bytes(PAYLOAD)
    source = root / "project.json"
    source.write_text(json.dumps(value), encoding="utf-8")
    return source


class BundleAuthorTests(unittest.TestCase):
    def test_external_one_file_product_compiles_without_engine_edits(self) -> None:
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            self.skipTest("C compiler unavailable for optional external product probe")
        fixture = Path(__file__).parent / "fixtures" / "authoring" / "neutral_one_file"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_root = root / "external product"
            shutil.copytree(fixture, project_root)
            final = project_root / "final"
            final.mkdir()
            executable = "hello.exe" if os.name == "nt" else "hello"
            subprocess.run([compiler, str(project_root / "hello.c"), "-o",
                            str(final / executable)], check=True, capture_output=True)
            definition = json.loads((project_root / "project.json").read_text(encoding="utf-8"))
            definition["components"][0]["variants"][0]["files"][0] = {
                "source": f"final/{executable}", "path": f"bin/{executable}"}
            (project_root / "project.json").write_text(json.dumps(definition), encoding="utf-8")
            output = root / "output"
            output.mkdir()
            cli = Path(__file__).resolve().parents[1] / "tools" / "usk_bundle_author.py"
            subprocess.run([sys.executable, str(cli), "build", "--source",
                            str(project_root / "project.json"), "--target", "neutral-local",
                            "--output-dir", str(output)], check=True, capture_output=True)
            bundle = json.loads((output / "product.bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(inspect_bundle(output / "product.bundle.json"), bundle)
            inspected = subprocess.run([sys.executable, str(cli), "inspect", "--bundle",
                                        str(output / "product.bundle.json")],
                                       check=True, capture_output=True, text=True)
            self.assertEqual(inspected.stdout.strip(), bundle["payload"]["sha256"])
            resolved = subprocess.run([sys.executable, str(cli), "resolve", "--bundle",
                                       str(output / "product.bundle.json")],
                                      check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(resolved.stdout), ["core"])
            with zipfile.ZipFile(output / "payload.zip") as archive:
                self.assertEqual(archive.read(f"bin/{executable}"),
                                 (final / executable).read_bytes())

    def test_reproducible_bundle_and_reopened_exact_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = []
            for name in ("ascii", "spaced root", "unicodé"):
                project_root = root / name
                project_root.mkdir()
                source = write_project(project_root, project())
                output = root / (name + " output")
                output.mkdir()
                bundle = compile_bundle(source, "windows-x64", output)
                self.assertEqual(inspect_bundle(output / "product.bundle.json"), bundle)
                self.assertEqual(bundle["components"][0]["files"], [
                    {"path": "bin/app.bin", "size_bytes": len(PAYLOAD),
                     "sha256": hashlib.sha256(PAYLOAD).hexdigest()}])
                self.assertEqual(resolve_component_ids(bundle["components"]), ("core",))
                with zipfile.ZipFile(output / "payload.zip") as archive:
                    self.assertEqual(archive.namelist(), ["bin/app.bin"])
                    self.assertEqual(archive.read("bin/app.bin"), PAYLOAD)
                results.append(((output / "payload.zip").read_bytes(),
                                (output / "product.bundle.json").read_bytes()))
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0], results[2])

    def test_selection_and_alternative_graph_are_retained(self) -> None:
        value = project()
        value["components"].append({"id": "addon", "required": False,
                                    "default_selected": False, "requires": ["core"],
                                    "conflicts": [], "variants": [{"target": "windows-x64",
                                    "files": [{"source": "final/addon.bin",
                                               "path": "bin/addon.bin"}]}]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_project(root / "project", value)
            (source.parent / "final" / "addon.bin").write_bytes(b"addon")
            output = root / "out"
            output.mkdir()
            bundle = compile_bundle(source, "windows-x64", output)
            self.assertEqual(resolve_component_ids(bundle["components"]), ("core",))
            self.assertEqual(resolve_component_ids(bundle["components"], ["addon"]),
                             ("core", "addon"))
            with zipfile.ZipFile(output / "payload.zip") as archive:
                self.assertEqual(archive.namelist(), ["bin/addon.bin", "bin/app.bin"])

    def test_hostile_paths_and_collisions_refuse_before_output(self) -> None:
        for path in ("../escape", "/absolute", "C:/drive", "bin\\app", "bin/../app",
                     "bin//app", "con.txt", "a./b", "unicode/é", "a" * 256):
            value = project()
            value["components"][0]["variants"][0]["files"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(AuthoringError):
                validate_project(value, "windows-x64")
        value = project()
        value["components"][0]["variants"][0]["files"].append(
            {"source": "final/app.bin", "path": "BIN/APP.BIN"})
        with self.assertRaisesRegex(AuthoringError, "duplicate bundle path"):
            validate_project(value, "windows-x64")
        value["components"][0]["variants"][0]["files"][1]["path"] = "bin/app.bin/child"
        with self.assertRaisesRegex(AuthoringError, "parent"):
            validate_project(value, "windows-x64")
        value["components"][0]["variants"][0]["files"] = [
            {"source": "final/app.bin", "path": "a" * 255}]
        self.assertEqual(validate_project(value, "windows-x64")[0]["files"][0]["path"],
                         "a" * 255)

    def test_interposed_name_cannot_hide_file_parent_collision(self) -> None:
        value = project()
        files = value["components"][0]["variants"][0]["files"]
        files[:] = [{"source": "final/app.bin", "path": path}
                    for path in ("a", "a-", "a/b")]
        with self.assertRaisesRegex(AuthoringError, "parent"):
            validate_project(value, "windows-x64")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_project(root / "project", project())
            output = root / "out"
            output.mkdir()
            bundle = compile_bundle(source, "windows-x64", output)
            template = bundle["components"][0]["files"][0]
            bundle["components"][0]["files"] = [dict(template, path=path)
                                                for path in ("a", "a-", "a/b")]
            sidecar = output / "product.bundle.json"
            sidecar.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaisesRegex(AuthoringError, "parent"):
                inspect_bundle(sidecar)

    def test_missing_variant_and_unselected_cycle_refuse(self) -> None:
        value = project()
        with self.assertRaisesRegex(AuthoringError, "missing target"):
            validate_project(value, "linux-x64")
        cyclic = copy.deepcopy(value["components"][0])
        cyclic["id"] = "unused"
        cyclic["required"] = False
        cyclic["default_selected"] = False
        cyclic["requires"] = ["unused"]
        cyclic["variants"][0]["files"][0]["path"] = "bin/unused.bin"
        value["components"].append(cyclic)
        with self.assertRaisesRegex(AuthoringError, "cycle"):
            validate_project(value, "windows-x64")

    def test_source_symlink_and_nonempty_output_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_project(root / "project", project())
            output = root / "out"
            output.mkdir()
            (output / "existing").write_bytes(b"preserve")
            with self.assertRaisesRegex(AuthoringError, "empty"):
                compile_bundle(source, "windows-x64", output)
            self.assertEqual((output / "existing").read_bytes(), b"preserve")
            (output / "existing").unlink()
            file = source.parent / "final" / "app.bin"
            file.unlink()
            try:
                file.symlink_to(root / "elsewhere.bin")
            except OSError:
                self.skipTest("file symlinks unavailable for this account")
            with self.assertRaises(AuthoringError):
                compile_bundle(source, "windows-x64", output)
            self.assertEqual(list(output.iterdir()), [])

    def test_carrier_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_project(root / "project", project())
            output = root / "out"
            output.mkdir()
            compile_bundle(source, "windows-x64", output)
            archive = output / "payload.zip"
            with archive.open("ab") as stream:
                stream.write(b"unexpected")
            with self.assertRaisesRegex(AuthoringError, "digest mismatch"):
                inspect_bundle(output / "product.bundle.json")

    def test_new_output_collision_preserves_the_other_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_project(root / "project", project())
            output = root / "out"
            output.mkdir()

            def claim_path(path, mode, **_kwargs):
                self.assertEqual(mode, "x")
                Path(path).write_bytes(b"other writer")
                raise FileExistsError(path)

            with mock.patch("usk_bundle_author.zipfile.ZipFile", side_effect=claim_path):
                with self.assertRaises(FileExistsError):
                    compile_bundle(source, "windows-x64", output)
            self.assertEqual((output / "payload.zip").read_bytes(), b"other writer")


if __name__ == "__main__":
    unittest.main()
