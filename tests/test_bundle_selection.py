# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_bundle_author import AuthoringError, compile_bundle, inspect_bundle
from usk_bundle_selection import SelectionError, finalize_selection, inspect_selection
from usk_component_resolver import resolve_component_ids
import usk_bundle_selection
from tests.test_bundle_author import project, write_project, PAYLOAD


class BundleSelectionTests(unittest.TestCase):
    def _source(self, root: Path) -> Path:
        value = project()
        value["components"].append({
            "id": "addon", "required": False, "default_selected": False,
            "requires": ["core"], "conflicts": ["alternative"],
            "variants": [{"target": "windows-x64", "files": [
                {"source": "final/addon.bin", "path": "bin/addon.bin"}]}],
        })
        value["components"].append({
            "id": "alternative", "required": False, "default_selected": False,
            "requires": [], "conflicts": [],
            "variants": [{"target": "windows-x64", "files": [
                {"source": "final/alternative.bin", "path": "bin/alternative.bin"}]}],
        })
        source = write_project(root / "external-product", value)
        (source.parent / "final" / "addon.bin").write_bytes(b"optional addon\n")
        (source.parent / "final" / "alternative.bin").write_bytes(b"alternative\n")
        compiled = root / "compiled"
        compiled.mkdir()
        compile_bundle(source, "windows-x64", compiled)
        return compiled / "product.bundle.json"

    def test_selected_payload_excludes_unselected_bytes_and_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source(root)
            source_bundle = inspect_bundle(source)
            results = []
            for number in range(2):
                selected = root / f"selected-{number}"
                selected.mkdir()
                receipt = finalize_selection(source, [], selected)
                self.assertEqual(inspect_selection(source, selected), receipt)
                bundle = inspect_bundle(selected / "product.bundle.json")
                self.assertEqual([entry["id"] for entry in bundle["components"]], ["core"])
                self.assertEqual(set(resolve_component_ids(bundle["components"])), {"core"})
                self.assertEqual(receipt["selected_components"], ["core"])
                self.assertEqual(receipt["source_payload_sha256"],
                                 source_bundle["payload"]["sha256"])
                with zipfile.ZipFile(selected / "payload.zip") as archive:
                    self.assertEqual(archive.namelist(), ["bin/app.bin"])
                    self.assertEqual(archive.read("bin/app.bin"), PAYLOAD)
                results.append(tuple((selected / name).read_bytes() for name in
                                     ("payload.zip", "product.bundle.json",
                                      "selection.receipt.json")))
            self.assertEqual(results[0], results[1])
            self.assertEqual(inspect_bundle(source), source_bundle)

    def test_explicit_addon_and_tamper_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source(root)
            selected = root / "selected"
            selected.mkdir()
            receipt = finalize_selection(source, ["addon"], selected)
            self.assertEqual(receipt["selected_components"], ["core", "addon"])
            self.assertEqual(set(resolve_component_ids(
                inspect_bundle(selected / "product.bundle.json")["components"])),
                {"core", "addon"})
            with zipfile.ZipFile(selected / "payload.zip") as archive:
                self.assertEqual(archive.namelist(), ["bin/addon.bin", "bin/app.bin"])
                self.assertEqual(archive.read("bin/addon.bin"), b"optional addon\n")
            original = (selected / "payload.zip").read_bytes()
            original_bundle = (selected / "product.bundle.json").read_bytes()
            original_receipt = (selected / "selection.receipt.json").read_bytes()
            (selected / "payload.zip").write_bytes(original + b"hidden suffix")
            with self.assertRaises(AuthoringError):
                inspect_selection(source, selected)
            # Rebinding every unsigned hash does not make undeclared physical
            # ZIP bytes a canonical selected package.
            changed = json.loads(original_bundle)
            changed["payload"]["size_bytes"] = (selected / "payload.zip").stat().st_size
            changed["payload"]["sha256"] = hashlib.sha256(
                (selected / "payload.zip").read_bytes()).hexdigest()
            changed_bundle = (json.dumps(changed, sort_keys=True,
                                         separators=(",", ":")) + "\n").encode("ascii")
            (selected / "product.bundle.json").write_bytes(changed_bundle)
            changed_receipt = json.loads(original_receipt)
            changed_receipt["final_payload_sha256"] = changed["payload"]["sha256"]
            changed_receipt["final_bundle_sha256"] = hashlib.sha256(changed_bundle).hexdigest()
            (selected / "selection.receipt.json").write_bytes((
                json.dumps(changed_receipt, sort_keys=True,
                           separators=(",", ":")) + "\n").encode("ascii"))
            with self.assertRaisesRegex(SelectionError, "noncanonical bytes"):
                inspect_selection(source, selected)
            (selected / "payload.zip").write_bytes(original)
            (selected / "product.bundle.json").write_bytes(original_bundle)
            (selected / "selection.receipt.json").write_bytes(original_receipt)
            self.assertEqual(inspect_selection(source, selected), receipt)
            mutated = copy.deepcopy(inspect_bundle(source))
            mutated["publisher_id"] = "org.example.other"
            source.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaises(SelectionError):
                inspect_selection(source, selected)

    def test_cli_refuses_unknown_selection_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source(root)
            selected = root / "selected"
            selected.mkdir()
            cli = Path(__file__).resolve().parents[1] / "tools" / "usk_bundle_selection.py"
            command = [sys.executable, str(cli), "finalize", "--bundle", str(source),
                       "--select", "missing", "--output-dir", str(selected)]
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(refused.returncode, 2)
            self.assertEqual(list(selected.iterdir()), [])
            command[command.index("missing")] = "addon"
            built = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(built.stdout)["selected_components"],
                             ["core", "addon"])
            inspected = subprocess.run([sys.executable, str(cli), "inspect",
                                        "--source-bundle", str(source),
                                        "--output-dir", str(selected)],
                                       capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(inspected.stdout), json.loads(built.stdout))
            self.assertEqual(hashlib.sha256((selected / "payload.zip").read_bytes()).hexdigest(),
                             json.loads(built.stdout)["final_payload_sha256"])

    def test_late_failure_cleans_only_its_files_and_preserves_a_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source(root)
            output = root / "late-failure"
            output.mkdir()
            real_hash = usk_bundle_selection._hash
            source_reads = 0

            def drift_on_recheck(path: Path) -> str:
                nonlocal source_reads
                if path == source:
                    source_reads += 1
                    if source_reads == 2:
                        raise SelectionError("injected late source drift")
                return real_hash(path)

            with mock.patch.object(usk_bundle_selection, "_hash", drift_on_recheck):
                with self.assertRaisesRegex(SelectionError, "late source drift"):
                    finalize_selection(source, [], output)
            self.assertEqual(list(output.iterdir()), [])
            self.assertEqual(inspect_bundle(source)["product_id"], "org.example.hello")

            def receipt_collision(*arguments):
                (output / "selection.receipt.json").write_bytes(b"external writer")
                return {"schema": "not relevant"}

            with mock.patch.object(usk_bundle_selection, "_receipt", receipt_collision):
                with self.assertRaises(FileExistsError):
                    finalize_selection(source, [], output)
            self.assertEqual([item.name for item in output.iterdir()],
                             ["selection.receipt.json"])
            self.assertEqual((output / "selection.receipt.json").read_bytes(),
                             b"external writer")

    def test_oversized_receipt_and_extra_entry_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._source(root)
            output = root / "selected"
            output.mkdir()
            finalize_selection(source, [], output)
            receipt_path = output / "selection.receipt.json"
            original = receipt_path.read_bytes()
            receipt_path.write_bytes(b"x" * (usk_bundle_selection.MAX_RECEIPT + 1))
            with self.assertRaisesRegex(SelectionError, "byte budget"):
                inspect_selection(source, output)
            receipt_path.write_bytes(original)
            (output / "foreign.txt").write_bytes(b"retain")
            with self.assertRaisesRegex(SelectionError, "extra entries"):
                inspect_selection(source, output)
            self.assertEqual((output / "foreign.txt").read_bytes(), b"retain")


if __name__ == "__main__":
    unittest.main()
