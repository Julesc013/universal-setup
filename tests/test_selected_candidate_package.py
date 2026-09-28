# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_bundle_author import compile_bundle
from usk_selected_candidate_package import (
    CandidatePackageError, build_candidate_package, inspect_candidate_package)
from tests.test_bundle_author import project, write_project
from tests.windows_publisher_metadata_inputs import create_inputs


class SelectedCandidatePackageTests(unittest.TestCase):
    def _inputs(self, root: Path):
        definition = write_project(root / "product", project())
        compiled = root / "compiled"
        compiled.mkdir()
        compile_bundle(definition, "windows-x64", compiled)
        binaries = root / "binaries"
        binaries.mkdir()
        paths = [binaries / name for name in (
            "usk_machine.exe", "usk_publisher_service.exe",
            "usk_publisher_service_control.exe", "usk_publisher_client.exe")]
        for index, path in enumerate(paths):
            path.write_bytes(b"MZ\x00selected-candidate-test-" + bytes((index,)))
        return compiled / "product.bundle.json", paths

    def test_compiled_product_and_native_binary_closure_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, binaries = self._inputs(root)
            output = root / "candidate"
            output.mkdir()
            manifest = build_candidate_package(bundle, *binaries, output)
            self.assertEqual(inspect_candidate_package(output), manifest)
            self.assertEqual(manifest["installation_mode"], "selected_ntfs_candidate")
            self.assertEqual(manifest["signing_status"], "unsigned")
            self.assertEqual(manifest["target"], "windows-x64")
            self.assertEqual(len(manifest["entries"]), 7)
            self.assertEqual((output / "inspect" / "payload.zip").read_bytes(),
                             (bundle.parent / "payload.zip").read_bytes())

    def test_payload_binary_and_extra_member_tampering_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, binaries = self._inputs(root)
            output = root / "candidate"
            output.mkdir()
            build_candidate_package(bundle, *binaries, output)
            client = output / "publisher" / "usk_publisher_client.exe"
            client.write_bytes(client.read_bytes() + b"modified")
            with self.assertRaises(CandidatePackageError):
                inspect_candidate_package(output)
            client.write_bytes(binaries[-1].read_bytes())
            (output / "publisher" / "unlisted.exe").write_bytes(b"MZ")
            with self.assertRaisesRegex(CandidatePackageError, "closure"):
                inspect_candidate_package(output)

    def test_fault_service_and_nonempty_output_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, binaries = self._inputs(root)
            fault = binaries[1].with_name("usk_publisher_lab_service_fault.exe")
            fault.write_bytes(b"MZ\x00fault")
            output = root / "candidate"
            output.mkdir()
            with self.assertRaisesRegex(CandidatePackageError, "ordinary, gate-free"):
                build_candidate_package(bundle, binaries[0], fault,
                                        binaries[2], binaries[3], output)
            lab = binaries[1].with_name("usk_publisher_lab_service.exe")
            lab.write_bytes(b"MZ\x00lab")
            with self.assertRaisesRegex(CandidatePackageError, "ordinary, gate-free"):
                build_candidate_package(bundle, binaries[0], lab,
                                        binaries[2], binaries[3], output)
            (output / "keep.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(CandidatePackageError, "empty"):
                build_candidate_package(bundle, *binaries, output)
            self.assertEqual((output / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_hosted_fixture_enumerates_every_source_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.mkdir()
            inputs = create_inputs(fixture, root / "target", "package.source.probe")
            sources = [Path(path) for path in inputs["source_files"]]
            self.assertEqual(len(sources), 9)
            self.assertEqual(len(set(sources)), len(sources))
            self.assertTrue(all(path.is_file() for path in sources))
            self.assertEqual(Path(inputs["bundle_file"]),
                             fixture / "selected" / "product.bundle.json")


if __name__ == "__main__":
    unittest.main()
