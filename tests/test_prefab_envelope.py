# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_bundle_author import compile_bundle
from usk_prefab_envelope import EnvelopeError, build_envelope, inspect_envelope
import usk_prefab_envelope
from tests.test_bundle_author import project, write_project


class PrefabEnvelopeTests(unittest.TestCase):
    def _inputs(self, root: Path) -> tuple[Path, Path]:
        source = root / "external product"
        source.mkdir()
        definition = write_project(source, project())
        compiled = root / "compiled"
        compiled.mkdir()
        compile_bundle(definition, "windows-x64", compiled)
        runtime = root / "built runtime.exe"
        runtime.write_bytes(b"MZ\x00unit-test-inspect-host\n")
        return compiled / "product.bundle.json", runtime

    def test_both_profiles_are_deterministic_and_reopen_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, runtime = self._inputs(root)
            for profile in ("sidecar", "one_file_carrier"):
                outputs = []
                for number in range(2):
                    output = root / f"{profile}-{number}"
                    output.mkdir()
                    manifest = build_envelope(bundle, runtime, profile, output)
                    carrier = output if profile == "sidecar" else output / "setup.carrier.zip"
                    self.assertEqual(inspect_envelope(carrier), manifest)
                    self.assertEqual(manifest["properties"]["installation_mode"], "inspect_only")
                    self.assertEqual(manifest["properties"]["runtime_dependency_closure"], "unqualified")
                    if profile == "sidecar":
                        self.assertEqual((output / "usk_machine.exe").read_bytes(), runtime.read_bytes())
                        outputs.append([(output / name).read_bytes() for name in sorted(
                            ("usk_machine.exe", "payload.zip", "product.bundle.json", "prefab.manifest.json"))])
                    else:
                        self.assertEqual(manifest["properties"]["physical_file_count"], 1)
                        self.assertEqual(manifest["properties"]["entrypoint_count"], 0)
                        self.assertTrue(manifest["properties"]["extraction_required"])
                        outputs.append((output / "setup.carrier.zip").read_bytes())
                self.assertEqual(outputs[0], outputs[1])

    def test_tamper_and_nonempty_output_are_refused_without_deleting_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, runtime = self._inputs(root)
            sidecar = root / "sidecar"
            sidecar.mkdir()
            build_envelope(bundle, runtime, "sidecar", sidecar)
            (sidecar / "payload.zip").write_bytes(b"changed")
            with self.assertRaises(EnvelopeError):
                inspect_envelope(sidecar)
            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("outside", encoding="utf-8")
            with self.assertRaises(EnvelopeError):
                build_envelope(bundle, runtime, "sidecar", occupied)
            self.assertEqual((occupied / "keep.txt").read_text(encoding="utf-8"), "outside")
            carrier_dir = root / "carrier"
            carrier_dir.mkdir()
            build_envelope(bundle, runtime, "one_file_carrier", carrier_dir)
            carrier = carrier_dir / "setup.carrier.zip"
            with zipfile.ZipFile(carrier, "a") as archive:
                archive.writestr("unlisted.txt", "changed")
            with self.assertRaises(EnvelopeError):
                inspect_envelope(carrier)

    def test_manifest_properties_cannot_be_relabelled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, runtime = self._inputs(root)
            output = root / "output"
            output.mkdir()
            build_envelope(bundle, runtime, "sidecar", output)
            path = output / "prefab.manifest.json"
            manifest = json.loads(path.read_bytes())
            manifest["properties"]["installation_mode"] = "full_install"
            path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                            encoding="ascii")
            with self.assertRaises(EnvelopeError):
                inspect_envelope(output)

    def test_concurrent_manifest_creation_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, runtime = self._inputs(root)
            output = root / "output"
            output.mkdir()
            original = usk_prefab_envelope._copy_observed

            def competing_writer(source, destination, limit=None):
                result = original(source, destination, limit)
                outsider = output / "prefab.manifest.json"
                if not outsider.exists():
                    outsider.write_bytes(b"concurrent writer")
                return result

            with mock.patch.object(usk_prefab_envelope, "_copy_observed", competing_writer):
                with self.assertRaises(FileExistsError):
                    build_envelope(bundle, runtime, "sidecar", output)
            self.assertEqual((output / "prefab.manifest.json").read_bytes(), b"concurrent writer")


if __name__ == "__main__":
    unittest.main()
