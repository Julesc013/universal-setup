# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import hashlib
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

    def test_hidden_carrier_prefix_and_suffix_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, runtime = self._inputs(root)
            output = root / "carrier"
            output.mkdir()
            build_envelope(bundle, runtime, "one_file_carrier", output)
            carrier = output / "setup.carrier.zip"
            original = carrier.read_bytes()
            for tampered in (runtime.read_bytes() + original,
                             original + b"unlisted trailing bytes"):
                carrier.write_bytes(tampered)
                with self.assertRaises(EnvelopeError):
                    inspect_envelope(carrier)
            carrier.write_bytes(original)
            self.assertEqual(inspect_envelope(carrier)["profile"], "one_file_carrier")

    def test_self_consistent_but_invalid_bundle_is_refused_in_both_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle, runtime = self._inputs(root)
            for profile in ("sidecar", "one_file_carrier"):
                output = root / profile
                output.mkdir()
                build_envelope(bundle, runtime, profile, output)
                if profile == "sidecar":
                    files = {name: (output / name).read_bytes() for name in (
                        "usk_machine.exe", "payload.zip", "product.bundle.json", "prefab.manifest.json")}
                else:
                    with zipfile.ZipFile(output / "setup.carrier.zip") as archive:
                        files = {name: archive.read(name) for name in archive.namelist()}
                product = json.loads(files["product.bundle.json"])
                product["schema"] = "invalid.bundle.schema"
                files["product.bundle.json"] = usk_prefab_envelope._canonical(product)
                manifest = json.loads(files["prefab.manifest.json"])
                manifest["entries"]["product.bundle.json"] = {
                    "sha256": hashlib.sha256(files["product.bundle.json"]).hexdigest(),
                    "size_bytes": len(files["product.bundle.json"])}
                files["prefab.manifest.json"] = usk_prefab_envelope._canonical(manifest)
                if profile == "sidecar":
                    for name in ("product.bundle.json", "prefab.manifest.json"):
                        (output / name).write_bytes(files[name])
                    carrier = output
                else:
                    carrier = output / "setup.carrier.zip"
                    carrier.unlink()
                    with zipfile.ZipFile(carrier, "x", allowZip64=True) as archive:
                        for name in sorted(files):
                            archive.writestr(usk_prefab_envelope._zip_info(name), files[name])
                with self.assertRaises(EnvelopeError):
                    inspect_envelope(carrier)


if __name__ == "__main__":
    unittest.main()
