# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools import provider_package_manifest as provider_manifest

SOURCE_COMMIT = "1" * 40
SOURCE_TREE = "2" * 40


class ProviderPackageManifestTests(unittest.TestCase):
    def make_prefix(self, root: Path, linkage: str = "combined") -> Path:
        prefix = root / "prefix"
        files = {
            "include/usk/usk_api.h": "#define USK_ABI_VERSION_MINOR 0\n",
            "share/universal-setup/contracts/abi/usk_c_abi.v1.toml": (
                "abi_major = 1\nabi_minor = 0\n"
            ),
            "share/universal-setup/contracts/schema/setup/installed_state.v1.schema.json": (
                '{"schema":"fixture"}\n'
            ),
            "share/universal-setup/contracts/schema/setup/transaction_journal.v1.schema.json": (
                '{"schema":"fixture"}\n'
            ),
            "share/licenses/universal-setup/LICENSE": "MIT fixture\n",
            "share/licenses/universal-setup/license.v1.toml": (
                'package_license_expression = "MIT AND Zlib"\n'
            ),
            "share/universal-setup/README-SDK.md": "SDK fixture\n",
        }
        targets = ["UniversalSetup::Headers"]
        if linkage in {"static", "combined"}:
            files["lib/usk.lib"] = "static fixture\n"
            targets.append("UniversalSetup::CoreStatic")
        if linkage in {"shared", "combined"}:
            files["bin/usk.dll"] = "shared fixture\n"
            targets.append("UniversalSetup::CoreShared")
        files["lib/cmake/UniversalSetup/UniversalSetupTargets.cmake"] = "".join(
            f"add_library({target} INTERFACE IMPORTED)\n" for target in targets
        )
        for relative, content in files.items():
            path = prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return prefix

    def build(self, prefix: Path, linkage: str = "combined") -> dict[str, object]:
        return provider_manifest.build_manifest(
            prefix=prefix,
            source_repository="Julesc013/universal-setup",
            source_commit=SOURCE_COMMIT,
            source_tree=SOURCE_TREE,
            source_ref="refs/heads/main",
            package_version="1.0.0",
            os_name="Windows",
            architecture="x64",
            linkage=linkage,
            configuration="Release",
            toolchain_id="MSVC",
            toolchain_version="19.44",
            compiler="C:/fixture/cl.exe",
        )

    def test_repository_package_truth_is_consistent(self) -> None:
        self.assertEqual(provider_manifest.check_repository(), [])

    def test_generation_is_byte_identical_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory))
            first = self.build(prefix)
            path = provider_manifest.write_manifest(prefix, first)
            first_bytes = path.read_bytes()
            second = self.build(prefix)
            provider_manifest.write_manifest(prefix, second)
            self.assertEqual(path.read_bytes(), first_bytes)
            verified = provider_manifest.verify_manifest(
                prefix,
                expected_source_commit=SOURCE_COMMIT,
                expected_source_tree=SOURCE_TREE,
                expected_source_ref="refs/heads/main",
                expected_package_version="1.0.0",
                expected_c_abi="1.0",
                expected_installed_state_read_versions=[1],
                expected_installed_state_write_version=1,
                expected_transaction_journal_read_versions=[1],
                expected_transaction_journal_write_version=1,
                expected_linkage="combined",
            )
            self.assertEqual(verified, first)

    def test_changed_or_missing_artifact_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory))
            provider_manifest.write_manifest(prefix, self.build(prefix))
            header = prefix / "include/usk/usk_api.h"
            header.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(provider_manifest.ManifestError, "artifact"):
                provider_manifest.verify_manifest(prefix)
            header.unlink()
            with self.assertRaisesRegex(provider_manifest.ManifestError, "artifact"):
                provider_manifest.verify_manifest(prefix)

    def test_identity_mismatches_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory))
            provider_manifest.write_manifest(prefix, self.build(prefix))
            cases = {
                "expected_source_commit": "3" * 40,
                "expected_source_tree": "4" * 40,
                "expected_source_ref": "refs/heads/dev",
                "expected_package_version": "1.0.1",
                "expected_c_abi": "1.1",
                "expected_installed_state_read_versions": [2],
                "expected_installed_state_write_version": 2,
                "expected_transaction_journal_read_versions": [2],
                "expected_transaction_journal_write_version": 2,
                "expected_linkage": "static",
            }
            for argument, value in cases.items():
                with self.subTest(argument=argument):
                    with self.assertRaises(provider_manifest.ManifestError):
                        provider_manifest.verify_manifest(prefix, **{argument: value})

    def test_wrong_source_repository_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory))
            with self.assertRaisesRegex(
                provider_manifest.ManifestError, "source repository"
            ):
                provider_manifest.build_manifest(
                    prefix=prefix,
                    source_repository="example/future-provider",
                    source_commit=SOURCE_COMMIT,
                    source_tree=SOURCE_TREE,
                    source_ref="refs/heads/main",
                    package_version="1.0.0",
                    os_name="Windows",
                    architecture="x64",
                    linkage="combined",
                    configuration="Release",
                    toolchain_id="MSVC",
                    toolchain_version="19.44",
                    compiler="C:/fixture/cl.exe",
                )

            manifest = self.build(prefix)
            manifest["source"]["repository"] = "example/future-provider"
            provider_manifest.write_manifest(prefix, manifest)
            with self.assertRaisesRegex(
                provider_manifest.ManifestError, "source repository"
            ):
                provider_manifest.verify_manifest(prefix)

    def test_changed_manifest_identity_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory))
            path = provider_manifest.write_manifest(prefix, self.build(prefix))
            changed = copy.deepcopy(json.loads(path.read_text(encoding="utf-8")))
            changed["provider"]["package_version"] = "1.0.1"
            path.write_bytes(provider_manifest.canonical_json_bytes(changed))
            with self.assertRaisesRegex(provider_manifest.ManifestError, "1.0.0"):
                provider_manifest.verify_manifest(prefix)

    def test_changed_qualification_or_inventory_algorithm_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory))
            original = self.build(prefix)
            cases = (
                ("qualification", "requirements", ["future-proof"]),
                ("inventories", "algorithm", "sha512-future"),
            )
            for section, field, value in cases:
                with self.subTest(section=section, field=field):
                    changed = copy.deepcopy(original)
                    changed[section][field] = value
                    provider_manifest.write_manifest(prefix, changed)
                    with self.assertRaises(provider_manifest.ManifestError):
                        provider_manifest.verify_manifest(prefix)

    def test_mixed_linkage_target_inventory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = self.make_prefix(Path(directory), linkage="combined")
            with self.assertRaisesRegex(provider_manifest.ManifestError, "linkage"):
                self.build(prefix, linkage="static")


if __name__ == "__main__":
    unittest.main()
