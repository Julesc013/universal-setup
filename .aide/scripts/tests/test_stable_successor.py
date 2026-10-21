"""Synthetic lineage tests; not published-predecessor upgrade qualification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import zipfile
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "successor_q47_fixture", Path(__file__).with_name("test_q47_release_bundle.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
lite = fixture.aide_lite


class StableSuccessorTests(unittest.TestCase):
    def profile(self, name, forms, *, system="Windows", outside=()):
        return {"profile_id": name,
                "environment": {"system": system, "release": "synthetic", "version": "fixture-only",
                                "machine": "fixture", "runtime": {"implementation": "CPython", "version": "3.14.8"}},
                "support_candidate": {"tier": "T3", "state": "usable", "mode": "companion", "capability_level": "L1"},
                "capabilities": ["local-cli", "owned-lifecycle"],
                "supported_cli_forms": [form for form in forms if form not in outside],
                "refused_cli_forms": [], "unqualified_cli_forms": list(outside),
                "limitations": ["Synthetic metadata fixture; no platform qualification or execution grant."]}

    def make_multi_repo(self):
        root, record = self.make_repo()
        lite.build_stable_release_candidate(root, "1.1.0")
        tag_commit = self.commit(root)
        self.git(root, "tag", "aide-lite-v1.1.0")
        historical = self.snapshot(root)
        record.update(schema_version="aide.stable-successor-candidate.v2", version="1.2.0",
                      profile_id=lite.MULTIPROFILE_RELEASE_PROFILE,
                      predecessor={"version": "1.1.0", "tag_commit": tag_commit})
        record["preserved_assets"] += self.pins(root, "1.1.0")
        forms = lite.stable_release_cli_forms(root) + record["additional_cli_forms"]
        outside = [form for form in forms if form.startswith("job run ")]
        record["profiles"] = [self.profile(lite.STABLE_RELEASE_PROFILE, forms),
                              self.profile("aide-lite-local-linux", forms, system="Linux", outside=outside)]
        self.save(root, record)
        self.commit(root)
        self.refresh_pack(root)
        return root, record, historical

    def test_multi_profile_marker_preserves_history_and_command_dispositions(self):
        root, record, original = self.make_multi_repo()
        result = lite.build_stable_release_candidate(root, "1.2.0")
        identity = result["identity"]
        self.assertEqual(identity["schema_version"], "aide.stable-release-identity.v2")
        self.assertEqual(identity["profile_id"], "aide-lite-local-cli")
        self.assertEqual(identity["profiles"], record["profiles"])
        self.assertNotIn("support_tier_candidate", identity)
        self.assertNotIn("support_mode", identity)
        self.assertEqual(identity["lifecycle_apply_platform"], lite.MULTIPROFILE_LIFECYCLE_SCOPE)
        self.assertEqual(identity["predecessor_matrix"][0]["profile_id"], lite.STABLE_RELEASE_PROFILE)
        self.assertEqual({name: self.snapshot(root)[name] for name in original}, original)
        with zipfile.ZipFile(root / lite.stable_release_paths("1.2.0")["zip"]) as archive:
            embedded = json.loads(archive.read(lite.RELEASE_ARCHIVE_ROOT + "/stable-release.json"))
        self.assertEqual(embedded, identity)
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.2.0")["result"], "PASS")
        linux = embedded["profiles"][1]
        self.assertTrue(linux["unqualified_cli_forms"])
        self.assertEqual(linux["refused_cli_forms"], [])
        self.assertFalse(set(linux["unqualified_cli_forms"]) & set(linux["supported_cli_forms"]))
        # Keep archive checksums and embedded/outer metadata coherent. Only the
        # declared profile contract, rather than a corrupt ZIP, can reject it.
        manifest = copy.deepcopy(result)
        manifest["identity"]["profiles"][1]["environment"]["machine"] = "unapproved-architecture"
        paths = lite.stable_release_paths("1.2.0")
        with lite.public_archive_fixture("aide-stable-pack-") as temporary:
            projected = Path(temporary) / lite.RELEASE_ARCHIVE_ROOT
            lite.build_release_pack_projection(lite.export_pack_root(root), projected)
            lite.write_text_if_changed(projected / "stable-release.json",
                                       lite.stable_json_text(manifest["identity"]))
            lite.write_text_if_changed(projected / "checksums.json",
                                       lite.stable_json_text(lite.build_pack_checksums(projected)))
            lite.write_release_zip(projected, root / paths["zip"])
            lite.write_release_tar_gz(projected, root / paths["tar_gz"])
        for key in ("zip", "tar_gz"):
            asset = root / paths[key]
            manifest["archives"][key].update(size_bytes=asset.stat().st_size,
                                             sha256=hashlib.sha256(asset.read_bytes()).hexdigest())
            self.assertEqual(lite.validate_release_archive(root, paths[key])["result"], "PASS")
        lite.write_text_if_changed(root / paths["manifest"], lite.stable_json_text(manifest))
        sums = "".join(f"{lite.sha256_file(root / paths[key])}  {Path(paths[key]).name}\n"
                       for key in ("zip", "tar_gz", "manifest"))
        lite.write_text_if_changed(root / paths["sha256sums"], sums)
        validation = lite.validate_stable_release_candidate(root, "1.2.0")
        self.assertEqual(validation["result"], "FAIL")
        self.assertFalse(any("asset digest" in p or "embedded identity" in p or "SHA256SUMS" in p
                             for p in validation["problems"]), validation)

    def test_v1_to_v2_profile_expansion_requires_minor_even_with_same_global_forms(self):
        root, record, _ = self.make_multi_repo()
        record["version"] = "1.1.1"
        self.save(root, record)
        with self.assertRaisesRegex(ValueError, "profile contract requires a minor"):
            lite.stable_release_contract(root, "1.1.1")
        self.refused_before_write(root, "1.1.1")

    def test_multi_profile_malformed_or_removed_behavior_refuses_before_write(self):
        root, record, _ = self.make_multi_repo()
        cases = []
        def changed(edit):
            bad = copy.deepcopy(record)
            edit(bad)
            cases.append(bad)
        changed(lambda bad: bad.update(profiles=[]))
        changed(lambda bad: bad["profiles"].append(copy.deepcopy(bad["profiles"][0])))
        changed(lambda bad: bad["profiles"][1].update(extra=True))
        changed(lambda bad: bad["profiles"][1]["environment"].update(runtime={"implementation": "CPython"}))
        changed(lambda bad: bad["profiles"][1]["support_candidate"].update(tier={"bad": True}))
        changed(lambda bad: bad["profiles"][1]["support_candidate"].update(capability_level="L9"))
        changed(lambda bad: bad["profiles"][1]["refused_cli_forms"].append("doctor"))
        changed(lambda bad: bad["profiles"][1]["unqualified_cli_forms"].append("unknown public form"))
        changed(lambda bad: bad["profiles"][1]["supported_cli_forms"].remove("doctor"))
        changed(lambda bad: bad["profiles"][0]["supported_cli_forms"].append("doctor"))
        changed(lambda bad: bad["profiles"].pop(0))
        changed(lambda bad: bad["profiles"][0]["environment"].update(system="Linux"))
        changed(lambda bad: bad["profiles"][0]["support_candidate"].update(mode="native"))
        def drop_windows_form(bad):
            bad["profiles"][0]["supported_cli_forms"].remove("doctor")
            bad["profiles"][0]["unqualified_cli_forms"].append("doctor")
        changed(drop_windows_form)
        changed(lambda bad: bad.update(schema_version={"bad": True}))
        changed(lambda bad: bad.update(schema_version="aide.stable-successor-candidate.v3"))
        for number, bad in enumerate(cases):
            with self.subTest(case=number):
                self.save(root, bad)
                with self.assertRaises(ValueError):
                    lite.stable_release_contract(root, "1.2.0")
                self.refused_before_write(root, "1.2.0")

    def test_multi_profile_successor_preserves_environment_and_profile_obligations(self):
        root, record, _ = self.make_multi_repo()
        refused = record["profiles"][1]["unqualified_cli_forms"].pop()
        record["profiles"][1]["refused_cli_forms"].append(refused)
        self.save(root, record)
        self.commit(root)
        self.refresh_pack(root)
        lite.build_stable_release_candidate(root, "1.2.0")
        tag_commit = self.commit(root)
        self.git(root, "tag", "aide-lite-v1.2.0")
        original = self.snapshot(root)
        record.update(version="1.3.0", predecessor={"version": "1.2.0", "tag_commit": tag_commit})
        record["preserved_assets"] += self.pins(root, "1.2.0")
        cases = []
        bad = copy.deepcopy(record)
        bad["profiles"].pop()
        cases.append(bad)
        bad = copy.deepcopy(record)
        bad["profiles"][1]["environment"]["machine"] = "different-architecture"
        cases.append(bad)
        bad = copy.deepcopy(record)
        bad["profiles"][1]["capabilities"].remove("owned-lifecycle")
        cases.append(bad)
        bad = copy.deepcopy(record)
        bad["profiles"][1]["refused_cli_forms"].remove(refused)
        bad["profiles"][1]["unqualified_cli_forms"].append(refused)
        cases.append(bad)
        bad = copy.deepcopy(record)
        bad["profiles"][1]["refused_cli_forms"].remove(refused)
        bad["profiles"][1]["supported_cli_forms"].append(refused)
        cases.append(bad)
        bad = copy.deepcopy(record)
        bad.update(schema_version="aide.stable-successor-candidate.v1", profile_id=lite.STABLE_RELEASE_PROFILE)
        del bad["profiles"]
        cases.append(bad)
        bad = copy.deepcopy(record)
        bad["version"] = "1.2.1"
        form = bad["profiles"][1]["unqualified_cli_forms"].pop()
        bad["profiles"][1]["supported_cli_forms"].append(form)
        cases.append(bad)
        for number, bad in enumerate(cases):
            with self.subTest(case=number):
                self.save(root, bad)
                with self.assertRaises(ValueError):
                    lite.stable_release_contract(root, bad["version"])
                self.refused_before_write(root, bad["version"])
        self.save(root, record)
        self.commit(root)
        self.refresh_pack(root)
        identity = lite.build_stable_release_candidate(root, "1.3.0")["identity"]
        self.assertEqual(identity["predecessor_matrix"][0]["profile_id"], lite.MULTIPROFILE_RELEASE_PROFILE)
        self.assertEqual({name: self.snapshot(root)[name] for name in original}, original)
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.3.0")["result"], "PASS")

    def git(self, root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

    def commit(self, root):
        self.git(root, "add", "-A")
        self.git(root, "commit", "--quiet", "-m", "owned synthetic release fixture")
        return self.git(root, "rev-parse", "HEAD")

    def save(self, root, record):
        (root / lite.STABLE_SUCCESSOR_PATH).write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")

    def pins(self, root, version):
        return [{"path": rel, "size_bytes": (root / rel).stat().st_size,
                 "sha256": hashlib.sha256((root / rel).read_bytes()).hexdigest()}
                for rel in lite.stable_release_paths(version).values()]

    def refresh_pack(self, root):
        # A policy/source change requires a new clean source identity. Do not
        # weaken production provenance to accommodate the synthetic fixture.
        pack = lite.export_pack_root(root)
        source = self.git(root, "rev-parse", "HEAD")
        (pack / "manifest.yaml").write_text(lite.render_manifest(
            lite.pack_manifest_list(pack, "included_files"), source, False),
            encoding="utf-8", newline="\n")
        (pack / "checksums.json").write_text(lite.stable_json_text(lite.build_pack_checksums(pack)),
                                             encoding="utf-8", newline="\n")
        self.commit(root)

    def make_repo(self):
        helper = fixture.Q47ReleaseBundleTests()
        self.addCleanup(helper.doCleanups)
        root = helper.make_repo()
        self.git(root, "init", "--quiet")
        self.git(root, "config", "user.name", "AIDE fixture")
        self.git(root, "config", "user.email", "fixture@example.invalid")
        source = self.commit(root)
        pack = lite.export_pack_root(root)
        helper.write(root, lite.EXPORT_PACK_PATH + "/manifest.yaml", lite.render_manifest(
            lite.pack_manifest_list(pack, "included_files"), source, False))
        helper.write(root, lite.EXPORT_PACK_PATH + "/checksums.json",
                     lite.stable_json_text(lite.build_pack_checksums(pack)))
        self.commit(root)
        lite.build_stable_release_candidate(root, "1.0.0")
        tag_commit = self.commit(root)
        self.git(root, "tag", "aide-lite-v1.0.0")
        record = {"schema_version": "aide.stable-successor-candidate.v1",
                  "version": "1.1.0", "profile_id": lite.STABLE_RELEASE_PROFILE,
                  "predecessor": {"version": "1.0.0", "tag_commit": tag_commit},
                  "additional_cli_forms": ["task current", "task current --json"],
                  "preserved_assets": self.pins(root, "1.0.0")}
        self.save(root, record)
        # A historical policy digest must not be reinterpreted as today's policy.
        policy = root / ".aide/policies/release-versioning.yaml"
        policy.write_text(policy.read_text(encoding="utf-8") + "\n# successor fixture\n",
                          encoding="utf-8", newline="\n")
        self.commit(root)
        self.refresh_pack(root)
        return root, record

    def snapshot(self, root):
        return {p.name: p.read_bytes() for p in (root / lite.STABLE_RELEASE_DIR).iterdir()
                if p.is_file()}

    def refused_before_write(self, root, version="1.1.0"):
        before = self.snapshot(root)
        with mock.patch.object(lite, "write_release_zip", side_effect=AssertionError("archive write")), \
                mock.patch.object(lite, "write_text_if_changed", side_effect=AssertionError("metadata write")):
            with self.assertRaises((ValueError, OSError)):
                lite.build_stable_release_candidate(root, version)
        self.assertEqual(self.snapshot(root), before)
        try:
            lite.stable_release_paths(version)
        except ValueError:
            with self.assertRaises(ValueError):
                lite.validate_stable_release_candidate(root, version)
        else:
            self.assertEqual(lite.validate_stable_release_candidate(root, version)["result"], "FAIL")

    def test_successor_preserves_history_binds_identity_and_replays(self):
        root, record = self.make_repo()
        original = self.snapshot(root)
        result = lite.build_stable_release_candidate(root, "1.1.0")
        identity = result["identity"]
        self.assertEqual(identity["public_cli_forms"], lite.stable_release_cli_forms(root) + record["additional_cli_forms"])
        self.assertEqual(identity["successor_contract_sha256"], hashlib.sha256(
            (root / lite.STABLE_SUCCESSOR_PATH).read_bytes()).hexdigest())
        previous = identity["predecessor_matrix"][0]
        self.assertEqual(previous["tag_commit"], record["predecessor"]["tag_commit"])
        old = json.loads(original["aide-lite-v1.0.0.manifest.json"])["identity"]
        self.assertEqual(previous["source_commit"], old["source_commit"])
        self.assertNotEqual(previous["source_commit"], previous["tag_commit"])
        self.assertEqual(previous["assets"], record["preserved_assets"])
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.1.0")["result"], "PASS")
        frozen = self.snapshot(root)
        lite.build_stable_release_candidate(root, "1.1.0")
        self.assertEqual(self.snapshot(root), frozen)
        (root / lite.stable_release_paths("1.1.0")["zip"]).write_bytes(b"tampered candidate")
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.1.0")["result"], "FAIL")
        lite.build_stable_release_candidate(root, "1.1.0")
        self.assertEqual(self.snapshot(root), frozen)
        self.assertEqual({name: frozen[name] for name in original}, original)

    def test_future_successor_retains_every_older_version(self):
        root, record = self.make_repo()
        lite.build_stable_release_candidate(root, "1.1.0")
        tag_commit = self.commit(root)
        self.git(root, "tag", "aide-lite-v1.1.0")
        old = self.snapshot(root)
        record.update(version="1.2.0", predecessor={"version": "1.1.0", "tag_commit": tag_commit})
        record["preserved_assets"] += self.pins(root, "1.1.0")
        self.save(root, record)
        self.commit(root)
        self.refresh_pack(root)
        lite.build_stable_release_candidate(root, "1.2.0")
        self.assertEqual({name: self.snapshot(root)[name] for name in old}, old)
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.2.0")["result"], "PASS")
        record["additional_cli_forms"] = []
        self.save(root, record)
        self.refused_before_write(root, "1.2.0")

    def test_missing_tampered_or_inconsistent_predecessor_refuses(self):
        root, record = self.make_repo()
        path = root / record["preserved_assets"][0]["path"]
        data = path.read_bytes()
        path.unlink()
        self.refused_before_write(root)
        path.write_bytes(data + b"x")
        self.refused_before_write(root)
        # Even repinning a corrupt archive cannot override the historical manifest.
        changed = copy.deepcopy(record)
        changed["preserved_assets"] = self.pins(root, "1.0.0")
        self.save(root, changed)
        self.refused_before_write(root)
        path.write_bytes(data)

    def test_strict_metadata_refuses_without_output(self):
        root, record = self.make_repo()
        path = root / lite.STABLE_SUCCESSOR_PATH
        cases = ["{}", "[]", "{\"version\":1,\"version\":2}", "{\"x\":NaN}",
                 "[" * 1500 + "]" * 1500, " " * 65537, "\ufeff{}"]
        for text in cases:
            with self.subTest(metadata=text[:30]):
                path.write_text(text, encoding="utf-8")
                self.refused_before_write(root)
        path.write_bytes(b"\xff")
        self.refused_before_write(root)
        for field, value in (("extra", True), ("profile_id", "another-profile"),
                             ("predecessor", []), ("preserved_assets", []),
                             ("additional_cli_forms", ["doctor"]),
                             ("additional_cli_forms", ["x", "x"]),
                             ("additional_cli_forms", [None])):
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(record)
                bad[field] = value
                self.save(root, bad)
                self.refused_before_write(root)

    def test_bad_versions_tags_and_policy_refuse(self):
        root, record = self.make_repo()
        for version in ("01.1.0", "1.0.1", "0.9.0", "2.0.0", "1.0.0/../x"):
            with self.subTest(version=version):
                bad = copy.deepcopy(record)
                bad["version"] = version
                self.save(root, bad)
                self.refused_before_write(root, version)
        self.save(root, record)
        self.git(root, "tag", "-d", "aide-lite-v1.0.0")
        self.refused_before_write(root)
        self.git(root, "tag", "aide-lite-v1.0.0")  # wrong source commit
        self.refused_before_write(root)
        self.git(root, "tag", "-f", "aide-lite-v1.0.0", record["predecessor"]["tag_commit"])
        self.git(root, "tag", "aide-lite-v1.0.9")
        self.refused_before_write(root)
        self.git(root, "tag", "-d", "aide-lite-v1.0.9")
        self.git(root, "tag", "aide-lite-v1.1.0")
        self.refused_before_write(root)
        self.git(root, "tag", "-d", "aide-lite-v1.1.0")
        policy = root / ".aide/policies/release-versioning.yaml"
        policy.write_text(policy.read_text(encoding="utf-8").replace(
            "successor_candidate_ref:", "unrecognized_ref:"), encoding="utf-8")
        self.refused_before_write(root)

    def test_asset_metadata_bounds_duplicates_and_paths(self):
        root, record = self.make_repo()
        for field, value in (("path", "../outside.zip"), ("path", record["preserved_assets"][1]["path"]),
                             ("size_bytes", True), ("size_bytes", 8388609), ("sha256", "f" * 64)):
            bad = copy.deepcopy(record)
            bad["preserved_assets"][0][field] = value
            self.save(root, bad)
            self.refused_before_write(root)
        for assets in (record["preserved_assets"] * 9, record["preserved_assets"][:-1],
                       record["preserved_assets"] + [record["preserved_assets"][0]]):
            bad = copy.deepcopy(record)
            bad["preserved_assets"] = assets
            self.save(root, bad)
            self.refused_before_write(root)

    def test_unknown_and_shared_output_members_refuse(self):
        root, record = self.make_repo()
        output = root / lite.STABLE_RELEASE_DIR
        alien = output / "unknown.txt"
        alien.write_text("owned test fixture", encoding="utf-8")
        self.refused_before_write(root)
        alien.unlink()
        candidate = root / lite.stable_release_paths("1.1.0")["zip"]
        os.link(root / record["preserved_assets"][0]["path"], candidate)
        self.refused_before_write(root)
        candidate.unlink()
        alias = root / "predecessor-link.zip"
        os.link(root / record["preserved_assets"][0]["path"], alias)
        self.refused_before_write(root)
        alias.unlink()
        candidate.mkdir()
        self.refused_before_write(root)
        candidate.rmdir()

    def test_contract_hardlink_and_reparse_metadata_are_rejected(self):
        root, _ = self.make_repo()
        record = root / lite.STABLE_SUCCESSOR_PATH
        alias = root / "candidate-alias.json"
        os.link(record, alias)
        self.refused_before_write(root)
        alias.unlink()
        original = Path.lstat
        def redirected(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == record:
                class Redirected:
                    st_mode = info.st_mode
                    st_file_attributes = 0x400
                return Redirected()
            return info
        with mock.patch.object(Path, "lstat", redirected):
            self.refused_before_write(root)

    def test_validator_detects_changed_contract_and_manifest_lineage(self):
        root, record = self.make_repo()
        lite.build_stable_release_candidate(root, "1.1.0")
        record["additional_cli_forms"].append("task status --fixture")
        self.save(root, record)
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.1.0")["result"], "FAIL")
        record["additional_cli_forms"].pop()
        self.save(root, record)
        manifest = root / lite.stable_release_paths("1.1.0")["manifest"]
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["identity"]["predecessor_matrix"] = []
        manifest.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.1.0")["result"], "FAIL")

    def test_patch_can_preserve_the_same_public_forms(self):
        root, record = self.make_repo()
        record.update(version="1.0.1", additional_cli_forms=[])
        self.save(root, record)
        self.commit(root)
        self.refresh_pack(root)
        lite.build_stable_release_candidate(root, "1.0.1")
        self.assertEqual(lite.validate_stable_release_candidate(root, "1.0.1")["result"], "PASS")

    def test_validator_rejects_coherent_wrong_identity(self):
        root, _ = self.make_repo()
        original = lite.build_stable_release_candidate(root, "1.1.0")
        paths = lite.stable_release_paths("1.1.0")
        for field, value in (("manifest_schema", "unknown"), ("schema_version", "unknown"),
                             ("tag", "aide-lite-v9.9.9"), ("release_axis", "another_product"),
                             ("source_commit", None), ("source_commit", 123)):
            with self.subTest(field=field, value=value):
                manifest = copy.deepcopy(original)
                if field == "manifest_schema":
                    manifest["schema_version"] = value
                else:
                    manifest["identity"][field] = value
                with lite.public_archive_fixture("aide-stable-pack-") as temporary:
                    projected = Path(temporary) / lite.RELEASE_ARCHIVE_ROOT
                    lite.build_release_pack_projection(lite.export_pack_root(root), projected)
                    lite.write_text_if_changed(projected / "stable-release.json",
                                               lite.stable_json_text(manifest["identity"]))
                    lite.write_text_if_changed(projected / "checksums.json",
                                               lite.stable_json_text(lite.build_pack_checksums(projected)))
                    lite.write_release_zip(projected, root / paths["zip"])
                    lite.write_release_tar_gz(projected, root / paths["tar_gz"])
                for key in ("zip", "tar_gz"):
                    asset = root / paths[key]
                    manifest["archives"][key].update(size_bytes=asset.stat().st_size,
                                                     sha256=hashlib.sha256(asset.read_bytes()).hexdigest())
                    self.assertEqual(lite.validate_release_archive(root, paths[key])["result"], "PASS")
                lite.write_text_if_changed(root / paths["manifest"], lite.stable_json_text(manifest))
                sums = "".join(f"{lite.sha256_file(root / paths[key])}  {Path(paths[key]).name}\n"
                               for key in ("zip", "tar_gz", "manifest"))
                lite.write_text_if_changed(root / paths["sha256sums"], sums)
                validation = lite.validate_stable_release_candidate(root, "1.1.0")
                self.assertEqual(validation["result"], "FAIL")
                self.assertFalse(any("asset digest" in p or "embedded identity" in p or "SHA256SUMS" in p
                                     for p in validation["problems"]), validation)


if __name__ == "__main__":
    unittest.main()
