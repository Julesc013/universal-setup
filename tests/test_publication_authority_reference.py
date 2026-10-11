# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "setup" / "wu004-windows-ntfs-publication-oracles.v1.json"
MODEL = ROOT / "tests" / "publication_authority_reference.py"
module_spec = importlib.util.spec_from_file_location("publication_authority_reference", MODEL)
assert module_spec is not None and module_spec.loader is not None
oracle = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = oracle
module_spec.loader.exec_module(oracle)


def _patch(value: object, changes: dict[str, object]) -> object:
    result = deepcopy(value)
    for dotted, replacement in changes.items():
        target = result
        parts = dotted.split(".")
        for part in parts[:-1]:
            target = target[int(part)] if isinstance(target, list) else target[part]
        if isinstance(target, list):
            target[int(parts[-1])] = deepcopy(replacement)
        else:
            target[parts[-1]] = deepcopy(replacement)
    return result


class FixtureResolver:
    def __init__(self, fixture: dict[str, object]) -> None:
        profile = fixture["profile"]
        self.security = deepcopy(profile["protected_security"])

        def expand_security(value: object) -> object:
            if value == "$protected_security":
                return deepcopy(self.security)
            if isinstance(value, dict):
                return {key: expand_security(item) for key, item in value.items()}
            if isinstance(value, list):
                return [expand_security(item) for item in value]
            return deepcopy(value)

        self.evidence = expand_security(profile["valid_evidence"])
        self.binding = expand_security(profile["verified_binding"])
        self.observation = {key: deepcopy(self.evidence[key]) for key in oracle.PHASE_OBSERVATION_KEYS}
        self.post_observation = deepcopy(self.observation)
        self.post_observation["protected_objects"][0]["observed_path"] = \
            self.evidence["protected_objects"][1]["observed_path"] + "/" + self.evidence["destination_name"]
        closure = self.binding["closure"]
        self.closures = {
            "$verified_closure": closure,
            "$foreign_id_closure": _patch(closure, {"1.file_id": "3478de651b6df063:abababababababababababababababab"}),
            "$changed_hash_closure": _patch(closure, {"1.content_sha256": "0123456789abcdef" * 4}),
            "$missing_child_closure": closure[:1],
            "$hardlink_closure": _patch(closure, {"1.link_count": 2}),
            "$ads_closure": _patch(closure, {"1.streams": ["::$DATA", ":evil:$DATA"]}),
            "$cross_volume_closure": _patch(closure, {"0.file_id": "bbbbbbbbbbbbbbbb:88888888888888888888888888888888",
                                                       "1.file_id": "bbbbbbbbbbbbbbbb:99999999999999999999999999999999"}),
            "$ads_path_closure": _patch(closure, {"1.relative_path": "sub/payload.bin:evil"}),
            "$orphan_closure": closure[1:],
            "$file_parent_closure": _patch(closure, {"0.type": "file", "0.content_sha256": "2" * 64,
                                                      "0.attributes": ["ARCHIVE"], "0.streams": ["::$DATA"]}),
            "$contradictory_reparse_closure": _patch(closure, {"1.attributes": ["ARCHIVE", "REPARSE_POINT"],
                                                                "1.reparse": False, "1.reparse_tag": 0}),
            "$duplicate_identity_closure": _patch(closure, {"1.file_id": closure[0]["file_id"]}),
            "$protected_alias_closure": _patch(
                closure, {"1.file_id": self.evidence["protected_objects"][1]["file_id"]}),
            "$file_directory_attribute_closure": _patch(closure, {"1.attributes": ["ARCHIVE", "DIRECTORY"]}),
            "$directory_missing_attribute_closure": _patch(closure, {"0.attributes": []}),
        }
        case_alias = deepcopy(closure)
        alias = deepcopy(closure[0])
        alias["relative_path"] = "SUB"
        alias["file_id"] = "3478de651b6df063:12121212121212121212121212121212"
        case_alias.insert(1, alias)
        self.closures["$case_alias_closure"] = case_alias
        self.roots = {"$cross_volume_root": _patch(
            self.binding["root"], {"file_id": "bbbbbbbbbbbbbbbb:77777777777777777777777777777777"}),
            "$duplicate_descendant_root": _patch(self.binding["root"], {"file_id": closure[0]["file_id"]})}
        extra = deepcopy(closure)
        extra.append({"relative_path": "z.bin", "type": "file",
                      "file_id": "3478de651b6df063:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                      "content_sha256": "1234567890abcdef" * 4, "size": 1,
                      "attributes": ["ARCHIVE"], "security": deepcopy(self.security),
                      "link_count": 1, "streams": ["::$DATA"], "reparse": False, "reparse_tag": None})
        self.closures["$extra_child_closure"] = extra
        self.bindings = {
            "$verified_binding": self.binding,
            "$foreign_id_binding": {"root": self.binding["root"], "closure": self.closures["$foreign_id_closure"]},
            "$changed_hash_binding": {"root": self.binding["root"], "closure": self.closures["$changed_hash_closure"]},
            "$missing_child_binding": {"root": self.binding["root"], "closure": self.closures["$missing_child_closure"]},
            "$extra_child_binding": {"root": self.binding["root"], "closure": self.closures["$extra_child_closure"]},
        }

    def value(self, value: object) -> object:
        if value == "$protected_security":
            return deepcopy(self.security)
        if value == "$valid_profile":
            return deepcopy(self.evidence)
        if value == "$phase_observation":
            return deepcopy(self.observation)
        if value == "$post_rename_observation":
            return deepcopy(self.post_observation)
        if value == "$truncated_ancestor_profile":
            result = deepcopy(self.evidence)
            result["protected_objects"] = result["protected_objects"][:4] + [result["protected_objects"][6]]
            return result
        if value == "$verified_root":
            return deepcopy(self.binding["root"])
        if isinstance(value, str) and value in self.roots:
            return deepcopy(self.roots[value])
        if isinstance(value, str) and value in self.closures:
            return deepcopy(self.closures[value])
        if isinstance(value, str) and value in self.bindings:
            return deepcopy(self.bindings[value])
        if isinstance(value, dict) and set(value) == {"$profile_patch"}:
            return _patch(self.evidence, value["$profile_patch"])
        if isinstance(value, dict) and set(value) == {"$observation_patch"}:
            return _patch(self.observation, value["$observation_patch"])
        if isinstance(value, dict) and set(value) == {"$post_observation_patch"}:
            return _patch(self.post_observation, value["$post_observation_patch"])
        if isinstance(value, dict):
            return {key: self.value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.value(item) for item in value]
        return deepcopy(value)

    def _prefix(self, name: str) -> list[dict[str, object]]:
        basic = [
            {"action": "admit_profile", "evidence": deepcopy(self.evidence)},
            {"action": "begin_materialization"},
            {"action": "seal", "observation": deepcopy(self.observation),
             "root": deepcopy(self.binding["root"]), "closure": deepcopy(self.binding["closure"])},
            {"action": "prepare_publish"},
        ]
        if name == "$through_prepare":
            return basic
        renamed = basic + [{"action": "rename", "observation": deepcopy(self.observation),
                            "outcome": "applied", "replace_if_exists": False,
                            "destination_exists": False}]
        if name == "$through_rename":
            return renamed
        if name == "$through_visible":
            return renamed + [{"action": "confirm_visible", "observation": deepcopy(self.post_observation),
                               "destination_name": "generation-1",
                               "root": deepcopy(self.binding["root"]),
                               "closure": deepcopy(self.binding["closure"])}]
        if name == "$metadata":
            return [{"action": "begin_metadata"}, {"action": "complete_metadata", "success": True}]
        raise AssertionError("unknown event macro: " + name)

    def events(self, events: list[object]) -> list[dict[str, object]]:
        resolved: list[dict[str, object]] = []
        for event in events:
            if isinstance(event, str):
                resolved.extend(self._prefix(event))
            else:
                item = self.value(event)
                assert isinstance(item, dict)
                resolved.append(item)
        return resolved


class PublicationAuthorityReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.resolver = FixtureResolver(cls.fixture)

    def _bound_context_variant(self, service_sid: str = "S-1-5-80-1-2-3-4-5"):
        # Synthetic model control, never a transformed native receipt. Preserve
        # the asserted SDK/SID rather than substituting the legacy constants.
        fixture = deepcopy(self.fixture)
        security = fixture["profile"]["protected_security"]
        security["dacl_aces"][1]["principal"] = service_sid
        security["canonical_descriptor_sha256"] = hashlib.sha256(
            oracle._security_canonical_payload(security)).hexdigest()
        evidence = fixture["profile"]["valid_evidence"]
        evidence["publisher_service_sid"] = service_sid
        evidence["sdk_version"] = "10.0.26100.0"
        evidence["protected_objects"] = evidence["protected_objects"][:6]
        publication_root = evidence["protected_objects"][5]["observed_path"]
        for entry in evidence["protected_objects"][:4]:
            entry["observed_path"] = publication_root + "/" + entry["observed_path"].rsplit("/", 1)[-1]
        context = oracle.PublicationModelContext(service_sid, "10.0.26100.0", 0)
        return FixtureResolver(fixture), context

    def test_explicit_model_context_preserves_sid_sdk_and_direct_root_chain(self) -> None:
        resolver, context = self._bound_context_variant()
        events = resolver.events(["$through_visible", "$metadata"])
        result = oracle.replay(oracle.initial_state(), events, context=context)
        self.assertEqual(result.disposition, "completed")
        self.assertEqual(result.state.profile.publisher_service_sid, context.service_sid)
        self.assertEqual(result.state.profile.sdk_version, "10.0.26100.0")
        self.assertEqual(len(result.state.profile.protected_objects), 6)
        # The original entry point still applies the original closed fixture.
        self.assertEqual(oracle.replay(oracle.initial_state(), events).disposition, "no_effect_refusal")
        # Once admitted, every phase uses the frozen profile, even with the
        # default transition context; it cannot silently reselect a provider.
        admitted = oracle.transition(oracle.initial_state(), events[0], context=context)
        self.assertEqual(oracle.replay(admitted.state, events[1:]).disposition, "completed")

    def test_context_cannot_be_changed_by_profile_claims(self) -> None:
        resolver, context = self._bound_context_variant()
        for sdk, sid, ancestors in (("10.0.17763.0", context.service_sid, 0),
                                   (context.sdk_version, oracle.SERVICE_SID, 0),
                                   (context.sdk_version, context.service_sid, 1)):
            pinned = oracle.PublicationModelContext(sid, sdk, ancestors)
            result = oracle.transition(oracle.initial_state(),
                {"action": "admit_profile", "evidence": resolver.evidence}, context=pinned)
            self.assertEqual(result.disposition, "no_effect_refusal")
        claimed = deepcopy(resolver.evidence)
        claimed["available"] = True
        self.assertEqual(oracle.transition(oracle.initial_state(),
            {"action": "admit_profile", "evidence": claimed}, context=context).disposition, "no_effect_refusal")

    def test_direct_root_chain_still_requires_every_immediate_parent_and_identity(self) -> None:
        resolver, context = self._bound_context_variant()
        publication_root = resolver.evidence["protected_objects"][5]["observed_path"]
        for change in ({"protected_objects.0.observed_path": publication_root + "/unbound/staging"},
                       {"protected_objects.5.observed_path": publication_root + "/unbound"},
                       {"protected_objects.1.file_id": resolver.evidence["protected_objects"][0]["file_id"]}):
            result = oracle.transition(oracle.initial_state(), {"action": "admit_profile",
                "evidence": _patch(resolver.evidence, change)}, context=context)
            self.assertEqual(result.disposition, "no_effect_refusal")

    def test_native_api_provenance_requires_its_pinned_context(self) -> None:
        resolver, original = self._native_child_layout_variant()
        context = oracle.PublicationModelContext(original.service_sid, original.sdk_version, 0,
            original.namespace_layout, "GetKernelObjectSecurity")
        original_evidence = deepcopy(resolver.evidence)
        resolver.evidence["observation_apis"] = list(context.observation_apis)
        events = resolver.events(["$through_visible", "$metadata"])
        self.assertEqual(oracle.replay(oracle.initial_state(), events, context=context).disposition, "completed")
        self.assertEqual(oracle.replay(oracle.initial_state(), events, context=original).disposition,
                         "no_effect_refusal")
        self.assertEqual(oracle.transition(oracle.initial_state(),
            {"action": "admit_profile", "evidence": original_evidence}, context=context).disposition,
            "no_effect_refusal")
        for api in ("GetSecurityInfo", "NtQuerySecurityObject", "AccessCheck"):
            changed = deepcopy(resolver.evidence)
            changed["observation_apis"][0] = api
            self.assertEqual(oracle.transition(oracle.initial_state(),
                {"action": "admit_profile", "evidence": changed}, context=context).disposition, "no_effect_refusal")
        changed = deepcopy(resolver.evidence)
        changed["observation_apis"].remove("NtQueryObject:ObjectBasicInformation")
        self.assertEqual(oracle.transition(oracle.initial_state(),
            {"action": "admit_profile", "evidence": changed}, context=context).disposition, "no_effect_refusal")
        with self.assertRaises(oracle.EvidenceError):
            oracle.PublicationModelContext(security_observation_api="caller_chosen_api")

    def test_every_bound_context_phase_refuses_a_different_service_descriptor(self) -> None:
        resolver, context = self._bound_context_variant()
        foreign, _ = self._bound_context_variant("S-1-5-80-6-7-8-9-10")
        for phase in ("seal", "rename", "confirm_visible"):
            events = resolver.events(["$through_visible", "$metadata"])
            other_events = foreign.events(["$through_visible", "$metadata"])
            for event, other in zip(events, other_events):
                if event["action"] == phase:
                    event["observation"] = deepcopy(other["observation"])
            result = oracle.replay(oracle.initial_state(), events, context=context)
            self.assertNotEqual(result.disposition, "completed")
            self.assertTrue(result.state.retained)

    def test_model_context_refuses_noncanonical_and_unbounded_inputs(self) -> None:
        for kwargs in ({"service_sid": None}, {"service_sid": "S-1-5-80-1"},
                       {"service_sid": "S-1-5-80-01-2-3-4-5"},
                       {"service_sid": "S-1-5-80-1-2-3-4-4294967296"},
                       {"sdk_version": "10.0.17762.0"}, {"sdk_version": "10.0.026100.0"},
                       {"sdk_version": False}, {"minimum_additional_ancestors": True},
                       {"minimum_additional_ancestors": -1}, {"minimum_additional_ancestors": 2},
                       {"namespace_layout": False}, {"namespace_layout": "unbound_payload"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(oracle.EvidenceError):
                oracle.PublicationModelContext(**kwargs)

    def _native_child_layout_variant(self):
        resolver, context = self._bound_context_variant()
        payload = deepcopy(resolver.evidence["protected_objects"][0])
        payload.update(role="payload_root", observed_path=payload["observed_path"] + "/candidate")
        resolver.evidence["protected_objects"][0]["file_id"] = "3478de651b6df063:" + "a" * 32
        resolver.evidence["protected_objects"].append(payload)
        resolver.evidence["covered_objects"].append("payload_root")
        resolver.observation = {key: deepcopy(resolver.evidence[key]) for key in oracle.PHASE_OBSERVATION_KEYS}
        resolver.post_observation = deepcopy(resolver.observation)
        resolver.post_observation["protected_objects"][6]["observed_path"] = \
            resolver.evidence["protected_objects"][1]["observed_path"] + "/" + resolver.evidence["destination_name"]
        return resolver, oracle.PublicationModelContext(context.service_sid, context.sdk_version, 0,
                                                        "staging_anchor_with_payload_child")

    def test_explicit_native_layout_moves_payload_and_keeps_staging_anchor(self) -> None:
        resolver, context = self._native_child_layout_variant()
        events = resolver.events(["$through_visible", "$metadata"])
        result = oracle.replay(oracle.initial_state(), events, context=context)
        self.assertEqual(result.disposition, "completed")
        self.assertEqual(result.state.profile.namespace_layout, context.namespace_layout)
        self.assertEqual(result.state.profile.published_root.file_id, resolver.binding["root"]["file_id"])
        self.assertEqual(result.state.post_rename_observation.protected_objects[0],
                         result.state.profile.protected_objects[0])
        self.assertEqual(result.state.post_rename_observation.protected_objects[6].observed_path,
                         resolver.post_observation["protected_objects"][6]["observed_path"])
        admitted = oracle.transition(oracle.initial_state(), events[0], context=context)
        self.assertEqual(oracle.replay(admitted.state, events[1:]).disposition, "completed")
        old_context = oracle.PublicationModelContext(context.service_sid, context.sdk_version, 0)
        self.assertEqual(oracle.replay(oracle.initial_state(), events, context=old_context).disposition,
                         "no_effect_refusal")

    def test_native_layout_refuses_wrong_parent_alias_and_evidence_selected_layout(self) -> None:
        resolver, context = self._native_child_layout_variant()
        staging = resolver.evidence["protected_objects"][0]
        for patch in ({"protected_objects.6.observed_path": "repo/destination/candidate"},
                      {"protected_objects.6.file_id": staging["file_id"]},
                      {"covered_objects": list(oracle.EXPECTED_COVERED_OBJECTS)}):
            result = oracle.transition(oracle.initial_state(), {"action": "admit_profile",
                "evidence": _patch(resolver.evidence, patch)}, context=context)
            self.assertEqual(result.disposition, "no_effect_refusal")
        claimed = deepcopy(resolver.evidence)
        claimed["namespace_layout"] = context.namespace_layout
        self.assertEqual(oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": claimed},
            context=context).disposition, "no_effect_refusal")
        events = resolver.events(["$through_visible", "$metadata"])
        for event in events:
            if event["action"] == "confirm_visible":
                event["observation"]["protected_objects"][0]["observed_path"] = \
                    event["observation"]["protected_objects"][6]["observed_path"]
        result = oracle.replay(oracle.initial_state(), events, context=context)
        self.assertEqual(result.disposition, "recovery_required")
        self.assertTrue(result.state.retained)

    def test_fixture_has_closed_schema_profile_and_cases(self) -> None:
        self.assertEqual(set(self.fixture), {"schema", "profile", "cases"})
        self.assertEqual(self.fixture["schema"], "usk.wu004.windows-ntfs-publication-oracles/2")
        self.assertEqual(set(self.fixture["profile"]), {
            "id", "status", "minimum_platform", "required_evidence_fields", "bounds", "required_ace_set",
            "protected_security", "included_adversaries", "excluded_adversaries", "nonclaims",
            "valid_evidence", "verified_binding"})
        self.assertEqual(set(self.fixture["profile"]["valid_evidence"]), set(oracle.PROFILE_KEYS))
        self.assertEqual(set(self.fixture["profile"]["required_evidence_fields"]), set(oracle.PROFILE_KEYS))
        self.assertEqual(self.fixture["profile"]["bounds"], {
            "max_closure_entries": oracle.MAX_CLOSURE_ENTRIES,
            "max_closure_depth": oracle.MAX_CLOSURE_DEPTH,
            "max_component_utf16_units": oracle.MAX_COMPONENT_UTF16_UNITS,
            "max_serialized_evidence_bytes": oracle.MAX_EVIDENCE_BYTES,
            "max_total_content_bytes": oracle.MAX_CONTENT_BYTES})
        case_keys = {"id", "mutation", "events", "expected"}
        projection_keys = {"disposition", "phase", "effect_state", "rename_state", "retained",
                           "durable_milestones", "visible_binding", "completed_generation_count", "reason_code"}
        ids = [case["id"] for case in self.fixture["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        for case in self.fixture["cases"]:
            self.assertEqual(set(case), case_keys, case["id"])
            self.assertEqual(set(case["mutation"]), {"predicate", "evidence"}, case["id"])
            self.assertEqual(set(case["expected"]), projection_keys, case["id"])
            self.assertIn(case["expected"]["disposition"], oracle.DISPOSITIONS, case["id"])

    def test_fixture_replay_matches_every_full_expected_projection(self) -> None:
        for case in self.fixture["cases"]:
            events = self.resolver.events(case["events"])
            result = oracle.replay(oracle.initial_state(), events)
            expected = self.resolver.value(case["expected"])
            self.assertEqual(oracle.projection(result), expected, case["id"])
            self.assertEqual(oracle.invariant_errors(result.state), (), case["id"])

    def test_success_contains_explicit_visible_root_and_every_child(self) -> None:
        success = next(case for case in self.fixture["cases"] if case["id"] == "protected-success")
        visible_event = next(event for event in success["events"]
                             if isinstance(event, dict) and event.get("action") == "confirm_visible")
        self.assertIsInstance(visible_event["root"], dict)
        self.assertEqual(visible_event["closure"], self.fixture["profile"]["verified_binding"]["closure"])
        self.assertEqual(len(visible_event["closure"]), 2)

    def test_substitution_and_missing_observation_cannot_complete(self) -> None:
        ids = {"identical-bytes-same-name-foreign-identity", "same-path-changed-hash",
               "extra-visible-child", "missing-visible-child", "omitted-visible-observation"}
        for case in self.fixture["cases"]:
            if case["id"] in ids:
                result = oracle.replay(oracle.initial_state(), self.resolver.events(case["events"]))
                self.assertEqual(result.disposition, "recovery_required", case["id"])
                self.assertNotEqual(result.state.phase, oracle.Phase.COMPLETED, case["id"])
                self.assertEqual(len(result.state.completed_generations), 0, case["id"])

    def test_volume_namespace_tree_and_reparse_adversarial_regressions_refuse(self) -> None:
        ids = {"wholesale-cross-volume-closure", "ads-colon-in-relative-path",
               "missing-intermediate-directory", "file-used-as-parent", "case-fold-alias",
               "contradictory-reparse-facts", "security-digest-structure-mismatch",
               "reserved-destination-name", "visible-destination-name-mismatch"}
        cases = {case["id"]: case for case in self.fixture["cases"]}
        self.assertTrue(ids.issubset(cases))
        self.assertIs(cases["wholesale-cross-volume-closure"]["mutation"]["evidence"]
                      ["caller_same_volume_assertion"], True)
        for case_id in ids:
            result = oracle.replay(oracle.initial_state(), self.resolver.events(cases[case_id]["events"]))
            self.assertIn(result.disposition,
                          {"no_effect_refusal", "retained_refusal", "recovery_required"}, case_id)
            self.assertNotEqual(result.state.phase, oracle.Phase.COMPLETED, case_id)

    def test_identity_type_and_protected_object_aliases_refuse(self) -> None:
        cases = {case["id"]: case for case in self.fixture["cases"]}
        expected = {
            "duplicate-closure-stable-identity": ("retained_refusal", "sealed_evidence_refused"),
            "closure-aliases-protected-destination-parent": ("retained_refusal", "sealed_evidence_refused"),
            "root-shares-descendant-identity": ("retained_refusal", "sealed_evidence_refused"),
            "file-with-directory-attribute": ("retained_refusal", "sealed_evidence_refused"),
            "directory-without-directory-attribute": ("retained_refusal", "sealed_evidence_refused"),
            "aliased-protected-object-roles": ("no_effect_refusal", "profile_evidence_refused"),
            "broken-protected-parent-chain": ("no_effect_refusal", "profile_evidence_refused"),
            "truncated-unrooted-ancestor-chain": ("no_effect_refusal", "profile_evidence_refused"),
            "seal-protected-ancestor-substitution": ("retained_refusal", "sealed_evidence_refused"),
            "seal-protected-reparse-change": ("retained_refusal", "sealed_evidence_refused"),
            "pre-rename-protected-dacl-change": ("retained_refusal", "pre_rename_observation_refused"),
            "post-rename-protected-case-change": ("recovery_required", "post_rename_observation_refused"),
            "post-rename-locality-change": ("recovery_required", "post_rename_observation_refused"),
            "post-rename-volume-change": ("recovery_required", "post_rename_observation_refused"),
        }
        self.assertTrue(set(expected).issubset(cases))
        for case_id, (disposition, reason) in expected.items():
            result = oracle.replay(oracle.initial_state(), self.resolver.events(cases[case_id]["events"]))
            self.assertEqual((result.disposition, result.reason_code), (disposition, reason), case_id)
            self.assertNotEqual(result.state.phase, oracle.Phase.COMPLETED, case_id)
            self.assertEqual(len(result.state.completed_generations), 0, case_id)

    def test_actual_local_ntfs_probe_semantics_and_old_assumptions(self) -> None:
        profile = oracle.ProfileEvidence.parse(self.resolver.evidence)
        self.assertEqual(profile.volume_name, "Fast")
        self.assertEqual(profile.volume_serial, "3478de651b6df063")
        self.assertEqual(profile.volume_information_serial, "1b6df063")
        self.assertEqual(profile.filesystem_flags, 0x03E706FF)
        self.assertEqual((profile.remote_protocol_query_status, profile.remote_protocol_error), ("error", 87))
        self.assertIsNone(profile.remote_protocol)

        mutations = [
            {"filesystem_flags": ["FILE_PERSISTENT_ACLS", "FILE_SUPPORTS_REPARSE_POINTS"]},
            {"remote_protocol_query_status": "success", "remote_protocol_error": None,
             "remote_protocol": 0, "remote_protocol_major": 0, "remote_protocol_minor": 0,
             "remote_protocol_revision": 0, "remote_protocol_flags": 0},
            {"volume_serial": "000000001b6df063"},
            {"filesystem_flags": 0x103E706FF},
        ]
        for changes in mutations:
            evidence = _patch(self.resolver.evidence, changes)
            result = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": evidence})
            self.assertEqual(result.disposition, "no_effect_refusal", changes)

    def test_every_phase_reobserves_chain_security_case_reparse_volume_and_locality(self) -> None:
        mutations = {
            "ancestor_rename": {"protected_objects.6.observed_path": "repo/other"},
            "ancestor_substitution": {
                "protected_objects.6.file_id": "3478de651b6df063:abababababababababababababababab"},
            "ancestor_dacl": {
                "protected_objects.6.security.effective_access.1.rights": ["FILE_DELETE_CHILD"],
                "protected_objects.6.security.canonical_descriptor_sha256":
                    "c2b8a8bc1bb3ed71d8b705b3d08c8c6d02b9efefbda7d27ea5bbdd2cc1047d65"},
            "ancestor_case": {"protected_objects.6.case_sensitive": True},
            "ancestor_reparse": {"protected_objects.6.reparse": True},
            "volume": {"volume_serial": "bbbbbbbbbbbbbbbb"},
            "locality": {"remote_protocol_query_status": "success"},
        }
        materializing = oracle.replay(
            oracle.initial_state(), self.resolver.events([
                {"action": "admit_profile", "evidence": "$valid_profile"},
                {"action": "begin_materialization"}])).state
        prepared = oracle.replay(oracle.initial_state(), self.resolver._prefix("$through_prepare")).state
        renamed = oracle.replay(oracle.initial_state(), self.resolver._prefix("$through_rename")).state
        for label, changes in mutations.items():
            seal = oracle.transition(materializing, {
                "action": "seal", "observation": _patch(self.resolver.observation, changes),
                "root": deepcopy(self.resolver.binding["root"]),
                "closure": deepcopy(self.resolver.binding["closure"])})
            self.assertEqual((seal.disposition, seal.reason_code),
                             ("retained_refusal", "sealed_evidence_refused"), label)
            pre = oracle.transition(prepared, {
                "action": "rename", "observation": _patch(self.resolver.observation, changes),
                "outcome": "applied", "replace_if_exists": False, "destination_exists": False})
            self.assertEqual((pre.disposition, pre.reason_code),
                             ("retained_refusal", "pre_rename_observation_refused"), label)
            post = oracle.transition(renamed, {
                "action": "confirm_visible", "observation": _patch(self.resolver.post_observation, changes),
                "destination_name": "generation-1", "root": deepcopy(self.resolver.binding["root"]),
                "closure": deepcopy(self.resolver.binding["closure"])})
            self.assertEqual((post.disposition, post.reason_code),
                             ("recovery_required", "post_rename_observation_refused"), label)

        boundary = deepcopy(self.resolver.evidence)
        boundary_security = boundary["protected_objects"][4]["security"]
        boundary_security["effective_access"][1]["rights"] = ["FILE_DELETE_CHILD"]
        boundary_security["canonical_descriptor_sha256"] = oracle.hashlib.sha256(
            oracle._security_canonical_payload(boundary_security)).hexdigest()
        refused = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": boundary})
        self.assertEqual((refused.disposition, refused.reason_code),
                         ("no_effect_refusal", "profile_evidence_refused"))

    def test_windows_component_rules_reject_reserved_and_ambiguous_names(self) -> None:
        for component in ("NUL.txt", "COM1", "bad.", "bad ", "bad<name", "bad:name", "bad\\name",
                          "C:drive", "control" + chr(1)):
            with self.assertRaises(oracle.EvidenceError, msg=component):
                oracle._validate_component(component)

    def test_unknown_fields_and_invalid_types_are_rejected(self) -> None:
        evidence = deepcopy(self.resolver.evidence)
        evidence["caller_eligible"] = True
        result = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": evidence})
        self.assertEqual(result.disposition, "no_effect_refusal")
        evidence = deepcopy(self.resolver.evidence)
        evidence["closure_entry_count"] = True
        result = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": evidence})
        self.assertEqual(result.disposition, "no_effect_refusal")
        result = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": evidence,
                                                            "eligible": True})
        self.assertEqual(result.disposition, "invalid_trace")

    def test_every_protected_object_identity_must_match_observed_volume(self) -> None:
        evidence = deepcopy(self.resolver.evidence)
        evidence["volume_information_serial"] = "deadbeef"
        result = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": evidence})
        self.assertEqual(result.disposition, "no_effect_refusal")
        for index in range(len(self.resolver.evidence["protected_objects"])):
            evidence = deepcopy(self.resolver.evidence)
            evidence["protected_objects"][index]["file_id"] = \
                "bbbbbbbbbbbbbbbb:" + evidence["protected_objects"][index]["file_id"].split(":", 1)[1]
            result = oracle.transition(oracle.initial_state(), {"action": "admit_profile", "evidence": evidence})
            self.assertEqual(result.disposition, "no_effect_refusal", index)

    def test_replay_stops_at_every_terminal_disposition(self) -> None:
        for case_id in ("unknown-profile-field", "continuation-after-destination-exists",
                        "rename-crash-ambiguity", "protected-success"):
            case = next(item for item in self.fixture["cases"] if item["id"] == case_id)
            events = self.resolver.events(case["events"]) + [{"action": "begin_metadata"}]
            result = oracle.replay(oracle.initial_state(), events)
            self.assertEqual(oracle.projection(result), self.resolver.value(case["expected"]), case_id)

    def test_immutable_types_and_completion_invariants(self) -> None:
        profile = oracle.ProfileEvidence.parse(self.resolver.evidence)
        with self.assertRaises(Exception):
            profile.remote_protocol = 1
        success = next(case for case in self.fixture["cases"] if case["id"] == "protected-success")
        result = oracle.replay(oracle.initial_state(), self.resolver.events(success["events"]))
        second = oracle.transition(result.state, {"action": "complete_metadata", "success": True})
        self.assertEqual(second.disposition, "invalid_trace")
        self.assertEqual(second.reason_code, "terminal_state")

    def test_recovery_does_not_manufacture_profile_or_delete_ambiguous_material(self) -> None:
        unavailable = oracle.initial_state()
        self.assertIsNone(unavailable.profile)
        case = next(item for item in self.fixture["cases"] if item["id"] == "rename-crash-ambiguity")
        result = oracle.replay(unavailable, self.resolver.events(case["events"]))
        self.assertTrue(result.state.retained)
        self.assertEqual(result.state.rename_state, oracle.RenameState.UNKNOWN)
        self.assertEqual(len(result.state.completed_generations), 0)

    def test_retained_legacy_cpp_negative_control_remains_present(self) -> None:
        text = (ROOT / "tests" / "native" / "usk_commit_authority_smoke.cpp").read_text(encoding="utf-8")
        self.assertIn("original_publication_regression", text)
        self.assertIn("commit must not publish or claim ownership", text)


if __name__ == "__main__":
    unittest.main()
