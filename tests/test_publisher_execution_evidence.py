# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic closed-record controls; these do not qualify Windows execution."""
import copy
import hashlib
import json
import unittest

from publisher_execution_evidence import EvidenceError, ROLES, SCHEMA, canonical_sha, reconcile

SERVICE = "USK_PUB_" + "a" * 32
SID = "S-1-5-80-1-2-3-4-5"
BUILD = 20348
SDK = "10.0.26100.0"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def fixture():
    ids = ["0000000000001234:" + f"{x:032x}" for x in range(1, 8)]
    anchors = {"boundary": {"file_id": ids[0]},
        "chain": [{"component": "publication", "object": {"file_id": ids[1]}}],
        **{key: {"file_id": value} for key, value in zip(
            ("staging", "destination_parent", "state", "journal"), ids[2:6])}}
    tree = {"root": {"file_id": ids[6]}, "descendants": [{"relative_path": "payload.bin"}]}
    def phase(name, native_tree, pid=500):
        return {"protected_anchors_sha256": canonical_sha(anchors), "tree_sha256": canonical_sha(native_tree),
            "execution": {"schema": "usk.publisher_execution_observation.v1",
                "scope": "supplied_held_service_handles", "phase": name,
                "platform": {"os_family": "Windows NT", "native_arch": "x64", "process_arch": "x64",
                    "major_version": 10, "minor_version": 0, "windows_build": BUILD,
                    "minimum_windows_build": 17763, "sdk_version": SDK},
                "service": {"service_name": SERVICE, "service_sid": SID, "service_sid_type": 3,
                    "service_type": 16, "service_state": 4, "process_id": pid,
                    "process_user_sid": "S-1-5-18", "thread_impersonating": False,
                    "process_groups": [{"sid": SID, "attributes": 4}],
                    "process_restricted_sids": [{"sid": SID, "attributes": 0}],
                    "token_id": f"{pid:016x}", "authentication_id": "00000000000003e7",
                    "modified_id": f"{pid + 1:016x}", "token_type": 1},
                "handles": [{"role": role, "file_id": identity, "handle_flags": 0}
                            for role, identity in zip(ROLES, ids)]}}
    prepared = {"schema": SCHEMA, "phase": "lab_prepared_evidence", "service_sid": SID,
        "volume_serial": 0x1234, "source_file_id": ids[6], "destination_parent_file_id": ids[3],
        "destination_name": "visible", "selected_file_set_digest": "c" * 64, "source_binding": {},
        "protected_anchors": anchors, "sealed_tree": tree,
        "execution_origin": "created_empty_in_current_worker",
        "execution_phases": [phase("protected_empty", dict(tree, descendants=[])),
                             phase("sealed", tree), phase("publish_prepared", tree)]}
    visible = {"schema": SCHEMA, "phase": "lab_visible_evidence", "source_file_id": ids[6],
        "destination_parent_file_id": ids[3], "destination_name": "visible", "selected_file_set_digest": "c" * 64,
        "prepared_record_sha256": hashlib.sha256(encode(prepared).encode()).hexdigest(),
        "protected_anchors": anchors, "visible_tree": tree, "execution_transition": "renamed_by_current_worker",
        "execution_phases": [phase("before_rename", tree), phase("visible_bound", tree)]}
    return prepared, visible


class ExecutionEvidenceTests(unittest.TestCase):
    def check(self, prepared, visible):
        if visible is not None:
            visible["prepared_record_sha256"] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        return reconcile(encode(prepared), None if visible is None else encode(visible), SERVICE, SID, BUILD, SDK)

    def test_normal_native_record_bindings(self):
        p, v = fixture()
        report = self.check(p, v)
        self.assertEqual(report["phase_count"], 5)
        self.assertEqual(report["worker_process_ids"], [500])
        self.assertIs(report["profile_qualified"], False)

    def test_restart_has_new_worker_without_earlier_rename_claim(self):
        p, v = fixture()
        v["execution_transition"] = "observed_visible_on_restart"
        v["execution_phases"] = v["execution_phases"][1:]
        s = v["execution_phases"][0]["execution"]["service"]
        s.update(process_id=600, token_id=f"{600:016x}", modified_id=f"{601:016x}")
        report = self.check(p, v)
        self.assertEqual(report["phase_count"], 4)
        self.assertEqual(report["worker_process_ids"], [500, 600])

    def test_reopened_stage_does_not_claim_empty_creation(self):
        p, v = fixture()
        p["execution_origin"] = "reopened_staged_tree"
        p["execution_phases"] = p["execution_phases"][1:]
        self.assertEqual(self.check(p, v)["phase_count"], 4)
        self.assertEqual(self.check(p, None)["visible_transition"], "visible_record_absent")

    def test_contradictory_and_missing_bindings_refuse(self):
        def mutate(path, value):
            def apply(p, v):
                target = p
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return apply
        execution = ("execution_phases", 1, "execution")
        controls = {
            "unknown origin": mutate(("execution_origin",), "inherited"),
            "phase missing": lambda p, v: p["execution_phases"].pop(),
            "wrong phase": mutate(execution + ("phase",), "before_rename"),
            "bad canonical tree binding": mutate(("execution_phases", 1, "tree_sha256"), "e" * 64),
            "missing boundary role": lambda p, v: p["execution_phases"][1]["execution"]["handles"].pop(0),
            "inheritable handle": mutate(execution + ("handles", 0, "handle_flags"), 1),
            "boolean flags": mutate(execution + ("handles", 0, "handle_flags"), False),
            "wrong object ID": mutate(execution + ("handles", 6, "file_id"), "0" * 49),
            "different SDK": mutate(execution + ("platform", "sdk_version"), "10.0.17763.0"),
            "different native build": mutate(execution + ("platform", "windows_build"), 17763),
            "wrong process architecture": mutate(execution + ("platform", "process_arch"), "x86"),
            "impersonating thread": mutate(execution + ("service", "thread_impersonating"), True),
            "nonprimary token": mutate(execution + ("service", "token_type"), 2),
            "zero token ID": mutate(execution + ("service", "token_id"), "0" * 16),
            "phase token changes": mutate(execution + ("service", "modified_id"), "a" * 16),
            "empty other group SID": lambda p, v: p["execution_phases"][1]["execution"]["service"]["process_groups"].append({"sid": "", "attributes": 0}),
            "noncanonical other SID": lambda p, v: p["execution_phases"][1]["execution"]["service"]["process_groups"].append({"sid": "S-1-05-32-545", "attributes": 0}),
            "duplicate service group": lambda p, v: p["execution_phases"][1]["execution"]["service"]["process_groups"].append({"sid": SID, "attributes": 4}),
            "missing restricted SID": mutate(execution + ("service", "process_restricted_sids"), []),
            "unknown field": lambda p, v: p["execution_phases"][1]["execution"].update(extra=True),
            "false restart claim": lambda p, v: v.update(execution_transition="observed_visible_on_restart"),
            "missing rename observation": lambda p, v: v["execution_phases"].pop(0),
        }
        for label, control in controls.items():
            with self.subTest(label=label):
                p, v = copy.deepcopy(fixture())
                control(p, v)
                with self.assertRaises((EvidenceError, KeyError, TypeError)):
                    self.check(p, v)

    def test_exact_prepared_bytes_and_duplicate_keys(self):
        p, v = fixture()
        with self.assertRaises(EvidenceError):
            reconcile(encode(p) + "\n", encode(v), SERVICE, SID, BUILD, SDK)
        with self.assertRaises(EvidenceError):
            reconcile(encode(p).replace('{', '{"phase":"other",', 1), None, SERVICE, SID, BUILD, SDK)


if __name__ == "__main__":
    unittest.main()
