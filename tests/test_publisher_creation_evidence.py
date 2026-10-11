# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic ABI/graph controls; these do not qualify native creation."""
import copy
import hashlib
import struct
import unittest

from publisher_creation_evidence import CALL_PROFILE, CREATOR_KEYS, canonical_sha, creation_graph
from publisher_execution_evidence import EvidenceError, reconcile
from test_publisher_execution_evidence import BUILD, SDK, SERVICE, SID, encode, fixture


def sid_bytes(text):
    values = text.split("-")
    subauthorities = list(map(int, values[3:]))
    return bytes((1, len(subauthorities))) + int(values[2]).to_bytes(6, "big") + struct.pack(
        "<" + "L" * len(subauthorities), *subauthorities)


def descriptor():
    owner = sid_bytes("S-1-5-18")
    aces = []
    for text in ("S-1-5-18", SID):
        principal = sid_bytes(text)
        aces.append(struct.pack("<BBHL", 0, 0, 8 + len(principal), 0x1F01FF) + principal)
    acl = struct.pack("<BBHHH", 2, 0, 8 + sum(map(len, aces)), 2, 0) + b"".join(aces)
    return struct.pack("<BBHLLLL", 1, 0, 0x9004, 20, 0, 0, 20 + len(owner)) + owner + acl


def creation_fixture():
    prepared, visible = fixture()
    prepared["schema"] = visible["schema"] = "usk.publisher.lab_phase_evidence.v4"
    tree = prepared["sealed_tree"]
    tree["root"]["attributes"] = 0x10
    tree["descendants"][0]["object"] = {"file_id": "0000000000001234:" + "0" * 31 + "8", "attributes": 0x20}
    for row in prepared["execution_phases"] + visible["execution_phases"]:
        native_tree = dict(tree, descendants=[]) if row["execution"]["phase"] == "protected_empty" else tree
        row["tree_sha256"] = canonical_sha(native_tree)
    raw = descriptor()
    graph = creation_graph(prepared["protected_anchors"], tree)
    prepared["creation_evidence"] = {"schema": "usk.publisher.creation_observation.v1",
        "scope": "successful_service_file_create_calls_to_bound_graph",
        "creator": {key: prepared["execution_phases"][0]["execution"]["service"][key] for key in CREATOR_KEYS},
        "native_call": dict(CALL_PROFILE), "handle_flags": 0,
        "volume_boundary_file_id": prepared["protected_anchors"]["boundary"]["file_id"],
        "creation_descriptor_sha256": hashlib.sha256(raw).hexdigest(), "creation_descriptor_hex": raw.hex(),
        "created_object_count": len(graph), "created_graph_sha256": canonical_sha(graph)}
    return prepared, visible


def process_creation_fixture():
    prepared, visible = creation_fixture()
    for row in prepared["execution_phases"] + visible["execution_phases"]:
        execution = row["execution"]
        execution["schema"] = "usk.publisher_execution_observation.v2"
        execution["scope"] = "supplied_held_service_handles_and_process_owner_dacl"
        execution["process_boundary"] = {"schema": "usk.publisher_process_boundary.v1",
            "scope": "stored_current_process_owner_dacl", "process_id": execution["service"]["process_id"],
            "owner_sid": "S-1-5-18", "dacl_present": True, "dacl_protected": False,
            "dacl_aces": [{"type": 0, "flags": 0, "access_mask": 0x1FFFFF, "sid": "S-1-5-18"},
                          {"type": 0, "flags": 0, "access_mask": 0x1FFFFF, "sid": SID},
                          {"type": 0, "flags": 0, "access_mask": 0x101000, "sid": "S-1-5-21-1-2-3-1000"}]}
    prepared["creation_evidence"].update(schema="usk.publisher.creation_observation.v2",
        scope="successful_service_file_create_calls_and_process_boundary_to_bound_graph",
        process_boundary=copy.deepcopy(prepared["execution_phases"][0]["execution"]["process_boundary"]))
    return prepared, visible


class CreationEvidenceTests(unittest.TestCase):
    def check(self, prepared, visible):
        if visible is not None:
            visible["prepared_record_sha256"] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        return reconcile(encode(prepared), None if visible is None else encode(visible), SERVICE, SID, BUILD, SDK)

    def test_created_graph_and_descriptor_binding(self):
        prepared, visible = creation_fixture()
        report = self.check(prepared, visible)
        self.assertEqual(report["schema"], "usk.publisher_execution_reconciliation.v2")
        self.assertEqual(report["creation_observation"]["created_object_count"], 7)
        self.assertEqual(report["creation_observation"]["creator_process_id"], 500)
        self.assertIs(report["creation_observation"]["profile_qualified"], False)
        self.assertIs(report["profile_qualified"], False)
        self.assertEqual(self.check(prepared, None)["visible_transition"], "visible_record_absent")

    def test_restart_keeps_original_creator(self):
        prepared, visible = creation_fixture()
        visible["execution_transition"] = "observed_visible_on_restart"
        visible["execution_phases"] = visible["execution_phases"][1:]
        visible["execution_phases"][0]["execution"]["service"].update(
            process_id=600, token_id=f"{600:016x}", modified_id=f"{601:016x}")
        report = self.check(prepared, visible)
        self.assertEqual(report["worker_process_ids"], [500, 600])
        self.assertEqual(report["creation_observation"]["creator_process_id"], 500)

    def test_process_bound_creation_and_each_phase(self):
        prepared, visible = process_creation_fixture()
        report = self.check(prepared, visible)
        self.assertEqual(report["schema"], "usk.publisher_execution_reconciliation.v3")
        self.assertEqual(report["process_bound_phase_count"], report["phase_count"])
        self.assertEqual(report["creation_observation"]["schema"], "usk.publisher_creation_reconciliation.v2")
        self.assertIs(report["creation_observation"]["process_boundary_checked"], True)
        self.assertIs(report["profile_qualified"], False)
        self.assertIs(report["creation_observation"]["profile_qualified"], False)

    def test_process_boundary_restart_does_not_rewrite_original_birth(self):
        prepared, visible = process_creation_fixture()
        visible["execution_transition"] = "observed_visible_on_restart"
        visible["execution_phases"] = visible["execution_phases"][1:]
        later = visible["execution_phases"][0]["execution"]
        later["service"].update(process_id=600, token_id=f"{600:016x}", modified_id=f"{601:016x}")
        later["process_boundary"]["process_id"] = 600
        original = copy.deepcopy(prepared["creation_evidence"])
        report = self.check(prepared, visible)
        self.assertEqual(report["worker_process_ids"], [500, 600])
        self.assertEqual(report["process_bound_phase_count"], 4)
        self.assertEqual(report["creation_observation"]["creator_process_id"], 500)
        self.assertEqual(prepared["creation_evidence"], original)

    def test_process_boundary_downgrade_change_and_outside_grants_refuse(self):
        def downgrade(prepared, visible):
            for row in prepared["execution_phases"] + visible["execution_phases"]:
                row["execution"].update(schema="usk.publisher_execution_observation.v1",
                                        scope="supplied_held_service_handles")
                row["execution"].pop("process_boundary")
        def downgrade_visible(prepared, visible):
            for row in visible["execution_phases"]:
                row["execution"].update(schema="usk.publisher_execution_observation.v1",
                                        scope="supplied_held_service_handles")
                row["execution"].pop("process_boundary")
        def change_visible(prepared, visible):
            for row in visible["execution_phases"]:
                row["execution"]["process_boundary"]["dacl_protected"] = True
        def downgrade_certificate(prepared, visible):
            prepared["creation_evidence"].update(schema="usk.publisher.creation_observation.v1",
                scope="successful_service_file_create_calls_to_bound_graph")
            prepared["creation_evidence"].pop("process_boundary")
        controls = {
            "wrong birth process": lambda p, v: p["creation_evidence"]["process_boundary"].update(process_id=501),
            "outside process duplicate": lambda p, v: p["execution_phases"][0]["execution"]["process_boundary"]["dacl_aces"][-1].update(access_mask=0x40),
            "changed valid DACL": lambda p, v: p["execution_phases"][1]["execution"]["process_boundary"].update(dacl_protected=True),
            "unknown phase scope": lambda p, v: p["execution_phases"][0]["execution"].update(scope="all_capabilities_excluded"),
            "phase downgrade": downgrade,
            "visible pair downgrade": downgrade_visible,
            "visible pair changed boundary": change_visible,
            "complete certificate downgrade": downgrade_certificate,
            "legacy certificate with process field": lambda p, v: p["creation_evidence"].update(
                schema="usk.publisher.creation_observation.v1", scope="successful_service_file_create_calls_to_bound_graph"),
            "unknown process owner": lambda p, v: p["execution_phases"][0]["execution"]["process_boundary"].update(owner_sid="S-1-5-21-1-2-3-1000"),
        }
        for name, change in controls.items():
            prepared, visible = process_creation_fixture()
            change(prepared, visible)
            with self.subTest(name=name), self.assertRaises((EvidenceError, ValueError, KeyError, TypeError)):
                self.check(prepared, visible)

    def test_separate_restart_worker_can_rename_with_its_own_process_boundary(self):
        prepared, visible = process_creation_fixture()
        for row in visible["execution_phases"]:
            row["execution"]["service"].update(process_id=600, token_id=f"{600:016x}", modified_id=f"{601:016x}")
            row["execution"]["process_boundary"].update(process_id=600, dacl_protected=True)
        report = self.check(prepared, visible)
        self.assertEqual(report["worker_process_ids"], [500, 600])
        self.assertEqual(report["process_bound_phase_count"], 5)
        self.assertEqual(report["creation_observation"]["creator_process_id"], 500)

    def test_missing_or_contradictory_creation_refuses(self):
        def field(key, value):
            return lambda p, v: p["creation_evidence"].update({key: value})
        controls = {
            "missing birth": lambda p, v: p.pop("creation_evidence"),
            "extra birth field": lambda p, v: p["creation_evidence"].update(extra=True),
            "unknown scope": field("scope", "all_handles_ever"),
            "wrong birth boundary": field("volume_boundary_file_id", "0" * 49),
            "inheritable birth": field("handle_flags", 1),
            "boolean birth flags": field("handle_flags", False),
            "graph digest differs": field("created_graph_sha256", "a" * 64),
            "graph count differs": field("created_object_count", 8),
            "boolean graph count": field("created_object_count", True),
            "descriptor digest differs": field("creation_descriptor_sha256", "b" * 64),
            "truncated descriptor": field("creation_descriptor_hex", "00" * 20),
            "noncanonical descriptor hex": field("creation_descriptor_hex", descriptor().hex().upper()),
            "extra descriptor bytes": field("creation_descriptor_hex", descriptor().hex() + "00"),
            "wrong creator token": lambda p, v: p["creation_evidence"]["creator"].update(token_id="a" * 16),
            "false creator type": lambda p, v: p["creation_evidence"]["creator"].update(token_type=True),
            "open-existing disposition": lambda p, v: p["creation_evidence"]["native_call"].update(create_disposition=1),
            "opened-existing result": lambda p, v: p["creation_evidence"]["native_call"].update(creation_result=1),
            "wrong NTSTATUS": lambda p, v: p["creation_evidence"]["native_call"].update(ntstatus=1),
            "boolean NTSTATUS": lambda p, v: p["creation_evidence"]["native_call"].update(ntstatus=False),
            "inheritable object attributes": lambda p, v: p["creation_evidence"]["native_call"].update(object_attribute_flags=0x42),
            "wrong regular-file options": lambda p, v: p["creation_evidence"]["native_call"].update(file_create_options=0x00200021),
            "legacy claiming birth": lambda p, v: p.update(schema="usk.publisher.lab_phase_evidence.v3"),
            "reopened claiming birth": lambda p, v: (p.update(execution_origin="reopened_staged_tree"), p["execution_phases"].pop(0)),
            "visible version differs": lambda p, v: v.update(schema="usk.publisher.lab_phase_evidence.v3"),
        }
        for label, mutate in controls.items():
            with self.subTest(label=label):
                prepared, visible = copy.deepcopy(creation_fixture())
                mutate(prepared, visible)
                with self.assertRaises((EvidenceError, KeyError, TypeError)):
                    self.check(prepared, visible)

    def test_descriptor_abi_offsets_owner_ace_and_flags_refuse(self):
        mutations = ((2, 0x00), (4, 0), (12, 20), (32, 4), (36, 1), (41, 1), (44, 0), (52, 1))
        for offset, byte in mutations:
            with self.subTest(offset=offset):
                prepared, visible = creation_fixture()
                raw = bytearray(descriptor())
                raw[offset] = byte
                prepared["creation_evidence"].update(creation_descriptor_hex=raw.hex(),
                    creation_descriptor_sha256=hashlib.sha256(raw).hexdigest())
                with self.assertRaises(EvidenceError):
                    self.check(prepared, visible)


if __name__ == "__main__":
    unittest.main()
