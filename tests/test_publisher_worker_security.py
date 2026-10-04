# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
from copy import deepcopy
import hashlib
import unittest

from publisher_worker_security import (WorkerSecurityError, TOKEN_QUERY_RIGHTS,
    THREAD_QUERY_RIGHTS, DEFAULT_QUERY_RIGHTS, validate_worker_security)
from publisher_execution_evidence import reconcile
from test_publisher_creation_evidence import process_creation_fixture
from test_publisher_execution_evidence import BUILD, SDK, SERVICE, SID, encode

CONSUMER = "S-1-5-21-1-2-3-1000"


def ace(principal, mask):
    return {"type": 0, "flags": 0, "access_mask": mask, "sid": principal}


def security_object(query_rights):
    return {"owner_sid": "S-1-5-18", "dacl_present": True, "dacl_protected": False,
            "dacl_aces": [ace("S-1-5-18", 0x1FFFFF), ace(SID, 0x1FFFFF), ace(CONSUMER, query_rights)]}


def worker_security(service):
    primary = security_object(TOKEN_QUERY_RIGHTS)
    primary.update({key: service[key] for key in ("token_id", "authentication_id", "modified_id")})
    primary.update(default_owner_sid="S-1-5-18", default_dacl_aces=[ace("S-1-5-18", 0x10000000),
        ace(SID, 0x10000000), ace(CONSUMER, DEFAULT_QUERY_RIGHTS)])
    thread = security_object(THREAD_QUERY_RIGHTS)
    thread.update(thread_id=700, creation_time="0000000000000700", thread_impersonating=False)
    return {"schema": "usk.publisher_worker_security.v1",
        "scope": "stored_primary_token_defaults_and_process_thread_owner_dacls",
        "process_id": service["process_id"], "current_thread_id": 700,
        "primary_token": primary, "threads": [thread]}


def security_creation_fixture():
    prepared, visible = process_creation_fixture()
    for row in prepared["execution_phases"] + visible["execution_phases"]:
        execution = row["execution"]
        execution.update(schema="usk.publisher_execution_observation.v3",
            scope="supplied_held_service_handles_and_worker_security",
            worker_security=worker_security(execution["service"]))
    prepared["creation_evidence"].update(schema="usk.publisher.creation_observation.v3",
        scope="successful_service_file_create_calls_and_worker_security_to_bound_graph",
        worker_security=deepcopy(prepared["execution_phases"][0]["execution"]["worker_security"]))
    return prepared, visible


class WorkerSecurityTests(unittest.TestCase):
    def context(self):
        prepared, _ = process_creation_fixture()
        return prepared["execution_phases"][0]["execution"]["service"]

    def check_records(self, prepared, visible):
        visible["prepared_record_sha256"] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        return reconcile(encode(prepared), encode(visible), SERVICE, SID, BUILD, SDK)

    def test_identity_queries_and_excluded_privileged_owners(self):
        service = self.context()
        for owner in ("S-1-5-18", "S-1-5-32-544", SID):
            value = worker_security(service)
            value["primary_token"]["owner_sid"] = owner
            value["primary_token"]["default_owner_sid"] = owner
            value["threads"][0]["owner_sid"] = owner
            self.assertEqual(validate_worker_security(value, service), value)
        service["process_groups"].append({"sid": "S-1-5-5-0-900", "attributes": 0xC0000005})
        value = worker_security(service)
        value["primary_token"]["owner_sid"] = "S-1-5-5-0-900"
        value["threads"][0]["dacl_aces"].append({"type": 1, "flags": 0, "access_mask": 0xFFFFFFFF, "sid": CONSUMER})
        self.assertEqual(validate_worker_security(value, service), value)

    def test_each_outside_non_query_token_default_and_thread_right_refuses(self):
        service = self.context()
        for target, query_rights in (("token", TOKEN_QUERY_RIGHTS), ("default", DEFAULT_QUERY_RIGHTS),
                                    ("thread", THREAD_QUERY_RIGHTS)):
            for bit in range(32):
                if query_rights & (1 << bit):
                    continue
                value = worker_security(service)
                aces = value["threads"][0]["dacl_aces"] if target == "thread" else value["primary_token"][
                    "default_dacl_aces" if target == "default" else "dacl_aces"]
                aces[-1]["access_mask"] |= 1 << bit
                with self.subTest(target=target, bit=bit), self.assertRaises(WorkerSecurityError):
                    validate_worker_security(value, service)

    def test_owner_identity_defaults_and_thread_closure_contradictions_refuse(self):
        service = self.context()
        changes = [lambda x: x.update(process_id=True), lambda x: x.update(current_thread_id=701),
            lambda x: x.update(threads=[]), lambda x: x["threads"].append(deepcopy(x["threads"][0])),
            lambda x: x["threads"][0].update(creation_time="0000000000000000"),
            lambda x: x["threads"][0].update(owner_sid=CONSUMER),
            lambda x: x["threads"][0].update(thread_impersonating=True),
            lambda x: x["threads"][0].update(thread_impersonating=0),
            lambda x: x["primary_token"].update(owner_sid=CONSUMER),
            lambda x: x["primary_token"].update(default_owner_sid=CONSUMER),
            lambda x: x["primary_token"].update(default_dacl_aces=None),
            lambda x: x["primary_token"].update(token_id="0000000000000501"),
            lambda x: x["primary_token"].update(dacl_protected=1),
            lambda x: x["primary_token"]["dacl_aces"][-1].update(flags=16),
            lambda x: x["primary_token"]["dacl_aces"][-1].update(access_mask=True)]
        for index, change in enumerate(changes):
            value = worker_security(service)
            change(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate_worker_security(value, service)

    def test_creation_and_every_native_phase_bind_worker_security(self):
        prepared, visible = security_creation_fixture()
        report = self.check_records(prepared, visible)
        self.assertEqual(report["schema"], "usk.publisher_execution_reconciliation.v4")
        self.assertEqual(report["worker_security_phase_count"], report["phase_count"])
        self.assertEqual(report["process_bound_phase_count"], report["phase_count"])
        self.assertIs(report["creation_observation"]["worker_security_checked"], True)
        self.assertEqual(report["creation_observation"]["schema"], "usk.publisher_creation_reconciliation.v3")
        self.assertIs(report["profile_qualified"], False)

    def test_coherent_visible_changes_and_complete_birth_downgrade_refuse(self):
        for mode in ("token", "thread", "default", "downgrade", "birth_downgrade"):
            prepared, visible = security_creation_fixture()
            if mode == "birth_downgrade":
                prepared["creation_evidence"].update(schema="usk.publisher.creation_observation.v2",
                    scope="successful_service_file_create_calls_and_process_boundary_to_bound_graph")
                prepared["creation_evidence"].pop("worker_security")
            else:
                for row in visible["execution_phases"]:
                    execution = row["execution"]
                    if mode == "downgrade":
                        execution.update(schema="usk.publisher_execution_observation.v2",
                            scope="supplied_held_service_handles_and_process_owner_dacl")
                        execution.pop("worker_security")
                    elif mode == "token":
                        execution["worker_security"]["primary_token"]["dacl_protected"] = True
                    elif mode == "thread":
                        execution["worker_security"]["threads"][0]["dacl_protected"] = True
                    else:
                        execution["worker_security"]["primary_token"]["default_dacl_aces"] = []
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.check_records(prepared, visible)

    def test_restart_binds_new_worker_without_rewriting_original_birth(self):
        prepared, visible = security_creation_fixture()
        visible["execution_transition"] = "observed_visible_on_restart"
        visible["execution_phases"] = visible["execution_phases"][1:]
        execution = visible["execution_phases"][0]["execution"]
        execution["service"].update(process_id=600, token_id=f"{600:016x}", modified_id=f"{601:016x}")
        execution["process_boundary"]["process_id"] = 600
        execution["worker_security"] = worker_security(execution["service"])
        execution["worker_security"]["threads"][0]["dacl_protected"] = True
        report = self.check_records(prepared, visible)
        self.assertEqual(report["worker_process_ids"], [500, 600])
        self.assertEqual(report["creation_observation"]["creator_process_id"], 500)


if __name__ == "__main__":
    unittest.main()
