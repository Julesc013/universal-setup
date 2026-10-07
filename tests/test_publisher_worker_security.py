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



def retirement_security(baseline, retired_ids=()):
    original = deepcopy(baseline)
    result = deepcopy(original)
    result.update(schema="usk.publisher_worker_security.v2",
        scope="original_pinned_token_defaults_and_native_thread_retirement_partition",
        original_baseline=original, retired_threads=[])
    result["threads"] = [thread for thread in result["threads"] if thread["thread_id"] not in retired_ids]
    for thread in original["threads"]:
        if thread["thread_id"] in retired_ids:
            result["retired_threads"].append({"thread_id": thread["thread_id"],
                "creation_time": thread["creation_time"], "exit_time": f'{thread["thread_id"] + 256:016x}'})
    return result


def retirement_fixture():
    # Constructed native-record data, never an actual restricted child launch.
    from test_publisher_effect_broker_evidence import effect_fixture
    prepared, visible = effect_fixture()
    prepared["schema"] = visible["schema"] = "usk.publisher.lab_phase_evidence.v11"
    baseline = deepcopy(prepared["execution_phases"][0]["execution"]["worker_security"])
    for identity in (701, 702):
        thread = deepcopy(baseline["threads"][0])
        thread.update(thread_id=identity, creation_time=f"{identity:016x}")
        baseline["threads"].append(thread)
    retirements = ((), (701,), (701, 702), (701, 702), (701, 702))
    for phase, retired in zip(prepared["execution_phases"] + visible["execution_phases"], retirements):
        phase["execution"].update(schema="usk.publisher_execution_observation.v8",
            scope="supplied_held_child_handles_authenticated_broker_access_and_native_retirement_partition",
            worker_security=retirement_security(baseline, retired))
    prepared["creation_evidence"].update(schema="usk.publisher.creation_observation.v5",
        scope="successful_child_file_create_calls_and_original_native_retirement_partition_to_bound_graph",
        worker_security=retirement_security(baseline),
        completed_worker_security=retirement_security(baseline, (701,)))
    return prepared, visible


class NativeRetirementEvidenceTests(unittest.TestCase):
    def context(self, execution):
        from publisher_effect_broker_evidence import worker_security_context
        return worker_security_context(execution["effect_worker"]["process_id"], SID,
                                       execution["effect_worker"]["primary_token"])

    def check_records(self, prepared, visible):
        visible["prepared_record_sha256"] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        return reconcile(encode(prepared), encode(visible), SERVICE, SID, BUILD, SDK)

    def test_full_original_partition_and_monotonic_creation_publication_join(self):
        prepared, visible = retirement_fixture()
        report = self.check_records(prepared, visible)
        self.assertEqual(report["effect_worker_phase_count"], 5)
        self.assertEqual(report["creation_observation"]["schema"], "usk.publisher_creation_reconciliation.v5")
        self.assertFalse(report["profile_qualified"])
        original = prepared["creation_evidence"]["worker_security"]
        self.assertEqual(len(original["original_baseline"]["threads"]), 3)
        self.assertEqual(len(visible["execution_phases"][-1]["execution"]["worker_security"]["retired_threads"]), 2)

    def test_missing_forged_or_contradictory_retirement_never_substitutes_for_native_proof(self):
        prepared, _ = retirement_fixture()
        execution = prepared["execution_phases"][1]["execution"]
        context = self.context(execution)
        proof = execution["worker_security"]
        def alter(field, value):
            return lambda changed: changed.__setitem__(field, value)
        changes = [
            lambda v: v.pop("original_baseline"),
            lambda v: v.pop("retired_threads"),
            alter("retired_threads", []),
            lambda v: v["retired_threads"].append(deepcopy(v["retired_threads"][0])),
            lambda v: v["retired_threads"][0].__setitem__("thread_id", True),
            lambda v: v["retired_threads"][0].__setitem__("thread_id", 999),
            lambda v: v["retired_threads"][0].__setitem__("creation_time", "0000000000000001"),
            lambda v: v["retired_threads"][0].__setitem__("exit_time", "0000000000000000"),
            lambda v: v["retired_threads"][0].__setitem__("exit_time", "0000000000000001"),
            lambda v: v["retired_threads"][0].__setitem__("exit_time", "A"*16),
            lambda v: v["retired_threads"][0].__setitem__("authority", "granted"),
            lambda v: v["threads"][0].__setitem__("owner_sid", "S-1-5-32-544"),
            lambda v: v["threads"][0].__setitem__("thread_impersonating", True),
            lambda v: v["original_baseline"].__setitem__("schema", "usk.publisher_worker_security.v2"),
            lambda v: v["original_baseline"]["threads"].pop(),
            lambda v: v["threads"].append(deepcopy(v["original_baseline"]["threads"][1])),
            lambda v: v.__setitem__("threads", v["threads"][1:]),
        ]
        for index, change in enumerate(changes):
            changed = deepcopy(proof)
            change(changed)
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError, TypeError)):
                validate_worker_security(changed, context)

    def test_valid_current_snapshots_cannot_revive_or_rewrite_original_exit_or_baseline(self):
        from publisher_worker_security import validate_worker_continuity
        prepared, _ = retirement_fixture()
        baseline = prepared["execution_phases"][0]["execution"]["worker_security"]["original_baseline"]
        earlier = retirement_security(baseline, (701,))
        later = retirement_security(baseline, (701, 702))
        context = self.context(prepared["execution_phases"][0]["execution"])
        validate_worker_continuity(earlier, later)
        revived = retirement_security(baseline)
        changed_exit = deepcopy(later)
        changed_exit["retired_threads"][0]["exit_time"] = "0000000000009999"
        changed_baseline = deepcopy(later)
        changed_baseline["original_baseline"]["threads"][1]["dacl_protected"] = True
        for invalid in (revived, changed_exit, changed_baseline):
            validate_worker_security(invalid, context)
            with self.assertRaises(ValueError):
                validate_worker_continuity(earlier, invalid)

    def test_certificate_and_phase_cannot_drop_or_downgrade_retirement_family(self):
        for mode in ("old_phase", "old_execution", "old_creation", "old_worker",
                     "missing_completion", "completion_ahead", "changed_exit"):
            prepared, visible = retirement_fixture()
            if mode == "old_phase":
                prepared["schema"] = visible["schema"] = "usk.publisher.lab_phase_evidence.v10"
            elif mode == "old_execution":
                prepared["execution_phases"][0]["execution"]["schema"] = "usk.publisher_execution_observation.v7"
            elif mode == "old_creation":
                prepared["creation_evidence"]["schema"] = "usk.publisher.creation_observation.v4"
            elif mode == "old_worker":
                proof = prepared["execution_phases"][1]["execution"]["worker_security"]
                prepared["execution_phases"][1]["execution"]["worker_security"] = deepcopy(proof["original_baseline"])
            elif mode == "missing_completion":
                prepared["creation_evidence"].pop("completed_worker_security")
            elif mode == "completion_ahead":
                prepared["creation_evidence"]["completed_worker_security"] = deepcopy(prepared["execution_phases"][-1]["execution"]["worker_security"])
                prepared["execution_phases"][-1]["execution"]["worker_security"] = deepcopy(
                    prepared["execution_phases"][1]["execution"]["worker_security"])
            else:
                visible["execution_phases"][0]["execution"]["worker_security"]["retired_threads"][0]["exit_time"] = "0000000000009999"
            with self.subTest(mode=mode), self.assertRaises((ValueError, KeyError, TypeError)):
                self.check_records(prepared, visible)

    def test_legacy_child_floors_keep_complete_security_equality(self):
        from test_publisher_effect_broker_evidence import effect_fixture
        prepared, visible = effect_fixture()
        execution = visible["execution_phases"][-1]["execution"]
        execution["worker_security"] = retirement_security(execution["worker_security"])
        with self.assertRaises(ValueError):
            self.check_records(prepared, visible)

if __name__ == "__main__":
    unittest.main()
