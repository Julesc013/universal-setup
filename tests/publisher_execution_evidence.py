# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Read-only reconciliation of retained native execution records.

These records cover supplied service handles. V4 binds retained native
successful-create observations to the sealed graph; V5 also retains successful
rename-call arguments/outcomes. Restart visibility keeps an unobserved call null.
These observations do not establish
global capabilities, absent creation history, an atomic snapshot or complete
publication qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Any

PREPARED_KEYS = frozenset({"schema", "phase", "service_sid", "volume_serial", "source_file_id",
    "destination_parent_file_id", "destination_name", "selected_file_set_digest", "source_binding",
    "protected_anchors", "sealed_tree", "execution_phases", "execution_origin"})
VISIBLE_KEYS = frozenset({"schema", "phase", "source_file_id", "destination_parent_file_id",
    "destination_name", "selected_file_set_digest", "prepared_record_sha256", "protected_anchors",
    "visible_tree", "execution_phases", "execution_transition"})
PLATFORM_KEYS = frozenset({"os_family", "native_arch", "process_arch", "major_version", "minor_version",
    "windows_build", "minimum_windows_build", "sdk_version"})
SERVICE_KEYS = frozenset({"service_name", "service_sid", "service_sid_type", "service_type", "service_state",
    "process_id", "process_user_sid", "thread_impersonating", "process_groups", "process_restricted_sids",
    "token_id", "authentication_id", "modified_id", "token_type"})
ROLES = ("volume_root", "publication_root", "staging_anchor", "destination_parent", "state_anchor",
         "journal_anchor", "payload_root")
SCHEMA = "usk.publisher.lab_phase_evidence.v3"
RENAME_SCHEMA = "usk.publisher.lab_phase_evidence.v5"
RIGHTS_SCHEMA = "usk.publisher.lab_phase_evidence.v6"
METADATA_SCHEMA = "usk.publisher.lab_phase_evidence.v7"
AUTHENTICATED_SCHEMA = "usk.publisher.lab_phase_evidence.v8"
DESCENDANT_SCHEMA = "usk.publisher.lab_phase_evidence.v9"
EFFECT_SCHEMA = "usk.publisher.lab_phase_evidence.v10"
RETIREMENT_SCHEMA = "usk.publisher.lab_phase_evidence.v11"
RENAME_KEYS = frozenset({"schema", "api", "source_file_id", "destination_parent_file_id", "destination_component",
    "former_name", "visible_name", "destination_absence_status", "information_class", "information_bytes",
    "file_name_bytes", "replace_if_exists", "native_status", "io_status", "clock", "start_tick", "end_tick", "frequency",
    "source_granted_access", "destination_parent_granted_access", "handle_access_api"})


class EvidenceError(ValueError):
    pass


def require(condition: bool, diagnostic: str) -> None:
    if not condition:
        raise EvidenceError(diagnostic)


def closed(value: Any, keys: frozenset[str], diagnostic: str) -> None:
    require(isinstance(value, dict) and value.keys() == keys, diagnostic)


def canonical_sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def sid(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 184 or not re.fullmatch(
            r"S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}", value):
        return False
    components = list(map(int, value.split("-")[2:]))
    return components[0] <= 0xFFFFFFFFFFFF and all(x <= 0xFFFFFFFF for x in components[1:])


def integer(value: Any, minimum: int = 0, maximum: int = 0xFFFFFFFF) -> bool:
    return type(value) is int and minimum <= value <= maximum


def validate_rename_call(call: Any, prepared: dict, visible: dict) -> None:
    rights_bound = isinstance(call, dict) and call.get('schema') == 'usk.publisher_bound_rename_call.v2'
    closed(call, RENAME_KEYS if rights_bound else RENAME_KEYS -
           {'source_granted_access', 'destination_parent_granted_access', 'handle_access_api'},
           "native rename call keys differ")
    require(isinstance(prepared["destination_name"], str) and all(isinstance(call[key], str) for key in
        ("schema", "api", "source_file_id", "destination_parent_file_id", "destination_component", "former_name", "visible_name", "clock")),
        "native rename text facts differ")
    name_bytes = len(prepared["destination_name"].encode("utf-16-le"))
    require(call["schema"] in ("usk.publisher_bound_rename_call.v1", "usk.publisher_bound_rename_call.v2") and
        (prepared['schema'] not in (RIGHTS_SCHEMA, METADATA_SCHEMA, AUTHENTICATED_SCHEMA, DESCENDANT_SCHEMA, EFFECT_SCHEMA, RETIREMENT_SCHEMA) or rights_bound) and call["api"] == "NtSetInformationFile" and
        (not rights_bound or (call["handle_access_api"] == "NtQueryObject:ObjectBasicInformation" and
        integer(call["source_granted_access"]) and call["source_granted_access"] & 0x10000 and
        integer(call["destination_parent_granted_access"]) and call["destination_parent_granted_access"] & 4)) and
        call["source_file_id"] == prepared["source_file_id"] and
        call["destination_parent_file_id"] == prepared["destination_parent_file_id"] and
        call["destination_component"] == prepared["destination_name"] and
        call["former_name"] == prepared["sealed_tree"]["root"]["native_name"] and
        call["visible_name"] == visible["visible_tree"]["root"]["native_name"], "native rename object/name binding differs")
    # The admitted x64 FILE_RENAME_INFO ABI has a 24-byte sizeof, including
    # its first WCHAR. The producer passes that structure plus the name bytes.
    expected = {"destination_absence_status": 0xc0000034, "information_class": 10,
        "information_bytes": 24 + name_bytes, "file_name_bytes": name_bytes, "native_status": 0, "io_status": 0}
    require(all(integer(call[key]) and call[key] == value for key, value in expected.items()) and
        call["replace_if_exists"] is False and call["clock"] == "qpc" and
        all(integer(call[key], 1, 0x7fffffffffffffff) for key in ("start_tick", "end_tick", "frequency")) and
        call["end_tick"] >= call["start_tick"], "native rename arguments/outcome/clock differs")


def object_bindings(anchors: dict, tree: dict) -> tuple[str, ...]:
    require(len(anchors["chain"]) == 1 and anchors["chain"][0]["component"] == "publication",
            "native direct publication chain differs")
    return (anchors["boundary"]["file_id"], anchors["chain"][0]["object"]["file_id"],
            anchors["staging"]["file_id"], anchors["destination_parent"]["file_id"],
            anchors["state"]["file_id"], anchors["journal"]["file_id"], tree["root"]["file_id"])


def validate_phase(value: dict, phase: str, anchors: dict, tree: dict, service_name: str,
                   service_sid: str, windows_build: int, sdk_version: str,
                   descendants_bound: bool = False) -> dict:
    closed(value, frozenset({"execution", "protected_anchors_sha256", "tree_sha256"}) |
           ({'authenticated_descendants'} if descendants_bound else set()),
           "native phase binding keys differ")
    require(value["protected_anchors_sha256"] == canonical_sha(anchors) and
            value["tree_sha256"] == canonical_sha(tree), "native phase canonical binding differs")
    execution = value["execution"]
    effect_bound = isinstance(execution, dict) and execution.get("schema") in ("usk.publisher_execution_observation.v7", "usk.publisher_execution_observation.v8")
    authenticated_bound = effect_bound or isinstance(execution, dict) and execution.get("schema") == "usk.publisher_execution_observation.v6"
    metadata_bound = authenticated_bound or isinstance(execution, dict) and execution.get("schema") == "usk.publisher_execution_observation.v5"
    rights_bound = metadata_bound or isinstance(execution, dict) and execution.get("schema") == "usk.publisher_execution_observation.v4"
    worker_bound = rights_bound or isinstance(execution, dict) and execution.get("schema") == "usk.publisher_execution_observation.v3"
    process_bound = worker_bound or isinstance(execution, dict) and execution.get("schema") == "usk.publisher_execution_observation.v2"
    closed(execution, frozenset({"schema", "scope", "phase", "platform", "service", "handles"}) |
           (frozenset({"process_boundary"}) if process_bound else frozenset()) |
           (frozenset({"worker_security"}) if worker_bound else frozenset()) |
           (frozenset({"authenticated_client"}) if authenticated_bound else frozenset()) |
           (frozenset({"effect_worker", "broker_readback"}) if effect_bound else frozenset()),
           "execution observation keys differ")
    require(execution["schema"] in ("usk.publisher_execution_observation.v1", "usk.publisher_execution_observation.v2",
            "usk.publisher_execution_observation.v3", "usk.publisher_execution_observation.v4", "usk.publisher_execution_observation.v5", "usk.publisher_execution_observation.v6", "usk.publisher_execution_observation.v7", "usk.publisher_execution_observation.v8") and
            execution["scope"] == ("supplied_held_child_handles_authenticated_broker_access_and_native_retirement_partition" if execution["schema"] == "usk.publisher_execution_observation.v8" else
                                   "supplied_held_child_handles_authenticated_broker_access_and_pinned_worker_security" if effect_bound else
                                   "supplied_held_service_handles_authenticated_access_and_worker_security" if authenticated_bound else
                                   "supplied_held_service_handles_security_access_and_worker_security" if metadata_bound else
                                   "supplied_held_service_handles_granted_access_and_worker_security" if rights_bound else
                                   "supplied_held_service_handles_and_worker_security" if worker_bound else
                                   "supplied_held_service_handles_and_process_owner_dacl" if process_bound else
                                   "supplied_held_service_handles") and execution["phase"] == phase,
            "execution phase identity or scope differs")
    platform = execution["platform"]
    closed(platform, PLATFORM_KEYS, "runtime platform keys differ")
    require(platform == {"os_family": "Windows NT", "native_arch": "x64", "process_arch": "x64",
            "major_version": 10, "minor_version": 0, "windows_build": windows_build,
            "minimum_windows_build": 17763, "sdk_version": sdk_version} and
            all(integer(platform[key]) for key in ("major_version", "minor_version", "windows_build",
                                                   "minimum_windows_build")),
            "runtime platform differs from independently bound build/runtime context")
    if effect_bound:
        from publisher_effect_broker_evidence import validate_effect_execution_identity
        context = validate_effect_execution_identity(execution, service_name, service_sid,
                                                    anchors['boundary'])
        from publisher_process_boundary import validate_process_boundary
        from publisher_worker_security import validate_worker_security
        validate_process_boundary(execution['process_boundary'], context['process_id'], service_sid,
                                  context['process_groups'])
        require(execution['worker_security']['schema'] == ('usk.publisher_worker_security.v2' if execution['schema'] == 'usk.publisher_execution_observation.v8' else 'usk.publisher_worker_security.v1'),
                'execution reinterpreted worker-security provenance')
        validate_worker_security(execution['worker_security'], context)
    else:
        service = execution["service"]
        closed(service, SERVICE_KEYS, "service observation keys differ")
        require(service["service_name"] == service_name and service["service_sid"] == service_sid and
                service["process_user_sid"] == "S-1-5-18" and service["thread_impersonating"] is False and
                service["service_sid_type"] == 3 and service["service_type"] == 16 and
                service["service_state"] == 4 and service["token_type"] == 1 and
                integer(service["process_id"], 1) and
                all(integer(service[key]) for key in ("service_sid_type", "service_type", "service_state", "token_type")),
                "restricted service or primary token binding differs")
        for key in ("token_id", "authentication_id", "modified_id"):
            require(isinstance(service[key], str) and re.fullmatch(r"[0-9a-f]{16}", service[key]) is not None and
                    service[key] != "0000000000000000", "token statistics identity differs")
        for key in ("process_groups", "process_restricted_sids"):
            groups = service[key]
            require(isinstance(groups, list) and 0 < len(groups) <= 4096, "token group closure bound differs")
            seen = set()
            for group in groups:
                closed(group, frozenset({"sid", "attributes"}), "token group keys differ")
                require(sid(group["sid"]) and group["sid"] not in seen and integer(group["attributes"]),
                        "token group SID, attributes or uniqueness differs")
                seen.add(group["sid"])
            selected = [group for group in groups if group["sid"] == service_sid]
            require(len(selected) == 1 and (key != "process_groups" or
                    selected[0]["attributes"] & 4 and not selected[0]["attributes"] & 16),
                    "service SID is missing, disabled or deny-only in the token")
        if process_bound:
            from publisher_process_boundary import validate_process_boundary
            try:
                validate_process_boundary(execution["process_boundary"], service["process_id"], service_sid,
                                          service["process_groups"])
            except (ValueError, KeyError, TypeError) as error:
                raise EvidenceError("retained process boundary differs: " + str(error)) from error
        if worker_bound:
            from publisher_worker_security import validate_worker_security
            try:
                require(execution["worker_security"]["schema"] == "usk.publisher_worker_security.v1", "legacy execution reinterpreted retirement provenance")
                validate_worker_security(execution["worker_security"], service)
            except (ValueError, KeyError, TypeError) as error:
                raise EvidenceError("retained worker security differs: " + str(error)) from error
    bindings = object_bindings(anchors, tree)
    require(len(set(bindings)) == len(ROLES) and all(isinstance(x, str) and
            re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{32}", x) for x in bindings) and
            len({x[:16] for x in bindings}) == 1, "held object bindings are not distinct on one volume")
    handles = execution["handles"]
    require(isinstance(handles, list) and len(handles) == len(ROLES), "held handle role closure differs")
    objects = (anchors['boundary'], anchors['chain'][0]['object'], anchors['staging'],
               anchors['destination_parent'], anchors['state'], anchors['journal'], tree['root'])
    for handle, role, file_id, expected_object in zip(handles, ROLES, bindings, objects):
        closed(handle, frozenset({"role", "file_id", "handle_flags"}) |
               ({"granted_access", "granted_access_api"} if rights_bound else set()) |
               ({'object_observation'} if metadata_bound else set()) |
               ({'authenticated_access'} if authenticated_bound else set()), "held handle keys differ")
        require(handle["role"] == role and handle["file_id"] == file_id and handle["handle_flags"] == 0 and
                integer(handle["handle_flags"]), "held handle flags, role or identity differs")
        if rights_bound:
            require(integer(handle["granted_access"]) and handle["granted_access"] & 0x20080 == 0x20080 and
                    handle["granted_access_api"] == "NtQueryObject:ObjectBasicInformation",
                    "held handle access rights/API differ")
        if metadata_bound:
            observed = handle['object_observation']
            closed(observed, frozenset({'file_id', 'native_name', 'owner_sid', 'dacl_protected', 'attributes',
                'reparse_tag', 'link_count', 'case_sensitive', 'dacl_aces'}), 'same-handle native object keys differ')
            require(observed == expected_object and observed['owner_sid'] == 'S-1-5-18' and
                observed['dacl_protected'] is True and observed['case_sensitive'] is False and
                integer(observed['attributes']) and observed['attributes'] & 0x10 and not observed['attributes'] & 0x400 and
                integer(observed['reparse_tag'], 0, 0) and integer(observed['link_count'], 1, 1) and
                isinstance(observed['native_name'], str) and bool(observed['native_name']),
                'same-handle security/identity differs from the bound native object')
            aces = observed['dacl_aces']
            require(isinstance(aces, list) and len(aces) == 2, 'same-handle protected ACE closure differs')
            for ace, principal in zip(aces, ('S-1-5-18', service_sid)):
                closed(ace, frozenset({'type', 'flags', 'access_mask', 'sid'}), 'same-handle ACE keys differ')
                require(ace['sid'] == principal and integer(ace['type'], 0, 0) and integer(ace['flags'], 0, 0) and
                    integer(ace['access_mask'], 0x1f01ff, 0x1f01ff), 'same-handle protected ACE facts differ')
        if authenticated_bound:
            from publisher_authenticated_access_evidence import validate_access
            try:
                validate_access(handle['authenticated_access'], execution['authenticated_client'], expected_object)
            except (ValueError, KeyError, TypeError, struct.error) as error:
                raise EvidenceError('authenticated phase access differs: ' + str(error)) from error
    if descendants_bound:
        require(authenticated_bound, 'descendant access requires an authenticated execution')
        from publisher_authenticated_access_evidence import validate_descendant_access
        try:
            validate_descendant_access(value['authenticated_descendants'], execution['authenticated_client'], tree)
        except (ValueError, KeyError, TypeError, struct.error) as error:
            raise EvidenceError('authenticated descendant access differs: ' + str(error)) from error
    return execution


def worker_match(earlier: dict, later: dict) -> None:
    if earlier['schema'] in ('usk.publisher_execution_observation.v7', 'usk.publisher_execution_observation.v8'):
        from publisher_effect_broker_evidence import immutable_broker_record
        require(earlier['effect_worker'] == later.get('effect_worker') and
            immutable_broker_record(earlier['broker_readback']) == immutable_broker_record(later['broker_readback']),
            'original child or immutable native broker changed between phases')
    handles = later['handles']
    if (earlier['schema'] == later['schema'] and earlier['schema'] in
            ('usk.publisher_execution_observation.v5', 'usk.publisher_execution_observation.v6', 'usk.publisher_execution_observation.v7', 'usk.publisher_execution_observation.v8') and
            earlier['phase'] == 'before_rename' and later['phase'] == 'visible_bound'):
        handles = [dict(handle) for handle in handles]
        handles[6]['object_observation'] = dict(handles[6]['object_observation'],
            native_name=earlier['handles'][6]['object_observation']['native_name'])
        if 'authenticated_client' in earlier:
            handles[6]['authenticated_access'] = dict(handles[6]['authenticated_access'],
                native_object_sha256=earlier['handles'][6]['authenticated_access']['native_object_sha256'])
    require(all(earlier[key] == later[key] for key in ("schema", "scope", "service", "platform")) and
            earlier['handles'] == handles and
            earlier.get("process_boundary") == later.get("process_boundary") and
            earlier.get('authenticated_client') == later.get('authenticated_client'),
            "worker token/process/platform or held objects changed between phases")
    if earlier['schema'] == 'usk.publisher_execution_observation.v8':
        from publisher_worker_security import validate_worker_continuity
        validate_worker_continuity(earlier['worker_security'], later['worker_security'])
    else:
        require(earlier.get('worker_security') == later.get('worker_security'),
                'legacy worker security changed between phases')


def record_continuity(earlier: dict, later: dict) -> None:
    from publisher_effect_broker_evidence import execution_worker_identity
    before, after = execution_worker_identity(earlier), execution_worker_identity(later)
    if before[0] == after[0] and (before[1] == after[1] or
            before[2] is not None and after[2] is not None and before[2] == after[2]):
        worker_match(earlier, later)


def descendant_continuity(earlier: dict, later: dict) -> None:
    if earlier['execution']['phase'] == 'protected_empty':
        return
    first, second = earlier['authenticated_descendants']['objects'], later['authenticated_descendants']['objects']
    require(len(first) == len(second), 'authenticated descendant phase closure changed')
    from publisher_effect_broker_evidence import execution_worker_identity
    old_worker, new_worker = execution_worker_identity(earlier['execution']), execution_worker_identity(later['execution'])
    both_children = old_worker[2] is not None and new_worker[2] is not None
    same_worker = old_worker[0] == new_worker[0] and (
        old_worker[2] == new_worker[2] if both_children else old_worker[1] == new_worker[1])
    for before_row, after_row in zip(first, second):
        require(before_row['relative_path'] == after_row['relative_path'], 'authenticated descendant phase path changed')
        before, after = before_row['authenticated_access'], dict(after_row['authenticated_access'])
        require(all(before[key] == after[key] for key in ('descriptor_api', 'descriptor_hex', 'observed_group_sid')),
                'authenticated descendant descriptor changed across phases')
        if same_worker:
            after['native_object_sha256'] = before['native_object_sha256']
            require(before == after, 'authenticated descendant access changed within one worker')


def reconcile(prepared_json: str, visible_json: str | None, service_name: str, service_sid: str,
              windows_build: int, sdk_version: str) -> dict:
    require(isinstance(service_name, str) and re.fullmatch(r"USK_PUB_[0-9a-f]{32}", service_name) is not None and
            sid(service_sid) and service_sid.startswith("S-1-5-80-") and len(service_sid.split("-")) == 9 and
            integer(windows_build, 17763) and isinstance(sdk_version, str) and
            re.fullmatch(r"10\.0\.[1-9][0-9]*\.0", sdk_version) is not None and
            17763 <= int(sdk_version.split(".")[2]) <= 0xFFFFFFFF, "independent execution context is invalid")
    prepared = load_json(prepared_json)
    require(isinstance(prepared, dict), "prepared native record is not an object")
    retirement_bound = prepared.get('schema') == RETIREMENT_SCHEMA
    effect_bound = retirement_bound or prepared.get('schema') == EFFECT_SCHEMA
    descendants_bound = effect_bound or prepared.get('schema') == DESCENDANT_SCHEMA
    authenticated_bound = descendants_bound or prepared.get('schema') == AUTHENTICATED_SCHEMA
    metadata_bound = authenticated_bound or prepared.get('schema') == METADATA_SCHEMA
    rights_bound = metadata_bound or prepared.get("schema") == RIGHTS_SCHEMA
    rename_bound = rights_bound or prepared.get("schema") == RENAME_SCHEMA
    creation_bound = prepared.get("schema") in ("usk.publisher.lab_phase_evidence.v4", RENAME_SCHEMA, RIGHTS_SCHEMA, METADATA_SCHEMA, AUTHENTICATED_SCHEMA, DESCENDANT_SCHEMA, EFFECT_SCHEMA, RETIREMENT_SCHEMA)
    closed(prepared, PREPARED_KEYS | ({"creation_evidence"} if creation_bound else set()) |
           ({'operation_admission'} if authenticated_bound else set()),
           "prepared native execution record keys differ")
    require(prepared["schema"] in (SCHEMA, "usk.publisher.lab_phase_evidence.v4", RENAME_SCHEMA, RIGHTS_SCHEMA, METADATA_SCHEMA, AUTHENTICATED_SCHEMA, DESCENDANT_SCHEMA, EFFECT_SCHEMA, RETIREMENT_SCHEMA) and prepared["phase"] == "lab_prepared_evidence" and
            prepared["service_sid"] == service_sid and
            prepared["source_file_id"] == prepared["sealed_tree"]["root"]["file_id"] and
            prepared["destination_parent_file_id"] == prepared["protected_anchors"]["destination_parent"]["file_id"],
            "prepared native record identity differs")
    fresh = prepared["execution_origin"] == "created_empty_in_current_worker"
    require(fresh or prepared["execution_origin"] == "reopened_staged_tree", "prepared origin is unknown")
    names = ("protected_empty", "sealed", "publish_prepared") if fresh else ("sealed", "publish_prepared")
    phases = prepared["execution_phases"]
    require(isinstance(phases, list) and len(phases) == len(names), "prepared phase sequence differs")
    executions = []
    for value, name in zip(phases, names):
        tree = prepared["sealed_tree"]
        if name == "protected_empty":
            tree = dict(tree, descendants=[])
        executions.append(validate_phase(value, name, prepared["protected_anchors"], tree,
                                         service_name, service_sid, windows_build, sdk_version, descendants_bound))
        require(not rights_bound or executions[-1]['schema'] in ('usk.publisher_execution_observation.v4', 'usk.publisher_execution_observation.v5', 'usk.publisher_execution_observation.v6', 'usk.publisher_execution_observation.v7', 'usk.publisher_execution_observation.v8'),
                "current prepared evidence requires actual held-handle rights")
        require(not metadata_bound or executions[-1]['schema'] == ('usk.publisher_execution_observation.v8' if retirement_bound else 'usk.publisher_execution_observation.v7' if effect_bound else 'usk.publisher_execution_observation.v6' if authenticated_bound else 'usk.publisher_execution_observation.v5'),
                'current prepared evidence requires same-handle security facts')
        if len(executions) > 1:
            worker_match(executions[-2], executions[-1])
            if descendants_bound:
                descendant_continuity(phases[len(executions) - 2], value)
    creation = None
    if creation_bound:
        require(fresh, "reopened staging cannot claim current-worker creation")
        from publisher_creation_evidence import reconcile_creation
        try:
            creation = reconcile_creation(prepared["creation_evidence"], prepared["protected_anchors"],
                                          prepared["sealed_tree"], executions[0])
            if retirement_bound:
                from publisher_worker_security import validate_worker_continuity
                validate_worker_continuity(prepared["creation_evidence"]["completed_worker_security"], executions[-1]["worker_security"])
        except (ValueError, KeyError, TypeError, struct.error) as error:
            raise EvidenceError("retained creation binding differs: " + str(error)) from error
    transition = "visible_record_absent"
    rename_calls_checked = 0
    if visible_json is not None:
        visible = load_json(visible_json)
        closed(visible, VISIBLE_KEYS | ({"rename_call"} if rename_bound else set()), "visible native execution record keys differ")
        require(visible["schema"] == prepared["schema"] and visible["phase"] == "lab_visible_evidence" and
                visible["prepared_record_sha256"] == hashlib.sha256(prepared_json.encode("utf-8")).hexdigest() and
                all(visible[key] == prepared[key] for key in ("source_file_id", "destination_parent_file_id",
                    "destination_name", "selected_file_set_digest", "protected_anchors")) and
                visible["visible_tree"]["root"]["file_id"] == prepared["source_file_id"],
                "visible record differs from prepared native binding")
        transition = visible["execution_transition"]
        renamed = transition == "renamed_by_current_worker"
        require(renamed or transition == "observed_visible_on_restart", "visible transition is unknown")
        if rename_bound:
            if renamed:
                validate_rename_call(visible["rename_call"], prepared, visible)
                rename_calls_checked = 1
            else:
                require(visible["rename_call"] is None, "restart cannot claim an unobserved native rename call")
        names = ("before_rename", "visible_bound") if renamed else ("visible_bound",)
        phases = visible["execution_phases"]
        require(isinstance(phases, list) and len(phases) == len(names), "visible phase sequence differs")
        visible_executions = []
        for value, name in zip(phases, names):
            tree = prepared["sealed_tree"] if name == "before_rename" else visible["visible_tree"]
            visible_executions.append(validate_phase(value, name, visible["protected_anchors"], tree,
                service_name, service_sid, windows_build, sdk_version, descendants_bound))
            require(not rights_bound or visible_executions[-1]['schema'] in ('usk.publisher_execution_observation.v4', 'usk.publisher_execution_observation.v5', 'usk.publisher_execution_observation.v6', 'usk.publisher_execution_observation.v7', 'usk.publisher_execution_observation.v8'),
                    "current visible evidence requires actual held-handle rights")
            require(not metadata_bound or visible_executions[-1]['schema'] == ('usk.publisher_execution_observation.v8' if retirement_bound else 'usk.publisher_execution_observation.v7' if effect_bound else 'usk.publisher_execution_observation.v6' if authenticated_bound else 'usk.publisher_execution_observation.v5'),
                    'current visible evidence requires same-handle security facts')
            if len(visible_executions) > 1:
                worker_match(visible_executions[-2], visible_executions[-1])
                if descendants_bound:
                    descendant_continuity(phases[len(visible_executions) - 2], value)
        record_continuity(executions[-1], visible_executions[0])
        if descendants_bound:
            descendant_continuity(prepared['execution_phases'][-1], phases[0])
        if renamed and rename_bound and visible['rename_call']['schema'] == 'usk.publisher_bound_rename_call.v2':
            call = visible['rename_call']
            handles = visible_executions[0]['handles']
            require(call['source_granted_access'] == handles[6]['granted_access'] and
                    call['destination_parent_granted_access'] == handles[3]['granted_access'],
                    "native rename rights differ from the actual retained handles")
        executions.extend(visible_executions)
    worker_count = sum(x["schema"] in ("usk.publisher_execution_observation.v3",
                                      "usk.publisher_execution_observation.v4", "usk.publisher_execution_observation.v5", "usk.publisher_execution_observation.v6", "usk.publisher_execution_observation.v7", "usk.publisher_execution_observation.v8") for x in executions)
    process_count = sum(x["schema"] != "usk.publisher_execution_observation.v1" for x in executions)
    report = {"schema": "usk.publisher_execution_reconciliation.v5" if effect_bound else
                       "usk.publisher_execution_reconciliation.v4" if worker_count else
                       "usk.publisher_execution_reconciliation.v3" if process_count else
                       "usk.publisher_execution_reconciliation.v2" if creation else "usk.publisher_execution_reconciliation.v1", "status": "bindings_consistent",
            "prepared_origin": prepared["execution_origin"], "visible_transition": transition,
            "phase_count": len(executions), "held_roles_per_phase": len(ROLES),
            "worker_process_ids": sorted({x["effect_worker" if x["schema"] in ("usk.publisher_execution_observation.v7", "usk.publisher_execution_observation.v8") else "service"]["process_id"] for x in executions}),
            "scope": "retained_native_execution_record_bindings", "profile_qualified": False}
    if effect_bound:
        report["broker_process_ids"] = sorted({x["service"]["process_id"] for x in executions})
        report["effect_worker_phase_count"] = len(executions)
    if creation:
        report["creation_observation"] = creation
    if process_count:
        report["process_bound_phase_count"] = process_count
    if worker_count:
        report["worker_security_phase_count"] = worker_count
    if rename_bound:
        report["native_rename_calls_checked"] = rename_calls_checked
        report["held_access_phase_count"] = sum(x['schema'] in ('usk.publisher_execution_observation.v4', 'usk.publisher_execution_observation.v5', 'usk.publisher_execution_observation.v6', 'usk.publisher_execution_observation.v7', 'usk.publisher_execution_observation.v8') for x in executions)
    if metadata_bound:
        report['same_handle_objects_checked'] = sum(len(x['handles']) for x in executions)
    if authenticated_bound:
        report['authenticated_access_objects_checked'] = sum(len(x['handles']) for x in executions)
        report['authenticated_actor_scope'] = 'actual_request_client_per_worker'
        from publisher_authenticated_access_evidence import validate_operation_admission
        try:
            report['registered_operation_bound'] = validate_operation_admission(prepared)
        except (ValueError, KeyError, TypeError) as error:
            raise EvidenceError('registered operation binding differs: ' + str(error)) from error
    if descendants_bound:
        bound_phases = prepared['execution_phases'] + (visible['execution_phases'] if visible_json is not None else [])
        report['authenticated_descendant_objects_checked'] = sum(
            len(phase['authenticated_descendants']['objects']) for phase in bound_phases)
        report['descendant_access_scope'] = 'fresh_descriptor_and_request_token_no_content_rehash'
    return report


def load_json(text: str) -> Any:
    require(isinstance(text, str) and len(text.encode("utf-8")) <= 4 * 1024 * 1024, "native record byte bound differs")
    def unique(pairs: list) -> dict:
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate native JSON key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    require(args.input.stat().st_size <= 8 * 1024 * 1024, "execution input exceeds byte bound")
    request = json.loads(args.input.read_text(encoding="utf-8"))
    closed(request, frozenset({"prepared_json", "visible_json", "service_name", "service_sid", "windows_build",
                              "sdk_version"}), "execution reconciliation input keys differ")
    print(json.dumps(reconcile(**request), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
