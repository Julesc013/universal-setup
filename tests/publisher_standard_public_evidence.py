# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent bounded standard-client receipt reconciliation; no profile admission."""
from __future__ import annotations
import hashlib
import json
import re
from publisher_execution_evidence import reconcile as reconcile_execution, sid, load_json


class StandardEvidenceError(ValueError):
    pass


BYPASS_PRIVILEGES = frozenset({"SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeCreateTokenPrivilege",
    "SeTakeOwnershipPrivilege", "SeManageVolumePrivilege", "SeRelabelPrivilege", "SeSecurityPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege"})
MUTATION_RIGHTS = {"write_or_add_file": 2, "append_or_add_directory": 4, "write_ea": 16,
    "delete_child": 64, "write_attributes": 256, "delete": 65536, "write_dac": 262144, "write_owner": 524288}


def require(condition, message):
    if not condition:
        raise StandardEvidenceError(message)


def integer(value, minimum=0, maximum=0xffffffff):
    return type(value) is int and minimum <= value <= maximum


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def client_token(facts, expected_sid):
    require(isinstance(facts, dict) and facts.keys() == {
        "user_sid", "groups", "privileges", "token_id", "authentication_id", "token_type", "impersonation_level"},
        "standard primary token is not closed")
    require(facts["user_sid"] == expected_sid and integer(facts["token_type"], 1, 1) and
        facts["impersonation_level"] is None, "standard primary identity/type differs")
    for key in ("token_id", "authentication_id"):
        require(isinstance(facts[key], str) and re.fullmatch(r"[0-9a-f]{16}", facts[key]) and int(facts[key], 16),
            "standard token identity is incomplete")
    for key in ("groups", "privileges"):
        require(isinstance(facts[key], list) and len(facts[key]) <= 2048, "standard token population exceeds bound")
    for group in facts["groups"]:
        require(isinstance(group, dict) and group.keys() == {"sid", "attributes"} and integer(group["attributes"]) and
            sid(group["sid"]) and group["sid"] not in ("S-1-5-18", "S-1-5-32-544") and
            not group["sid"].startswith("S-1-5-80-"), "standard token has privileged/service membership")
    for privilege in facts["privileges"]:
        require(isinstance(privilege, dict) and privilege.keys() == {"name", "attributes"} and
            integer(privilege["attributes"]) and isinstance(privilege["name"], str) and
            re.fullmatch(r"Se[A-Za-z]+Privilege", privilege["name"]) and
            privilege["name"] not in BYPASS_PRIVILEGES and
            (not privilege["attributes"] & 2 or privilege["name"] == "SeChangeNotifyPrivilege"),
            "standard token has an enabled bypass privilege")


def service_policy(value, client):
    # The observer's closed owner/ACE projection is checked below. Raw SDDL is
    # diagnostic provenance; this decoder does not parse it or claim equality.
    require(isinstance(value, dict) and value.keys() == {"owner", "raw_security_diagnostic", "aces"} and
        value["owner"] in ("S-1-5-18", "S-1-5-32-544") and isinstance(value["raw_security_diagnostic"], str) and
        0 < len(value["raw_security_diagnostic"]) <= 65536 and isinstance(value["aces"], list) and len(value["aces"]) <= 4096,
        "service owner/DACL readback differs")
    grants = 0
    for ace in value["aces"]:
        require(isinstance(ace, dict) and ace.keys() == {"sid", "mask", "type", "flags"} and
            sid(ace["sid"]) and integer(ace["mask"]) and integer(ace["flags"], 0, 0) and
            ace["type"] in ("AccessAllowed", "AccessDenied"), "service ACE form differs")
        allowed = 0x2018d | (0x10 if ace["sid"] == client else 0)
        require(ace["type"] == "AccessDenied" or ace["sid"] in ("S-1-5-18", "S-1-5-32-544") or
            not ace["mask"] & ~allowed, "service grants outside mutation")
        grants += ace["sid"] == client and ace["type"] == "AccessAllowed" and ace["mask"] == 0x20015
    require(grants == 1, "configured client start/query grant differs")


def deny_mutation(checks):
    require(isinstance(checks, dict) and checks.keys() == MUTATION_RIGHTS.keys() | {"maximum_allowed"},
        "native mutation checks are incomplete")
    for name, mask in MUTATION_RIGHTS.items():
        check = checks[name]
        require(isinstance(check, dict) and check.keys() == {"requested", "allowed", "granted"} and
            integer(check["requested"], mask, mask) and check["allowed"] is False and
            integer(check["granted"], 0, 0), "native mutation right is available")
    maximum = checks["maximum_allowed"]
    require(maximum.keys() == {"requested", "allowed", "granted"} and integer(maximum["requested"], 0x2000000, 0x2000000) and
        type(maximum["allowed"]) is bool and integer(maximum["granted"]) and
        not maximum["granted"] & sum(MUTATION_RIGHTS.values()) and
        (maximum["allowed"] or maximum["granted"] == 0), "native maximum access permits mutation")


def native_rows(rows, drive, visible, service, client):
    require(isinstance(rows, list) and 0 < len(rows) <= 10000 and len({x["path"] for x in rows}) == len(rows) and
        len({x["file_id"] for x in rows}) == len(rows), "native row identities alias")
    for row in rows:
        require(row["path"].startswith(drive) and re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{32}", row["file_id"]) and
            row["native_name"] == row["path"][2:] and row["link_count"] == 1 and row["case_sensitive"] is False and
            bool(row["attributes"] & 16) == row["directory"] and not row["attributes"] & 1024,
            "native object identity/closure differs")
        payload = row["path"] == visible or row["path"].startswith(visible + "\\")
        aces = [{"type": 0, "flags": 0, "access_mask": 2032127, "sid": principal}
                for principal in ("S-1-5-18", service)]
        if payload:
            aces.append({"type": 0, "flags": 0, "access_mask": 1179817, "sid": client})
        require(row["owner"] == "S-1-5-18" and row["protected"] is True and row["raw_aces"] == aces,
            "native private/payload access policy differs")
        for actor in ("initiating", "filtered"):
            deny_mutation(row["effective_rights"][actor])
        if row["directory"]:
            require(row["streams"] == [], "native directory streams differ")
        else:
            require(len(row["streams"]) == 1 and row["streams"][0]["name"] == "::$DATA" and
                row["streams"][0]["size"] == row["bytes"] and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
                "native file streams/bytes differ")
            if row.get("content_json"):
                require(hashlib.sha256(row["content_json"].encode()).hexdigest() == row["sha256"],
                    "native retained record digest differs")


def native_boundary(boundary):
    require(isinstance(boundary, dict) and boundary.keys() == {"root", "device"}, "standard volume boundary roles incomplete")
    for actor in ("initiating", "filtered"):
        deny_mutation(boundary["root"]["effective_rights"][actor])
        deny_mutation(boundary["device"]["checks"][actor])


def registered_admission(native, service, service_sid, client, image_sha256, volume_root, boundary_id):
    """Decode observed admission bindings; this does not certify source or mapped image bytes."""
    value = native.get('registered_admission')
    require(isinstance(value, dict) and value.keys() == {'schema', 'scope', 'service_name', 'service_sid',
        'process_id', 'configured_caller_sid', 'publisher_image', 'registration_sha256',
        'target_admitted_sha256', 'target_identity'}, 'registered admission observation is not closed')
    require(value['schema'] == 'usk.publisher_registered_admission_observation.v1' and
        value['scope'] == 'held_registered_service_image_and_controller_target_admission' and
        value['service_name'] == service and value['service_sid'] == service_sid and
        value['configured_caller_sid'] == client and integer(value['process_id'], 1) and
        value['process_id'] == native.get('process_id'), 'registered service/process/caller binding differs')
    image = value['publisher_image']
    require(isinstance(image, dict) and image.keys() == {'path', 'volume_id', 'file_id', 'size_bytes', 'sha256'} and
        all(isinstance(image[key], str) and 0 < len(image[key]) <= 32768 for key in ('path', 'volume_id', 'file_id')) and
        integer(image['size_bytes'], 1, 0xffffffffffffffff) and image['sha256'] == image_sha256 and
        isinstance(image_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', image_sha256),
        'registered executable differs from the independently built package')
    target = value['target_identity']
    require(isinstance(target, dict) and target.keys() == {'registration_sha256', 'volume_identity', 'disk_identity', 'metadata'} and
        target['registration_sha256'] == value['registration_sha256'] and
        isinstance(value['registration_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', value['registration_sha256']),
        'registered target authority binding differs')
    volume = target['volume_identity']
    require(isinstance(volume, dict) and volume.keys() == {'volume_root', 'root_file_id', 'volume_serial'} and
        volume['volume_root'] == volume_root and volume['root_file_id'] == boundary_id and
        isinstance(boundary_id, str) and re.fullmatch(r'[0-9a-f]{16}:[0-9a-f]{32}', boundary_id) and
        volume['volume_serial'] == str(int(boundary_id[:16], 16)), 'registered target differs from held native boundary')
    admitted = {'schema': 'usk.publisher_target_admitted.v1', 'identity': target}
    require(hashlib.sha256(canonical(admitted).encode('utf-8')).hexdigest() == value['target_admitted_sha256'],
        'registered admitted-target canonical digest differs')
    return value


def service_capability(native, request_id, windows_build, *, protocol="usk.publisher_capability.v2", sdk_version=None):
    """Reconcile service observations; retained root facts are not fresh ACL proof."""
    require(isinstance(native, dict) and native.keys() == {'schema', 'status', 'request_id', 'service_name',
        'service_sid', 'process_id', 'registered_admission', 'capability_observation'} and
        native['schema'] == 'usk.publisher_service_capability_observation.v1' and native['status'] == 'observed' and
        native['request_id'] == request_id, 'service observation envelope differs')
    value = native['capability_observation']
    require(protocol in ('usk.publisher_capability.v2', 'usk.publisher_capability.v3'), 'unknown service capability protocol')
    scoped = protocol == 'usk.publisher_capability.v3'
    if scoped:
        require(isinstance(sdk_version, str) and len(sdk_version) <= 32 and
            (not sdk_version or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', sdk_version)),
            'scoped capability compiled SDK differs')
    qualified = scoped and windows_build == 20348 and sdk_version == '10.0.26100.0'

    constants = {'schema': 'usk.publisher_capability.v2', 'request_id': request_id,
        'provider_id': 'windows_nt_x64_local_ntfs_service_sid_noreplace_v1',
        'implementation': 'partial', 'realization': 'restricted_service', 'availability': False,
        'required_privilege': 'none_for_registered_caller', 'permission': 'registered_caller_observed',
        'authority': 'not_granted_by_discovery', 'qualification': 'incomplete',
        'qualification_scope': 'service_admitted_target_observation',
        'binding_provenance': 'retained_controller_admission_and_current_disk_identity',
        'support': 'unsupported', 'recovery_ceiling': 'candidate_source_free_restart',
        'power_loss_qualified': False, 'revalidation_required_before_effects': True,
        'execution_lease_held': False, 'service_state': 4,
        'effects': ['service_start_may_occur', 'controller_guard_held_during_observation']}

    if scoped:
        constants.update(schema=protocol, availability=qualified,
            qualification='qualified_for_scope' if qualified else 'incomplete',
            support='supported_for_scope' if qualified else 'unsupported',
            qualification_scope='registered_public_apply_v9_process_restart_replay_verify',
            recovery_ceiling='source_free_process_restart_v9')
        bounds = value['qualification_bounds']
        require(isinstance(bounds, dict) and bounds == {
            'phase_schema': 'usk.publisher.lab_phase_evidence.v9',
            'execution_schema': 'usk.publisher_execution_observation.v6',
            'sdk_version': '10.0.26100.0', 'qualified_windows_build': 20348} and
            integer(bounds['qualified_windows_build'], 20348, 20348), 'scoped qualification bounds differ')
    require(isinstance(value, dict) and value.keys() == constants.keys() | {'platform', 'binding'} |
        ({'qualification_bounds'} if scoped else set()) and
        all(type(value[key]) is type(expected) and value[key] == expected for key, expected in constants.items()),
        'service capability fabricated dimensions or effects')
    platform = value['platform']
    expected_platform = {'os_family': 'Windows NT', 'native_arch': 'x64', 'process_arch': 'x64',
        'windows_build': windows_build, 'minimum_windows_build': 17763}
    if scoped:
        expected_platform['sdk_version'] = sdk_version
    require(platform == expected_platform and
        integer(platform['windows_build'], 17763, 0xffffffff) and
        integer(platform['minimum_windows_build'], 17763, 17763), 'service capability platform differs')
    admitted = native['registered_admission']
    volume = admitted['target_identity']['volume_identity']
    expected = {key: admitted[key] for key in ('service_name', 'service_sid', 'process_id')}
    expected.update(caller_sid=admitted['configured_caller_sid'],
        binary_sha256=admitted['publisher_image']['sha256'], registration_sha256=admitted['registration_sha256'],
        target_admitted_sha256=admitted['target_admitted_sha256'], volume_guid_root=volume['volume_root'],
        root_file_id=volume['root_file_id'], volume_serial=volume['volume_serial'])
    require(isinstance(value['binding'], dict) and value['binding'] == expected and
        integer(value['binding']['process_id'], 1, 0xffffffff) and
        all(native[key] == admitted[key] for key in ('service_name', 'service_sid', 'process_id')),
        'service capability differs from independently reconciled admission')
    return value


def require_native_capture_set(native_captures, captures, commands, *, allow_legacy_missing=False):
    if allow_legacy_missing and native_captures is None and 'publisher.observe' not in commands:
        return
    require(isinstance(native_captures, list) and len(native_captures) == len(commands) - 1 and
        all(isinstance(x, dict) for x in native_captures) and
        [x.get('command') for x in native_captures] == commands[1:] and
        [x.get('request_id') for x in native_captures] == [x['request_id'] for x in captures[1:]],
        'standard native response capture set differs')


def installed_material(observation, rows, drive):
    apply = observation["apply_request"]
    request, plan = apply["plan_request"], observation["plan"]
    installed = observation["apply"]["result"]["payload"]
    require(installed["install_id"] == request["install_id"] and installed["transaction_id"] == apply["transaction_id"] and
        installed["created_at"] == apply["applied_at"] and installed["lifecycle_status"] == "installed" and
        installed["target_root"].replace("/", "\\") == plan["target"]["root"].replace("/", "\\"),
        "installed identity differs from the reviewed request")
    by_path = {row["path"]: row for row in rows}
    state = drive + "setup-state\\state\\"
    installed_path = state + "installed\\" + installed["install_id"] + "." + installed["transaction_id"] + ".json"
    require(json.loads(by_path[installed_path]["content_json"]) == installed, "native installed record differs from response")
    ownership = json.loads(by_path[state + installed["ownership_manifest_ref"].replace("/", "\\")]["content_json"])
    require(ownership["install_id"] == installed["install_id"] and
        ownership["created_by_transaction_id"] == installed["transaction_id"] and
        ownership["manifest_digest"] == installed["ownership_manifest_digest"], "native ownership binding differs")
    entries = [x for x in plan["planned_entries"] if x["entry_type"] == "file"]
    visible = installed["target_root"].replace("/", "\\")
    files = {x["path"]: x for x in rows if not x["directory"] and x["path"].startswith(visible + "\\")}
    require(len(files) == len(entries) == len(ownership["files"]), "native payload file closure differs")
    for entry in entries:
        row = files[visible + "\\" + entry["relative_path"].replace("/", "\\")]
        owned = [x for x in ownership["files"] if x["relative_path"] == entry["relative_path"]]
        require(row["sha256"] == entry["sha256"] and row["bytes"] == entry["size_bytes"] and len(owned) == 1 and
            owned[0]["sha256"] == row["sha256"] and owned[0]["size_bytes"] == row["bytes"],
            "native payload/ownership bytes differ from reviewed plan")


def reconcile(receipt, expected_head, *, allow_legacy_missing_coordination=False, allow_legacy_missing_bootstrap=False):
    require(receipt.get("status") == "volume_and_protected_publish_observed" and
        receipt.get("build_profile", {}).get("pull_request_head") == expected_head,
        "standard hosted source/result differs")
    profile = receipt["build_profile"]
    observation = receipt["service_observation"]
    require(observation.get("schema") == "usk.publisher_standard_public_probe.v1" and
        observation.get("status") == "standard_public_install_verified_recovered" and
        observation.get("profile_qualified") is False and observation.get("source_free") is True and
        observation.get("launcher_identity") == "S-1-5-18" and observation.get("client_cleanup_confirmed") is True and
        observation.get("account_cleanup_confirmed") is True and observation.get("launcher_task_removed") is True and
        observation.get("launcher_process_exit_confirmed") is True and integer(observation.get("launcher_task_result"), 0, 0),
        "standard fixture scope/closure differs")
    client = observation["account_sid"]
    require(sid(client) and re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", client) and
        int(client.rsplit("-", 1)[1]) >= 1000, "standard account identity differs")
    service_policy(observation["service_policy"], client)
    build = observation["execution_build_context"]
    require(build["windows_sdk"] == profile["windows_sdk"] and
        re.fullmatch(r"[0-9a-f]{64}", build["publisher_project_sha256"]), "standard native build targets differ")
    captures = observation["client_captures"]
    service_protocol = observation.get('capability_protocol')
    require(service_protocol is None or service_protocol in ('usk.publisher_capability.v2', 'usk.publisher_capability.v3'),
        'standard capability protocol is unknown')
    mediated = service_protocol is not None
    commands = ["publisher.inspect"] + (["publisher.observe"] if mediated else []) + [
        "install_local.apply", "install_local.recover", "install_local.apply", "installed.verify"] + (
        ["publisher.observe"] if mediated else [])
    require(isinstance(captures, list) and [x["command"] for x in captures] == commands, "standard request capture set differs")
    require(len({x["request_id"] for x in captures}) == len(commands) and
        len({x["process_id"] for x in captures}) == len(commands),
        "standard request identities alias")
    native_captures = observation.get('native_observations')
    require_native_capture_set(native_captures, captures, commands, allow_legacy_missing=not mediated)
    for capture in captures:
        require(capture.get("captured_before_primary_thread_resume") is True and integer(capture["process_id"], 1) and
            re.fullmatch(r"[1-9][0-9]{16,18}", capture["creation_file_time"]) and
            capture["image_sha256"] == observation["machine_sha256"], "standard pre-resume process/image binding differs")
        client_token(capture["primary_token"], client)
        launcher = capture["launcher_token"]
        require(launcher["user_sid"] == "S-1-5-18" and integer(launcher["token_type"], 1, 1) and
            {"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"} <=
                {x["name"] for x in launcher["privileges"] if not x["attributes"] & 4},
            "standard launcher lacks documented creation authority")
    discovery = observation["discovery"]
    require(discovery["status"] == "refused" and discovery["result"] is None and
        discovery["error"]["code"] == "publisher_capability_unavailable", "standard discovery fabricated availability")
    installed = observation["apply"]["result"]["payload"]
    require(observation["recovery"]["result"]["payload"] == installed and
        observation["replayed_apply"]["result"]["payload"] == installed and
        observation["verification"]["result"]["payload"]["status"] == "pass", "standard public terminal results differ")
    readbacks = observation["readbacks"]
    require(isinstance(readbacks, list) and len(readbacks) == 4, "standard per-request native readbacks incomplete")
    reports = []
    baseline = None
    for readback, capture in zip(readbacks, captures[2:6] if mediated else captures[1:]):
        require(readback["observer_task_removed"] is True and readback["independent"]["identity"] == "S-1-5-18" and
            readback["independent"]["observer_token_handles_closed"] is True, "standard native reader closure differs")
        tokens = readback["independent"]["effective_right_tokens"]
        context = tokens["capture_context"]
        require(tokens["captured_client"]["process_id"] == capture["process_id"] and
            tokens["captured_client"]["creation_file_time"] == capture["creation_file_time"] and
            tokens["captured_client"]["exited_at_observation"] is True and
            context["capture_sha256"] == capture["capture_sha256"] and context["command"] == capture["command"] and
            context["request_id"] == capture["request_id"] and context["image_sha256"] == capture["image_sha256"] and
            tokens["initiating"]["user_sid"] == client and tokens["filtered"]["user_sid"] == client and
            tokens["initiating"]["token_id"] == capture["initiating_token_id"] and
            tokens["filtered"]["token_id"] == capture["filtered_token_id"], "standard held-native client binding differs")
        require(all(tokens["initiating"][key] == capture["primary_token"][key]
            for key in ("authentication_id", "groups", "privileges")), "standard primary/independent initiating facts differ")
        require(tokens["initiating"]["token_type"] == tokens["filtered"]["token_type"] == 2 and
            tokens["initiating"]["impersonation_level"] == tokens["filtered"]["impersonation_level"] == 2,
            "standard independent AccessCheck token type differs")
        rows = readback["independent"]["rows"]
        from publisher_installation_lease_evidence import snapshot as lease_snapshot, transition as lease_transition, LeaseEvidenceError
        require(rows and len(rows) <= 10000, "standard native row budget exceeded")
        try:
            if baseline is None:
                lease_snapshot(rows, receipt["volume_root"], installed, readback["independent"]["volume_boundary"]["root"]["file_id"],
                    allow_legacy_missing=allow_legacy_missing_coordination,
                    allow_legacy_missing_bootstrap=allow_legacy_missing_bootstrap)
            else:
                lease_transition(baseline, rows, receipt["volume_root"], installed,
                    readback["independent"]["volume_boundary"]["root"]["file_id"], readonly=capture["command"] == "installed.verify",
                    allow_legacy_missing=allow_legacy_missing_coordination,
                    allow_legacy_missing_bootstrap=allow_legacy_missing_bootstrap)
        except (LeaseEvidenceError, ValueError, KeyError, TypeError) as error:
            raise StandardEvidenceError("standard lease/native row transition differs: " + str(error)) from error
        baseline = rows
        drive = receipt["volume_root"]
        target = installed["target_root"].replace("/", "\\")
        native_rows(rows, drive, target, observation["service_sid"], client)
        installed_material(observation, rows, drive)
        native_boundary(readback["independent"]["volume_boundary"])
        prepared = [x["content_json"] for x in rows if x["path"].endswith("\\lab-prepared-evidence.json")]
        visible = [x["content_json"] for x in rows if x["path"].endswith("\\lab-visible-evidence.json")]
        require(len(prepared) == len(visible) == 1, "standard native phase records incomplete")
        report = reconcile_execution(prepared[0], visible[0], observation["service"], observation["service_sid"],
            int(receipt["windows_build"].split(".")[2]), build["windows_sdk"])
        require(report.get("worker_security_phase_count", 0) > 0 and
            report.get("creation_observation", {}).get("worker_security_checked") is True and
            report["profile_qualified"] is False, "standard native creation/worker bindings incomplete")
        prepared_schema = json.loads(prepared[0])['schema']
        if prepared_schema in ('usk.publisher.lab_phase_evidence.v6', 'usk.publisher.lab_phase_evidence.v7', 'usk.publisher.lab_phase_evidence.v8', 'usk.publisher.lab_phase_evidence.v9'):
            require_native_capture_set(native_captures, captures, commands)
        if native_captures is not None:
            require(prepared_schema in ('usk.publisher.lab_phase_evidence.v6', 'usk.publisher.lab_phase_evidence.v7', 'usk.publisher.lab_phase_evidence.v8', 'usk.publisher.lab_phase_evidence.v9') and
                report.get('held_access_phase_count') == 5 and report.get('native_rename_calls_checked') == 1,
                'current standard producer requires complete v6 access and actual rename bindings')
            if prepared_schema in ('usk.publisher.lab_phase_evidence.v7', 'usk.publisher.lab_phase_evidence.v8', 'usk.publisher.lab_phase_evidence.v9'):
                require(report.get('same_handle_objects_checked') == 35,
                    'current standard producer requires all seven same-handle security objects per phase')
            if prepared_schema in ('usk.publisher.lab_phase_evidence.v8', 'usk.publisher.lab_phase_evidence.v9'):
                from publisher_authenticated_access_evidence import reconcile_client_capture, reconcile_registered_operation
                require(report.get('authenticated_access_objects_checked') == 35,
                        'current standard producer requires authenticated access for every held phase role')
                phases = json.loads(prepared[0])['execution_phases'] + json.loads(visible[0])['execution_phases']
                for phase in phases:
                    actual_client = phase['execution']['authenticated_client']
                    matched = [capture for capture in captures if capture['process_id'] == actual_client['captured_process_id']]
                    require(len(matched) == 1, 'authenticated phase PID lacks a unique independent client capture')
                    try:
                        reconcile_client_capture(actual_client, matched[0])
                    except (ValueError, KeyError, TypeError) as error:
                        raise StandardEvidenceError('authenticated phase client capture differs: ' + str(error)) from error
                retained_prepared = json.loads(prepared[0])
                first_client = phases[0]['execution']['authenticated_client']
                original = [capture for capture in captures if capture['process_id'] == first_client['captured_process_id']]
                native_apply = [entry for entry in native_captures if entry['command'] == 'install_local.apply' and
                                entry['request_id'] == original[0]['request_id']]
                require(len(native_apply) == 1 and report.get('registered_operation_bound') is True,
                        'registered public path requires the original native apply admission')
                native = load_json(native_apply[0]['native_json'])
                try:
                    reconcile_registered_operation(retained_prepared, native['registered_admission'])
                    require(retained_prepared['operation_admission']['transaction_id'] ==
                            native['apply_response']['payload']['transaction_id'],
                            'registered operation transaction differs from native public completion')
                except (ValueError, KeyError, TypeError) as error:
                    raise StandardEvidenceError('registered public operation admission differs: ' + str(error)) from error
        require(report == readback["execution_reconciliation"], "standard embedded native reconciliation differs")
        reports.append(report)
    if native_captures is not None:
        boundary_id = json.loads(prepared[0])['protected_anchors']['boundary']['file_id']
        public_results = ([observation['service_discovery']['result']] if mediated else []) + [
            observation[key]['result'] for key in ('apply', 'recovery', 'replayed_apply', 'verification')] + (
            [observation['source_free_service_discovery']['result']] if mediated else [])
        for entry, public_result in zip(native_captures, public_results):
            require(isinstance(entry, dict) and entry.keys() == {'command', 'request_id', 'native_json', 'sha256'} and
                isinstance(entry['native_json'], str) and len(entry['native_json'].encode('utf-8')) <= 4 * 1024 * 1024 and
                hashlib.sha256(entry['native_json'].encode('utf-8')).hexdigest() == entry['sha256'],
                'standard native transport bytes/digest differ')
            native = load_json(entry['native_json'])
            registered_admission(native, observation['service'], observation['service_sid'], client,
                observation['service_sha256'], observation['volume_root'], boundary_id)
            if entry['command'] == 'publisher.observe':
                require(service_capability(native, entry['request_id'], int(receipt['windows_build'].split('.')[2]),
                    protocol=service_protocol, sdk_version=receipt['build_profile']['windows_sdk']) ==
                    public_result, 'service native/public capability differs')
                continue
            require(native.get('schema') == 'usk.publisher_lab_service_observation.v1' and native.get('status') == 'pass',
                'standard native response scope differs')
            if entry['command'] == 'installed.verify':
                returned = native.get('verify_response')
            elif entry['command'] == 'install_local.recover':
                returned = native.get('recovery_installed_response')
            else:
                responses = [native.get(key) for key in ('apply_response', 'recovery_installed_response')]
                require(sum(value is not None for value in responses) == 1,
                    'standard native apply completion is ambiguous')
                returned = next(value for value in responses if value is not None)
            require(returned == public_result, 'standard native/public completion bytes differ')
    return {"schema": "usk.publisher_standard_public_reconciliation.v1", "status": "bindings_consistent",
        "head": expected_head, "standard_client_sid": client, "captured_clients": len(commands), "native_readbacks": 4,
        "service_observations_checked": 2 if mediated else 0,
        "phase_bindings_checked": sum(x["worker_security_phase_count"] for x in reports),
        "native_rows": len(baseline), "profile_qualified": False}


def reconcile_native_model(receipt, expected_head, reviewed_source_tree, *, allow_legacy_missing_coordination=False,
                           allow_legacy_missing_bootstrap=False):
    """Current producer qualification input, with separately pinned review tree.

    Legacy reconciliation remains available above. It cannot stand in for
    current v7 native model evidence or the reviewed production-route argument.
    """
    from publication_authority_reference import PublicationModelContext
    from publisher_native_profile_evidence import project, ROUTE
    standard = reconcile(receipt, expected_head, allow_legacy_missing_coordination=allow_legacy_missing_coordination,
                         allow_legacy_missing_bootstrap=allow_legacy_missing_bootstrap)
    observation = receipt['service_observation']
    require(isinstance(reviewed_source_tree, str) and re.fullmatch('[0-9a-f]{40}', reviewed_source_tree) and
        receipt['build_profile']['source_tree'] == reviewed_source_tree,
        'current native model requires independently reviewed exact source tree')
    context = PublicationModelContext(service_sid=observation['service_sid'],
        sdk_version=observation['execution_build_context']['windows_sdk'], minimum_additional_ancestors=0,
        namespace_layout='staging_anchor_with_payload_child', security_observation_api='GetKernelObjectSecurity',
        provenance_profile='native_registered_controller_boundary', actor_profile='standard_and_filtered_same_account')
    source = {'head': expected_head, 'source_tree': receipt['build_profile']['source_tree'],
        'reviewed_source_tree': reviewed_source_tree, 'publisher_image_sha256': observation['service_sha256'],
        'route': ROUTE, 'no_export_basis': 'reviewed_selected_route_source_argument'}
    projections = []
    for readback in observation['readbacks']:
        snapshot = readback['independent']
        prepared = [row['content_json'] for row in snapshot['rows'] if row['path'].endswith('\\lab-prepared-evidence.json')]
        visible = [row['content_json'] for row in snapshot['rows'] if row['path'].endswith('\\lab-visible-evidence.json')]
        require(len(prepared) == len(visible) == 1, 'current native model record set differs')
        result = project(prepared[0], visible[0], snapshot, observation['service'], context, source)
        report = result['execution_reconciliation']
        require(report['phase_count'] == 5 and report['same_handle_objects_checked'] == 35 and
            report['native_rename_calls_checked'] == 1 and result['model_result']['phase'] == 'visible_bound' and
            result['terminal_consumer_delta_objects'] == 1 + len(load_json(prepared[0])['sealed_tree']['descendants']),
            'current standard profile replay lacks complete native/consumer evidence')
        projections.append(result)
    return {'schema': 'usk.publisher.standard_native_model_reconciliation.v1', 'status': 'bindings_consistent',
        'head': expected_head, 'source_tree': reviewed_source_tree, 'standard_reconciliation': standard,
        'native_projections': projections, 'profile_qualified': False, 'publication_authority_granted': False}
