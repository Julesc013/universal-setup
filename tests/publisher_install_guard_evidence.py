# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""One native installation-mutex/public verification case; no profile admission."""
from __future__ import annotations
import hashlib
import json
from pathlib import PureWindowsPath
import re
from publisher_standard_public_evidence import (
    canonical, integer, native_boundary, native_rows, reader_rows,
    registered_admission, require, standard_capture)

SCOPE = 'actual_native_installation_mutex_authenticated_source_free_verify'


def inspection_reference(volume, install_id):
    match = re.fullmatch(r'\\\\\?\\Volume\{([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}\\', volume)
    require(match is not None and isinstance(install_id, str) and
        re.fullmatch(r'[A-Za-z0-9._-]{1,128}', install_id), 'installation guard canonical scope differs')
    name = 'Global\\USK.Publisher.Install.' + match[1].lower() + '.' + install_id.encode('ascii').hex()
    return 'usk.operation-inspection.v1:' + hashlib.sha256(canonical(name).encode()).hexdigest()


def holder_binding(holder, observation, volume, install_id):
    require(isinstance(holder, dict) and holder.keys() == {
        'native_ready', 'native_ready_json', 'image_path', 'image_sha256', 'project_sha256', 'ready_sha256',
        'parent_process_id', 'parent_creation_file_time', 'volume_root', 'events_scope',
        'alive_before_request', 'alive_after_response', 'alive_after_readback', 'normal_release_confirmed', 'exit_code'},
        'installation holder record is not closed')
    ready = holder['native_ready']
    require(isinstance(ready, dict) and ready.keys() == {
        'schema', 'scope', 'process_id', 'creation_file_time', 'identity', 'install_id',
        'operation_inspection_ref', 'publication_authority_granted', 'service_sid', 'coordination_acl_scope',
        'coordination_security'} and
        ready['schema'] == 'usk.publisher_install_guard_holder.v1' and
        ready['scope'] == 'owned_installation_mutex_only_no_product_effects' and
        integer(ready['process_id'], 1) and isinstance(ready['creation_file_time'], str) and
        re.fullmatch(r'[1-9][0-9]{16,18}', ready['creation_file_time']) and
        ready['identity'] == 'S-1-5-18' and ready['install_id'] == install_id and
        ready['service_sid'] == observation['service_sid'] and
        re.fullmatch(r'S-1-5-80-(?:[0-9]+-){4}[0-9]+', ready['service_sid']) and
        ready['coordination_acl_scope'] == 'system_and_registered_service_sid_only' and
        ready['operation_inspection_ref'] == inspection_reference(volume, install_id) and
        ready['publication_authority_granted'] is False, 'native installation holder scope differs')
    security = ready['coordination_security']
    expected_security = {'schema': 'usk.publisher_install_guard_security.v1', 'owner': 'S-1-5-18',
        'dacl_protected': True, 'aces': [{'sid': grantee, 'mask': 0x001f0001, 'type': 0, 'flags': 0}
            for grantee in ('S-1-5-18', observation['service_sid'])]}
    require(security == expected_security and security['dacl_protected'] is True and
        all(type(ace[key]) is int for ace in security['aces'] for key in ('mask', 'type', 'flags')),
        'held native installation mutex security readback differs')
    raw = holder['native_ready_json']
    require(isinstance(raw, str) and 0 < len(raw.encode()) <= 4096 and json.loads(raw) == ready and
        hashlib.sha256(raw.encode()).hexdigest() == holder['ready_sha256'], 'native holder readiness bytes differ')
    parent = observation['launcher_process']
    require(holder['parent_process_id'] == parent['process_id'] and
        holder['parent_creation_file_time'] == parent['creation_file_time'] and parent['identity'] == 'S-1-5-18' and
        holder['volume_root'] == volume and
        holder['events_scope'] == 'unique_protected_system_only_ready_and_release' and
        all(holder[key] is True for key in ('alive_before_request', 'alive_after_response',
            'alive_after_readback', 'normal_release_confirmed')) and integer(holder['exit_code'], 0, 0),
        'installation holder custody/liveness/normal release differs')
    require(isinstance(holder['image_path'], str) and PureWindowsPath(holder['image_path']).is_absolute() and
        PureWindowsPath(holder['image_path']).name == 'usk_publisher_install_guard_holder.exe' and
        all(isinstance(holder[key], str) and re.fullmatch(r'[0-9a-f]{64}', holder[key])
            for key in ('image_sha256', 'project_sha256', 'ready_sha256')),
        'current native installation holder executable/build binding differs')
    return ready['operation_inspection_ref']


def conflict_projection(native, response, request_id, reference):
    require(isinstance(native, dict) and native.keys() == {
        'schema', 'status', 'error', 'error_code', 'operation_inspection_ref', 'process_id', 'registered_admission'} and
        native['schema'] == 'usk.publisher_lab_service_observation.v1' and native['status'] == 'failed' and
        native['error_code'] == 'operation_conflict' and native['operation_inspection_ref'] == reference and
        isinstance(native['error'], str) and 0 < len(native['error']) <= 4096,
        'authenticated native installation mutex refusal differs')
    require(response == {'schema': 'usk.oneshot_response.v1', 'request_id': request_id,
        'status': 'refused', 'error': {'code': 'operation_conflict'}, 'result': {
            'schema': 'usk.publisher_operation_diagnostic.v1', 'error_code': 'operation_conflict',
            'inspection_reference': reference}}, 'public installation mutex refusal/inspection projection differs')


def reconcile(observation, volume):
    record = observation['installation_guard_conflict']
    require(isinstance(record, dict) and record.keys() == {
        'schema', 'scope', 'profile_qualified', 'publication_authority_granted', 'source_free',
        'verify_payload', 'before_readback_index', 'after_release_readback_index', 'holder',
        'client_capture', 'response', 'exit_code', 'native_observation', 'after_refusal_readback'} and
        record['schema'] == 'usk.publisher_install_guard_conflict.v1' and record['scope'] == SCOPE and
        record['profile_qualified'] is False and record['publication_authority_granted'] is False and
        record['source_free'] is True and observation['source_free'] is True and
        integer(record['before_readback_index'], 2, 2) and integer(record['after_release_readback_index'], 3, 3) and
        integer(record['exit_code'], 4, 4), 'bounded installation mutex conflict record differs')
    installed = observation['apply']['result']['payload']
    reference = holder_binding(record['holder'], observation, volume, installed['install_id'])
    payload = record['verify_payload']
    verified = observation['verification']['result']['payload']
    require(isinstance(payload, dict) and payload.keys() == {
        'schema', 'request_id', 'install_id', 'transaction_id', 'report_id', 'verified_at'} and
        payload['schema'] == 'usk.publisher_installed_verify_request.v1' and
        payload['install_id'] == installed['install_id'] and payload['transaction_id'] == installed['transaction_id'] and
        payload['report_id'] == verified['report_id'] and verified['status'] == 'pass',
        'contended/normal verification target and report differ')
    capture = record['client_capture']
    standard_capture(capture, observation['account_sid'], observation['machine_sha256'])
    require(capture['command'] == 'installed.verify' and capture['request_id'] not in
        {item['request_id'] for item in observation['client_captures']} and
        (capture['process_id'], capture['creation_file_time']) not in
        {(item['process_id'], item['creation_file_time']) for item in observation['client_captures']} and
        capture['process_id'] != record['holder']['native_ready']['process_id'],
        'installation contender client aliases another operation or holder')
    raw = record['native_observation']
    require(isinstance(raw, dict) and raw.keys() == {'command', 'request_id', 'native_json', 'sha256'} and
        raw['command'] == capture['command'] and raw['request_id'] == capture['request_id'] and
        isinstance(raw['native_json'], str) and 0 < len(raw['native_json'].encode()) <= 4*1024*1024 and
        hashlib.sha256(raw['native_json'].encode()).hexdigest() == raw['sha256'],
        'actual native installation conflict response bytes differ')
    native = json.loads(raw['native_json'])
    conflict_projection(native, record['response'], capture['request_id'], reference)
    before = observation['readbacks'][2]['independent']
    client = observation['account_sid']
    admitted = registered_admission(native, observation['service'], observation['service_sid'], client,
        observation['service_sha256'], volume, before['volume_boundary']['root']['file_id'])
    positive = [json.loads(item['native_json']) for item in observation['native_observations']
        if item['command'] == 'installed.verify']
    require(len(positive) == 1, 'normal post-release native verification is missing')
    expected = dict(positive[0]['registered_admission']); expected.pop('process_id')
    actual = dict(admitted); actual.pop('process_id')
    require(actual == expected, 'installation conflict and normal verification admission differ')
    after = record['after_refusal_readback']
    rows = reader_rows(after, capture, client)
    require(rows == before['rows'] == observation['readbacks'][3]['independent']['rows'],
        'installation mutex refusal or post-release verification changed complete native rows')
    target = installed['target_root'].replace('/', '\\')
    native_rows(rows, target[:3], target, observation['service_sid'], client)
    native_boundary(after['independent']['volume_boundary'])
    require(after['independent']['volume_boundary'] == before['volume_boundary'] ==
        observation['readbacks'][3]['independent']['volume_boundary'],
        'installation mutex refusal or normal verification changed native volume boundary')
    return {'schema': 'usk.publisher_install_guard_conflict_reconciliation.v1',
        'status': 'bindings_consistent', 'scope': SCOPE, 'cases_checked': 1,
        'native_rows_unchanged': len(rows), 'source_free_verification_after_release': True,
        'public_wait_or_cancellation_qualified': False, 'live_holder_takeover_qualified': False,
        'profile_qualified': False, 'publication_authority_granted': False}
