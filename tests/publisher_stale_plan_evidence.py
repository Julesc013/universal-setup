# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Bounded immutable-context refusals; no changed-revision or takeover verdict."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import re
import sys
from publisher_standard_public_evidence import (
    canonical, installed_material, integer, native_boundary, native_rows,
    reader_rows, registered_admission, require, standard_capture)
from publisher_installation_lease_evidence import snapshot as lease_snapshot


def rows_digest(rows):
    require(isinstance(rows, list) and 0 < len(rows) <= 10000, 'stale-plan native row budget differs')
    return hashlib.sha256(canonical(rows).encode('utf-8')).hexdigest()


def reconcile(observation, drive):
    record = observation.get('stale_plan_refusals')
    require(isinstance(record, dict) and record.keys() == {
        'schema', 'scope', 'profile_qualified', 'publication_authority_granted', 'cases'} and
        record['schema'] == 'usk.publisher_stale_plan_probe.v1' and
        record['scope'] == 'authenticated_immutable_apply_context_before_effects' and
        record['profile_qualified'] is False and record['publication_authority_granted'] is False,
        'stale-plan fixture scope differs')
    cases = record['cases']
    fields = ('reviewed_plan_digest', 'plan_request.request_id', 'transaction_id', 'applied_at')
    require(isinstance(cases, list) and len(cases) == 4 and
        tuple(case['field'] for case in cases) == fields, 'finite stale-plan case set differs')
    original = observation['apply_request']
    installed = observation['apply']['result']['payload']
    client = observation['account_sid']
    successful_native = [json.loads(entry['native_json']) for entry in observation['native_observations']
        if entry['command'] == 'install_local.apply'][0]
    original_admission = dict(successful_native['registered_admission'])
    original_admission.pop('process_id')
    used_requests = {capture['request_id'] for capture in observation['client_captures']}
    used_processes = {(capture['process_id'], capture['creation_file_time'])
        for capture in observation['client_captures']}
    reports = []
    for index, case in enumerate(cases):
        require(case.keys() == {'field', 'source_free', 'apply_request', 'client_capture',
            'response', 'native_observation', 'readback'} and
            case['source_free'] is (index >= 2), 'stale-plan context/case is not closed')
        expected = copy.deepcopy(original)
        changed = case['apply_request']
        field = case['field']
        if field == 'plan_request.request_id':
            value = changed['plan_request']['request_id']
            require(isinstance(value, str) and re.fullmatch(r'stale\.[0-9a-f]{32}', value),
                'stale plan request identity differs')
            expected['plan_request']['request_id'] = value
        else:
            value = changed[field]
            expected[field] = value
            if field == 'reviewed_plan_digest':
                require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value),
                    'stale reviewed digest is invalid')
            elif field == 'transaction_id':
                require(isinstance(value, str) and re.fullmatch(r'stale\.[0-9a-f]{32}', value),
                    'stale transaction identity differs')
            else:
                require(value == '2000-01-01T00:00:00Z', 'stale applied time differs')
        require(changed == expected and changed != original, 'stale request changed an unqualified field')
        capture = case['client_capture']
        standard_capture(capture, client, observation['machine_sha256'])
        process = (capture['process_id'], capture['creation_file_time'])
        require(capture['command'] == 'install_local.apply' and capture['request_id'] not in used_requests and
            process not in used_processes, 'stale client aliases a different operation')
        used_requests.add(capture['request_id'])
        used_processes.add(process)
        public = case['response']
        require(isinstance(public, dict) and public.keys() == {'schema', 'request_id', 'status', 'result', 'error'} and
            public['schema'] == 'usk.oneshot_response.v1' and public['request_id'] == capture['request_id'] and
            public['status'] == 'refused' and public['result'] is None and
            isinstance(public['error'], dict) and public['error'].keys() == {'code'} and
            public['error']['code'] == 'stale_plan', 'stale public refusal/code/privacy differs')
        native_capture = case['native_observation']
        require(isinstance(native_capture, dict) and native_capture.keys() == {
            'command', 'request_id', 'native_json', 'sha256'} and
            native_capture['command'] == capture['command'] and native_capture['request_id'] == capture['request_id'] and
            isinstance(native_capture['native_json'], str) and 0 < len(native_capture['native_json'].encode()) <= 4*1024*1024 and
            hashlib.sha256(native_capture['native_json'].encode()).hexdigest() == native_capture['sha256'],
            'stale native response bytes/client binding differs')
        native = json.loads(native_capture['native_json'])
        require(native.keys() == {'schema', 'status', 'error', 'error_code', 'process_id', 'registered_admission'} and
            native['schema'] == 'usk.publisher_lab_service_observation.v1' and native['status'] == 'failed' and
            native['error_code'] == 'stale_plan' and isinstance(native['error'], str) and 0 < len(native['error']) <= 4096,
            'native stale refusal/effects status differs')
        baseline_index = 1 if case['source_free'] else 0
        baseline = observation['readbacks'][baseline_index]['independent']
        root_id = baseline['volume_boundary']['root']['file_id']
        registered_admission(native, observation['service'], observation['service_sid'], client,
            observation['service_sha256'], observation['volume_root'], root_id)
        admitted = dict(native['registered_admission'])
        admitted.pop('process_id')
        require(admitted == original_admission, 'stale refusal changed registered admission')
        readback = case['readback']
        reference = readback['independent']['rows']
        require(isinstance(reference, dict) and reference.keys() == {'schema', 'baseline_readback_index', 'sha256'} and
            reference['schema'] == 'usk.publisher_native_rows_reference.v1' and
            integer(reference['baseline_readback_index'], baseline_index, baseline_index) and
            reference['sha256'] == rows_digest(baseline['rows']), 'stale native row reference differs')
        require(readback['independent']['volume_boundary'] == baseline['volume_boundary'],
            'stale refusal changed native volume boundary')
        expanded = dict(readback, independent=dict(readback['independent'], rows=baseline['rows']))
        rows = reader_rows(expanded, capture, client)
        native_boundary(expanded['independent']['volume_boundary'])
        native_rows(rows, drive, installed['target_root'].replace('/', '\\'), observation['service_sid'], client)
        installed_material(observation, rows, drive)
        lease_snapshot(rows, drive, installed, root_id)
        reports.append({'field': field, 'source_free': case['source_free'],
            'unchanged_native_rows': len(rows), 'rows_sha256': reference['sha256']})
    return {'schema': 'usk.publisher_stale_plan_reconciliation.v1', 'status': 'bindings_consistent',
        'scope': record['scope'], 'cases_checked': len(reports), 'cases': reports,
        'changed_state_revision_qualified': False, 'profile_qualified': False,
        'publication_authority_granted': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rows-digest', action='store_true', required=True)
    parser.parse_args()
    raw = sys.stdin.buffer.read(4*1024*1024+1)
    require(len(raw) <= 4*1024*1024, 'stale native rows exceed input bound')
    print(rows_digest(json.loads(raw.decode('utf-8-sig'))))


if __name__ == '__main__':
    main()
