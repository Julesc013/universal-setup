# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Reconcile approved initial Plan A / commit B / unchanged A native refusal."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from usk_bundle_apply_binding import BindingError, compose_binding
from publisher_standard_public_evidence import (
    canonical, installed_material, integer, native_boundary, native_rows,
    reader_rows, registered_admission, require, standard_capture)
from publisher_stale_plan_evidence import rows_digest
from publisher_installation_lease_evidence import snapshot as lease_snapshot


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def approved_initial_plans(observation):
    record = observation.get('changed_state_revision')
    require(isinstance(record, dict) and record.keys() == {
        'schema', 'scope', 'profile_qualified', 'publication_authority_granted',
        'plan_a_request', 'plan_a_response', 'apply_a', 'envelope_a_json',
        'planned_at_file_time', 'enrolled_at_file_time', 'enrollments', 'cases'} and
        record['schema'] == 'usk.publisher_changed_state_revision_probe.v1' and
        record['scope'] == 'approved_initial_plan_a_commit_b_apply_a_before_effects' and
        record['profile_qualified'] is False and record['publication_authority_granted'] is False,
        'changed-state qualification scope or complete record differs')
    original = observation['plan_request']
    authored = record['plan_a_request']
    expected = copy.deepcopy(original)
    require(isinstance(authored, dict) and isinstance(authored.get('request_id'), str) and
        re.fullmatch(r'planA\.[0-9a-f]{32}', authored['request_id']) and
        authored['request_id'] != original['request_id'], 'Plan A authored identity differs')
    expected['request_id'] = authored['request_id']
    expected['payload']['request_id'] = authored['request_id']
    require(authored == expected, 'Plan A differs from B beyond its real planning identity')
    text = record['envelope_a_json']
    require(isinstance(text, str) and 0 < len(text.encode('utf-8')) <= 1024*1024,
        'approved Plan A envelope byte budget differs')
    envelope = json.loads(text)
    apply = record['apply_a']
    try:
        rebuilt_apply, rebuilt_envelope = compose_binding(authored, record['plan_a_response'],
            acceptance_root=envelope['acceptance_root'], state_root=envelope['state_root'],
            transaction_id=apply['transaction_id'], applied_at=apply['applied_at'])
    except (BindingError, KeyError, TypeError) as error:
        require(False, 'Plan A actual native planning/binding refused: '+str(error))
    require(rebuilt_apply == apply and rebuilt_envelope == envelope and
        apply['transaction_id'] != observation['apply_request']['transaction_id'] and
        apply['reviewed_plan_digest'] != observation['apply_request']['reviewed_plan_digest'] and
        apply['plan_request']['install_id'] == observation['apply_request']['plan_request']['install_id'],
        'Plan A apply/envelope was substituted or does not name B installation')
    positive_capture = next(x for x in observation['client_captures'] if x['command'] == 'install_local.apply')
    times = [record['planned_at_file_time'], record['enrolled_at_file_time'], positive_capture['creation_file_time']]
    require(all(isinstance(x, str) and re.fullmatch(r'[1-9][0-9]{16,18}', x) for x in times) and
        int(times[0]) <= int(times[1]) < int(times[2]), 'Plans/enrollments were not completed before B dispatch')
    enrollments = record['enrollments']
    require(isinstance(enrollments, list) and len(enrollments) == 2, 'Both initial reviewed operations must be approved')
    for index, request in enumerate((apply, observation['apply_request'])):
        entry = enrollments[index]
        require(isinstance(entry, dict) and entry.keys() == {'schema', 'status', 'service', 'approval'} and
            entry['schema'] == 'usk.publisher_service_control.v1' and entry['status'] == 'reviewed_operation_enrolled' and
            entry['service'] == observation['service'], 'Actual administrative enrollment result differs')
        approval = entry['approval']
        require(isinstance(approval, dict) and approval.keys() == {'schema', 'registration_sha256',
            'target_admitted_sha256', 'caller_sid', 'request_sha256', 'envelope_sha256', 'envelope_size_bytes'} and
            approval['schema'] == 'usk.publisher_reviewed_operation_approval.v1' and
            approval['caller_sid'] == observation['account_sid'] and approval['request_sha256'] == digest(request) and
            all(isinstance(approval[key], str) and re.fullmatch(r'[0-9a-f]{64}', approval[key])
                for key in ('registration_sha256', 'target_admitted_sha256', 'envelope_sha256')) and
            integer(approval['envelope_size_bytes'], 1, 1024*1024), 'Administrative exact-request approval differs')
    approval_a, approval_b = [x['approval'] for x in enrollments]
    require(approval_a['envelope_sha256'] == hashlib.sha256(text.encode('utf-8')).hexdigest() and
        approval_a['envelope_size_bytes'] == len(text.encode('utf-8')) and
        all(approval_a[key] == approval_b[key] for key in ('registration_sha256', 'target_admitted_sha256', 'caller_sid')),
        'Approved envelopes differ from native registration/target/caller or Plan A bytes')
    return record, approval_a


def protected_enrollment_file(facts, service, request_sha, suffix):
    require(isinstance(facts, dict) and facts.keys() == {'file_id', 'native_name', 'owner_sid',
        'dacl_protected', 'attributes', 'reparse_tag', 'link_count', 'case_sensitive', 'dacl_aces'} and
        isinstance(facts['file_id'], str) and re.fullmatch(r'[0-9a-f]{16}:[0-9a-f]{32}', facts['file_id']) and
        isinstance(facts['native_name'], str) and facts['native_name'].endswith(
            '\\Universal Setup\\Publisher\\'+service+'.operation-'+request_sha+suffix) and
        facts['owner_sid'] == 'S-1-5-32-544' and facts['dacl_protected'] is True and
        integer(facts['attributes']) and not facts['attributes'] & (16 | 1024) and
        integer(facts['reparse_tag'], 0, 0) and integer(facts['link_count'], 1, 1) and
        facts['case_sensitive'] is False and isinstance(facts['dacl_aces'], list) and len(facts['dacl_aces']) == 2,
        'Held enrollment file native shape/ownership/path differs')
    aces = facts['dacl_aces']
    require(all(isinstance(x, dict) and x.keys() == {'type', 'flags', 'access_mask', 'sid'} and
        integer(x['type'], 0, 0) and integer(x['flags'], 0, 0) and integer(x['access_mask'], 0x1f01ff, 0x1f01ff)
        for x in aces) and {x['sid'] for x in aces} == {'S-1-5-18', 'S-1-5-32-544'},
        'Held enrollment file grants mutation outside administrative ownership')


def reconcile(observation, drive):
    record, approval = approved_initial_plans(observation)
    installed = observation['apply']['result']['payload']
    client = observation['account_sid']
    positives = [json.loads(x['native_json']) for x in observation['native_observations']
        if x['command'] == 'install_local.apply']
    require(len(positives) == 2, 'Original B completion/replay native evidence is incomplete')
    original_admission = dict(positives[0]['registered_admission'])
    original_admission.pop('process_id')
    require(all(approval[key] == original_admission[key] for key in ('registration_sha256', 'target_admitted_sha256')),
        'Plan A administrative approval differs from successful B registration')
    cases = record['cases']
    require(isinstance(cases, list) and len(cases) == 2 and [x.get('source_free') for x in cases] == [False, True],
        'Finite sourceful/source-free unchanged Plan A cases differ')
    reports = []
    requests = {x['request_id'] for x in observation['client_captures']}
    processes = {(x['process_id'], x['creation_file_time']) for x in observation['client_captures']}
    for index, case in enumerate(cases):
        require(case.keys() == {'source_free', 'client_capture', 'response', 'native_observation', 'readback'} and
            type(case['source_free']) is bool, 'Changed-state case is not closed')
        capture = case['client_capture']
        standard_capture(capture, client, observation['machine_sha256'])
        process = (capture['process_id'], capture['creation_file_time'])
        require(capture['command'] == 'install_local.apply' and capture['request_id'] not in requests and
            process not in processes, 'Changed-state client aliases another operation')
        requests.add(capture['request_id']); processes.add(process)
        public = case['response']
        require(public.keys() == {'schema', 'request_id', 'status', 'result', 'error'} and
            public['schema'] == 'usk.oneshot_response.v1' and public['request_id'] == capture['request_id'] and
            public['status'] == 'refused' and public['result'] is None and
            isinstance(public['error'], dict) and public['error'].keys() == {'code'} and
            public['error']['code'] == 'state_revision_stale',
            'Public unchanged Plan A refusal reason/effects status differs')
        raw = case['native_observation']
        require(raw.keys() == {'command', 'request_id', 'native_json', 'sha256'} and
            raw['command'] == capture['command'] and raw['request_id'] == capture['request_id'] and
            isinstance(raw['native_json'], str) and 0 < len(raw['native_json'].encode()) <= 4*1024*1024 and
            hashlib.sha256(raw['native_json'].encode()).hexdigest() == raw['sha256'],
            'Native changed-state response bytes/client binding differs')
        native = json.loads(raw['native_json'])
        require(native.keys() == {'schema', 'status', 'error', 'error_code', 'process_id',
            'registered_admission', 'reviewed_operation_admission'} and
            native['schema'] == 'usk.publisher_lab_service_observation.v1' and native['status'] == 'failed' and
            native['error_code'] == 'state_revision_stale' and isinstance(native['error'], str) and
            0 < len(native['error']) <= 4096, 'Native approved fresh-operation refusal differs')
        baseline = observation['readbacks'][index]['independent']
        root_id = baseline['volume_boundary']['root']['file_id']
        registered_admission(native, observation['service'], observation['service_sid'], client,
            observation['service_sha256'], observation['volume_root'], root_id)
        admitted = dict(native['registered_admission']); admitted.pop('process_id')
        require(admitted == original_admission, 'Plan A refusal changed B native registration')
        selected = native['reviewed_operation_admission']
        require(selected.keys() == {'schema', 'scope', 'approval', 'approval_sha256',
            'approval_file', 'envelope_sha256', 'envelope_file'} and
            selected['schema'] == 'usk.publisher_selected_reviewed_operation_observation.v1' and
            selected['scope'] == 'authenticated_exact_request_and_held_protected_enrollment_files' and
            selected['approval'] == approval and selected['approval_sha256'] == digest(approval) and
            selected['envelope_sha256'] == approval['envelope_sha256'], 'Actual selected Plan A approval differs')
        for field, suffix in (('approval_file', '.approval.json'), ('envelope_file', '.envelope.json')):
            protected_enrollment_file(selected[field], observation['service'], approval['request_sha256'], suffix)
        require(selected['approval_file']['file_id'] != selected['envelope_file']['file_id'],
            'Native approval and envelope files alias one another')
        reference = case['readback']['independent']['rows']
        require(reference.keys() == {'schema', 'baseline_readback_index', 'sha256'} and
            reference['schema'] == 'usk.publisher_native_rows_reference.v1' and
            integer(reference['baseline_readback_index'], index, index) and reference['sha256'] == rows_digest(baseline['rows']) and
            case['readback']['independent']['volume_boundary'] == baseline['volume_boundary'],
            'Plan A refusal changed native B inventory/boundary')
        expanded = dict(case['readback'], independent=dict(case['readback']['independent'], rows=baseline['rows']))
        rows = reader_rows(expanded, capture, client)
        native_boundary(expanded['independent']['volume_boundary'])
        native_rows(rows, drive, installed['target_root'].replace('/', '\\'), observation['service_sid'], client)
        installed_material(observation, rows, drive)
        lease_snapshot(rows, drive, installed, root_id)
        a_prefix = drive+'installation-operations\\install-'+digest(installed['install_id'])+'\\operation-'+digest(record['apply_a']['transaction_id'])
        require(not any(row['path'].startswith(a_prefix) for row in rows),
            'Refused fresh Plan A left durable operation intent or bootstrap material')
        snapshots = [json.loads(row['content_json']) for row in rows
            if row['path'] == drive+'publication\\journal\\lab-reviewed-plan.json' and not row['directory']]
        require(len(snapshots) == 1 and snapshots[0]['plan_envelope_sha256'] ==
            record['enrollments'][1]['approval']['envelope_sha256'],
            'Committed B protected snapshot differs from its enrolled envelope')
        bindings = []
        for row in rows:
            if not row['directory'] and row['path'].startswith(drive+'setup-state\\state\\installed\\'):
                value = json.loads(row['content_json'])
                if value['install_id'] == installed['install_id']:
                    bindings.append({'record': row['path'].rsplit('\\', 1)[1], 'sha256': digest(value)})
        revision = digest(sorted(bindings, key=lambda x: x['record']))
        require(bindings and revision != digest([]), 'Committed B installed revision did not actually change')
        reports.append({'source_free': case['source_free'], 'expected_revision': digest([]),
            'observed_revision': revision, 'unchanged_native_rows': len(rows), 'rows_sha256': reference['sha256'],
            'fresh_a_intent_absent': True})
    return {'schema': 'usk.publisher_changed_state_revision_reconciliation.v1', 'status': 'bindings_consistent',
        'scope': record['scope'], 'cases_checked': 2, 'cases': reports,
        'changed_state_revision_qualified': True, 'profile_qualified': False, 'publication_authority_granted': False}
