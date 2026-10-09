# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Reconcile retained initial intent; JSON cannot grant native restoration."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import PureWindowsPath
import re
import sys

from publisher_execution_evidence import canonical_sha, closed, integer, require
from publisher_process_pair_evidence import original_provenance


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'initial retained JSON key repeats')
        result[key] = value
    return result


def record(row, path, bound, canonical_record=True):
    require(isinstance(row, dict) and row.get('path') == path and row.get('directory') is False,
            'initial retained record path/type differs')
    text = row.get('content_json')
    require(isinstance(text, str), 'initial retained record bytes are absent')
    raw = text.encode('utf-8')
    require(0 < len(raw) <= bound and hashlib.sha256(raw).hexdigest() == row.get('sha256'),
            'initial retained record bytes/hash differ')
    value = json.loads(text, object_pairs_hook=unique_object)
    # TransactionSession writes its own ordered snapshot without a final LF.
    # Protected original context, roots and custody use canonical JSON plus LF.
    if canonical_record:
        require(canonical(value) + '\n' == text, 'initial retained record is not exact canonical bytes')
    return value


def path_equal(actual, expected):
    require(isinstance(actual, str) and '\0' not in actual and
            PureWindowsPath(actual).is_absolute() and '..' not in PureWindowsPath(actual).parts and
            str(PureWindowsPath(actual)) == str(PureWindowsPath(expected)),
            'initial retained reviewed root differs from the owned fixture')


def reconcile(value):
    closed(value, frozenset({'schema', 'drive', 'request', 'service_name', 'boundary',
                            'journal', 'original', 'context', 'roots'}), 'initial evidence input keys differ')
    require(value['schema'] == 'usk.publisher_initial_maintenance_evidence_input.v1' and
            isinstance(value['drive'], str) and re.fullmatch(r'[A-Z]:\\', value['drive']),
            'initial evidence fixture/schema differs')
    drive, request, boundary = value['drive'], value['request'], value['boundary']
    tx = request['transaction_id']
    require(request['schema'] == 'usk.repair_apply_request.v1' and
            re.fullmatch(r'maintenance\.repair\.[0-9a-f]{32}', tx) and request['confirmation'] == 'APPLY',
            'initial evidence is outside its original repair')
    install = request['plan_request']['install_id']
    require(isinstance(install, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', install),
            'initial evidence install identity differs')
    prefix = drive + 'installation-operations\\install-' + canonical_sha(install) + '\\operation-' + canonical_sha(tx)
    transactions = drive + 'setup-state\\state\\transactions\\' + tx
    context = record(value['context'], prefix + '.json', 16 * 1024 * 1024)
    roots = record(value['roots'], prefix + '-roots.json', 1024 * 1024)
    journal = record(value['journal'], transactions + '.journal.json', 4 * 1024 * 1024, False)
    original = record(value['original'], transactions + '.native-maintenance-original.json', 16 * 1024 * 1024)
    closed(context, frozenset({'schema', 'install_id', 'operation', 'operation_id', 'volume_root_identity',
        'initial_state_revision', 'reviewed_snapshot', 'context_sha256'}), 'initial context keys differ')
    closed(roots, frozenset({'schema', 'install_id', 'operation_id', 'context_sha256',
        'setup_root_identity', 'state_root_identity', 'roots_sha256'}), 'initial root binding keys differ')
    require(context['schema'] == 'usk.installation_operation_context.v2' and context['operation'] == 'repair' and
            context['operation_id'] == roots['operation_id'] == tx and
            context['install_id'] == roots['install_id'] == install and
            roots['schema'] == 'usk.installation_operation_roots.v1' and
            context['context_sha256'] == roots['context_sha256'] ==
                canonical_sha({k: v for k, v in context.items() if k != 'context_sha256'}) and
            roots['roots_sha256'] == original['original_context_sha256'] ==
                canonical_sha({k: v for k, v in roots.items() if k != 'roots_sha256'}),
            'initial original context/root digest linkage differs')
    snapshot = context['reviewed_snapshot']
    plan = snapshot['reviewed_plan']
    require(snapshot['schema'] == 'usk.publisher.maintenance_reviewed_snapshot.v2' and
            snapshot['operation'] == 'repair' and snapshot['operation_id'] == tx and
            snapshot['install_id'] == install and snapshot['apply_request'] == request and
            snapshot['initial_state_revision'] == context['initial_state_revision'] ==
                original['original_lease_ownership']['expected_state_revision'] and
            snapshot['volume_root_identity'] == context['volume_root_identity'] and
            snapshot['setup_root_identity'] == roots['setup_root_identity'] and
            snapshot['state_root_identity'] == roots['state_root_identity'] and
            plan['plan_id'] == request['reviewed_plan_id'] and canonical_sha(plan) == request['reviewed_plan_digest'],
            'initial snapshot lost its actual original reviewed request/plan/identities')
    expected_roots = {'target': drive + 'publication\\destination\\.usk-repair-' + tx,
        'staging': drive + 'setup-state\\staging\\.usk-stage-' + tx,
        'setup_state': drive + 'setup-state\\state', 'audit': drive + 'setup-state\\audit'}
    path_equal(snapshot['installed_state']['target_root'], drive + 'publication\\destination\\visible')
    path_equal(plan['staging_parent'], drive + 'setup-state\\staging')
    path_equal(plan['state_root'], expected_roots['setup_state'])
    path_equal(plan['audit_root'], expected_roots['audit'])
    require(journal['schema'] == 'usk.transaction_journal.v1' and journal['operation'] == 'repair' and
            journal['transaction_id'] == tx and journal['plan_id'] == request['reviewed_plan_id'] and
            journal['plan_digest'] == request['reviewed_plan_digest'] and journal['current_state'] == 'staging',
            'initial authoritative journal binding differs')
    require(isinstance(journal['roots'], list) and len(journal['roots']) == 4,
            'initial journal root count differs')
    roles = set()
    for root in journal['roots']:
        role = root['role']
        require(role in expected_roots and role not in roles, 'initial journal root role differs or repeats')
        roles.add(role)
        path_equal(root['root'], expected_roots[role])
    phases = ('created', 'validated', 'planned', 'staging')
    transitions = journal['transitions']
    require(isinstance(transitions, list) and len(transitions) == 4, 'initial journal transition count differs')
    chain = bytearray()
    for i, transition in enumerate(transitions):
        previous = None if i == 0 else phases[i - 1]
        require(integer(transition['sequence'], i, i) and transition['from'] == previous and
                transition['to'] == phases[i] and transition['transition_id'] == tx + '.' + str(i) and
                transition['durable_before_external_visibility'] is True and
                isinstance(transition['recorded_at'], str) and
                re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', transition['recorded_at']),
                'initial shared journal transition differs')
        chain.extend((str(i) + '\0' + (previous or '') + '\0' + phases[i] + '\0' +
                      transition['recorded_at'] + '\n').encode('utf-8'))
    require(journal['journal_digest'] == hashlib.sha256(chain).hexdigest() and
            journal['updated_at'] == transitions[-1]['recorded_at'], 'initial shared journal digest/time differs')
    metadata = journal['recovery_metadata']
    stream = metadata['stream_journal']
    closed(stream, frozenset({'version', 'source_digest', 'restart_origin', 'entries', 'source_context', 'digest'}),
           'initial stream fields differ')
    require(integer(stream['version'], 1, 1) and stream['restart_origin'] is None and
            stream['digest'] == canonical_sha({k: v for k, v in stream.items() if k != 'digest'}),
            'initial stream version/origin/digest differs')
    require(metadata['staging_identity'] is None and metadata['staged_files'] == [] and
            metadata['commit_cleanup_policy'] == metadata['stream_cleanup_policy'] == 'retain_only' and
            journal['recovery']['required'] is False and
            journal['recovery']['available_actions'] == ['retain_for_operator'] and isinstance(stream, dict) and
            stream['entries'] == [] and not stream.get('publication_root_identity') and
            isinstance(stream['source_context'], str) and
            hashlib.sha256(stream['source_context'].encode('utf-8')).hexdigest() == stream['source_digest'],
            'initial shared intent is outside the window before staging')
    source = json.loads(stream['source_context'], object_pairs_hook=unique_object)
    require(canonical(source) == stream['source_context'] and
            source['schema'] == 'usk.maintenance_source_context.v1' and source['operation'] == 'repair' and
            source['install_id'] == install and source['transaction_id'] == tx and
            source['plan_id'] == request['reviewed_plan_id'] and source['plan_digest'] == request['reviewed_plan_digest'] and
            source['applied_at'] == request['applied_at'] and
            source['original_installed_transaction_id'] == snapshot['installed_state']['transaction_id'] and
            source['original_installed_state_digest'] == plan['installed_state_digest'] and
            source['reviewed_plan_ref'] == tx + '.maintenance-plan.json' and
            isinstance(source['reviewed_plan_sha256'], str) and re.fullmatch('[0-9a-f]{64}', source['reviewed_plan_sha256']) and
            source['installed_root']['native_identity'] == original['installed_root_journal_identity'],
            'initial stream source lost its original plan/installed intent binding')
    path_equal(source['installed_root']['root'], snapshot['installed_state']['target_root'])
    path_equal(source['operation_target_root'], expected_roots['target'])
    for key in ('staging_parent', 'state_root', 'audit_root'):
        path_equal(source[key]['root'], plan[key])
    require(boundary['phase'] == 'maintenance_initial' and
            boundary['status'] == 'terminated_initial_maintenance_before_staging' and
            boundary['maintenance_transaction_id'] == tx and
            boundary['maintenance_plan_digest'] == request['reviewed_plan_digest'] and
            boundary['maintenance_writer_lease_ownership'] == original['original_lease_ownership'] and
            boundary['initial_snapshot_sha256'] == value['journal']['sha256'] and
            boundary['original_custody_sha256'] == value['original']['sha256'] and
            boundary['original_context_record_sha256'] == value['context']['sha256'] and
            boundary['original_roots_record_sha256'] == value['roots']['sha256'] and
            all(boundary[k] is False for k in ('staging_before_kill', 'staging_after_kill',
                                              'target_before_kill', 'target_after_kill')),
            'initial shared intent differs from the original ended-pair boundary')
    provenance = original_provenance(original, request, value['service_name'], boundary)
    return {'schema': 'usk.publisher_initial_maintenance_evidence.v1',
        'original_provenance': provenance, 'initial_snapshot_sha256': value['journal']['sha256'],
        'shared_initial_snapshot_checked': True, 'native_restoration_qualified': False,
        'profile_qualified': False, 'scope': 'retained_initial_intent_and_original_native_pair_closure'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', choices=('-',), required=True)
    parser.parse_args()
    raw = sys.stdin.buffer.read(48 * 1024 * 1024 + 1)
    require(len(raw) <= 48 * 1024 * 1024, 'initial retained evidence input exceeds bound')
    print(json.dumps(reconcile(json.loads(raw)), separators=(',', ':')))


if __name__ == '__main__':
    main()
