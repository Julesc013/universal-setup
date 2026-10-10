# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Classify exact original repair backups in failed-request diagnostics only.

This decoder confers no restoration, process closure, effect or release authority.
It keeps the ordinary protected-row policy and transaction acceptance separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import PureWindowsPath
import re
import sys

from publisher_authenticated_access_evidence import reconcile_client_capture
from publisher_effect_broker_evidence import validate_original_maintenance_provenance
from publisher_execution_evidence import canonical_sha, closed, integer, require
from publisher_initial_maintenance_evidence import canonical, path_equal, record, unique_object
from publisher_installation_lease_evidence import native_object
from publisher_standard_public_evidence import native_boundary, native_rows, reader_rows, standard_capture

INPUT_KEYS = frozenset({'schema', 'failure', 'capture', 'readback', 'case', 'drive',
    'service_name', 'service_sid', 'consumer_sid', 'machine_sha256'})
NATIVE_KEYS = frozenset({'schema', 'transaction_id', 'sequence', 'kind', 'details',
    'original_admission_sha256', 'original_context_sha256', 'original_lease_ownership_sha256',
    'plan_digest', 'transaction_snapshot_sha256', 'pending_history_sha256',
    'pending_intent_sequence', 'writer_lease_ownership', 'previous_record_sha256'})
EFFECT_KEYS = frozenset({'schema', 'transaction_id', 'sequence', 'phase', 'details',
    'source_digest', 'previous_digest', 'digest'})


def legacy_identity(obj):
    volume, file_id = obj['file_id'].split(':')
    require(re.fullmatch(r'[0-9a-f]{16}', volume) and re.fullmatch(r'[0-9a-f]{32}', file_id) and
        bytes.fromhex(file_id)[8:] == bytes(8), 'diagnostic legacy/native identity shape differs')
    return format(int(volume, 16) & 0xffffffff, '016x') + ':' + \
        format(int.from_bytes(bytes.fromhex(file_id)[:8], 'little'), '016x')


def reconcile(value):
    closed(value, INPUT_KEYS, 'failed backup diagnostic input keys differ')
    require(value['schema'] == 'usk.publisher_failed_repair_backup_input.v1' and
        isinstance(value['drive'], str) and re.fullmatch(r'[A-Z]:\\', value['drive']),
        'failed backup diagnostic fixture/schema differs')
    failure, capture, case = value['failure'], value['capture'], value['case']
    require(failure['scope'] == 'original_failed_request_before_cleanup' and
        failure['qualification_granted'] is False and failure['command'] == 'repair.apply' and
        capture['request_id'] == failure['request_id'] and capture['command'] == failure['command'] and
        capture['process_id'] == failure['client_process_id'] and
        capture['creation_file_time'] == failure['client_creation_file_time'] and
        case['operation'] == 'repair' and case['response'] is None,
        'diagnostic is outside its original failed repair')
    drive, service, consumer = value['drive'], value['service_sid'], value['consumer_sid']
    request = case['request']
    tx, install = request['transaction_id'], request['plan_request']['install_id']
    require(re.fullmatch(r'maintenance\.repair\.[0-9a-f]{32}', tx) and
        re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', install), 'failed repair identifiers differ')
    standard_capture(capture, consumer, value['machine_sha256'])
    independent = value['readback']['independent']
    exited = independent['effective_right_tokens']['captured_client']['exited_at_observation']
    require(type(exited) is bool, 'diagnostic client liveness observation absent')
    # A later readback liveness sample supplies no original deadline exit code.
    rows = reader_rows(value['readback'], capture, consumer, expected_exited=exited)
    require(isinstance(rows, list) and 0 < len(rows) <= 10000 and
        len({r['path'] for r in rows}) == len(rows) and
        len({r['file_id'] for r in rows}) == len(rows), 'diagnostic paths/identities alias')
    by_path = {r['path']: r for r in rows}
    native_boundary(independent['volume_boundary'])
    visible = drive + 'publication\\destination\\visible'
    target = drive + 'publication\\destination\\.usk-repair-' + tx
    transactions = drive + 'setup-state\\state\\transactions\\' + tx

    def read(path, bound=16 * 1024 * 1024, exact=True):
        require(path in by_path, 'required original diagnostic record is absent: ' + path)
        row = by_path[path]
        require(row['bytes'] == len(row['content_json'].encode('utf-8')),
            'diagnostic record byte length differs')
        return record(row, path, bound, exact)

    original_path = transactions + '.native-maintenance-original.json'
    original = read(original_path)
    provenance = validate_original_maintenance_provenance(original, request, value['service_name'])
    require(original['schema'] == 'usk.publisher.maintenance_original_custody.v4' and
        original['broker_readback']['service']['service_sid'] == service and
        original['authenticated_client']['user_sid'] == consumer,
        'diagnostic original service/consumer family differs')
    reconcile_client_capture(original['authenticated_client'], capture)
    completion = original['original_consumer_completion']
    closed(completion, frozenset({'schema', 'consumer_read_sid', 'install_id', 'original_transaction_id',
        'original_visible_root_file_id', 'setup_root', 'completion_record_sha256', 'reviewed_snapshot_sha256',
        'prepared_record_sha256', 'visible_record_sha256'}), 'diagnostic original consumer completion keys differ')
    require(completion['schema'] == 'usk.publisher.original_consumer_completion.v1' and
        completion['consumer_read_sid'] == consumer and completion['install_id'] == install and
        completion['original_visible_root_file_id'] == original['installed_root']['file_id'],
        'diagnostic original consumer completion differs')
    completed_records = {}
    for key, path in {'completion_record_sha256': 'publication\\state\\lab-installed-state.json',
        'reviewed_snapshot_sha256': 'publication\\journal\\lab-reviewed-plan.json',
        'prepared_record_sha256': 'publication\\journal\\lab-prepared-evidence.json',
        'visible_record_sha256': 'publication\\journal\\lab-visible-evidence.json'}.items():
        completed_records[key] = read(drive + path)
        require(by_path[drive + path]['sha256'] == completion[key], 'diagnostic consumer completion hash differs')
    original_reviewed = completed_records['reviewed_snapshot_sha256']
    original_prepared = completed_records['prepared_record_sha256']
    original_visible = completed_records['visible_record_sha256']
    original_completed = completed_records['completion_record_sha256']
    require(original_reviewed['schema'] == 'usk.publisher.lab_reviewed_plan_snapshot.v4' and
        original_reviewed['transaction_id'] == original_reviewed['apply_request']['transaction_id'] ==
            completion['original_transaction_id'] and
        original_reviewed['consumer_read_sid'] == consumer and original_reviewed['plan_request']['install_id'] == install,
        'diagnostic original consumer transaction differs from protected reviewed install')
    path_equal(original_reviewed['setup_root'], completion['setup_root'])
    path_equal(original_reviewed['target_root'], visible)
    require(original_reviewed['apply_request']['plan_request'] == original_reviewed['plan_request'] and
        original_reviewed['apply_request']['reviewed_plan_digest'] == original_reviewed['plan_digest'] and
        original_reviewed['plan_request']['archive']['expected_sha256'] == original_reviewed['archive_sha256'],
        'diagnostic original reviewed apply/source fields differ')
    path_equal(original_reviewed['plan_request']['target']['root'], visible)
    source_keys = ('archive_identity_digest', 'archive_sha256', 'entry_set_digest', 'plan_envelope_sha256')
    expected_source = {key: original_reviewed[key] for key in source_keys} | {
        'reviewed_plan_digest': original_reviewed['plan_digest'],
        'reviewed_plan_snapshot_sha256': completion['reviewed_snapshot_sha256']}
    require(original_prepared['source_binding'] == original_completed['source_binding'] == expected_source,
        'diagnostic protected completed source differs from original reviewed install')
    admission = original_prepared['operation_admission']
    closed(admission, frozenset({'schema', 'scope', 'route', 'transaction_id', 'reviewed_plan_digest',
        'reviewed_plan_snapshot_sha256', 'configured_caller_sid', 'service_name', 'service_sid', 'service_process_id',
        'captured_client_process_id', 'authenticated_client_sha256', 'publisher_image_sha256', 'registration_sha256',
        'target_admitted_sha256', 'root_file_id', 'volume_guid_root', 'volume_serial'}),
        'diagnostic original prepared admission keys differ')
    root_id = independent['volume_boundary']['root']['file_id']
    serial = int(root_id.split(':')[0], 16)
    require(admission['schema'] == 'usk.publisher_operation_admission.v1' and
        admission['scope'] == 'live_registered_request_and_held_volume_before_effects' and
        admission['route'] == 'registered_service_admitted_production' and
        admission['reviewed_plan_digest'] == original_reviewed['plan_digest'] and
        admission['reviewed_plan_snapshot_sha256'] == completion['reviewed_snapshot_sha256'] and
        admission['configured_caller_sid'] == consumer and admission['service_sid'] == service and
        admission['service_name'] == value['service_name'] and admission['root_file_id'] == root_id and
        integer(admission['volume_serial'], serial, serial),
        'diagnostic original prepared admission differs from reviewed consumer/service/volume')
    # These are prior retained admission fields, not current repair actors or
    # proof that a prior actor is still live. The decoder confers no admission.
    parent_path = str(PureWindowsPath(visible).parent)
    before_parent = [r for r in case['before']['independent']['rows'] if r['path'] == parent_path]
    require(len(before_parent) == 1 and before_parent[0]['directory'] is True,
        'diagnostic original visible parent is absent')
    for body, phase in ((original_prepared, 'lab_prepared_evidence'),
        (original_visible, 'lab_visible_evidence'), (original_completed, 'lab_installed_state')):
        require(body['phase'] == phase and body['destination_name'] == 'visible' and
            body['selected_file_set_digest'] == original_reviewed['selected_file_set_digest'] and
            body['destination_parent_file_id'] == before_parent[0]['file_id'],
            'diagnostic original protected completion role/selection/parent differs')
    require(integer(original_prepared['volume_serial'], serial, serial) and
        integer(original_completed['volume_serial'], serial, serial), 'diagnostic original completed native volume differs')
    require(original_completed['schema'] == 'usk.publisher.lab_installed_state.v2' and
        original_prepared['schema'] == original_visible['schema'] == 'usk.publisher.lab_phase_evidence.v11' and
        original_completed['prepared_record_sha256'] == original_visible['prepared_record_sha256'] ==
            completion['prepared_record_sha256'] and
        original_completed['visible_record_sha256'] == completion['visible_record_sha256'] and
        original_completed['source_binding'] == original_prepared['source_binding'] and
        original_completed['source_binding']['reviewed_plan_snapshot_sha256'] == completion['reviewed_snapshot_sha256'] and
        original_prepared['operation_admission']['transaction_id'] == completion['original_transaction_id'] and
        original_completed['visible_root_file_id'] == original_prepared['source_file_id'] ==
            original_visible['source_file_id'] == completion['original_visible_root_file_id'] and
        original_completed['service_sid'] == original_prepared['service_sid'] == service,
        'diagnostic original protected completion record lineage differs')
    prefix = drive + 'installation-operations\\install-' + canonical_sha(install) + '\\operation-' + canonical_sha(tx)
    context, roots = read(prefix + '.json'), read(prefix + '-roots.json', 1024 * 1024)
    closed(context, frozenset({'schema', 'install_id', 'operation', 'operation_id', 'volume_root_identity',
        'initial_state_revision', 'reviewed_snapshot', 'context_sha256'}), 'diagnostic context keys differ')
    closed(roots, frozenset({'schema', 'install_id', 'operation_id', 'context_sha256',
        'setup_root_identity', 'state_root_identity', 'roots_sha256'}), 'diagnostic roots keys differ')
    require(context['schema'] == 'usk.installation_operation_context.v2' and context['operation'] == 'repair' and
        roots['schema'] == 'usk.installation_operation_roots.v1' and
        context['operation_id'] == roots['operation_id'] == tx and
        context['install_id'] == roots['install_id'] == install and
        context['context_sha256'] == roots['context_sha256'] ==
            canonical_sha({k: v for k, v in context.items() if k != 'context_sha256'}) and
        roots['roots_sha256'] == original['original_context_sha256'] ==
            canonical_sha({k: v for k, v in roots.items() if k != 'roots_sha256'}),
        'diagnostic original context/root linkage differs')
    snapshot = context['reviewed_snapshot']
    plan = snapshot['reviewed_plan']
    # Match the existing lifecycle installed_digest projection, which excludes
    # schema and last_verification; hashing the whole record is a different contract.
    installed = snapshot['installed_state']
    closed(installed, frozenset({'schema', 'audit_chain_id', 'component_selection', 'created_at', 'entrypoints',
        'install_id', 'lifecycle_status', 'ownership_manifest_digest', 'ownership_manifest_ref', 'product_id',
        'product_version', 'recipe_digest', 'setup_abi', 'source_archive_digest', 'target_root', 'target_scope',
        'transaction_id', 'last_verification'}), 'diagnostic original installed-state keys differ')
    require(installed['schema'] == 'usk.installed_state.v1' and installed['target_scope'] == 'portable' and
        canonical_sha({k: v for k, v in installed.items() if k not in ('schema', 'last_verification')}) ==
            plan['installed_state_digest'] and installed['install_id'] == install and
        installed['ownership_manifest_digest'] == plan['ownership_manifest_digest'] and
        installed['source_archive_digest'] == original_reviewed['archive_sha256'],
        'diagnostic original installed-state digest/binding differs')
    path_equal(completion['setup_root'], drive + 'setup-state')
    require(completion['original_transaction_id'] == snapshot['installed_state']['transaction_id'],
        'diagnostic original consumer transaction differs')
    require(snapshot['schema'] == 'usk.publisher.maintenance_reviewed_snapshot.v2' and
        snapshot['operation'] == 'repair' and snapshot['operation_id'] == tx and snapshot['install_id'] == install and
        snapshot['apply_request'] == request and plan['plan_id'] == request['reviewed_plan_id'] and
        canonical_sha(plan) == request['reviewed_plan_digest'] and
        snapshot['installed_state']['target_root'] == visible and
        snapshot['setup_root_identity'] == roots['setup_root_identity'] and
        snapshot['state_root_identity'] == roots['state_root_identity'] and
        snapshot['volume_root_identity'] == context['volume_root_identity'] and
        snapshot['initial_state_revision'] == context['initial_state_revision'] ==
            original['original_lease_ownership']['expected_state_revision'],
        'diagnostic snapshot/request/state identities differ')
    for identity, row in ((context['volume_root_identity'], independent['volume_boundary']['root']),
        (roots['setup_root_identity'], by_path[drive + 'setup-state']),
        (roots['state_root_identity'], by_path[drive + 'setup-state\\state'])):
        require(row['file_id'] == format(int(identity['volume_serial']), '016x') + ':' + identity['file_id'],
            'diagnostic actual context/root native identity differs')
    volume_serial = independent['volume_boundary']['root']['file_id'].split(':')[0]
    require(all(r['file_id'].split(':')[0] == volume_serial for r in rows), 'diagnostic current volume differs')
    lease = original['original_lease_ownership']
    lease_path = drive + 'setup-state\\state\\leases\\install-' + canonical_sha(install) + '\\g' + \
        str(lease['generation']).zfill(20) + '-active.json'
    require(read(lease_path) == lease, 'diagnostic original active lease differs')
    journal_path = transactions + '.journal.json'
    journal = read(journal_path, 4 * 1024 * 1024, False)
    require(journal['schema'] == 'usk.transaction_journal.v1' and journal['operation'] == 'repair' and
        journal['transaction_id'] == tx and journal['plan_id'] == request['reviewed_plan_id'] and
        journal['plan_digest'] == request['reviewed_plan_digest'], 'diagnostic journal original binding differs')
    source_text = journal['recovery_metadata']['stream_journal']['source_context']
    source = json.loads(source_text, object_pairs_hook=unique_object)
    source_sha = hashlib.sha256(source_text.encode('utf-8')).hexdigest()
    require(canonical(source) == source_text and source['schema'] == 'usk.maintenance_source_context.v1' and
        source['operation'] == 'repair' and source['install_id'] == install and source['transaction_id'] == tx and
        source['plan_id'] == request['reviewed_plan_id'] and source['plan_digest'] == request['reviewed_plan_digest'] and
        source['applied_at'] == request['applied_at'] and source['reviewed_plan_ref'] == tx + '.maintenance-plan.json' and
        source['original_source_archive_digest'] == request['plan_request']['archive']['expected_sha256'] and
        source['original_installed_transaction_id'] == snapshot['installed_state']['transaction_id'] and
        source['original_installed_state_digest'] == plan['installed_state_digest'] and
        source['installed_root']['native_identity'] == original['installed_root_journal_identity'] and
        source_sha == journal['recovery_metadata']['stream_journal']['source_digest'],
        'diagnostic original source binding differs')
    path_equal(source['operation_target_root'], target)
    path_equal(source['installed_root']['root'], visible)
    for key in ('staging_parent', 'state_root', 'audit_root'):
        path_equal(source[key]['root'], plan[key])
    created_path = transactions + '.native-maintenance-created.json'
    created = read(created_path)
    closed(created, frozenset({'schema', 'transaction_id', 'plan_digest', 'original_context_sha256',
        'original_admission_sha256', 'lease_ownership_sha256', 'transaction_snapshot_sha256', 'source_context',
        'worker_security', 'process_boundary', 'registration_sha256', 'authenticated_client', 'root', 'root_parent',
        'target_parent', 'root_native_identity', 'created_objects'}), 'diagnostic created closure keys differ')

    def owned_relative(text, empty=False):
        require(isinstance(text, str) and ((empty and text == '') or
            (re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', text) and
             all(part not in ('.', '..') for part in text.split('/')))),
            'diagnostic relative path is not canonical')

    def observed_object(obj, path, *, directory):
        require(path in by_path and by_path[path]['directory'] is directory and
            obj['native_name'] == path[2:] and
            native_object(by_path[path]) == {k: v for k, v in obj.items() if k != 'native_name'},
            'diagnostic original native object/path/type differs')

    def journal_binding(doc):
        # Interpret the original shared journal's ordered bytes, independently
        # of its outer raw hash. This checks retained intent consistency only;
        # it does not apply recovery state floors or grant journal acceptance.
        require(doc['schema'] == 'usk.transaction_journal.v1' and doc['operation'] == 'repair' and
            doc['transaction_id'] == tx and doc['plan_id'] == request['reviewed_plan_id'] and
            doc['plan_digest'] == request['reviewed_plan_digest'], 'diagnostic native snapshot original binding differs')
        expected_roots = {'target': target, 'staging': drive + 'setup-state\\staging\\.usk-stage-' + tx,
            'setup_state': plan['state_root'], 'audit': plan['audit_root']}
        require(isinstance(doc['roots'], list) and len(doc['roots']) == 4 and
            {root['role'] for root in doc['roots']} == set(expected_roots), 'diagnostic native snapshot roots differ')
        for root in doc['roots']:
            closed(root, frozenset({'role', 'root', 'classification'}), 'diagnostic journal root keys differ')
            path_equal(root['root'], expected_roots[root['role']])
            require(root['classification'] == {'target': 'operator_selected_owned_target', 'staging': 'setup_owned',
                'setup_state': 'setup_owned', 'audit': 'audit_owned'}[root['role']],
                'diagnostic journal root classification differs')
        transitions = doc['transitions']
        require(isinstance(transitions, list) and 0 < len(transitions) <= 1000,
            'diagnostic native snapshot transition count differs')
        legal = {None: ('created',), 'created': ('validated',), 'validated': ('planned',), 'planned': ('staging',),
            'staging': ('staged', 'recovery_required', 'refused'), 'staged': ('verified', 'recovery_required', 'refused'),
            'verified': ('committing', 'recovery_required', 'refused'), 'committing': ('committed', 'recovery_required'),
            'committed': ('completed', 'recovery_required'),
            'recovery_required': ('committing', 'rolled_back', 'abandoned_by_operator')}
        prior, chain = None, bytearray()
        for i, transition in enumerate(transitions):
            closed(transition, frozenset({'sequence', 'transition_id', 'from', 'to', 'recorded_at',
                'durable_before_external_visibility'}), 'diagnostic native snapshot transition keys differ')
            require(integer(transition['sequence'], i, i) and transition['from'] == prior and
                transition['to'] in legal.get(prior, ()) and transition['transition_id'] == tx + '.' + str(i) and
                transition['durable_before_external_visibility'] is True and
                re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', transition['recorded_at']),
                'diagnostic native snapshot transition chain differs')
            chain.extend((str(i) + '\0' + (prior or '') + '\0' + transition['to'] + '\0' + transition['recorded_at'] + '\n').encode())
            prior = transition['to']
        require(doc['current_state'] == prior and doc['journal_digest'] == hashlib.sha256(chain).hexdigest() and
            doc['created_at'] == transitions[0]['recorded_at'] and
            doc['updated_at'] == transitions[-1]['recorded_at'], 'diagnostic native snapshot state/digest differs')
        stream = doc['recovery_metadata']['stream_journal']
        closed(stream, frozenset({'version', 'restart_origin', 'source_context', 'source_digest', 'entries', 'digest'}) |
            ({'publication_root_identity'} if stream['version'] == 2 else set()), 'diagnostic snapshot stream keys differ')
        require(integer(stream['version'], 1, 2) and stream['restart_origin'] is None and
            stream['source_context'] == source_text and stream['source_digest'] == source_sha and
            stream['digest'] == canonical_sha({k: v for k, v in stream.items() if k != 'digest'}),
            'diagnostic native snapshot stream/source differs')
        if stream['version'] == 2:
            require(stream['publication_root_identity'] == legacy_identity(created['root']),
                'diagnostic stream publication identity differs')
        require(isinstance(stream['entries'], list) and len(stream['entries']) <= 1000,
            'diagnostic stream entry count differs')
        paths = set()
        for entry in stream['entries']:
            closed(entry, frozenset({'expected_size', 'output_identity', 'phase', 'relative_path', 'sha256',
                'source_identity_digest'}), 'diagnostic stream entry keys differ')
            owned_relative(entry['relative_path'])
            require(entry['relative_path'] not in paths and entry['phase'] == 'complete' and
                entry['source_identity_digest'] == request['reviewed_plan_digest'],
                'diagnostic stream entry phase/source differs')
            paths.add(entry['relative_path'])
            objects = [obj for obj in created['created_objects'] if obj['relative_path'] == entry['relative_path']]
            require(len(objects) == 1 and entry['output_identity'] == objects[0]['native_identity'] ==
                legacy_identity(objects[0]['object']) and entry['expected_size'] == objects[0]['size_bytes'] and
                entry['sha256'] == objects[0]['sha256'], 'diagnostic stream output/created bytes differ')

    journal_binding(journal)
    artifact = read(transactions + '.maintenance-plan.json')
    require(artifact['reviewed_plan'] == plan and
        by_path[transactions + '.maintenance-plan.json']['sha256'] == source['reviewed_plan_sha256'],
        'diagnostic protected reviewed plan differs')
    require(created['schema'] == 'usk.publisher.maintenance_created_closure.v2' and
        created['transaction_id'] == tx and created['plan_digest'] == request['reviewed_plan_digest'] and
        created['original_admission_sha256'] == by_path[original_path]['sha256'] and
        created['original_context_sha256'] == roots['roots_sha256'] and
        created['lease_ownership_sha256'] == canonical_sha(lease) and created['source_context'] == source_text and
        created['authenticated_client'] == original['authenticated_client'] and
        created['registration_sha256'] == original['registration_sha256'] and
        created['worker_security'] == original['worker_security'] and
        created['process_boundary'] == original['process_boundary'], 'diagnostic created closure lost original joins')
    require(isinstance(created['created_objects'], list) and 0 < len(created['created_objects']) <= 1000 and
        created['root']['native_name'] == (drive + 'setup-state\\staging\\.usk-stage-' + tx)[2:],
        'diagnostic original created namespace differs')
    created_snapshot_path = transactions + '.native-maintenance-snapshots\\' + created['transaction_snapshot_sha256'] + '.json'
    journal_binding(read(created_snapshot_path, 4 * 1024 * 1024, False))
    require(by_path[created_snapshot_path]['sha256'] == created['transaction_snapshot_sha256'] and
        created['root_native_identity'] == legacy_identity(created['root']),
        'diagnostic created snapshot/root identity differs')
    observed_object(created['root_parent'], str(PureWindowsPath(drive + 'setup-state\\staging')), directory=True)

    def effect_binding(kind, body):
        keys = {'publish_target': {'native_identity'},
            'backup_file': {'relative_path', 'native_identity', 'sha256', 'size_bytes'},
            'replace_file': {'relative_path', 'native_identity', 'sha256', 'size_bytes'},
            'remove_file': {'root_role', 'relative_path', 'native_identity', 'sha256', 'size_bytes'},
            'remove_directory': {'root_role', 'relative_path', 'native_identity'},
            'write_ownership': {'manifest_id', 'prior_manifest_digest'},
            'write_installed': {'install_id', 'state_digest'} | ({'state_revision'} if 'state_revision' in body else set()),
            'append_audit': {'chain_id', 'input_digest'} | ({'input'} if 'input' in body else set())}
        closed(body, frozenset(keys[kind]), 'diagnostic effect body keys differ')
        require(len(canonical(body).encode()) <= 8192, 'diagnostic effect body exceeds bound')
        if 'relative_path' in body:
            owned_relative(body['relative_path'], kind == 'remove_directory')
        if 'native_identity' in body:
            require(re.fullmatch(r'[0-9a-f]{16}:[0-9a-f]{16}', body['native_identity']),
                'diagnostic effect native identity shape differs')
        for key in ('sha256', 'prior_manifest_digest', 'state_digest', 'input_digest'):
            if key in body:
                require(re.fullmatch(r'[0-9a-f]{64}', body[key]), 'diagnostic effect digest shape differs')
        if 'size_bytes' in body:
            require(integer(body['size_bytes'], 0, 1 << 32), 'diagnostic effect file size differs')
        if kind in ('remove_file', 'remove_directory'):
            require(body['root_role'] == 'operation_target', 'diagnostic repair removal role differs')
        if kind == 'publish_target':
            require(body['native_identity'] == created['root_native_identity'], 'diagnostic publication effect identity differs')
        if kind == 'replace_file':
            require({k: body[k] for k in ('relative_path', 'sha256', 'size_bytes')} in plan['replacement_files'],
                'diagnostic replacement is outside its reviewed plan')
        if kind == 'write_ownership':
            require(body['manifest_id'] == 'ownership.' + install + '.' + tx and
                body['prior_manifest_digest'] == plan['ownership_manifest_digest'],
                'diagnostic ownership intent differs from original reviewed plan')
        if kind == 'write_installed':
            require(body['install_id'] == install, 'diagnostic installed-state intent identity differs')
            if 'state_revision' in body:
                revision = body['state_revision']
                closed(revision, frozenset({'target_root', 'ownership_manifest_ref', 'ownership_manifest_digest',
                    'transaction_id', 'created_at', 'lifecycle_status', 'last_verification'}),
                    'diagnostic installed-state revision keys differ')
                closed(revision['last_verification'], frozenset({'report_id', 'report_digest', 'status', 'verified_at'}),
                    'diagnostic installed-state verification keys differ')
                require(revision['transaction_id'] == tx and re.fullmatch(r'[0-9a-f]{64}', revision['ownership_manifest_digest']) and
                    re.fullmatch(r'[0-9a-f]{64}', revision['last_verification']['report_digest']),
                    'diagnostic installed-state revision binding differs')
                path_equal(revision['target_root'], visible)
        if kind == 'append_audit':
            require(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', body['chain_id']), 'diagnostic audit chain identifier differs')
            if 'input' in body:
                closed(body['input'], frozenset({'created_at', 'operation', 'phase', 'status', 'subject_type',
                    'subject_id', 'details_digest', 'transaction_id', 'plan_id', 'message'}),
                    'diagnostic audit input keys differ')
                require(all(isinstance(x, str) for x in body['input'].values()) and
                    body['input_digest'] == canonical_sha(body['input']) and body['input']['operation'] == 'repair' and
                    body['input']['transaction_id'] == tx and body['input']['plan_id'] == request['reviewed_plan_id'],
                    'diagnostic audit input binding differs')

    def prefix_records(suffix, keys, schema, previous_key, canonical_link):
        directory = transactions + suffix + '\\'
        candidates = [p for p in by_path if p.startswith(directory)]
        require(0 < len(candidates) <= 1000, 'diagnostic record prefix absent or exceeds bound')
        result, previous = [], None
        for i, path in enumerate(sorted(candidates)):
            require(path == directory + str(i).zfill(20) + '.json', 'diagnostic record prefix gaps/repeats')
            doc = read(path, 1024 * 1024)
            closed(doc, keys, 'diagnostic record prefix keys differ')
            require(doc['schema'] == schema and integer(doc['sequence'], i, i) and
                doc['transaction_id'] == tx and doc[previous_key] == previous,
                'diagnostic record sequence/previous link differs')
            if canonical_link:
                require(doc['digest'] == canonical_sha({k: v for k, v in doc.items() if k != 'digest'}) and
                    doc['source_digest'] == source_sha, 'diagnostic effect digest/source differs')
                previous = doc['digest']
            else:
                require(doc['original_admission_sha256'] == by_path[original_path]['sha256'] and
                    doc['original_context_sha256'] == roots['roots_sha256'] and
                    doc['original_lease_ownership_sha256'] == canonical_sha(lease) and
                    doc['writer_lease_ownership'] == lease and doc['plan_digest'] == request['reviewed_plan_digest'],
                    'diagnostic native prefix original writer differs')
                snapshot_path = transactions + '.native-maintenance-snapshots\\' + doc['transaction_snapshot_sha256'] + '.json'
                saved = read(snapshot_path, 4 * 1024 * 1024, False)
                journal_binding(saved)
                require(by_path[snapshot_path]['sha256'] == doc['transaction_snapshot_sha256'] and
                    saved['transaction_id'] == tx and saved['plan_digest'] == request['reviewed_plan_digest'],
                    'diagnostic immutable native snapshot differs')
                previous = by_path[path]['sha256']
            result.append(doc)
        return result

    effects = prefix_records('.maintenance', EFFECT_KEYS, 'usk.maintenance_effect_record.v1', 'previous_digest', True)
    pending, completions, sealed = None, {}, False
    for i, effect in enumerate(effects):
        phase, details = effect['phase'], effect['details']
        require(not sealed, 'diagnostic effect record follows a seal')
        if i == 0:
            closed(details, frozenset({'source_context', 'directory_identity'}), 'diagnostic effect context keys differ')
            require(phase == 'context' and details['source_context'] == source_text,
                'diagnostic effect lacks its original source context')
            directory = transactions + '.maintenance'
            require(directory in by_path and by_path[directory]['directory'] is True and
                details['directory_identity'] == legacy_identity(by_path[directory]),
                'diagnostic effect context directory identity differs')
        elif phase == 'intent':
            closed(details, frozenset({'kind', 'effect'}), 'diagnostic effect intent keys differ')
            require(pending is None and details['kind'] in ('publish_target', 'backup_file', 'replace_file',
                'remove_file', 'remove_directory', 'write_ownership', 'write_installed', 'append_audit'),
                'diagnostic effect intent overlaps or has an unrecognized kind')
            effect_binding(details['kind'], details['effect'])
            pending = effect
        elif phase == 'complete':
            closed(details, frozenset({'intent_sequence', 'kind', 'outcome', 'result_digest'}),
                'diagnostic effect completion keys differ')
            require(pending is not None and integer(details['intent_sequence'], pending['sequence'], pending['sequence']) and
                details['kind'] == pending['details']['kind'] and
                (details['outcome'] == 'applied' or (details['kind'] == 'remove_directory' and details['outcome'] == 'retained')),
                'diagnostic effect completion contradicts its original intent')
            metadata = details['kind'] in ('write_ownership', 'write_installed', 'append_audit')
            require((isinstance(details['result_digest'], str) and re.fullmatch(r'[0-9a-f]{64}', details['result_digest']))
                if metadata else details['result_digest'] is None, 'diagnostic effect completion result differs')
            completions[pending['sequence']] = details
            pending = None
        elif phase == 'sealed':
            require(pending is None and details is None, 'diagnostic effect seal has unresolved intent')
            sealed = True
        else:
            require(False, 'diagnostic effect phase is unrecognized')
    native = prefix_records('.native-maintenance-custody', NATIVE_KEYS,
        'usk.publisher.maintenance_native_custody.v2', 'previous_record_sha256', False)
    require(effects[0]['phase'] == 'context' and effects[0]['details']['source_context'] == source_text and
        native[0]['kind'] == 'confirmed_publication' and
        native[0]['details']['created_closure_sha256'] == by_path[created_path]['sha256'],
        'diagnostic original publication/source closure differs')
    publication = native[0]['details']
    require(publication['root']['file_id'] == created['root']['file_id'] and
        {k: v for k, v in publication['root'].items() if k != 'native_name'} ==
            {k: v for k, v in created['root'].items() if k != 'native_name'} and
        publication['parent'] == created['target_parent'] and
        publication['parent']['native_name'] == str(PureWindowsPath(target).parent)[2:] and
        publication['root']['native_name'] == target[2:] and
        publication['publication_transaction_snapshot_sha256'] == native[0]['transaction_snapshot_sha256'] ==
            created['transaction_snapshot_sha256'] and native[0]['pending_intent_sequence'] is None and
        native[0]['pending_history_sha256'] is None, 'diagnostic original publication rename differs')
    ancestors = {publication['root']['native_name']: publication['root'],
        publication['parent']['native_name']: publication['parent']}
    confirmed = set()
    for n in native:
        require(n['kind'] in ('confirmed_publication', 'later_created_directory', 'confirmed_effect',
            'consumer_read_grant', 'created_metadata'), 'diagnostic native record kind is unrecognized')
        require(n['kind'] != 'confirmed_publication' or n is native[0], 'diagnostic publication repeats')
        detail_keys = {'confirmed_publication': {'root', 'parent', 'created_closure_sha256', 'publication_transaction_snapshot_sha256'},
            'later_created_directory': {'native_identity', 'object', 'parent', 'relative_path'},
            'confirmed_effect': {'effect_kind', 'effect_details', 'effect_transaction_snapshot_sha256', 'intent_sequence', 'outcome', 'result_digest'},
            'consumer_read_grant': {'before', 'after', 'parent', 'consumer_sid', 'native_identity', 'relative_path', 'root_role'},
            'created_metadata': {'object', 'parent', 'setup_relative_path', 'sha256', 'size_bytes'}}
        closed(n['details'], frozenset(detail_keys[n['kind']]), 'diagnostic native detail keys differ')
        if n['kind'] == 'later_created_directory':
            d = n['details']
            require(d['object']['native_name'] == target[2:] + '\\' + d['relative_path'].replace('/', '\\') and
                d['parent'] == ancestors.get(str(PureWindowsPath(d['object']['native_name']).parent)) and
                d['object']['native_name'] not in ancestors and d['native_identity'] == legacy_identity(d['object']),
                'diagnostic backup ancestor creation differs')
            owned_relative(d['relative_path'])
            ancestors[d['object']['native_name']] = d['object']
        if n['pending_intent_sequence'] is not None:
            i = n['pending_intent_sequence']
            require(integer(i, 1, len(effects) - 1) and effects[i]['phase'] == 'intent' and
                n['pending_history_sha256'] == effects[i]['digest'], 'diagnostic native pending intent differs')
        else:
            require(n['pending_history_sha256'] is None, 'diagnostic native null intent/history contradict')
        if n['kind'] != 'confirmed_publication':
            require(n['pending_intent_sequence'] is not None, 'diagnostic native effect lacks an original intent')
            intent = effects[n['pending_intent_sequence']]['details']
            if n['kind'] == 'later_created_directory':
                require(intent['kind'] == 'backup_file' and n['details']['relative_path'].split('/')[0] == 'backup',
                    'diagnostic created directory is outside original backup intent')
            if n['kind'] == 'consumer_read_grant':
                d = n['details']
                owned_relative(d['relative_path'])
                before_grant = d['before']
                after_grant = dict(before_grant, dacl_aces=before_grant['dacl_aces'] +
                    [{'access_mask': 1179817, 'flags': 0, 'sid': consumer, 'type': 0}])
                require(intent['kind'] == 'replace_file' and d['root_role'] == 'installed' and
                    d['relative_path'] == intent['effect']['relative_path'] and d['consumer_sid'] == consumer and
                    d['native_identity'] == intent['effect']['native_identity'] == legacy_identity(d['after']) and
                    d['after'] == after_grant, 'diagnostic consumer grant lost its original replacement/ACE binding')
                path = visible + '\\' + d['relative_path'].replace('/', '\\')
                observed_object(d['after'], path, directory=False)
                observed_object(d['parent'], str(PureWindowsPath(path).parent), directory=True)
                require(by_path[path]['sha256'] == intent['effect']['sha256'] and
                    by_path[path]['bytes'] == intent['effect']['size_bytes'], 'diagnostic consumer-granted replacement bytes differ')
            if n['kind'] == 'created_metadata':
                d = n['details']
                owned_relative(d['setup_relative_path'])
                require(intent['kind'] in ('write_ownership', 'write_installed', 'append_audit') and
                    integer(d['size_bytes'], 0, 4 * 1024 * 1024) and re.fullmatch(r'[0-9a-f]{64}', d['sha256']),
                    'diagnostic metadata creation differs from bounded original metadata intent')
                path = drive + 'setup-state\\' + d['setup_relative_path'].replace('/', '\\')
                observed_object(d['object'], path, directory=False)
                observed_object(d['parent'], str(PureWindowsPath(path).parent), directory=True)
                require(by_path[path]['bytes'] == d['size_bytes'] and by_path[path]['sha256'] == d['sha256'],
                    'diagnostic created metadata bytes differ')
                if intent['kind'] == 'write_ownership':
                    require(d['setup_relative_path'] == 'state/ownership/' + intent['effect']['manifest_id'] + '.json',
                        'diagnostic ownership creation path differs')
        if n['kind'] == 'confirmed_effect':
            d, i = n['details'], n['pending_intent_sequence']
            require(i is not None and d['intent_sequence'] == i and d['outcome'] == 'applied' and
                d['effect_kind'] == effects[i]['details']['kind'] and
                d['effect_details'] == effects[i]['details']['effect'] and
                d['effect_transaction_snapshot_sha256'] == n['transaction_snapshot_sha256'] and i not in confirmed,
                'diagnostic confirmed native effect differs from its actual intent')
            confirmed.add(i)
            require((isinstance(d['result_digest'], str) and re.fullmatch(r'[0-9a-f]{64}', d['result_digest']))
                if d['effect_kind'] in ('write_ownership', 'write_installed', 'append_audit') else d['result_digest'] is None,
                'diagnostic native confirmation result shape differs')
            if i in completions:
                require(all(d[key] == completions[i][key] for key in ('outcome', 'result_digest')),
                    'diagnostic native/effect completion contradict each other')
    require(all(i in confirmed or completion['kind'] == 'publish_target' for i, completion in completions.items()),
        'diagnostic completed effect lacks its original native confirmation')
    for name, obj in ancestors.items():
        path = drive[:2] + name
        require(path in by_path and by_path[path]['directory'] is True and obj['attributes'] & 16 and
            not obj['attributes'] & 1024 and obj['reparse_tag'] == 0 and
            native_object(by_path[path]) == {k: v for k, v in obj.items() if k != 'native_name'},
            'diagnostic current native ancestor differs')

    before_rows = case['before']['independent']['rows']
    require(case['before']['observer_task_removed'] is True and
        case['before']['independent']['identity'] == 'S-1-5-18' and
        case['before']['independent']['observer_token_handles_closed'] is True,
        'diagnostic original before reader closure differs')
    native_rows(before_rows, drive, visible, service, consumer)
    before = {r['path']: r for r in before_rows}
    require(len(before) == len(before_rows), 'diagnostic original before paths repeat')
    require(visible in before and before[visible]['directory'] is True and
        original['installed_root']['native_name'] == visible[2:] and
        native_object(before[visible]) == {k: v for k, v in original['installed_root'].items() if k != 'native_name'} and
        legacy_identity(original['installed_root']) == original['installed_root_journal_identity'],
        'diagnostic original installed root differs from its before-row')
    root_joins = [(source['installed_root'], visible, before),
        (source['installed_root']['parent'], str(PureWindowsPath(visible).parent), before),
        (source['operation_target_parent'], str(PureWindowsPath(target).parent), by_path)]
    root_joins.extend((source[key], str(PureWindowsPath(plan[key])), by_path)
        for key in ('staging_parent', 'state_root', 'audit_root'))
    for observed, path, namespace in root_joins:
        path_equal(observed['root'], path)
        require(path in namespace and namespace[path]['directory'] is True and
            observed['native_identity'] == legacy_identity(namespace[path]),
            'diagnostic recorded native source root/parent identity differs')
    backups = {}
    for effect in effects:
        if effect['phase'] != 'intent' or effect['details'].get('kind') != 'backup_file':
            continue
        detail = effect['details']['effect']
        relative = detail['relative_path']
        require(re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', relative) and
            all(p not in ('.', '..') for p in relative.split('/')), 'diagnostic backup path is not canonical')
        originals = [o for o in original['original_objects'] if o['relative_path'] == relative]
        require(len(originals) == 1, 'diagnostic backup has no unique admitted original')
        old = originals[0]
        require(old['present'] is True and old['type'] == 'file' and
            detail == {k: old[k] for k in ('relative_path', 'native_identity', 'sha256', 'size_bytes')},
            'diagnostic backup intent is not its original bytes/identity')
        require(old['native_identity'] == legacy_identity(old['object']),
            'diagnostic original legacy/native file identity differs')
        confirmations = [n for n in native if n['kind'] == 'confirmed_effect' and
            n['details'].get('effect_kind') == 'backup_file' and n['pending_intent_sequence'] == effect['sequence']]
        require(len(confirmations) == 1 and confirmations[0]['details']['outcome'] == 'applied' and
            confirmations[0]['details']['effect_details'] == detail and
            confirmations[0]['details']['intent_sequence'] == effect['sequence'],
            'diagnostic backup has no exact native confirmation')
        path = target + '\\backup\\' + relative.replace('/', '\\')
        prior_path = visible + '\\' + relative.replace('/', '\\')
        require(path in by_path and path not in backups and prior_path in before, 'diagnostic backup current/before path differs')
        row, prior = by_path[path], before[prior_path]
        prior_parent = str(PureWindowsPath(prior_path).parent)
        require(old['object']['native_name'] == prior_path[2:] and prior_parent in before and
            old['parent']['native_name'] == prior_parent[2:] and
            native_object(before[prior_parent]) == {k: v for k, v in old['parent'].items() if k != 'native_name'} and
            native_object(prior) == {k: v for k, v in old['object'].items() if k != 'native_name'},
            'diagnostic original payload namespace/parent differs')
        damage = case['damage']
        require(damage['schema'] == 'usk.publisher.owned_payload_damage.v1' and damage['identity'] == 'S-1-5-18' and
            damage['path'] == prior_path and damage['bytes'] == old['size_bytes'] and
            damage['before_sha256'] == prior['sha256'] and damage['after_sha256'] == old['sha256'],
            'diagnostic backup is outside the original controlled damage')
        require(row['directory'] is False and row['native_name'] == path[2:] and
            native_object(row) == {k: v for k, v in old['object'].items() if k != 'native_name'} and
            prior['file_id'] == row['file_id'] and row['bytes'] == old['size_bytes'] and row['sha256'] == old['sha256'] and
            row['raw_security'] == prior['raw_security'] and row['owner_dacl_sha256'] == prior['owner_dacl_sha256'] and
            row['effective_right_group_sid'] == 'S-1-5-18' and
            str(PureWindowsPath(row['native_name']).parent) in ancestors,
            'diagnostic backup object/bytes/raw descriptor/ancestor differs')
        expected_aces = '(A;;FA;;;SY)(A;;FA;;;' + service + ')(A;;0x1200a9;;;' + consumer + ')'
        require(row['raw_security'] in ('O:SYD:P' + expected_aces, 'O:SYD:PAI' + expected_aces) and
            re.fullmatch(r'[0-9a-f]{64}', row['owner_dacl_sha256']),
            'diagnostic backup ordered SDDL differs from its raw ACEs')
        # The exact admitted file is the only payload role here. No prefix-wide
        # consumer grant, directory exception or rewritten observation is used.
        native_rows([row], drive, path, service, consumer)
        require(all(row['effective_rights'][actor]['maximum_allowed'] ==
            {'requested': 0x2000000, 'allowed': True, 'granted': 1179817}
            for actor in ('initiating', 'filtered')), 'diagnostic backup consumer maximum differs')
        backups[path] = {'file_id': row['file_id'], 'bytes': row['bytes'], 'sha256': row['sha256'],
            'original_native_identity': old['native_identity'], 'owner_dacl_sha256': row['owner_dacl_sha256']}
    require(backups, 'diagnostic has no confirmed original backup payload')
    native_rows([r for r in rows if r['path'] not in backups], drive, visible, service, consumer)
    return {'schema': 'usk.publisher_failed_repair_backup_diagnostic.v1',
        'scope': 'original_failed_repair_backup_roles_only', 'request_id': failure['request_id'],
        'transaction_id': tx, 'backups': backups, 'retained_original_provenance': provenance,
        'qualification_granted': False, 'native_restoration_qualified': False,
        'operation_completion_qualified': False, 'whole_target_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(16 * 1024 * 1024 + 1) if args.input == '-' else open(args.input, 'rb').read(16 * 1024 * 1024 + 1)
        require(0 < len(raw) <= 16 * 1024 * 1024, 'failed diagnostic input exceeds bound')
        print(json.dumps(reconcile(json.loads(raw, object_pairs_hook=unique_object)), sort_keys=True, separators=(',', ':')))
    except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
        print('original failed repair backup diagnostic refused: ' + str(error)[:4096], file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
