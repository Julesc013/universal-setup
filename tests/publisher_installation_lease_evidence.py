# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Bounded independent record/append reconciliation. No native authority grant."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


class LeaseEvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LeaseEvidenceError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def root(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{16}:[0-9a-f]{32}', value), 'native root identity absent')
    require(int(value[:16], 16) and int(value[17:], 16), 'native root identity zero')
    return {'file_id': value[17:], 'volume_serial': str(int(value[:16], 16))}


def document(row):
    text = row.get('content_json')
    require(row.get('directory') is False and isinstance(text, str) and 0 < len(text.encode('utf-8')) <= 4 * 1024 * 1024,
            'coordination record is not bounded regular JSON')
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'coordination JSON member duplicated')
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=pairs)
    require(canonical(value) + '\n' == text and row['sha256'] == hashlib.sha256(text.encode('utf-8')).hexdigest() and
            row['bytes'] == len(text.encode('utf-8')), 'coordination canonical bytes/readback differ')
    return value


def native_object(row):
    fields = ('file_id', 'attributes', 'link_count', 'case_sensitive')
    require(all(key in row for key in fields) and 'owner' in row and 'protected' in row and 'raw_aces' in row,
            'retained bootstrap lacks independent native facts')
    return dict((key, row[key]) for key in fields) | {'owner_sid': row['owner'],
        'dacl_protected': row['protected'], 'reparse_tag': row.get('reparse_tag', 0), 'dacl_aces': row['raw_aces']}


def bootstrap_history(by_path, drive, context_directory, context_path, context, roots, volume_root_id, history):
    prefix = context_path[:-5]
    all_rows = [row for path, row in by_path.items() if path.startswith(context_directory + '\\')]
    reservation_rows = sorted((row for row in all_rows if row['path'].startswith(prefix + '-bootstrap-')),
                              key=lambda row: row['path'])
    require(0 < len(reservation_rows) <= 64, 'current producer lacks bounded bootstrap reservations')
    active = {value['generation']: value for value in history if value['status'] == 'active'}
    expected_files, expected_directories = set(), set()
    for index, row in enumerate(reservation_rows):
        reserved = document(row)
        require(reserved.keys() == {'schema', 'install_id', 'operation_id', 'context_sha256', 'roots_sha256',
                'volume_root_identity', 'ownership', 'publication_absent', 'reservation_sha256'},
                'bootstrap reservation is not closed')
        ownership = reserved['ownership']
        require(isinstance(ownership, dict) and type(ownership.get('generation')) is int and
                ownership == active.get(ownership['generation']), 'bootstrap reserved ownership is not a native journal record')
        generation = ownership['generation']
        require(row['path'] == prefix + f'-bootstrap-g{generation:020d}.json' and
                reserved['schema'] == 'usk.publication_bootstrap_reservation.v1' and
                reserved['install_id'] == context['install_id'] and reserved['operation_id'] == context['operation_id'] and
                reserved['context_sha256'] == context['context_sha256'] and reserved['roots_sha256'] == roots['roots_sha256'] and
                reserved['volume_root_identity'] == root(volume_root_id) and reserved['publication_absent'] is True and
                reserved['reservation_sha256'] == digest({key: value for key, value in reserved.items() if key != 'reservation_sha256'}),
                'bootstrap reservation attempt/root/seal differs')
        expected_files.add(row['path'])
        move_path = prefix + f'-preserve-g{generation:020d}.json'
        retained_path = prefix + f'-retained-g{generation:020d}'
        require(index != len(reservation_rows) - 1 or move_path not in by_path,
                'current live publication lacks an undisposed creation reservation')
        prepared_path = drive + 'publication\\journal\\lab-prepared-evidence.json'
        if index == len(reservation_rows) - 1 and prepared_path in by_path:
            prepared = document(by_path[prepared_path])
            origin = prepared.get('execution_origin')
            require(origin in ('created_empty_in_current_worker', 'reopened_staged_tree'),
                    'live publication has unknown native execution origin')
            if origin == 'created_empty_in_current_worker':
                require(isinstance(prepared.get('execution_phases'), list) and prepared['execution_phases'],
                        'live publication creation phases absent')
                execution = prepared['execution_phases'][0]['execution']
                if prepared.get('schema') in ('usk.publisher.lab_phase_evidence.v10', 'usk.publisher.lab_phase_evidence.v11'):
                    from publisher_effect_broker_evidence import validate_active_child_lease, validate_effect_execution_identity
                    require(execution['schema'] == ('usk.publisher_execution_observation.v8' if prepared['schema'] == 'usk.publisher.lab_phase_evidence.v11' else 'usk.publisher_execution_observation.v7'),
                            'child reservation lost its child execution family')
                    require(prepared['protected_anchors']['boundary']['file_id'] == volume_root_id,
                            'child reservation changed its independently bound native volume')
                    validate_effect_execution_identity(execution, execution['service']['service_name'],
                        prepared['service_sid'], prepared['protected_anchors']['boundary'])
                    validate_active_child_lease(ownership, execution['broker_readback'])
                else:
                    require(execution['service']['process_id'] == ownership['holder']['process_id'],
                            'live publication creation worker differs from its reserved native ownership')
        if move_path not in by_path:
            require(index == len(reservation_rows) - 1, 'earlier bootstrap reservation lacks a durable disposition')
            continue
        move = document(by_path[move_path])
        expected_files.add(move_path)
        require(move.get('install_id') == context['install_id'] and move.get('operation_id') == context['operation_id'] and
                move.get('reservation_sha256') == reserved['reservation_sha256'] and
                move.get('preservation_sha256') == digest({key: value for key, value in move.items() if key != 'preservation_sha256'}),
                'bootstrap preservation scope/seal differs')
        if move.get('schema') == 'usk.publication_bootstrap_absence.v1':
            require(move.keys() == {'schema', 'install_id', 'operation_id', 'reservation_sha256',
                    'closing_ownership', 'publication_absent', 'preservation_sha256'} and move['publication_absent'] is True and
                    isinstance(move['closing_ownership'], dict) and type(move['closing_ownership'].get('generation')) is int and
                    move['closing_ownership'] == active.get(move['closing_ownership']['generation']) and
                    move['closing_ownership']['generation'] > generation,
                    'bootstrap absence disposition is not bound to later native ownership')
            continue
        require(move.get('schema') == 'usk.publication_bootstrap_preservation.v1' and
                move.keys() == {'schema', 'install_id', 'operation_id', 'reservation_sha256', 'source_name',
                    'source_root_identity', 'destination_parent_identity', 'destination_name', 'tree', 'preservation_sha256'} and
                move['source_name'] == 'publication' and move['destination_name'] == retained_path.rsplit('\\', 1)[1] and
                move['destination_parent_identity'] == root(by_path[context_directory]['file_id']) and retained_path in by_path,
                'bootstrap preservation destination/root differs')
        require(ownership['expected_state_revision'] == digest([]) and
                not any(value['generation'] == generation and value['status'] == 'completed' for value in history) and
                any(value['generation'] > generation and value['status'] == 'active' for value in history),
                'bootstrap preservation cannot retire a completed installation')
        retained = by_path[retained_path]
        tree = move['tree']
        require(isinstance(tree, dict) and tree.keys() == {'root', 'root_streams', 'entries'} and
                isinstance(tree['entries'], list) and len(tree['entries']) <= 5 and retained['directory'] is True and
                native_object(retained) == tree['root'] and retained['streams'] == tree['root_streams'] and
                retained['file_id'] == move['source_root_identity'], 'retained bootstrap root native facts differ')
        expected_directories.add(retained_path)
        present, snapshot_present = set(), False
        for entry in tree['entries']:
            require(isinstance(entry, dict) and entry.keys() == {'relative_path', 'object', 'bytes', 'sha256', 'streams'},
                    'retained bootstrap entry is not closed')
            name = entry['relative_path'].replace('/', '\\')
            path = retained_path + '\\' + name
            require(path in by_path, 'retained bootstrap descendant absent')
            observed = by_path[path]
            require(native_object(observed) == entry['object'] and observed['streams'] == entry['streams'] and
                    observed['bytes'] == entry['bytes'] and (observed['sha256'] or '') == entry['sha256'],
                    'retained bootstrap descendant identity/security/bytes differ')
            if observed['directory']:
                require(name in ('staging', 'destination', 'state', 'journal') and name not in present,
                        'retained bootstrap has extra or aliased directories')
                present.add(name)
                expected_directories.add(path)
            else:
                require(name == 'journal\\lab-reviewed-plan.json' and not snapshot_present and
                        type(observed['bytes']) is int and 0 <= observed['bytes'] <= 4 * 1024 * 1024,
                        'retained bootstrap has product payload or extra files')
                snapshot_present = True
                original_bytes = (canonical(context['reviewed_snapshot']) + '\n').encode('utf-8')
                require(observed['bytes'] <= len(original_bytes) and
                        observed['sha256'] == hashlib.sha256(original_bytes[:observed['bytes']]).hexdigest(),
                        'retained snapshot bytes are not an exact prefix of the original intent')
                expected_files.add(path)
        ordered = ('staging', 'destination', 'state', 'journal')
        require(present == set(ordered[:len(present)]) and (not snapshot_present or len(present) == 4),
                'retained bootstrap is not an exact creation-order prefix')
    return expected_files, expected_directories


def snapshot(rows, drive, installed, volume_root_id, *, allow_active=False, allow_legacy_missing=False,
             allow_legacy_missing_bootstrap=False, allow_initial_empty_state=False):
    return _snapshot(rows, drive, installed, volume_root_id, allow_active=allow_active,
        allow_legacy_missing=allow_legacy_missing, allow_legacy_missing_bootstrap=allow_legacy_missing_bootstrap,
        allow_initial_empty_state=allow_initial_empty_state)


def _snapshot(rows, drive, installed, volume_root_id, *, allow_active=False, allow_legacy_missing=False,
              allow_legacy_missing_bootstrap=False, allow_initial_empty_state=False, early_reviewed=None):
    require(isinstance(rows, list) and 0 < len(rows) <= 10000, 'coordination row budget exceeded')
    require(all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in rows), 'coordination row missing path')
    by_path = {row['path']: row for row in rows}
    require(len(by_path) == len(rows), 'coordination paths alias')
    state = drive + 'setup-state\\state'
    leases = state + '\\leases'
    operations = drive + 'installation-operations'
    lease_rows = [row for row in rows if row['path'] == leases or row['path'].startswith(leases + '\\')]
    context_rows = [row for row in rows if row['path'] == operations or row['path'].startswith(operations + '\\')]
    if not lease_rows and not context_rows:
        require(allow_legacy_missing, 'current producer is missing all installation coordination')
        return None  # Explicit historical mode; no lease claim.
    require(lease_rows and context_rows, 'lease and original context must both be observed')
    install, operation = installed['install_id'], installed['transaction_id']
    require(all(isinstance(value, str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value) for value in (install, operation)),
            'coordination operation identity invalid')
    install_name = 'install-' + digest(install)
    lease_directory = leases + '\\' + install_name
    context_directory = operations + '\\' + install_name
    context_path = context_directory + '\\operation-' + digest(operation) + '.json'
    roots_path = context_directory + '\\operation-' + digest(operation) + '-roots.json'
    directories = {leases, lease_directory, lease_directory + '\\pending',
                   operations, context_directory, context_directory + '\\pending'}
    require(directories <= {row['path'] for row in lease_rows + context_rows if row['directory']},
            'coordination base directories absent')
    context_files = [row for row in context_rows if not row['directory']]
    require({context_path, roots_path} <= {row['path'] for row in context_files},
            'original operation context files absent')
    context = document(by_path[context_path])
    require(context.keys() == {'schema', 'install_id', 'operation', 'operation_id', 'volume_root_identity',
            'initial_state_revision', 'reviewed_snapshot', 'context_sha256'}, 'operation context is not closed')
    unsealed = {key: value for key, value in context.items() if key != 'context_sha256'}
    reviewed_path = drive + 'publication\\journal\\lab-reviewed-plan.json'
    reviewed = document(by_path[reviewed_path]) if early_reviewed is None else early_reviewed
    require(early_reviewed is None or reviewed_path not in by_path,
            'early ownership cannot replace a published reviewed plan')
    require(context['schema'] == 'usk.installation_operation_context.v1' and context['install_id'] == install and
            context['operation'] == 'install_local' and context['operation_id'] == operation and
            context['volume_root_identity'] == root(volume_root_id) and context['context_sha256'] == digest(unsealed) and
            context['initial_state_revision'] == digest([]) and
            context['reviewed_snapshot'] == reviewed, 'original reviewed operation binding differs')
    state_identity = root(by_path[state]['file_id'])
    roots = document(by_path[roots_path])
    require(roots.keys() == {'schema', 'install_id', 'operation_id', 'context_sha256',
            'setup_root_identity', 'state_root_identity', 'roots_sha256'}, 'operation root binding is not closed')
    require(roots['schema'] == 'usk.installation_operation_roots.v1' and roots['install_id'] == install and
            roots['operation_id'] == operation and roots['context_sha256'] == context['context_sha256'] and
            roots['setup_root_identity'] == root(by_path[drive + 'setup-state']['file_id']) and
            roots['state_root_identity'] == state_identity and
            roots['roots_sha256'] == digest({key: value for key, value in roots.items() if key != 'roots_sha256'}),
            'original setup/state root binding differs')
    filename = install + '.' + operation + '.json'
    installed_path = state + '\\installed\\' + filename
    if allow_initial_empty_state:
        initial_directory = state + '\\installed'
        require(allow_active and initial_directory in by_path and by_path[initial_directory]['directory'] is True and
                not any(path.startswith(initial_directory + '\\') for path in by_path),
                'initial active ownership lacks an independently empty installed-state directory')
        state_revision = digest([])
    else:
        require(installed_path in by_path and document(by_path[installed_path]) == installed,
                'lease installed-state readback differs')
        state_revision = digest([{'record': filename, 'sha256': digest(installed)}])
    lease_files = sorted((row for row in lease_rows if not row['directory']), key=lambda row: row['path'])
    require(0 < len(lease_files) <= 4096, 'lease record closure differs')
    history = []
    previous = None
    attempts = set()
    for index, row in enumerate(lease_files):
        value = document(row)
        require(value.keys() == {'schema', 'install_id', 'operation', 'operation_id', 'attempt_id',
                'state_root_identity', 'holder', 'generation', 'expected_state_revision', 'status',
                'result_state_revision', 'predecessor_sha256', 'ownership_sha256', 'operation_context_sha256'},
                'lease record is not closed')
        generation = value['generation']
        active = value['status'] == 'active'
        expected_generation = (1 if previous is None else previous['generation'] + 1) if active else (
            0 if previous is None else previous['generation'])
        expected_name = f'g{generation:020d}-' + ('active' if active else 'terminal') + '.json'
        require(row['path'] == lease_directory + '\\' + expected_name and type(value['generation']) is int and
                1 <= generation <= 0xffffffffffffffff and generation == expected_generation and value['schema'] == 'usk.installation_lease_ownership.v1' and
                value['install_id'] == install and value['operation'] == 'install_local' and value['operation_id'] == operation and
                value['state_root_identity'] == state_identity and value['operation_context_sha256'] == roots['roots_sha256'],
                'lease operation/root/context/generation differs')
        holder = value['holder']
        require(isinstance(holder, dict) and holder.keys() == {'process_id', 'process_creation_time'} and
                type(holder['process_id']) is int and 1 <= holder['process_id'] <= 0xffffffff and
                isinstance(holder['process_creation_time'], str) and re.fullmatch('[0-9a-f]{16}', holder['process_creation_time']) and
                int(holder['process_creation_time'], 16), 'lease holder identity incomplete')
        require(isinstance(value['attempt_id'], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value['attempt_id']) and
                value['ownership_sha256'] == digest({key: item for key, item in value.items() if key != 'ownership_sha256'}),
                'lease attempt or seal differs')
        if active:
            require(value['attempt_id'] not in attempts, 'lease attempt reused')
            attempts.add(value['attempt_id'])
            require(value['status'] == 'active' and value['result_state_revision'] is None and
                    value['expected_state_revision'] in ({digest([])} if previous is None else (
                        {previous['expected_state_revision'], state_revision} if previous['status'] == 'active' else
                        {previous['result_state_revision']})) and
                    value['predecessor_sha256'] == (None if previous is None else previous['ownership_sha256']),
                    'lease active transition differs')
            if previous is not None and previous['status'] == 'active':
                require(holder != previous['holder'], 'crash takeover reused the same holder identity')
        else:
            require(previous is not None and previous['status'] == 'active' and value['status'] in ('completed', 'handoff'),
                    'lease terminal has no active predecessor')
            require(value['result_state_revision'] in ({state_revision} if value['status'] == 'completed' else
                    {digest([]), state_revision}), 'lease terminal revision differs')
            expected = dict(previous, status=value['status'], result_state_revision=value['result_state_revision'])
            expected['ownership_sha256'] = digest({key: item for key, item in expected.items() if key != 'ownership_sha256'})
            require(value == expected, 'lease terminal transition differs')
        history.append(value)
        previous = value
    require(allow_active or history[-1]['status'] == 'completed', 'current snapshot lacks completed ownership')
    if allow_initial_empty_state:
        require(len(history) == 1 and history[0]['status'] == 'active' and history[0]['generation'] == 1 and
                history[0]['expected_state_revision'] == digest([]),
                'initial empty state cannot represent completed ownership or a replacement attempt')
    reserved = any(row['path'].startswith(context_path[:-5] + '-bootstrap-') for row in context_files)
    if not reserved and allow_legacy_missing_bootstrap:
        bootstrap_files, bootstrap_directories = set(), set()
    else:
        bootstrap_files, bootstrap_directories = bootstrap_history(by_path, drive, context_directory, context_path,
            context, roots, volume_root_id, history)
    require({row['path'] for row in lease_rows + context_rows if row['directory']} == directories | bootstrap_directories and
            {row['path'] for row in context_files} == {context_path, roots_path} | bootstrap_files,
            'coordination bootstrap file/directory closure differs')
    result = {'history': history, 'context_sha256': context['context_sha256'],
            'bootstrap_protocol': 'reserved_creation' if reserved else 'historical_unreserved',
            'files': [context_path, roots_path] + sorted(bootstrap_files) + [row['path'] for row in lease_files]}
    if allow_initial_empty_state:
        result['initial_empty_state_observed'] = True
    return result


def active_ownership(rows, drive, installed, volume_root_id, request, response, apply, consumer, held_holder):
    """Original g1 ownership only; never publication, completion or native authority.

    The v3 fixture can stop at complete empty publication anchors. Ordinary
    snapshots and the historical v2 fixture still require the published plan.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    from usk_bundle_apply_binding import BindingError, compose_binding, _bytes
    require(isinstance(rows, list) and 0 < len(rows) <= 10000 and
            all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in rows),
            'active ownership row budget or path differs')
    by_path = {row['path']: row for row in rows}
    require(len(by_path) == len(rows) and isinstance(apply, dict) and isinstance(installed, dict) and
            installed.get('install_id') == apply['plan_request']['install_id'] and
            installed.get('transaction_id') == apply['transaction_id'],
            'active ownership original apply identity differs')
    require(isinstance(request, dict) and request.keys() == {'schema', 'request_id', 'command', 'payload', 'dry_run'} and
            isinstance(response, dict) and response.get('request_id') == request.get('request_id') and
            response.get('error') is None and response.get('result', {}).get('error') is None and
            isinstance(consumer, str) and re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', consumer),
            'active ownership actual planning response or consumer differs')
    try:
        rebuilt_apply, envelope = compose_binding(request, response, acceptance_root=drive,
            state_root=drive + 'setup-state', transaction_id=apply['transaction_id'], applied_at=apply['applied_at'])
    except (BindingError, KeyError, TypeError) as error:
        raise LeaseEvidenceError('active ownership actual planning binding differs: ' + str(error)) from error
    require(rebuilt_apply == apply, 'active ownership actual apply was substituted')
    plan = response['result']['payload']
    context_path = (drive + 'installation-operations\\install-' + digest(installed['install_id']) +
                    '\\operation-' + digest(installed['transaction_id']) + '.json')
    require(context_path in by_path, 'active ownership protected original context absent')
    reviewed = document(by_path[context_path]).get('reviewed_snapshot')
    fields = {'schema', 'plan_digest', 'plan_envelope_sha256', 'archive_sha256', 'archive_identity_digest',
        'entry_set_digest', 'selected_file_set_digest', 'target_root', 'setup_root', 'transaction_id', 'applied_at',
        'policy_digest', 'restart_policy_context', 'plan_request', 'planned_entries', 'consumer_read_sid', 'apply_request'}
    require(isinstance(reviewed, dict) and reviewed.keys() == fields and
            reviewed['schema'] == 'usk.publisher.lab_reviewed_plan_snapshot.v4',
            'active ownership lost its closed current consumer-bound snapshot')
    expected = {'plan_digest': plan['plan_digest'], 'plan_envelope_sha256': hashlib.sha256(_bytes(envelope)).hexdigest(),
        'archive_sha256': plan['source']['sha256'], 'archive_identity_digest': plan['source']['filesystem_identity_digest'],
        'target_root': plan['target']['root'], 'setup_root': drive + 'setup-state',
        'transaction_id': apply['transaction_id'], 'applied_at': apply['applied_at'],
        'policy_digest': plan['input_identity']['policy_digest'], 'plan_request': request['payload'],
        'planned_entries': plan['planned_entries'], 'consumer_read_sid': consumer, 'apply_request': apply}
    require(all(reviewed[key] == value for key, value in expected.items()),
            'active ownership protected snapshot differs from actual plan/apply/source/consumer')
    require(isinstance(reviewed['entry_set_digest'], str) and re.fullmatch('[0-9a-f]{64}', reviewed['entry_set_digest']),
            'active ownership opaque native entry-set digest absent')
    files = []
    for entry in plan['planned_entries']:
        require(entry.get('entry_type') in ('file', 'directory') and isinstance(entry.get('relative_path'), str) and
                re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', entry['relative_path']),
                'active fixture selected path is outside its bounded ASCII profile')
        if entry['entry_type'] == 'file':
            require(type(entry.get('size_bytes')) is int and 0 <= entry['size_bytes'] <= 0xffffffffffffffff and
                    isinstance(entry.get('sha256'), str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']),
                    'active fixture selected file facts differ')
            files.append({'relative_path': entry['relative_path'], 'size': entry['size_bytes'], 'sha256': entry['sha256']})
    require(0 < len(files) <= 4096 and len({f['relative_path'].upper() for f in files}) == len(files),
            'active fixture selected file count or alias differs')
    files.sort(key=lambda f: f['relative_path'].upper())
    selected = canonical({'schema': 'usk.publisher.lab_selected_file_set.v1', 'files': files}) + '\n'
    require(reviewed['selected_file_set_digest'] == hashlib.sha256(selected.encode('utf-8')).hexdigest(),
            'active ownership selected files differ from actual planning output')
    policy_text = reviewed['restart_policy_context']
    require(isinstance(policy_text, str) and 0 < len(policy_text.encode('utf-8')) <= 65536,
            'active ownership restart policy exceeds its bounded context')
    policy = json.loads(policy_text)
    target = policy.get('target_evidence', {})
    target_fields = {'capacity_satisfied', 'excluded_roots_absent', 'filesystem_identity_digest', 'filesystem_kind',
        'local_filesystem', 'mount_redirection_absent', 'path_components_stable', 'schema', 'source_target_distinct',
        'target_identity_digest', 'target_state'}
    flags = ('capacity_satisfied', 'excluded_roots_absent', 'local_filesystem', 'mount_redirection_absent',
             'path_components_stable', 'source_target_distinct')
    require(canonical(policy) == policy_text and policy.keys() == {'schema', 'policy', 'setup_initial_state', 'target_evidence'} and
            policy['schema'] == 'usk.install_restart_policy_context.v1' and policy['setup_initial_state'] == 'absent' and
            isinstance(policy['policy'], dict) and policy['policy'].keys() == {'activation', 'setup_binding_digest', 'target_binding_digest'} and
            policy['policy'].get('activation') == 'operator_acceptance_candidate' and
            all(isinstance(policy['policy'][key], str) and re.fullmatch('[0-9a-f]{64}', policy['policy'][key])
                for key in ('setup_binding_digest', 'target_binding_digest')) and
            digest(policy['policy']) == reviewed['policy_digest'] and
            isinstance(target, dict) and target.keys() == target_fields and all(target[key] is True for key in flags) and
            target.get('schema') == 'usk.install_target_recovery_evidence.v1' and
            target.get('filesystem_kind') == plan['target']['filesystem']['kind'] and
            target.get('filesystem_identity_digest') == plan['target']['filesystem']['identity_digest'] and
            target.get('target_identity_digest') == plan['target']['identity_digest'] and target.get('target_state') == 'nonexistent',
            'active ownership original restart/target policy differs')
    reviewed_path = drive + 'publication\\journal\\lab-reviewed-plan.json'
    early = reviewed_path not in by_path
    if early:
        publication = drive + 'publication'
        expected_paths = {publication} | {publication + '\\' + name for name in ('staging', 'destination', 'state', 'journal')}
        actual_paths = {path for path in by_path if path == publication or path.startswith(publication + '\\')}
        require(actual_paths == expected_paths and all(by_path[path].get('directory') is True for path in expected_paths),
                'early active ownership lacks exactly complete empty publication anchors')
    result = _snapshot(rows, drive, installed, volume_root_id, allow_active=True, allow_initial_empty_state=True,
                       early_reviewed=reviewed if early else None)
    require(result['history'][0]['holder'] == held_holder,
            'active ownership generation does not name the held original native child')
    require(result['bootstrap_protocol'] == 'reserved_creation', 'active ownership lacks its original bootstrap reservation')
    result['active_ownership_phase'] = 'prepublication_empty_anchors' if early else 'published_reviewed_plan'
    return result


def transition(before, after, drive, installed, volume_root_id, *, readonly=False, allow_legacy_missing=False,
               allow_legacy_missing_bootstrap=False):
    old = snapshot(before, drive, installed, volume_root_id, allow_legacy_missing=allow_legacy_missing,
                   allow_legacy_missing_bootstrap=allow_legacy_missing_bootstrap)
    new = snapshot(after, drive, installed, volume_root_id, allow_legacy_missing=allow_legacy_missing,
                   allow_legacy_missing_bootstrap=allow_legacy_missing_bootstrap)
    if readonly or old is None:
        require(before == after, 'read-only or historical request changed native rows')
        return
    require(new is not None and old['context_sha256'] == new['context_sha256'] and
            new['history'][:-2] == old['history'] and len(new['history']) == len(old['history']) + 2,
            'recovery/replay must append exactly one active and completed generation')
    old_rows = {row['path']: row for row in before}
    new_rows = {row['path']: row for row in after}
    require(all(path in new_rows and new_rows[path] == row for path, row in old_rows.items()),
            'recovery/replay changed or removed a prior native row')
    expected_new = set(new['files']) - set(old['files'])
    require(set(new_rows) - set(old_rows) == expected_new and len(expected_new) == 2,
            'recovery/replay appended an unexpected native object')


def bootstrap_takeover(before, after, drive, installed, volume_root_id, terminated_holder):
    """Check a measured process-loss prefix against its independently retained tree.

    The caller must separately establish the owned native process termination.
    These rows and records remain evidence data; they confer no authority.
    """
    completed = snapshot(after, drive, installed, volume_root_id)
    history = completed['history']
    require(len(history) == 3 and [value['status'] for value in history] == ['active', 'active', 'completed'] and
            history[0]['holder'] == terminated_holder and history[0]['expected_state_revision'] == digest([]) and
            history[1]['expected_state_revision'] == digest([]) and history[1]['holder'] != terminated_holder,
            'bootstrap takeover is not one interrupted native generation followed by completion')
    return _bootstrap_original_prefix(before, after, drive, installed, history, terminated_holder)


def constructed_prefix_takeover(before, after, drive, installed, volume_root_id, terminated_holder, case, snapshot_size):
    """Native replacement of separately validated SYSTEM-constructed rows.

    The original empty-root process-loss and the construction must be retained
    and checked separately. This result never labels construction as a crash.
    """
    from publisher_bootstrap_prefix_evidence import SCOPE, named_prefix_rows
    named_prefix_rows(case, snapshot_size, before, drive, installed)
    result = bootstrap_takeover(before, after, drive, installed, volume_root_id, terminated_holder)
    return dict(result, schema='usk.publisher_constructed_prefix_takeover_reconciliation.v1',
                scope=SCOPE, case=case, snapshot_size_bytes=snapshot_size,
                native_crash_at_constructed_prefix_observed=False)


def _bootstrap_original_prefix(before, after, drive, installed, history, terminated_holder):
    require(isinstance(before, list) and 0 < len(before) <= 10000 and
            all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in before),
            'bootstrap interruption row budget/path differs')
    old = {row['path']: row for row in before}
    new = {row['path']: row for row in after}
    require(len(old) == len(before), 'bootstrap interruption paths alias')
    context_prefix = drive + 'installation-operations\\install-' + digest(installed['install_id']) + '\\operation-' + digest(installed['transaction_id'])
    lease_directory = drive + 'setup-state\\state\\leases\\install-' + digest(installed['install_id'])
    active_path = lease_directory + '\\g00000000000000000001-active.json'
    context_files = {context_prefix + '.json', context_prefix + '-roots.json',
                     context_prefix + '-bootstrap-g00000000000000000001.json'}
    coordination = context_files | {active_path}
    marker_path = drive + 'setup-state\\.usk-owned-root.v1.json'
    require(marker_path in old and document(old[marker_path]) == {
        'schema': 'usk.setup_owned_root.v1', 'acceptance_root': drive.replace('\\', '/')},
        'bootstrap setup marker is not bound to the original admitted volume root')
    coordination.add(marker_path)
    publication = drive + 'publication'
    retained = context_prefix + '-retained-g00000000000000000001'
    move_path = context_prefix + '-preserve-g00000000000000000001.json'
    require(active_path in old and document(old[active_path]) == history[0] and publication in old and
            move_path not in old and retained not in old,
            'interrupted worker lacks original active ownership or contains a later disposition')
    require({path for path, row in old.items() if not row['directory'] and
            not (path == publication or path.startswith(publication + '\\'))} == coordination,
            'interrupted bootstrap has extra context, lease, or installed state files')
    move = document(new[move_path])
    require(move['source_root_identity'] == old[publication]['file_id'] and
            new[publication]['file_id'] != old[publication]['file_id'],
            'bootstrap takeover did not preserve the interrupted root and create a different root')
    old_tree = {path for path in old if path == publication or path.startswith(publication + '\\')}
    new_tree = {path for path in new if path == retained or path.startswith(retained + '\\')}
    require({retained + path[len(publication):] for path in old_tree} == new_tree,
            'bootstrap preservation lost or added native descendants')
    for path, row in old.items():
        renamed = path in old_tree
        target = retained + path[len(publication):] if renamed else path
        require(target in new, 'bootstrap takeover lost an original object')
        if renamed:
            require(row.get('native_name') == path[2:] and new[target].get('native_name') == target[2:] and
                    {key: value for key, value in row.items() if key not in ('path', 'native_name')} ==
                    {key: value for key, value in new[target].items() if key not in ('path', 'native_name')},
                    'bootstrap retained object identity/security/streams/bytes changed')
        else:
            require(row == new[target], 'bootstrap takeover changed original coordination or state root')
    return {'schema': 'usk.publisher_bootstrap_takeover_reconciliation.v1', 'status': 'bindings_consistent',
            'terminated_holder': terminated_holder, 'replacement_generation': history[-1]['generation'],
            'retained_root_identity': old[publication]['file_id'], 'retained_objects': len(old_tree),
            'profile_qualified': False, 'publication_authority_granted': False}


def bootstrap_preservation_takeover(before, preserved, after, drive, installed, volume_root_id, terminated_holders):
    """Reconcile actual loss after a durable preservation move, before replacement creation."""
    completed = snapshot(after, drive, installed, volume_root_id)
    history = completed['history']
    require(isinstance(terminated_holders, list) and len(terminated_holders) == 2 and
            len(history) == 4 and [value['status'] for value in history] == ['active', 'active', 'active', 'completed'] and
            [value['holder'] for value in history[:2]] == terminated_holders and
            all(value['expected_state_revision'] == digest([]) for value in history[:3]) and
            len({(value['holder']['process_id'], value['holder']['process_creation_time']) for value in history[:3]}) == 3,
            'preservation takeover is not two interrupted holders followed by completion')
    original = _bootstrap_original_prefix(before, after, drive, installed, history, terminated_holders[0])
    require(isinstance(preserved, list) and 0 < len(preserved) <= 10000 and
            all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in preserved),
            'preservation interruption row budget/path differs')
    moved = {row['path']: row for row in preserved}
    final = {row['path']: row for row in after}
    require(len(moved) == len(preserved), 'preservation interruption paths alias')
    prefix = drive + 'installation-operations\\install-' + digest(installed['install_id']) + '\\operation-' + digest(installed['transaction_id'])
    retained = prefix + '-retained-g00000000000000000001'
    move_path = prefix + '-preserve-g00000000000000000001.json'
    active_path = drive + 'setup-state\\state\\leases\\install-' + digest(installed['install_id']) + '\\g00000000000000000002-active.json'
    publication = drive + 'publication'
    expected_paths = {retained + row['path'][len(publication):] if row['path'] == publication or
                      row['path'].startswith(publication + '\\') else row['path'] for row in before} | {move_path, active_path}
    require(set(moved) == expected_paths and all(path in final and row == final[path] for path, row in moved.items()) and
            document(moved[active_path]) == history[1] and
            document(moved[move_path])['source_root_identity'] == original['retained_root_identity'],
            'preservation interruption changed retained objects or admitted replacement effects')
    return dict(original, schema='usk.publisher_bootstrap_preservation_takeover_reconciliation.v1',
                terminated_holders=terminated_holders, preserved_generation=2, replacement_generation=3,
                preservation_reentry_checked=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    args = parser.parse_args()
    if args.input == '-':
        sys.stdin.reconfigure(encoding='utf-8-sig')
        value = json.load(sys.stdin)
    else:
        with open(args.input, encoding='utf-8-sig') as stream:
            value = json.load(stream)
    if value['mode'] == 'snapshot':
        result = snapshot(value['rows'], value['drive'], value['installed'], value['volume_root_id'],
                          allow_active=value.get('allow_active') is True, allow_legacy_missing=value.get('allow_legacy_missing') is True,
                          allow_initial_empty_state=value.get('allow_initial_empty_state') is True)
    elif value['mode'] == 'active_ownership':
        result = active_ownership(value['rows'], value['drive'], value['installed'], value['volume_root_id'],
            value['request'], value['response'], value['apply'], value['consumer'], value['held_holder'])
    elif value['mode'] == 'bootstrap_takeover':
        result = bootstrap_takeover(value['before'], value['after'], value['drive'], value['installed'],
                                    value['volume_root_id'], value['terminated_holder'])
    elif value['mode'] == 'constructed_prefix_takeover':
        result = constructed_prefix_takeover(value['before'], value['after'], value['drive'], value['installed'],
            value['volume_root_id'], value['terminated_holder'], value['case'], value['snapshot_size_bytes'])
    elif value['mode'] == 'bootstrap_preservation_takeover':
        result = bootstrap_preservation_takeover(value['before'], value['preserved'], value['after'],
            value['drive'], value['installed'], value['volume_root_id'], value['terminated_holders'])
    else:
        require(value['mode'] in ('append', 'readonly'), 'unknown lease reconciliation mode')
        transition(value['before'], value['after'], value['drive'], value['installed'], value['volume_root_id'],
                   readonly=value['mode'] == 'readonly', allow_legacy_missing=value.get('allow_legacy_missing') is True)
        result = None
    print(canonical({'status': 'bindings_consistent', 'coordination': result, 'profile_qualified': False,
                     'publication_authority_granted': False}))


if __name__ == '__main__':
    main()
