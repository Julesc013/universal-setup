# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Bounded independent record/append reconciliation. No native authority grant."""
from __future__ import annotations
import argparse
import hashlib
import json
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


def snapshot(rows, drive, installed, volume_root_id, *, allow_active=False):
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
        return None  # Historical producer has no lease evidence; no lease claim.
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
    require({row['path'] for row in lease_rows + context_rows if row['directory']} == directories,
            'coordination directory closure differs')
    context_files = [row for row in context_rows if not row['directory']]
    require(len(context_files) == 2 and {row['path'] for row in context_files} == {context_path, roots_path},
            'original operation context file closure differs')
    context = document(by_path[context_path])
    require(context.keys() == {'schema', 'install_id', 'operation', 'operation_id', 'volume_root_identity',
            'initial_state_revision', 'reviewed_snapshot', 'context_sha256'}, 'operation context is not closed')
    unsealed = {key: value for key, value in context.items() if key != 'context_sha256'}
    reviewed_path = drive + 'publication\\journal\\lab-reviewed-plan.json'
    require(context['schema'] == 'usk.installation_operation_context.v1' and context['install_id'] == install and
            context['operation'] == 'install_local' and context['operation_id'] == operation and
            context['volume_root_identity'] == root(volume_root_id) and context['context_sha256'] == digest(unsealed) and
            context['initial_state_revision'] == digest([]) and
            context['reviewed_snapshot'] == document(by_path[reviewed_path]), 'original reviewed operation binding differs')
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
    require(document(by_path[installed_path]) == installed, 'lease installed-state readback differs')
    state_revision = digest([{'record': filename, 'sha256': digest(installed)}])
    lease_files = sorted((row for row in lease_rows if not row['directory']), key=lambda row: row['path'])
    require(0 < len(lease_files) <= 4096 and (allow_active or len(lease_files) % 2 == 0), 'terminal lease record closure differs')
    history = []
    previous = None
    attempts = set()
    for index, row in enumerate(lease_files):
        value = document(row)
        require(value.keys() == {'schema', 'install_id', 'operation', 'operation_id', 'attempt_id',
                'state_root_identity', 'holder', 'generation', 'expected_state_revision', 'status',
                'result_state_revision', 'predecessor_sha256', 'ownership_sha256', 'operation_context_sha256'},
                'lease record is not closed')
        generation = index // 2 + 1
        active = index % 2 == 0
        expected_name = f'g{generation:020d}-' + ('active' if active else 'terminal') + '.json'
        require(row['path'] == lease_directory + '\\' + expected_name and type(value['generation']) is int and
                value['generation'] == generation and value['schema'] == 'usk.installation_lease_ownership.v1' and
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
                    value['expected_state_revision'] == (digest([]) if generation == 1 else state_revision) and
                    value['predecessor_sha256'] == (None if previous is None else previous['ownership_sha256']),
                    'lease active transition differs')
        else:
            expected = dict(previous, status='completed', result_state_revision=state_revision)
            expected['ownership_sha256'] = digest({key: item for key, item in expected.items() if key != 'ownership_sha256'})
            require(value == expected, 'lease terminal transition differs')
        history.append(value)
        previous = value
    return {'history': history, 'context_sha256': context['context_sha256'],
            'files': [context_path, roots_path] + [row['path'] for row in lease_files]}


def transition(before, after, drive, installed, volume_root_id, *, readonly=False):
    old = snapshot(before, drive, installed, volume_root_id)
    new = snapshot(after, drive, installed, volume_root_id)
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
                          allow_active=value.get('allow_active') is True)
    else:
        require(value['mode'] in ('append', 'readonly'), 'unknown lease reconciliation mode')
        transition(value['before'], value['after'], value['drive'], value['installed'], value['volume_root_id'],
                   readonly=value['mode'] == 'readonly')
        result = None
    print(canonical({'status': 'bindings_consistent', 'coordination': result, 'profile_qualified': False,
                     'publication_authority_granted': False}))


if __name__ == '__main__':
    main()
