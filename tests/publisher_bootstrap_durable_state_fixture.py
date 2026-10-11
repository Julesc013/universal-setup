# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Pure-byte construction for the next finite owned durable-state fixtures.

No native writer or authority: callers must separately admit the exact owned
target, ended holder, protected CREATE_NEW operation, and independent readback.
Constructed states never claim actual crashes, uncertain native errors or power loss.
"""
import base64
import hashlib
import json
import re
import sys

from publisher_installation_lease_evidence import canonical, digest, document, native_object, require, root

CASES = ('move_intent', 'pending_empty', 'pending_middle', 'pending_full',
         'publication_absent', 'next_reservation_absent')


def records(rows, drive, installed, volume_id):
    require(isinstance(rows, list) and 0 < len(rows) <= 10000 and
        all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in rows), 'durable fixture rows differ')
    by_path = {row['path']: row for row in rows}
    require(len(by_path) == len(rows), 'durable fixture rows alias')
    directory = drive + 'installation-operations\\install-' + digest(installed['install_id'])
    prefix = directory + '\\operation-' + digest(installed['transaction_id'])
    require(all(path in by_path for path in (directory, directory + '\\pending', prefix + '.json', prefix + '-roots.json')),
        'durable fixture original context/parents absent')
    context, roots = document(by_path[prefix + '.json']), document(by_path[prefix + '-roots.json'])
    require(context['schema'] == 'usk.installation_operation_context.v1' and
        context['install_id'] == installed['install_id'] and context['operation_id'] == installed['transaction_id'] and
        context['volume_root_identity'] == root(volume_id) and
        context['context_sha256'] == digest({key: value for key, value in context.items() if key != 'context_sha256'}),
        'durable fixture original context seal/identity differs')
    require(roots['schema'] == 'usk.installation_operation_roots.v1' and
        roots['install_id'] == installed['install_id'] and roots['operation_id'] == installed['transaction_id'] and
        roots['context_sha256'] == context['context_sha256'] and
        roots['roots_sha256'] == digest({key: value for key, value in roots.items() if key != 'roots_sha256'}),
        'durable fixture root bindings differ')
    for name, member in (('setup-state', 'setup_root_identity'), ('setup-state\\state', 'state_root_identity')):
        require(drive + name in by_path and by_path[drive + name]['directory'] is True and
            roots[member] == root(by_path[drive + name]['file_id']), 'durable fixture actual setup/state root differs')
    return by_path, directory, prefix, context, roots


def active_ownership(by_path, drive, context, roots, generation):
    path = (drive + 'setup-state\\state\\leases\\install-' + digest(context['install_id']) +
            f'\\g{generation:020d}-active.json')
    require(path in by_path and by_path[path]['directory'] is False, 'durable fixture active native journal row absent')
    value = document(by_path[path])
    require(value.keys() == {'schema', 'install_id', 'operation', 'operation_id', 'attempt_id',
        'state_root_identity', 'holder', 'generation', 'expected_state_revision', 'status',
        'result_state_revision', 'predecessor_sha256', 'ownership_sha256', 'operation_context_sha256'} and
        value['schema'] == 'usk.installation_lease_ownership.v1' and
        type(value['generation']) is int and value['generation'] == generation and
        value['status'] == 'active' and value['operation'] == 'install_local' and
        value['install_id'] == context['install_id'] and value['operation_id'] == context['operation_id'] and
        value['state_root_identity'] == roots['state_root_identity'] and
        value['operation_context_sha256'] == roots['roots_sha256'] and
        value['expected_state_revision'] == digest([]) and value['result_state_revision'] is None and
        isinstance(value['attempt_id'], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value['attempt_id']) and
        value['ownership_sha256'] == digest({key: item for key, item in value.items() if key != 'ownership_sha256'}),
        'durable fixture active journal generation/context/seal differs')
    holder = value['holder']
    require(isinstance(holder, dict) and holder.keys() == {'process_id', 'process_creation_time'} and
        type(holder['process_id']) is int and 1 <= holder['process_id'] <= 0xffffffff and
        isinstance(holder['process_creation_time'], str) and re.fullmatch('[0-9a-f]{16}', holder['process_creation_time']) and
        int(holder['process_creation_time'], 16) != 0, 'durable fixture active journal holder differs')
    if generation == 1:
        require(value['predecessor_sha256'] is None, 'durable fixture first generation has predecessor')
    else:
        previous = active_ownership(by_path, drive, context, roots, generation - 1)
        require(value['predecessor_sha256'] == previous['ownership_sha256'] and
            value['holder'] != previous['holder'] and value['attempt_id'] != previous['attempt_id'],
            'durable fixture active native journal transition differs')
    return value


def reservation(context, roots, ownership):
    require(ownership['status'] == 'active' and ownership['operation'] == 'install_local' and
        ownership['install_id'] == context['install_id'] and ownership['operation_id'] == context['operation_id'] and
        ownership['operation_context_sha256'] == roots['roots_sha256'] and
        ownership['state_root_identity'] == roots['state_root_identity'] and
        ownership['ownership_sha256'] == digest({key: value for key, value in ownership.items() if key != 'ownership_sha256'}),
        'durable fixture reservation is not actual bound active ownership')
    value = dict(schema='usk.publication_bootstrap_reservation.v1', install_id=context['install_id'],
        operation_id=context['operation_id'], context_sha256=context['context_sha256'], roots_sha256=roots['roots_sha256'],
        volume_root_identity=context['volume_root_identity'], ownership=ownership, publication_absent=True)
    value['reservation_sha256'] = digest(value)
    return value


def prepare(case, rows, drive, installed, volume_id, pending_name=None):
    require(case in CASES, 'durable fixture case differs')
    require(isinstance(drive, str) and re.fullmatch(r'[A-Z]:\\', drive) and
        isinstance(installed, dict) and {'install_id', 'transaction_id'} <= installed.keys() and
        all(isinstance(installed[name], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', installed[name])
            for name in ('install_id', 'transaction_id')), 'durable fixture native operation/drive input differs')
    by_path, directory, prefix, context, roots = records(rows, drive, installed, volume_id)
    publication = drive + 'publication'
    if case == 'next_reservation_absent':
        require(publication not in by_path and prefix + '-preserve-g00000000000000000001.json' in by_path and
            prefix + '-retained-g00000000000000000001' in by_path, 'next reservation fixture lacks real preserved absence')
        value = reservation(context, roots, active_ownership(by_path, drive, context, roots, 2))
        target = prefix + '-bootstrap-g00000000000000000002.json'
        parent = directory
    else:
        require(publication in by_path and by_path[publication]['directory'] is True and
            not any(path.startswith(publication + '\\') for path in by_path), 'durable fixture lacks measured empty root')
        reservation_path = prefix + '-bootstrap-g00000000000000000001.json'
        require(reservation_path in by_path, 'durable fixture original reservation absent')
        original = document(by_path[reservation_path])
        ownership = active_ownership(by_path, drive, context, roots, 1)
        require(original == reservation(context, roots, ownership), 'original reservation differs from actual active journal')
        require(prefix + '-preserve-g00000000000000000001.json' not in by_path and
            prefix + '-retained-g00000000000000000001' not in by_path, 'durable fixture already has move effects')
        if case == 'publication_absent':
            return dict(case=case, action='remove_exact_empty_owned_root', path=publication,
                file_id=by_path[publication]['file_id'], content_base64=None)
        value = dict(schema='usk.publication_bootstrap_preservation.v1', install_id=context['install_id'],
            operation_id=context['operation_id'], reservation_sha256=original['reservation_sha256'],
            source_name='publication', source_root_identity=by_path[publication]['file_id'],
            destination_parent_identity=root(by_path[directory]['file_id']),
            destination_name=prefix.rsplit('\\', 1)[1] + '-retained-g00000000000000000001',
            tree=dict(root=native_object(by_path[publication]), root_streams=[], entries=[]))
        value['preservation_sha256'] = digest(value)
        target, parent = prefix + '-preserve-g00000000000000000001.json', directory
    raw = (canonical(value) + '\n').encode('utf-8')
    require(len(raw) <= 1024 * 1024, 'durable fixture byte bound differs')
    if case.startswith('pending_'):
        require(isinstance(pending_name, str) and re.fullmatch(r'bootstrap-[1-9][0-9]*-[0-9]+-[1-9][0-9]*', pending_name),
            'durable fixture pending basename differs')
        parent, target = directory + '\\pending', directory + '\\pending\\' + pending_name
        length = {'pending_empty': 0, 'pending_middle': len(raw) // 2, 'pending_full': len(raw)}[case]
        while True:
            try:
                raw[:length].decode('utf-8')
                break
            except UnicodeDecodeError:
                length -= 1
        raw = raw[:length]
    require(target not in by_path and by_path[parent]['directory'] is True, 'durable fixture target exists/parent differs')
    return dict(case=case, action='create_new_protected_record', path=target, parent=parent,
        parent_file_id=by_path[parent]['file_id'], content_base64=base64.b64encode(raw).decode('ascii'),
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare', action='store_true', required=True)
    parser.parse_args()
    sys.stdin.reconfigure(encoding='utf-8-sig')
    text = sys.stdin.read(4 * 1024 * 1024 + 1)
    require(0 < len(text.encode('utf-8')) <= 4 * 1024 * 1024, 'durable preparation input byte bound differs')
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'durable preparation input has duplicate members')
            value[key] = item
        return value
    value = json.loads(text, object_pairs_hook=pairs)
    require(isinstance(value, dict) and value.keys() == {'case', 'rows', 'drive', 'installed', 'volume_id', 'pending_name'},
        'durable preparation input is not closed')
    print(json.dumps(prepare(**value), separators=(',', ':')))


if __name__ == '__main__':
    main()
