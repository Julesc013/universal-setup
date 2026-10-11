# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent data reconciliation for the finite owned durable-state fixtures.

Callers must separately prove actual ended holders, owned
hosted construction, native readbacks and ordinary authenticated completion.
No JSON value grants native custody or publication authority.
"""
import base64
import json
import re

from publisher_installation_lease_evidence import (
    bootstrap_takeover, bootstrap_preservation_takeover, digest, document, require, snapshot, transition)

import publisher_bootstrap_durable_state_fixture as factory
SCOPE = 'system_constructed_durable_state_after_observed_bootstrap_process_loss'


def observed_fixture(record, original, drive, installed, observation, capture, volume_boundary):
    """Bind the separately observed constructor to original custody and tokens."""
    from publisher_standard_public_evidence import reader_rows, native_rows, native_boundary
    require(isinstance(record, dict) and record.keys() == {
        'schema', 'scope', 'case', 'fixture_actor', 'pending_name', 'created_at_file_time', 'readback'} and
        record['schema'] == 'usk.publisher_constructed_bootstrap_durable_state.v1' and record['scope'] == SCOPE and
        record['case'] in factory.CASES, 'constructed durable receipt is not closed/scoped')
    actor = record['fixture_actor']
    launcher = observation['launcher_process']
    require(isinstance(actor, dict) and actor.keys() == {
        'identity', 'process_id', 'creation_file_time', 'service', 'service_stopped', 'parent_file_id', 'removed_root_file_id'} and
        actor['identity'] == launcher['identity'] == 'S-1-5-18' and
        type(actor['process_id']) is int and actor['process_id'] > 0 and actor['process_id'] == launcher['process_id'] and
        isinstance(actor['creation_file_time'], str) and re.fullmatch('[1-9][0-9]{16,18}', actor['creation_file_time']) and
        actor['creation_file_time'] == launcher['creation_file_time'] and
        actor['service'] == observation['service'] and actor['service_stopped'] is True,
        'constructed durable actor differs from the actual acknowledged SYSTEM launcher')
    require(isinstance(record['created_at_file_time'], str) and
        re.fullmatch('[1-9][0-9]{16,18}', record['created_at_file_time']) and
        int(record['created_at_file_time']) > int(actor['creation_file_time']), 'constructed durable timestamp differs')
    pending_name = record['pending_name']
    require((isinstance(pending_name, str) and re.fullmatch('bootstrap-' + str(actor['process_id']) + '-[0-9]+-[1-9][0-9]*', pending_name))
        if record['case'].startswith('pending_') else pending_name is None, 'constructed durable pending name differs')
    volume_id = volume_boundary['root']['file_id']
    independent = record['readback']['independent']
    rows = reader_rows(record['readback'], capture, observation['account_sid'])
    native_rows(rows, drive, installed['target_root'].replace('/', '\\'), observation['service_sid'], observation['account_sid'])
    native_boundary(independent['volume_boundary'])
    require(independent['volume_boundary'] == volume_boundary, 'constructed durable volume custody changed')
    expected, added = constructed_rows(record['case'], original, rows, drive, installed, volume_id, pending_name)
    if expected['action'] == 'remove_exact_empty_owned_root':
        require(actor['parent_file_id'] is None and actor['removed_root_file_id'] == expected['file_id'],
            'constructed durable removed root identity differs')
    else:
        require(actor['parent_file_id'] == expected['parent_file_id'] and actor['removed_root_file_id'] is None,
            'constructed durable held parent identity differs')
    generation = {'publication_absent': 1, 'next_reservation_absent': 2}.get(record['case'])
    if generation:
        reserved_absence(independent, drive, installed, generation)
    else:
        require('publication_absence' not in independent, 'constructed durable ordinary reader admitted absence')
    return rows, added if record['case'].startswith('pending_') else None


def indexed(rows):
    require(isinstance(rows, list) and 0 < len(rows) <= 10000 and
        all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in rows), 'durable rows budget/path differs')
    result = {row['path']: row for row in rows}
    require(len(result) == len(rows), 'durable rows alias')
    return result


def constructed_rows(case, original, constructed, drive, installed, volume_id, pending_name=None):
    """Bind the one named effect to original native bytes and unchanged custody."""
    expected = factory.prepare(case, original, drive, installed, volume_id, pending_name)
    old, new = indexed(original), indexed(constructed)
    path = expected['path']
    if expected['action'] == 'remove_exact_empty_owned_root':
        require(set(new) == set(old) - {path} and all(new[name] == row for name, row in old.items() if name != path),
            'constructed absence removed another object or changed original custody')
        return expected, None
    require(set(new) == set(old) | {path} and all(new[name] == row for name, row in old.items()),
        'constructed durable state changed original custody or added another object')
    row = new[path]
    require(row.get('directory') is False and type(row.get('bytes')) is int and
        row['bytes'] == expected['bytes'] and row.get('sha256') == expected['sha256'] and
        row.get('native_name') == path[2:] and type(row.get('link_count')) is int and row['link_count'] == 1 and
        row.get('reparse_tag', 0) == 0 and row.get('case_sensitive') is False and row.get('protected') is True and
        row.get('owner') in ('S-1-5-18', 'S-1-5-32-544') and isinstance(row.get('raw_aces'), list),
        'constructed durable native file identity/type/bytes/security differs')
    factory.root(row.get('file_id'))
    streams = row.get('streams')
    require(isinstance(streams, list) and len(streams) == 1 and streams[0].get('name') == '::$DATA' and
        type(streams[0].get('size')) is int and streams[0]['size'] == expected['bytes'],
        'constructed durable file stream closure differs')
    if not case.startswith('pending_'):
        raw = base64.b64decode(expected['content_base64'])
        require(document(row) == json.loads(raw) and row['content_json'].encode('utf-8') == raw,
            'constructed durable canonical record differs')
    else:
        require(row.get('content_json') is None, 'unpublished fragment was promoted into a canonical record')
    return expected, row


def without_retained_fragment(rows, fragment, drive, installed):
    """Exclude only one already bound fragment from lease record closure.

    Its full measured row must remain present and identical in every readback.
    All original native rows remain available to namespace/security validators.
    Default lease snapshot validation still refuses unpublished fragments.
    """
    actual = indexed(rows)
    directory = drive + 'installation-operations\\install-' + digest(installed['install_id']) + '\\pending\\'
    require(isinstance(fragment, dict) and isinstance(fragment.get('path'), str) and
        fragment['path'].startswith(directory) and
        re.fullmatch('bootstrap-[1-9][0-9]*-[0-9]+-[1-9][0-9]*', fragment['path'][len(directory):]) and
        fragment['path'] in actual and actual[fragment['path']] == fragment,
        'known retained fragment disappeared, changed or escaped its original pending directory')
    return [row for row in rows if row['path'] != fragment['path']]


def reserved_absence(readback, drive, installed, generation):
    require(type(generation) is int and generation in (1, 2) and isinstance(readback, dict),
        'reserved absence input generation differs')
    record = readback.get('publication_absence')
    require(isinstance(record, dict) and record.keys() == {'schema', 'path', 'parent_root_identity',
        'win32_error_before', 'win32_error_after', 'generation', 'reservation_record_path', 'ownership_record_path',
        'previous_preservation_record_path', 'previous_retained_root_path'} and
        record['schema'] == 'usk.publisher_reserved_publication_absence.v1' and
        type(record['generation']) is int and record['generation'] == generation and
        record['path'] == drive + 'publication' and
        all(type(record[key]) is int and record[key] == 2 for key in ('win32_error_before', 'win32_error_after')),
        'reserved absence record is not closed or lacks actual native absence results')
    volume_id = readback['volume_boundary']['root']['file_id']
    require(record['parent_root_identity'] == volume_id, 'reserved absence native volume root differs')
    rows = readback['rows']
    by_path, directory, prefix, context, roots = factory.records(rows, drive, installed, volume_id)
    require(drive + 'publication' not in by_path and
        not any(path.startswith(drive + 'publication\\') for path in by_path), 'reserved absence contains publication material')
    reservation = prefix + f'-bootstrap-g{generation:020d}.json'
    ownership = drive + 'setup-state\\state\\leases\\install-' + digest(installed['install_id']) + f'\\g{generation:020d}-active.json'
    active = factory.active_ownership(by_path, drive, context, roots, generation)
    require(record['reservation_record_path'] == reservation and record['ownership_record_path'] == ownership and
        reservation in by_path and document(by_path[reservation]) == factory.reservation(context, roots, active) and
        prefix + f'-preserve-g{generation:020d}.json' not in by_path and
        prefix + f'-retained-g{generation:020d}' not in by_path,
        'reserved absence generation paths or native reservation/ownership differ')
    retained, move = prefix + '-retained-g00000000000000000001', prefix + '-preserve-g00000000000000000001.json'
    if generation == 1:
        require(record['previous_preservation_record_path'] is None and record['previous_retained_root_path'] is None and
            retained not in by_path and move not in by_path, 'generation1 reserved absence contains invented prior preservation')
    else:
        require(record['previous_preservation_record_path'] == move and record['previous_retained_root_path'] == retained and
            move in by_path and retained in by_path and by_path[retained]['directory'] is True and
            document(by_path[move])['schema'] == 'usk.publication_bootstrap_preservation.v1',
            'generation2 reserved absence lacks original native retained preservation')
    return dict(status='bindings_consistent', generation=generation, parent_root_identity=volume_id,
        profile_qualified=False, publication_authority_granted=False)


def reconcile(case, original, constructed, after, drive, installed, volume_id, terminated_holders,
              pending_name=None, original_empty=None):
    expected, added = constructed_rows(case, original, constructed, drive, installed, volume_id, pending_name)
    final = indexed(after)
    if added is not None:
        require(added['path'] in final and final[added['path']] == added,
            'native retry changed or removed the measured durable fixture file')
    require(isinstance(terminated_holders, list) and len(terminated_holders) == (2 if case == 'next_reservation_absent' else 1),
        'durable fixture ended-holder count differs')
    if case.startswith('pending_'):
        completed = without_retained_fragment(after, added, drive, installed)
        result = bootstrap_takeover(original, completed, drive, installed, volume_id, terminated_holders[0])
    elif case == 'move_intent':
        result = bootstrap_takeover(original, after, drive, installed, volume_id, terminated_holders[0])
    elif case == 'next_reservation_absent':
        require(original_empty is not None, 'next-reservation fixture lacks original real bootstrap loss rows')
        result = bootstrap_preservation_takeover(original_empty, original, after, drive, installed, volume_id, terminated_holders)
        prefix = expected['path'][:-len('-bootstrap-g00000000000000000002.json')]
        disposition = document(final[prefix + '-preserve-g00000000000000000002.json'])
        history = snapshot(after, drive, installed, volume_id)['history']
        require(disposition['schema'] == 'usk.publication_bootstrap_absence.v1' and
            disposition['closing_ownership'] == history[2], 'generation2 absence is not closed by the actual generation3')
    else:
        require(case == 'publication_absent', 'durable takeover case differs')
        history = snapshot(after, drive, installed, volume_id)['history']
        require(len(history) == 3 and [value['status'] for value in history] == ['active', 'active', 'completed'] and
            history[0]['holder'] == terminated_holders[0] and history[1]['holder'] != terminated_holders[0] and
            history[0]['expected_state_revision'] == history[1]['expected_state_revision'] == digest([]),
            'constructed absence is not one actual interrupted generation followed by completion')
        old, directory, prefix, context, roots = factory.records(original, drive, installed, volume_id)
        active_path = drive + 'setup-state\\state\\leases\\install-' + digest(installed['install_id']) + '\\g00000000000000000001-active.json'
        require(document(old[active_path]) == history[0], 'constructed absence original native ownership differs')
        files = {prefix + '.json', prefix + '-roots.json', prefix + '-bootstrap-g00000000000000000001.json',
                 active_path, drive + 'setup-state\\.usk-owned-root.v1.json'}
        require({path for path, row in old.items() if row['directory'] is False} == files and
            document(old[drive + 'setup-state\\.usk-owned-root.v1.json']) == {
                'schema': 'usk.setup_owned_root.v1', 'acceptance_root': drive.replace('\\', '/')},
            'constructed absence has extra original effects or an unbound setup marker')
        require(all(path in final and final[path] == row for path, row in indexed(constructed).items()) and
            drive + 'publication' in final and final[drive + 'publication']['directory'] is True and
            final[drive + 'publication']['file_id'] != old[drive + 'publication']['file_id'] and
            prefix + '-retained-g00000000000000000001' not in final,
            'constructed absence changed original custody or fabricated retained material')
        disposition = document(final[prefix + '-preserve-g00000000000000000001.json'])
        require(disposition['schema'] == 'usk.publication_bootstrap_absence.v1' and
            disposition['closing_ownership'] == history[1], 'generation1 absence is not closed by actual generation2')
        result = dict(status='bindings_consistent', replacement_generation=2, terminated_holder=terminated_holders[0],
            retained_objects=0, profile_qualified=False, publication_authority_granted=False)
    return dict(result, schema='usk.publisher_constructed_durable_takeover_reconciliation.v1', scope=SCOPE,
        case=case, fixture_bytes=expected.get('bytes'), retained_fragment=added if case.startswith('pending_') else None,
        native_crash_at_constructed_state_observed=False, native_uncertain_error_observed=False, power_loss_observed=False)


def reconcile_request(value):
    require(isinstance(value, dict), 'durable request differs')
    mode = value.get('mode')
    require(isinstance(value.get('case'), str) and value['case'] in factory.CASES and
        (isinstance(value.get('pending_name'), str) if value['case'].startswith('pending_') else value.get('pending_name') is None),
        'durable request named case or pending name differs')
    common = {'mode', 'case', 'original', 'constructed', 'drive', 'installed', 'volume_root_id', 'pending_name'}
    require(set(value) == common | ({'after', 'terminated_holders', 'original_empty'} if mode == 'constructed_durable_takeover'
        else {'rows'} if mode == 'snapshot' else {'before', 'after'}), 'durable request is not closed')
    arguments = (value['drive'], value['installed'], value['volume_root_id'])
    if mode == 'constructed_durable_takeover':
        require((value['case'] == 'next_reservation_absent') is (value['original_empty'] is not None),
            'durable request original loss phase differs')
        result = reconcile(value['case'], value['original'], value['constructed'], value['after'], *arguments,
            value['terminated_holders'], value['pending_name'], value['original_empty'])
    else:
        require(value['case'].startswith('pending_') and mode in ('snapshot', 'append', 'readonly'),
            'retained fragment exception requires a named pending fixture')
        _, fragment = constructed_rows(value['case'], value['original'], value['constructed'], *arguments, value['pending_name'])
        require(fragment is not None, 'retained fragment is absent')
        if mode == 'snapshot':
            result = snapshot(without_retained_fragment(value['rows'], fragment, *arguments[:2]), *arguments)
        else:
            result = transition(without_retained_fragment(value['before'], fragment, *arguments[:2]),
                without_retained_fragment(value['after'], fragment, *arguments[:2]), *arguments, readonly=mode == 'readonly')
    return dict(status='bindings_consistent', coordination=result, profile_qualified=False, publication_authority_granted=False)


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', choices=['-'], required=True)
    parser.parse_args()
    sys.stdin.reconfigure(encoding='utf-8-sig')
    text = sys.stdin.read(4 * 1024 * 1024 + 1)
    require(0 < len(text.encode('utf-8')) <= 4 * 1024 * 1024, 'durable request byte bound differs')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'durable request has duplicate members')
            result[key] = value
        return result
    print(json.dumps(reconcile_request(json.loads(text, object_pairs_hook=pairs)), separators=(',', ':')))


if __name__ == '__main__':
    main()
