# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic record contradictions; these tests never qualify native ownership."""
import copy
import hashlib
import json
import unittest
from publisher_installation_lease_evidence import canonical, digest, snapshot, transition, LeaseEvidenceError

DRIVE = 'U:\\'
ROOT = '0000000000000001:' + 'a' * 32
STATE_ROOT = {'file_id': 'b' * 32, 'volume_serial': '1'}
INSTALLED = {'install_id': 'org.example.setup', 'transaction_id': 'operation.1', 'lifecycle_status': 'installed'}
INSTALL_NAME = 'install-' + digest(INSTALLED['install_id'])
LEASES = DRIVE + 'setup-state\\state\\leases\\' + INSTALL_NAME
CONTEXTS = DRIVE + 'installation-operations\\' + INSTALL_NAME


def record(path, value):
    text = canonical(value) + '\n'
    return {'path': path, 'directory': False, 'bytes': len(text.encode('utf-8')),
            'content_json': text, 'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()}


def fixture(generations=1):
    reviewed = {'transaction_id': INSTALLED['transaction_id'], 'plan_digest': 'f' * 64}
    context = {'schema': 'usk.installation_operation_context.v1', 'install_id': INSTALLED['install_id'],
        'operation': 'install_local', 'operation_id': INSTALLED['transaction_id'],
        'volume_root_identity': {'file_id': 'a' * 32, 'volume_serial': '1'},
        'initial_state_revision': digest([]), 'reviewed_snapshot': reviewed}
    context['context_sha256'] = digest(context)
    roots = {'schema': 'usk.installation_operation_roots.v1', 'install_id': INSTALLED['install_id'],
        'operation_id': INSTALLED['transaction_id'], 'context_sha256': context['context_sha256'],
        'setup_root_identity': {'file_id': 'b' * 32, 'volume_serial': '1'}, 'state_root_identity': STATE_ROOT}
    roots['roots_sha256'] = digest(roots)
    state = DRIVE + 'setup-state\\state'
    directories = [DRIVE + 'setup-state', state, state + '\\leases', LEASES, LEASES + '\\pending',
                   DRIVE + 'installation-operations', CONTEXTS, CONTEXTS + '\\pending']
    rows = [{'path': path, 'directory': True, 'file_id': '0000000000000001:' + 'b' * 32} for path in directories]
    filename = INSTALLED['install_id'] + '.' + INSTALLED['transaction_id'] + '.json'
    revision = digest([{'record': filename, 'sha256': digest(INSTALLED)}])
    rows += [record(CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id']) + '.json', context),
             record(CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id']) + '-roots.json', roots),
             record(DRIVE + 'publication\\journal\\lab-reviewed-plan.json', reviewed),
             record(state + '\\installed\\' + filename, INSTALLED)]
    previous = None
    for generation in range(1, generations + 1):
        active = {'schema': 'usk.installation_lease_ownership.v1', 'install_id': INSTALLED['install_id'],
            'operation': 'install_local', 'operation_id': INSTALLED['transaction_id'], 'attempt_id': f'attempt.{generation}',
            'state_root_identity': STATE_ROOT, 'holder': {'process_id': 100 + generation, 'process_creation_time': '0' * 15 + '1'},
            'generation': generation, 'expected_state_revision': digest([]) if generation == 1 else revision,
            'status': 'active', 'result_state_revision': None, 'predecessor_sha256': previous,
            'operation_context_sha256': roots['roots_sha256']}
        active['ownership_sha256'] = digest(active)
        if generation == 1:
            reservation = {'schema': 'usk.publication_bootstrap_reservation.v1', 'install_id': INSTALLED['install_id'],
                'operation_id': INSTALLED['transaction_id'], 'context_sha256': context['context_sha256'],
                'roots_sha256': roots['roots_sha256'], 'volume_root_identity': context['volume_root_identity'],
                'ownership': copy.deepcopy(active), 'publication_absent': True}
            reservation['reservation_sha256'] = digest(reservation)
            rows.append(record(CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id']) +
                               '-bootstrap-g00000000000000000001.json', reservation))
        terminal = dict(active, status='completed', result_state_revision=revision)
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows += [record(LEASES + f'\\g{generation:020d}-active.json', active),
                 record(LEASES + f'\\g{generation:020d}-terminal.json', terminal)]
        previous = terminal['ownership_sha256']
    return rows


def preserved_fixture(anchor_count=4, snapshot_bytes=None):
    rows = fixture(2)
    first_active = json.loads(next(row for row in rows if row['path'] == LEASES + '\\g00000000000000000001-active.json')['content_json'])
    rows = [row for row in rows if row['path'] != LEASES + '\\g00000000000000000001-terminal.json']
    second_path = LEASES + '\\g00000000000000000002-active.json'
    second = json.loads(next(row for row in rows if row['path'] == second_path)['content_json'])
    second.update(expected_state_revision=digest([]), predecessor_sha256=first_active['ownership_sha256'])
    second['ownership_sha256'] = digest({key: value for key, value in second.items() if key != 'ownership_sha256'})
    terminal_path = LEASES + '\\g00000000000000000002-terminal.json'
    revision = json.loads(next(row for row in rows if row['path'] == terminal_path)['content_json'])['result_state_revision']
    terminal = dict(second, status='completed', result_state_revision=revision)
    terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
    rows = [record(row['path'], second if row['path'] == second_path else terminal)
            if row['path'] in (second_path, terminal_path) else row for row in rows]
    prefix = CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id'])
    reservation = json.loads(next(row for row in rows if row['path'] == prefix + '-bootstrap-g00000000000000000001.json')['content_json'])
    next_reservation = dict(reservation, ownership=second)
    next_reservation['reservation_sha256'] = digest({key: value for key, value in next_reservation.items() if key != 'reservation_sha256'})
    rows.append(record(prefix + '-bootstrap-g00000000000000000002.json', next_reservation))
    retained_path = prefix + '-retained-g00000000000000000001'
    def observed(path, identity, directory, raw=b''):
        aces = [{'type': 0, 'flags': 0, 'access_mask': 2032127, 'sid': 'S-1-5-18'},
                {'type': 0, 'flags': 0, 'access_mask': 2032127, 'sid': 'S-1-5-80-1-2-3-4-5'}]
        obj = {'file_id': '0000000000000001:' + f'{identity:032x}', 'attributes': 16 if directory else 32,
            'link_count': 1, 'case_sensitive': False, 'reparse_tag': 0, 'owner_sid': 'S-1-5-18',
            'dacl_protected': True, 'dacl_aces': aces}
        streams = [] if directory else [{'name': '::$DATA', 'size': len(raw), 'allocation_size': 4096}]
        row = {'path': path, 'directory': directory, 'file_id': obj['file_id'], 'attributes': obj['attributes'],
            'link_count': 1, 'case_sensitive': False, 'owner': 'S-1-5-18', 'protected': True, 'raw_aces': aces,
            'streams': streams, 'bytes': len(raw), 'sha256': None if directory else hashlib.sha256(raw).hexdigest(),
            'content_json': None if directory else raw.decode('utf-8', errors='replace')}
        return row, obj
    retained, root_object = observed(retained_path, 99, True)
    rows.append(retained)
    entries = []
    for index, name in enumerate(('staging', 'destination', 'state', 'journal')[:anchor_count]):
        row, obj = observed(retained_path + '\\' + name, 100 + index, True)
        rows.append(row)
        entries.append({'relative_path': name, 'object': obj, 'bytes': 0, 'sha256': '', 'streams': []})
    if snapshot_bytes is not None:
        reviewed = json.loads(next(row for row in rows if row['path'] == DRIVE + 'publication\\journal\\lab-reviewed-plan.json')['content_json'])
        raw = (canonical(reviewed) + '\n').encode('utf-8')[:snapshot_bytes]
        row, obj = observed(retained_path + '\\journal\\lab-reviewed-plan.json', 104, False, raw)
        rows.append(row)
        entries.append({'relative_path': 'journal/lab-reviewed-plan.json', 'object': obj, 'bytes': len(raw),
                        'sha256': row['sha256'], 'streams': row['streams']})
    move = {'schema': 'usk.publication_bootstrap_preservation.v1', 'install_id': INSTALLED['install_id'],
        'operation_id': INSTALLED['transaction_id'], 'reservation_sha256': reservation['reservation_sha256'],
        'source_name': 'publication', 'source_root_identity': retained['file_id'],
        'destination_parent_identity': {'file_id': 'b' * 32, 'volume_serial': '1'},
        'destination_name': retained_path.rsplit('\\', 1)[1],
        'tree': {'root': root_object, 'root_streams': [], 'entries': entries}}
    move['preservation_sha256'] = digest(move)
    rows.append(record(prefix + '-preserve-g00000000000000000001.json', move))
    return rows


class LeaseRecordReconciliationTests(unittest.TestCase):
    def test_current_bootstrap_reservation_cannot_be_omitted(self):
        rows = [row for row in fixture() if '-bootstrap-' not in row['path']]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        historical = snapshot(rows, DRIVE, INSTALLED, ROOT, allow_legacy_missing_bootstrap=True)
        self.assertEqual(historical['bootstrap_protocol'], 'historical_unreserved')
        rows = [row for row in preserved_fixture(4, 9)
                if not row['path'].endswith('-bootstrap-g00000000000000000002.json')]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_recorded_fresh_creator_must_match_latest_native_reservation(self):
        rows = preserved_fixture(4, 9)
        active = json.loads(next(row for row in rows if row['path'] == LEASES + '\\g00000000000000000002-active.json')['content_json'])
        prepared = {'execution_origin': 'created_empty_in_current_worker', 'execution_phases': [
            {'execution': {'service': {'process_id': active['holder']['process_id']}}}]}
        path = DRIVE + 'publication\\journal\\lab-prepared-evidence.json'
        snapshot(rows + [record(path, prepared)], DRIVE, INSTALLED, ROOT)
        prepared['execution_phases'][0]['execution']['service']['process_id'] += 1
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows + [record(path, prepared)], DRIVE, INSTALLED, ROOT)

    def test_preserved_bootstrap_prefixes_and_snapshot_prefix_bytes(self):
        for count, size in [(0, None), (1, None), (2, None), (3, None), (4, None), (4, 0), (4, 9), (4, 10000)]:
            with self.subTest(anchors=count, bytes=size):
                rows = preserved_fixture(count, size)
                self.assertEqual(len(snapshot(rows, DRIVE, INSTALLED, ROOT)['history']), 3)

    def test_retained_bootstrap_identity_security_and_bytes_are_independent(self):
        for key, value in [('file_id', ROOT), ('owner', 'S-1-5-32-545'), ('sha256', 'e' * 64), ('bytes', 999)]:
            rows = preserved_fixture(4, 9)
            row = next(row for row in rows if '-retained-' in row['path'] and not row['directory'])
            row[key] = value
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_resealed_preservation_cannot_change_parent_or_original_snapshot_prefix(self):
        for changed_key in ('destination_parent_identity', 'reservation_sha256', 'source_name'):
            rows = preserved_fixture(4, 9)
            index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
            move = json.loads(rows[index]['content_json'])
            move[changed_key] = {'file_id': 'd' * 32, 'volume_serial': '1'} if changed_key == 'destination_parent_identity' else 'unrelated'
            move['preservation_sha256'] = digest({key: value for key, value in move.items() if key != 'preservation_sha256'})
            rows[index] = record(rows[index]['path'], move)
            with self.subTest(key=changed_key), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)
        rows = preserved_fixture(4, 9)
        move_index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
        move = json.loads(rows[move_index]['content_json'])
        entry = move['tree']['entries'][-1]
        changed_sha = hashlib.sha256(b'unrelated').hexdigest()
        entry['sha256'] = changed_sha
        move['preservation_sha256'] = digest({key: value for key, value in move.items() if key != 'preservation_sha256'})
        rows[move_index] = record(rows[move_index]['path'], move)
        next(row for row in rows if '-retained-' in row['path'] and not row['directory'])['sha256'] = changed_sha
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_absent_bootstrap_disposition_binds_later_actual_ownership(self):
        rows = preserved_fixture(0)
        move_index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
        original_move = json.loads(rows[move_index]['content_json'])
        later = json.loads(next(row for row in rows if row['path'] == LEASES + '\\g00000000000000000002-active.json')['content_json'])
        absent = {'schema': 'usk.publication_bootstrap_absence.v1', 'install_id': INSTALLED['install_id'],
            'operation_id': INSTALLED['transaction_id'], 'reservation_sha256': original_move['reservation_sha256'],
            'closing_ownership': later, 'publication_absent': True}
        absent['preservation_sha256'] = digest(absent)
        rows[move_index] = record(rows[move_index]['path'], absent)
        rows = [row for row in rows if '-retained-' not in row['path']]
        snapshot(rows, DRIVE, INSTALLED, ROOT)
        absent['closing_ownership']['holder']['process_id'] = 999
        absent['preservation_sha256'] = digest({key: value for key, value in absent.items() if key != 'preservation_sha256'})
        move_index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
        rows[move_index] = record(rows[move_index]['path'], absent)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_preserved_bootstrap_extra_objects_and_missing_ancestors_refuse(self):
        rows = preserved_fixture(4, 9)
        root_path = next(row['path'] for row in rows if '-retained-' in row['path'] and row['path'].endswith('01'))
        for bad in (rows + [record(root_path + '\\payload.bin', {})],
                    [row for row in rows if row['path'] != root_path + '\\destination']):
            with self.assertRaises(LeaseEvidenceError):
                snapshot(bad, DRIVE, INSTALLED, ROOT)

    def test_recovery_appends_one_generation_and_verification_is_readonly(self):
        before, after = fixture(), fixture(2)
        self.assertEqual(len(snapshot(before, DRIVE, INSTALLED, ROOT)['history']), 2)
        transition(before, after, DRIVE, INSTALLED, ROOT)
        transition(after, copy.deepcopy(after), DRIVE, INSTALLED, ROOT, readonly=True)
        with self.assertRaises(LeaseEvidenceError):
            transition(before, after, DRIVE, INSTALLED, ROOT, readonly=True)

    def test_cannot_change_any_prior_payload_or_journal_row(self):
        before = fixture()
        for key, value in [('bytes', 999), ('sha256', '0' * 64), ('native_name', '\\changed')]:
            after = fixture(2)
            after.append({'path': DRIVE + 'publication\\destination\\visible\\payload.bin', 'directory': False})
            original = copy.deepcopy(after[-1])
            old = before + [original]
            after[-1][key] = value
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                transition(old, after, DRIVE, INSTALLED, ROOT)

    def test_cannot_append_extra_objects_or_skip_generations(self):
        before = fixture()
        for after in (fixture(3), fixture(2) + [record(LEASES + '\\pending\\unexpected.json', {})],
                      fixture(2) + [record(DRIVE + 'unexpected.json', {})]):
            with self.assertRaises(LeaseEvidenceError):
                transition(before, after, DRIVE, INSTALLED, ROOT)

    def test_resealed_changed_operation_or_state_root_is_refused(self):
        for key, value in [('operation_id', 'another.1'), ('operation_context_sha256', 'e' * 64),
                           ('generation', True), ('expected_state_revision', 'e' * 64),
                           ('state_root_identity', {'file_id': 'c' * 32, 'volume_serial': '1'})]:
            rows = fixture()
            import json
            item = json.loads(rows[-2]['content_json'])
            item[key] = value
            item['ownership_sha256'] = digest({name: data for name, data in item.items() if name != 'ownership_sha256'})
            rows[-2] = record(rows[-2]['path'], item)
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_original_context_and_completed_revision_cannot_be_replaced(self):
        import json
        rows = fixture()
        context_row = next(row for row in rows if row['path'].endswith(digest(INSTALLED['transaction_id']) + '.json'))
        changed = json.loads(context_row['content_json'])
        changed['reviewed_snapshot']['plan_digest'] = 'e' * 64
        changed['context_sha256'] = digest({key: value for key, value in changed.items() if key != 'context_sha256'})
        rows[rows.index(context_row)] = record(context_row['path'], changed)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        rows = fixture()
        terminal = json.loads(rows[-1]['content_json'])
        terminal['result_state_revision'] = 'e' * 64
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows[-1] = record(rows[-1]['path'], terminal)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_partial_observation_does_not_fabricate_terminal_record(self):
        rows = fixture()[:-1]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        self.assertEqual(len(snapshot(rows, DRIVE, INSTALLED, ROOT, allow_active=True)['history']), 1)

    def test_current_native_root_observations_must_match_retained_bindings(self):
        for path in (DRIVE + 'setup-state', DRIVE + 'setup-state\\state'):
            rows = fixture()
            next(row for row in rows if row['path'] == path)['file_id'] = '0000000000000001:' + 'c' * 32
            with self.subTest(path=path), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(fixture(), DRIVE, INSTALLED, '0000000000000002:' + 'a' * 32)

    def test_historical_evidence_still_requires_every_row_unchanged(self):
        rows = [{'path': DRIVE + 'old.json', 'directory': False}]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        with self.assertRaises(LeaseEvidenceError):
            transition(rows, copy.deepcopy(rows), DRIVE, INSTALLED, ROOT)
        self.assertIsNone(snapshot(rows, DRIVE, INSTALLED, ROOT, allow_legacy_missing=True))
        transition(rows, copy.deepcopy(rows), DRIVE, INSTALLED, ROOT, allow_legacy_missing=True)
        with self.assertRaises(LeaseEvidenceError):
            transition(rows, rows + [{'path': DRIVE + 'extra.json', 'directory': False}], DRIVE, INSTALLED, ROOT,
                       allow_legacy_missing=True)

    def test_ended_holder_takeover_can_leave_prior_generation_active(self):
        import json
        rows = fixture(2)
        # Synthetic history, without any native holder-liveness verdict.
        rows = [row for row in rows if not row['path'].endswith('g00000000000000000001-terminal.json')]
        first = json.loads(rows[-3]['content_json'])
        second = json.loads(rows[-2]['content_json'])
        second['predecessor_sha256'] = first['ownership_sha256']
        second['expected_state_revision'] = first['expected_state_revision']
        second['ownership_sha256'] = digest({key: value for key, value in second.items() if key != 'ownership_sha256'})
        terminal = dict(second, status='completed', result_state_revision=json.loads(rows[-1]['content_json'])['result_state_revision'])
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows[-2] = record(rows[-2]['path'], second)
        rows[-1] = record(rows[-1]['path'], terminal)
        self.assertEqual(len(snapshot(rows, DRIVE, INSTALLED, ROOT)['history']), 3)
        second['holder'] = first['holder']
        second['ownership_sha256'] = digest({key: value for key, value in second.items() if key != 'ownership_sha256'})
        rows[-2] = record(rows[-2]['path'], second)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
