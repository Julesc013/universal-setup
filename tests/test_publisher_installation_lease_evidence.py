# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic record contradictions; these tests never qualify native ownership."""
import copy
import hashlib
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
        terminal = dict(active, status='completed', result_state_revision=revision)
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows += [record(LEASES + f'\\g{generation:020d}-active.json', active),
                 record(LEASES + f'\\g{generation:020d}-terminal.json', terminal)]
        previous = terminal['ownership_sha256']
    return rows


class LeaseRecordReconciliationTests(unittest.TestCase):
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
        self.assertIsNone(snapshot(rows, DRIVE, INSTALLED, ROOT))
        transition(rows, copy.deepcopy(rows), DRIVE, INSTALLED, ROOT)
        with self.assertRaises(LeaseEvidenceError):
            transition(rows, rows + [{'path': DRIVE + 'extra.json', 'directory': False}], DRIVE, INSTALLED, ROOT)
