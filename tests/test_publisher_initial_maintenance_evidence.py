# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic corruption controls only; no actual interruption qualification."""
import copy
import hashlib
import json
import unittest

from publisher_execution_evidence import canonical_sha
from publisher_initial_maintenance_evidence import canonical, reconcile
from test_publisher_process_pair_evidence import pair_fixture
from test_publisher_worker_security import retirement_security


PINS = {'journal': 'initial_snapshot_sha256', 'original': 'original_custody_sha256',
        'context': 'original_context_record_sha256', 'roots': 'original_roots_record_sha256'}


def row(path, value, ordered=False):
    text = json.dumps(value, separators=(',', ':')) if ordered else canonical(value) + '\n'
    return {'path': path, 'directory': False, 'content_json': text,
            'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()}


def fixture():
    boundary, original, request = pair_fixture()
    tx = 'maintenance.repair.' + '1' * 32
    request['transaction_id'] = tx
    drive = 'F:\\'
    plan = {'plan_id': request['reviewed_plan_id'], 'state_root': drive + 'setup-state/state',
            'audit_root': drive + 'setup-state/audit', 'staging_parent': drive + 'setup-state/staging',
            'installed_state_digest': '2' * 64}
    request['reviewed_plan_digest'] = canonical_sha(plan)
    identity = original['original_lease_ownership']['state_root_identity']
    snapshot = {'schema': 'usk.publisher.maintenance_reviewed_snapshot.v2', 'operation': 'repair',
        'operation_id': tx, 'install_id': request['plan_request']['install_id'],
        'reviewed_plan': plan, 'apply_request': copy.deepcopy(request), 'initial_state_revision': '2' * 64,
        'installed_state': {'target_root': drive + 'publication/destination/visible', 'transaction_id': 'install.old'},
        'volume_root_identity': {'native': 'volume'}, 'state_root_identity': identity,
        'setup_root_identity': {'native': 'setup'}}
    context = {'schema': 'usk.installation_operation_context.v2', 'operation': 'repair', 'operation_id': tx,
        'install_id': request['plan_request']['install_id'], 'initial_state_revision': '2' * 64,
        'reviewed_snapshot': snapshot, 'volume_root_identity': snapshot['volume_root_identity']}
    context['context_sha256'] = canonical_sha(context)
    roots = {'schema': 'usk.installation_operation_roots.v1', 'operation_id': tx,
        'install_id': context['install_id'], 'context_sha256': context['context_sha256'],
        'state_root_identity': identity, 'setup_root_identity': snapshot['setup_root_identity']}
    roots['roots_sha256'] = canonical_sha(roots)
    original.update(schema='usk.publisher.maintenance_original_custody.v4', transaction_id=tx,
        plan_digest=request['reviewed_plan_digest'], original_context_sha256=roots['roots_sha256'],
        worker_security=retirement_security(original['worker_security']))
    lease = original['original_lease_ownership']
    lease.update(operation_id=tx, operation_context_sha256=roots['roots_sha256'])
    lease.pop('ownership_sha256')
    lease['ownership_sha256'] = canonical_sha(lease)
    broker = original['broker_readback']
    broker['request_sha256'] = broker['custody']['request_sha256'] = canonical_sha(request)
    source = {'schema': 'usk.maintenance_source_context.v1', 'operation': 'repair',
        'install_id': context['install_id'], 'transaction_id': tx, 'plan_id': plan['plan_id'],
        'plan_digest': request['reviewed_plan_digest'], 'applied_at': request['applied_at'],
        'original_installed_transaction_id': 'install.old', 'original_installed_state_digest': '2' * 64,
        'reviewed_plan_ref': tx + '.maintenance-plan.json', 'reviewed_plan_sha256': '9' * 64,
        'installed_root': {'root': snapshot['installed_state']['target_root'],
                           'native_identity': original['installed_root_journal_identity']},
        'operation_target_root': drive + 'publication/destination/.usk-repair-' + tx}
    source.update({key: {'root': plan[key]} for key in ('state_root', 'audit_root', 'staging_parent')})
    stream = {'version': 1, 'restart_origin': None, 'source_context': canonical(source),
              'source_digest': canonical_sha(source), 'entries': []}
    stream['digest'] = canonical_sha(stream)
    roles = {'target': source['operation_target_root'], 'staging': plan['staging_parent'] + '/.usk-stage-' + tx,
             'setup_state': plan['state_root'], 'audit': plan['audit_root']}
    phases = ('created', 'validated', 'planned', 'staging')
    stamp = '2026-10-07T00:00:00Z'
    transitions = [{'sequence': i, 'from': None if i == 0 else phases[i - 1], 'to': phase,
        'transition_id': tx + '.' + str(i), 'recorded_at': stamp, 'durable_before_external_visibility': True}
        for i, phase in enumerate(phases)]
    chain = ''.join(str(i) + '\0' + (t['from'] or '') + '\0' + t['to'] + '\0' + stamp + '\n'
                    for i, t in enumerate(transitions))
    journal = {'schema': 'usk.transaction_journal.v1', 'operation': 'repair', 'transaction_id': tx,
        'plan_id': plan['plan_id'], 'plan_digest': request['reviewed_plan_digest'], 'current_state': 'staging',
        'journal_digest': hashlib.sha256(chain.encode()).hexdigest(), 'updated_at': stamp,
        'roots': [{'role': role, 'root': path} for role, path in roles.items()], 'transitions': transitions,
        'recovery_metadata': {'staging_identity': None, 'staged_files': [], 'stream_journal': stream,
                              'stream_cleanup_policy': 'retain_only', 'commit_cleanup_policy': 'retain_only'},
        'recovery': {'required': False, 'available_actions': ['retain_for_operator']}}
    prefix = drive + 'installation-operations\\install-' + canonical_sha(context['install_id']) + '\\operation-' + canonical_sha(tx)
    transaction = drive + 'setup-state\\state\\transactions\\' + tx
    value = {'schema': 'usk.publisher_initial_maintenance_evidence_input.v1', 'drive': drive, 'request': request,
        'service_name': boundary['service_name'], 'boundary': boundary,
        'context': row(prefix + '.json', context), 'roots': row(prefix + '-roots.json', roots),
        'original': row(transaction + '.native-maintenance-original.json', original),
        'journal': row(transaction + '.journal.json', journal, True)}
    boundary.update(phase='maintenance_initial', status='terminated_initial_maintenance_before_staging',
        maintenance_transaction_id=tx, maintenance_plan_digest=request['reviewed_plan_digest'],
        maintenance_writer_lease_ownership=copy.deepcopy(lease))
    boundary.update({pin: value[key]['sha256'] for key, pin in PINS.items()})
    boundary.update({key: False for key in ('staging_before_kill', 'staging_after_kill', 'target_before_kill', 'target_after_kill')})
    return value


def replace_document(value, key, document):
    value[key] = row(value[key]['path'], document, key == 'journal')
    value['boundary'][PINS[key]] = value[key]['sha256']


class InitialMaintenanceEvidenceTests(unittest.TestCase):
    def test_actual_ordered_journal_shape_joins_original_pair_without_authority(self):
        value = fixture()
        self.assertFalse(value['journal']['content_json'].endswith('\n'))
        result = reconcile(value)
        self.assertTrue(result['shared_initial_snapshot_checked'])
        self.assertTrue(result['original_provenance']['original_pair_closure_checked'])
        self.assertFalse(result['native_restoration_qualified'])
        self.assertFalse(result['profile_qualified'])

    def test_raw_bytes_and_distinct_context_root_linkage_must_both_match(self):
        value = fixture()
        value['journal']['content_json'] += ' '
        with self.assertRaises(ValueError): reconcile(value)
        value = fixture()
        document = json.loads(value['original']['content_json'])
        document['original_context_sha256'] = json.loads(value['context']['content_json'])['context_sha256']
        replace_document(value, 'original', document)
        with self.assertRaises(ValueError): reconcile(value)

    def test_rehashed_later_or_corrupted_prefix_is_not_initial_intent(self):
        changes = [('transitions', lambda d: d['transitions'].pop()),
            ('journal_digest', lambda d: d.update(journal_digest='0' * 64)),
            ('creator', lambda d: d['recovery_metadata'].update(staging_identity='created')),
            ('payload', lambda d: d['recovery_metadata']['stream_journal']['entries'].append({'phase': 'writing'})),
            ('restart', lambda d: d['recovery_metadata']['stream_journal'].update(restart_origin={'transaction_id': 'other'})),
            ('root', lambda d: d['roots'][1].update(root='F:\\elsewhere'))]
        for label, change in changes:
            with self.subTest(label=label):
                value = fixture();document = json.loads(value['journal']['content_json']);change(document)
                replace_document(value, 'journal', document)
                with self.assertRaises(ValueError): reconcile(value)

    def test_duplicate_journal_keys_are_refused_even_with_matching_raw_hash(self):
        value = fixture();text = value['journal']['content_json']
        value['journal']['content_json'] = '{"current_state":"completed",' + text[1:]
        value['journal']['sha256'] = hashlib.sha256(value['journal']['content_json'].encode()).hexdigest()
        value['boundary'][PINS['journal']] = value['journal']['sha256']
        with self.assertRaises(ValueError): reconcile(value)

    def test_native_child_kill_unknown_closure_and_raced_namespace_cannot_qualify(self):
        for section, key, change in [('native_process_pair', 'child_termination_invoked', True),
            ('native_process_pair', 'child_native_wait_result', 258), (None, 'staging_after_kill', True),
            (None, 'target_after_kill', True), (None, 'original_pair_closure_confirmed', False)]:
            with self.subTest(key=key):
                value = fixture();target = value['boundary'] if section is None else value['boundary'][section]
                target[key] = change
                with self.assertRaises(ValueError): reconcile(value)

    def test_absolute_fixture_paths_refuse_parent_traversal_and_case_changes(self):
        for path in ('F:\\setup-state\\state\\..\\state', 'f:\\setup-state\\state', 'F:setup-state\\state'):
            with self.subTest(path=path):
                value = fixture();document = json.loads(value['journal']['content_json'])
                document['roots'][2]['root'] = path;replace_document(value, 'journal', document)
                with self.assertRaises(ValueError): reconcile(value)


if __name__ == '__main__':
    unittest.main()
