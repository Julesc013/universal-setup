# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic current/legacy joins; no native execution or qualification claim."""
import copy
import hashlib
import unittest

from publisher_effect_broker_evidence import (immutable_broker_record, parse_registered_command,
    validate_active_child_lease, validate_broker_record, validate_original_maintenance_provenance, worker_security_context)
from publisher_execution_evidence import EvidenceError, canonical_sha, reconcile
from publisher_native_profile_evidence import project
from test_publisher_authenticated_access_evidence import descendant_fixture
from test_publisher_execution_evidence import BUILD, SDK, SERVICE, SID, encode
from test_publisher_native_profile_evidence import CLIENT, CONTEXT, SOURCE, profile_fixture
from test_publisher_worker_security import worker_security


def effect_fixture():
    prepared, visible = descendant_fixture()
    prepared['schema'] = visible['schema'] = 'usk.publisher.lab_phase_evidence.v10'
    first = prepared['execution_phases'][0]['execution']
    legacy = first['service']
    token = {'user_sid': legacy['process_user_sid'], 'groups': copy.deepcopy(legacy['process_groups']),
        'restricted_sids': copy.deepcopy(legacy['process_restricted_sids']), 'observing_thread_impersonating': False,
        **{key: int(legacy[key], 16) for key in ('token_id', 'authentication_id', 'modified_id')}, 'token_type': 1}
    child_token = dict(copy.deepcopy(token), token_id=600, modified_id=601)
    service = {'service_name': SERVICE, 'service_sid': SID, 'service_sid_type': 3,
        'service_type': 16, 'service_state': 4, 'process_id': 500, 'primary_token': token}
    image = {'path': r'C:\Program Files\USK\publisher.exe', 'volume_id': 'image-volume',
             'file_id': 'image-id', 'size_bytes': 4096, 'sha256': 'e' * 64}
    volume = {'volume_root': r'\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}' + '\\',
              'root_file_id': prepared['protected_anchors']['boundary']['file_id'], 'volume_serial': '4660'}
    target = {'registration_sha256': 'c' * 64, 'volume_identity': volume, 'disk_identity': {}, 'metadata': []}
    admission = {'schema': 'usk.publisher_registered_admission_observation.v1',
        'scope': 'held_registered_service_image_and_controller_target_admission', 'service_name': SERVICE,
        'service_sid': SID, 'process_id': 500, 'configured_caller_sid': CLIENT, 'publisher_image': image,
        'registration_sha256': 'c' * 64,
        'target_admitted_sha256': canonical_sha({'schema': 'usk.publisher_target_admitted.v1', 'identity': target}),
        'target_identity': target}
    args = [image['path'], '--service', SERVICE, '--no-receipt', volume['volume_root'],
            '--reviewed-plan-envelope', r'C:\Program Files\USK\approved.json', 'f' * 64,
            '--service-admitted-client', '--authorized-client-sid', CLIENT]
    command = ('"' + args[0] + '" --service ' + SERVICE + ' --no-receipt ' + args[4] +
               ' --reviewed-plan-envelope "' + args[6] + '" ' + ' '.join(args[7:]))
    parent_security = copy.deepcopy(first['worker_security'])
    parent_security['current_thread_id'] = parent_security['threads'][0]['thread_id'] = 710
    parent_security['threads'][0]['creation_time'] = '0000000000000710'
    broker = {'schema': 'usk.publisher_effect_broker_native_readback.v2', 'authority': 'read_only_observation',
        'request_sha256': '9' * 64, 'custody': {'schema': 'usk.publisher_effect_transport_custody.v1',
            'authority': 'none', 'request_sha256': '9' * 64, 'current_process_id': 500,
            'current_process_birth': '0000000000000500', 'peer_process_id': 600,
            'peer_process_birth': '0000000000000600', 'image': {key: value for key, value in image.items() if key != 'path'},
            'owned_job_active_process_limit': 1, 'owned_job_kill_on_close': True},
        'service': service, 'effect_primary_token': child_token, 'registered_admission': admission,
        'volume_root': copy.deepcopy(prepared['protected_anchors']['boundary']), 'broker_volume_granted_access': 0x120080,
        'authenticated_client': copy.deepcopy(first['authenticated_client']),
        'service_configuration': {'schema': 'usk.publisher_registered_execution_configuration.v1',
            'scope': 'original_held_scm_configuration', 'service_type': 16, 'start_type': 3, 'service_sid_type': 3,
            'command': command, 'account': 'LocalSystem', 'display_name': SERVICE, 'arguments': args},
        'broker_security': {'process_boundary': copy.deepcopy(first['process_boundary']), 'worker_security': parent_security}}
    worker = {'process_id': 600, 'process_birth': '0000000000000600', 'service_sid': SID, 'primary_token': child_token}
    for phase in prepared['execution_phases'] + visible['execution_phases']:
        execution = phase['execution']
        execution.update(schema='usk.publisher_execution_observation.v7',
            scope='supplied_held_child_handles_authenticated_broker_access_and_pinned_worker_security',
            service=copy.deepcopy(service), effect_worker=copy.deepcopy(worker), broker_readback=copy.deepcopy(broker))
        execution['process_boundary']['process_id'] = 600
        execution['worker_security'] = worker_security(worker_security_context(600, SID, child_token))
    prepared['source_binding']['plan_envelope_sha256'] = 'f' * 64
    prepared['operation_admission']['target_admitted_sha256'] = admission['target_admitted_sha256']
    certificate = prepared['creation_evidence']
    certificate.update(schema='usk.publisher.creation_observation.v4',
        scope='successful_child_file_create_calls_and_pinned_worker_security_to_bound_graph',
        creator={'service_name': SERVICE, 'service_sid': SID, 'broker_process_id': 500, 'effect_worker': copy.deepcopy(worker)},
        broker_readback=copy.deepcopy(broker), process_boundary=copy.deepcopy(first['process_boundary']),
        worker_security=copy.deepcopy(first['worker_security']))
    visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
    return prepared, visible


class EffectBrokerEvidenceTests(unittest.TestCase):
    def check(self, prepared, visible):
        if visible is not None:
            visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        return reconcile(encode(prepared), None if visible is None else encode(visible), SERVICE, SID, BUILD, SDK)

    def test_separate_full_child_creator_broker_and_descendant_bindings(self):
        prepared, visible = effect_fixture()
        report = self.check(prepared, visible)
        self.assertEqual(report['schema'], 'usk.publisher_execution_reconciliation.v5')
        self.assertEqual(report['worker_process_ids'], [600])
        self.assertEqual(report['broker_process_ids'], [500])
        self.assertEqual(report['effect_worker_phase_count'], 5)
        self.assertEqual(report['authenticated_descendant_objects_checked'], 4)
        self.assertEqual(report['same_handle_objects_checked'], 35)
        self.assertEqual(report['creation_observation']['creator_process_id'], 600)
        self.assertEqual(report['creation_observation']['broker_process_id'], 500)
        self.assertTrue(report['creation_observation']['original_broker_checked'])
        self.assertFalse(report['creation_observation']['profile_qualified'])
        self.assertFalse(report['profile_qualified'])

    def test_native_model_projection_retains_independent_descriptor_and_actor_proofs(self):
        prepared, visible = effect_fixture()
        _, _, snapshot = profile_fixture()
        snapshot['native_phase_descriptor_access']['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        report = project(encode(prepared), encode(visible), snapshot, SERVICE, CONTEXT, SOURCE)
        self.assertEqual(report['model_result']['phase'], 'visible_bound')
        self.assertEqual(report['descriptor_objects_checked'], 8)
        self.assertFalse(report['profile_qualified'])

    def test_original_child_and_immutable_broker_cannot_be_substituted(self):
        base = ('execution_phases', 1, 'execution')
        contradictions = [
            (base + ('effect_worker', 'process_id'), 500),
            (base + ('effect_worker', 'process_birth'), '0000000000000601'),
            (base + ('effect_worker', 'primary_token', 'token_type'), True),
            (base + ('service', 'service_sid_type'), 3.0),
            (base + ('broker_readback', 'custody', 'peer_process_id'), 500),
            (base + ('broker_readback', 'custody', 'owned_job_kill_on_close'), False),
            (base + ('broker_readback', 'broker_volume_granted_access'), 0x1f01ff),
            (base + ('broker_readback', 'service_configuration', 'command'), 'different.exe'),
            (base + ('broker_readback', 'service', 'primary_token', 'authentication_id'), 1000),
            (base + ('broker_readback', 'registered_admission', 'publisher_image', 'sha256'), 'a' * 64),
            (base + ('process_boundary', 'process_id'), 500),
            (base + ('worker_security', 'primary_token', 'token_id'), '0000000000000500'),
            (base + ('worker_security', 'threads', 0, 'creation_time'), '0000000000000701'),
            (base + ('authenticated_client', 'captured_process_id'), 102),
            (('operation_admission',), None),
            (('operation_admission', 'registration_sha256'), 'a' * 64),
            (('source_binding', 'plan_envelope_sha256'), 'a' * 64),
            (('creation_evidence', 'creator', 'broker_process_id'), 600),
            (('creation_evidence', 'creator', 'effect_worker', 'process_id'), 500),
            (('creation_evidence', 'broker_readback', 'custody', 'peer_process_birth'), '0000000000000601'),
            (('creation_evidence', 'schema'), 'usk.publisher.creation_observation.v3'),
        ]
        for path, replacement in contradictions:
            with self.subTest(path=path):
                prepared, visible = effect_fixture()
                target = prepared
                for key in path[:-1]:
                    target = target[key]
                self.assertTrue(type(target[path[-1]]) is not type(replacement) or target[path[-1]] != replacement,
                                'negative control must change its retained fact or JSON type')
                target[path[-1]] = replacement
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    self.check(prepared, visible)

    def test_consistent_broker_volume_changes_preserve_protected_phase_but_are_rejected(self):
        # Mutate every broker copy together. Continuity and independently protected
        # phase/model objects stay valid; rejection must check broker policy/binding.
        contradictions = [
            (('owner_sid',), CLIENT), (('dacl_protected',), False),
            (('link_count',), 2), (('link_count',), True),
            (('dacl_aces',), []),
            (('dacl_aces', 0, 'type'), 1), (('dacl_aces', 0, 'type'), False),
            (('dacl_aces', 0, 'flags'), 1), (('dacl_aces', 0, 'flags'), 0.0),
            (('dacl_aces', 0, 'access_mask'), 0x120080),
            (('dacl_aces', 1, 'sid'), CLIENT),
            # Extra non-reparse directory attributes satisfy broker policy but
            # differ from the complete independently bound and held root.
            (('attributes',), 0x30),
        ]
        for path, replacement in contradictions:
            with self.subTest(path=path, replacement=replacement):
                prepared, visible = effect_fixture()
                _, _, snapshot = profile_fixture()
                bound_root = copy.deepcopy(prepared['protected_anchors']['boundary'])
                brokers = [phase['execution']['broker_readback'] for phase in
                           prepared['execution_phases'] + visible['execution_phases']]
                brokers.append(prepared['creation_evidence']['broker_readback'])
                for broker in brokers:
                    target = broker['volume_root']
                    for key in path[:-1]:
                        target = target[key]
                    self.assertTrue(type(target[path[-1]]) is not type(replacement) or
                                    target[path[-1]] != replacement)
                    target[path[-1]] = copy.deepcopy(replacement)
                self.assertEqual(prepared['protected_anchors']['boundary'], bound_root)
                self.assertEqual(prepared['execution_phases'][0]['execution']['handles'][0]['object_observation'], bound_root)
                if path == ('attributes',):
                    validate_broker_record(brokers[0])  # Binding, rather than policy, must reject this.
                else:
                    with self.assertRaises(ValueError):
                        validate_broker_record(brokers[0])
                with self.assertRaises(ValueError):
                    self.check(prepared, visible)
                snapshot['native_phase_descriptor_access']['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
                with self.assertRaises(ValueError):
                    project(encode(prepared), encode(visible), snapshot, SERVICE, CONTEXT, SOURCE)

    def test_fresh_parent_thread_population_still_requires_full_policy(self):
        prepared, visible = effect_fixture()
        before = prepared['execution_phases'][0]['execution']['broker_readback']
        later = prepared['execution_phases'][1]['execution']['broker_readback']
        thread = copy.deepcopy(later['broker_security']['worker_security']['threads'][0])
        thread.update(thread_id=720, creation_time='0000000000000720')
        later['broker_security']['worker_security']['threads'].append(thread)
        self.assertEqual(immutable_broker_record(before), immutable_broker_record(later))
        self.assertEqual(self.check(prepared, visible)['effect_worker_phase_count'], 5)
        thread['dacl_aces'].append({'type': 0, 'flags': 0, 'access_mask': 2, 'sid': CLIENT})
        with self.assertRaises(ValueError):
            validate_broker_record(later)

    def test_windows_registered_command_preserves_slashes_quotes_and_argument_boundaries(self):
        prepared, _ = effect_fixture()
        configuration = prepared['execution_phases'][0]['execution']['broker_readback']['service_configuration']
        self.assertEqual(parse_registered_command(configuration['command']), configuration['arguments'])
        self.assertEqual(parse_registered_command('"C:\\space path\\p.exe" one\\ two "three four"'),
                         [r'C:\space path\p.exe', 'one\\', 'two', 'three four'])
        self.assertEqual(parse_registered_command('p.exe "a\\\\" b'), ['p.exe', 'a\\', 'b'])
        self.assertEqual(parse_registered_command(' p.exe'), ['', 'p.exe'])
        with self.assertRaises(EvidenceError):
            parse_registered_command('p.exe "unfinished')

    def original_fixture(self):
        prepared, _ = effect_fixture()
        execution = prepared['execution_phases'][0]['execution']
        broker = copy.deepcopy(execution['broker_readback'])
        request = {'schema': 'usk.repair_apply_request.v1', 'plan_request': {'install_id': 'native.install'},
            'reviewed_plan_id': 'native.plan', 'reviewed_plan_digest': 'a' * 64,
            'transaction_id': 'maintenance.repair.synthetic', 'applied_at': '2026-10-07T00:00:00Z', 'confirmation': 'APPLY'}
        broker['request_sha256'] = broker['custody']['request_sha256'] = canonical_sha(request)
        lease = {'schema': 'usk.installation_lease_ownership.v1', 'install_id': 'native.install', 'operation': 'repair',
            'operation_id': request['transaction_id'], 'attempt_id': 'native.attempt',
            'state_root_identity': {'file_id': 'b' * 32, 'volume_serial': '4660'},
            'holder': {'process_id': 600, 'process_creation_time': '0000000000000600'}, 'generation': 4,
            'expected_state_revision': '2' * 64, 'status': 'active', 'result_state_revision': None,
            'predecessor_sha256': '3' * 64, 'operation_context_sha256': '4' * 64}
        lease['ownership_sha256'] = canonical_sha(lease)
        original = {'schema': 'usk.publisher.maintenance_original_custody.v3', 'transaction_id': request['transaction_id'],
            'operation': 'repair', 'plan_digest': request['reviewed_plan_digest'], 'original_context_sha256': '4' * 64,
            'original_lease_ownership': lease, 'worker_security': copy.deepcopy(execution['worker_security']),
            'process_boundary': copy.deepcopy(execution['process_boundary']), 'registration_sha256': canonical_sha(broker['registered_admission']),
            'authenticated_client': copy.deepcopy(execution['authenticated_client']), 'original_consumer_completion': {},
            'installed_root': copy.deepcopy(prepared['sealed_tree']['root']), 'installed_root_journal_identity': 'synthetic',
            'original_objects': [], 'broker_readback': broker}
        return original, request

    def test_original_v3_provenance_requires_sealed_child_lease_and_exact_original_apply(self):
        original, request = self.original_fixture()
        result = validate_original_maintenance_provenance(original, request, SERVICE)
        self.assertEqual(result['holder'], {'process_id': 600, 'process_creation_time': '0000000000000600'})
        self.assertEqual(result['broker_process_id'], 500)
        self.assertFalse(result['native_restoration_qualified'])
        contradictions = [('holder', 'process_id', 500), ('holder', 'process_creation_time', '0000000000000601'),
                          ('state_root_identity', 'volume_serial', '4661')]
        for field, key, replacement in contradictions:
            with self.subTest(field=field, key=key):
                changed = copy.deepcopy(original)
                lease = changed['original_lease_ownership']
                lease[field][key] = replacement
                lease['ownership_sha256'] = canonical_sha({key: value for key, value in lease.items() if key != 'ownership_sha256'})
                with self.assertRaises(ValueError):
                    validate_original_maintenance_provenance(changed, request, SERVICE)
        for key, replacement in (('schema', 'usk.publisher.maintenance_original_custody.v2'),
                ('registration_sha256', 'a' * 64), ('original_context_sha256', '5' * 64), ('transaction_id', 'different')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_original_maintenance_provenance(dict(original, **{key: replacement}), request, SERVICE)
        with self.assertRaises(ValueError):
            validate_original_maintenance_provenance(original, dict(request, confirmation='CANCEL'), SERVICE)
        with self.assertRaises(ValueError):
            validate_active_child_lease(dict(original['original_lease_ownership'], ownership_sha256='0' * 64), original['broker_readback'])


if __name__ == '__main__':
    unittest.main()
