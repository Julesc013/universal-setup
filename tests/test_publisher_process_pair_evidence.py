# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic identity/closure controls; no actual held pair or runtime proof."""
import unittest

from publisher_execution_evidence import canonical_sha
from publisher_process_pair_evidence import original_provenance, validate_ended_process_pair
import test_publisher_effect_broker_evidence as broker_controls
from test_publisher_execution_evidence import SERVICE


def pair_fixture():
    original, request = broker_controls.EffectBrokerEvidenceTests().original_fixture()
    broker = original['broker_readback']
    image = 'C:\\Program Files\\USK\\' + SERVICE + '.exe'
    config = broker['service_configuration']
    old_image = broker['registered_admission']['publisher_image']['path']
    broker['registered_admission']['publisher_image']['path'] = config['arguments'][0] = image
    config['command'] = config['command'].replace('"' + old_image + '"', '"' + image + '"', 1)
    original['registration_sha256'] = canonical_sha(broker['registered_admission'])
    boundary = {'schema': 'usk.publisher.production_rename_observer.v2', 'identity': 'S-1-5-18',
        'original_pair_closure_confirmed': True, 'service_name': SERVICE, 'service_pid': 500,
        'service_executable': image, 'process_creation_file_time': '0000000000000500',
        'effect_holder': {'process_id': 600, 'process_creation_time': '0000000000000600'},
        'termination': {'confirmed': True, 'terminated': 1, 'kill_invoked': True,
            'method': 'TerminateProcess_owned_held_root', 'process_id': 500,
            'process_creation_file_time': '0000000000000500', 'native_wait_result': 0},
        'native_process_pair': {'schema': 'usk.publisher_owned_native_process_pair.v1',
            'scope': 'held_scm_parent_termination_and_original_effect_child_end',
            'parent_process_id': 500, 'parent_process_birth': '0000000000000500',
            'effect_process_id': 600, 'effect_process_birth': '0000000000000600',
            'native_parent_process_id': 500, 'original_image_path': image,
            'both_live_before_termination': True, 'parent_termination_invoked': True,
            'child_termination_invoked': False, 'parent_native_wait_result': 0,
            'child_native_wait_result': 0, 'child_observer_access': 0x101400,
            'child_observer_handle_flags': 0, 'child_observer_close_confirmed': True}}
    return boundary, original, request


class ProcessPairEvidenceTests(unittest.TestCase):
    def test_actual_roles_join_full_broker_and_sealed_original_child_provenance(self):
        boundary, original, request = pair_fixture()
        self.assertEqual(validate_ended_process_pair(boundary, original['broker_readback']), boundary['effect_holder'])
        report = original_provenance(original, request, SERVICE, boundary)
        self.assertEqual(report['broker_process_id'], 500)
        self.assertEqual(report['holder']['process_id'], 600)
        self.assertTrue(report['original_pair_closure_checked'])
        self.assertFalse(report['native_restoration_qualified'])

    def test_native_closure_cannot_substitute_tree_kill_cancellation_or_unknown_observer_close(self):
        changes = [('schema', 'old'), ('scope', 'tree_termination'),
            ('native_parent_process_id', 501), ('effect_process_id', 500),
            ('effect_process_birth', '0000000000000499'), ('parent_process_birth', '0' * 16),
            ('both_live_before_termination', False), ('parent_termination_invoked', False),
            ('child_termination_invoked', True), ('parent_native_wait_result', 258),
            ('child_native_wait_result', 258), ('child_native_wait_result', False),
            ('child_observer_access', 0x101401), ('child_observer_handle_flags', 1),
            ('child_observer_close_confirmed', False), ('original_image_path', 'C:\\different.exe')]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                boundary, original, _ = pair_fixture()
                old = boundary['native_process_pair'][key]
                self.assertTrue(type(old) is not type(value) or old != value)
                boundary['native_process_pair'][key] = value
                with self.assertRaises(ValueError):
                    validate_ended_process_pair(boundary, original['broker_readback'])

    def test_consistent_replaced_child_still_refuses_original_native_broker_join(self):
        boundary, original, request = pair_fixture()
        boundary['native_process_pair']['effect_process_id'] = boundary['effect_holder']['process_id'] = 601
        # Pair-only data shape remains consistent; original native custody must differ.
        self.assertEqual(validate_ended_process_pair(boundary)['process_id'], 601)
        with self.assertRaises(ValueError):
            original_provenance(original, request, SERVICE, boundary)
        boundary, original, request = pair_fixture()
        boundary['native_process_pair']['effect_process_birth'] = boundary['effect_holder']['process_creation_time'] = '0000000000000601'
        self.assertEqual(validate_ended_process_pair(boundary)['process_creation_time'], '0000000000000601')
        with self.assertRaises(ValueError):
            original_provenance(original, request, SERVICE, boundary)

    def test_current_pair_requires_closed_typed_distinct_roles_and_parent_only_termination(self):
        for path, value in [(('termination', 'terminated'), 2), (('termination', 'terminated'), True),
                (('termination', 'method'), 'Kill_owned_tree'), (('effect_holder', 'process_id'), 500),
                (('schema',), 'usk.publisher.production_rename_observer.v1'),
                (('original_pair_closure_confirmed',), False), (('native_process_pair', 'extra'), 'unexpected')]:
            with self.subTest(path=path):
                boundary, _, _ = pair_fixture()
                target = boundary
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    validate_ended_process_pair(boundary)


if __name__ == '__main__':
    unittest.main()
