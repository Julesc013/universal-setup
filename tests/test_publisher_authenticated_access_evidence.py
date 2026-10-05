# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic decoding controls; these do not qualify Windows or authenticate JSON."""
import copy
import hashlib
import struct
import unittest

from publisher_authenticated_access_evidence import (RIGHTS, descriptor_facts, reconcile_client_capture,
    reconcile_registered_operation, validate_client, validate_operation_admission)
from publisher_execution_evidence import EvidenceError, canonical_sha, reconcile
from test_publisher_execution_evidence import BUILD, SDK, SERVICE, SID, encode
from test_publisher_native_profile_evidence import CLIENT, descriptor, profile_fixture


def authenticated_fixture():
    prepared, visible, _ = profile_fixture()
    prepared['schema'] = visible['schema'] = 'usk.publisher.lab_phase_evidence.v8'
    prepared['operation_admission'] = None
    client = {'schema': 'usk.publisher_authenticated_client_observation.v1',
        'scope': 'held_authenticated_identification_token', 'captured_process_id': 101,
        'user_sid': CLIENT, 'token_type': 2, 'impersonation_level': 1,
        'token_id': 303, 'authentication_id': 505, 'modified_id': 707,
        'groups': [{'sid': 'S-1-5-32-545', 'attributes': 7}], 'restricted_sids': [], 'privileges': []}
    raw = bytearray.fromhex(descriptor('S-1-5-20'))
    struct.pack_into('<H', raw, 2, 0x8004)  # API representation without the stored protected flag.
    for phase in prepared['execution_phases'] + visible['execution_phases']:
        execution = phase['execution']
        execution.update(schema='usk.publisher_execution_observation.v6',
            scope='supplied_held_service_handles_authenticated_access_and_worker_security',
            authenticated_client=copy.deepcopy(client))
        for handle in execution['handles']:
            handle['authenticated_access'] = {'schema': 'usk.publisher_authenticated_object_access.v1',
                'scope': 'fresh_held_authenticated_token_and_file_descriptor',
                'client_sha256': canonical_sha(client), 'native_object_sha256': canonical_sha(handle['object_observation']),
                'descriptor_api': 'GetSecurityInfo:SE_FILE_OBJECT:OWNER_GROUP_DACL', 'descriptor_hex': raw.hex(),
                'observed_group_sid': 'S-1-5-20',
                'checks': {name: {'requested': value, 'allowed': False, 'granted': 0} for name, value in RIGHTS.items()}}
    visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
    return prepared, visible, client


def registered_fixture():
    prepared, visible, client = authenticated_fixture()
    prepared['source_binding'].update(reviewed_plan_digest='a' * 64, reviewed_plan_snapshot_sha256='b' * 64)
    service = prepared['execution_phases'][0]['execution']['service']
    admission = {'schema': 'usk.publisher_operation_admission.v1',
        'scope': 'live_registered_request_and_held_volume_before_effects',
        'route': 'registered_service_admitted_production', 'service_name': SERVICE, 'service_sid': SID,
        'service_process_id': service['process_id'], 'configured_caller_sid': CLIENT,
        'authenticated_client_sha256': canonical_sha(client), 'captured_client_process_id': client['captured_process_id'],
        'registration_sha256': 'c' * 64, 'target_admitted_sha256': 'd' * 64, 'publisher_image_sha256': 'e' * 64,
        'volume_guid_root': '\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\',
        'root_file_id': prepared['protected_anchors']['boundary']['file_id'], 'volume_serial': prepared['volume_serial'],
        'reviewed_plan_digest': 'a' * 64, 'reviewed_plan_snapshot_sha256': 'b' * 64, 'transaction_id': 'tx.native'}
    prepared['operation_admission'] = admission
    visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
    registration = {'service_name': SERVICE, 'service_sid': SID, 'process_id': service['process_id'],
        'configured_caller_sid': CLIENT, 'registration_sha256': 'c' * 64, 'target_admitted_sha256': 'd' * 64,
        'publisher_image': {'sha256': 'e' * 64}, 'target_identity': {'volume_identity': {
            'volume_root': admission['volume_guid_root'], 'root_file_id': admission['root_file_id'],
            'volume_serial': str(admission['volume_serial'])}}}
    return prepared, visible, registration


def descendant_fixture():
    prepared, visible, _ = registered_fixture()
    prepared['schema'] = visible['schema'] = 'usk.publisher.lab_phase_evidence.v9'
    for phase in prepared['execution_phases'] + visible['execution_phases']:
        execution = phase['execution']
        tree = visible['visible_tree'] if execution['phase'] == 'visible_bound' else prepared['sealed_tree']
        descendants = [] if execution['phase'] == 'protected_empty' else tree['descendants']
        rows = []
        for descendant in descendants:
            access = copy.deepcopy(execution['handles'][6]['authenticated_access'])
            access['native_object_sha256'] = canonical_sha(descendant['object'])
            rows.append({'relative_path': descendant['relative_path'], 'authenticated_access': access})
        phase['authenticated_descendants'] = {'schema': 'usk.publisher_authenticated_descendant_access.v1',
            'scope': 'fresh_held_descriptors_for_bound_tree_no_content_rehash',
            'client_sha256': canonical_sha(execution['authenticated_client']), 'objects': rows}
    visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
    return prepared, visible


class AuthenticatedAccessTests(unittest.TestCase):
    def test_complete_descendant_phases_keep_content_and_access_scopes_separate(self):
        prepared, visible = descendant_fixture()
        result = reconcile(encode(prepared), encode(visible), SERVICE, SID, BUILD, SDK)
        self.assertEqual(result['authenticated_access_objects_checked'], 35)
        self.assertEqual(result['authenticated_descendant_objects_checked'], 4)
        self.assertEqual(result['descendant_access_scope'], 'fresh_descriptor_and_request_token_no_content_rehash')
        self.assertTrue(result['registered_operation_bound'])
        self.assertFalse(result['profile_qualified'])

    def test_descendant_closure_identity_caller_and_mutation_grants_are_required(self):
        prepared, _ = descendant_fixture()
        for change in ('missing', 'extra', 'path', 'object', 'client', 'grant', 'maximum', 'omitted', 'downgrade'):
            changed = copy.deepcopy(prepared)
            phase = changed['execution_phases'][1]
            collection = phase['authenticated_descendants']
            row = collection['objects'][0]
            if change == 'missing': collection['objects'] = []
            elif change == 'extra': collection['objects'].append(copy.deepcopy(row))
            elif change == 'path': row['relative_path'] = 'other.bin'
            elif change == 'object': row['authenticated_access']['native_object_sha256'] = '0' * 64
            elif change == 'client': collection['client_sha256'] = '0' * 64
            elif change == 'grant': row['authenticated_access']['checks']['delete'].update(allowed=True, granted=65536)
            elif change == 'maximum': row['authenticated_access']['checks']['maximum_allowed'].update(allowed=True, granted=2)
            elif change == 'omitted': del phase['authenticated_descendants']
            elif change == 'downgrade': changed['schema'] = 'usk.publisher.lab_phase_evidence.v8'
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                reconcile(encode(changed), None, SERVICE, SID, BUILD, SDK)

    def test_complete_phase_bindings_preserve_api_normalization_and_scope(self):
        prepared, visible, _ = authenticated_fixture()
        result = reconcile(encode(prepared), encode(visible), SERVICE, SID, BUILD, SDK)
        self.assertEqual(result['authenticated_access_objects_checked'], 35)
        self.assertEqual(result['authenticated_actor_scope'], 'actual_request_client_per_worker')
        self.assertIs(result['profile_qualified'], False)
        access = prepared['execution_phases'][0]['execution']['handles'][0]['authenticated_access']
        self.assertEqual(descriptor_facts(access['descriptor_hex'])['api_control'], 0x8004)

    def test_descendant_descriptor_group_drift_is_not_hidden_by_per_phase_consistency(self):
        prepared, _ = descendant_fixture()
        access = prepared['execution_phases'][2]['authenticated_descendants']['objects'][0]['authenticated_access']
        raw = bytearray.fromhex(descriptor('S-1-5-18'))
        struct.pack_into('<H', raw, 2, 0x8004)
        access.update(observed_group_sid='S-1-5-18', descriptor_hex=raw.hex())
        with self.assertRaisesRegex(EvidenceError, 'descriptor changed across phases'):
            reconcile(encode(prepared), None, SERVICE, SID, BUILD, SDK)

    def test_descriptor_bounds_bindings_and_access_grants_are_checked(self):
        prepared, _, _ = authenticated_fixture()
        for field, replacement in [('descriptor_hex', '01000480000000000000000000000000ffffffff'),
            ('client_sha256', '0' * 64), ('native_object_sha256', '0' * 64),
            ('observed_group_sid', 'S-1-5-18'), ('descriptor_api', 'reconstructed')]:
            changed = copy.deepcopy(prepared)
            changed['execution_phases'][0]['execution']['handles'][0]['authenticated_access'][field] = replacement
            with self.subTest(field=field), self.assertRaises((ValueError, EvidenceError)):
                reconcile(encode(changed), None, SERVICE, SID, BUILD, SDK)
        changed = copy.deepcopy(prepared)
        changed['execution_phases'][0]['execution']['handles'][0]['authenticated_access']['checks']['delete'].update(
            allowed=True, granted=65536)
        with self.assertRaises(EvidenceError):
            reconcile(encode(changed), None, SERVICE, SID, BUILD, SDK)

    def test_new_schema_cannot_omit_or_downgrade_authentication(self):
        prepared, _, _ = authenticated_fixture()
        for field in ('authenticated_client', 'schema'):
            changed = copy.deepcopy(prepared)
            execution = changed['execution_phases'][1]['execution']
            if field == 'schema':
                execution['schema'] = 'usk.publisher_execution_observation.v5'
            else:
                del execution[field]
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                reconcile(encode(changed), None, SERVICE, SID, BUILD, SDK)

    def test_primary_capture_uses_account_session_not_token_id_equality(self):
        _, _, client = authenticated_fixture()
        capture = {'captured_before_primary_thread_resume': True, 'process_id': 101,
            'primary_token': {'token_type': 1, 'user_sid': CLIENT, 'authentication_id': f'{505:016x}',
                'token_id': f'{999:016x}', 'groups': copy.deepcopy(client['groups'])}}
        self.assertEqual(reconcile_client_capture(client, capture)['scope'], 'account_session_and_captured_pipe_pid')
        for key, replacement in [('authentication_id', f'{506:016x}'), ('groups', [])]:
            changed = copy.deepcopy(capture)
            changed['primary_token'][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                reconcile_client_capture(client, changed)

    def test_authenticated_token_sids_use_the_bounded_canonical_policy(self):
        _, _, client = authenticated_fixture()
        for principal in ('S-1-5-21-1-2-3-4294967296', 'S-1-5-32-0545',
                          'S-1-281474976710656-1', 'S-1-5-' + '-'.join('1' for _ in range(16))):
            for field in ('user_sid', 'groups', 'restricted_sids'):
                changed = copy.deepcopy(client)
                changed[field] = principal if field == 'user_sid' else [{'sid': principal, 'attributes': 7}]
                with self.subTest(principal=principal, field=field), self.assertRaises(ValueError):
                    validate_client(changed)

    def test_registered_operation_is_bound_to_native_target_plan_and_original_worker(self):
        prepared, visible, registration = registered_fixture()
        self.assertTrue(validate_operation_admission(prepared))
        self.assertEqual(reconcile_registered_operation(prepared, registration)['root_file_id'],
                         prepared['protected_anchors']['boundary']['file_id'])
        result = reconcile(encode(prepared), encode(visible), SERVICE, SID, BUILD, SDK)
        self.assertTrue(result['registered_operation_bound'])
        self.assertIs(result['profile_qualified'], False)
        for field, replacement in [('service_process_id', 9999), ('captured_client_process_id', 9998),
            ('root_file_id', '0' * 49), ('volume_serial', 0), ('reviewed_plan_digest', '0' * 64),
            ('authenticated_client_sha256', '0' * 64), ('transaction_id', 'bad/id')]:
            changed = copy.deepcopy(prepared)
            changed['operation_admission'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_operation_admission(changed)
        changed = copy.deepcopy(registration)
        changed['publisher_image']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            reconcile_registered_operation(prepared, changed)

    def test_private_authenticated_phase_cannot_be_promoted_to_registered_admission(self):
        prepared, _, _ = authenticated_fixture()
        _, _, registration = registered_fixture()
        self.assertFalse(validate_operation_admission(prepared))
        with self.assertRaises(ValueError):
            reconcile_registered_operation(prepared, registration)

    def test_registration_serial_is_canonical_decimal_string_without_float_conversion(self):
        prepared, _, registration = registered_fixture()
        # This control checks this binding representation only; no execution or
        # volume observation is claimed by these synthetic inputs.
        serial = 12714473842410676888
        prepared['volume_serial'] = prepared['operation_admission']['volume_serial'] = serial
        registration['target_identity']['volume_identity']['volume_serial'] = str(serial)
        self.assertEqual(reconcile_registered_operation(prepared, registration)['volume_serial'], serial)
        for value in (serial, float(serial), '0' + str(serial), str(2 ** 64), '-1', '1e16'):
            changed = copy.deepcopy(registration)
            changed['target_identity']['volume_identity']['volume_serial'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                reconcile_registered_operation(prepared, changed)


if __name__ == '__main__':
    unittest.main()
