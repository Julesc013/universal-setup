# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic decoding controls; these do not qualify Windows or authenticate JSON."""
import copy
import hashlib
import struct
import unittest

from publisher_authenticated_access_evidence import RIGHTS, descriptor_facts, reconcile_client_capture
from publisher_execution_evidence import EvidenceError, canonical_sha, reconcile
from test_publisher_execution_evidence import BUILD, SDK, SERVICE, SID, encode
from test_publisher_native_profile_evidence import CLIENT, descriptor, profile_fixture


def authenticated_fixture():
    prepared, visible, _ = profile_fixture()
    prepared['schema'] = visible['schema'] = 'usk.publisher.lab_phase_evidence.v8'
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


class AuthenticatedAccessTests(unittest.TestCase):
    def test_complete_phase_bindings_preserve_api_normalization_and_scope(self):
        prepared, visible, _ = authenticated_fixture()
        result = reconcile(encode(prepared), encode(visible), SERVICE, SID, BUILD, SDK)
        self.assertEqual(result['authenticated_access_objects_checked'], 35)
        self.assertEqual(result['authenticated_actor_scope'], 'actual_request_client_per_worker')
        self.assertIs(result['profile_qualified'], False)
        access = prepared['execution_phases'][0]['execution']['handles'][0]['authenticated_access']
        self.assertEqual(descriptor_facts(access['descriptor_hex'])['api_control'], 0x8004)

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


if __name__ == '__main__':
    unittest.main()
