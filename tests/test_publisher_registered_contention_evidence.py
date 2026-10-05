# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Closed data contradictions only; synthetic fixtures grant no runtime authority."""
import copy
import hashlib
import unittest
from publisher_standard_public_evidence import (
    MUTATION_RIGHTS, StandardEvidenceError, canonical, reconcile_registered_contention)


def fixture():
    client = 'S-1-5-21-1-2-3-1001'
    service = 'USK_PUB_' + 'a' * 32
    image = 'C:\\Program Files\\Universal Setup\\Publisher\\' + service + '.exe'
    reference = 'usk.operation-inspection.v1:' + hashlib.sha256(
        canonical((r'\\.\pipe\USK-Publisher-' + service).upper()).encode()).hexdigest()
    token = {'user_sid': client, 'groups': [{'sid': 'S-1-5-32-545', 'attributes': 7}],
        'privileges': [{'name': 'SeChangeNotifyPrivilege', 'attributes': 3}],
        'token_id': '0000000000001234', 'authentication_id': '0000000000001235',
        'token_type': 1, 'impersonation_level': None}
    capture = {'request_id': 'contention-test', 'command': 'registered_contention', 'process_id': 111,
        'creation_file_time': '132000000000000000', 'captured_before_primary_thread_resume': True,
        'primary_token': token, 'launcher_token': {'user_sid': 'S-1-5-18', 'token_type': 1,
            'privileges': [{'name': name, 'attributes': 0} for name in
                ('SeAssignPrimaryTokenPrivilege', 'SeIncreaseQuotaPrivilege')]},
        'image_sha256': 'c' * 64, 'capture_sha256': 'd' * 64,
        'initiating_token_id': '0000000000001236', 'filtered_token_id': '0000000000001237'}
    checks = {name: {'requested': mask, 'allowed': False, 'granted': 0} for name, mask in MUTATION_RIGHTS.items()}
    checks['maximum_allowed'] = {'requested': 0x2000000, 'allowed': True, 'granted': 0x120089}
    boundary = {'root': {'effective_rights': {actor: checks for actor in ('initiating', 'filtered')}},
        'device': {'checks': {actor: checks for actor in ('initiating', 'filtered')}}}
    rows = [{'path': 'U:\\publication', 'file_id': 'actual-row-fixture', 'sha256': 'e' * 64}]
    def readback(exited):
        initiating = dict(token, token_id=capture['initiating_token_id'], token_type=2, impersonation_level=2)
        filtered = dict(initiating, token_id=capture['filtered_token_id'])
        return {'observer_task_removed': True, 'independent': {'identity': 'S-1-5-18',
            'observer_token_handles_closed': True, 'rows': copy.deepcopy(rows), 'volume_boundary': copy.deepcopy(boundary),
            'effective_right_tokens': {'captured_client': {'process_id': capture['process_id'],
                'creation_file_time': capture['creation_file_time'], 'exited_at_observation': exited},
                'capture_context': {key: capture[key] for key in ('capture_sha256', 'command', 'request_id', 'image_sha256')},
                'initiating': initiating, 'filtered': filtered}}}
    cases = []
    for label in ('fail_fast', 'deadline', 'ready_cancel', 'async_cancel'):
        code = 'operation_cancelled' if label.endswith('cancel') else 'operation_conflict'
        cases.append({'case': label, 'elapsed_milliseconds': 75 if label == 'deadline' else 10, 'exit_code': 4,
            'response': {'schema': 'usk.oneshot_response.v1', 'status': 'refused',
                'request_id': 'registered-contention.' + label, 'error': {'code': code},
                'result': {'schema': 'usk.publisher_operation_diagnostic.v1', 'error_code': code,
                    'inspection_reference': reference}}})
    native = {'schema': 'usk.publisher_registered_contention_observation.v1', 'status': 'pass',
        'scope': 'registered_endpoint_before_effect_request_bytes', 'profile_qualified': False,
        'service_name': service, 'inspection_reference': reference, 'worker_process_id': 222,
        'worker_process_creation_time': 132000000000000001, 'worker_alive_after_cases': True,
        'worker_process_image_path': image, 'worker_expected_image_sha256': 'b' * 64, 'request_sha256': 'f' * 64,
        'caller_process_id': capture['process_id'], 'caller_process_creation_time': int(capture['creation_file_time']),
        'cases': cases}
    cases[-1]['cancellation_order'] = {'call_started_qpc': 100, 'cancellation_signalled_qpc': 200,
        'call_completed_qpc': 300, 'call_active_at_signal': True}
    record = {'schema': 'usk.publisher_registered_contention_probe.v1', 'scope': native['scope'],
        'profile_qualified': False, 'producer_sha256': capture['image_sha256'], 'request_sha256': native['request_sha256'],
        'client_capture': capture, 'native_observation': native, 'before': readback(False), 'after': readback(True),
        'worker_stopped': True}
    return {'service': service, 'service_sha256': 'b' * 64, 'installed_binary': image,
        'readbacks': [{'independent': {'rows': rows, 'volume_boundary': boundary}}],
        'registered_contention': record}, client


class RegisteredContentionEvidenceTests(unittest.TestCase):
    def test_asynchronous_cancellation_requires_an_active_ordered_call(self):
        observation, client = fixture()
        for mutate in (
            lambda c: c.update(elapsed_milliseconds=0),
            lambda c: c.pop('cancellation_order'),
            lambda c: c['cancellation_order'].update(call_active_at_signal=False),
            lambda c: c['cancellation_order'].update(call_started_qpc=200),
            lambda c: c['cancellation_order'].update(call_completed_qpc=199),
            lambda c: c['cancellation_order'].update(cancellation_signalled_qpc=True),
            lambda c: c['cancellation_order'].update(unobserved_wait=True)):
            changed = copy.deepcopy(observation)
            mutate(changed['registered_contention']['native_observation']['cases'][-1])
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile_registered_contention(changed, client)

    def test_bounded_endpoint_evidence_never_grants_profile_authority(self):
        observation, client = fixture()
        result = reconcile_registered_contention(observation, client)
        self.assertEqual(result['cases_checked'], 4)
        self.assertFalse(result['profile_qualified'])
        self.assertIsNone(reconcile_registered_contention({}, client))

    def test_cases_preserve_unknown_ceiling_and_refuse_secret_or_authority_fields(self):
        observation, client = fixture()
        for mutate in (
            lambda r: r['native_observation']['cases'][0].update(exit_code=5),
            lambda r: r['native_observation']['cases'][0]['response'].update(status='unknown'),
            lambda r: r['native_observation']['cases'][1].update(elapsed_milliseconds=74),
            lambda r: r['native_observation']['cases'][0]['response']['result'].update(error='PRIVATE_CANARY'),
            lambda r: r['native_observation']['cases'][0]['response']['error'].update(message='PRIVATE_CANARY'),
            lambda r: r['native_observation']['cases'][0]['response']['result'].update(inspection_authority=True),
            lambda r: r['native_observation']['cases'].pop(),
            lambda r: r['native_observation'].update(profile_qualified=True),
            lambda r: r['native_observation'].update(inspection_reference='usk.operation-inspection.v1:' + '0' * 64)):
            changed = copy.deepcopy(observation)
            mutate(changed['registered_contention'])
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile_registered_contention(changed, client)

    def test_actual_client_lifetime_and_completed_target_are_required(self):
        observation, client = fixture()
        for mutate in (
            lambda r: r['before']['independent']['effective_right_tokens']['captured_client'].update(exited_at_observation=True),
            lambda r: r['after']['independent']['effective_right_tokens']['captured_client'].update(exited_at_observation=False),
            lambda r: r['after']['independent']['rows'][0].update(sha256='0' * 64),
            lambda r: r['native_observation'].update(worker_alive_after_cases=False),
            lambda r: r['native_observation'].update(worker_process_creation_time=True),
            lambda r: r['native_observation'].update(worker_process_image_path='C:\\other.exe'),
            lambda r: r.update(worker_stopped=False)):
            changed = copy.deepcopy(observation)
            mutate(changed['registered_contention'])
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile_registered_contention(changed, client)
        changed = copy.deepcopy(observation)
        changed['registered_contention']['before']['independent']['rows'].clear()
        changed['registered_contention']['after']['independent']['rows'].clear()
        with self.assertRaises(StandardEvidenceError):
            reconcile_registered_contention(changed, client)
