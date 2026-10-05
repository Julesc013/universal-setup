# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic refusal contradictions; independent native helpers have separate tests."""
import copy
import hashlib
import json
import unittest
from contextlib import ExitStack
from unittest.mock import patch
from publisher_standard_public_evidence import StandardEvidenceError, canonical
from publisher_stale_plan_evidence import reconcile, rows_digest
from test_publisher_registered_contention_evidence import fixture as contention_fixture


def fixture():
    observation, client = contention_fixture()
    original = {'schema': 'usk.install_local_apply_request.v1', 'plan_request': {'request_id': 'plan.original'},
        'reviewed_plan_id': 'plan.original', 'reviewed_plan_digest': 'a'*64,
        'transaction_id': 'original.transaction', 'applied_at': '2026-10-05T00:00:00Z', 'confirmation': 'APPLY'}
    template = observation['registered_contention']
    root_id = '0000000000000001:'+'a'*32
    volume = r'\\?\Volume{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'+'\\'
    target = {'registration_sha256': 'd'*64,
        'volume_identity': {'volume_root': volume, 'root_file_id': root_id, 'volume_serial': '1'},
        'disk_identity': {}, 'metadata': {}}
    admission = {'schema': 'usk.publisher_registered_admission_observation.v1',
        'scope': 'held_registered_service_image_and_controller_target_admission',
        'service_name': observation['service'], 'service_sid': 'S-1-5-80-1-2-3-4-5',
        'process_id': 200, 'configured_caller_sid': client, 'registration_sha256': 'd'*64,
        'target_admitted_sha256': hashlib.sha256(canonical(
            {'schema': 'usk.publisher_target_admitted.v1', 'identity': target}).encode()).hexdigest(),
        'target_identity': target, 'publisher_image': {'path': observation['installed_binary'],
            'volume_id': 'volume', 'file_id': 'file', 'size_bytes': 100, 'sha256': observation['service_sha256']}}
    observation.update(account_sid=client, service_sid=admission['service_sid'], volume_root=volume,
        machine_sha256='c'*64, apply_request=original, apply={'result': {'payload': {'target_root': 'U:\\visible'}}},
        client_captures=[{'request_id': 'positive', 'process_id': 1, 'creation_file_time': '132000000000000001'}],
        native_observations=[{'command': 'install_local.apply', 'native_json': json.dumps({'registered_admission': admission})}])
    observation['readbacks'] = [copy.deepcopy(template['after']) for _ in range(2)]
    for readback in observation['readbacks']:
        readback['independent']['volume_boundary']['root']['file_id'] = root_id
    cases = []
    for index, field in enumerate(('reviewed_plan_digest', 'plan_request.request_id', 'transaction_id', 'applied_at')):
        changed = copy.deepcopy(original)
        if field == 'plan_request.request_id':
            changed['plan_request']['request_id'] = 'stale.'+'0'*32
        elif field == 'reviewed_plan_digest':
            changed[field] = '0'*64
        elif field == 'transaction_id':
            changed[field] = 'stale.'+'1'*32
        else:
            changed[field] = '2000-01-01T00:00:00Z'
        capture = copy.deepcopy(template['client_capture'])
        capture.update(command='install_local.apply', request_id=f'stale.case.{index}', process_id=300+index)
        readback = copy.deepcopy(template['after'])
        baseline_index = 0 if index < 2 else 1
        baseline = observation['readbacks'][baseline_index]['independent']
        readback['independent']['volume_boundary'] = copy.deepcopy(baseline['volume_boundary'])
        tokens = readback['independent']['effective_right_tokens']
        tokens['captured_client']['process_id'] = capture['process_id']
        tokens['capture_context'].update(command=capture['command'], request_id=capture['request_id'])
        readback['independent']['rows'] = {'schema': 'usk.publisher_native_rows_reference.v1',
            'baseline_readback_index': baseline_index, 'sha256': rows_digest(baseline['rows'])}
        native_admission = copy.deepcopy(admission)
        native_admission['process_id'] = 400+index
        native = {'schema': 'usk.publisher_lab_service_observation.v1', 'status': 'failed',
            'error': 'PRIVATE_NATIVE_CAUSE', 'error_code': 'stale_plan', 'process_id': 400+index,
            'registered_admission': native_admission}
        text = canonical(native)+'\n'
        cases.append({'field': field, 'source_free': index >= 2, 'apply_request': changed,
            'client_capture': capture, 'readback': readback,
            'response': {'schema': 'usk.oneshot_response.v1', 'request_id': capture['request_id'],
                'status': 'refused', 'result': None, 'error': {'code': 'stale_plan'}},
            'native_observation': {'command': capture['command'], 'request_id': capture['request_id'],
                'native_json': text, 'sha256': hashlib.sha256(text.encode()).hexdigest()}})
    observation['stale_plan_refusals'] = {'schema': 'usk.publisher_stale_plan_probe.v1',
        'scope': 'authenticated_immutable_apply_context_before_effects',
        'profile_qualified': False, 'publication_authority_granted': False, 'cases': cases}
    return observation


class StalePlanEvidenceTests(unittest.TestCase):
    def setUp(self):
        # These established native validators have their own contradiction tests.
        # No mocked or synthetic row can qualify the hosted production profile.
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ('native_rows', 'native_boundary', 'installed_material', 'lease_snapshot'):
            self.stack.enter_context(patch('publisher_stale_plan_evidence.'+name))

    def test_finite_two_contexts_keep_qualification_false(self):
        result = reconcile(fixture(), 'U:\\')
        self.assertEqual(result['cases_checked'], 4)
        self.assertIs(result['changed_state_revision_qualified'], False)
        self.assertIs(result['profile_qualified'], False)
        self.assertIs(result['publication_authority_granted'], False)

    def test_refuses_changed_request_scope_refusal_and_row_binding(self):
        mutations = (
            lambda o, c: c.update(source_free=False),
            lambda o, c: c['apply_request'].update(confirmation='REPLACE'),
            lambda o, c: c.update(apply_request=o['apply_request']),
            lambda o, c: c['response'].update(status='recovery_required'),
            lambda o, c: c['response']['error'].update(code='publisher_failed'),
            lambda o, c: c['response'].update(result={'error': 'PRIVATE_NATIVE_CAUSE'}),
            lambda o, c: c['native_observation'].update(sha256='0'*64),
            lambda o, c: c['readback']['independent']['rows'].update(baseline_readback_index=0),
            lambda o, c: c['readback']['independent']['rows'].update(baseline_readback_index=True),
            lambda o, c: c['readback']['independent']['rows'].update(sha256='0'*64),
            lambda o, c: c['readback']['independent']['volume_boundary']['root'].update(file_id='changed'),
            lambda o, c: c['client_capture'].update(request_id='positive'),
            lambda o, c: c['readback']['independent']['effective_right_tokens']['captured_client'].update(process_id=999),
            lambda o, c: c['readback']['independent'].update(observer_token_handles_closed=False),
            lambda o, c: o['stale_plan_refusals'].update(profile_qualified=True),
            lambda o, c: o['stale_plan_refusals'].update(publication_authority_granted=True),
        )
        for mutate in mutations:
            observation = fixture()
            case = observation['stale_plan_refusals']['cases'][2]
            mutate(observation, case)
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile(observation, 'U:\\')

    def test_refuses_resealed_native_status_and_registration_substitution(self):
        for mutate in (
            lambda n: n.update(status='recovery_required'),
            lambda n: n.update(error_code='state_revision_stale'),
            lambda n: n.update(process_id=999),
            lambda n: n['registered_admission']['publisher_image'].update(file_id='substituted'),
            lambda n: n.update(publication_authority_granted=True),
        ):
            observation = fixture()
            capture = observation['stale_plan_refusals']['cases'][0]['native_observation']
            native = json.loads(capture['native_json'])
            mutate(native)
            capture['native_json'] = canonical(native)+'\n'
            capture['sha256'] = hashlib.sha256(capture['native_json'].encode()).hexdigest()
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile(observation, 'U:\\')

    def test_digest_shares_only_identical_ordered_native_rows(self):
        rows = [{'path': 'U:\\a', 'bytes': 10}, {'path': 'U:\\b', 'bytes': 20}]
        self.assertNotEqual(rows_digest(rows), rows_digest(list(reversed(rows))))
        changed = copy.deepcopy(rows)
        changed[0]['bytes'] = 11
        self.assertNotEqual(rows_digest(rows), rows_digest(changed))
        for invalid in ([], {}, 'rows', [0]*10001):
            with self.subTest(rows=type(invalid)), self.assertRaises(StandardEvidenceError):
                rows_digest(invalid)


if __name__ == '__main__':
    unittest.main()
