# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
from __future__ import annotations
import copy
from contextlib import ExitStack
import hashlib
import json
import unittest
from unittest.mock import patch

import test_bundle_apply_binding as bundle_fixture
from test_publisher_stale_plan_evidence import fixture as stale_fixture
from usk_bundle_apply_binding import compose_binding
from publisher_changed_state_revision_evidence import approved_initial_plans, digest, reconcile
from publisher_standard_public_evidence import canonical, StandardEvidenceError
from publisher_stale_plan_evidence import rows_digest


def fixture():
    # Decoder contradiction fixture only. Native row/protection validators are
    # separately tested; these synthetic bytes cannot qualify a hosted run.
    observation = stale_fixture()
    model = bundle_fixture.BundleApplyBindingTests(); model.setUp()
    request = model.request; request['payload']['install_id'] = 'example.install'
    response = model.response
    apply_b, _ = compose_binding(request, response, acceptance_root='Q:\\', state_root='Q:/setup-state',
        transaction_id='install.b', applied_at='2026-10-05T00:00:00Z')
    request_a = copy.deepcopy(request)
    request_a['request_id'] = 'planA.'+'1'*32
    request_a['payload']['request_id'] = request_a['request_id']
    response_a = copy.deepcopy(response)
    response_a['result']['payload'].update(plan_id=request_a['request_id'], plan_digest='e'*64)
    apply_a, envelope_a = compose_binding(request_a, response_a,
        acceptance_root='Q:\\', state_root='Q:/setup-state', transaction_id='install.a', applied_at='2026-10-05T00:00:01Z')
    text = canonical(envelope_a)+'\n'
    admission = json.loads(observation['native_observations'][0]['native_json'])['registered_admission']
    observation['plan_request'] = request
    observation['apply_request'] = apply_b
    observation['client_captures'][0].update(command='install_local.apply', creation_file_time='132000000000000003')
    observation['native_observations'].append(copy.deepcopy(observation['native_observations'][0]))
    installed = {'schema': 'usk.installed_state.v1', 'install_id': 'example.install',
        'transaction_id': 'install.b', 'target_root': 'Q:/publication/destination/visible'}
    observation['apply']['result']['payload'] = installed
    enrollments = []
    for apply, envelope_sha, size in ((apply_a, hashlib.sha256(text.encode()).hexdigest(), len(text.encode())),
        (apply_b, 'f'*64, 123)):
        approval = {'schema': 'usk.publisher_reviewed_operation_approval.v1',
            'registration_sha256': admission['registration_sha256'],
            'target_admitted_sha256': admission['target_admitted_sha256'],
            'caller_sid': observation['account_sid'], 'request_sha256': digest(apply),
            'envelope_sha256': envelope_sha, 'envelope_size_bytes': size}
        enrollments.append({'schema': 'usk.publisher_service_control.v1', 'status': 'reviewed_operation_enrolled',
            'service': observation['service'], 'approval': approval})
    cases = []
    for index, old_index in enumerate((0, 2)):
        old = observation['stale_plan_refusals']['cases'][old_index]
        case = {key: copy.deepcopy(old[key]) for key in
            ('source_free', 'client_capture', 'response', 'native_observation', 'readback')}
        case['response']['error']['code'] = 'state_revision_stale'
        rows = [{'path': 'Q:\\setup-state\\state\\installed\\example.install.install.b.json',
            'directory': False, 'content_json': canonical(installed)+'\n'},
            {'path': 'Q:\\publication\\journal\\lab-reviewed-plan.json', 'directory': False,
                'content_json': canonical({'plan_envelope_sha256': 'f'*64})+'\n'}]
        observation['readbacks'][index]['independent']['rows'] = rows
        case['readback']['independent']['rows']['sha256'] = rows_digest(rows)
        native = json.loads(case['native_observation']['native_json'])
        native['error_code'] = 'state_revision_stale'
        approval = enrollments[0]['approval']
        def file_facts(suffix, file_id):
            return {'file_id': '0000000000000001:'+file_id*32,
                'native_name': '\\Device\\HarddiskVolume1\\Universal Setup\\Publisher\\'+observation['service']+
                    '.operation-'+approval['request_sha256']+suffix,
                'owner_sid': 'S-1-5-32-544', 'dacl_protected': True, 'attributes': 128,
                'reparse_tag': 0, 'link_count': 1, 'case_sensitive': False,
                'dacl_aces': [{'type': 0, 'flags': 0, 'access_mask': 0x1f01ff, 'sid': sid}
                    for sid in ('S-1-5-18', 'S-1-5-32-544')]}
        native['reviewed_operation_admission'] = {
            'schema': 'usk.publisher_selected_reviewed_operation_observation.v1',
            'scope': 'authenticated_exact_request_and_held_protected_enrollment_files',
            'approval': approval, 'approval_sha256': digest(approval),
            'approval_file': file_facts('.approval.json', 'b'), 'envelope_sha256': approval['envelope_sha256'],
            'envelope_file': file_facts('.envelope.json', 'c')}
        reseal(case, native)
        cases.append(case)
    observation['changed_state_revision'] = {'schema': 'usk.publisher_changed_state_revision_probe.v1',
        'scope': 'approved_initial_plan_a_commit_b_apply_a_before_effects', 'profile_qualified': False,
        'publication_authority_granted': False, 'plan_a_request': request_a, 'plan_a_response': response_a,
        'apply_a': apply_a, 'envelope_a_json': text, 'planned_at_file_time': '132000000000000000',
        'enrolled_at_file_time': '132000000000000001', 'enrollments': enrollments, 'cases': cases}
    return observation


def reseal(case, native):
    case['native_observation']['native_json'] = canonical(native)+'\n'
    case['native_observation']['sha256'] = hashlib.sha256(case['native_observation']['native_json'].encode()).hexdigest()


class ChangedStateRevisionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for name in ('native_rows', 'native_boundary', 'installed_material', 'lease_snapshot'):
            self.stack.enter_context(patch('publisher_changed_state_revision_evidence.'+name))

    def test_two_approved_plans_and_unchanged_b_keep_scope_bounded(self):
        result = reconcile(fixture(), 'Q:\\')
        self.assertEqual(result['cases_checked'], 2)
        self.assertNotEqual(result['cases'][0]['expected_revision'], result['cases'][0]['observed_revision'])
        self.assertIs(result['profile_qualified'], False)
        self.assertIs(result['publication_authority_granted'], False)

    def test_invalid_or_unapproved_plan_a_is_not_revision_protection(self):
        for mutate in (
            lambda r: r.pop('plan_a_response'),
            lambda r: r['plan_a_response'].update(status='refused'),
            lambda r: r['plan_a_response']['result']['payload'].update(commit_authority_available=True),
            lambda r: r['plan_a_request']['payload']['archive'].update(expected_sha256='0'*64),
            lambda r: r['apply_a'].update(reviewed_plan_digest='0'*64),
            lambda r: r['enrollments'].pop(),
            lambda r: r['enrollments'][0].update(status='failed'),
            lambda r: r['enrollments'][0]['approval'].update(caller_sid='S-1-5-18'),
            lambda r: r['enrollments'][0]['approval'].update(request_sha256='0'*64),
            lambda r: r.update(enrolled_at_file_time='132000000000000004'),
            lambda r: r.update(profile_qualified=True),
        ):
            observation = fixture(); mutate(observation['changed_state_revision'])
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                approved_initial_plans(observation)

    def test_refuses_resealed_native_authority_status_and_file_substitution(self):
        for mutate in (
            lambda n: n.update(error_code='stale_plan'),
            lambda n: n.update(status='recovery_required'),
            lambda n: n.update(process_id=999),
            lambda n: n['reviewed_operation_admission']['approval'].update(request_sha256='0'*64),
            lambda n: n['reviewed_operation_admission'].update(envelope_sha256='0'*64),
            lambda n: n['reviewed_operation_admission']['approval_file'].update(link_count=2),
            lambda n: n['reviewed_operation_admission']['approval_file'].update(dacl_protected=False),
            lambda n: n['reviewed_operation_admission']['approval_file']['dacl_aces'][0].update(sid='S-1-1-0'),
            lambda n: n['reviewed_operation_admission'].update(envelope_file=n['reviewed_operation_admission']['approval_file']),
        ):
            observation = fixture(); case = observation['changed_state_revision']['cases'][0]
            native = json.loads(case['native_observation']['native_json']); mutate(native); reseal(case, native)
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile(observation, 'Q:\\')

    def test_refuses_missing_record_unchanged_revision_and_reader_closure(self):
        for mutate in (
            lambda o: o.pop('changed_state_revision'),
            lambda o: o['changed_state_revision']['cases'][0]['response']['error'].update(code='stale_plan'),
            lambda o: o['changed_state_revision']['cases'][0]['readback']['independent']['rows'].update(sha256='0'*64),
            lambda o: o['changed_state_revision']['cases'][0]['readback']['independent'].update(observer_token_handles_closed=False),
        ):
            observation = fixture(); mutate(observation)
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile(observation, 'Q:\\')
        observation = fixture()
        rows = [{'path': 'Q:\\unrelated.json', 'directory': False, 'content_json': '{}'}]
        rows.append({'path': 'Q:\\publication\\journal\\lab-reviewed-plan.json', 'directory': False,
            'content_json': canonical({'plan_envelope_sha256': 'f'*64})+'\n'})
        observation['readbacks'][0]['independent']['rows'] = rows
        observation['changed_state_revision']['cases'][0]['readback']['independent']['rows']['sha256'] = rows_digest(rows)
        with self.assertRaises(StandardEvidenceError):
            reconcile(observation, 'Q:\\')


if __name__ == '__main__':
    unittest.main()
