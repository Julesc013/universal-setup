# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic contradictions only; these tests do not qualify an active installer."""
import copy
import json
import unittest
from publisher_installation_lease_evidence import LeaseEvidenceError, snapshot
from publisher_standard_public_evidence import StandardEvidenceError, reconcile_active_install_contention
from test_publisher_registered_contention_evidence import fixture as endpoint_fixture
from test_publisher_installation_lease_evidence import fixture as lease_fixture, DRIVE, ROOT, INSTALLED
from test_publisher_installation_lease_evidence import active_fixture, record as lease_record
from publisher_installation_lease_evidence import active_ownership, digest


def fixture():
    observation, client = endpoint_fixture()
    record = observation.pop('registered_contention')
    observation['active_install_contention'] = record
    scope = 'active_install_holder_endpoint_before_effect_request_bytes'
    record['scope'] = record['native_observation']['scope'] = scope
    record['worker_stopped'] = False
    record['native_observation']['worker_process_id'] = 101
    record['native_observation']['worker_process_creation_time'] = 1
    record['paused_worker'] = {'process_id': 101, 'process_creation_file_time': '1',
                              'paused_threads': 2, 'identity_live_while_paused': True}
    record['installer_live_before_resume'] = record['worker_pause_restored'] = True
    completed = lease_fixture()
    completed.append({'path': DRIVE+'setup-state\\state\\installed', 'directory': True,
                      'file_id': ROOT})
    active = [row for row in completed if not row['path'].endswith('-terminal.json') and
              '\\installed\\' not in row['path']]
    boundary = observation['readbacks'][0]['independent']['volume_boundary']
    boundary['root']['file_id'] = ROOT
    planning = {'schema': 'usk.install_local_plan_request.v1', 'request_id': 'active.plan',
                'target': {'root': DRIVE+'publication\\destination\\visible'}}
    observation['plan_request'] = {'schema': 'usk.oneshot_request.v1', 'request_id': planning['request_id'],
        'command': 'install_local.plan', 'payload': copy.deepcopy(planning), 'dry_run': True}
    observation['apply_request'] = {'plan_request': copy.deepcopy(planning)}
    observation['plan'] = {'target': {'root': planning['target']['root'].replace('\\', '/')}}
    observation['apply'] = {'result': {'payload': INSTALLED}}
    observation['readbacks'][0]['independent']['rows'] = completed
    for name in ('before', 'after'):
        record[name]['independent']['rows'] = copy.deepcopy(active)
        record[name]['independent']['volume_boundary'] = copy.deepcopy(boundary)
    record['lease_before'] = {'status': 'bindings_consistent',
        'coordination': snapshot(active, DRIVE, INSTALLED, ROOT, allow_active=True, allow_initial_empty_state=True),
        'profile_qualified': False, 'publication_authority_granted': False}
    return observation, client


def child_fixture():
    observation, client = fixture()
    record = observation['active_install_contention']
    record['schema'] = 'usk.publisher_active_install_contention_probe.v2'
    # Original sealed native lease remains child101; SCM is deliberately102.
    record['native_observation']['worker_process_id'] = record['paused_worker']['process_id'] = 102
    pair = {'schema': 'usk.publisher_owned_live_process_pair.v1',
        'scope': 'held_scm_parent_and_original_live_effect_child',
        'parent_process_id': 102, 'parent_process_birth': '0000000000000001',
        'effect_process_id': 101, 'effect_process_birth': '0000000000000001',
        'native_parent_process_id': 102, 'original_image_path': observation['installed_binary'],
        'both_live': True, 'child_observer_access': 0x101400, 'child_observer_handle_flags': 0}
    record['live_pair_before'] = copy.deepcopy(pair)
    record['live_pair_after'] = copy.deepcopy(pair)
    record['child_observer_close_confirmed'] = True
    return observation, client


def ownership_fixture(published=False):
    observation, client = child_fixture()
    record = observation['active_install_contention']
    rows, request, response, apply, consumer, holder = active_fixture(published)
    assert client == consumer
    observation.update(plan_request=request, plan_response=response, plan=response['result']['payload'], apply_request=apply)
    record['schema'] = 'usk.publisher_active_install_contention_probe.v3'
    record['paused_effect_child'] = {'process_id': holder['process_id'], 'process_creation_file_time': '1',
                                    'paused_threads': 1, 'identity_live_while_paused': True}
    record['effect_child_pause_restored'] = True
    for name in ('before', 'after'):
        record[name]['independent']['rows'] = copy.deepcopy(rows)
    record['lease_before']['coordination'] = active_ownership(rows, DRIVE, INSTALLED, ROOT,
        request, response, apply, consumer, holder)
    completed = copy.deepcopy(rows)
    active = next(row for row in rows if row['path'].endswith('-active.json'))
    terminal = dict(json.loads(active['content_json']), status='completed',
        result_state_revision=digest([{'record': INSTALLED['install_id']+'.'+INSTALLED['transaction_id']+'.json',
                                      'sha256': digest(INSTALLED)}]))
    terminal['ownership_sha256'] = digest({k: v for k, v in terminal.items() if k != 'ownership_sha256'})
    completed += [lease_record(active['path'].replace('-active.json', '-terminal.json'), terminal),
                  lease_record(DRIVE+'setup-state\\state\\installed\\'+INSTALLED['install_id']+'.'+INSTALLED['transaction_id']+'.json', INSTALLED)]
    if not published:
        context = json.loads(next(row['content_json'] for row in rows if row['path'].endswith('.json') and
            'reviewed_snapshot' in json.loads(row['content_json'])))
        completed.append(lease_record(DRIVE+'publication\\journal\\lab-reviewed-plan.json', context['reviewed_snapshot']))
    observation['readbacks'][0]['independent']['rows'] = completed
    return observation, client


class ActiveInstallContentionEvidenceTests(unittest.TestCase):
    def test_v3_original_early_and_published_ownership_reconcile_with_checked_child_pause(self):
        for published in (False, True):
            observation, client = ownership_fixture(published)
            result = reconcile_active_install_contention(observation, client)
            self.assertEqual(result['cases_checked'], 4)
            self.assertFalse(result['profile_qualified'])

    def test_v3_child_suspend_custody_cannot_replace_query_pair_or_skip_restoration(self):
        for mutate in (
            lambda r: r['paused_effect_child'].update(process_id=102),
            lambda r: r['paused_effect_child'].update(process_creation_file_time='2'),
            lambda r: r['paused_effect_child'].update(paused_threads=0),
            lambda r: r['paused_effect_child'].update(identity_live_while_paused=False),
            lambda r: r.update(effect_child_pause_restored=False),
            lambda r: r.pop('paused_effect_child'),
            lambda r: r['live_pair_after'].update(effect_process_birth='0000000000000002'),
            lambda r: r['live_pair_before'].update(child_observer_access=0x101401),
        ):
            observation, client = ownership_fixture()
            mutate(observation['active_install_contention'])
            with self.subTest(mutation=mutate), self.assertRaises((StandardEvidenceError, LeaseEvidenceError)):
                reconcile_active_install_contention(observation, client)

    def test_v3_actual_response_and_phase_cannot_be_substituted_or_downgraded(self):
        observation, client = ownership_fixture()
        observation['plan_response']['request_id'] = 'different.original.request'
        with self.assertRaises(LeaseEvidenceError):
            reconcile_active_install_contention(observation, client)
        observation, client = ownership_fixture()
        observation['active_install_contention']['lease_before']['coordination']['active_ownership_phase'] = 'published_reviewed_plan'
        with self.assertRaises(StandardEvidenceError):
            reconcile_active_install_contention(observation, client)
        observation, client = ownership_fixture()
        r = observation['active_install_contention'];r['schema'] = 'usk.publisher_active_install_contention_probe.v2'
        r.pop('paused_effect_child');r.pop('effect_child_pause_restored')
        with self.assertRaises(KeyError):
            reconcile_active_install_contention(observation, client)

    def test_current_phase_families_require_original_live_child_contention(self):
        for phase in ('usk.publisher.lab_phase_evidence.v10', 'usk.publisher.lab_phase_evidence.v11'):
            marker = {'path': DRIVE+'publication\\lab-prepared-evidence.json',
                      'content_json': '{"schema":"'+phase+'"}'}
            with self.subTest(phase=phase):
                observation, client = fixture()
                observation['readbacks'][0]['independent']['rows'].append(copy.deepcopy(marker))
                with self.assertRaisesRegex(StandardEvidenceError, 'downgraded its live-pair'):
                    reconcile_active_install_contention(observation, client)
                observation, client = child_fixture()
                observation['readbacks'][0]['independent']['rows'].append(copy.deepcopy(marker))
                result = reconcile_active_install_contention(observation, client)
                self.assertEqual(result['cases_checked'], 4)
                self.assertFalse(result['profile_qualified'])

    def test_current_child_lease_is_distinct_from_actual_scm_pause_and_endpoint(self):
        observation, client = child_fixture()
        result = reconcile_active_install_contention(observation, client)
        self.assertEqual(result['cases_checked'], 4)
        self.assertFalse(result['profile_qualified'])
        record = observation['active_install_contention']
        self.assertNotEqual(record['paused_worker']['process_id'], record['lease_before']['coordination']['history'][0]['holder']['process_id'])

    def test_current_live_child_custody_and_scm_roles_cannot_be_substituted(self):
        for mutate in (
            lambda r: r['paused_worker'].update(process_id=101),
            lambda r: r['native_observation'].update(worker_process_id=101),
            lambda r: r['live_pair_after'].update(effect_process_birth='0000000000000002'),
            lambda r: r.update(child_observer_close_confirmed=False),
            lambda r: r['live_pair_before'].update(both_live=False),
            lambda r: r['live_pair_before'].update(child_observer_access=0x101401),
            lambda r: r['live_pair_before'].update(child_observer_handle_flags=False),
            lambda r: r.update(worker_pause_restored=False),
        ):
            observation, client = child_fixture()
            mutate(observation['active_install_contention'])
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile_active_install_contention(observation, client)
        observation, client = child_fixture()
        record = observation['active_install_contention']
        for key in ('live_pair_before', 'live_pair_after'):
            record[key]['effect_process_id'] = 103
        # Consistent native pair copies still contradict the sealed original lease.
        with self.assertRaises(StandardEvidenceError):
            reconcile_active_install_contention(observation, client)

    def test_requires_real_planning_envelope_and_matching_reviewed_targets(self):
        observation, client = fixture()
        for mutate in (
            lambda o: o.update(plan_request={'target': o['plan_request']['payload']['target']}),
            lambda o: o['plan_request'].update(target=o['plan_request']['payload']['target']),
            lambda o: o['plan_request'].update(dry_run=False),
            lambda o: o['plan_request'].update(payload='missing typed plan'),
            lambda o: o['plan_request']['payload'].update(request_id='different.plan'),
            lambda o: o['plan_request']['payload'].update(target=None),
            lambda o: o['apply_request']['plan_request']['target'].update(root=DRIVE+'another-target'),
            lambda o: o['plan']['target'].update(root=DRIVE+'another-target'),
        ):
            changed = copy.deepcopy(observation)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises(StandardEvidenceError):
                reconcile_active_install_contention(changed, client)

    def test_requires_native_active_holder_and_completed_same_installation(self):
        observation, client = fixture()
        result = reconcile_active_install_contention(observation, client)
        self.assertEqual(result['cases_checked'], 4)
        self.assertEqual(result['scope'], 'active_install_holder_endpoint_before_effect_request_bytes')
        self.assertIs(result['profile_qualified'], False)
        self.assertIsNone(reconcile_active_install_contention({}, client))

    def test_refuses_missing_restoration_and_contradictory_native_holder(self):
        observation, client = fixture()
        for mutate in (
            lambda r: r.update(worker_pause_restored=False),
            lambda r: r.update(installer_live_before_resume=False),
            lambda r: r['paused_worker'].update(identity_live_while_paused=False),
            lambda r: r['paused_worker'].update(process_id=True),
            lambda r: r['paused_worker'].update(process_id=102),
            lambda r: r['paused_worker'].update(process_creation_file_time='2'),
            lambda r: r['paused_worker'].update(paused_threads=0),
            lambda r: r['lease_before'].update(publication_authority_granted=True),
            lambda r: r['native_observation'].update(worker_process_creation_time=2),
            lambda r: r['before']['independent'].update(rows=[]),
            lambda r: r.update(worker_stopped=True),
        ):
            changed = copy.deepcopy(observation)
            mutate(changed['active_install_contention'])
            with self.subTest(mutation=mutate), self.assertRaises((StandardEvidenceError, LeaseEvidenceError)):
                reconcile_active_install_contention(changed, client)

    def test_refuses_completed_holder_disguised_as_active(self):
        observation, client = fixture()
        completed = observation['readbacks'][0]['independent']['rows']
        for phase in ('before', 'after'):
            observation['active_install_contention'][phase]['independent']['rows'] = copy.deepcopy(completed)
        with self.assertRaises((StandardEvidenceError, LeaseEvidenceError)):
            reconcile_active_install_contention(observation, client)

    def test_initial_empty_state_requires_its_explicit_bounded_mode(self):
        observation, _ = fixture()
        rows = observation['active_install_contention']['before']['independent']['rows']
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT, allow_active=True)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT, allow_initial_empty_state=True)
        foreign = copy.deepcopy(rows)
        foreign.append({'path': DRIVE+'setup-state\\state\\installed\\another-install.json',
                        'directory': False})
        with self.assertRaises(LeaseEvidenceError):
            snapshot(foreign, DRIVE, INSTALLED, ROOT, allow_active=True, allow_initial_empty_state=True)


if __name__ == '__main__':
    unittest.main()
