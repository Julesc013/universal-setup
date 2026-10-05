# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic contradictions only; these tests do not qualify an active installer."""
import copy
import unittest
from publisher_installation_lease_evidence import LeaseEvidenceError, snapshot
from publisher_standard_public_evidence import StandardEvidenceError, reconcile_active_install_contention
from test_publisher_registered_contention_evidence import fixture as endpoint_fixture
from test_publisher_installation_lease_evidence import fixture as lease_fixture, DRIVE, ROOT, INSTALLED


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
    observation['plan_request'] = {'target': {'root': DRIVE+'publication\\destination\\visible'}}
    observation['apply'] = {'result': {'payload': INSTALLED}}
    observation['readbacks'][0]['independent']['rows'] = completed
    for name in ('before', 'after'):
        record[name]['independent']['rows'] = copy.deepcopy(active)
        record[name]['independent']['volume_boundary'] = copy.deepcopy(boundary)
    record['lease_before'] = {'status': 'bindings_consistent',
        'coordination': snapshot(active, DRIVE, INSTALLED, ROOT, allow_active=True, allow_initial_empty_state=True),
        'profile_qualified': False, 'publication_authority_granted': False}
    return observation, client


class ActiveInstallContentionEvidenceTests(unittest.TestCase):
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
