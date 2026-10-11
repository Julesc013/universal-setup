# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
import base64
import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path.cwd() / 'tests'))
import test_publisher_installation_lease_evidence as fixture
from publisher_installation_lease_evidence import LeaseEvidenceError

import publisher_bootstrap_durable_state_fixture as factory


class DurableFixtureContradictions(unittest.TestCase):
    def test_live_cli_rejects_unclosed_and_duplicate_inputs(self):
        before, _, _ = fixture.takeover_fixture(0)
        request = dict(case='pending_empty', rows=before, drive=fixture.DRIVE, installed=fixture.INSTALLED,
            volume_id=fixture.ROOT, pending_name='bootstrap-123-456-1')
        command = [sys.executable, '-B', str(Path(__file__).with_name('publisher_bootstrap_durable_state_fixture.py')), '--prepare']
        environment = dict(os.environ, PYTHONPATH=str(Path.cwd() / 'tests'))
        result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['bytes'], 0)
        self.assertEqual(json.loads(result.stdout)['content_base64'], '')
        extra = json.dumps(dict(request, authority=True))
        duplicate = json.dumps(request)[:-1] + ',"case":"pending_full"}'
        for text in (extra, duplicate):
            result = subprocess.run(command, input=text, text=True, capture_output=True, env=environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')

    def test_finite_durable_byte_states(self):
        before, _, _ = fixture.takeover_fixture(0)
        outputs = {case: factory.prepare(case, before, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT,
                                        'bootstrap-123-456-1') for case in factory.CASES[:-1]}
        self.assertEqual(outputs['publication_absent']['action'], 'remove_exact_empty_owned_root')
        self.assertEqual(base64.b64decode(outputs['pending_empty']['content_base64']), b'')
        move = base64.b64decode(outputs['move_intent']['content_base64'])
        self.assertEqual(base64.b64decode(outputs['pending_full']['content_base64']), move)
        middle = base64.b64decode(outputs['pending_middle']['content_base64'])
        self.assertTrue(move.startswith(middle))
        self.assertLess(len(middle), len(move))
        _, preserved, _, _ = fixture.preservation_takeover_fixture()
        result = factory.prepare('next_reservation_absent', preserved, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT)
        self.assertTrue(result['path'].endswith('-bootstrap-g00000000000000000002.json'))

    def test_no_existing_target_or_nonempty_root_adoption(self):
        before, _, _ = fixture.takeover_fixture(0)
        target = factory.prepare('move_intent', before, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT)['path']
        for changed in (before + [{'path': target, 'directory': False}],
                        before + [{'path': fixture.DRIVE + 'publication\\payload.bin', 'directory': False}]):
            with self.assertRaises(LeaseEvidenceError):
                factory.prepare('move_intent', changed, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT)

    def test_pending_basename_cannot_escape_parent(self):
        before, _, _ = fixture.takeover_fixture(0)
        for name in ('../outside', 'bootstrap-1-2-0', 'bootstrap-1-2-3\\extra', None):
            with self.subTest(name=name), self.assertRaises(LeaseEvidenceError):
                factory.prepare('pending_full', before, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT, name)

    def test_seals_volume_and_actual_stage_must_match(self):
        before, _, _ = fixture.takeover_fixture(0)
        for mode in ('alias', 'volume', 'stage'):
            changed = copy.deepcopy(before)
            volume = fixture.ROOT
            case = 'move_intent'
            if mode == 'alias': changed.append(copy.deepcopy(changed[0]))
            elif mode == 'volume': volume = '0000000000000001:' + 'c' * 32
            else: case = 'next_reservation_absent'
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                factory.prepare(case, changed, fixture.DRIVE, fixture.INSTALLED, volume)

    def test_reservation_must_match_actual_native_active_journal(self):
        before, _, _ = fixture.takeover_fixture(0)
        reservation_path = fixture.CONTEXTS + '\\operation-' + fixture.digest(fixture.INSTALLED['transaction_id']) + '-bootstrap-g00000000000000000001.json'
        for mode in ('holder', 'missing_journal', 'boolean_generation', 'root_identity'):
            changed = copy.deepcopy(before)
            if mode == 'missing_journal':
                changed = [row for row in changed if row['path'] != fixture.LEASES + '\\g00000000000000000001-active.json']
            elif mode == 'root_identity':
                next(row for row in changed if row['path'] == fixture.DRIVE + 'setup-state')['file_id'] = '0000000000000001:' + 'c' * 32
            else:
                index = next(index for index, row in enumerate(changed) if row['path'] == reservation_path)
                value = json.loads(changed[index]['content_json'])
                if mode == 'holder': value['ownership']['holder']['process_id'] += 1
                else: value['ownership']['generation'] = True
                value['ownership']['ownership_sha256'] = fixture.digest({key: item for key, item in value['ownership'].items() if key != 'ownership_sha256'})
                value['reservation_sha256'] = fixture.digest({key: item for key, item in value.items() if key != 'reservation_sha256'})
                changed[index].update(fixture.record(reservation_path, value))
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                factory.prepare('move_intent', changed, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT)

    def test_generation2_native_row_cannot_relabel_a_self_sealed_holder(self):
        _, preserved, _, _ = fixture.preservation_takeover_fixture()
        path = fixture.LEASES + '\\g00000000000000000002-active.json'
        for mode in ('generation', 'boolean_generation', 'predecessor', 'same_holder', 'text_pid'):
            changed = copy.deepcopy(preserved)
            index = next(index for index, row in enumerate(changed) if row['path'] == path)
            value = json.loads(changed[index]['content_json'])
            first = json.loads(next(row for row in changed if row['path'] == fixture.LEASES + '\\g00000000000000000001-active.json')['content_json'])
            if mode == 'generation': value['generation'] = 1
            elif mode == 'boolean_generation': value['generation'] = True
            elif mode == 'predecessor': value['predecessor_sha256'] = 'f' * 64
            elif mode == 'same_holder': value['holder'] = first['holder']
            else: value['holder']['process_id'] = str(value['holder']['process_id'])
            value['ownership_sha256'] = fixture.digest({key: item for key, item in value.items() if key != 'ownership_sha256'})
            changed[index].update(fixture.record(path, value))
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                factory.prepare('next_reservation_absent', changed, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT)


if __name__ == '__main__':
    unittest.main()
