# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic fixture contradictions; no native/runtime qualification."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_publisher_installation_lease_evidence as lease_fixture
from publisher_bootstrap_prefix_evidence import ANCHORS, CASES, SCOPE, constructed_rows, prefix
from publisher_installation_lease_evidence import LeaseEvidenceError, digest, constructed_prefix_takeover


class ConstructedPrefixEvidenceTests(unittest.TestCase):
    def test_direct_takeover_cannot_label_empty_root_as_named_prefix(self):
        before, after, holder = lease_fixture.takeover_fixture(0)
        for case, length in (('anchors_1', None), ('snapshot_full', -1), ('snapshot_empty', False)):
            with self.subTest(case=case), self.assertRaises(LeaseEvidenceError):
                constructed_prefix_takeover(before, after, lease_fixture.DRIVE, lease_fixture.INSTALLED,
                    lease_fixture.ROOT, holder, case, length)

    def test_direct_takeover_checks_actual_typed_size_and_bytes(self):
        original = lease_fixture.takeover_fixture(4, 1)
        for mode in ('length_negative', 'length_bool', 'length_wrong', 'bytes', 'case'):
            before, after, holder = copy.deepcopy(original)
            size, case = 1, 'snapshot_first'
            if mode == 'length_negative': size = -1
            elif mode == 'length_bool': size = True
            elif mode == 'length_wrong': size = 2
            elif mode == 'bytes': next(row for row in before if row['path'].endswith('lab-reviewed-plan.json'))['sha256'] = '0' * 64
            else: case = 'snapshot_full'
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                constructed_prefix_takeover(before, after, lease_fixture.DRIVE, lease_fixture.INSTALLED,
                    lease_fixture.ROOT, holder, case, size)
        before, after, holder = original
        result = constructed_prefix_takeover(before, after, lease_fixture.DRIVE, lease_fixture.INSTALLED,
            lease_fixture.ROOT, holder, 'snapshot_first', 1)
        self.assertEqual(result['retained_objects'], 6)
        self.assertFalse(result['native_crash_at_constructed_prefix_observed'])

    def test_live_cli_rejects_empty_root_labelled_full_snapshot(self):
        before, after, holder = lease_fixture.takeover_fixture(0)
        request = dict(mode='constructed_prefix_takeover', before=before, after=after, drive=lease_fixture.DRIVE,
            installed=lease_fixture.INSTALLED, volume_root_id=lease_fixture.ROOT, terminated_holder=holder,
            case='snapshot_full', snapshot_size_bytes=-1)
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('publisher_installation_lease_evidence.py')),
            '--input', '-'], input=json.dumps(request), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def fixture(self, case='snapshot_middle'):
        drive, installed = lease_fixture.DRIVE, dict(lease_fixture.INSTALLED, target_root='U:/publication/destination/visible')
        before, _, _ = lease_fixture.takeover_fixture(0)
        context_path = (drive + 'installation-operations\\install-' + digest(installed['install_id']) +
                        '\\operation-' + digest(installed['transaction_id']) + '.json')
        context = next(row for row in before if row['path'] == context_path)
        count, raw = prefix(case, context)
        root = drive + 'publication'
        rows = copy.deepcopy(before)
        rows += [{'path': root + '\\' + name, 'directory': True} for name in ANCHORS[:count]]
        if raw is not None:
            rows.append({'path': root + '\\journal\\lab-reviewed-plan.json', 'directory': False,
                'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'content_json': raw.decode()})
        boundary = {'root': {'file_id': lease_fixture.ROOT}, 'device': {}}
        observation = {'service': 'USK_PUB_example', 'account_sid': 'S-1-5-21-1-2-3-1001', 'service_sid': 'S-1-5-80-1-2-3-4-5'}
        record = {'schema': 'usk.publisher_constructed_bootstrap_prefix.v1', 'scope': SCOPE, 'case': case,
            'fixture_actor': {'identity': 'S-1-5-18', 'process_id': 123, 'creation_file_time': '134356780000000000',
                'service': observation['service'], 'service_stopped': True,
                'publication_root_file_id': next(row['file_id'] for row in before if row['path'] == root)},
            'anchor_count': count, 'snapshot_size_bytes': None if raw is None else len(raw),
            'created_at_file_time': '134356780000000001',
            'readback': {'independent': {'rows': rows, 'volume_boundary': boundary}}}
        return record, before, drive, installed, observation, {}, boundary

    def decode(self, values):
        # Native rows/token/rights validators have their own tests. These mocks
        # isolate prefix contradictions and are never runtime evidence.
        with patch('publisher_standard_public_evidence.reader_rows', side_effect=lambda readback, *_: readback['independent']['rows']), \
             patch('publisher_standard_public_evidence.native_rows'), \
             patch('publisher_standard_public_evidence.native_boundary'):
            return constructed_rows(*values)

    def test_all_named_shapes_preserve_original_rows_and_exact_prefix(self):
        for case in CASES:
            with self.subTest(case=case):
                values = self.fixture(case)
                rows = self.decode(values)
                self.assertEqual(len(rows) - len(values[1]), values[0]['anchor_count'] +
                                 (0 if values[0]['snapshot_size_bytes'] is None else 1))

    def test_changed_original_or_extra_objects_are_rejected(self):
        for mode in ('original', 'extra', 'missing_anchor', 'snapshot_bytes'):
            values = self.fixture()
            rows = values[0]['readback']['independent']['rows']
            if mode == 'original':
                rows[0]['file_id'] = 'changed'
            elif mode == 'extra':
                rows.append({'path': values[2] + 'publication\\payload.bin', 'directory': False})
            elif mode == 'missing_anchor':
                rows[:] = [row for row in rows if row['path'] != values[2] + 'publication\\state']
            else:
                rows[-1]['sha256'] = '0' * 64
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                self.decode(values)

    def test_actor_scope_volume_and_typed_lengths_cannot_be_forged(self):
        for mode in ('actor', 'stopped', 'scope', 'volume', 'length', 'anchor_bool'):
            values = self.fixture('snapshot_empty')
            record = values[0]
            if mode == 'actor': record['fixture_actor']['identity'] = 'S-1-5-32-544'
            elif mode == 'stopped': record['fixture_actor']['service_stopped'] = False
            elif mode == 'scope': record['scope'] = 'native_crash_at_every_prefix'
            elif mode == 'volume': record['readback']['independent']['volume_boundary'] = {}
            elif mode == 'length': record['snapshot_size_bytes'] = False
            else: record['anchor_count'] = True
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                self.decode(values)

    def test_nonempty_original_root_and_claimed_shape_are_rejected(self):
        for mode in ('original_child', 'case', 'root_identity'):
            values = self.fixture('anchors_2')
            if mode == 'original_child': values[1].append({'path': values[2] + 'publication\\staging', 'directory': True})
            elif mode == 'case': values[0]['case'] = 'anchors_3'
            else: values[0]['fixture_actor']['publication_root_file_id'] = lease_fixture.ROOT
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                self.decode(values)


if __name__ == '__main__':
    unittest.main()
