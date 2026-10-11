# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic contradictions only; no native fixture or custody qualification."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd() / 'tests'))
import test_publisher_installation_lease_evidence as fixture
from publisher_installation_lease_evidence import LeaseEvidenceError, snapshot

import publisher_bootstrap_durable_state_evidence as evidence
NAME = 'bootstrap-123-456-1'


def constructed(case, rows):
    prepared = evidence.factory.prepare(case, rows, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT, NAME)
    measured = copy.deepcopy(rows)
    if prepared['action'] == 'remove_exact_empty_owned_root':
        return [row for row in measured if row['path'] != prepared['path']], None
    native = copy.deepcopy(next(row for row in rows if 'raw_aces' in row))
    native.update(path=prepared['path'], native_name=prepared['path'][2:], directory=False,
        file_id='0000000000000001:' + 'f' * 32, attributes=32, link_count=1, case_sensitive=False,
        reparse_tag=0, protected=True, owner='S-1-5-18', bytes=prepared['bytes'], sha256=prepared['sha256'],
        streams=[dict(name='::$DATA', size=prepared['bytes'], allocation_size=4096)],
        content_json=None if case.startswith('pending_') else base64.b64decode(prepared['content_base64']).decode('utf-8'))
    measured.append(native)
    return measured, native


def scenario(case):
    before, after, holder = fixture.takeover_fixture(0)
    prefix = fixture.CONTEXTS + '\\operation-' + fixture.digest(fixture.INSTALLED['transaction_id'])
    original_empty = None
    holders = [holder]
    if case == 'next_reservation_absent':
        original_empty, before, after, holders = fixture.preservation_takeover_fixture()
    measured, added = constructed(case, before)
    if case.startswith('pending_') or case == 'next_reservation_absent':
        after.append(copy.deepcopy(added))
    if case == 'move_intent':
        actual = next(row for row in after if row['path'] == added['path'])
        assert actual['content_json'] == added['content_json'], 'Factory move bytes differ from the native-format fixture'
        actual.update(added)
    if case in ('publication_absent', 'next_reservation_absent'):
        generation = 1 if case == 'publication_absent' else 2
        active = json.loads(next(row for row in after if row['path'] == fixture.LEASES + f'\\g{generation + 1:020d}-active.json')['content_json'])
        reserved_path = prefix + f'-bootstrap-g{generation:020d}.json'
        reservation = json.loads(next(row for row in after if row['path'] == reserved_path)['content_json'])
        value = dict(schema='usk.publication_bootstrap_absence.v1', install_id=fixture.INSTALLED['install_id'],
            operation_id=fixture.INSTALLED['transaction_id'], reservation_sha256=reservation['reservation_sha256'],
            closing_ownership=active, publication_absent=True)
        value['preservation_sha256'] = fixture.digest(value)
        path = prefix + f'-preserve-g{generation:020d}.json'
        after = [row for row in after if row['path'] != path]
        after.append(dict(fixture.record(path, value), native_name=path[2:]))
        if generation == 1:
            retained = prefix + '-retained-g00000000000000000001'
            after = [row for row in after if row['path'] != retained and not row['path'].startswith(retained + '\\')]
    return before, measured, after, holders, original_empty


def reconcile(case, values):
    before, measured, after, holders, original_empty = values
    return evidence.reconcile(case, before, measured, after, fixture.DRIVE, fixture.INSTALLED, fixture.ROOT,
        holders, NAME, original_empty)


class DurableStateEvidenceContradictions(unittest.TestCase):
    def test_closed_cli_reconciles_all_six_exact_cases(self):
        for case in evidence.factory.CASES:
            before, measured, after, holders, original_empty = scenario(case)
            request = dict(mode='constructed_durable_takeover', case=case, original=before, constructed=measured,
                after=after, drive=fixture.DRIVE, installed=fixture.INSTALLED, volume_root_id=fixture.ROOT,
                pending_name=NAME if case.startswith('pending_') else None,
                terminated_holders=holders, original_empty=original_empty)
            result = evidence.reconcile_request(request)
            self.assertEqual(result['coordination']['case'], case)
            self.assertFalse(result['profile_qualified'])
            self.assertFalse(result['publication_authority_granted'])
            for changed in (dict(request, extra=True), {k: v for k, v in request.items() if k != 'original'},
                            dict(request, case=True), dict(request, pending_name='other')):
                with self.subTest(case=case), self.assertRaises((LeaseEvidenceError, ValueError)):
                    evidence.reconcile_request(changed)

    def test_live_cli_preserves_closed_and_duplicate_input_refusals(self):
        before, measured, after, holders, _ = scenario('pending_empty')
        request = dict(mode='snapshot', case='pending_empty', original=before, constructed=measured, rows=after,
            drive=fixture.DRIVE, installed=fixture.INSTALLED, volume_root_id=fixture.ROOT, pending_name=NAME)
        environment = dict(os.environ, PYTHONPATH=str(Path.cwd() / 'tests'))
        for text, accepted in ((json.dumps(request), True), (json.dumps(dict(request, extra=True)), False),
                               ('{"mode":"snapshot",' + json.dumps(request)[1:], False)):
            result = subprocess.run([sys.executable, '-B', str(Path(evidence.__file__)), '--input', '-'],
                input=text, capture_output=True, text=True, env=environment)
            if accepted:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(json.loads(result.stdout)['publication_authority_granted'])
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_observed_constructor_requires_actual_launcher_and_exact_parent(self):
        before, measured, _, _, _ = scenario('pending_middle')
        expected, fragment = evidence.constructed_rows('pending_middle', before, measured, fixture.DRIVE,
            fixture.INSTALLED, fixture.ROOT, NAME)
        boundary = {'root': {'file_id': fixture.ROOT}}
        launcher = dict(identity='S-1-5-18', process_id=123, creation_file_time='134356780000000000')
        observation = dict(launcher_process=launcher, service='USK_PUB_fixture', account_sid='S-1-5-21-1-2-3-1001',
            service_sid='S-1-5-80-1-2-3-4-5')
        record = dict(schema='usk.publisher_constructed_bootstrap_durable_state.v1', scope=evidence.SCOPE,
            case='pending_middle', pending_name=NAME, created_at_file_time='134356780000000001',
            fixture_actor=dict(launcher, service=observation['service'], service_stopped=True,
                parent_file_id=expected['parent_file_id'], removed_root_file_id=None),
            readback={'independent': {'rows': measured, 'volume_boundary': boundary}})
        installed = dict(fixture.INSTALLED, target_root='U:/publication/destination/visible')
        with patch('publisher_standard_public_evidence.reader_rows', side_effect=lambda r, *a: r['independent']['rows']), \
                patch('publisher_standard_public_evidence.native_rows'), patch('publisher_standard_public_evidence.native_boundary'):
            rows, actual = evidence.observed_fixture(record, before, fixture.DRIVE, installed, observation, {}, boundary)
            self.assertEqual((rows, actual), (measured, fragment))
            for mode in ('extra', 'scope', 'pid', 'bool_pid', 'birth', 'principal', 'parent', 'removed_root', 'timestamp', 'pending', 'service_live'):
                changed = copy.deepcopy(record)
                if mode == 'extra': changed['authority'] = True
                elif mode == 'scope': changed['scope'] = 'actual_crash'
                elif mode == 'pid': changed['fixture_actor']['process_id'] = 124
                elif mode == 'bool_pid': changed['fixture_actor']['process_id'] = True
                elif mode == 'birth': changed['fixture_actor']['creation_file_time'] = '134356780000000002'
                elif mode == 'principal': changed['fixture_actor']['identity'] = 'S-1-5-19'
                elif mode == 'parent': changed['fixture_actor']['parent_file_id'] = 'other'
                elif mode == 'removed_root': changed['fixture_actor']['removed_root_file_id'] = fixture.ROOT
                elif mode == 'timestamp': changed['created_at_file_time'] = launcher['creation_file_time']
                elif mode == 'pending': changed['pending_name'] = 'bootstrap-124-456-1'
                else: changed['fixture_actor']['service_stopped'] = False
                with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                    evidence.observed_fixture(changed, before, fixture.DRIVE, installed, observation, {}, boundary)

    def test_reserved_absence_requires_exact_native_generation_and_two_absence_reads(self):
        for generation, case in ((1, 'publication_absent'), (2, 'next_reservation_absent')):
            before, measured, after, holders, original_empty = scenario(case)
            prefix = fixture.CONTEXTS + '\\operation-' + fixture.digest(fixture.INSTALLED['transaction_id'])
            record = dict(schema='usk.publisher_reserved_publication_absence.v1', path=fixture.DRIVE + 'publication',
                parent_root_identity=fixture.ROOT, win32_error_before=2, win32_error_after=2, generation=generation,
                reservation_record_path=prefix + f'-bootstrap-g{generation:020d}.json',
                ownership_record_path=fixture.LEASES + f'\\g{generation:020d}-active.json',
                previous_preservation_record_path=None if generation == 1 else prefix + '-preserve-g00000000000000000001.json',
                previous_retained_root_path=None if generation == 1 else prefix + '-retained-g00000000000000000001')
            readback = dict(rows=measured, volume_boundary=dict(root=dict(file_id=fixture.ROOT)), publication_absence=record)
            result = evidence.reserved_absence(readback, fixture.DRIVE, fixture.INSTALLED, generation)
            self.assertEqual(result['generation'], generation)
            self.assertFalse(result['profile_qualified'])
            for mode in ('schema', 'boolean_generation', 'unknown_before', 'parent_missing_before',
                    'parent_missing_after', 'boolean_after', 'volume', 'reservation', 'extra'):
                changed = copy.deepcopy(readback)
                target = changed['publication_absence']
                if mode == 'schema': target['schema'] = 'usk.publisher_preserved_publication_absence.v1'
                elif mode == 'boolean_generation': target['generation'] = True
                elif mode == 'unknown_before': target['win32_error_before'] = 5
                elif mode == 'parent_missing_before': target['win32_error_before'] = 3
                elif mode == 'parent_missing_after': target['win32_error_after'] = 3
                elif mode == 'boolean_after': target['win32_error_after'] = False
                elif mode == 'volume': target['parent_root_identity'] = '0000000000000001:' + 'c' * 32
                elif mode == 'reservation': target['reservation_record_path'] += '.other'
                else: target['authority'] = True
                with self.subTest(generation=generation, mode=mode), self.assertRaises(LeaseEvidenceError):
                    evidence.reserved_absence(changed, fixture.DRIVE, fixture.INSTALLED, generation)

    def test_all_six_named_states_have_distinct_bounded_reconciliation(self):
        for case in evidence.factory.CASES:
            with self.subTest(case=case):
                result = reconcile(case, scenario(case))
                self.assertEqual(result['schema'], 'usk.publisher_constructed_durable_takeover_reconciliation.v1')
                self.assertEqual(result['replacement_generation'], 3 if case == 'next_reservation_absent' else 2)
                self.assertEqual(result['case'], case)
                self.assertFalse(result['native_crash_at_constructed_state_observed'])
                self.assertFalse(result['native_uncertain_error_observed'])
                self.assertFalse(result['power_loss_observed'])
                self.assertFalse(result['profile_qualified'])
                self.assertFalse(result['publication_authority_granted'])

    def test_default_record_closure_still_refuses_the_retained_fragment(self):
        values = scenario('pending_full')
        with self.assertRaises(LeaseEvidenceError):
            snapshot(values[2], fixture.DRIVE, fixture.INSTALLED, fixture.ROOT)
        self.assertIsNotNone(reconcile('pending_full', values)['retained_fragment'])

    def test_pending_shape_or_typed_size_cannot_be_relabelled(self):
        for mode in ('boolean_bytes', 'wrong_hash', 'extra_stream', 'parsed_fragment', 'extra_file', 'changed_original'):
            values = scenario('pending_middle')
            measured = values[1]
            row = measured[-1]
            if mode == 'boolean_bytes': row['bytes'] = True
            elif mode == 'wrong_hash': row['sha256'] = 'f' * 64
            elif mode == 'extra_stream': row['streams'].append(dict(name=':other:$DATA', size=0))
            elif mode == 'parsed_fragment': row['content_json'] = '{}'
            elif mode == 'extra_file': measured.append(dict(row, path=row['path'] + '-other'))
            else: measured[0]['file_id'] = '0000000000000001:' + 'd' * 32
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                reconcile('pending_middle', values)
        with self.assertRaises(LeaseEvidenceError):
            reconcile('pending_full', scenario('pending_middle'))

    def test_retry_must_retain_the_entire_measured_fragment_row(self):
        for member in ('file_id', 'raw_aces', 'streams', 'bytes'):
            values = scenario('pending_empty')
            row = values[2][-1]
            row[member] = [] if member in ('raw_aces', 'streams') else 'changed'
            with self.subTest(member=member), self.assertRaises(LeaseEvidenceError):
                reconcile('pending_empty', values)

    def test_absence_cannot_remove_unrelated_custody_or_use_wrong_closing_holder(self):
        for mode in ('extra_removed', 'closing_holder', 'fake_retained'):
            values = scenario('publication_absent')
            if mode == 'extra_removed': values[1].pop(0)
            elif mode == 'fake_retained':
                values[2].append(dict(values[2][0], path=fixture.CONTEXTS + '\\operation-' +
                    fixture.digest(fixture.INSTALLED['transaction_id']) + '-retained-g00000000000000000001', directory=True))
            else:
                row = next(row for row in values[2] if row['path'].endswith('-preserve-g00000000000000000001.json'))
                value = json.loads(row['content_json'])
                value['closing_ownership']['holder']['process_id'] += 1
                value['preservation_sha256'] = fixture.digest({key: item for key, item in value.items() if key != 'preservation_sha256'})
                row.update(fixture.record(row['path'], value))
            with self.subTest(mode=mode), self.assertRaises(LeaseEvidenceError):
                reconcile('publication_absent', values)

    def test_next_reservation_requires_both_original_process_loss_rows_and_holders(self):
        before, measured, after, holders, original_empty = scenario('next_reservation_absent')
        for changed_holders, changed_empty in ((holders[:1], original_empty),
                ([dict(holders[0], process_id=999), holders[1]], original_empty), (holders, None)):
            with self.assertRaises(LeaseEvidenceError):
                evidence.reconcile('next_reservation_absent', before, measured, after, fixture.DRIVE,
                    fixture.INSTALLED, fixture.ROOT, changed_holders, NAME, changed_empty)


if __name__ == '__main__':
    unittest.main()
