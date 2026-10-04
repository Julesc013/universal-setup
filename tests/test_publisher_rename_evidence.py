# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Closed-record controls; these do not qualify Windows rename execution."""
import copy
import hashlib
import unittest

from publisher_execution_evidence import EvidenceError, RENAME_SCHEMA, canonical_sha, reconcile
from test_publisher_creation_evidence import creation_fixture
from test_publisher_execution_evidence import BUILD, SDK, SERVICE, SID, encode


def rename_fixture():
    prepared, visible = creation_fixture()
    prepared['schema'] = visible['schema'] = RENAME_SCHEMA
    prepared['sealed_tree']['root']['native_name'] = r'\publication\staging\candidate'
    visible['visible_tree']['root']['native_name'] = r'\publication\destination\visible'
    for phase in prepared['execution_phases'] + visible['execution_phases']:
        name = phase['execution']['phase']
        tree = visible['visible_tree'] if name == 'visible_bound' else prepared['sealed_tree']
        if name == 'protected_empty':
            tree = dict(tree, descendants=[])
        phase['tree_sha256'] = canonical_sha(tree)
    name_bytes = len(prepared['destination_name'].encode('utf-16-le'))
    visible['rename_call'] = {'schema': 'usk.publisher_bound_rename_call.v1', 'api': 'NtSetInformationFile',
        'source_file_id': prepared['source_file_id'], 'destination_parent_file_id': prepared['destination_parent_file_id'],
        'destination_component': prepared['destination_name'], 'former_name': prepared['sealed_tree']['root']['native_name'],
        'visible_name': visible['visible_tree']['root']['native_name'], 'destination_absence_status': 0xc0000034,
        'information_class': 10, 'information_bytes': 24 + name_bytes, 'file_name_bytes': name_bytes,
        'replace_if_exists': False, 'native_status': 0, 'io_status': 0, 'clock': 'qpc',
        'start_tick': 100, 'end_tick': 110, 'frequency': 10000000}
    return prepared, visible


class RenameEvidenceTests(unittest.TestCase):
    def check(self, prepared, visible):
        if visible is not None:
            visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
        return reconcile(encode(prepared), None if visible is None else encode(visible), SERVICE, SID, BUILD, SDK)

    def test_measured_call_and_absent_visible_record(self):
        prepared, visible = rename_fixture()
        report = self.check(prepared, visible)
        self.assertEqual(report['native_rename_calls_checked'], 1)
        self.assertIs(report['profile_qualified'], False)
        self.assertEqual(self.check(prepared, None)['native_rename_calls_checked'], 0)

    def test_bound_arguments_and_outcomes_refuse_contradictions(self):
        prepared, visible = rename_fixture()
        for key, value in {'source_file_id': 'wrong', 'destination_parent_file_id': 'wrong',
            'destination_component': 'other', 'former_name': 'other', 'visible_name': 'other',
            'destination_absence_status': 0, 'information_class': 11, 'information_bytes': 1,
            'file_name_bytes': 1, 'replace_if_exists': True, 'native_status': 1, 'io_status': 1,
            'clock': 'other', 'end_tick': 99, 'frequency': 0, 'start_tick': 0}.items():
            changed = copy.deepcopy(visible)
            changed['rename_call'][key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                self.check(prepared, changed)

    def test_closed_fields_and_numeric_types(self):
        prepared, visible = rename_fixture()
        changes = [('rename_call', None), ('native_status', False), ('replace_if_exists', 0),
            ('information_class', True), ('start_tick', 1 << 63), ('io_status', -1)]
        for key, value in changes:
            changed = copy.deepcopy(visible)
            if key == 'rename_call':
                del changed[key]
            else:
                changed['rename_call'][key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                self.check(prepared, changed)

    def test_restart_keeps_prior_call_unobserved(self):
        prepared, visible = rename_fixture()
        visible['execution_transition'] = 'observed_visible_on_restart'
        visible['execution_phases'] = visible['execution_phases'][-1:]
        with self.assertRaises(EvidenceError):
            self.check(prepared, visible)
        visible['rename_call'] = None
        self.assertEqual(self.check(prepared, visible)['native_rename_calls_checked'], 0)
