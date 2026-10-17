# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic closed-record controls, never Windows/profile qualification."""
import copy
import dataclasses
import hashlib
import struct
import unittest

from publication_authority_reference import PublicationModelContext
from publisher_creation_evidence import creation_graph
from publisher_execution_evidence import EvidenceError, canonical_sha
from publisher_native_profile_evidence import ROUTE, descriptor_facts, native_objects, project
from test_publisher_execution_evidence import SERVICE, SID, SDK, encode
from test_publisher_rename_evidence import rename_fixture

CLIENT = 'S-1-5-21-1-2-3-1001'
CONTEXT = PublicationModelContext(service_sid=SID, sdk_version=SDK, minimum_additional_ancestors=0,
    namespace_layout='staging_anchor_with_payload_child', security_observation_api='GetKernelObjectSecurity',
    provenance_profile='native_registered_controller_boundary', actor_profile='standard_and_filtered_same_account')
SOURCE = {'head': 'a' * 40, 'source_tree': 'b' * 40, 'reviewed_source_tree': 'b' * 40,
    'publisher_image_sha256': 'c' * 64, 'route': ROUTE, 'no_export_basis': 'reviewed_selected_route_source_argument'}


def descriptor(group):
    def sid_bytes(value):
        values = list(map(int, value.split('-')[1:]))
        return bytes((values[0], len(values) - 2)) + values[1].to_bytes(6, 'big') + struct.pack('<' + 'L' * (len(values) - 2), *values[2:])
    owner, group_bytes = sid_bytes('S-1-5-18'), sid_bytes(group)
    aces = [struct.pack('<BBHL', 0, 0, 8 + len(sid_bytes(value)), 0x1f01ff) + sid_bytes(value) for value in ('S-1-5-18', SID)]
    acl = struct.pack('<BBHHH', 2, 0, 8 + sum(map(len, aces)), 2, 0) + b''.join(aces)
    return (struct.pack('<BBHLLLL', 1, 0, 0x9004, 20, 20 + len(owner), 0, 20 + len(owner) + len(group_bytes)) +
        owner + group_bytes + acl).hex()


def profile_fixture():
    prepared, visible = rename_fixture()
    prepared['schema'] = visible['schema'] = 'usk.publisher.lab_phase_evidence.v7'
    anchors, tree = prepared['protected_anchors'], prepared['sealed_tree']
    objects = native_objects(anchors, tree)
    names = ['\\', r'\publication', r'\publication\staging', r'\publication\destination',
        r'\publication\state', r'\publication\journal', r'\publication\staging\candidate',
        r'\publication\staging\candidate\payload.bin']
    for obj, name in zip(objects, names):
        obj.update(native_name=name, owner_sid='S-1-5-18', dacl_protected=True,
            attributes=obj.get('attributes', 16), reparse_tag=0, link_count=1, case_sensitive=False,
            dacl_aces=[{'type': 0, 'flags': 0, 'access_mask': 0x1f01ff, 'sid': principal} for principal in ('S-1-5-18', SID)])
    tree.update(volume={'volume_label': 'FIXTURE', 'volume_information_serial': 0x1234, 'file_id_volume_serial': 0x1234,
        'filesystem_name': 'NTFS', 'maximum_component_length': 255, 'filesystem_flags': 0x200008b, 'remote_protocol_error': 87}, root_streams=[])
    tree['descendants'][0].update(size=3, sha256=hashlib.sha256(b'abc').hexdigest(),
        streams=[{'name': '::$DATA', 'size': 3, 'allocation_size': 4096}])
    visible['protected_anchors'] = copy.deepcopy(anchors)
    visible['visible_tree'] = copy.deepcopy(tree)
    visible['visible_tree']['root']['native_name'] = r'\publication\destination\visible'
    visible['visible_tree']['descendants'][0]['object']['native_name'] = r'\publication\destination\visible\payload.bin'
    for phase in prepared['execution_phases'] + visible['execution_phases']:
        execution = phase['execution']
        execution.update(schema='usk.publisher_execution_observation.v5',
            scope='supplied_held_service_handles_security_access_and_worker_security')
        phase_tree = visible['visible_tree'] if execution['phase'] == 'visible_bound' else tree
        for handle, obj in zip(execution['handles'], native_objects(anchors, phase_tree)):
            handle['object_observation'] = copy.deepcopy(obj)
        phase['protected_anchors_sha256'] = canonical_sha(anchors)
        phase['tree_sha256'] = canonical_sha(dict(phase_tree, descendants=[])
            if execution['phase'] == 'protected_empty' else phase_tree)
    prepared['creation_evidence']['created_graph_sha256'] = canonical_sha(creation_graph(anchors, tree))
    visible['prepared_record_sha256'] = hashlib.sha256(encode(prepared).encode()).hexdigest()
    from publisher_native_profile_evidence import MUTATION_RIGHTS
    access = {name: {'requested': mask, 'allowed': False, 'granted': 0}
        for name, mask in dict(MUTATION_RIGHTS, maximum_allowed=0x2000000).items()}
    rows, observations = [], []
    for index, obj in enumerate(objects):
        group = 'S-1-5-20' if index == 0 else 'S-1-5-18'
        directory = bool(obj['attributes'] & 16)
        rows.append({'file_id': obj['file_id'], 'effective_right_group_sid': group,
            'owner': obj['owner_sid'], 'protected': True, 'attributes': obj['attributes'],
            'link_count': 1, 'case_sensitive': False, 'directory': directory,
            'bytes': 0 if directory else 3, 'sha256': None if directory else tree['descendants'][0]['sha256'],
            'streams': [] if directory else copy.deepcopy(tree['descendants'][0]['streams']),
            'raw_aces': copy.deepcopy(obj['dacl_aces'])})
        terminal_name = obj['native_name'].replace(r'\staging\candidate', r'\destination\visible') if index >= 6 else obj['native_name']
        rows[-1].update(native_name=terminal_name, path='E:' + terminal_name)
        if index >= 6:
            rows[-1]['raw_aces'].append({'type': 0, 'flags': 0, 'access_mask': 0x1200a9, 'sid': CLIENT})
        observations.append({'native_object': copy.deepcopy(obj), 'observed_group_sid': group,
            'reconstructed_descriptor_hex': descriptor(group), 'checks': {actor: copy.deepcopy(access) for actor in ('initiating', 'filtered')}})
    snapshot = {'schema': 'usk.publisher.metadata_independent_readback.v1', 'identity': 'S-1-5-18',
        'observer_token_handles_closed': True, 'rows': rows[1:], 'volume_boundary': {'root': rows[0]},
        'effective_right_tokens': {actor: {'user_sid': CLIENT, 'token_type': 2} for actor in ('initiating', 'filtered')},
        'native_phase_descriptor_access': {'schema': 'usk.publisher.phase_descriptor_access.v1',
            'basis': 'native_closed_owner_dacl_with_independently_observed_group', 'live_phase_access_check': False,
            'prepared_record_sha256': hashlib.sha256(encode(prepared).encode()).hexdigest(), 'objects': observations}}
    return prepared, visible, snapshot


class NativeProfileEvidenceTests(unittest.TestCase):
    def check(self, prepared, visible, snapshot, context=CONTEXT, source=SOURCE):
        return project(encode(prepared), encode(visible) if visible is not None else None, snapshot, SERVICE, context, source)

    def test_complete_native_projection_keeps_actor_provenance_and_consumer_delta(self):
        report = self.check(*profile_fixture())
        self.assertEqual(report['model_result']['phase'], 'visible_bound')
        self.assertEqual(report['descriptor_objects_checked'], 8)
        self.assertEqual(report['terminal_consumer_delta_objects'], 2)
        self.assertEqual(report['actor_principals'], ['captured_standard_client', 'filtered_same_account'])
        self.assertFalse(report['profile_qualified'])
        self.assertFalse(report['live_phase_access_checks'])
        self.assertFalse(report['global_export_history_observed'])

    def test_unrelated_projection_consumes_owned_login_binding(self):
        from test_publisher_actor_evidence import fixture as actor_fixture
        prepared, visible, snapshot = profile_fixture()
        actors = actor_fixture()
        snapshot['effective_right_tokens'] = actors['effective_right_tokens']
        for actor in ('initiating', 'filtered'):
            snapshot['effective_right_tokens'][actor]['user_sid'] = CLIENT
        for row in snapshot['rows'] + [snapshot['volume_boundary']['root']]:
            row['effective_rights'] = copy.deepcopy(actors['rows'][0]['effective_rights'])
            row['raw_aces'] = row['raw_aces'][:2]
        for checked in snapshot['native_phase_descriptor_access']['objects']:
            checked['checks']['unrelated'] = copy.deepcopy(checked['checks']['filtered'])
        context = dataclasses.replace(CONTEXT, actor_profile='initiating_and_unrelated_login')
        report = self.check(prepared, visible, snapshot, context=context)
        self.assertEqual(report['actor_principals'], list(context.effective_access_principals))
        self.assertFalse(report['profile_qualified'])
        snapshot['effective_right_tokens']['unrelated_logon_context']['token_id'] = '0000000000000004'
        with self.assertRaises(ValueError):
            self.check(prepared, visible, snapshot, context=context)

    def test_historical_unavailable_projection_cannot_qualify_full_original_profile(self):
        prepared, visible, snapshot = profile_fixture()
        projection = snapshot['native_phase_descriptor_access']
        missing = projection['objects'].pop()
        projection.update(schema='usk.publisher.historical_phase_descriptor_access.v1',
                          availability='partial', unavailable_payload_objects=[dict(
                              native_object=missing['native_object'],
                              reason='original_payload_identity_not_in_current_snapshot')],
                          completed_maintenance_observation=dict(transaction_id='repair.current'))
        with self.assertRaises(ValueError):
            self.check(prepared, visible, snapshot)

    def test_reconstructed_access_refuses_every_mutation_and_nonempty_maximum(self):
        prepared, visible, snapshot = profile_fixture()
        for actor in ('initiating', 'filtered'):
            for name in snapshot['native_phase_descriptor_access']['objects'][0]['checks'][actor]:
                changed = copy.deepcopy(snapshot)
                changed['native_phase_descriptor_access']['objects'][0]['checks'][actor][name].update(allowed=True, granted=1)
                with self.subTest(actor=actor, right=name), self.assertRaises(EvidenceError):
                    self.check(prepared, visible, changed)

    def test_descriptor_group_id_basis_and_coverage_are_bound(self):
        prepared, visible, snapshot = profile_fixture()
        for field, value in [('observed_group_sid', 'S-1-5-18'), ('reconstructed_descriptor_hex', descriptor('S-1-5-18')),
                             ('native_object', snapshot['native_phase_descriptor_access']['objects'][1]['native_object'])]:
            changed = copy.deepcopy(snapshot)
            changed['native_phase_descriptor_access']['objects'][0][field] = value
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                self.check(prepared, visible, changed)
        for field, value in [('live_phase_access_check', True), ('basis', 'live_same_handle'), ('prepared_record_sha256', '0' * 64), ('objects', [])]:
            changed = copy.deepcopy(snapshot); changed['native_phase_descriptor_access'][field] = value
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                self.check(prepared, visible, changed)

    def test_terminal_content_and_exact_consumer_delta_refuse_changes(self):
        prepared, visible, snapshot = profile_fixture()
        for field, value in [('sha256', '0' * 64), ('bytes', 4), ('raw_aces', []), ('attributes', 16), ('link_count', True)]:
            changed = copy.deepcopy(snapshot); changed['rows'][-1][field] = value
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                self.check(prepared, visible, changed)
        changed = copy.deepcopy(snapshot); changed['rows'][-1]['raw_aces'][-1]['sid'] = 'S-1-5-21-1-2-3-1002'
        with self.assertRaises(EvidenceError):
            self.check(prepared, visible, changed)

    def test_exact_terminal_payload_namespace_refuses_extra_directory_or_moved_row(self):
        prepared, visible, snapshot = profile_fixture()
        changed = copy.deepcopy(snapshot)
        changed['rows'][-1].update(native_name=r'\publication\destination\visible\other.bin',
                                  path=r'E:\publication\destination\visible\other.bin')
        with self.assertRaises(EvidenceError):
            self.check(prepared, visible, changed)
        changed = copy.deepcopy(snapshot)
        extra = copy.deepcopy(changed['rows'][-1])
        extra.update(file_id='0000000000001234:' + '9' * 32, native_name=r'\publication\destination\visible\extra',
            path=r'E:\publication\destination\visible\extra', directory=True, attributes=16, bytes=0, sha256=None, streams=[])
        changed['rows'].append(extra)
        with self.assertRaises(EvidenceError):
            self.check(prepared, visible, changed)

    def test_fixture_context_and_wrong_reviewed_source_cannot_qualify_native_inputs(self):
        data = profile_fixture()
        with self.assertRaises(EvidenceError):
            self.check(*data, context=PublicationModelContext())
        for field, value in [('reviewed_source_tree', 'd' * 40), ('route', 'instrumented_fixture'), ('publisher_image_sha256', 'bad')]:
            changed = dict(SOURCE, **{field: value})
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                self.check(*data, source=changed)

    def test_reconstruction_parser_refuses_control_padding_and_sid_changes(self):
        raw = bytearray.fromhex(descriptor('S-1-5-20'))
        self.assertEqual(descriptor_facts(raw.hex())['group_sid'], 'S-1-5-20')
        for changed in (raw + b'\x00', raw[:3] + b'\x80' + raw[4:], raw[:20] + b'\x02' + raw[21:]):
            with self.assertRaises(EvidenceError):
                descriptor_facts(changed.hex())

    def test_restart_or_missing_call_remains_unknown_in_model(self):
        prepared, visible, snapshot = profile_fixture()
        visible['execution_transition'] = 'observed_visible_on_restart'
        visible['execution_phases'] = visible['execution_phases'][-1:]
        visible['rename_call'] = None
        execution = visible['execution_phases'][0]['execution']
        execution['service'].update(process_id=600, token_id=f'{600:016x}', modified_id=f'{601:016x}')
        execution['process_boundary']['process_id'] = 600
        execution['worker_security']['process_id'] = 600
        for key in ('token_id', 'modified_id'):
            execution['worker_security']['primary_token'][key] = execution['service'][key]
        report = self.check(prepared, visible, snapshot)
        self.assertEqual(report['model_result']['phase'], 'recovery_required')
        self.assertEqual(report['model_result']['rename_state'], 'unknown')
        self.assertEqual(report['execution_reconciliation']['native_rename_calls_checked'], 0)
