# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic contradiction controls, never native mutex qualification."""
import copy
import hashlib
import json
import unittest
from publisher_install_guard_evidence import inspection_reference, holder_binding, conflict_projection
from publisher_standard_public_evidence import StandardEvidenceError, canonical

VOLUME = r'\\?\Volume{12345678-1234-1234-1234-123456789abc}' + '\\'
INSTALL = 'install-A_01'


class InstallationGuardEvidenceTests(unittest.TestCase):
    def holder(self):
        reference = inspection_reference(VOLUME, INSTALL)
        ready = {'schema': 'usk.publisher_install_guard_holder.v1',
            'scope': 'owned_installation_mutex_only_no_product_effects', 'process_id': 1234,
            'creation_file_time': '134041540000000001', 'identity': 'S-1-5-18', 'install_id': INSTALL,
            'operation_inspection_ref': reference, 'publication_authority_granted': False,
            'service_sid': 'S-1-5-80-1-2-3-4-5', 'coordination_acl_scope': 'system_and_registered_service_sid_only',
            'coordination_security': {'schema': 'usk.publisher_install_guard_security.v1',
                'owner': 'S-1-5-18', 'dacl_protected': True,
                'aces': [{'sid': principal, 'mask': 0x001f0001, 'type': 0, 'flags': 0}
                    for principal in ('S-1-5-18', 'S-1-5-80-1-2-3-4-5')]}}
        raw = canonical(ready) + '\n'
        holder = {'native_ready': ready, 'native_ready_json': raw,
            'image_path': r'C:\build\Release\usk_publisher_install_guard_holder.exe',
            'image_sha256': 'a'*64, 'project_sha256': 'b'*64,
            'ready_sha256': hashlib.sha256(raw.encode()).hexdigest(),
            'parent_process_id': 4321, 'parent_creation_file_time': '134041540000000000',
            'volume_root': VOLUME, 'events_scope': 'unique_protected_system_only_ready_and_release',
            'alive_before_request': True, 'alive_after_response': True, 'alive_after_readback': True,
            'normal_release_confirmed': True, 'exit_code': 0}
        observation = {'service_sid': 'S-1-5-80-1-2-3-4-5', 'launcher_process': {'process_id': 4321,
            'creation_file_time': '134041540000000000', 'identity': 'S-1-5-18'}}
        return holder, observation

    def test_reference_names_installation_scope_and_canonical_volume(self):
        name = 'Global\\USK.Publisher.Install.12345678-1234-1234-1234-123456789abc.' + INSTALL.encode().hex()
        expected = 'usk.operation-inspection.v1:' + hashlib.sha256(json.dumps(name).encode()).hexdigest()
        self.assertEqual(inspection_reference(VOLUME, INSTALL), expected)
        self.assertEqual(inspection_reference(VOLUME.upper().replace('VOLUME', 'Volume'), INSTALL), expected)
        self.assertNotEqual(inspection_reference(VOLUME, 'install-B'), expected)
        for volume, install in [('C:/', INSTALL), (VOLUME, ''), (VOLUME, 'a'*129), (VOLUME, 'a/b')]:
            with self.subTest(volume=volume, install=install), self.assertRaises(StandardEvidenceError):
                inspection_reference(volume, install)

    def test_holder_requires_retained_liveness_and_normal_release(self):
        holder, observation = self.holder()
        holder_binding(holder, observation, VOLUME, INSTALL)
        for key, value in [('alive_before_request', False), ('alive_after_response', False),
            ('alive_after_readback', False), ('normal_release_confirmed', False), ('exit_code', 1),
            ('exit_code', False), ('parent_process_id', 9999), ('parent_creation_file_time', '134041540000000099'),
            ('volume_root', VOLUME.replace('12345678', '87654321')), ('image_path', r'C:\other.exe'),
            ('events_scope', 'shared_events'), ('ready_sha256', '0'*64), ('extra', False)]:
            changed = copy.deepcopy(holder); changed[key] = value
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                holder_binding(changed, observation, VOLUME, INSTALL)

    def test_native_readiness_cannot_substitute_identity_scope_or_authority(self):
        holder, observation = self.holder()
        for key, value in [('identity', 'S-1-5-32-544'), ('install_id', 'other-install'),
            ('operation_inspection_ref', 'usk.operation-inspection.v1:'+'0'*64),
            ('publication_authority_granted', True), ('process_id', True), ('creation_file_time', '123'),
            ('scope', 'volume_guard'), ('service_sid', 'S-1-5-18'),
            ('coordination_acl_scope', 'default_system_dacl'), ('extra', False)]:
            changed = copy.deepcopy(holder); changed['native_ready'][key] = value
            raw = canonical(changed['native_ready'])+'\n'
            changed['native_ready_json'] = raw; changed['ready_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                holder_binding(changed, observation, VOLUME, INSTALL)

    def projection(self):
        reference = inspection_reference(VOLUME, INSTALL)
        native = {'schema': 'usk.publisher_lab_service_observation.v1', 'status': 'failed',
            'error': 'publisher installation operation is active', 'error_code': 'operation_conflict',
            'operation_inspection_ref': reference, 'process_id': 2345, 'registered_admission': {}}
        response = {'schema': 'usk.oneshot_response.v1', 'request_id': 'public.case', 'status': 'refused',
            'error': {'code': 'operation_conflict'}, 'result': {'schema': 'usk.publisher_operation_diagnostic.v1',
                'error_code': 'operation_conflict', 'inspection_reference': reference}}
        return native, response, reference

    def test_coordination_descriptor_requires_exact_protected_service_grant(self):
        holder, observation = self.holder()
        for key, value in [('owner', 'S-1-5-32-544'), ('dacl_protected', False),
            ('aces', [{'sid': 'S-1-1-0', 'mask': 0x001f0001, 'type': 0, 'flags': 0}]),
            ('extra', False)]:
            changed = copy.deepcopy(holder); changed['native_ready']['coordination_security'][key] = value
            raw = canonical(changed['native_ready'])+'\n'
            changed['native_ready_json'] = raw; changed['ready_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                holder_binding(changed, observation, VOLUME, INSTALL)
        changed = copy.deepcopy(holder)
        changed['native_ready']['coordination_security']['aces'][0]['flags'] = False
        raw = canonical(changed['native_ready'])+'\n'
        changed['native_ready_json'] = raw; changed['ready_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
        with self.assertRaises(StandardEvidenceError):
            holder_binding(changed, observation, VOLUME, INSTALL)

    def test_public_projection_requires_actual_native_failed_conflict(self):
        native, response, reference = self.projection()
        conflict_projection(native, response, 'public.case', reference)
        for key, value in [('status', 'recovery_required'), ('status', 'unknown'), ('error_code', 'publisher_failed'),
            ('operation_inspection_ref', 'usk.operation-inspection.v1:'+'0'*64),
            ('extra', False)]:
            changed = copy.deepcopy(native); changed[key] = value
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                conflict_projection(changed, response, 'public.case', reference)

    def test_public_response_cannot_promote_hide_or_retarget_conflict(self):
        native, response, reference = self.projection()
        for key, value in [('status', 'ok'), ('status', 'unknown'), ('request_id', 'other'),
            ('result', None), ('error', {'code': 'operation_cancelled'}), ('extra', False)]:
            changed = copy.deepcopy(response); changed[key] = value
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                conflict_projection(native, changed, 'public.case', reference)
        changed = copy.deepcopy(response)
        changed['result']['inspection_reference'] = 'usk.operation-inspection.v1:'+'0'*64
        with self.assertRaises(StandardEvidenceError):
            conflict_projection(native, changed, 'public.case', reference)


if __name__ == '__main__':
    unittest.main()
