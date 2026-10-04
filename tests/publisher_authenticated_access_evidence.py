# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent bounded decoding of retained authenticated phase AccessCheck facts.

This checks bindings and representation. JSON cannot authenticate a token or
grant publication authority. Stored protection facts and GetSecurityInfo's
returned control flags remain separate observations.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from publisher_execution_evidence import sid

RIGHTS = {'write_or_add_file': 2, 'append_or_add_directory': 4, 'write_ea': 16,
          'delete_child': 64, 'write_attributes': 256, 'delete': 65536,
          'write_dac': 262144, 'write_owner': 524288, 'maximum_allowed': 0x02000000}
MUTATION_MASK = sum(value for key, value in RIGHTS.items() if key != 'maximum_allowed')
CLIENT_KEYS = {'schema', 'scope', 'captured_process_id', 'user_sid', 'token_type',
               'impersonation_level', 'token_id', 'authentication_id', 'modified_id',
               'groups', 'restricted_sids', 'privileges'}
ACCESS_KEYS = {'schema', 'scope', 'client_sha256', 'native_object_sha256',
               'descriptor_api', 'descriptor_hex', 'observed_group_sid', 'checks'}
OPERATION_KEYS = {'schema', 'scope', 'route', 'service_name', 'service_sid', 'service_process_id',
    'configured_caller_sid', 'authenticated_client_sha256', 'captured_client_process_id', 'registration_sha256',
    'target_admitted_sha256', 'publisher_image_sha256', 'volume_guid_root', 'root_file_id', 'volume_serial',
    'reviewed_plan_digest', 'reviewed_plan_snapshot_sha256', 'transaction_id'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def closed(value, keys, message):
    require(isinstance(value, dict) and set(value) == set(keys), message)


def integer(value, minimum=0, maximum=0xffffffff):
    return type(value) is int and minimum <= value <= maximum


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                   ensure_ascii=False).encode('utf-8')).hexdigest()


def validate_client(client):
    closed(client, CLIENT_KEYS, 'authenticated client keys differ')
    require(client['schema'] == 'usk.publisher_authenticated_client_observation.v1' and
            client['scope'] == 'held_authenticated_identification_token' and
            integer(client['captured_process_id'], 1) and sid(client['user_sid']) and
            integer(client['token_type'], 2, 2) and integer(client['impersonation_level'], 1, 3) and
            all(integer(client[key], 1, 0xffffffffffffffff) for key in
                ('token_id', 'authentication_id', 'modified_id')), 'authenticated client scope or identity differs')
    for key in ('groups', 'restricted_sids'):
        groups = client[key]
        require(isinstance(groups, list) and len(groups) <= 1024, 'authenticated token group bound differs')
        seen = set()
        for group in groups:
            closed(group, {'sid', 'attributes'}, 'authenticated token group keys differ')
            require(sid(group['sid']) and group['sid'] not in seen and integer(group['attributes']),
                    'authenticated token group identity or attributes differ')
            seen.add(group['sid'])
    privileges = client['privileges']
    require(isinstance(privileges, list) and len(privileges) <= 256, 'authenticated privilege bound differs')
    seen = set()
    for privilege in privileges:
        closed(privilege, {'luid', 'attributes'}, 'authenticated privilege keys differ')
        require(integer(privilege['luid'], 1, 0xffffffffffffffff) and privilege['luid'] not in seen and
                integer(privilege['attributes']), 'authenticated privilege identity or attributes differ')
        seen.add(privilege['luid'])


def reconcile_client_capture(client, capture):
    """Bind stable account/session facts, not primary/impersonation token IDs."""
    validate_client(client)
    primary = capture['primary_token']
    require(capture['captured_before_primary_thread_resume'] is True and
            integer(capture['process_id'], 1) and capture['process_id'] == client['captured_process_id'] and
            primary['token_type'] == 1 and primary['user_sid'] == client['user_sid'] and
            isinstance(primary['authentication_id'], str) and
            re.fullmatch(r'[0-9a-f]{16}', primary['authentication_id']) and
            int(primary['authentication_id'], 16) == client['authentication_id'] and
            sorted(primary['groups'], key=lambda group: group['sid']) ==
            sorted(client['groups'], key=lambda group: group['sid']),
            'authenticated client differs from the independently captured primary account/session')
    return {'process_id': client['captured_process_id'], 'user_sid': client['user_sid'],
            'authentication_id': client['authentication_id'], 'scope': 'account_session_and_captured_pipe_pid'}


def validate_operation_admission(prepared):
    """Retained bindings only; a null private legacy record has no route admission."""
    admission = prepared['operation_admission']
    if admission is None:
        return False
    closed(admission, OPERATION_KEYS, 'registered operation admission keys differ')
    execution = prepared['execution_phases'][0]['execution']
    client, service = execution['authenticated_client'], execution['service']
    source, anchors = prepared['source_binding'], prepared['protected_anchors']
    require(admission['schema'] == 'usk.publisher_operation_admission.v1' and
        admission['scope'] == 'live_registered_request_and_held_volume_before_effects' and
        admission['route'] == 'registered_service_admitted_production' and
        admission['service_name'] == service['service_name'] and admission['service_sid'] == prepared['service_sid'] and
        integer(admission['service_process_id'], 1) and admission['service_process_id'] == service['process_id'] and
        admission['configured_caller_sid'] == client['user_sid'] and
        integer(admission['captured_client_process_id'], 1) and
        admission['captured_client_process_id'] == client['captured_process_id'] and
        admission['authenticated_client_sha256'] == canonical_sha(client) and
        admission['root_file_id'] == anchors['boundary']['file_id'] and
        integer(admission['volume_serial'], 0, 0xffffffffffffffff) and admission['volume_serial'] == prepared['volume_serial'] and
        admission['reviewed_plan_digest'] == source['reviewed_plan_digest'] and
        admission['reviewed_plan_snapshot_sha256'] == source['reviewed_plan_snapshot_sha256'] and
        isinstance(admission['transaction_id'], str) and
        re.fullmatch(r'[A-Za-z0-9._-]{1,128}', admission['transaction_id']),
        'registered operation admission differs from native phase, target or reviewed source')
    require(all(isinstance(admission[key], str) and re.fullmatch(r'[0-9a-f]{64}', admission[key]) for key in
                ('registration_sha256', 'target_admitted_sha256', 'publisher_image_sha256')) and
        isinstance(admission['volume_guid_root'], str) and re.fullmatch(
            r'\\\\\?\\Volume\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\\', admission['volume_guid_root']),
        'registered operation admission provenance or volume GUID differs')
    return True


def reconcile_registered_operation(prepared, native_registration):
    require(validate_operation_admission(prepared), 'registered public path cannot promote null private admission')
    admission, target = prepared['operation_admission'], native_registration['target_identity']['volume_identity']
    expected = {'service_name': native_registration['service_name'], 'service_sid': native_registration['service_sid'],
        'service_process_id': native_registration['process_id'],
        'configured_caller_sid': native_registration['configured_caller_sid'],
        'registration_sha256': native_registration['registration_sha256'],
        'target_admitted_sha256': native_registration['target_admitted_sha256'],
        'publisher_image_sha256': native_registration['publisher_image']['sha256'],
        'volume_guid_root': target['volume_root'], 'root_file_id': target['root_file_id'], 'volume_serial': target['volume_serial']}
    require(all(admission[key] == value for key, value in expected.items()),
            'public operation admission differs from independently retained native registration')
    return expected


def descriptor_facts(encoded):
    require(isinstance(encoded, str) and re.fullmatch(r'(?:[0-9a-f]{2}){20,65536}', encoded),
            'authenticated descriptor is not bounded canonical hex')
    raw = bytes.fromhex(encoded)
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from('<BBHLLLL', raw)
    require(revision == 1 and reserved == 0 and control & 0x8004 == 0x8004 and sacl == 0,
            'authenticated descriptor header differs')

    def read_sid(offset, end):
        require(20 <= offset <= end - 8 and offset % 4 == 0, 'authenticated SID offset differs')
        version, count = raw[offset:offset + 2]
        size = 8 + 4 * count
        require(version == 1 and count <= 15 and size <= end - offset, 'authenticated SID shape differs')
        authority = int.from_bytes(raw[offset + 2:offset + 8], 'big')
        parts = struct.unpack_from('<' + 'L' * count, raw, offset + 8)
        return 'S-1-' + str(authority) + ''.join('-' + str(part) for part in parts)

    owner_sid, group_sid = read_sid(owner, len(raw)), read_sid(group, len(raw))
    require(20 <= dacl <= len(raw) - 8 and dacl % 4 == 0, 'authenticated ACL offset differs')
    version, reserved, size, count, reserved2 = struct.unpack_from('<BBHHH', raw, dacl)
    require(version in (2, 4) and reserved == reserved2 == 0 and 8 <= size <= len(raw) - dacl and
            size % 4 == 0 and count <= (size - 8) // 16, 'authenticated ACL header differs')
    end, cursor, aces = dacl + size, dacl + 8, []
    for _ in range(count):
        require(cursor <= end - 16, 'authenticated ACE is truncated')
        kind, flags, size, mask = struct.unpack_from('<BBHL', raw, cursor)
        require(kind == 0 and size >= 16 and size % 4 == 0 and size <= end - cursor,
                'authenticated ACE format differs')
        aces.append({'type': kind, 'flags': flags, 'access_mask': mask,
                     'sid': read_sid(cursor + 8, cursor + size)})
        cursor += size
    require(cursor == end, 'authenticated ACL has unaccounted bytes')
    return {'owner_sid': owner_sid, 'group_sid': group_sid, 'api_control': control, 'dacl_aces': aces}


def validate_access(access, client, obj, *, deny_mutation=True):
    validate_client(client)
    closed(access, ACCESS_KEYS, 'authenticated access keys differ')
    require(access['schema'] == 'usk.publisher_authenticated_object_access.v1' and
            access['scope'] == 'fresh_held_authenticated_token_and_file_descriptor' and
            access['client_sha256'] == canonical_sha(client) and access['native_object_sha256'] == canonical_sha(obj) and
            access['descriptor_api'] == 'GetSecurityInfo:SE_FILE_OBJECT:OWNER_GROUP_DACL' and
            sid(access['observed_group_sid']), 'authenticated access scope, API or binding differs')
    facts = descriptor_facts(access['descriptor_hex'])
    require(facts['owner_sid'] == obj['owner_sid'] and facts['group_sid'] == access['observed_group_sid'] and
            facts['dacl_aces'] == obj['dacl_aces'], 'authenticated descriptor owner/group/ordered ACE facts differ')
    closed(access['checks'], RIGHTS, 'authenticated access request closure differs')
    for name, requested in RIGHTS.items():
        check = access['checks'][name]
        closed(check, {'requested', 'allowed', 'granted'}, 'authenticated AccessCheck keys differ')
        require(integer(check['requested'], requested, requested) and type(check['allowed']) is bool and
                integer(check['granted']) and check['granted'] & ~0x1f01ff == 0 and
                check['allowed'] == (check['granted'] != 0) and
                (name == 'maximum_allowed' or check['granted'] == (requested if check['allowed'] else 0)),
                'authenticated AccessCheck request or result differs')
        if deny_mutation:
            require(check['granted'] & MUTATION_MASK == 0 if name == 'maximum_allowed' else
                    check['allowed'] is False and check['granted'] == 0,
                    'authenticated caller retains mutation access to the protected role')
    return facts
