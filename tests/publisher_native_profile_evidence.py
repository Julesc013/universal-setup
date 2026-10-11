# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Retrospective native-record/model consistency; never publication authority.

AccessCheck results concern reconstructed closed owner/DACL facts with a
separately observed group. They are not live checks in earlier phases. The
reviewed route argument is source evidence, not global capability history.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct

import publication_authority_reference as model
from publisher_execution_evidence import canonical_sha, closed, integer, load_json, reconcile, require, sid


ATTRIBUTE_BITS = {1: 'READONLY', 2: 'HIDDEN', 4: 'SYSTEM', 16: 'DIRECTORY', 32: 'ARCHIVE',
    128: 'NORMAL', 256: 'TEMPORARY', 512: 'SPARSE_FILE', 1024: 'REPARSE_POINT',
    2048: 'COMPRESSED', 4096: 'OFFLINE', 8192: 'NOT_CONTENT_INDEXED', 16384: 'ENCRYPTED'}
OBJECT_KEYS = frozenset({'file_id', 'native_name', 'owner_sid', 'dacl_protected', 'attributes',
    'reparse_tag', 'link_count', 'case_sensitive', 'dacl_aces'})
MUTATION_RIGHTS = {'write_or_add_file': 2, 'append_or_add_directory': 4, 'write_ea': 16,
    'delete_child': 64, 'write_attributes': 256, 'delete': 65536, 'write_dac': 262144, 'write_owner': 524288}
SOURCE_KEYS = frozenset({'head', 'source_tree', 'reviewed_source_tree', 'publisher_image_sha256', 'route', 'no_export_basis'})
ROUTE = 'registered_service_admitted_production'


def descriptor_facts(hex_bytes):
    """Decode only the exact bounded reconstruction format, not arbitrary SDs."""
    require(isinstance(hex_bytes, str) and re.fullmatch(r'(?:[0-9a-f]{2}){20,65536}', hex_bytes),
            'reconstructed descriptor bytes are not bounded canonical hex')
    raw = bytes.fromhex(hex_bytes)
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from('<BBHLLLL', raw)
    require((revision, reserved, control, sacl) == (1, 0, 0x9004, 0),
            'reconstructed descriptor control differs')

    def read_sid(offset, end):
        require(20 <= offset <= end - 8, 'reconstructed SID offset differs')
        version, count = raw[offset:offset + 2]
        size = 8 + 4 * count
        require(version == 1 and 1 <= count <= 15 and offset + size <= end, 'reconstructed SID shape differs')
        authority = int.from_bytes(raw[offset + 2:offset + 8], 'big')
        parts = struct.unpack_from('<' + 'L' * count, raw, offset + 8)
        return 'S-1-' + str(authority) + '-' + '-'.join(map(str, parts)), size

    owner_sid, owner_size = read_sid(owner, len(raw))
    group_sid, group_size = read_sid(group, len(raw))
    require(20 <= dacl <= len(raw) - 8, 'reconstructed ACL offset differs')
    version, reserved, size, count, reserved2 = struct.unpack_from('<BBHHH', raw, dacl)
    end = dacl + size
    require((version, reserved, count, reserved2) == (2, 0, 2, 0) and size >= 8 and end <= len(raw),
            'reconstructed ACL header differs')
    cursor, aces = dacl + 8, []
    for _ in range(count):
        require(cursor <= end - 8, 'reconstructed ACE is truncated')
        kind, flags, size, mask = struct.unpack_from('<BBHL', raw, cursor)
        require(kind == flags == 0 and mask == 0x1f01ff and size >= 16 and cursor + size <= end,
                'reconstructed ACE policy differs')
        principal, sid_size = read_sid(cursor + 8, cursor + size)
        require(size == 8 + sid_size, 'reconstructed ACE size differs')
        aces.append({'type': kind, 'flags': flags, 'access_mask': mask, 'sid': principal})
        cursor += size
    segments = sorted(((owner, owner + owner_size), (group, group + group_size), (dacl, end)))
    require(cursor == end and segments[0][0] == 20 and segments[-1][1] == len(raw) and
            all(a[1] == b[0] for a, b in zip(segments, segments[1:])),
            'reconstructed descriptor overlaps or has unbound bytes')
    return {'owner_sid': owner_sid, 'group_sid': group_sid, 'dacl_protected': True, 'dacl_aces': aces}


def native_objects(anchors, tree):
    require(len(anchors['chain']) == 1 and anchors['chain'][0]['component'] == 'publication',
            'native profile namespace chain differs')
    return [anchors['boundary'], anchors['chain'][0]['object'], anchors['staging'],
        anchors['destination_parent'], anchors['state'], anchors['journal'], tree['root']] + \
        [entry['object'] for entry in tree['descendants']]


def validate_object(obj, service_sid):
    closed(obj, OBJECT_KEYS, 'native profile object keys differ')
    require(isinstance(obj['file_id'], str) and model.FILE_ID_RE.fullmatch(obj['file_id']) and
        isinstance(obj['native_name'], str) and obj['native_name'].startswith('\\') and
        obj['owner_sid'] == 'S-1-5-18' and obj['dacl_protected'] is True and
        integer(obj['attributes']) and not obj['attributes'] & ~sum(ATTRIBUTE_BITS) and
        not obj['attributes'] & 0x400 and integer(obj['reparse_tag']) and obj['reparse_tag'] == 0 and
        integer(obj['link_count']) and obj['link_count'] == 1 and obj['case_sensitive'] is False,
        'native profile object policy differs')
    require(isinstance(obj['dacl_aces'], list) and len(obj['dacl_aces']) == 2, 'native profile ACE count differs')
    for ace, principal in zip(obj['dacl_aces'], ('S-1-5-18', service_sid)):
        closed(ace, frozenset({'type', 'flags', 'access_mask', 'sid'}), 'native profile ACE keys differ')
        require(all(integer(ace[key]) for key in ('type', 'flags', 'access_mask')) and
            ace == {'type': 0, 'flags': 0, 'access_mask': 0x1f01ff, 'sid': principal},
            'native profile ACE differs')


def access_security(obj, checked, observed, context):
    validate_object(obj, context.service_sid)
    closed(checked, frozenset({'native_object', 'observed_group_sid', 'reconstructed_descriptor_hex', 'checks'}),
           'phase descriptor access object keys differ')
    require(checked['native_object'] == obj and sid(checked['observed_group_sid']) and
        checked['observed_group_sid'] == observed['effective_right_group_sid'] and
        observed['file_id'] == obj['file_id'], 'phase descriptor identity/group binding differs')
    facts = descriptor_facts(checked['reconstructed_descriptor_hex'])
    require(facts == {'owner_sid': obj['owner_sid'], 'group_sid': checked['observed_group_sid'],
        'dacl_protected': obj['dacl_protected'], 'dacl_aces': obj['dacl_aces']},
        'reconstructed descriptor differs from native owner/DACL and observed group')
    actors = ('initiating', 'filtered') if context.actor_profile == 'standard_and_filtered_same_account' else ('initiating', 'unrelated')
    require(isinstance(checked['checks'], dict) and set(actors) <= checked['checks'].keys() <=
        {'initiating', 'filtered', 'unrelated'}, 'phase descriptor actor set differs')
    for actor in actors:
        checks = checked['checks'][actor]
        closed(checks, frozenset(MUTATION_RIGHTS) | {'maximum_allowed'}, 'phase access right set differs')
        for name, requested in dict(MUTATION_RIGHTS, maximum_allowed=0x2000000).items():
            value = checks[name]
            closed(value, frozenset({'requested', 'allowed', 'granted'}), 'phase access check keys differ')
            require(integer(value['requested']) and value['requested'] == requested and
                isinstance(value['allowed'], bool) and integer(value['granted']) and value['granted'] == 0 and
                (name == 'maximum_allowed' or value['allowed'] is False), 'phase access check permits access or has wrong types')
    security = {'owner_sid': obj['owner_sid'], 'dacl_protected': obj['dacl_protected'],
        'inherited_aces': [], 'other_aces': [], 'dacl_aces': [
            {'principal': ace['sid'], 'type': 'allow', 'rights': list(model.FULL_CONTROL)} for ace in obj['dacl_aces']],
        'effective_access': [{'principal': principal, 'rights': []} for principal in context.effective_access_principals]}
    security['canonical_descriptor_sha256'] = canonical_sha(security)
    model.SecurityEvidence.parse(security, context.service_sid, context.effective_access_principals)
    return security


def project(prepared_json, visible_json, snapshot, service_name, context, source_provenance):
    """Project a complete current record set and replay its bounded native trace.

    The caller separately verifies transport, actual tokens, build/image and
    controller target admission. Source provenance is an independently pinned
    review input; this function cannot perform a historical export census.
    """
    require(context.provenance_profile == 'native_registered_controller_boundary', 'native model context is not independently pinned')
    closed(source_provenance, SOURCE_KEYS, 'native source provenance keys differ')
    require(all(isinstance(source_provenance[key], str) and re.fullmatch('[0-9a-f]{40}', source_provenance[key])
        for key in ('head', 'source_tree', 'reviewed_source_tree')) and
        source_provenance['source_tree'] == source_provenance['reviewed_source_tree'] and
        isinstance(source_provenance['publisher_image_sha256'], str) and
        model.SHA256_RE.fullmatch(source_provenance['publisher_image_sha256']) and
        source_provenance['route'] == ROUTE and
        source_provenance['no_export_basis'] == 'reviewed_selected_route_source_argument', 'native source review/image binding differs')
    prepared, visible = load_json(prepared_json), load_json(visible_json) if visible_json is not None else None
    require(prepared['schema'] in ('usk.publisher.lab_phase_evidence.v7', 'usk.publisher.lab_phase_evidence.v8', 'usk.publisher.lab_phase_evidence.v9'),
            'native profile projection requires current same-handle metadata')
    first_execution = prepared['execution_phases'][0]['execution']
    execution_report = reconcile(prepared_json, visible_json, service_name, context.service_sid,
        first_execution['platform']['windows_build'], context.sdk_version)
    require(snapshot['schema'] == 'usk.publisher.metadata_independent_readback.v1' and
        snapshot['identity'] == 'S-1-5-18' and snapshot['observer_token_handles_closed'] is True,
        'native profile independent observer scope differs')
    checked = snapshot['native_phase_descriptor_access']
    closed(checked, frozenset({'schema', 'basis', 'live_phase_access_check', 'prepared_record_sha256', 'objects'}),
           'native phase descriptor access keys differ')
    require(checked['schema'] == 'usk.publisher.phase_descriptor_access.v1' and
        checked['basis'] == 'native_closed_owner_dacl_with_independently_observed_group' and
        checked['live_phase_access_check'] is False and
        checked['prepared_record_sha256'] == hashlib.sha256(prepared_json.encode('utf-8')).hexdigest(),
        'native phase descriptor access basis/binding differs')
    anchors, sealed = prepared['protected_anchors'], prepared['sealed_tree']
    objects = native_objects(anchors, sealed)
    require(isinstance(checked['objects'], list) and len(checked['objects']) == len(objects) <= 10000,
        'native phase descriptor coverage differs')
    rows = list(snapshot['rows']) + [snapshot['volume_boundary']['root']]
    require(len({row['file_id'] for row in rows}) == len(rows), 'native independent object identities alias')
    by_id = {row['file_id']: row for row in rows}
    tokens = snapshot['effective_right_tokens']
    require(tokens['initiating']['token_type'] == tokens['filtered']['token_type'] == 2 and
        sid(tokens['initiating']['user_sid']) and
        tokens['initiating']['user_sid'] == tokens['filtered']['user_sid'],
        'native access token/account binding differs')
    if context.actor_profile == 'initiating_and_unrelated_login':
        from publisher_actor_evidence import reconcile_unrelated_login
        reconcile_unrelated_login(snapshot, context.service_sid)
    checks = {value['native_object']['file_id']: value for value in checked['objects']}
    require(len(checks) == len(objects) and set(checks) == {obj['file_id'] for obj in objects},
        'native phase descriptor identities alias or omit objects')
    security = {obj['file_id']: access_security(obj, checks[obj['file_id']], by_id[obj['file_id']], context) for obj in objects}
    payload_ids = {sealed['root']['file_id']} | {entry['object']['file_id'] for entry in sealed['descendants']}
    drive = snapshot['volume_boundary']['root']['path']
    require(isinstance(drive, str) and re.fullmatch(r'[A-Z]:\\', drive), 'independent volume drive root differs')
    payload_name = by_id[sealed['root']['file_id']]['native_name']
    allowed_names = (visible['visible_tree']['root']['native_name'],) if visible is not None else (
        sealed['root']['native_name'], anchors['destination_parent']['native_name'] + '\\' + prepared['destination_name'])
    require(payload_name in allowed_names and
        {row['file_id'] for row in rows if row['native_name'] == payload_name or
         row['native_name'].startswith(payload_name + '\\')} == payload_ids,
        'independent payload namespace has extra, missing or misplaced objects')
    expected_names = {obj['file_id']: obj['native_name'] for obj in objects[:6]}
    expected_names[sealed['root']['file_id']] = payload_name
    for item in sealed['descendants']:
        relative = item['relative_path'].replace('\\', '/')
        model._validate_relative_path(relative)
        require(item['object']['native_name'] == sealed['root']['native_name'] + '\\' + relative.replace('/', '\\'),
                'sealed native descendant namespace differs')
        expected_names[item['object']['file_id']] = payload_name + '\\' + relative.replace('/', '\\')
    consumer_delta_count = 0
    for obj in objects:
        observed = by_id[obj['file_id']]
        require(observed['native_name'] == expected_names[obj['file_id']] and
            observed['path'] == drive.rstrip('\\') + observed['native_name'] and
            observed['owner'] == obj['owner_sid'] and observed['protected'] is True and
            integer(observed['attributes']) and observed['attributes'] == obj['attributes'] and
            integer(observed['link_count']) and observed['link_count'] == obj['link_count'] and
            observed['case_sensitive'] is False and isinstance(observed['directory'], bool) and
            observed['directory'] == bool(obj['attributes'] & 16),
            'independent terminal object metadata differs from the native phase')
        require(isinstance(observed['raw_aces'], list), 'independent terminal ACE set differs')
        for ace in observed['raw_aces']:
            closed(ace, frozenset({'type', 'flags', 'access_mask', 'sid'}), 'independent terminal ACE keys differ')
            require(all(integer(ace[key]) for key in ('type', 'flags', 'access_mask')), 'independent terminal ACE types differ')
        expected = obj['dacl_aces']
        if observed['raw_aces'] != expected:
            require(obj['file_id'] in payload_ids and context.actor_profile == 'standard_and_filtered_same_account' and
                observed['raw_aces'] == expected + [{'type': 0, 'flags': 0, 'access_mask': 0x1200a9,
                    'sid': tokens['initiating']['user_sid']}], 'terminal consumer descriptor is not the exact admitted RX delta')
            consumer_delta_count += 1
    require(consumer_delta_count in (0, len(payload_ids)), 'terminal consumer grant is incomplete')

    def observation(phase, native_anchors, native_tree):
        volume = native_tree['volume']
        closed(volume, frozenset({'volume_label', 'volume_information_serial', 'file_id_volume_serial',
            'filesystem_name', 'maximum_component_length', 'filesystem_flags', 'remote_protocol_error'}),
            'native volume fact set differs')
        require(all(integer(volume[key], 0, 0xffffffffffffffff if key == 'file_id_volume_serial' else 0xffffffff)
            for key in ('file_id_volume_serial', 'volume_information_serial', 'maximum_component_length',
                        'filesystem_flags', 'remote_protocol_error')), 'native volume integers differ')
        result = {'volume_name': volume['volume_label'], 'volume_serial': f"{volume['file_id_volume_serial']:016x}",
            'volume_information_serial': f"{volume['volume_information_serial']:08x}",
            'filesystem_name': volume['filesystem_name'], 'maximum_component_length': volume['maximum_component_length'],
            'filesystem_flags': volume['filesystem_flags'], 'remote_protocol_query_status': 'error',
            'remote_protocol_error': volume['remote_protocol_error'], 'remote_protocol': None,
            'remote_protocol_major': None, 'remote_protocol_minor': None, 'remote_protocol_revision': None,
            'remote_protocol_flags': None, 'protected_objects': []}
        expected = native_objects(native_anchors, native_tree)[:7]
        require(len(phase['execution']['handles']) == 7 and all(handle['object_observation'] == obj
            for handle, obj in zip(phase['execution']['handles'], expected)), 'native phase object set differs')
        for index, role in ((2, 'staging_root'), (3, 'destination_parent'), (4, 'state_anchor'),
                           (5, 'journal_anchor'), (0, 'volume_root'), (1, 'publication_root'), (6, 'payload_root')):
            obj = expected[index]
            result['protected_objects'].append({'role': role, 'observed_path': obj['native_name'].lstrip('\\').replace('\\', '/') or '.',
                'file_id': obj['file_id'], 'reparse': bool(obj['attributes'] & 0x400),
                'case_sensitive': obj['case_sensitive'], 'security': security[obj['file_id']]})
        return result

    def closure(tree):
        require(tree['root_streams'] == [], 'native root carries streams')
        def entry(obj, relative_path, size, digest, streams):
            validate_object(obj, context.service_sid)
            directory = bool(obj['attributes'] & 16)
            require(integer(size, 0, model.MAX_CONTENT_BYTES) and isinstance(streams, list), 'native closure size/streams differ')
            require(directory and digest in ('', None) and streams == [] or not directory and
                isinstance(digest, str) and model.SHA256_RE.fullmatch(digest) and len(streams) == 1 and
                streams[0].keys() == {'name', 'size', 'allocation_size'} and streams[0]['name'] == '::$DATA' and
                integer(streams[0]['size'], 0, model.MAX_CONTENT_BYTES) and streams[0]['size'] == size and
                integer(streams[0]['allocation_size'], 0, model.MAX_CONTENT_BYTES), 'native closure content/streams differ')
            observed = by_id[obj['file_id']]
            require(integer(observed['bytes'], 0, model.MAX_CONTENT_BYTES) and observed['bytes'] == size and
                observed['sha256'] == (None if directory else digest) and observed['streams'] == streams,
                'independent terminal content/streams differ from the sealed native closure')
            value = {'relative_path': relative_path, 'type': 'directory' if directory else 'file',
                'file_id': obj['file_id'], 'size': size, 'content_sha256': None if directory else digest,
                'attributes': sorted(name for bit, name in ATTRIBUTE_BITS.items() if obj['attributes'] & bit),
                'security': security[obj['file_id']], 'link_count': obj['link_count'],
                'streams': [stream['name'] for stream in streams], 'reparse': False, 'reparse_tag': None}
            model.ClosureEntry.parse(value, context.service_sid, context.effective_access_principals)
            return value
        root = entry(tree['root'], '.', 0, None, tree['root_streams'])
        require(all(item['object']['native_name'] == tree['root']['native_name'] + '\\' +
            item['relative_path'].replace('/', '\\') for item in tree['descendants']),
            'native closure descendant path/name binding differs')
        descendants = [entry(item['object'], item['relative_path'].replace('\\', '/'), item['size'], item['sha256'], item['streams'])
            for item in tree['descendants']]
        descendants.sort(key=lambda item: item['relative_path'].casefold())
        return root, descendants

    root, descendants = closure(sealed)
    evidence = observation(prepared['execution_phases'][0], anchors, dict(sealed, descendants=[]))
    evidence.update(profile_id=model.PROFILE_ID, os_family=first_execution['platform']['os_family'],
        os_arch=first_execution['platform']['native_arch'], windows_build=first_execution['platform']['windows_build'],
        sdk_version=first_execution['platform']['sdk_version'], publisher_service_sid=context.service_sid,
        service_sid_type='SERVICE_SID_TYPE_RESTRICTED', anchor_creation='atomic_protected_from_inception',
        consumer_grants=[], untrusted_mutating_rights=[], covered_objects=list(model.EXPECTED_COVERED_OBJECTS) + ['payload_root'],
        observer_provenance=context.provenance[0], handle_provenance=context.provenance[1], volume_root_provenance=context.provenance[2],
        anchor_preexisting=False, handles_inheritable=False, handles_duplicated_outside_service=False,
        destination_name=prepared['destination_name'], destination_open_result='ERROR_FILE_NOT_FOUND', replace_if_exists=False,
        observation_apis=list(context.observation_apis), closure_entry_count=len(descendants),
        closure_max_depth=max((len(item['relative_path'].split('/')) for item in descendants), default=0),
        max_component_utf16_units=sealed['volume']['maximum_component_length'],
        serialized_evidence_bytes=len(json.dumps({'root': root, 'closure': descendants}, sort_keys=True, separators=(',', ':')).encode()),
        total_content_bytes=sum(item['size'] for item in descendants))
    profile = model.ProfileEvidence.parse(evidence, context)
    sealed_observation = observation(prepared['execution_phases'][1], anchors, sealed)
    prepared_observation = observation(prepared['execution_phases'][2], anchors, sealed)
    model.PhaseObservation.parse(prepared_observation, profile)
    events = [{'action': 'admit_profile', 'evidence': evidence}, {'action': 'begin_materialization'},
        {'action': 'seal', 'observation': sealed_observation, 'root': root, 'closure': descendants},
        {'action': 'prepare_publish'}]
    if visible is not None and visible['execution_transition'] == 'renamed_by_current_worker':
        before = observation(visible['execution_phases'][0], visible['protected_anchors'], sealed)
        after = observation(visible['execution_phases'][1], visible['protected_anchors'], visible['visible_tree'])
        visible_root, visible_descendants = closure(visible['visible_tree'])
        events += [{'action': 'rename', 'observation': before, 'outcome': 'applied',
            'replace_if_exists': visible['rename_call']['replace_if_exists'],
            'destination_exists': visible['rename_call']['destination_absence_status'] != 0xc0000034},
            {'action': 'confirm_visible', 'observation': after, 'destination_name': visible['destination_name'],
             'root': visible_root, 'closure': visible_descendants}]
    else:
        # A restart observation supplies no missing original native call.
        events.append({'action': 'crash', 'rename_outcome': 'unknown'})
    result = model.replay(model.initial_state(), events, context=context)
    require(result.disposition in ('advanced', 'recovery_required') and not model.invariant_errors(result.state),
            'native publication model replay refused its projected evidence')
    return {'schema': 'usk.publisher.native_profile_model_reconciliation.v1', 'status': 'bindings_consistent',
        'scope': 'retrospective_native_record_consistency', 'source_provenance': dict(source_provenance),
        'profile_evidence': evidence, 'events': events, 'model_result': model.projection(result),
        'execution_reconciliation': execution_report, 'descriptor_objects_checked': len(objects),
        'terminal_consumer_delta_objects': consumer_delta_count,
        'actor_principals': list(context.effective_access_principals), 'live_phase_access_checks': False,
        'destination_absence_basis': 'retained_native_call' if visible is not None and
            visible['execution_transition'] == 'renamed_by_current_worker' else 'reviewed_fresh_route_model_precondition',
        'handle_export_basis': 'reviewed_selected_route_source_argument',
        'global_export_history_observed': False, 'profile_qualified': False, 'publication_authority_granted': False}
