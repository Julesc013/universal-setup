# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent retained-data joins for the separate native broker/effect child.

These checks preserve the actual SCM and child roles. They cannot authenticate
JSON, launch a child, adopt a native owner or establish runtime qualification.
"""
from __future__ import annotations

import copy
import re

from publisher_execution_evidence import canonical_sha, closed, integer, require, sid
from publisher_process_boundary import validate_process_boundary
from publisher_worker_security import validate_worker_security

BROKER_KEYS = frozenset({'schema', 'authority', 'request_sha256', 'custody', 'service',
    'effect_primary_token', 'registered_admission', 'volume_root', 'broker_volume_granted_access',
    'authenticated_client', 'service_configuration', 'broker_security'})
TOKEN_KEYS = frozenset({'user_sid', 'groups', 'restricted_sids', 'observing_thread_impersonating',
                        'token_id', 'authentication_id', 'modified_id', 'token_type'})
SERVICE_KEYS = frozenset({'service_name', 'service_sid', 'service_sid_type', 'service_type',
                          'service_state', 'process_id', 'primary_token'})
WORKER_KEYS = frozenset({'process_id', 'process_birth', 'service_sid', 'primary_token'})
CUSTODY_KEYS = frozenset({'schema', 'authority', 'request_sha256', 'current_process_id',
    'current_process_birth', 'peer_process_id', 'peer_process_birth', 'image',
    'owned_job_active_process_limit', 'owned_job_kill_on_close'})
OBJECT_KEYS = frozenset({'file_id', 'native_name', 'owner_sid', 'dacl_protected', 'attributes',
                        'reparse_tag', 'link_count', 'case_sensitive', 'dacl_aces'})
REGISTRATION_KEYS = frozenset({'schema', 'scope', 'service_name', 'service_sid', 'process_id',
    'configured_caller_sid', 'publisher_image', 'registration_sha256', 'target_admitted_sha256', 'target_identity'})
CONFIGURATION_KEYS = frozenset({'schema', 'scope', 'service_type', 'start_type', 'service_sid_type',
                               'command', 'account', 'display_name', 'arguments'})
HEX_ID = re.compile(r'[0-9a-f]{16}')
SHA256 = re.compile(r'[0-9a-f]{64}')
FILE_ID = re.compile(r'[0-9a-f]{16}:[0-9a-f]{32}')
VOLUME_ROOT = re.compile(r'\\\\\?\\Volume\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\\')


def text(value, maximum=32768):
    return isinstance(value, str) and 0 < len(value) <= maximum and '\0' not in value


def hex_value(value, pattern, *, nonzero=False):
    return isinstance(value, str) and pattern.fullmatch(value) is not None and (
        not nonzero or int(value, 16) != 0)


def validate_primary_token(token, service_sid):
    closed(token, TOKEN_KEYS, 'broker primary token keys differ')
    require(token['user_sid'] == 'S-1-5-18' and token['observing_thread_impersonating'] is False and
        integer(token['token_type'], 1, 1) and all(integer(token[key], 1, 0xffffffffffffffff)
        for key in ('token_id', 'authentication_id', 'modified_id')), 'broker restricted primary token differs')
    for key in ('groups', 'restricted_sids'):
        groups = token[key]
        require(isinstance(groups, list) and 0 < len(groups) <= 4096, 'broker token group closure differs')
        seen = set()
        for group in groups:
            closed(group, frozenset({'sid', 'attributes'}), 'broker group keys differ')
            require(sid(group['sid']) and group['sid'] not in seen and integer(group['attributes']),
                    'broker group identity or attributes differ')
            seen.add(group['sid'])
        selected = [group for group in groups if group['sid'] == service_sid]
        require(len(selected) == 1 and (key != 'groups' or selected[0]['attributes'] & 4 and
            not selected[0]['attributes'] & 16), 'broker token lacks its enabled/restricting service SID')


def worker_security_context(process_id, service_sid, token):
    """Adapt independently validated native token facts, never substitute a PID."""
    return {'process_id': process_id, 'service_sid': service_sid, 'token_type': token['token_type'],
        'process_groups': token['groups'], 'process_restricted_sids': token['restricted_sids'],
        **{key: f"{token[key]:016x}" for key in ('token_id', 'authentication_id', 'modified_id')}}


def parse_registered_command(command):
    """Decode the bounded Windows argv grammar used by original SCM records.

The executable's first argument has Windows' separate quote rule; subsequent
arguments use backslash/quote parity. No shell, expansion or platform effects.
"""
    require(text(command), 'broker original command is not bounded text')
    args, index, size = [], 0, len(command)
    # Leading whitespace is an empty argv[0] in CommandLineToArgvW.
    if command[0] in ' \t':
        args.append('')
    else:
        first, quoted = [], False
        while index < size:
            char = command[index]
            if char == '"':
                quoted = not quoted
            elif char in ' \t' and not quoted:
                break
            else:
                first.append(char)
            index += 1
        require(not quoted, 'broker executable quote is unfinished')
        args.append(''.join(first))
    while index < size:
        while index < size and command[index] in ' \t':
            index += 1
        if index == size:
            break
        value, quoted = [], False
        while index < size:
            if command[index] in ' \t' and not quoted:
                break
            slashes = 0
            while index < size and command[index] == '\\':
                slashes += 1
                index += 1
            if index < size and command[index] == '"':
                value.extend('\\' * (slashes // 2))
                if slashes % 2:
                    value.append('"')
                elif quoted and index + 1 < size and command[index + 1] == '"':
                    value.append('"')
                    index += 1
                else:
                    quoted = not quoted
                index += 1
            else:
                value.extend('\\' * slashes)
                if index < size and (quoted or command[index] not in ' \t'):
                    value.append(command[index])
                    index += 1
                else:
                    break
        require(not quoted, 'broker original argument quote is unfinished')
        args.append(''.join(value))
        require(len(args) <= 16, 'broker original argument bound exceeded')
    return args


def validate_broker_record(broker):
    closed(broker, BROKER_KEYS, 'broker readback keys differ')
    custody, service = broker['custody'], broker['service']
    closed(custody, CUSTODY_KEYS, 'broker original custody keys differ')
    require(broker['schema'] == 'usk.publisher_effect_broker_native_readback.v2' and
        broker['authority'] == 'read_only_observation' and
        custody['schema'] == 'usk.publisher_effect_transport_custody.v1' and custody['authority'] == 'none' and
        hex_value(broker['request_sha256'], SHA256) and broker['request_sha256'] == custody['request_sha256'] and
        integer(custody['current_process_id'], 1) and integer(custody['peer_process_id'], 1) and
        custody['current_process_id'] != custody['peer_process_id'] and
        all(hex_value(custody[key], HEX_ID, nonzero=True) for key in ('current_process_birth', 'peer_process_birth')) and
        integer(custody['owned_job_active_process_limit'], 1, 1) and custody['owned_job_kill_on_close'] is True,
        'broker original request/process/birth/job custody differs')
    closed(service, SERVICE_KEYS, 'broker SCM service keys differ')
    service_sid = service['service_sid']
    require(text(service['service_name'], 256) and sid(service_sid) and
        service_sid.startswith('S-1-5-80-') and len(service_sid.split('-')) == 9 and
        integer(service['service_sid_type'], 3, 3) and integer(service['service_type'], 16, 16) and
        integer(service['service_state'], 4, 4) and integer(service['process_id'], 1) and
        service['process_id'] == custody['current_process_id'], 'broker actual SCM identity differs')
    parent_token, child_token = service['primary_token'], broker['effect_primary_token']
    validate_primary_token(parent_token, service_sid)
    validate_primary_token(child_token, service_sid)
    require(all(parent_token[key] == child_token[key] for key in
        ('user_sid', 'authentication_id', 'token_type', 'groups', 'restricted_sids')),
        'broker child token does not retain original inherited account/session/groups')
    from publisher_authenticated_access_evidence import validate_client
    validate_client(broker['authenticated_client'])
    admission, image = broker['registered_admission'], custody['image']
    closed(admission, REGISTRATION_KEYS, 'broker native registration keys differ')
    closed(image, frozenset({'volume_id', 'file_id', 'size_bytes', 'sha256'}), 'broker held image keys differ')
    admitted_image = admission['publisher_image']
    closed(admitted_image, frozenset({'path', 'volume_id', 'file_id', 'size_bytes', 'sha256'}),
           'broker registered image keys differ')
    require(all(text(image[key]) for key in ('volume_id', 'file_id')) and integer(image['size_bytes'], 1, 0xffffffffffffffff) and
        hex_value(image['sha256'], SHA256) and text(admitted_image['path']) and
        all(admitted_image[key] == image[key] and type(admitted_image[key]) is type(image[key]) for key in image) and
        admission['schema'] == 'usk.publisher_registered_admission_observation.v1' and
        admission['scope'] == 'held_registered_service_image_and_controller_target_admission' and
        admission['service_name'] == service['service_name'] and admission['service_sid'] == service_sid and
        integer(admission['process_id'], 1) and admission['process_id'] == service['process_id'] and
        admission['configured_caller_sid'] == broker['authenticated_client']['user_sid'] and
        all(hex_value(admission[key], SHA256) for key in ('registration_sha256', 'target_admitted_sha256')),
        'broker original image/registration/caller differs')
    target = admission['target_identity']
    closed(target, frozenset({'registration_sha256', 'volume_identity', 'disk_identity', 'metadata'}),
           'broker original target keys differ')
    volume = target['volume_identity']
    closed(volume, frozenset({'volume_root', 'root_file_id', 'volume_serial'}), 'broker volume identity keys differ')
    require(target['registration_sha256'] == admission['registration_sha256'] and isinstance(target['disk_identity'], dict) and
        isinstance(target['metadata'], list) and len(target['metadata']) <= 4096 and
        canonical_sha({'schema': 'usk.publisher_target_admitted.v1', 'identity': target}) == admission['target_admitted_sha256'] and
        isinstance(volume['volume_root'], str) and VOLUME_ROOT.fullmatch(volume['volume_root']) and
        isinstance(volume['root_file_id'], str) and FILE_ID.fullmatch(volume['root_file_id']) and
        volume['volume_serial'] == str(int(volume['root_file_id'][:16], 16)), 'broker original admitted volume differs')
    root = broker['volume_root']
    closed(root, OBJECT_KEYS, 'broker original volume observer keys differ')
    require(root['file_id'] == volume['root_file_id'] and root['native_name'] == '\\' and root['owner_sid'] == 'S-1-5-18' and
        root['dacl_protected'] is True and root['case_sensitive'] is False and integer(root['attributes']) and
        root['attributes'] & 16 and not root['attributes'] & 0x400 and integer(root['reparse_tag'], 0, 0) and
        integer(root['link_count'], 1, 1) and isinstance(root['dacl_aces'], list) and len(root['dacl_aces']) == 2 and
        integer(broker['broker_volume_granted_access'], 0x120080, 0x120080), 'broker original query-only volume differs')
    for ace, principal in zip(root['dacl_aces'], ('S-1-5-18', service_sid)):
        closed(ace, frozenset({'type', 'flags', 'access_mask', 'sid'}), 'broker volume ACE keys differ')
        require(integer(ace['type'], 0, 0) and integer(ace['flags'], 0, 0) and
                integer(ace['access_mask'], 0x1f01ff, 0x1f01ff) and ace['sid'] == principal,
                'broker volume ACE facts differ')
    configuration = broker['service_configuration']
    closed(configuration, CONFIGURATION_KEYS, 'broker original SCM configuration keys differ')
    args = configuration['arguments']
    require(configuration['schema'] == 'usk.publisher_registered_execution_configuration.v1' and
        configuration['scope'] == 'original_held_scm_configuration' and integer(configuration['service_type'], 16, 16) and
        integer(configuration['start_type'], 3, 3) and integer(configuration['service_sid_type'], 3, 3) and
        isinstance(configuration['account'], str) and configuration['account'].lower() == 'localsystem' and
        text(configuration['display_name']) and isinstance(args, list) and len(args) in (9, 11) and all(text(arg) for arg in args) and
        args[:5] == [admitted_image['path'], '--service', service['service_name'], '--no-receipt', volume['volume_root']] and
        args[-3:] == ['--service-admitted-client', '--authorized-client-sid', admission['configured_caller_sid']] and
        (len(args) == 9 and args[5] in ('--recover-reviewed', '--verify-installed') or len(args) == 11 and
            args[5] == '--reviewed-plan-envelope' and hex_value(args[7], SHA256)) and
        parse_registered_command(configuration['command']) == args, 'broker original command/configuration differs')
    security = broker['broker_security']
    closed(security, frozenset({'process_boundary', 'worker_security'}), 'broker native security keys differ')
    context = worker_security_context(service['process_id'], service_sid, parent_token)
    validate_process_boundary(security['process_boundary'], context['process_id'], service_sid, context['process_groups'])
    validate_worker_security(security['worker_security'], context)
    return worker_security_context(custody['peer_process_id'], service_sid, child_token)


def immutable_broker_record(broker):
    """Validate every current parent thread, then retain immutable parent facts."""
    validate_broker_record(broker)
    retained = copy.deepcopy(broker)
    del retained['broker_security']['worker_security']['threads']
    return retained


def validate_effect_execution_identity(execution, service_name, service_sid, volume_root):
    broker, worker = execution['broker_readback'], execution['effect_worker']
    context = validate_broker_record(broker)
    closed(worker, WORKER_KEYS, 'actual effect-worker keys differ')
    closed(execution['service'], SERVICE_KEYS, 'actual execution SCM service keys differ')
    validate_primary_token(worker['primary_token'], service_sid)
    require(canonical_sha(execution['service']) == canonical_sha(broker['service']) and broker['service']['service_name'] == service_name and
        broker['service']['service_sid'] == service_sid and worker['service_sid'] == service_sid and
        integer(worker['process_id'], 1) and worker['process_id'] == context['process_id'] and
        worker['process_birth'] == broker['custody']['peer_process_birth'] and
        worker['primary_token'] == broker['effect_primary_token'] and
        canonical_sha(execution['authenticated_client']) == canonical_sha(broker['authenticated_client']) and
        canonical_sha(broker['volume_root']) == canonical_sha(volume_root) and
        canonical_sha(broker['volume_root']) == canonical_sha(execution['handles'][0]['object_observation']),
        'actual child/SCM/caller/complete target binding differs')
    return context


def execution_worker_identity(execution):
    """Select a distinct retained-data family; never infer a live native owner."""
    if execution['schema'] == 'usk.publisher_execution_observation.v7':
        worker = execution['effect_worker']
        return worker['process_id'], worker['primary_token']['token_id'], worker['process_birth']
    service = execution['service']
    return service['process_id'], service['token_id'], None


def validate_active_child_lease(lease, broker):
    """Bind an original sealed active record to the separate retained child.

    This is not proof that its holder has ended or that a takeover is permitted.
    Native liveness, append lineage and full durable history remain separate.
    """
    context = validate_broker_record(broker)
    closed(lease, frozenset({'schema', 'install_id', 'operation', 'operation_id', 'attempt_id',
        'state_root_identity', 'holder', 'generation', 'expected_state_revision', 'status',
        'result_state_revision', 'predecessor_sha256', 'ownership_sha256', 'operation_context_sha256'}),
        'original child lease keys differ')
    root, holder = lease['state_root_identity'], lease['holder']
    closed(root, frozenset({'file_id', 'volume_serial'}), 'original lease root keys differ')
    closed(holder, frozenset({'process_id', 'process_creation_time'}), 'original lease holder keys differ')
    identifiers = ('install_id', 'operation_id', 'attempt_id')
    require(lease['schema'] == 'usk.installation_lease_ownership.v1' and lease['status'] == 'active' and
        lease['result_state_revision'] is None and lease['operation'] in ('install_local', 'repair', 'move', 'uninstall') and
        all(isinstance(lease[key], str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', lease[key]) for key in identifiers) and
        integer(lease['generation'], 1, 0xffffffffffffffff) and
        (lease['predecessor_sha256'] is None if lease['generation'] == 1 else hex_value(lease['predecessor_sha256'], SHA256)) and
        all(hex_value(lease[key], SHA256) for key in ('expected_state_revision', 'operation_context_sha256', 'ownership_sha256')) and
        isinstance(root['file_id'], str) and re.fullmatch(r'[0-9a-f]{32}', root['file_id']) and
        root['volume_serial'] == broker['registered_admission']['target_identity']['volume_identity']['volume_serial'] and
        integer(holder['process_id'], 1) and holder['process_id'] == context['process_id'] and
        holder['process_creation_time'] == broker['custody']['peer_process_birth'] and
        canonical_sha({key: value for key, value in lease.items() if key != 'ownership_sha256'}) == lease['ownership_sha256'],
        'original child lease seal/IDs/target/PID-birth differs')
    return holder


def validate_original_maintenance_provenance(original, request, service_name):
    """Decode v3 provenance only; native object restoration is a separate proof."""
    closed(original, frozenset({'schema', 'transaction_id', 'operation', 'plan_digest', 'original_context_sha256',
        'original_lease_ownership', 'worker_security', 'process_boundary', 'registration_sha256',
        'authenticated_client', 'original_consumer_completion', 'installed_root',
        'installed_root_journal_identity', 'original_objects', 'broker_readback'}),
        'child maintenance original custody keys differ')
    closed(request, frozenset({'schema', 'plan_request', 'reviewed_plan_id', 'reviewed_plan_digest',
                              'transaction_id', 'applied_at', 'confirmation'}), 'original maintenance apply keys differ')
    require(original['schema'] == 'usk.publisher.maintenance_original_custody.v3',
            'child maintenance original custody has another provenance family')
    broker = original['broker_readback']
    context = validate_broker_record(broker)
    validate_process_boundary(original['process_boundary'], context['process_id'], context['service_sid'], context['process_groups'])
    validate_worker_security(original['worker_security'], context)
    lease = original['original_lease_ownership']
    validate_active_child_lease(lease, broker)
    operation = original['operation']
    args = broker['service_configuration']['arguments']
    require(operation in ('repair', 'move', 'uninstall') and request['schema'] == 'usk.' + operation + '_apply_request.v1' and
        request['confirmation'] == 'APPLY' and isinstance(request['plan_request'], dict) and
        broker['service']['service_name'] == service_name and len(args) == 11 and args[5] == '--reviewed-plan-envelope' and
        broker['request_sha256'] == canonical_sha(request) and
        original['registration_sha256'] == canonical_sha(broker['registered_admission']) and
        original['plan_digest'] == request['reviewed_plan_digest'] and hex_value(original['plan_digest'], SHA256) and
        original['authenticated_client'] == broker['authenticated_client'] and lease['operation'] == operation and
        lease['operation_id'] == original['transaction_id'] == request['transaction_id'] and
        lease['install_id'] == request['plan_request']['install_id'] and
        lease['operation_context_sha256'] == original['original_context_sha256'],
        'child original custody lost original request/registration/caller/lease provenance')
    return {'scope': 'retained_original_child_provenance_only', 'holder': dict(lease['holder']),
            'broker_process_id': broker['service']['process_id'], 'native_restoration_qualified': False}
