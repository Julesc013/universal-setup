# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Decode retained original SCM/effect-child closure; JSON grants no authority."""
from __future__ import annotations

import argparse
import json
from pathlib import PureWindowsPath
import re
import sys

from publisher_execution_evidence import canonical_sha, closed, integer, require

PAIR_KEYS = frozenset({'schema', 'scope', 'parent_process_id', 'parent_process_birth',
    'effect_process_id', 'effect_process_birth', 'native_parent_process_id', 'original_image_path',
    'both_live_before_termination', 'parent_termination_invoked', 'child_termination_invoked',
    'parent_native_wait_result', 'child_native_wait_result', 'child_observer_access',
    'child_observer_handle_flags', 'child_observer_close_confirmed'})
HOLDER_KEYS = frozenset({'process_id', 'process_creation_time'})
TERMINATION_KEYS = frozenset({'confirmed', 'terminated', 'kill_invoked', 'method',
    'process_id', 'process_creation_file_time', 'native_wait_result'})
LIVE_PAIR_KEYS = frozenset({'schema', 'scope', 'parent_process_id', 'parent_process_birth',
    'effect_process_id', 'effect_process_birth', 'native_parent_process_id', 'original_image_path',
    'both_live', 'child_observer_access', 'child_observer_handle_flags'})


def birth(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{16}', value) is not None and int(value, 16) != 0


def validate_live_process_pair(pair, parent_process_id, parent_process_birth, image):
    closed(pair, LIVE_PAIR_KEYS, 'original live process-pair keys differ')
    require(pair['schema'] == 'usk.publisher_owned_live_process_pair.v1' and
        pair['scope'] == 'held_scm_parent_and_original_live_effect_child' and
        integer(parent_process_id, 1) and integer(parent_process_birth, 1, 0xffffffffffffffff) and
        all(integer(pair[key], 1) for key in ('parent_process_id', 'effect_process_id', 'native_parent_process_id')) and
        pair['parent_process_id'] == pair['native_parent_process_id'] == parent_process_id and
        pair['effect_process_id'] != parent_process_id and
        all(birth(pair[key]) for key in ('parent_process_birth', 'effect_process_birth')) and
        int(pair['effect_process_birth'], 16) >= int(pair['parent_process_birth'], 16) and
        int(pair['parent_process_birth'], 16) == parent_process_birth and pair['both_live'] is True and
        isinstance(pair['original_image_path'], str) and 0 < len(pair['original_image_path']) <= 32768 and
        '\0' not in pair['original_image_path'] and PureWindowsPath(pair['original_image_path']).is_absolute() and
        isinstance(image, str) and pair['original_image_path'].casefold() == image.casefold() and
        integer(pair['child_observer_access'], 0x101400, 0x101400) and
        integer(pair['child_observer_handle_flags'], 0, 0), 'original live process-pair roles/native custody differ')
    return {'process_id': pair['effect_process_id'], 'process_creation_time': pair['effect_process_birth']}


def validate_ended_process_pair(boundary, broker=None):
    require(boundary['schema'] == 'usk.publisher.production_rename_observer.v2' and
        boundary['identity'] == 'S-1-5-18' and boundary['original_pair_closure_confirmed'] is True,
        'current original native process-pair observation is absent')
    pair, holder, termination = boundary['native_process_pair'], boundary['effect_holder'], boundary['termination']
    closed(pair, PAIR_KEYS, 'original native process-pair keys differ')
    closed(holder, HOLDER_KEYS, 'original ended effect holder keys differ')
    closed(termination, TERMINATION_KEYS, 'original SCM termination keys differ')
    image = pair['original_image_path']
    require(pair['schema'] == 'usk.publisher_owned_native_process_pair.v1' and
        pair['scope'] == 'held_scm_parent_termination_and_original_effect_child_end' and
        all(integer(pair[key], 1) for key in ('parent_process_id', 'effect_process_id', 'native_parent_process_id')) and
        pair['parent_process_id'] != pair['effect_process_id'] and
        pair['native_parent_process_id'] == pair['parent_process_id'] and
        integer(boundary['service_pid'], 1) and boundary['service_pid'] == pair['parent_process_id'] and
        all(birth(pair[key]) for key in ('parent_process_birth', 'effect_process_birth')) and
        int(pair['effect_process_birth'], 16) >= int(pair['parent_process_birth'], 16) and
        boundary['process_creation_file_time'] == pair['parent_process_birth'] and
        integer(holder['process_id'], 1) and holder['process_id'] == pair['effect_process_id'] and
        holder['process_creation_time'] == pair['effect_process_birth'] and
        isinstance(image, str) and 0 < len(image) <= 32768 and '\0' not in image and
        PureWindowsPath(image).is_absolute() and PureWindowsPath(image).name == boundary['service_name'] + '.exe' and
        image == boundary['service_executable'] and pair['both_live_before_termination'] is True and
        pair['parent_termination_invoked'] is True and pair['child_termination_invoked'] is False and
        integer(pair['parent_native_wait_result'], 0, 0) and integer(pair['child_native_wait_result'], 0, 0) and
        integer(pair['child_observer_access'], 0x101400, 0x101400) and
        integer(pair['child_observer_handle_flags'], 0, 0) and pair['child_observer_close_confirmed'] is True,
        'original native process-pair identity/ancestry/liveness/closure differs')
    require(termination['confirmed'] is True and termination['kill_invoked'] is True and
        integer(termination['terminated'], 1, 1) and termination['method'] == 'TerminateProcess_owned_held_root' and
        integer(termination['process_id'], 1) and termination['process_id'] == pair['parent_process_id'] and
        termination['process_creation_file_time'] == pair['parent_process_birth'] and
        integer(termination['native_wait_result'], 0, 0), 'termination does not identify only the original held SCM owner')
    if broker is not None:
        from publisher_effect_broker_evidence import validate_broker_record
        validate_broker_record(broker)
        custody = broker['custody']
        require(custody['current_process_id'] == pair['parent_process_id'] and
            custody['current_process_birth'] == pair['parent_process_birth'] and
            custody['peer_process_id'] == pair['effect_process_id'] and
            custody['peer_process_birth'] == pair['effect_process_birth'] and
            broker['registered_admission']['publisher_image']['path'] == image,
            'held original process pair differs from full retained native broker custody')
    return holder


def original_provenance(original, request, service_name, boundary):
    from publisher_effect_broker_evidence import validate_original_maintenance_provenance
    report = validate_original_maintenance_provenance(original, request, service_name)
    holder = validate_ended_process_pair(boundary, original['broker_readback'])
    require(canonical_sha(holder) == canonical_sha(report['holder']) and boundary['service_name'] == service_name,
            'ended original pair differs from sealed original child provenance')
    report['original_pair_closure_checked'] = True
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', choices=('-',), required=True)
    parser.parse_args()
    # Original durable custody is bounded at 16 MiB, plus the original request
    # and small observer record. This is retained data, not a transport frame.
    raw = sys.stdin.buffer.read(18 * 1024 * 1024 + 1)
    require(len(raw) <= 18 * 1024 * 1024, 'retained process-pair input exceeds bound')
    value = json.loads(raw)
    if isinstance(value, dict) and value.get('mode') == 'ended_pair':
        closed(value, frozenset({'mode', 'boundary'}), 'retained ended-pair input keys differ')
        print(json.dumps({'holder': validate_ended_process_pair(value['boundary']), 'profile_qualified': False}, separators=(',', ':')))
        return
    closed(value, frozenset({'mode', 'original', 'request', 'service_name', 'boundary'}), 'retained provenance input keys differ')
    require(value['mode'] == 'original_maintenance_provenance', 'unknown retained provenance mode')
    print(json.dumps(original_provenance(value['original'], value['request'], value['service_name'], value['boundary']), separators=(',', ':')))


if __name__ == '__main__':
    main()
