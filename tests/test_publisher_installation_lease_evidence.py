# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic record contradictions; these tests never qualify native ownership."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from publisher_installation_lease_evidence import canonical, digest, snapshot, transition, bootstrap_takeover, bootstrap_preservation_takeover, active_ownership, LeaseEvidenceError

DRIVE = 'U:\\'
ROOT = '0000000000000001:' + 'a' * 32
STATE_ROOT = {'file_id': 'b' * 32, 'volume_serial': '1'}
INSTALLED = {'install_id': 'org.example.setup', 'transaction_id': 'operation.1', 'lifecycle_status': 'installed'}
INSTALL_NAME = 'install-' + digest(INSTALLED['install_id'])
LEASES = DRIVE + 'setup-state\\state\\leases\\' + INSTALL_NAME
CONTEXTS = DRIVE + 'installation-operations\\' + INSTALL_NAME


def record(path, value):
    text = canonical(value) + '\n'
    return {'path': path, 'directory': False, 'bytes': len(text.encode('utf-8')),
            'content_json': text, 'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()}


def fixture(generations=1):
    reviewed = {'transaction_id': INSTALLED['transaction_id'], 'plan_digest': 'f' * 64}
    context = {'schema': 'usk.installation_operation_context.v1', 'install_id': INSTALLED['install_id'],
        'operation': 'install_local', 'operation_id': INSTALLED['transaction_id'],
        'volume_root_identity': {'file_id': 'a' * 32, 'volume_serial': '1'},
        'initial_state_revision': digest([]), 'reviewed_snapshot': reviewed}
    context['context_sha256'] = digest(context)
    roots = {'schema': 'usk.installation_operation_roots.v1', 'install_id': INSTALLED['install_id'],
        'operation_id': INSTALLED['transaction_id'], 'context_sha256': context['context_sha256'],
        'setup_root_identity': {'file_id': 'b' * 32, 'volume_serial': '1'}, 'state_root_identity': STATE_ROOT}
    roots['roots_sha256'] = digest(roots)
    state = DRIVE + 'setup-state\\state'
    directories = [DRIVE + 'setup-state', state, state + '\\leases', LEASES, LEASES + '\\pending',
                   DRIVE + 'installation-operations', CONTEXTS, CONTEXTS + '\\pending']
    rows = [{'path': path, 'directory': True, 'file_id': '0000000000000001:' + 'b' * 32} for path in directories]
    filename = INSTALLED['install_id'] + '.' + INSTALLED['transaction_id'] + '.json'
    revision = digest([{'record': filename, 'sha256': digest(INSTALLED)}])
    rows += [record(CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id']) + '.json', context),
             record(CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id']) + '-roots.json', roots),
             record(DRIVE + 'publication\\journal\\lab-reviewed-plan.json', reviewed),
             record(state + '\\installed\\' + filename, INSTALLED)]
    previous = None
    for generation in range(1, generations + 1):
        active = {'schema': 'usk.installation_lease_ownership.v1', 'install_id': INSTALLED['install_id'],
            'operation': 'install_local', 'operation_id': INSTALLED['transaction_id'], 'attempt_id': f'attempt.{generation}',
            'state_root_identity': STATE_ROOT, 'holder': {'process_id': 100 + generation, 'process_creation_time': '0' * 15 + '1'},
            'generation': generation, 'expected_state_revision': digest([]) if generation == 1 else revision,
            'status': 'active', 'result_state_revision': None, 'predecessor_sha256': previous,
            'operation_context_sha256': roots['roots_sha256']}
        active['ownership_sha256'] = digest(active)
        if generation == 1:
            reservation = {'schema': 'usk.publication_bootstrap_reservation.v1', 'install_id': INSTALLED['install_id'],
                'operation_id': INSTALLED['transaction_id'], 'context_sha256': context['context_sha256'],
                'roots_sha256': roots['roots_sha256'], 'volume_root_identity': context['volume_root_identity'],
                'ownership': copy.deepcopy(active), 'publication_absent': True}
            reservation['reservation_sha256'] = digest(reservation)
            rows.append(record(CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id']) +
                               '-bootstrap-g00000000000000000001.json', reservation))
        terminal = dict(active, status='completed', result_state_revision=revision)
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows += [record(LEASES + f'\\g{generation:020d}-active.json', active),
                 record(LEASES + f'\\g{generation:020d}-terminal.json', terminal)]
        previous = terminal['ownership_sha256']
    return rows


def relink_active_rows(rows, reviewed=None, holder=None):
    """Reseal all linked synthetic records, so negative tests exercise joins."""
    prefix = CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id'])
    indexed = {row['path']: row for row in rows}
    context = json.loads(indexed[prefix + '.json']['content_json'])
    if reviewed is not None:
        context['reviewed_snapshot'] = reviewed
    context['context_sha256'] = digest({k: v for k, v in context.items() if k != 'context_sha256'})
    roots = json.loads(indexed[prefix + '-roots.json']['content_json'])
    roots['context_sha256'] = context['context_sha256']
    roots['roots_sha256'] = digest({k: v for k, v in roots.items() if k != 'roots_sha256'})
    active_path = LEASES + '\\g00000000000000000001-active.json'
    active = json.loads(indexed[active_path]['content_json'])
    if holder is not None:
        active['holder'] = holder
    active['operation_context_sha256'] = roots['roots_sha256']
    active['ownership_sha256'] = digest({k: v for k, v in active.items() if k != 'ownership_sha256'})
    reservation_path = prefix + '-bootstrap-g00000000000000000001.json'
    reservation = json.loads(indexed[reservation_path]['content_json'])
    reservation.update(context_sha256=context['context_sha256'], roots_sha256=roots['roots_sha256'], ownership=active)
    reservation['reservation_sha256'] = digest({k: v for k, v in reservation.items() if k != 'reservation_sha256'})
    replacements = {prefix + '.json': context, prefix + '-roots.json': roots,
                    active_path: active, reservation_path: reservation}
    return [record(row['path'], replacements[row['path']]) if row['path'] in replacements else row for row in rows]


def active_fixture(published=False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
    from usk_bundle_apply_binding import compose_binding, _bytes
    request = {'schema': 'usk.oneshot_request.v1', 'request_id': 'plan.active', 'command': 'install_local.plan', 'dry_run': True,
        'payload': {'schema': 'usk.install_local_plan_request.v1', 'request_id': 'plan.active',
            'install_id': INSTALLED['install_id'], 'required_commit_authority': 'staged_child_bound_v1',
            'archive': {'path': 'U:/authored/payload.zip', 'expected_sha256': '1' * 64},
            'target': {'root': 'U:/publication/destination/visible'},
            'recipe': {'components': ['core'], 'provider_revision': '2' * 64, 'recipe_digest': '3' * 64}}}
    policy = {'schema': 'usk.install_restart_policy_context.v1', 'setup_initial_state': 'absent',
        'policy': {'activation': 'operator_acceptance_candidate', 'setup_binding_digest': '4' * 64, 'target_binding_digest': '5' * 64},
        'target_evidence': {'schema': 'usk.install_target_recovery_evidence.v1', 'filesystem_kind': 'windows_fixed',
            'filesystem_identity_digest': '6' * 64, 'target_identity_digest': '7' * 64, 'target_state': 'nonexistent',
            'capacity_satisfied': True, 'excluded_roots_absent': True, 'local_filesystem': True,
            'mount_redirection_absent': True, 'path_components_stable': True, 'source_target_distinct': True}}
    entries = [{'entry_type': 'file', 'relative_path': 'bin/core.bin', 'size_bytes': 12, 'sha256': '8' * 64}]
    plan = {'schema': 'usk.install_plan.v1', 'operation': 'install_local', 'plan_id': 'plan.active', 'plan_digest': '9' * 64,
        'required_commit_authority': 'staged_child_bound_v1', 'commit_authority_available': False,
        'target': {'root': 'U:/publication/destination/visible', 'identity_digest': '7' * 64,
            'filesystem': {'kind': 'windows_fixed', 'identity_digest': '6' * 64}},
        'source': {'path': 'U:/authored/payload.zip', 'sha256': '1' * 64, 'filesystem_identity_digest': 'a' * 64},
        'component_selection': ['core'], 'planned_entries': entries,
        'input_identity': {'provider_revision': '2' * 64, 'recipe_digest': '3' * 64, 'policy_digest': digest(policy['policy'])}}
    response = {'schema': 'usk.oneshot_response.v1', 'request_id': 'plan.active', 'status': 'ok', 'error': None,
                'result': {'status': 'ok', 'error': None, 'payload': plan}}
    apply, envelope = compose_binding(request, response, acceptance_root=DRIVE, state_root=DRIVE + 'setup-state',
        transaction_id=INSTALLED['transaction_id'], applied_at='2026-10-07T00:00:00Z')
    files = [{'relative_path': 'bin/core.bin', 'size': 12, 'sha256': '8' * 64}]
    selected = canonical({'schema': 'usk.publisher.lab_selected_file_set.v1', 'files': files}) + '\n'
    consumer = 'S-1-5-21-1-2-3-1001'
    reviewed = {'schema': 'usk.publisher.lab_reviewed_plan_snapshot.v4', 'plan_digest': plan['plan_digest'],
        'plan_envelope_sha256': hashlib.sha256(_bytes(envelope)).hexdigest(), 'archive_sha256': '1' * 64,
        'archive_identity_digest': 'a' * 64, 'entry_set_digest': 'b' * 64,
        'selected_file_set_digest': hashlib.sha256(selected.encode()).hexdigest(), 'target_root': plan['target']['root'],
        'setup_root': DRIVE + 'setup-state', 'transaction_id': apply['transaction_id'], 'applied_at': apply['applied_at'],
        'policy_digest': digest(policy['policy']), 'restart_policy_context': canonical(policy),
        'plan_request': request['payload'], 'planned_entries': entries, 'consumer_read_sid': consumer, 'apply_request': apply}
    rows = [row for row in fixture() if not row['path'].endswith('-terminal.json') and
            row['path'] != DRIVE + 'publication\\journal\\lab-reviewed-plan.json' and
            not row['path'].startswith(DRIVE + 'setup-state\\state\\installed\\')]
    present = {row['path'] for row in rows}
    directories = [DRIVE + 'setup-state', DRIVE + 'setup-state\\state\\installed', DRIVE + 'publication'] + [
        DRIVE + 'publication\\' + name for name in ('staging', 'destination', 'state', 'journal')]
    rows += [{'path': path, 'directory': True, 'file_id': '0000000000000001:' + 'b' * 32}
             for path in directories if path not in present]
    rows = relink_active_rows(rows, reviewed)
    if published:
        rows.append(record(DRIVE + 'publication\\journal\\lab-reviewed-plan.json', reviewed))
    holder = {'process_id': 101, 'process_creation_time': '0000000000000001'}
    return rows, request, response, apply, consumer, holder


def preserved_fixture(anchor_count=4, snapshot_bytes=None):
    rows = fixture(2)
    first_active = json.loads(next(row for row in rows if row['path'] == LEASES + '\\g00000000000000000001-active.json')['content_json'])
    rows = [row for row in rows if row['path'] != LEASES + '\\g00000000000000000001-terminal.json']
    second_path = LEASES + '\\g00000000000000000002-active.json'
    second = json.loads(next(row for row in rows if row['path'] == second_path)['content_json'])
    second.update(expected_state_revision=digest([]), predecessor_sha256=first_active['ownership_sha256'])
    second['ownership_sha256'] = digest({key: value for key, value in second.items() if key != 'ownership_sha256'})
    terminal_path = LEASES + '\\g00000000000000000002-terminal.json'
    revision = json.loads(next(row for row in rows if row['path'] == terminal_path)['content_json'])['result_state_revision']
    terminal = dict(second, status='completed', result_state_revision=revision)
    terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
    rows = [record(row['path'], second if row['path'] == second_path else terminal)
            if row['path'] in (second_path, terminal_path) else row for row in rows]
    prefix = CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id'])
    reservation = json.loads(next(row for row in rows if row['path'] == prefix + '-bootstrap-g00000000000000000001.json')['content_json'])
    next_reservation = dict(reservation, ownership=second)
    next_reservation['reservation_sha256'] = digest({key: value for key, value in next_reservation.items() if key != 'reservation_sha256'})
    rows.append(record(prefix + '-bootstrap-g00000000000000000002.json', next_reservation))
    retained_path = prefix + '-retained-g00000000000000000001'
    def observed(path, identity, directory, raw=b''):
        aces = [{'type': 0, 'flags': 0, 'access_mask': 2032127, 'sid': 'S-1-5-18'},
                {'type': 0, 'flags': 0, 'access_mask': 2032127, 'sid': 'S-1-5-80-1-2-3-4-5'}]
        obj = {'file_id': '0000000000000001:' + f'{identity:032x}', 'attributes': 16 if directory else 32,
            'link_count': 1, 'case_sensitive': False, 'reparse_tag': 0, 'owner_sid': 'S-1-5-18',
            'dacl_protected': True, 'dacl_aces': aces}
        streams = [] if directory else [{'name': '::$DATA', 'size': len(raw), 'allocation_size': 4096}]
        row = {'path': path, 'directory': directory, 'file_id': obj['file_id'], 'attributes': obj['attributes'],
            'link_count': 1, 'case_sensitive': False, 'owner': 'S-1-5-18', 'protected': True, 'raw_aces': aces,
            'streams': streams, 'bytes': len(raw), 'sha256': None if directory else hashlib.sha256(raw).hexdigest(),
            'content_json': None if directory else raw.decode('utf-8', errors='replace')}
        return row, obj
    retained, root_object = observed(retained_path, 99, True)
    rows.append(retained)
    entries = []
    for index, name in enumerate(('staging', 'destination', 'state', 'journal')[:anchor_count]):
        row, obj = observed(retained_path + '\\' + name, 100 + index, True)
        rows.append(row)
        entries.append({'relative_path': name, 'object': obj, 'bytes': 0, 'sha256': '', 'streams': []})
    if snapshot_bytes is not None:
        reviewed = json.loads(next(row for row in rows if row['path'] == DRIVE + 'publication\\journal\\lab-reviewed-plan.json')['content_json'])
        raw = (canonical(reviewed) + '\n').encode('utf-8')[:snapshot_bytes]
        row, obj = observed(retained_path + '\\journal\\lab-reviewed-plan.json', 104, False, raw)
        rows.append(row)
        entries.append({'relative_path': 'journal/lab-reviewed-plan.json', 'object': obj, 'bytes': len(raw),
                        'sha256': row['sha256'], 'streams': row['streams']})
    move = {'schema': 'usk.publication_bootstrap_preservation.v1', 'install_id': INSTALLED['install_id'],
        'operation_id': INSTALLED['transaction_id'], 'reservation_sha256': reservation['reservation_sha256'],
        'source_name': 'publication', 'source_root_identity': retained['file_id'],
        'destination_parent_identity': {'file_id': 'b' * 32, 'volume_serial': '1'},
        'destination_name': retained_path.rsplit('\\', 1)[1],
        'tree': {'root': root_object, 'root_streams': [], 'entries': entries}}
    move['preservation_sha256'] = digest(move)
    rows.append(record(prefix + '-preserve-g00000000000000000001.json', move))
    return rows


def takeover_fixture(anchor_count=4, snapshot_bytes=None):
    after = preserved_fixture(anchor_count, snapshot_bytes)
    after.append(record(DRIVE + 'setup-state\\.usk-owned-root.v1.json',
        {'schema': 'usk.setup_owned_root.v1', 'acceptance_root': DRIVE.replace('\\', '/')}))
    prefix = CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id'])
    retained = prefix + '-retained-g00000000000000000001'
    for row in after:
        row['native_name'] = row['path'][2:]
    live = copy.deepcopy(next(row for row in after if row['path'] == retained))
    live.update(path=DRIVE + 'publication', native_name='\\publication', file_id='0000000000000001:' + 'c' * 32)
    after.append(live)
    coordination = {prefix + '.json', prefix + '-roots.json', prefix + '-bootstrap-g00000000000000000001.json',
                    LEASES + '\\g00000000000000000001-active.json', DRIVE + 'setup-state\\.usk-owned-root.v1.json'}
    before = []
    for original in after:
        row = copy.deepcopy(original)
        if row['path'] == retained or row['path'].startswith(retained + '\\'):
            row['path'] = DRIVE + 'publication' + row['path'][len(retained):]
            row['native_name'] = row['path'][2:]
            before.append(row)
        elif row['path'] in coordination or (row['directory'] and not row['path'].startswith(DRIVE + 'publication')):
            before.append(row)
    return before, after, {'process_id': 101, 'process_creation_time': '0000000000000001'}


def preservation_takeover_fixture():
    before, after, first_holder = takeover_fixture(4, 7)
    prefix = CONTEXTS + '\\operation-' + digest(INSTALLED['transaction_id'])
    second = json.loads(next(row for row in after if row['path'] == LEASES + '\\g00000000000000000002-active.json')['content_json'])
    third = dict(second, generation=3, attempt_id='attempt.3',
        holder={'process_id': 103, 'process_creation_time': '0000000000000003'},
        predecessor_sha256=second['ownership_sha256'])
    third['ownership_sha256'] = digest({key: value for key, value in third.items() if key != 'ownership_sha256'})
    terminal = json.loads(next(row for row in after if row['path'] == LEASES + '\\g00000000000000000002-terminal.json')['content_json'])
    terminal = dict(third, status='completed', result_state_revision=terminal['result_state_revision'])
    terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
    reservation = json.loads(next(row for row in after if row['path'] == prefix + '-bootstrap-g00000000000000000002.json')['content_json'])
    reservation['ownership'] = third
    reservation['reservation_sha256'] = digest({key: value for key, value in reservation.items() if key != 'reservation_sha256'})
    after = [row for row in after if row['path'] not in {LEASES + '\\g00000000000000000002-terminal.json',
        prefix + '-bootstrap-g00000000000000000002.json'}]
    for path, value in ((LEASES + '\\g00000000000000000003-active.json', third),
                        (LEASES + '\\g00000000000000000003-terminal.json', terminal),
                        (prefix + '-bootstrap-g00000000000000000003.json', reservation)):
        row = record(path, value)
        row['native_name'] = path[2:]
        after.append(row)
    retained = prefix + '-retained-g00000000000000000001'
    publication = DRIVE + 'publication'
    paths = {retained + row['path'][len(publication):] if row['path'] == publication or
             row['path'].startswith(publication + '\\') else row['path'] for row in before} | {
                 prefix + '-preserve-g00000000000000000001.json', LEASES + '\\g00000000000000000002-active.json'}
    preserved = copy.deepcopy([row for row in after if row['path'] in paths])
    return before, preserved, after, [first_holder, second['holder']]


class LeaseRecordReconciliationTests(unittest.TestCase):
    def test_v3_active_ownership_accepts_only_explicit_original_early_or_published_phase(self):
        for published in (False, True):
            rows, request, response, apply, consumer, holder = active_fixture(published)
            result = active_ownership(rows, DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)
            self.assertEqual(result['active_ownership_phase'],
                'published_reviewed_plan' if published else 'prepublication_empty_anchors')
            self.assertTrue(result['initial_empty_state_observed'])
            if not published:
                with self.assertRaises(KeyError):
                    snapshot(rows, DRIVE, INSTALLED, ROOT, allow_active=True, allow_initial_empty_state=True)

    def test_v3_early_ownership_refuses_missing_extra_or_aliased_native_namespace(self):
        base, request, response, apply, consumer, holder = active_fixture()
        for suffix in ('-roots.json', '-bootstrap-g00000000000000000001.json', '-active.json',
                       '\\publication\\state', '\\publication\\journal'):
            rows = [row for row in base if not row['path'].endswith(suffix)]
            with self.subTest(missing=suffix), self.assertRaises((LeaseEvidenceError, KeyError)):
                active_ownership(rows, DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)
        for path in (DRIVE+'publication\\staging\\candidate', DRIVE+'publication\\state\\foreign',
                     DRIVE+'setup-state\\state\\installed\\foreign.json', CONTEXTS+'\\foreign.json'):
            rows = base + [record(path, {})]
            with self.subTest(extra=path), self.assertRaises(LeaseEvidenceError):
                active_ownership(rows, DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)
        with self.assertRaises(LeaseEvidenceError):
            active_ownership(base + [base[0]], DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)

    def test_v3_resealed_context_cannot_replace_original_plan_apply_source_or_consumer(self):
        base, request, response, apply, consumer, holder = active_fixture()
        prefix = CONTEXTS+'\\operation-'+digest(INSTALLED['transaction_id'])+'.json'
        original = json.loads(next(row['content_json'] for row in base if row['path'] == prefix))['reviewed_snapshot']
        for field in ('schema', 'plan_digest', 'plan_envelope_sha256', 'archive_sha256', 'archive_identity_digest',
                      'selected_file_set_digest', 'target_root', 'setup_root', 'transaction_id', 'applied_at',
                      'policy_digest', 'consumer_read_sid'):
            changed = copy.deepcopy(original);changed[field] = 'substituted'
            rows = relink_active_rows(base, changed)
            with self.subTest(field=field), self.assertRaises(LeaseEvidenceError):
                active_ownership(rows, DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)
        for field in ('plan_request', 'apply_request', 'planned_entries'):
            changed = copy.deepcopy(original);changed[field] = {}
            with self.subTest(field=field), self.assertRaises(LeaseEvidenceError):
                active_ownership(relink_active_rows(base, changed), DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)
        changed = copy.deepcopy(original);policy = json.loads(changed['restart_policy_context'])
        policy['target_evidence']['path_components_stable'] = False
        changed['restart_policy_context'] = canonical(policy)
        with self.assertRaises(LeaseEvidenceError):
            active_ownership(relink_active_rows(base, changed), DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)

    def test_v3_active_ownership_refuses_resealed_replacement_holder_and_published_plan_mismatch(self):
        for field, value in (('process_id', 102), ('process_creation_time', '0000000000000002')):
            rows, request, response, apply, consumer, holder = active_fixture()
            changed = dict(holder);changed[field] = value
            with self.subTest(field=field), self.assertRaises(LeaseEvidenceError):
                active_ownership(relink_active_rows(rows, holder=changed), DRIVE, INSTALLED, ROOT,
                                 request, response, apply, consumer, holder)
        rows, request, response, apply, consumer, holder = active_fixture(True)
        path = DRIVE+'publication\\journal\\lab-reviewed-plan.json'
        altered = [record(path, {'substituted': True}) if row['path'] == path else row for row in rows]
        with self.assertRaises(LeaseEvidenceError):
            active_ownership(altered, DRIVE, INSTALLED, ROOT, request, response, apply, consumer, holder)

    def test_preservation_loss_requires_exact_moved_tree_and_third_owner(self):
        before, preserved, after, holders = preservation_takeover_fixture()
        report = bootstrap_preservation_takeover(before, preserved, after, DRIVE, INSTALLED, ROOT, holders)
        self.assertTrue(report['preservation_reentry_checked'])
        self.assertEqual(report['replacement_generation'], 3)
        self.assertFalse(report['publication_authority_granted'])
        with self.assertRaises(LeaseEvidenceError):
            bootstrap_takeover(before, after, DRIVE, INSTALLED, ROOT, holders[0])

    def test_preservation_loss_cannot_invent_or_alias_native_holders(self):
        before, preserved, after, holders = preservation_takeover_fixture()
        for key, value in (('process_id', 999), ('process_creation_time', '0000000000000009')):
            changed = copy.deepcopy(holders)
            changed[1][key] = value
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                bootstrap_preservation_takeover(before, preserved, after, DRIVE, INSTALLED, ROOT, changed)
        with self.assertRaises(LeaseEvidenceError):
            bootstrap_preservation_takeover(before, preserved, after, DRIVE, INSTALLED, ROOT, holders[:1])

    def test_preservation_loss_rejects_missing_changed_or_extra_objects(self):
        before, preserved, after, holders = preservation_takeover_fixture()
        for suffix in ('-preserve-g00000000000000000001.json', '-retained-g00000000000000000001',
                       'g00000000000000000002-active.json'):
            changed = [row for row in preserved if not row['path'].endswith(suffix)]
            with self.subTest(missing=suffix), self.assertRaises(LeaseEvidenceError):
                bootstrap_preservation_takeover(before, changed, after, DRIVE, INSTALLED, ROOT, holders)
        for suffix in ('publication', 'installation-operations\\pending\\draft.json'):
            changed = preserved + [{'path': DRIVE + suffix, 'directory': True}]
            with self.subTest(extra=suffix), self.assertRaises(LeaseEvidenceError):
                bootstrap_preservation_takeover(before, changed, after, DRIVE, INSTALLED, ROOT, holders)
        for key, value in (('file_id', ROOT), ('owner', 'S-1-5-32-544'), ('bytes', 100), ('native_name', '\\other')):
            changed = copy.deepcopy(preserved)
            next(row for row in changed if row['path'].endswith('lab-reviewed-plan.json'))[key] = value
            with self.subTest(changed=key), self.assertRaises(LeaseEvidenceError):
                bootstrap_preservation_takeover(before, changed, after, DRIVE, INSTALLED, ROOT, holders)

    def test_preservation_loss_cli_consumes_both_interrupted_readbacks(self):
        before, preserved, after, holders = preservation_takeover_fixture()
        payload = canonical(dict(mode='bootstrap_preservation_takeover', before=before, preserved=preserved, after=after,
            drive=DRIVE, installed=INSTALLED, volume_root_id=ROOT, terminated_holders=holders))
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('publisher_installation_lease_evidence.py')),
            '--input', '-'], input=payload, text=True, encoding='utf-8', capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['coordination']['replacement_generation'], 3)

    def test_bootstrap_oracle_cli_loads_stdin_and_file_before_dispatch(self):
        before, after, holder = takeover_fixture(4, 7)
        request = canonical({'mode': 'bootstrap_takeover', 'before': before, 'after': after, 'drive': DRIVE,
            'installed': INSTALLED, 'volume_root_id': ROOT, 'terminated_holder': holder})
        script = Path(__file__).with_name('publisher_installation_lease_evidence.py')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'takeover.json'
            path.write_text(request, encoding='utf-8')
            for input_path, payload in (('-', request), (str(path), None)):
                with self.subTest(input=input_path):
                    result = subprocess.run([sys.executable, '-B', str(script), '--input', input_path],
                        input=payload, text=True, encoding='utf-8', capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['coordination']['replacement_generation'], 2)
                    self.assertFalse(report['profile_qualified'])

    def test_measured_bootstrap_takeover_retains_every_observed_object(self):
        for anchors, byte_count in ((0, None), (2, None), (4, 0), (4, 7), (4, 100000)):
            with self.subTest(anchors=anchors, bytes=byte_count):
                before, after, holder = takeover_fixture(anchors, byte_count)
                result = bootstrap_takeover(before, after, DRIVE, INSTALLED, ROOT, holder)
                self.assertEqual(result['replacement_generation'], 2)
                self.assertEqual(result['retained_objects'], 1 + anchors + (byte_count is not None))
                self.assertFalse(result['publication_authority_granted'])

    def test_bootstrap_takeover_requires_observed_pid_and_birth(self):
        before, after, holder = takeover_fixture()
        for changed in (dict(holder, process_id=102), dict(holder, process_creation_time='0000000000000002')):
            with self.assertRaises(LeaseEvidenceError):
                bootstrap_takeover(before, after, DRIVE, INSTALLED, ROOT, changed)

    def test_bootstrap_takeover_cannot_lose_or_change_interrupted_objects(self):
        before, after, holder = takeover_fixture(4, 7)
        for key, value in (('file_id', ROOT), ('owner', 'S-1-5-32-544'), ('bytes', 8), ('native_name', '\\other')):
            changed = copy.deepcopy(before)
            row = next(row for row in changed if row['path'].endswith('lab-reviewed-plan.json'))
            row[key] = value
            with self.assertRaises(LeaseEvidenceError):
                bootstrap_takeover(changed, after, DRIVE, INSTALLED, ROOT, holder)
        with self.assertRaises(LeaseEvidenceError):
            bootstrap_takeover(before[:-1], after, DRIVE, INSTALLED, ROOT, holder)

    def test_bootstrap_takeover_cannot_omit_original_reservation_or_add_state(self):
        before, after, holder = takeover_fixture()
        for changed in ([row for row in before if '-bootstrap-' not in row['path']],
                        before + [record(DRIVE + 'setup-state\\state\\installed\\extra.json', {})]):
            with self.assertRaises(LeaseEvidenceError):
                bootstrap_takeover(changed, after, DRIVE, INSTALLED, ROOT, holder)

    def test_bootstrap_takeover_binds_setup_marker_and_preserves_its_whole_row(self):
        before, after, holder = takeover_fixture()
        marker = DRIVE + 'setup-state\\.usk-owned-root.v1.json'
        for value in ({'schema': 'usk.setup_owned_root.v1', 'acceptance_root': 'V:/'},
                      {'schema': 'usk.setup_owned_root.v1', 'acceptance_root': 'U:/', 'extra': True}):
            changed = [record(marker, value) if row['path'] == marker else row for row in before]
            with self.assertRaises(LeaseEvidenceError):
                bootstrap_takeover(changed, after, DRIVE, INSTALLED, ROOT, holder)
        changed = copy.deepcopy(after)
        next(row for row in changed if row['path'] == marker)['native_name'] = '\\other'
        with self.assertRaises(LeaseEvidenceError):
            bootstrap_takeover(before, changed, DRIVE, INSTALLED, ROOT, holder)

    def test_current_bootstrap_reservation_cannot_be_omitted(self):
        rows = [row for row in fixture() if '-bootstrap-' not in row['path']]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        historical = snapshot(rows, DRIVE, INSTALLED, ROOT, allow_legacy_missing_bootstrap=True)
        self.assertEqual(historical['bootstrap_protocol'], 'historical_unreserved')
        rows = [row for row in preserved_fixture(4, 9)
                if not row['path'].endswith('-bootstrap-g00000000000000000002.json')]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_recorded_fresh_creator_must_match_latest_native_reservation(self):
        rows = preserved_fixture(4, 9)
        active = json.loads(next(row for row in rows if row['path'] == LEASES + '\\g00000000000000000002-active.json')['content_json'])
        prepared = {'execution_origin': 'created_empty_in_current_worker', 'execution_phases': [
            {'execution': {'service': {'process_id': active['holder']['process_id']}}}]}
        path = DRIVE + 'publication\\journal\\lab-prepared-evidence.json'
        snapshot(rows + [record(path, prepared)], DRIVE, INSTALLED, ROOT)
        prepared['execution_phases'][0]['execution']['service']['process_id'] += 1
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows + [record(path, prepared)], DRIVE, INSTALLED, ROOT)

    def test_preserved_bootstrap_prefixes_and_snapshot_prefix_bytes(self):
        for count, size in [(0, None), (1, None), (2, None), (3, None), (4, None), (4, 0), (4, 9), (4, 10000)]:
            with self.subTest(anchors=count, bytes=size):
                rows = preserved_fixture(count, size)
                self.assertEqual(len(snapshot(rows, DRIVE, INSTALLED, ROOT)['history']), 3)

    def test_retained_bootstrap_identity_security_and_bytes_are_independent(self):
        for key, value in [('file_id', ROOT), ('owner', 'S-1-5-32-545'), ('sha256', 'e' * 64), ('bytes', 999)]:
            rows = preserved_fixture(4, 9)
            row = next(row for row in rows if '-retained-' in row['path'] and not row['directory'])
            row[key] = value
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_resealed_preservation_cannot_change_parent_or_original_snapshot_prefix(self):
        for changed_key in ('destination_parent_identity', 'reservation_sha256', 'source_name'):
            rows = preserved_fixture(4, 9)
            index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
            move = json.loads(rows[index]['content_json'])
            move[changed_key] = {'file_id': 'd' * 32, 'volume_serial': '1'} if changed_key == 'destination_parent_identity' else 'unrelated'
            move['preservation_sha256'] = digest({key: value for key, value in move.items() if key != 'preservation_sha256'})
            rows[index] = record(rows[index]['path'], move)
            with self.subTest(key=changed_key), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)
        rows = preserved_fixture(4, 9)
        move_index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
        move = json.loads(rows[move_index]['content_json'])
        entry = move['tree']['entries'][-1]
        changed_sha = hashlib.sha256(b'unrelated').hexdigest()
        entry['sha256'] = changed_sha
        move['preservation_sha256'] = digest({key: value for key, value in move.items() if key != 'preservation_sha256'})
        rows[move_index] = record(rows[move_index]['path'], move)
        next(row for row in rows if '-retained-' in row['path'] and not row['directory'])['sha256'] = changed_sha
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_absent_bootstrap_disposition_binds_later_actual_ownership(self):
        rows = preserved_fixture(0)
        move_index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
        original_move = json.loads(rows[move_index]['content_json'])
        later = json.loads(next(row for row in rows if row['path'] == LEASES + '\\g00000000000000000002-active.json')['content_json'])
        absent = {'schema': 'usk.publication_bootstrap_absence.v1', 'install_id': INSTALLED['install_id'],
            'operation_id': INSTALLED['transaction_id'], 'reservation_sha256': original_move['reservation_sha256'],
            'closing_ownership': later, 'publication_absent': True}
        absent['preservation_sha256'] = digest(absent)
        rows[move_index] = record(rows[move_index]['path'], absent)
        rows = [row for row in rows if '-retained-' not in row['path']]
        snapshot(rows, DRIVE, INSTALLED, ROOT)
        absent['closing_ownership']['holder']['process_id'] = 999
        absent['preservation_sha256'] = digest({key: value for key, value in absent.items() if key != 'preservation_sha256'})
        move_index = next(index for index, row in enumerate(rows) if '-preserve-' in row['path'])
        rows[move_index] = record(rows[move_index]['path'], absent)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_preserved_bootstrap_extra_objects_and_missing_ancestors_refuse(self):
        rows = preserved_fixture(4, 9)
        root_path = next(row['path'] for row in rows if '-retained-' in row['path'] and row['path'].endswith('01'))
        for bad in (rows + [record(root_path + '\\payload.bin', {})],
                    [row for row in rows if row['path'] != root_path + '\\destination']):
            with self.assertRaises(LeaseEvidenceError):
                snapshot(bad, DRIVE, INSTALLED, ROOT)

    def test_recovery_appends_one_generation_and_verification_is_readonly(self):
        before, after = fixture(), fixture(2)
        self.assertEqual(len(snapshot(before, DRIVE, INSTALLED, ROOT)['history']), 2)
        transition(before, after, DRIVE, INSTALLED, ROOT)
        transition(after, copy.deepcopy(after), DRIVE, INSTALLED, ROOT, readonly=True)
        with self.assertRaises(LeaseEvidenceError):
            transition(before, after, DRIVE, INSTALLED, ROOT, readonly=True)

    def test_cannot_change_any_prior_payload_or_journal_row(self):
        before = fixture()
        for key, value in [('bytes', 999), ('sha256', '0' * 64), ('native_name', '\\changed')]:
            after = fixture(2)
            after.append({'path': DRIVE + 'publication\\destination\\visible\\payload.bin', 'directory': False})
            original = copy.deepcopy(after[-1])
            old = before + [original]
            after[-1][key] = value
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                transition(old, after, DRIVE, INSTALLED, ROOT)

    def test_cannot_append_extra_objects_or_skip_generations(self):
        before = fixture()
        for after in (fixture(3), fixture(2) + [record(LEASES + '\\pending\\unexpected.json', {})],
                      fixture(2) + [record(DRIVE + 'unexpected.json', {})]):
            with self.assertRaises(LeaseEvidenceError):
                transition(before, after, DRIVE, INSTALLED, ROOT)

    def test_resealed_changed_operation_or_state_root_is_refused(self):
        for key, value in [('operation_id', 'another.1'), ('operation_context_sha256', 'e' * 64),
                           ('generation', True), ('expected_state_revision', 'e' * 64),
                           ('state_root_identity', {'file_id': 'c' * 32, 'volume_serial': '1'})]:
            rows = fixture()
            import json
            item = json.loads(rows[-2]['content_json'])
            item[key] = value
            item['ownership_sha256'] = digest({name: data for name, data in item.items() if name != 'ownership_sha256'})
            rows[-2] = record(rows[-2]['path'], item)
            with self.subTest(key=key), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_original_context_and_completed_revision_cannot_be_replaced(self):
        import json
        rows = fixture()
        context_row = next(row for row in rows if row['path'].endswith(digest(INSTALLED['transaction_id']) + '.json'))
        changed = json.loads(context_row['content_json'])
        changed['reviewed_snapshot']['plan_digest'] = 'e' * 64
        changed['context_sha256'] = digest({key: value for key, value in changed.items() if key != 'context_sha256'})
        rows[rows.index(context_row)] = record(context_row['path'], changed)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        rows = fixture()
        terminal = json.loads(rows[-1]['content_json'])
        terminal['result_state_revision'] = 'e' * 64
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows[-1] = record(rows[-1]['path'], terminal)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)

    def test_partial_observation_does_not_fabricate_terminal_record(self):
        rows = fixture()[:-1]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        self.assertEqual(len(snapshot(rows, DRIVE, INSTALLED, ROOT, allow_active=True)['history']), 1)

    def test_current_native_root_observations_must_match_retained_bindings(self):
        for path in (DRIVE + 'setup-state', DRIVE + 'setup-state\\state'):
            rows = fixture()
            next(row for row in rows if row['path'] == path)['file_id'] = '0000000000000001:' + 'c' * 32
            with self.subTest(path=path), self.assertRaises(LeaseEvidenceError):
                snapshot(rows, DRIVE, INSTALLED, ROOT)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(fixture(), DRIVE, INSTALLED, '0000000000000002:' + 'a' * 32)

    def test_historical_evidence_still_requires_every_row_unchanged(self):
        rows = [{'path': DRIVE + 'old.json', 'directory': False}]
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
        with self.assertRaises(LeaseEvidenceError):
            transition(rows, copy.deepcopy(rows), DRIVE, INSTALLED, ROOT)
        self.assertIsNone(snapshot(rows, DRIVE, INSTALLED, ROOT, allow_legacy_missing=True))
        transition(rows, copy.deepcopy(rows), DRIVE, INSTALLED, ROOT, allow_legacy_missing=True)
        with self.assertRaises(LeaseEvidenceError):
            transition(rows, rows + [{'path': DRIVE + 'extra.json', 'directory': False}], DRIVE, INSTALLED, ROOT,
                       allow_legacy_missing=True)

    def test_ended_holder_takeover_can_leave_prior_generation_active(self):
        import json
        rows = fixture(2)
        # Synthetic history, without any native holder-liveness verdict.
        rows = [row for row in rows if not row['path'].endswith('g00000000000000000001-terminal.json')]
        first = json.loads(rows[-3]['content_json'])
        second = json.loads(rows[-2]['content_json'])
        second['predecessor_sha256'] = first['ownership_sha256']
        second['expected_state_revision'] = first['expected_state_revision']
        second['ownership_sha256'] = digest({key: value for key, value in second.items() if key != 'ownership_sha256'})
        terminal = dict(second, status='completed', result_state_revision=json.loads(rows[-1]['content_json'])['result_state_revision'])
        terminal['ownership_sha256'] = digest({key: value for key, value in terminal.items() if key != 'ownership_sha256'})
        rows[-2] = record(rows[-2]['path'], second)
        rows[-1] = record(rows[-1]['path'], terminal)
        self.assertEqual(len(snapshot(rows, DRIVE, INSTALLED, ROOT)['history']), 3)
        second['holder'] = first['holder']
        second['ownership_sha256'] = digest({key: value for key, value in second.items() if key != 'ownership_sha256'})
        rows[-2] = record(rows[-2]['path'], second)
        with self.assertRaises(LeaseEvidenceError):
            snapshot(rows, DRIVE, INSTALLED, ROOT)
