"""Behavioral oracles for bounded, non-authorizing current-task observations."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'aide_lite_task_current', Path(__file__).resolve().parents[1] / 'aide_lite.py')
aide = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aide
SPEC.loader.exec_module(aide)


class CurrentTaskView(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task = 'PROJECT-WORK-01'
        self.base = f'.aide/queue/{self.task}'
        self.write('.aide/queue/index.yaml',
                   f'schema_version: aide.queue-index.v0\nitems:\n  - id: {self.task}\n    status: passed\n')
        self.write(aide.LATEST_PACKET_PATH, f'# Task\n\ntask_id: {self.task}\n')
        self.write(self.base + '/task.yaml', f'id: {self.task}\nstatus: planning\n'
                   'title: Useful native preparation\nobjective: >\n  Preserve work\n  through recovery.\n')
        self.status('status: passed\nresult: PASS_WITH_ENVIRONMENT_SKIPS\n'
                    'classification: preparation_only\nproduct_qualified: false\n'
                    'target_mutated: false\nowner: project_team\n'
                    'next_action: request_native_owner_adoption\n'
                    'remaining_obligations:\n  - target_adoption\n  - whole_task_accounting\n')

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
        return path

    def status(self, text):
        self.write(self.base + '/status.yaml', f'task_id: {self.task}\n' + text)

    def view(self, identity=None):
        return aide.build_current_task_view(self.root, identity)

    def command(self, *arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = aide.main(['--repo-root', str(self.root), 'task', 'current', *arguments])
        return code, output.getvalue()

    def test_preparation_success_preserves_unfinished_native_obligations(self):
        data = self.view()
        self.assertEqual(data['objective'], 'Preserve work through recovery.')
        self.assertEqual(data['status'], 'passed')
        self.assertEqual(data['result'], 'PASS_WITH_ENVIRONMENT_SKIPS')
        self.assertEqual(data['remaining_obligations'], ['target_adoption', 'whole_task_accounting'])
        self.assertEqual(data['next_action'], 'request_native_owner_adoption')
        self.assertFalse(data['scope']['product_qualified'])
        self.assertFalse(data['scope']['target_mutated'])
        self.assertFalse(data['acceptance_verified'])

    def test_human_legacy_prefix_and_json_report_same_record(self):
        code, human = self.command()
        self.assertEqual(code, 0)
        self.assertEqual(human.splitlines()[:3], ['AIDE Lite task current',
                         'task_id: PROJECT-WORK-01', 'status: passed'])
        code, structured = self.command('--json')
        self.assertEqual(code, 0)
        data = json.loads(structured)
        for field in ['task_id', 'status', 'result', 'objective', 'owner', 'next_action']:
            self.assertIn(f'{field}: {data[field]}', human)
        self.assertEqual(data['schema_version'], 'aide.task-current.v1')
        self.assertEqual(structured, self.command('--json')[1])

    def test_explicit_selection_does_not_depend_on_a_broken_latest_packet(self):
        self.write(aide.LATEST_PACKET_PATH, '# Task\ntask_id: ../../outside\n')
        code, output = self.command('--task-id', self.task, '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['task_id'], self.task)
        self.assertEqual(self.command('--json')[0], 1)

    def test_unknown_and_escaping_identities_refuse_without_fallback(self):
        for identity in ['PROJECT-MISSING', '../../outside', 'C:/outside', '']:
            with self.subTest(identity=identity):
                code, output = self.command('--task-id', identity, '--json')
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(output)['task_id'], '')

    def test_conflicting_packet_and_task_identity_refuse(self):
        self.write(aide.LATEST_PACKET_PATH, f'task_id: {self.task}\nphase: ANOTHER-01\n')
        self.assertEqual(self.command('--json')[0], 1)
        self.write(self.base + '/task.yaml', 'id: ANOTHER-01\n')
        self.assertEqual(self.command('--task-id', self.task, '--json')[0], 1)

    def test_planning_declaration_does_not_override_recorded_status(self):
        data = self.view()
        self.assertEqual(data['declared_status'], 'planning')
        self.assertEqual(data['status'], 'passed')
        self.assertEqual(data['issues'], [])
        self.assertEqual(data['sources']['status'], self.base + '/status.yaml')

    def test_stale_index_status_is_explained_without_repair(self):
        path = self.write('.aide/queue/index.yaml', f'items:\n  - id: {self.task}\n    status: running\n')
        before = path.read_bytes()
        data = self.view()
        self.assertEqual(data['status'], 'passed')
        self.assertEqual(data['index_status'], 'running')
        self.assertIn('index_status_conflict', [i['code'] for i in data['issues']])
        self.assertEqual(path.read_bytes(), before)

    def test_needs_review_is_not_accepted(self):
        self.status('status: needs_review\nresult: PASS\n')
        data = self.view()
        self.assertEqual(data['status'], 'needs_review')
        self.assertFalse(data['acceptance_verified'])
        self.assertIsNone(data['owner'])
        self.assertIsNone(data['next_action'])

    def test_missing_and_foreign_status_remain_unknown(self):
        (self.root / self.base / 'status.yaml').unlink()
        data = self.view()
        self.assertEqual(data['status'], 'unknown')
        self.assertIn('missing_record', [i['code'] for i in data['issues']])
        self.write(self.base + '/status.yaml', 'task_id: ANOTHER\nstatus: passed\n')
        data = self.view()
        self.assertEqual(data['status'], 'unknown')
        self.assertIsNone(data['result'])

    def test_duplicate_fields_cannot_select_a_convenient_status(self):
        self.status('status: failed\nstatus: passed\nresult: FAIL\n')
        data = self.view()
        self.assertEqual(data['status'], 'unknown')
        self.assertIn('duplicate_field', [i['code'] for i in data['issues']])

    def test_unsupported_shapes_and_types_are_visible(self):
        self.status('status: [passed]\nresult: !!python/object:run\nowner: true\n'
                    'product_qualified: sometimes\nbroken record\n')
        data = self.view()
        self.assertEqual(data['status'], 'unknown')
        self.assertIsNone(data['result'])
        self.assertIsNone(data['owner'])
        self.assertIsNone(data['scope']['product_qualified'])
        self.assertIn('malformed_record', [i['code'] for i in data['issues']])

    def test_comment_only_values_are_unknown_and_quoted_hashes_are_preserved(self):
        self.status('status: # pending determination\nowner: # not assigned\n'
                    'next_action: "# literal action"\nresult: \'# literal result\'\n')
        data = self.view()
        self.assertEqual(data['status'], 'unknown')
        self.assertIsNone(data['owner'])
        self.assertEqual(data['next_action'], '# literal action')
        self.assertEqual(data['result'], '# literal result')

    def test_present_digest_does_not_establish_evidence_applicability(self):
        data = b'{"result":"PASS","source":"old"}\n'
        self.write(self.base + '/evidence/result.json', data.decode())
        self.status('status: passed\nfinal_result_ref: evidence/result.json\n'
                    'final_result_sha256: ' + hashlib.sha256(data).hexdigest() + '\n')
        ref = self.view()['evidence'][0]
        self.assertEqual(ref['availability'], 'present')
        self.assertTrue(ref['digest_verified'])
        self.assertEqual(ref['applicability'], 'unverified')

    def test_missing_and_digest_mismatch_remain_distinct(self):
        self.write(self.base + '/evidence/result.json', 'changed\n')
        self.status('status: passed\nfinal_result_ref: evidence/result.json\n'
                    'final_result_sha256: ' + '0' * 64 + '\noriginal_ref: evidence/missing.json\n')
        refs = {item['field']: item for item in self.view()['evidence']}
        self.assertEqual(refs['final_result_ref']['availability'], 'digest_mismatch')
        self.assertEqual(refs['original_ref']['availability'], 'missing')

    def test_repository_reference_accepts_windows_separators(self):
        self.write(self.base + '/evidence/result.json', 'retained\n')
        reference = (self.base + '/evidence/result.json').replace('/', '\\')
        self.status('status: passed\nfinal_result_ref: ' + reference + '\n')
        self.assertEqual(self.view()['evidence'][0]['availability'], 'present')

    def test_empty_required_record_is_visible(self):
        self.write(self.base + '/status.yaml', '')
        data = self.view()
        self.assertEqual(data['status'], 'unknown')
        self.assertIn('empty_record', [i['code'] for i in data['issues']])

    def test_private_and_escape_references_are_rejected_before_open(self):
        for ref in ['../../../../outside', '.aide/../.env', '.aide.local/key',
                    'C:/private', '/outside', '.aide/queue/../secrets/key',
                    'evidence/credentials.json', '.aide/queue/.env.local']:
            with self.subTest(ref=ref):
                self.status('status: passed\nfinal_result_ref: ' + ref + '\n')
                item = self.view()['evidence'][0]
                self.assertEqual(item['availability'], 'unsafe_reference')
                self.assertIsNone(item['path'])

    def test_hardlinked_reference_is_not_read(self):
        original = self.write('private.txt', 'private sentinel')
        alias = self.root / self.base / 'alias.txt'
        os.link(original, alias)
        self.status('status: passed\nfinal_result_ref: alias.txt\n')
        data = self.view()
        self.assertEqual(data['evidence'][0]['availability'], 'unsafe_reference')
        self.assertNotIn('private sentinel', json.dumps(data))

    def test_windows_dot_space_aliases_are_refused_before_filesystem_access(self):
        for relative in ['.aide.local./key', '.git /config',
                         self.base + '/.aide.local. /key', self.base + '/result.json.']:
            with self.subTest(relative=relative):
                with patch.object(Path, 'lstat', side_effect=AssertionError('must not access')):
                    with self.assertRaisesRegex(ValueError, 'unsafe_reference'):
                        aide.task_view_read(self.root, relative)

    def test_windows_reparse_attribute_is_refused_without_open(self):
        target = self.write(self.base + '/evidence/result.json', 'private sentinel')
        self.status('status: passed\nfinal_result_ref: evidence/result.json\n')
        original = Path.lstat
        def lstat(path):
            info = original(path)
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if path == target else info
        with patch.object(Path, 'lstat', lstat):
            self.assertEqual(self.view()['evidence'][0]['availability'], 'unsafe_reference')

    def test_record_and_diagnostic_output_are_bounded(self):
        self.status('status: passed\n' + 'broken\n' * 10000)
        data = self.view()
        self.assertLessEqual(len(data['issues']), 35)
        self.assertLess(len(json.dumps(data)), 16384)
        self.status('status: passed\n' + '#' * 131072)
        self.assertIn('record_too_large', [i['code'] for i in self.view()['issues']])

    def test_observation_leaves_all_fixture_bytes_and_mtimes_unchanged(self):
        self.write(self.base + '/evidence/result.json', 'retained\n')
        self.status('status: passed\nfinal_result_ref: evidence/result.json\n')
        def snapshot():
            return {p.relative_to(self.root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
                    for p in self.root.rglob('*') if p.is_file()}
        before = snapshot()
        self.command()
        self.command('--json')
        self.assertEqual(snapshot(), before)


if __name__ == '__main__':
    unittest.main()
