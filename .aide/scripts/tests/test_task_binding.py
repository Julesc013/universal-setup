"""Regression oracles for selected WorkUnit meaning and verification scope."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'aide_lite_task_binding', Path(__file__).resolve().parents[1] / 'aide_lite.py')
aide = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aide
SPEC.loader.exec_module(aide)


class SelectedTaskBinding(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.selected = 'AIDE-FOCUSED-01'
        self.other = 'AIDE-OTHER-01'
        index = 'schema_version: aide.queue-index.v0\nitems:\n'
        for task, paths in ((self.selected, ['source/selected/**']),
                            (self.other, ['source/**'])):
            index += (f'  - id: {task}\n    status: running\n'
                      f'    task: .aide/queue/{task}/task.yaml\n')
            aide.write_text(self.root / f'.aide/queue/{task}/task.yaml',
                            f'id: {task}\ntitle: Useful bounded change\n'
                            'scope:\n  allowed_paths:\n' +
                            ''.join(f'    - {value}\n' for value in paths) +
                            '  forbidden_paths:\n    - .aide.local/**\n')
        aide.write_text(self.root / '.aide/queue/index.yaml', index)
        self.packet(self.selected)

    def packet(self, identity, *, path=None, suffix=''):
        path = path or aide.LATEST_PACKET_PATH
        aide.write_text(self.root / path,
                        '# Task\n\ntask_id: ' + identity +
                        '\n\n## PHASE\n\nBounded work\n\n## GOAL\n\nUseful work\n' + suffix)
        return path

    def report(self, packet=None):
        with patch.object(aide, 'git_status_short', return_value=(True, [
                (' M', 'source/selected/helper.py'), (' M', 'source/other/helper.py')], '')):
            return aide.build_verification_report(
                self.root, task_packet_path=packet, changed_files_only=True)

    def test_named_packet_projects_identity_refs_and_actual_scope(self):
        packet = aide.build_task_packet(self.root, self.selected).text
        self.assertIn('task_id: ' + self.selected, packet)
        self.assertIn(f'.aide/queue/{self.selected}/task.yaml', packet)
        allowed = packet.split('## ALLOWED_PATHS\n', 1)[1].split('## FORBIDDEN_PATHS', 1)[0]
        self.assertIn('source/selected/**', allowed)
        self.assertNotIn('source/**', allowed)
        self.assertNotIn('<fill', allowed)
        self.assertNotIn('UNSPECIFIED', packet)

    def test_default_verification_uses_selected_task_not_last_active(self):
        classifications = {item.path: item.classification for item in self.report().changed_files}
        self.assertEqual(classifications['source/selected/helper.py'], 'allowed')
        self.assertEqual(classifications['source/other/helper.py'], 'unknown')

    def test_explicit_packet_overrides_latest_task_for_scope(self):
        explicit = self.packet(self.selected, path='.aide/context/chosen.md')
        self.packet(self.other)
        classifications = {item.path: item.classification for item in self.report(explicit).changed_files}
        self.assertEqual(classifications['source/other/helper.py'], 'unknown')

    def test_incidental_later_q_identifier_does_not_replace_declared_task(self):
        self.packet(self.selected, suffix='\n## EVIDENCE\n\nOld Q20 examples are context.\n')
        self.assertEqual(aide.current_task_id(self.root), self.selected)

    def test_unknown_explicit_identity_refuses_scope_fallback(self):
        self.packet('AIDE-MISSING-01')
        report = self.report()
        self.assertEqual(report.result, 'FAIL')
        self.assertTrue(any(f.severity == 'ERROR' and f.check == 'diff_scope' for f in report.findings))
        self.assertFalse(any(item.classification == 'allowed' for item in report.changed_files))

    def test_escaping_explicit_identity_refuses_scope_fallback(self):
        self.packet('../../outside')
        self.assertEqual(self.report().result, 'FAIL')

    def test_unknown_named_task_refuses_before_packet_write(self):
        before = (self.root / aide.LATEST_PACKET_PATH).read_bytes()
        with self.assertRaises(ValueError):
            aide.write_task_packet(self.root, 'AIDE-MISSING-01')
        self.assertEqual((self.root / aide.LATEST_PACKET_PATH).read_bytes(), before)

    def test_legacy_phase_declaration_selects_named_task(self):
        aide.write_text(self.root / aide.LATEST_PACKET_PATH,
                        '# Task\n\n## PHASE\n\nphase: ' + self.selected +
                        '\n\n## GOAL\n\nUseful work\n')
        classifications = {item.path: item.classification for item in self.report().changed_files}
        self.assertEqual(classifications['source/other/helper.py'], 'unknown')

    def test_named_packet_repeated_render_is_deterministic(self):
        self.assertEqual(aide.build_task_packet(self.root, self.selected).text,
                         aide.build_task_packet(self.root, self.selected).text)

    def test_empty_or_conflicting_declaration_refuses_scope_fallback(self):
        for identity in ['', self.selected + '\nphase: ' + self.other]:
            with self.subTest(identity=identity):
                self.packet(identity)
                self.assertEqual(self.report().result, 'FAIL')

    def test_missing_explicit_packet_refuses_scope_fallback(self):
        self.assertEqual(self.report('.aide/context/missing.md').result, 'FAIL')

    def test_invalid_identity_fails_even_without_git_observations(self):
        self.packet('AIDE-MISSING-01')
        with patch.object(aide, 'git_status_short', return_value=(False, [], 'unavailable')):
            report = aide.build_verification_report(self.root, changed_files_only=True)
        self.assertEqual(report.result, 'FAIL')

    def test_review_evidence_uses_the_same_selected_workunit(self):
        self.assertEqual(aide.default_evidence_dir(self.root),
                         f'.aide/queue/{self.selected}/evidence')

    def test_mismatched_task_owner_refuses_scope_fallback(self):
        path = self.root / f'.aide/queue/{self.selected}/task.yaml'
        aide.write_text(path, aide.read_text(path).replace('id: ' + self.selected, 'id: ' + self.other))
        self.assertEqual(self.report().result, 'FAIL')

    def test_named_task_without_scope_refuses_scope_fallback(self):
        aide.write_text(self.root / f'.aide/queue/{self.selected}/task.yaml',
                        'id: ' + self.selected + '\n')
        self.assertEqual(self.report().result, 'FAIL')

    def test_generic_q_inference_compatibility(self):
        self.assertEqual(aide.infer_phase('Implement Q12 Verifier v0'), ('Q12', 'Verifier v0'))

    def test_existing_project_named_queue_id_needs_no_aide_prefix(self):
        name = 'PROJECT-TASK-17'
        aide.write_text(self.root / f'.aide/queue/{name}/task.yaml',
                        f'id: {name}\ntitle: Project-owned task\n'
                        'scope:\n  allowed_paths:\n    - project/**\n')
        packet = aide.build_task_packet(self.root, name).text
        self.assertIn('task_id: ' + name, packet)
        self.assertIn('project/**', packet)

    def context_fixture(self, status='running'):
        aide.write_text(self.root / f'.aide/queue/{self.selected}/status.yaml',
                        f'task_id: {self.selected}\nstatus: {status}\n')
        aide.write_text(self.root / '.aide/queue/Q17-router-profile-v0/status.yaml',
                        'status: passed\n')

    def context_packet(self):
        return aide.build_context_packet(self.root, {}, {}, {})

    def test_context_selected_task_overrides_historical_and_other_active_work(self):
        self.context_fixture()
        text = self.context_packet().text
        self.assertEqual(aide.current_queue_ref(self.root), f'.aide/queue/{self.selected}/')
        self.assertIn(f'selected_task: `{self.selected}`', text)
        self.assertNotIn('Q17-router-profile-v0', text)
        self.assertNotIn(self.other, text)

    def test_context_selection_provenance_matches_current_view(self):
        self.context_fixture()
        view = aide.build_current_task_view(self.root)
        self.assertEqual(view['selection'],
                         {'mode': 'task_packet', 'source': aide.LATEST_PACKET_PATH})
        explicit = aide.build_current_task_view(self.root, self.other)
        self.assertEqual(explicit['selection'], {'mode': 'explicit_request', 'source': 'request'})
        text = self.context_packet().text
        self.assertIn('selection_mode: task_packet', text)
        self.assertIn(f"selection_source: `{view['selection']['source']}`", text)
        self.assertIn('acceptance_verified: false', text)

    def test_context_missing_packet_uses_existing_queue_fallback(self):
        self.context_fixture()
        (self.root / aide.LATEST_PACKET_PATH).unlink()
        view = aide.build_current_task_view(self.root)
        self.assertEqual(view['task_id'], self.other)
        self.assertEqual(view['selection'],
                         {'mode': 'queue_fallback', 'source': '.aide/queue/index.yaml'})
        self.assertIn(f'current_queue_ref: `.aide/queue/{self.other}/`', self.context_packet().text)
        aide.write_text(self.root / '.aide/queue/index.yaml', 'items: []\n')
        self.assertEqual(aide.current_queue_ref(self.root), '.aide/queue/index.yaml')
        self.assertIn('selected_task: `unresolved`', self.context_packet().text)

    def test_context_retains_completed_blocked_and_review_selections(self):
        for status in ['passed', 'passed_with_notes', 'blocked', 'needs_review']:
            with self.subTest(status=status):
                self.context_fixture(status)
                text = self.context_packet().text
                self.assertIn(f'selected_task: `{self.selected}`', text)
                self.assertIn('recorded_status: ' + json.dumps(status), text)
                self.assertIn('index_status_conflict', text)
                self.assertIn('not an active worker or permission', text)
                self.assertNotIn(self.other, text)

    def test_context_legacy_phase_identity_remains_selected(self):
        self.context_fixture()
        aide.write_text(self.root / aide.LATEST_PACKET_PATH,
                        '# Task\n\n## PHASE\n\nphase: ' + self.selected + '\n')
        text = self.context_packet().text
        self.assertIn(f'selected_task: `{self.selected}`', text)
        self.assertIn('selection_mode: task_packet', text)

    def test_context_invalid_selection_exposes_issue_without_historical_fallback(self):
        self.context_fixture()
        for identity in ['AIDE-MISSING-01', '../../outside', '',
                         self.selected + '\nphase: ' + self.other,
                         self.selected + '\n' + 'x' * 131073]:
            with self.subTest(identity=identity[:80]):
                self.packet(identity)
                view = aide.build_current_task_view(self.root)
                self.assertEqual(view['task_id'], '')
                self.assertTrue(view['issues'])
                text = self.context_packet().text
                self.assertIn('current_queue_ref: `.aide/queue/index.yaml`', text)
                self.assertIn('selected_task: `unresolved`', text)
                self.assertNotIn('selection_issues: none', text)
                self.assertNotIn('Q17-router-profile-v0', text)

    def test_context_render_is_deterministic_read_only_and_preserves_accounting(self):
        self.context_fixture()
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        packet = self.context_packet()
        self.assertEqual(packet.text, self.context_packet().text)
        for section in aide.CONTEXT_PACKET_REQUIRED_SECTIONS:
            self.assertIn(f'## {section}', packet.text)
        self.assertEqual(packet.stats.chars, len(packet.text))
        self.assertEqual(packet.stats.approx_tokens, (len(packet.text) + 3) // 4)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes()
                                 for p in self.root.rglob('*') if p.is_file()})

    def test_actual_context_cli_preserves_selected_task_and_history(self):
        self.context_fixture('blocked')
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        command = [sys.executable, '-B', str(Path(aide.__file__).resolve()),
                   '--repo-root', str(self.root)]
        completed = subprocess.run(command + ['context'], capture_output=True, text=True,
                                   encoding='utf-8', timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        text = (self.root / aide.LATEST_CONTEXT_PACKET_PATH).read_text(encoding='utf-8')
        self.assertIn(f'current_queue_ref: `.aide/queue/{self.selected}/`', text)
        self.assertIn('recorded_status: "blocked"', text)
        self.assertIn(f'chars: {len(text)}', completed.stdout)
        for section in aide.CONTEXT_PACKET_REQUIRED_SECTIONS:
            self.assertIn(f'## {section}', text)
        current = subprocess.run(command + ['task', 'current', '--json'], capture_output=True,
                                 text=True, encoding='utf-8', timeout=30)
        view = json.loads(current.stdout)
        self.assertEqual(view['task_id'], self.selected)
        self.assertEqual(view['status'], 'blocked')
        self.assertEqual(view['selection']['mode'], 'task_packet')
        for relative, data in before.items():
            self.assertEqual((self.root / relative).read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
