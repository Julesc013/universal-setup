"""Regression oracles for selected WorkUnit meaning and verification scope."""
from __future__ import annotations

import importlib.util
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
