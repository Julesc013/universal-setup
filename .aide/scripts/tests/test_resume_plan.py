"""Continuation advice must preserve evidence without granting execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'aide_lite_resume_plan', Path(__file__).resolve().parents[1] / 'aide_lite.py')
aide = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aide
SPEC.loader.exec_module(aide)


class ResumePlan(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task = 'PROJECT-RESUME-01'
        self.base = '.aide/queue/' + self.task
        self.write(self.base + '/task.yaml', f'id: {self.task}\ntitle: Resume useful work\n')
        self.write(aide.LATEST_PACKET_PATH, f'task_id: {self.task}\n')
        self.status('running')

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding='utf-8', newline='\n')
        return path

    def status(self, status, extra=''):
        self.write(self.base + '/status.yaml', f'task_id: {self.task}\nstatus: {status}\n' + extra)

    def command(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = aide.main(['--repo-root', str(self.root), 'task', 'resume-plan', *args])
        return code, output.getvalue()

    def plan(self):
        code, text = self.command('--json')
        self.assertEqual(code, 0)
        return json.loads(text)

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob('*') if p.is_file()}

    def test_json_leaves_all_inputs_and_old_report_untouched(self):
        self.write(aide.TASK_OS_RESUME_PLAN_REPORT_PATH, 'retained old report\n')
        before = self.snapshot()
        data = self.plan()
        self.assertTrue(data['read_only'])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(data, self.plan())

    def test_no_known_state_or_unknown_state_grants_execution(self):
        for status in ('pending', 'planning', 'claimed', 'running', 'blocked', 'paused',
                       'deferred', 'failed', 'interrupted', 'needs_review', 'passed',
                       'passed_with_notes', 'complete', 'completed', 'superseded', 'other'):
            with self.subTest(status=status):
                self.status(status)
                data = self.plan()
                self.assertIsNone(data['safe_to_resume'])
                self.assertFalse(data['execution_admitted'])
                self.assertFalse(data['task']['acceptance_verified'])
        self.assertEqual(data['recommendation'], 'reconcile_records')

    def test_named_identity_survives_a_different_or_invalid_latest_packet(self):
        for packet in ('task_id: OTHER\n', 'task_id: ../../outside\n'):
            self.write(aide.LATEST_PACKET_PATH, packet)
            code, text = self.command('--task-id', self.task, '--json')
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(text)['task']['task_id'], self.task)
        self.assertEqual(self.command('--json')[0], 1)

    def test_completed_outcome_keeps_remaining_consumer_obligations(self):
        self.status('passed', 'result: PASS_PREPARATION\nproduct_qualified: false\n'
                    'remaining_obligations:\n  - native_adoption\nnext_action: inspect_native_owner\n')
        data = self.plan()
        self.assertEqual(data['recommendation'], 'inspect_completed_evidence')
        self.assertEqual(data['task']['remaining_obligations'], ['native_adoption'])
        self.assertEqual(data['task']['result'], 'PASS_PREPARATION')
        self.assertFalse(data['task']['scope']['product_qualified'])

    def test_completed_receipt_and_original_failure_remain_distinct(self):
        self.write(self.base + '/first.json', '{"result":"FAIL"}\n')
        receipt = '{"effect":"completed","source":"old"}\n'
        self.write(self.base + '/second.json', receipt)
        self.status('interrupted', 'original_ref: first.json\ncompleted_ref: second.json\n'
                    'completed_sha256: ' + hashlib.sha256(receipt.encode()).hexdigest() + '\n'
                    'remaining_obligations:\n  - inspect_uncertain_effect\n')
        before = self.snapshot()
        data = self.plan()
        self.assertEqual(data['recommendation'], 'reconcile_attempt')
        refs = {e['field']: e for e in data['task']['evidence']}
        self.assertEqual(len(refs), 2)
        self.assertTrue(refs['completed_ref']['digest_verified'])
        self.assertEqual(refs['completed_ref']['applicability'], 'unverified')
        self.assertEqual(before, self.snapshot())

    def test_blocker_owner_and_next_action_remain_attributed(self):
        self.status('blocked', 'owner: project_owner\nblocking_input: existing_session_binding\n'
                    'next_action: inspect_binding_after_change\n')
        data = self.plan()
        self.assertEqual(data['recommendation'], 'inspect_unblock_condition')
        self.assertEqual(data['task']['remaining_obligations'], 'existing_session_binding')
        self.assertEqual(data['task']['owner'], 'project_owner')
        self.assertEqual(data['task']['sources']['next_action'], self.base + '/status.yaml')

    def test_passing_test_result_does_not_close_review(self):
        self.status('needs_review', 'result: PASS\n')
        self.assertEqual(self.plan()['recommendation'], 'inspect_review_gate')

    def test_missing_or_modified_evidence_requires_reconciliation(self):
        self.status('passed', 'result_ref: absent.json\n')
        self.assertEqual(self.plan()['recommendation'], 'reconcile_records')
        self.write(self.base + '/absent.json', 'changed')
        self.status('passed', 'result_ref: absent.json\nresult_sha256: ' + '0' * 64 + '\n')
        data = self.plan()
        self.assertEqual(data['recommendation'], 'reconcile_records')
        self.assertEqual(data['task']['evidence'][0]['availability'], 'digest_mismatch')

    def test_conflicting_records_cannot_become_a_completed_recommendation(self):
        self.status('passed', 'status: failed\n')
        self.assertEqual(self.plan()['recommendation'], 'reconcile_records')
        self.status('passed')
        self.write('.aide/queue/index.yaml', f'items:\n  - id: {self.task}\n    status: running\n')
        self.assertEqual(self.plan()['recommendation'], 'reconcile_records')

    def test_missing_identity_exits_one_without_json_writes(self):
        before = self.snapshot()
        for identity in ('MISSING', '../../outside', ''):
            code, text = self.command('--task-id', identity, '--json')
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(text)['recommendation'], 'reconcile_records')
        self.assertEqual(before, self.snapshot())

    def test_legacy_report_uses_actual_task_and_affected_checks(self):
        code, output = self.command()
        self.assertEqual(code, 0)
        self.assertIn('safe_to_resume: unknown', output)
        report = (self.root / aide.TASK_OS_RESUME_PLAN_REPORT_PATH).read_text(encoding='utf-8')
        self.assertIn(self.base + '/status.yaml', report)
        self.assertIn('reconcile_attempt', report)
        self.assertIn('Safe To Resume', report)
        self.assertIn('task_execution: false', report)
        self.assertIn('affected required checks', report)
        for text in ('X-OS-01', 'safe_to_resume: true', 'all Task OS report-only commands'):
            self.assertNotIn(text, report + output)

    def test_legacy_callable_writer_returns_selected_identity(self):
        self.write(aide.LATEST_PACKET_PATH, 'task_id: OTHER\n')
        result, context = aide.write_task_os_resume_plan(self.root, self.task)
        self.assertEqual(context['latest_task_id'], self.task)
        self.assertTrue((self.root / aide.TASK_OS_RESUME_PLAN_REPORT_PATH).exists())


if __name__ == '__main__':
    unittest.main()
