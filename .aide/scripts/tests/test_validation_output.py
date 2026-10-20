"""Presentation must preserve the complete validator result and its exit status."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / '.aide/scripts/aide_lite.py'
spec = importlib.util.spec_from_file_location('validation_output_aide', CLI)
aide = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = aide
spec.loader.exec_module(aide)


class ValidationOutputTests(unittest.TestCase):
    def render(self, messages, ok=True, **options):
        stream = io.StringIO()
        with mock.patch.object(aide, 'validate_repo', return_value=(ok, messages)) as collect:
            with contextlib.redirect_stdout(stream):
                code = aide.command_validate(argparse.Namespace(repo_root=ROOT, **options))
        collect.assert_called_once_with(ROOT)
        return code, stream.getvalue()

    def test_compact_keeps_all_nonpass_findings_and_counts(self):
        messages = ['PASS first', 'WARN uncertain', 'FAIL missing', 'WARN uncertain',
                    'UNKNOWN future', '', 'PASSAGE is not PASS', 'PASS last']
        code, text = self.render(messages, False)
        self.assertEqual(code, 1)
        self.assertIn('checks: 8; PASS: 2; WARN: 2; FAIL: 1; OTHER: 3', text)
        self.assertEqual([line[2:] for line in text.splitlines() if line.startswith('- ')],
                         messages[1:-1])
        self.assertNotIn('- PASS first', text)
        self.assertIn('use validate --full or --json', text)

    def test_full_is_exact_legacy_text_for_success_and_failure(self):
        messages = ['PASS first', 'WARN same', 'WARN same', 'FAIL bad\n  detail', '']
        for ok in (True, False):
            with self.subTest(ok=ok):
                expected = io.StringIO()
                with contextlib.redirect_stdout(expected):
                    code = aide.print_messages('AIDE Lite validate', ok, messages)
                self.assertEqual(self.render(messages, ok, full=True), (code, expected.getvalue()))

    def test_json_is_lossless_ordered_and_versioned(self):
        messages = ['PASS first', 'WARN café\n  日本語', 'WARN café\n  日本語', '', 'NOTE future']
        code, text = self.render(messages, json=True)
        data = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(data, {'schema': 'aide.validation-result.v1', 'status': 'PASS',
                               'total': 5, 'counts': {'PASS': 1, 'WARN': 2, 'FAIL': 0, 'OTHER': 2},
                               'messages': messages})
        self.assertEqual(len(text.splitlines()), 1)

    def test_empty_result_is_explicit_without_invented_findings(self):
        code, text = self.render([])
        self.assertEqual(code, 0)
        self.assertIn('checks: 0; PASS: 0; WARN: 0; FAIL: 0; OTHER: 0', text)
        self.assertEqual(json.loads(self.render([], json=True)[1])['messages'], [])

    def test_all_modes_preserve_validator_failure_even_without_messages(self):
        for options in ({}, {'full': True}, {'json': True}):
            with self.subTest(options=options):
                code, text = self.render([], False, **options)
                self.assertEqual(code, 1)
                self.assertIn('FAIL', text)

    def test_large_pass_list_does_not_hide_late_failure_or_warning(self):
        messages = ['PASS repeated'] * 61000 + ['WARN retained', 'FAIL final']
        code, text = self.render(messages, False)
        self.assertEqual(code, 1)
        self.assertLess(len(text), 400)
        self.assertIn('checks: 61002; PASS: 61000; WARN: 1; FAIL: 1', text)
        self.assertIn('- WARN retained\n- FAIL final\n', text)

    def test_multiline_nonpass_details_are_not_truncated(self):
        message = 'FAIL first\n  explanation\n  another detail'
        self.assertIn('- ' + message + '\n', self.render([message], False)[1])

    def test_parser_rejects_combined_modes(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            aide.build_parser(ROOT).parse_args(['validate', '--full', '--json'])
        self.assertEqual(error.exception.code, 2)

    def test_actual_cli_modes_agree_on_valid_and_broken_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'AGENTS.md').write_text('# Project instructions\n', encoding='utf-8')
            # An ordinary project owns its memory and has no AIDE-source phase
            # markers. The source selftest helper seeds unrelated phase reports.
            for relative in aide.REQUIRED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if relative.startswith('.aide/memory/'):
                    destination.write_text('# Project fixture\n', encoding='utf-8')
                else:
                    destination.write_bytes((ROOT / relative).read_bytes())
            def inventory():
                return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in root.rglob('*') if p.is_file()}
            for broken in (False, True):
                with self.subTest(broken=broken):
                    if broken:
                        (root / '.aide/prompts/compact-task.md').write_text('# Broken\n', encoding='utf-8')
                    before = inventory()
                    results = {}
                    for mode in ((), ('--full',), ('--json',)):
                        results[mode] = subprocess.run(
                            [sys.executable, '-I', '-B', str(CLI), '--repo-root', str(root), 'validate', *mode],
                            cwd=root, capture_output=True, text=True, encoding='utf-8', timeout=30)
                    data = json.loads(results[('--json',)].stdout)
                    expected_code = 1 if broken else 0
                    self.assertEqual([r.returncode for r in results.values()], [expected_code] * 3, data)
                    self.assertTrue(all(not r.stderr for r in results.values()))
                    expected_full = 'AIDE Lite validate\nstatus: ' + data['status'] + '\n'
                    expected_full += ''.join('- ' + m + '\n' for m in data['messages'])
                    self.assertEqual(results[('--full',)].stdout, expected_full)
                    self.assertEqual([line[2:] for line in results[()].stdout.splitlines() if line.startswith('- ')],
                                     [m for m in data['messages'] if not m.startswith('PASS ')])
                    self.assertEqual(sum(data['counts'].values()), data['total'])
                    if broken:
                        self.assertIn('FAIL compact task missing section: GOAL', data['messages'])
                    self.assertEqual(inventory(), before)


if __name__ == '__main__':
    unittest.main()
