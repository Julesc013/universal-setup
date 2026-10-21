"""Task interchange preserves unfinished work without importing its authority."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'aide_lite_handoff_test', Path(__file__).resolve().parents[1] / 'aide_lite.py')
aide = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aide
SPEC.loader.exec_module(aide)
codec = aide.task_handoff_codec()


class TaskHandoff(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.task = 'PROJECT-CONTINUE-01'
        self.paths = codec.record_paths(self.task)
        self.write(self.paths[0], ('\ufeffid: ' + self.task + '\r\ntitle: Continue useful work\r\n'
                                  'project_extension:\r\n  preserve: café\r\n').encode('utf-8'))
        self.write(self.paths[1], b'status: interrupted\nresult: INCOMPLETE\n'
                   b'remaining_obligations:\n  - reconcile_attempt\n  - validate_consumer\n')
        self.write(self.paths[2], b'# Continuation\nAttempt 1 failed; attempt 2 interrupted.\n'
                   b'Completed effect: local patch. Uncertain effect: push.\nDo not repeat blindly.\n')

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob('*') if p.is_file()}

    def command(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = aide.main(['--repo-root', str(self.root), 'task', 'handoff', *args])
        return code, out.getvalue(), err.getvalue()

    def exported(self):
        code, text, err = self.command('export', '--task-id', self.task)
        self.assertEqual(code, 0, err)
        return text.encode('ascii')

    def inspect(self, raw=None):
        raw = self.exported() if raw is None else raw
        self.write('handoff.json', raw)
        code, text, err = self.command('inspect', '--bundle', 'handoff.json',
                                      '--sha256', codec.sha(raw), '--json')
        self.assertEqual(code, 0, err)
        return json.loads(text)

    def test_original_bytes_and_unknown_task_fields_survive(self):
        before = self.snapshot()
        bundle = codec.decode(self.exported(), codec.sha(self.exported()))
        for path in self.paths:
            self.assertEqual(bundle['records'][path]['text'].encode('utf-8'), before[path])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(bundle['continuation']['recommendation'], 'reconcile_attempt')
        self.assertEqual(bundle['continuation']['task']['remaining_obligations'],
                         ['reconcile_attempt', 'validate_consumer'])

    def test_inspection_is_read_only_and_not_admission(self):
        raw = self.exported()
        self.write('handoff.json', raw)
        before = self.snapshot()
        result = self.inspect(raw)
        self.assertEqual(before, self.snapshot())
        self.assertEqual([x['comparison'] for x in result['records']], ['matching'] * 3)
        for key in ('execution_admitted', 'authorship_verified', 'evidence_applicability_verified'):
            self.assertIs(result[key], False)
        self.assertIsNone(result['safe_to_resume'])

    def test_changed_and_missing_local_records_are_distinct(self):
        raw = self.exported()
        self.write(self.paths[1], b'status: passed\n')
        (self.root / self.paths[2]).unlink()
        self.assertEqual([x['comparison'] for x in self.inspect(raw)['records']],
                         ['matching', 'changed', 'missing'])

    def test_missing_optional_records_remain_missing(self):
        for path in self.paths[1:]:
            (self.root / path).unlink()
        raw = self.exported()
        self.write(self.paths[1], b'status: planning\n')
        self.assertEqual([x['comparison'] for x in self.inspect(raw)['records']],
                         ['matching', 'not_captured', 'missing_in_both'])

    def test_missing_or_mismatched_identity_refuses(self):
        for content in (None, b'id: OTHER\n', b'id: X\nid: PROJECT-CONTINUE-01\n'):
            with self.subTest(content=content):
                if content is None:
                    (self.root / self.paths[0]).unlink()
                else:
                    self.write(self.paths[0], content)
                self.assertEqual(self.command('export', '--task-id', self.task)[0], 1)

    def test_status_identity_mismatch_refuses(self):
        self.write(self.paths[1], b'id: OTHER\nstatus: passed\n')
        self.assertEqual(self.command('export', '--task-id', self.task)[0], 1)

    def test_unsafe_task_ids_refuse(self):
        for identity in ('../outside', 'X/Y', 'X\\Y', 'C:secret', 'X.', 'X' * 161):
            with self.subTest(identity=identity):
                self.assertEqual(self.command('export', '--task-id', identity)[0], 1)

    def test_optional_json_roundtrips_and_required_semantics_refuse(self):
        bundle = json.loads(self.exported())
        bundle['future'] = {'nested': [1, 'retain', None]}
        bundle['records'][self.paths[0]]['extension'] = {'retain': True}
        raw = codec.encode(bundle)
        self.assertEqual(codec.decode(raw, codec.sha(raw)), bundle)
        for change in ({'required_features': ['observational_only', 'future']},
                       {'schema_version': 'aide.task-handoff.v99'},
                       {'execution_admitted': True}, {'read_only': False}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                codec.encode({**bundle, **change})

    def test_wrong_digest_and_altered_content_refuse(self):
        raw = self.exported()
        with self.assertRaises(ValueError):
            codec.decode(raw, '0' * 64)
        bundle = json.loads(raw)
        bundle['records'][self.paths[1]]['text'] = 'status: passed\n'
        raw = json.dumps(bundle).encode()
        with self.assertRaises(ValueError):
            codec.decode(raw, codec.sha(raw))

    def test_duplicate_nonfinite_deep_oversized_invalid_json_refuses(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
                    b'[' * 1000 + b']' * 1000, b'x' * (codec.MAX_BUNDLE + 1), b'\xff', b'null'):
            with self.subTest(prefix=raw[:20]), self.assertRaises(ValueError):
                codec.decode(raw, codec.sha(raw))

    def test_record_set_and_identity_substitution_refuse(self):
        bundle = json.loads(self.exported())
        bundle['records']['../outside'] = bundle['records'].pop(self.paths[0])
        with self.assertRaises(ValueError):
            codec.encode(bundle)
        bundle = json.loads(self.exported())
        bundle['records'][self.paths[0]] = codec.record(b'id: OTHER\n')
        raw = codec.encode(bundle)
        self.write('handoff.json', raw)
        self.assertEqual(self.command('inspect', '--bundle', 'handoff.json',
                         '--sha256', codec.sha(raw), '--json')[0], 1)

    def test_record_size_and_encoding_refuse_without_partial_export(self):
        for raw in (b'x' * (codec.MAX_RECORD + 1), b'\xff'):
            self.write(self.paths[2], raw)
            code, text, _ = self.command('export', '--task-id', self.task)
            self.assertEqual((code, text), (1, ''))

    def test_secret_like_content_refuses_without_echo(self):
        # Construct a synthetic detector fixture, never an actual credential.
        self.write(self.paths[2], ('sk-' + 'x' * 32).encode())
        code, text, err = self.command('export', '--task-id', self.task)
        self.assertEqual((code, text), (1, ''))
        self.assertNotIn('x' * 32, err)

    def test_hardlinked_records_refuse(self):
        linked = self.root / 'linked.txt'
        os.link(self.root / self.paths[2], linked)
        self.assertEqual(self.command('export', '--task-id', self.task)[0], 1)

    def test_changed_during_export_refuses(self):
        original = aide.build_task_resume_plan
        def changed(*args):
            result = original(*args)
            self.write(self.paths[2], b'changed after observation\n')
            return result
        with patch.object(aide, 'build_task_resume_plan', side_effect=changed):
            self.assertEqual(self.command('export', '--task-id', self.task)[0], 1)

    def test_unsafe_bundle_path_refuses(self):
        raw = self.exported()
        self.write('.aide.local/handoff.json', raw)
        for path in ('../outside.json', '.aide.local/handoff.json', 'C:/outside.json'):
            self.assertEqual(self.command('inspect', '--bundle', path,
                             '--sha256', codec.sha(raw))[0], 1)

    def test_unsafe_receiver_record_is_not_missing_or_matching(self):
        raw = self.exported()
        os.link(self.root / self.paths[2], self.root / 'linked.txt')
        self.assertEqual(self.inspect(raw)['records'][2]['comparison'], 'unsafe_or_unreadable')

    def test_ordinary_process_does_not_write_bytecode_on_success_or_refusal(self):
        cli = self.write('.aide/scripts/aide_lite.py', Path(aide.__file__).read_bytes())
        self.write('.aide/scripts/task_handoff.py', Path(codec.__file__).read_bytes())
        before = self.snapshot()
        env = {key: value for key, value in os.environ.items()
               if key.upper() != 'PYTHONDONTWRITEBYTECODE'}
        for identity, code in ((self.task, 0), ('../outside', 1)):
            result = subprocess.run([sys.executable, '-I', str(cli), '--repo-root', str(self.root),
                                     'task', 'handoff', 'export', '--task-id', identity],
                                    env=env, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertEqual(before, self.snapshot())
        self.assertFalse((cli.parent / '__pycache__').exists())

    def test_redirected_or_multiply_linked_helper_never_executes(self):
        cli = self.root / '.aide/scripts/aide_lite.py'
        helper = self.write('.aide/scripts/task_handoff.py', b'raise RuntimeError("sentinel executed")\n')
        with patch.object(aide, '__file__', str(cli)):
            os.link(helper, self.root / 'helper-link.py')
            with self.assertRaises(ValueError):
                aide.task_handoff_codec()
            (self.root / 'helper-link.py').unlink()
            original = Path.lstat
            def redirected(path):
                info = original(path)
                if path == helper:
                    from types import SimpleNamespace
                    return SimpleNamespace(st_mode=info.st_mode, st_nlink=1,
                                           st_size=info.st_size, st_file_attributes=0x400)
                return info
            with patch.object(Path, 'lstat', redirected), self.assertRaises(ValueError):
                aide.task_handoff_codec()

    def test_actual_cli_fresh_process_handoff(self):
        cli = str(Path(aide.__file__).resolve())
        prefix = [sys.executable, '-I', '-B', cli, '--repo-root', str(self.root), 'task', 'handoff']
        result = subprocess.run(prefix + ['export', '--task-id', self.task], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write('handoff.json', result.stdout)
        before = self.snapshot()
        inspected = subprocess.run(prefix + ['inspect', '--bundle', 'handoff.json',
                                    '--sha256', codec.sha(result.stdout), '--json'],
                                   capture_output=True, timeout=15)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertEqual(json.loads(inspected.stdout)['task_id'], self.task)
        self.assertEqual(before, self.snapshot())



class OfflineResults(unittest.TestCase):
    setUp = TaskHandoff.setUp
    write = TaskHandoff.write
    snapshot = TaskHandoff.snapshot
    command = TaskHandoff.command

    def request(self):
        self.write('src/owner.py', b'def total(a, b):\r\n    return a - b\r\n')
        code, text, err = self.command('export', '--task-id', self.task, '--input', 'src/owner.py')
        self.assertEqual(code, 0, err)
        raw = text.encode('ascii')
        self.write('request.json', raw)
        return raw

    def reply(self, request, outcome='submitted', attempt='attempt-1'):
        self.write('report.txt', '\ufeffRepair candidate; caf\u00e9\r\n'.encode('utf-8'))
        self.write('candidate.patch', b'-    return a - b\n+    return a + b\n')
        self.write('checks.json', b'{"result":"PASS","coverage":"selected cases only"}\n')
        code, text, err = self.command(
            'result-export', '--request', 'request.json', '--request-sha256', codec.sha(request),
            '--attempt-id', attempt, '--outcome', outcome, '--report', 'report.txt',
            '--patch', 'candidate.patch', '--checks', 'checks.json')
        self.assertEqual(code, 0, err)
        raw = text.encode('ascii')
        self.write('result.json', raw)
        return raw

    def inspect_result(self, request, result, expected=0):
        code, text, err = self.command(
            'result-inspect', '--request', 'request.json', '--request-sha256', codec.sha(request),
            '--result', 'result.json', '--result-sha256', codec.sha(result), '--json')
        self.assertEqual(code, expected, err)
        if expected:
            self.assertEqual(text, '')
            return None
        return json.loads(text)

    def test_default_remains_v1_and_selected_inputs_make_v2(self):
        code, text, err = self.command('export', '--task-id', self.task)
        self.assertEqual(code, 0, err)
        old = json.loads(text)
        new = json.loads(self.request())
        self.assertEqual(old['schema_version'], 'aide.task-handoff.v1')
        self.assertNotIn('inputs', old)
        self.assertEqual(new['schema_version'], 'aide.task-handoff.v2')
        self.assertEqual(new['records'], old['records'])
        self.assertIn('selected_input_sha256', new['required_features'])

    def test_request_and_result_preserve_bytes_without_writes(self):
        request = self.request()
        result = self.reply(request)
        before = self.snapshot()
        observed = self.inspect_result(request, result)
        self.assertEqual(observed['selected_input_state'], 'matching')
        self.assertEqual(observed['source_commit_comparison'], 'unknown')
        self.assertEqual(observed['captured_result']['artifacts']['report']['text'].encode('utf-8'),
                         before['report.txt'])
        self.assertEqual(json.loads(request)['inputs']['src/owner.py']['text'].encode(),
                         before['src/owner.py'])
        self.assertEqual(observed['captured_result']['artifacts']['patch']['text'].encode(),
                         before['candidate.patch'])
        for key in ('execution_admitted', 'accepted', 'authorship_verified', 'evidence_applicability_verified'):
            self.assertIs(observed[key], False)
        self.assertIsNone(observed['safe_to_apply'])
        self.assertEqual(before, self.snapshot())
        self.assertTrue(request.isascii() and result.isascii())

    def test_failed_and_interrupted_outputs_remain_candidates(self):
        request = self.request()
        for outcome in ('failed', 'interrupted', 'submitted'):
            result = self.reply(request, outcome, 'attempt-' + outcome)
            data = self.inspect_result(request, result)
            self.assertEqual(data['recorded_outcome'], outcome)
            self.assertEqual(data['attempt_id'], 'attempt-' + outcome)
            self.assertFalse(data['accepted'])
            self.assertIn('patch', data['captured_result']['artifacts'])

    def test_declared_inputs_and_task_changes_are_distinct(self):
        request = self.request()
        result = self.reply(request)
        self.write(self.paths[1], b'status: running\n')
        data = self.inspect_result(request, result)
        self.assertEqual(data['records'][1]['comparison'], 'changed')
        self.assertEqual(data['selected_input_state'], 'matching')
        self.write('src/owner.py', b'changed\n')
        self.assertEqual(self.inspect_result(request, result)['selected_input_state'], 'changed')
        (self.root / 'src/owner.py').unlink()
        data = self.inspect_result(request, result)
        self.assertEqual((data['selected_input_state'], data['inputs'][0]['comparison']), ('unavailable', 'missing'))
        self.write('src/owner.py', b'new\n')
        os.link(self.root / 'src/owner.py', self.root / 'alias')
        self.assertEqual(self.inspect_result(request, result)['inputs'][0]['comparison'], 'unsafe_or_unreadable')

    def test_source_revision_comparison_is_separate(self):
        request = self.request()
        original = json.loads(request)
        for source, current, expected in [('a' * 40, 'a' * 40, 'matching'),
                                          ('a' * 40, 'b' * 40, 'different'),
                                          (None, 'a' * 40, 'unknown')]:
            bundle = {**original, 'source': {'git_head': source}}
            request = codec.encode(bundle)
            self.write('request.json', request)
            result = self.reply(request)
            with patch.object(aide, 'safe_git_head_commit', return_value=current):
                data = self.inspect_result(request, result)
            self.assertEqual(data['source_commit_comparison'], expected)
            self.assertIsNone(data['safe_to_apply'])

    def test_wrong_request_task_and_provenance_refuse(self):
        request = self.request()
        result = json.loads(self.reply(request))
        for change in ({'task_id': 'another-task'}, {'source': {'git_head': 'a' * 40}},
                       {'request_sha256': '1' * 64}, {'schema_version': codec.SCHEMA}):
            changed = json.dumps({**result, **change}).encode()
            self.write('result.json', changed)
            self.inspect_result(request, changed, expected=1)

    def test_corrupt_or_partial_transfer_refuses_even_with_new_outer_digest(self):
        request = self.request()
        result = self.reply(request)
        changed = json.loads(result)
        changed['artifacts']['patch']['text'] += 'altered'
        variants = [result[:-10], b'\xff', json.dumps(changed).encode(),
                    result.replace(b'"accepted":false', b'"accepted":false,"accepted":false'),
                    b'[' * 1000 + b']' * 1000]
        for raw in variants:
            with self.subTest(raw=raw[:30]):
                self.write('result.json', raw)
                self.inspect_result(request, raw, expected=1)
        self.write('result.json', result)
        self.write('request.json', request[:-10])
        self.inspect_result(request, result, expected=1)

    def test_required_features_refuse_and_optional_data_roundtrips(self):
        request = json.loads(self.request())
        request['extension'] = {'future': ['preserved', 1]}
        request['inputs']['src/owner.py']['extension'] = 'kept'
        raw = codec.encode(request)
        self.write('request.json', raw)
        result = json.loads(self.reply(raw))
        result['extension'] = {'future': None}
        result['artifacts']['report']['extension'] = 'kept'
        encoded = codec.encode(result)
        self.assertEqual(codec.decode(encoded, codec.sha(encoded)), result)
        self.write('result.json', encoded)
        self.assertEqual(self.inspect_result(raw, encoded)['captured_result'], result)
        for bundle in (request, result):
            with self.assertRaises(ValueError):
                codec.encode({**bundle, 'required_features': bundle['required_features'] + ['future']})

    def test_forged_acceptance_and_artifact_roles_refuse(self):
        request = self.request()
        result = json.loads(self.reply(request))
        for change in ({'accepted': True}, {'execution_admitted': True}, {'read_only': False},
                       {'outcome': 'accepted'}, {'attempt_id': '../escape'},
                       {'artifacts': {'script': codec.record(b'execute')}},
                       {'artifacts': {'report': codec.record(b'  ')}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                codec.encode({**result, **change})

    def test_input_names_and_count_refuse_ambiguity(self):
        for paths in ([], ['A.py', 'a.py'], ['../outside'], ['/absolute'], ['C:/drive'],
                      ['a\\b'], ['a//b'], ['a.'], ['a '], ['NUL.txt'], ['src/COM1'],
                      ['a\nb'], ['e\u0301.py'], ['a' * 257], ['file' + str(x) for x in range(9)]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                codec.input_paths(paths)
        self.assertEqual(codec.input_paths(['src/caf\u00e9.py']), ['src/caf\u00e9.py'])

    def test_export_refuses_missing_private_linked_or_large_inputs(self):
        self.request()
        for path, raw in [('missing', None), ('.env', b'x'), ('private.txt', ('sk-' + 'z' * 32).encode()),
                          ('big.txt', b'x' * (codec.MAX_RECORD + 1)), ('invalid.txt', b'\xff')]:
            if raw is not None:
                self.write(path, raw)
            code, text, err = self.command('export', '--task-id', self.task, '--input', path)
            self.assertEqual((code, text), (1, ''))
            self.assertNotIn('z' * 32, err)
        os.link(self.root / 'src/owner.py', self.root / 'linked')
        self.assertEqual(self.command('export', '--task-id', self.task, '--input', 'src/owner.py')[0], 1)

    def test_result_export_refuses_invalid_report_without_partial_output(self):
        request = self.request()
        for raw in (b'', b'\xff', b'x' * (codec.MAX_RECORD + 1), ('sk-' + 'z' * 32).encode()):
            self.write('report.txt', raw)
            code, text, err = self.command(
                'result-export', '--request', 'request.json', '--request-sha256', codec.sha(request),
                '--attempt-id', 'a1', '--outcome', 'failed', '--report', 'report.txt')
            self.assertEqual((code, text), (1, ''))
            self.assertNotIn('z' * 32, err)

    def test_changed_input_during_export_refuses(self):
        self.request()
        original = aide.task_handoff_capture
        calls = 0
        def capture(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.write('src/owner.py', b'concurrent edit\n')
            return original(*args)
        with patch.object(aide, 'task_handoff_capture', capture):
            code, text, _ = self.command('export', '--task-id', self.task, '--input', 'src/owner.py')
        self.assertEqual((code, text), (1, ''))

    def test_changed_result_input_during_export_refuses(self):
        request = self.request()
        self.write('report.txt', b'original\n')
        original = aide.task_handoff_capture
        calls = 0
        def capture(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.write('report.txt', b'concurrent edit\n')
            return original(*args)
        with patch.object(aide, 'task_handoff_capture', capture):
            code, text, _ = self.command(
                'result-export', '--request', 'request.json', '--request-sha256', codec.sha(request),
                '--attempt-id', 'a1', '--outcome', 'interrupted', '--report', 'report.txt')
        self.assertEqual((code, text), (1, ''))

    def test_changed_receiver_during_inspection_refuses(self):
        request = self.request()
        result = self.reply(request)
        original = aide.task_handoff_records
        calls = 0
        def records(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                self.write('src/owner.py', b'changed after observation\n')
            return original(*args, **kwargs)
        with patch.object(aide, 'task_handoff_records', records):
            self.inspect_result(request, result, expected=1)

    def test_v1_request_cannot_bind_a_result_and_result_is_not_request(self):
        code, text, _ = self.command('export', '--task-id', self.task)
        self.assertEqual(code, 0)
        self.write('v1.json', text.encode())
        self.write('report.txt', b'answer')
        code, output, _ = self.command(
            'result-export', '--request', 'v1.json', '--request-sha256', codec.sha(text.encode()),
            '--attempt-id', 'a1', '--outcome', 'submitted', '--report', 'report.txt')
        self.assertEqual((code, output), (1, ''))
        request = self.request()
        result = self.reply(request)
        self.assertEqual(self.command('inspect', '--bundle', 'result.json', '--sha256', codec.sha(result))[0], 1)

    def test_fresh_process_replay_is_read_only(self):
        request = self.request()
        result = self.reply(request, 'interrupted')
        cli = self.write('.aide/scripts/aide_lite.py', Path(aide.__file__).read_bytes())
        self.write('.aide/scripts/task_handoff.py', Path(codec.__file__).read_bytes())
        before = self.snapshot()
        prefix = [sys.executable, '-I', str(cli), '--repo-root', str(self.root), 'task', 'handoff']
        arguments = ['result-inspect', '--request', 'request.json', '--request-sha256', codec.sha(request),
                     '--result', 'result.json', '--result-sha256', codec.sha(result), '--json']
        outputs = []
        for _ in range(2):
            completed = subprocess.run(prefix + arguments, capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outputs.append(completed.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(json.loads(outputs[0])['recorded_outcome'], 'interrupted')
        self.assertEqual(before, self.snapshot())

    def test_bounded_report_only_result_and_text_explanation(self):
        request = self.request()
        self.write('report.txt', b'Failed before a patch; preserve this observation.\n')
        code, text, err = self.command(
            'result-export', '--request', 'request.json', '--request-sha256', codec.sha(request),
            '--attempt-id', 'a1', '--outcome', 'failed', '--report', 'report.txt')
        self.assertEqual(code, 0, err)
        result = text.encode()
        self.write('result.json', result)
        self.assertEqual(set(json.loads(result)['artifacts']), {'report'})
        code, text, err = self.command(
            'result-inspect', '--request', 'request.json', '--request-sha256', codec.sha(request),
            '--result', 'result.json', '--result-sha256', codec.sha(result))
        self.assertEqual(code, 0, err)
        self.assertIn('next_action:', text)
        self.assertIn('safe_to_apply: unknown; accepted: false', text)
        self.assertNotIn('Failed before a patch', text)


if __name__ == '__main__':
    unittest.main()
