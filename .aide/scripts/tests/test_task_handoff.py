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


if __name__ == '__main__':
    unittest.main()
