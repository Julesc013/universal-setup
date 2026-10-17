from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest
import uuid
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from core.execution import managed_workspace as owner
from core.execution.retired_evidence import Custody, PENDING


class CustodyTests(unittest.TestCase):
    def setUp(self):
        parent = owner.root_path(os.environ['AIDE_RESOURCE_TEST_PARENT'])
        self.fixture = parent / ('custody-' + uuid.uuid4().hex)
        self.fixture.mkdir()
        self.addCleanup(self.cleanup)
        self.roots = {v: self.fixture / v for v in ('scratch', 'retained', 'control')}
        for root in self.roots.values():
            root.mkdir()
        (self.roots['control'] / 'admission.lock').write_bytes(b'0')
        self.source = self.fixture / 'source'
        self.source.mkdir()
        self.config = {'schema': 'aide.managed-workspace.local.v1',
            'roots': {k: str(v) for k, v in self.roots.items()},
            'volume_ids': {k: owner.volume_identity(v) for k, v in self.roots.items()},
            'working_roots': [str(self.source)],
            'limits': {'disk_reserve_bytes': 1024, 'physical_reserve_bytes': 1024,
                       'commit_reserve_bytes': 1024, 'scratch_bytes': 1048576,
                       'retained_bytes': 1048576, 'memory_bytes': 134217728,
                       'log_bytes': 4096, 'runtime_seconds': 3, 'processes': 4, 'max_files': 10000},
            'execution_host': {'aggregate_bytes': 32 * 1048576}}
        self.config_path = self.fixture / 'config.json'
        owner.write_json(self.config_path, self.config)
        self.id = uuid.uuid4().hex
        self.root = self.roots['retained'] / self.id
        self.root.mkdir()
        for name in ('logs', 'output', 'output/empty', 'output/nested'):
            (self.root / name).mkdir()
        self.text = b'complete important evidence\n' * 5000
        (self.root / 'logs/stdout').write_bytes(self.text)
        (self.root / 'logs/stderr').write_bytes(b'')
        (self.root / 'output/nested/binary.dat').write_bytes(bytes(range(256)) * 20)
        self.job = {'owner': 'owned-tiny-fixture', 'workunit': 'AIDE-RETIRED-EVIDENCE-CUSTODY-01'}
        self.receipt = {'job_id': self.id, 'manifest_digest': owner.digest(self.job), 'job': self.job,
            'phase': 'retired', 'scratch_absent': True, 'reservation_released': True,
            'result': {'quiescent': True, 'reason': 'exited', 'exit_code': 0},
            'collected_manifest': {v: owner.content_digest(self.root / v) for v in ('logs', 'output')}}
        owner.write_json(self.root / 'owner.json', {'job_id': self.id, 'manifest_digest': owner.digest(self.job)})
        owner.write_json(self.root / 'receipt.json', self.receipt)
        self.raw_receipt = (self.root / 'receipt.json').read_bytes()
        self.raw_owner = (self.root / 'owner.json').read_bytes()
        self.custody = Custody(owner, self.config_path)
        self.native_capacity = {'disk_free': {owner.volume_identity(self.fixture): 2**40},
                                'physical_free': 2**40, 'commit_free': 2**40}
        self.capacity = mock.patch.object(owner, 'capacity', return_value=self.native_capacity)
        self.capacity.start()
        self.addCleanup(self.capacity.stop)

    def cleanup(self):
        resolved = self.fixture.resolve(strict=True)
        if resolved.parent != owner.root_path(os.environ['AIDE_RESOURCE_TEST_PARENT']):
            raise AssertionError('fixture cleanup root changed')
        owner.tree_usage(resolved, maximum=32 * 1048576, max_files=10000)
        shutil.rmtree(resolved)

    def frozen_plan(self):
        return self.custody.plan(self.id)['plan_digest']

    def interrupt(self, boundary):
        def checkpoint(current):
            if current == boundary:
                raise RuntimeError('owned fixture interrupted at ' + current)
        digest = self.frozen_plan()
        with self.assertRaisesRegex(RuntimeError, 'owned fixture interrupted'):
            self.custody.apply(self.id, digest, checkpoint=checkpoint)
        self.assertTrue(self.custody.active.exists())
        return digest

    def assert_closed(self):
        self.assertEqual((self.root / 'receipt.json').read_bytes(), self.raw_receipt)
        self.assertEqual((self.root / 'owner.json').read_bytes(), self.raw_owner)
        self.assertFalse((self.root / 'logs').exists())
        self.assertFalse((self.root / 'output').exists())
        self.assertFalse(self.custody.active.exists())
        self.assertEqual(self.custody.verify(self.id)['plan']['collected_manifest'], self.receipt['collected_manifest'])

    def test_complete_binary_empty_directory_roundtrip_and_receipt_identity(self):
        result = self.custody.apply(self.id, self.frozen_plan())
        self.assertGreater(result['saved_logical_bytes'], 0)
        self.assert_closed()
        manifest = self.custody.verify(self.id)
        self.assertIn('output/empty', {v['path'] for v in manifest['plan']['directories']})
        view = self.custody.read(self.id, 'output/nested/binary.dat', limit=65536)
        self.assertEqual(base64.b64decode(view['slice_base64']), bytes(range(256)) * 20)

    def test_raw_and_custodied_lookup_identical_bounded_slice(self):
        expected = hashlib.sha256(self.text).hexdigest()
        before = self.custody.read(self.id, 'logs/stdout', offset=9, limit=33, expected_sha256=expected)
        self.custody.apply(self.id, self.frozen_plan())
        after = self.custody.read(self.id, 'logs/stdout', offset=9, limit=33, expected_sha256=expected)
        self.assertEqual(after['slice_base64'], before['slice_base64'])
        self.assertEqual(after['sha256'], before['sha256'])
        self.assertEqual(base64.b64decode(after['slice_base64']), self.text[9:42])

    def test_read_survives_unrelated_execution_configuration_change(self):
        self.custody.apply(self.id, self.frozen_plan())
        self.config['limits']['runtime_seconds'] = 4
        owner.write_json(self.config_path, self.config)
        reader = Custody(owner, self.config_path)
        self.assertEqual(reader.verify(self.id)['plan']['anchors']['receipt.json'], hashlib.sha256(self.raw_receipt).hexdigest())
        self.assertEqual(base64.b64decode(reader.read(self.id, 'logs/stdout')['slice_base64']), self.text[:2048])

    def test_pending_intent_recovery(self):
        digest = self.interrupt('intent_persisted')
        self.custody.recover(self.id, digest)
        self.assert_closed()

    def test_complete_intent_staging_recovers_without_new_job(self):
        digest = self.interrupt('intent_persisted')
        staging = self.custody.active.with_name('active.json.next')
        os.rename(self.custody.active, staging)
        self.custody.recover(self.id, digest)
        self.assertFalse(staging.exists())
        self.assert_closed()

    def test_verified_archive_recovery_reuses_exact_archive(self):
        digest = self.interrupt('archive_written')
        archive = owner.file_digest(self.root / 'custody.zip')
        with mock.patch.object(self.custody, 'build', side_effect=AssertionError('archive must be reused')):
            self.custody.recover(self.id, digest)
        self.assertEqual(owner.file_digest(self.root / 'custody.zip'), archive)
        self.assert_closed()

    def test_manifest_boundary_recovery(self):
        digest = self.interrupt('manifest_verified')
        self.custody.recover(self.id, digest)
        self.assert_closed()

    def test_partial_raw_retirement_recovery(self):
        digest = self.interrupt('raw_file_retired')
        self.custody.recover(self.id, digest)
        self.assert_closed()

    def test_after_raw_retirement_recovery_and_repeat_are_idempotent(self):
        digest = self.interrupt('raw_retired')
        self.custody.recover(self.id, digest)
        archive = owner.file_digest(self.root / 'custody.zip')
        self.assertFalse(self.custody.apply(self.id, digest)['writes'])
        self.assertFalse(self.custody.recover(self.id, digest)['writes'])
        self.assertEqual(owner.file_digest(self.root / 'custody.zip'), archive)
        self.assert_closed()

    def test_interrupted_partial_archive_preserves_raw_and_recovers(self):
        digest = self.interrupt('intent_persisted')
        (self.root / 'custody.zip.next').write_bytes(b'partial owned staging')
        self.custody.recover(self.id, digest)
        self.assert_closed()

    def test_stale_plan_preserves_every_original(self):
        digest = self.frozen_plan()
        (self.root / 'logs/stdout').write_bytes(b'changed unique evidence')
        with self.assertRaises(owner.WorkspaceRefused):
            self.custody.apply(self.id, digest)
        self.assertFalse(self.custody.active.exists())
        self.assertEqual((self.root / 'logs/stdout').read_bytes(), b'changed unique evidence')

    def test_unknown_active_and_wrong_owner_refused(self):
        (self.root / 'unknown-source.txt').write_bytes(b'preserve unknown')
        with self.assertRaisesRegex(owner.WorkspaceRefused, 'unknown retained'):
            self.custody.plan(self.id)
        (self.root / 'unknown-source.txt').unlink()
        owner.write_json(self.custody.active, {'job_id': 'other'})
        with self.assertRaisesRegex(owner.WorkspaceRefused, 'existing active'):
            self.custody.plan(self.id)
        self.custody.active.unlink()
        owner.write_json(self.root / 'owner.json', {'job_id': 'other'})
        with self.assertRaisesRegex(owner.WorkspaceRefused, 'only owned'):
            self.custody.plan(self.id)

    def test_nonquiescent_or_live_scratch_refused(self):
        self.receipt['result']['quiescent'] = False
        owner.write_json(self.root / 'receipt.json', self.receipt)
        with self.assertRaises(owner.WorkspaceRefused):
            self.custody.plan(self.id)
        self.receipt['result']['quiescent'] = True
        owner.write_json(self.root / 'receipt.json', self.receipt)
        (self.roots['scratch'] / self.id).mkdir()
        with self.assertRaises(owner.WorkspaceRefused):
            self.custody.plan(self.id)

    def test_hardlinked_original_refused_and_preserved(self):
        alias = self.fixture / 'external-alias'
        os.link(self.root / 'logs/stdout', alias)
        info = alias.lstat()
        identity = (info.st_dev, info.st_ino)
        try:
            with self.assertRaisesRegex(owner.WorkspaceRefused, 'single-link'):
                self.custody.plan(self.id)
            self.assertEqual(alias.read_bytes(), self.text)
        finally:
            # Retire only this exact fixture-created alias even on test failure.
            # A changed identity/content remains preserved for reconciliation.
            current = alias.lstat()
            if (not stat.S_ISREG(current.st_mode) or getattr(current, 'st_file_attributes', 0) & 0x400
                    or (current.st_dev, current.st_ino) != identity or current.st_nlink != 2
                    or current.st_size != len(self.text)
                    or hashlib.sha256(alias.read_bytes()).digest() != hashlib.sha256(self.text).digest()):
                raise AssertionError('fixture hardlink alias changed; preserve it')
            alias.unlink()

    def test_aggregate_staging_refusal_has_no_effect(self):
        self.config['execution_host']['aggregate_bytes'] = 4096
        owner.write_json(self.config_path, self.config)
        custody = Custody(owner, self.config_path)
        with self.assertRaisesRegex(owner.WorkspaceRefused, 'staging cannot fit'):
            custody.plan(self.id)
        self.assertFalse(custody.active.exists())
        self.assertFalse((self.root / 'custody.zip').exists())

    def test_configured_canonical_artifacts_are_in_aggregate_inventory(self):
        self.config['execution_host']['canonical_outputs'] = ['.aide/release']
        release = self.source / '.aide/release'
        release.mkdir(parents=True)
        (release / 'artifact.bin').write_bytes(b'x' * 6000)
        owner.write_json(self.config_path, self.config)
        with_canonical = Custody(owner, self.config_path).inventory()
        self.config['execution_host']['canonical_outputs'] = []
        owner.write_json(self.config_path, self.config)
        without_canonical = Custody(owner, self.config_path).inventory()
        self.assertEqual(with_canonical - without_canonical, 6000)

    def test_tampered_archive_refuses_read_without_raw_changes(self):
        self.custody.apply(self.id, self.frozen_plan())
        (self.root / 'custody.zip').write_bytes(b'corrupt archived evidence')
        with self.assertRaises((ValueError, OSError, __import__('zipfile').BadZipFile)):
            self.custody.read(self.id, 'logs/stdout')
        self.assertEqual((self.root / 'receipt.json').read_bytes(), self.raw_receipt)

    def test_changed_remaining_raw_blocks_cleanup_and_allocation(self):
        digest = self.interrupt('manifest_verified')
        (self.root / 'logs/stdout').write_bytes(b'new unique post-archive evidence')
        with self.assertRaisesRegex(owner.WorkspaceRefused, 'remaining raw evidence changed'):
            self.custody.recover(self.id, digest)
        self.assertTrue(self.custody.active.exists())
        self.assertEqual((self.root / 'logs/stdout').read_bytes(), b'new unique post-archive evidence')
        with mock.patch.object(owner, 'validate_job', return_value=self.source):
            with self.assertRaisesRegex(owner.WorkspaceRefused, 'previous job requires explicit reconciliation'):
                owner.run(self.config_path, {'adapter': 'python'})
        self.assertFalse(any(self.roots['scratch'].iterdir()))

    def test_wrong_recovery_digest_cannot_modify_pending_evidence(self):
        self.interrupt('intent_persisted')
        original = self.custody.active.read_bytes()
        with self.assertRaisesRegex(owner.WorkspaceRefused, 'exact custody intent'):
            self.custody.recover(self.id, '0' * 64)
        self.assertEqual(self.custody.active.read_bytes(), original)
        self.assertFalse((self.root / 'custody.zip').exists())

    def test_member_escape_or_unbounded_read_refused(self):
        for member in ('../receipt.json', 'output/../receipt.json', 'output\\file', '/output/file', 'owner.json'):
            with self.assertRaises(owner.WorkspaceRefused):
                self.custody.read(self.id, member)
        for limit in (0, -1, 65537, True):
            with self.assertRaises(owner.WorkspaceRefused):
                self.custody.read(self.id, 'logs/stdout', limit=limit)

    def test_existing_estate_lock_prevents_competing_custody(self):
        with owner.estate_lock(self.roots['control']):
            with self.assertRaisesRegex(owner.WorkspaceRefused, 'another heavy job'):
                self.custody.plan(self.id)
        self.assertFalse(self.custody.active.exists())

    def test_public_ordinary_recovery_has_specific_custody_refusal(self):
        self.interrupt('intent_persisted')
        name = 'custody_test_lite'
        if name not in sys.modules:
            spec = importlib.util.spec_from_file_location(name, REPO / '.aide/scripts/aide_lite.py')
            lite = importlib.util.module_from_spec(spec)
            sys.modules[name] = lite
            spec.loader.exec_module(lite)
        lite = sys.modules[name]
        args = argparse.Namespace(repo_root=REPO, config=str(self.config_path), job_command='recover')
        # Tiny config intentionally has no host executable; exercise the actual
        # public recovery handler with the unchanged owner, without launching.
        with mock.patch.object(lite, '_job_wait_read_json', return_value=({}, b'')), contextlib.redirect_stdout(io.StringIO()) as output:
            result = lite.command_managed_job(args)
        self.assertEqual(result, 1)
        self.assertIn('requires job custody recover', output.getvalue())
        self.assertEqual(owner.read_json(self.custody.active)['schema'], PENDING)

    def test_actual_public_cli_with_pinned_owner_completes_custody_and_lookup(self):
        # Reuse the exact public supervisor selection; only newly owned fixture
        # roots/limits differ. No live pool grants or source archive edits.
        public_config = REPO / '.aide/queue/AIDE-RETIRED-EVIDENCE-CUSTODY-01/evidence/native-fixture-configuration.json'
        selection = json.loads(public_config.read_text(encoding='utf-8'))['execution_host']
        self.config['execution_host'] = selection
        owner.write_json(self.config_path, self.config)

        def invoke(operation, *extra):
            result = subprocess.run([sys.executable, '-B', str(REPO / '.aide/scripts/aide_lite.py'),
                '--repo-root', str(REPO), 'job', 'custody', operation,
                '--config', str(self.config_path), '--job-id', self.id, *extra],
                capture_output=True, text=True, encoding='utf-8', timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return json.loads(result.stdout)

        plan = invoke('plan')
        self.assertEqual(plan['state'], 'PLANNED')
        self.assertNotIn('plan', plan)  # routine view remains bounded
        before = invoke('read', '--member', 'logs/stdout', '--limit', '31')
        changed = invoke('apply', '--expect-plan', plan['plan_digest'])
        self.assertEqual(changed['state'], 'CUSTODIED')
        self.assertTrue(changed['pending_absent'])
        self.assertEqual(invoke('verify')['state'], 'VERIFIED')
        after = invoke('read', '--member', 'logs/stdout', '--limit', '31')
        self.assertEqual(after['slice_base64'], before['slice_base64'])
        self.assertEqual(after['sha256'], before['sha256'])
        self.assertEqual((self.root / 'receipt.json').read_bytes(), self.raw_receipt)
        self.assertEqual((self.root / 'owner.json').read_bytes(), self.raw_owner)
        self.assertFalse((self.root / 'logs').exists())
        self.assertFalse(self.custody.active.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
