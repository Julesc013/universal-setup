# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Retained failed-cohort decoding and corruption controls; no runtime admission."""
import copy
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from publisher_failed_repair_backup_evidence import reconcile
from publisher_initial_maintenance_evidence import canonical, unique_object
from publisher_execution_evidence import canonical_sha


def fixture():
    path = Path(__file__).parent / 'fixtures/setup/publisher-failed-repair-backup-1ccb228.v1.json.gz'
    raw = path.read_bytes()
    assert len(raw) == 74271 and hashlib.sha256(raw).hexdigest() == 'e87a8194431c4d6b2e842880e793dc3104a3e5bad63d0a36fb2be99ab3d23eda'
    decoded = gzip.decompress(raw)
    assert len(decoded) == 999983 and hashlib.sha256(decoded).hexdigest() == '660f6fd06ae09bd41420bb1031773e44efdbe7a941a868b89841ea056d0c2b08'
    return json.loads(decoded, object_pairs_hook=unique_object)


def backup(value):
    return next(r for r in value['readback']['independent']['rows'] if '\\backup\\bin\\core.bin' in r['path'])


def rewrite_native(value, sequence, change):
    rows = sorted((r for r in value['readback']['independent']['rows']
        if '.native-maintenance-custody\\' in r['path']), key=lambda r: r['path'])
    previous = None
    for i, row in enumerate(rows):
        doc = json.loads(row['content_json'])
        if i == sequence:
            change(doc)
        doc['previous_record_sha256'] = previous
        encode(row, doc)
        previous = row['sha256']


def encode(row, document, *, ordered=False):
    row['content_json'] = json.dumps(document, ensure_ascii=False, separators=(',', ':')) if ordered else canonical(document) + '\n'
    row['bytes'] = len(row['content_json'].encode())
    row['sha256'] = hashlib.sha256(row['content_json'].encode()).hexdigest()
    row['streams'][0]['size'] = row['bytes']


def rewrite_saved_snapshot(value, change):
    rows = value['readback']['independent']['rows']
    row = next(r for r in rows if '.native-maintenance-snapshots\\' in r['path'])
    old = row['sha256']
    doc = json.loads(row['content_json']);change(doc)
    stream = doc['recovery_metadata']['stream_journal']
    stream['source_digest'] = hashlib.sha256(stream['source_context'].encode()).hexdigest()
    stream['digest'] = canonical_sha({k:v for k,v in stream.items() if k != 'digest'})
    encode(row, doc, ordered=True)
    row['path'] = row['path'].rsplit('\\', 1)[0] + '\\' + row['sha256'] + '.json'
    row['native_name'] = row['path'][2:]
    created = next(r for r in rows if r['path'].endswith('.native-maintenance-created.json'))
    doc = json.loads(created['content_json']);doc['transaction_snapshot_sha256'] = row['sha256'];encode(created, doc)
    for native in (r for r in rows if '.native-maintenance-custody\\' in r['path']):
        doc = json.loads(native['content_json'])
        if doc['transaction_snapshot_sha256'] == old:doc['transaction_snapshot_sha256'] = row['sha256']
        for key in ('publication_transaction_snapshot_sha256', 'effect_transaction_snapshot_sha256'):
            if doc['details'].get(key) == old:doc['details'][key] = row['sha256']
        if doc['kind'] == 'confirmed_publication':doc['details']['created_closure_sha256'] = created['sha256']
        encode(native, doc)
    rewrite_native(value, -1, lambda d: None)


def rewrite_effect(value, sequence, change):
    rows = value['readback']['independent']['rows']
    effects = sorted((r for r in rows if '.maintenance\\' in r['path']), key=lambda r:r['path'])
    previous, digests = None, {}
    for row in effects:
        doc = json.loads(row['content_json']);old = doc['digest']
        if doc['sequence'] == sequence:change(doc)
        doc['previous_digest'] = previous
        doc['digest'] = canonical_sha({k:v for k,v in doc.items() if k != 'digest'})
        encode(row, doc);digests[old] = doc['digest'];previous = doc['digest']
    for native in (r for r in rows if '.native-maintenance-custody\\' in r['path']):
        doc = json.loads(native['content_json'])
        if doc['pending_history_sha256'] in digests:doc['pending_history_sha256'] = digests[doc['pending_history_sha256']]
        encode(native, doc)
    rewrite_native(value, -1, lambda d: None)


def rewrite_effect_completion(value):
    rewrite_effect(value, 4, lambda d:d['details'].update(outcome='retained'))


def rewrite_current_source(value, change):
    rows = value['readback']['independent']['rows']
    row = next(r for r in rows if r['path'].endswith('.journal.json'))
    doc = json.loads(row['content_json']);stream = doc['recovery_metadata']['stream_journal']
    source = json.loads(stream['source_context']);change(source)
    text = canonical(source);source_sha = hashlib.sha256(text.encode()).hexdigest()
    snapshots = {}
    for journal in (r for r in rows if r['path'].endswith('.journal.json') or '.native-maintenance-snapshots\\' in r['path']):
        doc = json.loads(journal['content_json']);stream = doc['recovery_metadata']['stream_journal']
        old = journal['sha256']
        stream.update(source_context=text, source_digest=source_sha)
        stream['digest'] = canonical_sha({k:v for k,v in stream.items() if k != 'digest'})
        encode(journal, doc, ordered=True)
        if '.native-maintenance-snapshots\\' in journal['path']:
            snapshots[old] = journal['sha256']
            journal['path'] = journal['path'].rsplit('\\', 1)[0] + '\\' + journal['sha256'] + '.json'
            journal['native_name'] = journal['path'][2:]
    created = next(r for r in rows if r['path'].endswith('.native-maintenance-created.json'))
    doc = json.loads(created['content_json']);doc['source_context'] = text
    doc['transaction_snapshot_sha256'] = snapshots[doc['transaction_snapshot_sha256']];encode(created, doc)
    for effect in (r for r in rows if '.maintenance\\' in r['path']):
        doc = json.loads(effect['content_json']);doc['source_digest'] = source_sha
        if doc['phase'] == 'context':doc['details']['source_context'] = text
        encode(effect, doc)
    rewrite_effect(value, -1, lambda d:None)
    for native in (r for r in rows if '.native-maintenance-custody\\' in r['path']):
        doc = json.loads(native['content_json'])
        doc['transaction_snapshot_sha256'] = snapshots[doc['transaction_snapshot_sha256']]
        for key in ('publication_transaction_snapshot_sha256', 'effect_transaction_snapshot_sha256'):
            if key in doc['details']:doc['details'][key] = snapshots[doc['details'][key]]
        if doc['kind'] == 'confirmed_publication':doc['details']['created_closure_sha256'] = created['sha256']
        encode(native, doc)
    rewrite_native(value, -1, lambda d:None)


def rewrite_original(value, change):
    rows = value['readback']['independent']['rows']
    original = next(r for r in rows if r['path'].endswith('.native-maintenance-original.json'))
    doc = json.loads(original['content_json']);change(doc);encode(original, doc)
    created = next(r for r in rows if r['path'].endswith('.native-maintenance-created.json'))
    doc = json.loads(created['content_json']);doc['original_admission_sha256'] = original['sha256'];encode(created, doc)
    for native in (r for r in rows if '.native-maintenance-custody\\' in r['path']):
        doc = json.loads(native['content_json']);doc['original_admission_sha256'] = original['sha256']
        if doc['kind'] == 'confirmed_publication':doc['details']['created_closure_sha256'] = created['sha256']
        encode(native, doc)
    rewrite_native(value, -1, lambda d: None)


def rewrite_protected_completion(value, change):
    rows = value['readback']['independent']['rows']
    def row(suffix):
        return next(r for r in rows if r['path'].endswith(suffix))
    reviewed, prepared, visible, completed = (row(name) for name in
        ('lab-reviewed-plan.json', 'lab-prepared-evidence.json', 'lab-visible-evidence.json', 'lab-installed-state.json'))
    old_reviewed_sha = reviewed['sha256']
    documents = [json.loads(r['content_json']) for r in (reviewed, prepared, visible, completed)]
    change(documents)
    encode(reviewed, documents[0])
    for binding in (documents[1]['source_binding'], documents[1]['operation_admission']):
        if binding['reviewed_plan_snapshot_sha256'] == old_reviewed_sha:
            binding['reviewed_plan_snapshot_sha256'] = reviewed['sha256']
    encode(prepared, documents[1])
    documents[2]['prepared_record_sha256'] = prepared['sha256'];encode(visible, documents[2])
    documents[3]['prepared_record_sha256'] = prepared['sha256']
    documents[3]['visible_record_sha256'] = visible['sha256']
    encode(completed, documents[3])
    references = dict(reviewed_snapshot_sha256=reviewed['sha256'], prepared_record_sha256=prepared['sha256'],
        visible_record_sha256=visible['sha256'], completion_record_sha256=completed['sha256'])
    rewrite_original(value, lambda d:d['original_consumer_completion'].update(references))


def rewrite_context_installed(value, change):
    rows = value['readback']['independent']['rows']
    context = next(r for r in rows if isinstance(r.get('content_json'), str) and
        json.loads(r['content_json']).get('schema') == 'usk.installation_operation_context.v2')
    doc = json.loads(context['content_json']);change(doc['reviewed_snapshot']['installed_state'])
    doc['context_sha256'] = canonical_sha({k:v for k,v in doc.items() if k != 'context_sha256'});encode(context, doc)
    roots = next(r for r in rows if r['path'] == context['path'][:-5] + '-roots.json')
    root_doc = json.loads(roots['content_json']);root_doc['context_sha256'] = doc['context_sha256']
    root_doc['roots_sha256'] = canonical_sha({k:v for k,v in root_doc.items() if k != 'roots_sha256'});encode(roots, root_doc)
    lease_row = next(r for r in rows if r['path'].endswith('g00000000000000000004-active.json'))
    lease = json.loads(lease_row['content_json']);lease['operation_context_sha256'] = root_doc['roots_sha256']
    lease['ownership_sha256'] = canonical_sha({k:v for k,v in lease.items() if k != 'ownership_sha256'});encode(lease_row, lease)
    rewrite_original(value, lambda d:d.update(original_context_sha256=root_doc['roots_sha256'], original_lease_ownership=lease))
    created = next(r for r in rows if r['path'].endswith('.native-maintenance-created.json'))
    doc = json.loads(created['content_json']);doc.update(original_context_sha256=root_doc['roots_sha256'],
        lease_ownership_sha256=canonical_sha(lease));encode(created, doc)
    for native in (r for r in rows if '.native-maintenance-custody\\' in r['path']):
        doc = json.loads(native['content_json']);doc.update(original_context_sha256=root_doc['roots_sha256'],
            original_lease_ownership_sha256=canonical_sha(lease), writer_lease_ownership=lease)
        if doc['kind'] == 'confirmed_publication':doc['details']['created_closure_sha256'] = created['sha256']
        encode(native, doc)
    rewrite_native(value, -1, lambda d:None)


def rewrite_coordinated_original_transaction(value):
    transaction = 'install.unrelated'
    rewrite_context_installed(value, lambda d:d.update(transaction_id=transaction))
    rewrite_current_source(value, lambda d:d.update(original_installed_transaction_id=transaction))
    rewrite_original(value, lambda d:d['original_consumer_completion'].update(original_transaction_id=transaction))


class FailedRepairBackupEvidenceTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell reader bridge')
    def test_actual_reader_keeps_ordinary_refusal_and_separate_failed_diagnostic(self):
        code = r"""$ErrorActionPreference='Stop'
$functionText=@()
foreach($selection in @(@{file='windows_publisher_standard_public_probe.ps1';name='Read-NativeSnapshot'},
 @{file='windows_publisher_metadata_readback.ps1';name='Assert-IndependentProtectedRows'})) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:USK_TEST_SOURCE $selection.file),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Actual reader/policy syntax differs'}
 $definitions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
  $n.Name -ceq $selection.name},$true))
 if($definitions.Count -ne 1){throw 'Actual reader/policy function is ambiguous'}
 $functionText+=$definitions[0].Extent.Text
}
$readerFile=Join-Path (Split-Path -Parent $env:USK_TEST_FIXTURE) 'reader-functions.ps1'
[IO.File]::WriteAllText($readerFile,($functionText -join "`n"))
. $readerFile
$PythonBinary=$env:USK_TEST_PYTHON;$MaintenanceQualification=$true;$lab='inert'
$ownerCreation='134360233108516653';$clientCaptureFile='inert';$clientCaptureSha256='a'*64
$VolumeRoot='inert';$disk=[pscustomobject]@{Number=3}
foreach($variant in @('original','ordinary','damaged_identity','missing_native_prefix','unclosed','move')) {
 $v=[IO.File]::ReadAllText($env:USK_TEST_FIXTURE)|ConvertFrom-Json
 $drive=$v.drive;$sid=$v.service_sid;$accountSid=$v.consumer_sid;$service=$v.service_name
 $failed=[ordered]@{scope=$v.failure.scope;qualification_granted=$false;command=$v.failure.command;
  request_id=$v.failure.request_id;client_process_id=$v.failure.client_process_id;
  client_creation_file_time=$v.failure.client_creation_file_time;readback=$null}
 $receipt=[ordered]@{request_execution_failure=$failed;client_captures=@($v.capture);
  maintenance=@{cases=@($v.case)};machine_sha256=$v.machine_sha256}
 $script:observed=$v.readback;$supplied=$failed
 switch($variant) {
  'ordinary' {$supplied=$null}
  'damaged_identity' {($script:observed.independent.rows|Where-Object path -match '\\backup\\bin\\core.bin$').file_id=
    '66c68ca0c68c725b:99000000000001000000000000000000'}
  'missing_native_prefix' {$script:observed.independent.rows=@($script:observed.independent.rows|Where-Object {
    -not $_.path.EndsWith('.native-maintenance-custody\00000000000000000002.json')})}
  'unclosed' {$script:observed.independent.observer_token_handles_closed=$false}
  'move' {$failed.command='move.apply';$receipt.client_captures[0].command='move.apply'}
 }
 function Invoke-IndependentMetadataReadback {return $script:observed}
 $caught=$null;$returned=$null
 try {$returned=Read-NativeSnapshot -OriginalFailedRequest $supplied} catch {$caught=$_.Exception.Message}
 if($variant -ceq 'original') {
  if($caught -or -not [object]::ReferenceEquals($returned,$script:observed) -or
   $failed.readback_policy.status -cne 'refused' -or $failed.readback_policy.qualification_granted -ne $false -or
   $failed.backup_role_diagnostic.status -cne 'verified_original_backup_roles' -or
   $failed.backup_role_diagnostic.qualification_granted -ne $false -or
   $failed.backup_role_diagnostic.result.operation_completion_qualified -ne $false -or
   $failed.qualification_granted -ne $false){throw ('Original diagnostic bridge differs: '+$caught+
    '; decoder='+$failed.backup_role_diagnostic.failure)}
 } elseif(-not $caught -or $returned) {throw ('Unbound/corrupt diagnostic returned: '+$variant)}
 if($variant -cin @('damaged_identity','missing_native_prefix')) {
  if(-not $caught.StartsWith('Independent owner/DACL differs: ',[StringComparison]::Ordinal) -or
   $failed.backup_role_diagnostic.status -cne 'refused' -or -not $failed.backup_role_diagnostic.failure -or
   -not [object]::ReferenceEquals($failed.readback,$script:observed)) {throw 'Decoder refusal masked original policy or erased rows'}
 }
 if($variant -ceq 'unclosed' -and ($failed.readback -or $failed.Contains('backup_role_diagnostic'))) {
  throw 'Unclosed observer entered the backup diagnostic'
 }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'selected-input.json'
            path.write_text(json.dumps(fixture()), encoding='utf-8')
            # Preserve the actual AST function text in a file so PowerShell's
            # automatic PSScriptRoot has its real semantics. The decoder bytes
            # are copied unchanged; dependencies resolve to the source modules.
            shutil.copyfile(Path(__file__).parent / 'publisher_failed_repair_backup_evidence.py',
                Path(directory) / 'publisher_failed_repair_backup_evidence.py')
            environment = dict(os.environ, USK_TEST_SOURCE=str(Path(__file__).parent),
                USK_TEST_FIXTURE=str(path), USK_TEST_PYTHON=sys.executable, PYTHONPATH=str(Path(__file__).parent))
            for binary in ('powershell', 'pwsh'):
                executable = shutil.which(binary)
                if executable:
                    with self.subTest(binary=binary):
                        result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
                            base64.b64encode(code.encode('utf-16le')).decode()], env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45)
                        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))

    def test_retained_original_backup_is_diagnostic_only(self):
        result = reconcile(fixture())
        self.assertEqual(result['scope'], 'original_failed_repair_backup_roles_only')
        self.assertEqual(len(result['backups']), 1)
        item = next(iter(result['backups'].values()))
        self.assertEqual(item['sha256'], '365bf3f024d60a7f3ae37ec55f98568733e9967736f2768c2fd508bf935397df')
        self.assertEqual(item['original_native_identity'], '00000000c68c725b:0001000000000042')
        for key in ('qualification_granted', 'native_restoration_qualified',
                    'operation_completion_qualified', 'whole_target_qualified'):
            self.assertIs(result[key], False)
        self.assertIs(result['retained_original_provenance']['native_restoration_qualified'], False)

    def test_object_capture_and_rehashed_native_contradictions_refuse(self):
        mutations = {
            'ordinary': lambda v: v['failure'].update(command='publisher.observe'),
            'move': lambda v: v['failure'].update(command='move.apply'),
            'qualifying': lambda v: v['failure'].update(qualification_granted=True),
            'unclosed': lambda v: v['readback']['independent'].update(observer_token_handles_closed=False),
            'incomplete schema': lambda v: v['readback']['independent'].update(
                schema='usk.publisher.metadata_incomplete_failed_request_diagnostic.v1'),
            'unreadable content': lambda v: backup(v).update(content_read_failure={'field': 'content_json'}),
            'incomplete failures': lambda v: v['readback']['independent'].update(content_read_failures=[]),
            'birth': lambda v: v['capture'].update(creation_file_time='134360233619370105'),
            'wrong consumer': lambda v: v.update(consumer_sid='S-1-5-21-1-2-3-4'),
            'directory': lambda v: backup(v).update(directory=True),
            'substituted ID': lambda v: backup(v).update(file_id='66c68ca0c68c725b:99000000000001000000000000000000'),
            'clean replacement bytes': lambda v: backup(v).update(sha256='76260c623a5a4b3039aaf5aabc76fa9f847651cb8e34bf7b28439247ee0e79d8'),
            'stream': lambda v: backup(v)['streams'].append({'name': ':extra:$DATA', 'size': 0, 'allocation_size': 0}),
            'hard link': lambda v: backup(v).update(link_count=2),
            'reparse': lambda v: backup(v).update(attributes=1056),
            'case sensitive': lambda v: backup(v).update(case_sensitive=True),
            'raw ACE order': lambda v: backup(v)['raw_aces'].reverse(),
            'SDDL': lambda v: backup(v).update(raw_security='O:SYD:P(A;;FA;;;WD)'),
            'MAX write': lambda v: backup(v)['effective_rights']['filtered']['maximum_allowed'].update(granted=2032127),
            'no original native prefix': lambda v: v['readback']['independent'].update(rows=[r for r in v['readback']['independent']['rows'] if '.native-maintenance-custody\\00000000000000000002.json' not in r['path']]),
            'unrecognized native kind': lambda v: rewrite_native(v, 7, lambda d: d.update(kind='unrecognized')),
            'rehashed backup identity': lambda v: rewrite_native(v, 3, lambda d: d['details']['effect_details'].update(native_identity='00000000c68c725b:0001000000000099')),
            'rehashed ancestor': lambda v: rewrite_native(v, 2, lambda d: d['details']['object'].update(file_id='66c68ca0c68c725b:99000000000001000000000000000000')),
            'rehashed saved operation': lambda v: rewrite_saved_snapshot(v, lambda d:d.update(operation='move')),
            'rehashed saved root': lambda v: rewrite_saved_snapshot(v, lambda d:d['roots'][0].update(root='F:\\unrelated')),
            'rehashed saved source': lambda v: rewrite_saved_snapshot(v, lambda d:d['recovery_metadata']['stream_journal'].update(source_context='{}')),
            'rehashed saved transition': lambda v: rewrite_saved_snapshot(v, lambda d:d['transitions'][0].update(to='completed')),
            'rehashed saved last state': lambda v: rewrite_saved_snapshot(v, lambda d:d.update(current_state='completed')),
            'rehashed complete contradiction': rewrite_effect_completion,
            'rehashed null history contradiction': lambda v: rewrite_native(v, 0, lambda d:d.update(pending_history_sha256='1'*64)),
            'rehashed original consumer transaction': lambda v: rewrite_original(v, lambda d:d['original_consumer_completion'].update(original_transaction_id='install.unrelated')),
            'rehashed original setup root': lambda v: rewrite_original(v, lambda d:d['original_consumer_completion'].update(setup_root='F:\\unrelated')),
            'rehashed original payload name': lambda v: rewrite_original(v, lambda d:d['original_objects'][0]['object'].update(native_name='\\unrelated\\core.bin')),
            'rehashed original payload parent': lambda v: rewrite_original(v, lambda d:d['original_objects'][0]['parent'].update(native_name='\\unrelated')),
            'rehashed source applied time': lambda v: rewrite_current_source(v, lambda d:d.update(applied_at='2026-10-09T12:42:42Z')),
            'rehashed source plan reference': lambda v: rewrite_current_source(v, lambda d:d.update(reviewed_plan_ref='unrelated.maintenance-plan.json')),
            'rehashed source native parent': lambda v: rewrite_current_source(v, lambda d:d['operation_target_parent'].update(native_identity='00000000c68c725b:0001000000000099')),
            'rehashed root classification': lambda v: rewrite_saved_snapshot(v, lambda d:d['roots'][0].update(classification='setup_owned')),
            'rehashed stream publication identity': lambda v: rewrite_saved_snapshot(v, lambda d:d['recovery_metadata']['stream_journal'].update(publication_root_identity='00000000c68c725b:0001000000000099')),
            'rehashed effect context directory': lambda v: rewrite_effect(v, 0, lambda d:d['details'].update(directory_identity='00000000c68c725b:0001000000000099')),
            'rehashed completion phase': lambda v: rewrite_effect(v, 4, lambda d:d.update(phase='unknown')),
            'rehashed completion extra field': lambda v: rewrite_effect(v, 4, lambda d:d['details'].update(unrecognized=True)),
            'rehashed replacement intent extra field': lambda v: rewrite_effect(v, 5, lambda d:d['details']['effect'].update(unrecognized=True)),
            'rehashed native publication snapshot': lambda v: rewrite_native(v, 0, lambda d:d['details'].update(publication_transaction_snapshot_sha256='1'*64)),
            'rehashed later directory legacy identity': lambda v: rewrite_native(v, 1, lambda d:d['details'].update(native_identity='00000000c68c725b:0001000000000099')),
            'rehashed consumer grant identity': lambda v: rewrite_native(v, 5, lambda d:d['details'].update(consumer_sid='S-1-5-21-1-2-3-4')),
            'rehashed consumer grant parent': lambda v: rewrite_native(v, 5, lambda d:d['details']['parent'].update(native_name='\\unrelated')),
            'rehashed metadata creation bytes': lambda v: rewrite_native(v, 6, lambda d:d['details'].update(sha256='1'*64)),
            'ancestor file type': lambda v: next(r for r in v['readback']['independent']['rows'] if r['path'].endswith('\\backup\\bin')).update(directory=False),
            'rehashed protected reviewed transaction': lambda v: rewrite_protected_completion(v,
                lambda ds:ds[0].update(transaction_id='install.unrelated')),
            'rehashed protected completion link': lambda v: rewrite_protected_completion(v,
                lambda ds:ds[3]['source_binding'].update(reviewed_plan_snapshot_sha256='1'*64)),
            'rehashed installed-state projection': lambda v: rewrite_context_installed(v, lambda d:d.update(product_version='9.9.9')),
            'rehashed coordinated original transaction': rewrite_coordinated_original_transaction,
            'rehashed prior selection': lambda v: rewrite_protected_completion(v,
                lambda ds:ds[1].update(selected_file_set_digest='1'*64)),
            'rehashed prior destination parent': lambda v: rewrite_protected_completion(v,
                lambda ds:ds[2].update(destination_parent_file_id='66c68ca0c68c725b:99000000000001000000000000000000')),
        }
        expected_reasons = {'rehashed protected reviewed transaction': 'protected reviewed install',
            'rehashed protected completion link': 'protected completed source differs',
            'rehashed installed-state projection': 'original installed-state digest/binding',
            'rehashed coordinated original transaction': 'protected reviewed install'}
        for field in ('archive_sha256', 'archive_identity_digest', 'entry_set_digest', 'plan_envelope_sha256', 'reviewed_plan_digest'):
            name = 'rehashed paired completed source ' + field
            mutations[name] = lambda v, key=field: rewrite_protected_completion(v,
                lambda ds:[d['source_binding'].update({key:'1'*64}) for d in (ds[1], ds[3])])
            expected_reasons[name] = 'protected completed source differs'
        for field, wrong in {'reviewed_plan_digest': '1'*64, 'reviewed_plan_snapshot_sha256': '1'*64,
            'configured_caller_sid': 'S-1-5-21-1-2-3-4', 'service_sid': 'S-1-5-80-1-2-3-4-5',
            'service_name': 'unrelated', 'root_file_id': '66c68ca0c68c725b:99000000000001000000000000000000',
            'volume_serial': 1}.items():
            name = 'rehashed prior admission ' + field
            mutations[name] = lambda v, key=field, bad=wrong: rewrite_protected_completion(v,
                lambda ds:ds[1]['operation_admission'].update({key:bad}))
            expected_reasons[name] = 'original prepared admission differs'
        for index in (1, 2, 3):
            name = 'rehashed prior record phase ' + str(index)
            mutations[name] = lambda v, i=index: rewrite_protected_completion(v,
                lambda ds:ds[i].update(phase='lab_unrelated'))
            expected_reasons[name] = 'completion role/selection/parent differs'
        original = fixture()
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = copy.deepcopy(original)
                mutate(value)
                with (self.assertRaisesRegex(ValueError, expected_reasons[name]) if name in expected_reasons else
                    self.assertRaises((ValueError, KeyError, TypeError))):
                    reconcile(value)


if __name__ == '__main__':
    unittest.main()
