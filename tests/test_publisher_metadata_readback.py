# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

import json
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == "nt", "Windows PowerShell readback oracle")
class PublisherMetadataReadbackTests(unittest.TestCase):
    def test_failed_maintenance_readback_retains_rows_without_accepting_acl_role(self):
        # Exercise only actual reader/policy control flow with inert observed
        # data. No native access check, token custody or backup is manufactured.
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
foreach($selection in @(@{file='windows_publisher_standard_public_probe.ps1';name='Read-NativeSnapshot'},
 @{file='windows_publisher_metadata_readback.ps1';name='Assert-IndependentProtectedRows'})) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:USK_TEST_SOURCE $selection.file),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Actual reader/policy syntax differs'}
 $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
  $n.Name -ceq $selection.name},$true))
 if($functions.Count -ne 1){throw 'Actual reader/policy function is ambiguous'}
 . ([scriptblock]::Create($functions[0].Extent.Text))
}
$MaintenanceQualification=$true;$drive='E:\';$lab='inert';$ownerCreation='134360177507798014'
$PIDValue=7832;$accountSid='S-1-5-21-1-2-3-4';$sid='S-1-5-80-1-2-3-4-5'
$clientCaptureFile='inert';$clientCaptureSha256='a'*64;$VolumeRoot='inert'
$disk=[pscustomobject]@{Number=1};$script:invocations=0
$script:observed=[pscustomobject]@{observer_task_removed=$true;independent=[pscustomobject]@{
 identity='S-1-5-18';observer_token_handles_closed=$true;rows=@([pscustomobject]@{
 path='E:\publication\destination\.usk-repair-maintenance.repair.original\backup\bin\core.bin';
 owner='S-1-5-18';protected=$true;aces=@(
 @{sid='S-1-5-18';rights=2032127;type='Allow';inherited=$false;inheritance=0;propagation=0},
 @{sid=$sid;rights=2032127;type='Allow';inherited=$false;inheritance=0;propagation=0},
 @{sid=$accountSid;rights=1179817;type='Allow';inherited=$false;inheritance=0;propagation=0})})}}
function Invoke-IndependentMetadataReadback {
 $script:invocations++;return $script:observed
}
foreach($variant in @('ordinary','original_failure','copied_failure','changed_capture','unconfirmed_close','qualification_changed')) {
 $failed=[ordered]@{scope='original_failed_request_before_cleanup';qualification_granted=$false;
  command='repair.apply';request_id='public.original';client_process_id=$PIDValue;
  client_creation_file_time=$ownerCreation;readback=$null}
 $receipt=[ordered]@{request_execution_failure=$failed;client_captures=@([pscustomobject]@{
  request_id=$failed.request_id;command=$failed.command;process_id=$PIDValue;creation_file_time=$ownerCreation;
  captured_before_primary_thread_resume=$true;primary_token=@{user_sid=$accountSid}})}
 $supplied=$failed;$before=$script:invocations;$caught=$null
 $script:observed.independent.observer_token_handles_closed=$true
 switch($variant) {
  'ordinary' {$supplied=$null}
  'copied_failure' {$supplied=$failed|ConvertTo-Json -Depth 8|ConvertFrom-Json}
  'changed_capture' {$receipt.client_captures[0].creation_file_time='134360177507798015'}
  'unconfirmed_close' {$script:observed.independent.observer_token_handles_closed=$false}
  'qualification_changed' {$failed.qualification_granted=$true}
 }
 try {$ignored=Read-NativeSnapshot -OriginalFailedRequest $supplied} catch {$caught=$_.Exception.Message}
 if(-not $caught){throw ('Refused diagnostic returned an accepted snapshot: '+$variant)}
 if($variant -ceq 'original_failure') {
  if(-not $caught.StartsWith('Independent owner/DACL differs: ',[StringComparison]::Ordinal) -or
   -not [object]::ReferenceEquals($failed.readback,$script:observed) -or
   $failed.readback_policy.status -cne 'refused' -or $failed.readback_policy.qualification_granted -ne $false -or
   $failed.readback_policy.failure -cne $caught -or $failed.readback_policy.failure_truncated -ne $false -or
   $failed.qualification_granted -ne $false -or -not $script:observersClosed) {
   throw 'Original refused policy erased rows or granted qualification'
  }
 } elseif($failed.readback -or $failed.Contains('readback_policy')) {
  throw ('An unrelated or unclosed reader retained approved diagnostics: '+$variant)
 }
 if($variant -cin @('copied_failure','changed_capture','qualification_changed') -and $script:invocations -ne $before) {
  throw 'Unbound failure invoked an observer'
 }
}
"""
        for binary in ("powershell", "pwsh"):
            executable = shutil.which(binary)
            if not executable:
                continue
            with self.subTest(binary=binary):
                environment = dict(os.environ, USK_TEST_SOURCE=str(root / "tests"))
                result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    base64.b64encode(code.encode("utf-16le")).decode()], env=environment,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))

    def test_incomplete_original_failure_rows_remain_separate_and_refused(self):
        # Actual reader control flow, inert diagnostic data; no native authority.
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_READER_SOURCE,[ref]$t,[ref]$e)
if($e){throw 'Reader parse differs'}
$definition=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $n.Name -ceq 'Read-NativeSnapshot'},$true))
if($definition.Count -ne 1){throw 'Reader ambiguous'}
. ([scriptblock]::Create($definition[0].Extent.Text))
$MaintenanceQualification=$true;$drive='E:\';$lab='inert';$ownerCreation='134360177507798014'
$accountSid='S-1-5-21-1-2-3-4';$sid='S-1-5-80-1-2-3-4-5';$clientCaptureFile='inert'
$clientCaptureSha256='a'*64;$VolumeRoot='inert';$disk=@{Number=1}
$script:invocations=0;$script:policyInvocations=0
function Assert-IndependentProtectedRows {$script:policyInvocations++;throw 'Incomplete rows reached policy'}
function Invoke-IndependentMetadataReadback {
 param($OriginalFailedRequestDiagnosticBinding)
 $script:invocations++
 if($supplied) {
  $binding=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(
   $OriginalFailedRequestDiagnosticBinding))|ConvertFrom-Json
  if($binding.request_id -cne $failed.request_id -or $binding.command -cne $failed.command -or
   $binding.client_process_id -ne $failed.client_process_id -or
   $binding.client_creation_file_time -cne $failed.client_creation_file_time -or
   $binding.account_sid -cne $accountSid -or $binding.client_capture_sha256 -cne $clientCaptureSha256 -or
   $binding.qualification_granted -ne $false){throw 'Diagnostic opt-in lost original binding'}
 }
 return $script:observed
}
foreach($variant in @('original','ordinary','copied_failure','different_request','qualifying','unclosed')) {
 $failed=[ordered]@{scope='original_failed_request_before_cleanup';qualification_granted=$false;
  request_id=('public.'+('a'*32));command='repair.apply';client_process_id=123;
  client_creation_file_time=$ownerCreation;readback=$null}
 $receipt=@{request_execution_failure=$failed;client_captures=@(@{request_id=$failed.request_id;
  command='repair.apply';process_id=123;creation_file_time=$ownerCreation;
  captured_before_primary_thread_resume=$true;primary_token=@{user_sid=$accountSid}})}
 $script:observed=[pscustomobject]@{observer_task_removed=$true;independent=[pscustomobject]@{
  schema='usk.publisher.metadata_incomplete_failed_request_diagnostic.v1';identity='S-1-5-18';
  observer_token_handles_closed=$true;status='incomplete';scope='original_failed_request_content_read_only';
  original_request=[pscustomobject]@{request_id=$failed.request_id;command='repair.apply';client_process_id=123;
   client_creation_file_time=$ownerCreation};rows=@(@{path='blocked.json';content_json=$null});
  content_read_failures=@(@{field='content_json';status='unreadable'});
  qualification_granted=$false;operation_completion_qualified=$false;native_restoration_qualified=$false;
  whole_target_qualified=$false;authority_granted=$false}}
 $supplied=$failed;$before=$script:invocations
 switch($variant) {
  'ordinary' {$supplied=$null}
  'copied_failure' {$supplied=$failed|ConvertTo-Json|ConvertFrom-Json}
  'different_request' {$script:observed.independent.original_request.request_id='public.'+('b'*32)}
  'qualifying' {$script:observed.independent.qualification_granted=$true}
  'unclosed' {$script:observed.independent.observer_token_handles_closed=$false}
 }
 $caught=$null
 try {$ignored=Read-NativeSnapshot -OriginalFailedRequest $supplied} catch {$caught=$_.Exception.Message}
 if(-not $caught -or $failed.readback -or $script:policyInvocations -ne 0 -or $failed.Contains('backup_role_diagnostic')) {
  throw 'Incomplete data became an ordinary snapshot, policy input or backup provenance'
 }
 if($variant -ceq 'original') {
  if(-not [object]::ReferenceEquals($failed.incomplete_readback_diagnostic,$script:observed) -or
   -not $script:observersClosed -or $failed.qualification_granted -ne $false){throw 'Original incomplete rows lost'}
 } elseif($failed.Contains('incomplete_readback_diagnostic')) {throw 'Unbound/unclosed diagnostic retained'}
 if($variant -ceq 'copied_failure' -and $script:invocations -ne $before){throw 'Copied failure invoked observer'}
}
"""
        for binary in ('powershell', 'pwsh'):
            executable = shutil.which(binary)
            self.assertIsNotNone(executable)
            with self.subTest(binary=binary):
                result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-EncodedCommand',
                    base64.b64encode(code.encode('utf-16le')).decode()],
                    env=dict(os.environ, USK_READER_SOURCE=str(root / 'tests/windows_publisher_standard_public_probe.ps1')),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))

    def test_failed_content_diagnostic_catches_only_actual_sharing_and_retains_native_facts(self):
        # Owned local file/handles and the actual ReadClosure/content code.
        # This isolates I/O diagnostics; no machine/request authority is claimed.
        root = Path(__file__).resolve().parents[1]
        source = (root / 'tests/windows_publisher_metadata_readback.ps1').read_text(encoding='utf-8')
        native = source.split(' Add-Type -TypeDefinition @"\n', 1)[1].split('"@', 1)[0]
        code = r"""$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:USK_CONTENT_NATIVE))
$source=[IO.File]::ReadAllText($env:USK_CONTENT_SOURCE)
$start=$source.IndexOf("  if(-not `$p.PSIsContainer -and `$p.Extension -eq '.json') {",[StringComparison]::Ordinal)
$end=$source.IndexOf('  if($effectiveRights) {',$start,[StringComparison]::Ordinal)
if($start -lt 0 -or $end -le $start){throw 'Actual content-read block missing'}
$content=[scriptblock]::Create($source.Substring($start,$end-$start))
$file=Join-Path $env:USK_CONTENT_ROOT 'held.json'
[IO.File]::WriteAllText($file,'{"owned":true}',[Text.UTF8Encoding]::new($false))
$holder=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,
 ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
try {
 $facts=[UskMetadataFacts]::ReadClosure($file)
 foreach($optedIn in @($false,$true)) {
  $p=Get-Item -LiteralPath $file
  $row=[ordered]@{file_id=[string]$facts[0];sha256=$facts[6];bytes=[long]$facts[7];content_json=$null}
  $contentReadFailures=[Collections.Generic.List[object]]::new()
  $failedContentBinding=if($optedIn){@{qualification_granted=$false}}else{$null}
  $caught=$null
  try {. $content} catch {$caught=$_}
  if($optedIn) {
   if($caught -or $contentReadFailures.Count -ne 1 -or $row.content_json -ne $null -or
    $row.content_read_failure.field -cne 'content_json' -or $row.content_read_failure.status -cne 'unreadable' -or
    $row.content_read_failure.win32_error -ne 32 -or $row.content_read_failure.path -cne $file -or
    $row.file_id -cne [string]$facts[0] -or $row.sha256 -cne $facts[6] -or $row.bytes -ne $facts[7]) {
    throw 'Sharing diagnostic lost actual native facts or manufactured content'
   }
  } elseif(-not $caught -or $contentReadFailures.Count -ne 0 -or $row.Contains('content_read_failure')) {
   throw 'Ordinary content read no longer refuses sharing'
  }
 }
} finally {$holder.Dispose()}
$failedContentBinding=@{qualification_granted=$false};$contentReadFailures=[Collections.Generic.List[object]]::new()
$row=@{content_json=$null};$p=Get-Item -LiteralPath $file
. $content
if($row.content_json -cne '{"owned":true}' -or $contentReadFailures.Count){throw 'Closed ordinary content changed'}
[IO.File]::Delete($file)
$caught=$null
try {. $content} catch {$caught=$_}
if(-not $caught -or $contentReadFailures.Count -ne 0){throw 'Nonsharing I/O failure was swallowed'}
"""
        for binary in ('powershell', 'pwsh'):
            executable = shutil.which(binary)
            self.assertIsNotNone(executable)
            with self.subTest(binary=binary), tempfile.TemporaryDirectory(prefix='usk-sharing-control-') as temporary:
                path = Path(temporary) / 'native.cs'
                path.write_text(native, encoding='utf-8')
                result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-EncodedCommand',
                    base64.b64encode(code.encode('utf-16le')).decode()], env=dict(os.environ,
                        USK_CONTENT_NATIVE=str(path), USK_CONTENT_ROOT=temporary,
                        USK_CONTENT_SOURCE=str(root / 'tests/windows_publisher_metadata_readback.ps1')),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=40)
                self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))

    def test_observer_failure_keeps_child_error_when_task_status_query_fails(self):
        # Run only the owned failure serializer/formatter. No scheduled task,
        # native observation or token-close acknowledgement is manufactured.
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText($env:USK_FAILURE_SOURCE)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors){throw 'Outer reader syntax differs'}
$strings=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and
 $n.Value.Contains("schema='usk.publisher.metadata_observer_failure.v1';status='failed'")},$true))
$branches=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Extent.Text.StartsWith('if(Test-Path -LiteralPath $failureOutput)',[StringComparison]::Ordinal)},$true))
if($strings.Count -ne 1 -or $branches.Count -ne 1){throw 'Actual failure serializer/formatter absent or ambiguous'}
$output=Join-Path $env:USK_FAILURE_DIRECTORY 'success.json'
$failureOutput=$output+'.failure.json'
$child='$global:UskMetadataObserverPhase=''control_child_failure''; try { throw [InvalidOperationException]::new(''child-original-''+(''x''*10000)) }'+
 $strings[0].Value.Replace('__FAILURE_OUTPUT__',$failureOutput.Replace("'","''"))
& $env:USK_FAILURE_BINARY -NoProfile -NonInteractive -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child)))
if($LASTEXITCODE -ne 1 -or (Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath ($failureOutput+'.pending'))){
 throw 'Failure-only atomic publication differs'
}
$record=[IO.File]::ReadAllText($failureOutput)|ConvertFrom-Json
if($record.schema -cne 'usk.publisher.metadata_observer_failure.v1' -or $record.status -cne 'failed' -or
 $record.phase -cne 'control_child_failure' -or $record.exception_type -cne 'System.InvalidOperationException' -or
 $record.hresult -ne -2146233079 -or -not $record.message.StartsWith('child-original-',[StringComparison]::Ordinal) -or
 $record.message.Length -ne 8192 -or $record.stack.Length -gt 8192 -or $record.observer_token_handles_closed -ne $false -or
 (Get-Item -LiteralPath $failureOutput).Length -gt 65536){throw 'Actual child diagnostic differs'}
function Get-ScheduledTaskInfo {param($TaskName,$ErrorAction) throw [InvalidOperationException]::new('task-status-unavailable-'+('z'*10000))}
$name='inert-control';$caught=$null
try {& ([scriptblock]::Create($branches[0].Extent.Text))} catch {$caught=$_.Exception.Message}
$prefix='Independent observer failed: '
$separator='; task result observation='
if(-not $caught -or -not $caught.StartsWith($prefix,[StringComparison]::Ordinal)){throw 'Child diagnostic was masked'}
$index=$caught.LastIndexOf($separator,[StringComparison]::Ordinal)
if($index -lt $prefix.Length){throw 'Supplementary query observation absent'}
$propagated=$caught.Substring($prefix.Length,$index-$prefix.Length)|ConvertFrom-Json
$query=$caught.Substring($index+$separator.Length)|ConvertFrom-Json
if($propagated.phase -cne $record.phase -or $propagated.hresult -ne $record.hresult -or
 $propagated.message -cne $record.message -or $propagated.observer_token_handles_closed -ne $false -or
 $query.available -ne $false -or $null -ne $query.result -or $query.error.Length -ne 8192 -or
 -not $query.error.StartsWith('task-status-unavailable-',[StringComparison]::Ordinal)) {
 throw 'Child failure or bounded supplementary query error differs'
}
"""
        for binary in ("powershell", "pwsh"):
            executable = shutil.which(binary)
            if not executable:
                continue
            with self.subTest(binary=binary), tempfile.TemporaryDirectory() as directory:
                environment = dict(os.environ, USK_FAILURE_SOURCE=str(root / "tests/windows_publisher_metadata_readback.ps1"),
                                   USK_FAILURE_DIRECTORY=directory, USK_FAILURE_BINARY=executable)
                result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                    base64.b64encode(code.encode("utf-16le")).decode()], env=environment,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))

    def test_historical_payload_projection_requires_complete_current_record_links(self):
        # Constructed metadata exercises the reader's observational join only;
        # it supplies no native objects, access results or mutation authority.
        root = Path(__file__).resolve().parents[1]
        service = "S-1-5-80-1-2-3-4-5"
        install, initial, current = "org.example.projection", "install.original", "repair.current"

        def encoded(value):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))

        def row(path, value):
            text = encoded(value) + "\n"
            return dict(path="E:\\" + path, directory=False, file_id="constructed-data-only", content_json=text,
                        sha256=hashlib.sha256(text.encode()).hexdigest(), owner="S-1-5-18", protected=True,
                        raw_aces=[dict(sid=sid, type=0, flags=0, access_mask=2032127)
                                  for sid in ("S-1-5-18", service)])

        snapshot = row("publication\\journal\\lab-reviewed-plan.json", dict(
            schema="usk.publisher.lab_reviewed_plan_snapshot.v4", transaction_id=initial,
            target_root="E:/publication/destination/visible", plan_request=dict(install_id=install)))
        prepared = row("publication\\journal\\lab-prepared-evidence.json", dict(
            source_binding=dict(reviewed_plan_snapshot_sha256=snapshot["sha256"])))
        completion = row("publication\\state\\lab-installed-state.json", dict(
            schema="usk.publisher.lab_installed_state.v2", prepared_record_sha256=prepared["sha256"],
            source_binding=dict(reviewed_plan_snapshot_sha256=snapshot["sha256"]), visible_root_file_id="original-root"))
        installed = [row(f"setup-state\\state\\installed\\{install}.{tx}.json", dict(
            schema="usk.installed_state.v1", install_id=install, transaction_id=tx, created_at=stamp,
            lifecycle_status=status, target_root="E:\\publication\\destination\\visible"))
            for tx, stamp, status in ((initial, "2026-10-01T00:00:00Z", "installed"),
                                     (current, "2026-10-01T00:00:01Z", "verified"))]
        revision = hashlib.sha256(encoded([dict(record=entry["path"].rsplit("\\", 1)[1],
            sha256=hashlib.sha256(entry["content_json"][:-1].encode()).hexdigest())
            for entry in sorted(installed, key=lambda entry: entry["path"])]).encode()).hexdigest()
        journal = row(f"setup-state\\state\\transactions\\{current}.journal.json", dict(
            schema="usk.transaction_journal.v1", transaction_id=current, operation="repair", current_state="completed"))
        lease = row("setup-state\\state\\leases\\install-owned\\g00000000000000000002-terminal.json", dict(
            schema="usk.installation_lease_ownership.v1", install_id=install, operation_id=current,
            operation="repair", status="completed", result_state_revision=revision, operation_context_sha256="a" * 64))
        roots = row("installation-operations\\install-owned\\operation-owned-roots.json", dict(
            schema="usk.installation_operation_roots.v1", install_id=install, operation_id=current,
            roots_sha256="a" * 64, context_sha256="b" * 64))
        context = row("installation-operations\\install-owned\\operation-owned.json", dict(
            schema="usk.installation_operation_context.v2", install_id=install, operation_id=current,
            operation="repair", context_sha256="b" * 64))
        sealed = row(f"setup-state\\state\\transactions\\{current}.maintenance\\00000000000000000012.json", dict(
            schema="usk.maintenance_effect_record.v1", transaction_id=current, phase="sealed"))
        fixture = dict(service_sid=service, prepared=prepared, revision=revision,
                       rows=[snapshot, completion, *installed, journal, lease, roots, context, sealed])
        code = r"""$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText($env:USK_PROJECTION_SOURCE)
$start=$source.IndexOf("`$observer=@'`n",[StringComparison]::Ordinal)
if($start -lt 0){$start=$source.IndexOf("`$observer=@'`r`n",[StringComparison]::Ordinal)}
if($start -lt 0){throw 'Observer body absent'}
$body=$source.Substring($source.IndexOf("`n",$start)+1);$end=$body.IndexOf("`n'@",[StringComparison]::Ordinal)
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($body.Substring(0,$end),[ref]$t,[ref]$e)
if($e){throw 'Observer body syntax differs'}
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $n.Name -ceq 'Get-CompletedMaintenanceProjectionBasis'},$true))
if($functions.Count -ne 1){throw 'Completed observational join absent or ambiguous'}
. ([scriptblock]::Create($functions[0].Extent.Text))
$fixture=[IO.File]::ReadAllText($env:USK_PROJECTION_FIXTURE)|ConvertFrom-Json
$DriveRoot='E:\';$ServiceSid=$fixture.service_sid;$preparedRows=@($fixture.prepared)
$prepared=$fixture.prepared.content_json|ConvertFrom-Json;$tree=@{root=@{file_id='original-root'}}
foreach($variant in @('supported','missing_current','pending_journal','missing_seal','wrong_revision','wrong_context',
 'outside_acl','outside_owner','unprotected','outside_mask','outside_flags','outside_ace_count')) {
 $rows=$fixture.rows|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json
 switch($variant) {
  'missing_current' {$rows=@($rows|Where-Object path -cnotlike '*repair.current.json')}
  'missing_seal' {$rows=@($rows|Where-Object path -cnotlike '*.maintenance\*')}
  'pending_journal' {
   $j=@($rows|Where-Object path -clike '*.journal.json')[0]
   $v=$j.content_json|ConvertFrom-Json;$v.current_state='committed';$j.content_json=$v|ConvertTo-Json -Depth 16 -Compress
  }
  'wrong_revision' {
   $j=@($rows|Where-Object path -clike '*terminal.json')[0]
   $v=$j.content_json|ConvertFrom-Json;$v.result_state_revision='0'*64;$j.content_json=$v|ConvertTo-Json -Depth 16 -Compress
  }
  'wrong_context' {
   $j=@($rows|Where-Object path -ceq 'E:\installation-operations\install-owned\operation-owned.json')[0]
   $v=$j.content_json|ConvertFrom-Json;$v.context_sha256='0'*64;$j.content_json=$v|ConvertTo-Json -Depth 16 -Compress
  }
  'outside_acl' {@($rows|Where-Object path -clike '*.journal.json')[0].raw_aces[1].sid='S-1-5-11'}
  'outside_owner' {@($rows|Where-Object path -clike '*.journal.json')[0].owner='S-1-5-11'}
  'unprotected' {@($rows|Where-Object path -clike '*.journal.json')[0].protected=$false}
  'outside_mask' {@($rows|Where-Object path -clike '*.journal.json')[0].raw_aces[1].access_mask=1179785}
  'outside_flags' {@($rows|Where-Object path -clike '*.journal.json')[0].raw_aces[1].flags=16}
  'outside_ace_count' {@($rows|Where-Object path -clike '*.journal.json')[0].raw_aces=@()}
 }
 $refused=$false;$basis=$null
 try {$basis=Get-CompletedMaintenanceProjectionBasis} catch {
  $refused=$true;if($variant -ceq 'supported'){throw}
  if($variant -cin @('outside_acl','outside_owner','unprotected','outside_mask','outside_flags','outside_ace_count')) {
   $diagnosticPrefix='Historical payload projection metadata is outside the observed private policy; row='
   if(-not $_.Exception.Message.StartsWith($diagnosticPrefix,[StringComparison]::Ordinal)){throw 'Private-row diagnostic absent'}
   $facts=$_.Exception.Message.Substring($diagnosticPrefix.Length)|ConvertFrom-Json
   $expected=@($rows|Where-Object path -clike '*.journal.json')[0]
   if($facts.role -cne 'transaction_journal' -or $facts.path -cne $expected.path -or $facts.path_truncated -ne $false -or
    $facts.file_id -cne $expected.file_id -or $facts.sha256 -cne $expected.sha256 -or $facts.owner -cne $expected.owner -or
    $facts.protected -ne $expected.protected -or $facts.raw_ace_count -ne @($expected.raw_aces).Count) {
    throw 'Private-row diagnostic differs from the offending constructed data'
   }
   for($i=0;$i -lt @($expected.raw_aces).Count;$i++) {
    foreach($field in @('sid','type','flags','access_mask')) {
     if($facts.raw_aces[$i].$field -cne $expected.raw_aces[$i].$field){throw 'Private-row ACE diagnostic differs'}
    }
   }
  }
 }
 if($refused -ne ($variant -cne 'supported')){throw ('Observational join admission differs: '+$variant)}
 if($basis -and ($basis.result_state_revision -cne $fixture.revision -or $basis.operation -cne 'repair' -or
  $basis.transaction_id -cne 'repair.current' -or $basis.original_transaction_id -cne 'install.original')) {
  throw 'Completed observational join result differs'
 }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory) / "constructed-records.json"
            fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
            environment = dict(os.environ, USK_PROJECTION_SOURCE=str(root / "tests/windows_publisher_metadata_readback.ps1"),
                               USK_PROJECTION_FIXTURE=str(fixture_path))
            for binary in ("powershell", "pwsh"):
                if not shutil.which(binary):
                    continue
                with self.subTest(binary=binary):
                    result = subprocess.run([binary, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                        base64.b64encode(code.encode("utf-16le")).decode()], env=environment,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace"))

    def test_observer_publishes_only_after_token_close_acknowledgement(self):
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
class OwnedTokenClose {
 [bool]$Fail
 [bool]$Closed
 OwnedTokenClose([bool]$fail){$this.Fail=$fail}
 [void] Dispose(){if($this.Fail){throw 'owned token close failed'};$this.Closed=$true}
}
$source=[IO.File]::ReadAllText($env:USK_CLOSE_SOURCE)
$start=$source.IndexOf("`$observer=@'`n",[StringComparison]::Ordinal)
if($start -lt 0){$start=$source.IndexOf("`$observer=@'`r`n",[StringComparison]::Ordinal)}
if($start -lt 0){throw 'Observer body is absent'}
$body=$source.Substring($source.IndexOf("`n",$start)+1)
$end=$body.IndexOf("`n'@",[StringComparison]::Ordinal)
if($end -lt 0){throw 'Observer body is incomplete'}
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($body.Substring(0,$end),[ref]$t,[ref]$e)
if($e){throw 'Observer source parse failed'}
$statements=@($ast.EndBlock.Statements[-1].Body.Statements)
$first=-1
for($index=0;$index -lt $statements.Count;$index++) {
 if($statements[$index] -is [Management.Automation.Language.AssignmentStatementAst] -and
  $statements[$index].Left.VariablePath.UserPath -ceq 'temporary'){$first=$index;break}
}
if($first -lt 0){throw 'Atomic observer publication is absent'}
$tail=[scriptblock]::Create(($statements[$first..($statements.Count-1)].Extent.Text -join "`n"))
foreach($fail in @($false,$true)) {
 $Output=Join-Path $env:USK_CLOSE_ROOT ('result-'+$fail+'.json')
 $result=@{owned_control=$true};$lease=[OwnedTokenClose]::new($fail);$effectiveRights=$lease
 $failed=$false
 try {& $tail}catch {if($_.Exception.Message -cne 'owned token close failed'){throw};$failed=$true}
 if($failed -ne $fail){throw 'Token-close outcome differs'}
 if($fail) {
  if((Test-Path -LiteralPath $Output) -or (Test-Path -LiteralPath ($Output+'.pending'))){throw 'Failed token close exposed an observer receipt'}
 } else {
  $receipt=[IO.File]::ReadAllText($Output)|ConvertFrom-Json
  if(-not $lease.Closed -or $receipt.observer_token_handles_closed -ne $true){throw 'Successful receipt lacks completed token close'}
 }
}
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_PUBLIC_CLOSE_SOURCE,[ref]$t,[ref]$e)
if($e){throw 'Public cleanup source parse failed'}
$main=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
if($main.Count -ne 1){throw 'Public cleanup is absent or ambiguous'}
$cleanup=[scriptblock]::Create(($main[0].Finally.Statements.Extent.Text -join "`n"))
$boundaryObserver=$null;$created=$false;$unrelatedAccountCreated=$true;$unrelatedObserversClosed=$true
$receipt=[ordered]@{status='owned_control';unrelated_local_login=[ordered]@{cleanup='pending'}}
$clientTokenLease=[OwnedTokenClose]::new($true);$unrelatedTokenLease=[OwnedTokenClose]::new($false)
$OutputPath=Join-Path $env:USK_CLOSE_ROOT 'public-failed-close.json';$script:accountOperations=0
function Get-LocalUser {$script:accountOperations++;throw 'Unexpected local-account lookup'}
function Remove-LocalUser {$script:accountOperations++;throw 'Unexpected local-account removal'}
function Write-Json([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))}
& $cleanup
$saved=[IO.File]::ReadAllText($OutputPath)|ConvertFrom-Json
if(-not $unrelatedTokenLease.Closed -or $saved.status -cne 'failed' -or $saved.unrelated_observers_token_close_confirmed -ne $false -or
 $saved.unrelated_local_login.cleanup -cnotmatch '^observer/token close unconfirmed' -or $script:accountOperations -ne 0) {
 throw 'Failed client-token close skipped remaining cleanup or invented account retirement'
}
@{closed_before_publication=$true;failed_close_has_no_receipt=$true;failed_client_close_preserves_cleanup_receipt=$true}|ConvertTo-Json -Compress
"""
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='usk-token-close-') as temporary:
                environment = dict(os.environ, USK_CLOSE_ROOT=temporary,
                                   USK_CLOSE_SOURCE=str(root / 'tests/windows_publisher_metadata_readback.ps1'),
                                   USK_PUBLIC_CLOSE_SOURCE=str(root / 'tests/windows_publisher_public_path_probe.ps1'))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'closed_before_publication': True, 'failed_close_has_no_receipt': True,
                    'failed_client_close_preserves_cleanup_receipt': True})

    def test_public_requests_capture_each_client_and_retire_only_owned_prior_binding(self):
        root = Path(__file__).resolve().parents[1]
        # Benign local console fixture: only reads its owned request and prints
        # a complete no-effect response. No SCM, volume or account operations.
        stub = r'''using System;
using System.IO;
using System.Text.RegularExpressions;
public static class OwnedClient {
 public static int Main(string[] args) {
  int index=Array.IndexOf(args,"--request-file");
  if(index<0 || index+1>=args.Length)return 9;
  string id=Regex.Match(File.ReadAllText(args[index+1]),"\\\"request_id\\\":\\\"([^\\\"]+)\\\"").Groups[1].Value;
  Console.WriteLine("{\"schema\":\"usk.oneshot_response.v1\",\"request_id\":\""+id+"\",\"status\":\"failed\",\"result\":null,\"error\":{\"code\":\"owned_fixture_refusal\"}}");
  return 3;
 }
}'''
        code = r"""$ErrorActionPreference='Stop'
& (Get-Command powershell.exe).Source -NoProfile -NonInteractive -Command 'Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:USK_PUBLIC_STUB_SOURCE)) -OutputAssembly $env:USK_PUBLIC_STUB_EXE -OutputType ConsoleApplication'
if($LASTEXITCODE -ne 0){throw 'Owned console fixture compilation failed'}
. $env:USK_PUBLIC_READBACK
. $env:USK_PUBLIC_PROCESS_HELPER
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_PUBLIC_PROBE,[ref]$tokens,[ref]$errors)
if($errors){throw 'Public request fixture parse failed'}
foreach($name in @('Write-Json','Invoke-PublicRequest')) {
 $function=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true)
 if(@($function).Count -ne 1){throw 'Public request function absent or ambiguous'}
 . ([scriptblock]::Create($function[0].Extent.Text))
}
function Get-Service {param([string]$Name) [pscustomobject]@{Status='Stopped'}}
$lab=$env:USK_PUBLIC_ROOT;$MachineBinary=$env:USK_PUBLIC_STUB_EXE
$service='USK_PUB_'+[guid]::NewGuid().ToString('N');$sid='S-1-5-80-1-2-3-4-5'
$caller=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$owner=Get-Process -Id $PID;$invokingCreation=$owner.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$utf8=[Text.UTF8Encoding]::new($false);$clientTokenLease=$null
$clientCaptureFile=Join-Path $lab 'public-client-token.json';$clientCaptureSha256=''
$receipt=@{machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();machine_client_captures=[Collections.Generic.List[object]]::new()}
try {
 foreach($command in @('install_local.apply','install_local.recover','installed.verify')) {
  Invoke-PublicRequest $command @{} 3|Out-Null
  $capture=Get-Content -LiteralPath $clientCaptureFile -Raw|ConvertFrom-Json
  if($capture.command -cne $command -or $capture.request_id -cne $receipt.machine_client_capture.request_id -or
   $capture.initiating_token_id -cne $receipt.machine_client_capture.initiating_token_id){throw 'Current request capture differs'}
 }
 if($receipt.machine_client_captures.Count -ne 3 -or
  @($receipt.machine_client_captures.initiating_token_id|Select-Object -Unique).Count -ne 3 -or
  @(Get-ChildItem -LiteralPath $lab -Filter 'retired-client-token-*.json').Count -ne 2){throw 'Per-request capture/retirement sequence differs'}
 [IO.File]::AppendAllText($clientCaptureFile,'changed')
 $refused=$false
 try {Invoke-PublicRequest 'install_local.recover' @{} 3|Out-Null}catch {$refused=$_.Exception.Message -ceq 'Prior owned client capture changed before retirement'}
 if(-not $refused -or $receipt.machine_client_captures.Count -ne 3){throw 'Changed prior capture was reused or retired'}
 @{captured_clients=3;archived_captures=2;changed_prior_capture_refused=$true}|ConvertTo-Json -Compress
} finally {if($clientTokenLease){$clientTokenLease.Dispose()}}
"""
        shell = shutil.which('pwsh')
        self.assertIsNotNone(shell)
        with tempfile.TemporaryDirectory(prefix='usk-public-client-') as temporary:
            native_path = Path(temporary) / 'owned-client.cs'
            native_path.write_text(stub, encoding='utf-8')
            environment = dict(os.environ, USK_PUBLIC_ROOT=temporary, USK_PUBLIC_STUB_SOURCE=str(native_path),
                               USK_PUBLIC_STUB_EXE=str(Path(temporary) / 'owned-client.exe'),
                               USK_PUBLIC_PROBE=str(root / 'tests/windows_publisher_public_path_probe.ps1'),
                               USK_PUBLIC_READBACK=str(root / 'tests/windows_publisher_metadata_readback.ps1'),
                               USK_PUBLIC_PROCESS_HELPER=str(root / 'tests/windows_publisher_owned_process.ps1'))
            result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                    env=environment, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                'captured_clients': 3, 'archived_captures': 2, 'changed_prior_capture_refused': True})

    def test_volume_boundary_observation_rejects_foreign_and_mutating_facts(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'tests/windows_publisher_metadata_readback.ps1').read_text(encoding='utf-8')
        native = source.split('Add-Type -TypeDefinition @"', 1)[1].split('\n"@', 1)[0]
        code = r"""$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:USK_BOUNDARY_NATIVE))
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_BOUNDARY_PROBE,[ref]$tokens,[ref]$errors)
if($errors){throw 'Boundary assertion source parse failed'}
$function=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-PublicVolumeBoundary'},$true)
if(@($function).Count -ne 1){throw 'Boundary assertion is absent or ambiguous'}
. ([scriptblock]::Create($function[0].Extent.Text))
$extent=[byte[]]::new(32)
[BitConverter]::GetBytes([uint32]1).CopyTo($extent,0)
[BitConverter]::GetBytes([uint32]7).CopyTo($extent,8)
[BitConverter]::GetBytes([long]16777216).CopyTo($extent,16)
[BitConverter]::GetBytes([long]520028160).CopyTo($extent,24)
$parsed=[UskPublisherEffectiveRights]::ParseSingleExtent($extent,32,7)
$badExtents=0
foreach($variant in 0..6) {
 $bytes=$extent.Clone();$returned=[uint32]32;$disk=[uint32]7
 switch($variant) {
  0 {$returned=31}
  1 {$bytes=[byte[]]::new(8)}
  2 {[BitConverter]::GetBytes([uint32]2).CopyTo($bytes,0)}
  3 {$disk=8}
  4 {[BitConverter]::GetBytes([long]-1).CopyTo($bytes,16)}
  5 {[BitConverter]::GetBytes([long]0).CopyTo($bytes,24)}
  6 {[BitConverter]::GetBytes([long]::MaxValue).CopyTo($bytes,16)}
 }
 $refused=$false
 try {[UskPublisherEffectiveRights]::ParseSingleExtent($bytes,$returned,$disk)|Out-Null}catch {$refused=$true}
 if(-not $refused){throw 'Contradictory raw-volume extent was admitted'}
 ++$badExtents
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$service='S-1-5-80-1-2-3-4-5';$process=Get-Process -Id $PID
$rights=[UskPublisherEffectiveRights]::new($PID,$process.StartTime.ToUniversalTime().ToFileTimeUtc(),$sid,$service)
try {
 $security='O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$service+')'
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($security)
 $bytes=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($bytes,0)
 $aces=@(@{type=0;flags=0;access_mask=2032127;sid='S-1-5-18'},@{type=0;flags=0;access_mask=2032127;sid=$service})
 $native=@{attributes=22;case_sensitive=$false;dacl_aces=$aces;dacl_protected=$true;
  file_id='123456789abcdef0:05000000000005000000000000000000';link_count=1;native_name='\';owner_sid='S-1-5-18';reparse_tag=0}
 $prepared=@{protected_anchors=@{boundary=$native}}|ConvertTo-Json -Depth 12 -Compress
 $observed=@{rows=@(@{path='Q:\publication\journal\lab-prepared-evidence.json';content_json=$prepared})}
 $boundary=@{root=@{path='Q:\';directory=$true;file_id=$native.file_id;native_name='\';attributes=22;
  link_count=1;case_sensitive=$false;streams=@();owner='S-1-5-18';protected=$true;raw_aces=$aces;effective_rights=$rights.CheckDescriptor($bytes)};
  device=@{path='\\?\Volume{00000000-0000-0000-0000-000000000001}';extent=$parsed;raw_security=$security;checks=$rights.CheckDescriptor($bytes)}}
 $deviceIntent=@{original_owner_dacl=$security;intended_policy=@{owner='S-1-5-18';dacl_protected=$true;
  aces=@(@{type=0;flags=0;mask=2032127;sid='S-1-5-18'},@{type=0;flags=0;mask=2032127;sid=$service})}}|ConvertTo-Json -Depth 12|ConvertFrom-Json
 Assert-PublicVolumeBoundary $observed $boundary 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service $deviceIntent
 $badIntents=0
 foreach($change in @(
  {param($i) $i.PSObject.Properties.Remove('intended_policy')},
  {param($i) $i.intended_policy=$null},
  {param($i) $i.intended_policy.owner='S-1-5-32-544'},
  {param($i) $i.intended_policy.dacl_protected=$false},
  {param($i) $i.intended_policy.aces[0].mask=1179785},
  {param($i) $i.intended_policy.aces[0].flags=16},
  {param($i) $i.intended_policy.aces[1].sid='S-1-5-32-545'},
  {param($i) $i.intended_policy.aces=@($i.intended_policy.aces[0])})) {
  $bad=$deviceIntent|ConvertTo-Json -Depth 12|ConvertFrom-Json;& $change $bad
  $refused=$false
  try {Assert-PublicVolumeBoundary $observed $boundary 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service $bad}catch {$refused=$true}
  if(-not $refused){throw 'Missing or mismatched mounted device intent was admitted'}
  ++$badIntents
 }
 $badBoundaries=0
 foreach($change in @(
  {param($b) $b.root.file_id='123456789abcdef0:06000000000005000000000000000000'},
  {param($b) $b.root.raw_aces[0].flags=16},
  {param($b) $b.root.case_sensitive=$true},
  {param($b) $b.root.effective_rights.filtered.delete.allowed=$true;$b.root.effective_rights.filtered.delete.granted=65536},
  {param($b) $b.device.extent.disk_number=8},
  {param($b) $b.device.extent.length--},
  {param($b) $b.device.raw_security='O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$service+')(A;;FW;;;WD)'},
  {param($b) $b.device.checks.filtered.maximum_allowed.granted=65536})) {
  $bad=$boundary|ConvertTo-Json -Depth 16|ConvertFrom-Json;& $change $bad
  $refused=$false
  try {Assert-PublicVolumeBoundary $observed $bad 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service $deviceIntent}catch {$refused=$true}
  if(-not $refused){throw 'Contradictory volume namespace/device facts were admitted'}
  ++$badBoundaries
 }
 # These are explicit pure observation controls, not unrelated-login evidence.
 $three=$boundary|ConvertTo-Json -Depth 16|ConvertFrom-Json
 $three.root.effective_rights|Add-Member NoteProperty unrelated $three.root.effective_rights.filtered
 $three.device.checks|Add-Member NoteProperty unrelated $three.device.checks.filtered
 Assert-PublicVolumeBoundary $observed $three 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service $deviceIntent -RequireUnrelated
 $unrelatedRefusals=0
 foreach($location in @('root','device')) {
  foreach($missing in @('all','maximum_allowed','write_or_add_file','append_or_add_directory','write_ea','delete_child','write_attributes','delete','write_dac','write_owner')) {
   $bad=$three|ConvertTo-Json -Depth 16|ConvertFrom-Json
   $checks=if($location -ceq 'root'){$bad.root.effective_rights}else{$bad.device.checks}
   if($missing -ceq 'all'){$checks.PSObject.Properties.Remove('unrelated')}
   else {$checks.unrelated.PSObject.Properties.Remove($missing)}
   $refused=$false
   try {Assert-PublicVolumeBoundary $observed $bad 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service $deviceIntent -RequireUnrelated}catch {$refused=$true}
   if(-not $refused){throw 'Missing unrelated boundary evidence was admitted'}
   ++$unrelatedRefusals
  }
 }
 @{owned_token_control=$true;extent_refusals=$badExtents;boundary_refusals=$badBoundaries;missing_unrelated_refusals=$unrelatedRefusals;device_intent_refusals=$badIntents}|ConvertTo-Json -Compress
} finally {$rights.Dispose()}
"""
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='usk-boundary-') as temporary:
                native_path = Path(temporary) / 'native.cs'
                native_path.write_text(native, encoding='utf-8')
                environment = dict(os.environ, USK_BOUNDARY_NATIVE=str(native_path),
                                   USK_BOUNDARY_PROBE=str(root / 'tests/windows_publisher_public_path_probe.ps1'))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'owned_token_control': True, 'extent_refusals': 7, 'boundary_refusals': 8,
                    'missing_unrelated_refusals': 20, 'device_intent_refusals': 8})

    def test_real_client_token_is_captured_before_resume_and_read_after_exit(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'tests/windows_publisher_metadata_readback.ps1').read_text(encoding='utf-8')
        native = source.split('Add-Type -TypeDefinition @"', 1)[1].split('\n"@', 1)[0]
        code = "& ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_CAPTURE_UNIT))) -Root $env:USK_CAPTURE_ROOT"
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='usk-held-client-') as temporary:
                native_path = Path(temporary) / 'native.cs'
                native_path.write_text(native, encoding='utf-8')
                environment = dict(os.environ, USK_CAPTURE_ROOT=temporary, USK_CAPTURE_NATIVE=str(native_path),
                                   USK_CAPTURE_UNIT=str(root / 'tests/windows_publisher_client_token_unit.ps1'))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([json.loads(line) for line in result.stdout.splitlines()], [
                    {'held_exited_client_observed': True, 'positive_owned_control': True,
                     'closed_actor_checks': 18, 'contradictory_contexts_refused': 7,
                     'invalid_owned_login_inputs_refused': 3},
                    {'primary_thread_paused_during_capture': True, 'client_token_captured': True,
                     'resume_once_refused': True, 'stdout_observed': True},
                    {'never_resumed_client_termination_confirmed': True}])

    def test_public_fixture_exit_status_follows_final_assertions(self):
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_PUBLIC_SOURCE,[ref]$t,[ref]$e)
if($e){throw 'Public probe parse failed'}
$statements=@($ast.EndBlock.Statements)
$tail=[scriptblock]::Create(($statements[-3..-1].Extent.Text -join "`n"))
$positive=0;$refused=0
foreach($profile in @('none','metadata_collision','payload_changed')) {
 $PostRenameRefusal=$profile
 $receipt=@{status=$(if($profile -ceq 'none'){'public_install_verified_recovered'}else{'public_refusal_retained'});client_cleanup_confirmed=$true;failure='controlled failed assertion'}
 $global:LASTEXITCODE=3
 & $tail
 if($global:LASTEXITCODE -ne 0){throw 'Successful fixture leaked expected refusal exit code'}
 ++$positive
 foreach($change in @('status','cleanup')) {
  $bad=@{};foreach($key in $receipt.Keys){$bad[$key]=$receipt[$key]}
  if($change -ceq 'status'){$bad.status='failed'}else{$bad.client_cleanup_confirmed=$false}
  $saved=$receipt;$receipt=$bad;$global:LASTEXITCODE=3
  try {& $tail;throw 'Failed fixture assertion was suppressed'}
  catch {if($_.Exception.Message -ceq 'Failed fixture assertion was suppressed'){throw};++$refused}
  if($global:LASTEXITCODE -ne 3){throw 'Failure was converted into success exit status'}
  $receipt=$saved
 }
}
@{successful_profiles=$positive;failed_assertions_retained=$refused}|ConvertTo-Json -Compress
"""
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell):
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=dict(os.environ, USK_PUBLIC_SOURCE=str(root / 'tests/windows_publisher_public_path_probe.ps1')),
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'successful_profiles': 3, 'failed_assertions_retained': 6})

    def test_metadata_collision_worker_retains_guard_failure_without_target_access(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'tests/windows_publisher_owned_metadata_collision.ps1').read_text(encoding='utf-8')
        worker = source.split("$observer=@'\n", 1)[1].split("\n'@", 1)[0]
        code = r"""$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ceq 'S-1-5-18') {
 throw 'Non-SYSTEM owned unit fixture required'
}
$worker=[scriptblock]::Create([IO.File]::ReadAllText($env:USK_COLLISION_WORKER))
& $worker -VhdPath 'invalid' -VolumeRoot 'invalid' -DriveRoot 'invalid' -ServiceName 'invalid' -ServiceSid 'invalid' -TransactionId 'invalid' -Output $env:USK_COLLISION_OUTPUT
$item=Get-Item -LiteralPath $env:USK_COLLISION_OUTPUT
$record=[IO.File]::ReadAllText($item.FullName)|ConvertFrom-Json
if($item.Length -gt 16KB -or $record.schema -cne 'usk.publisher.owned_metadata_collision.v1' -or
 $record.status -cne 'failed' -or $record.failure -cne 'Owned SYSTEM metadata collision context differs' -or
 $record.identity -ceq 'S-1-5-18' -or (Test-Path -LiteralPath ($env:USK_COLLISION_OUTPUT+'.pending'))) {
 throw 'Guard failure was lost or reached the target'
}
@{guard_failure_retained=$true;target_access=$false;pending_absent=$true}|ConvertTo-Json -Compress
"""
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='usk-collision-guard-') as temporary:
                path = Path(temporary) / 'worker.ps1'
                path.write_text(worker, encoding='utf-8')
                environment = dict(os.environ, USK_COLLISION_WORKER=str(path),
                                   USK_COLLISION_OUTPUT=str(Path(temporary) / 'failure.json'))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'guard_failure_retained': True, 'target_access': False, 'pending_absent': True})

    def test_metadata_collision_admits_only_bound_private_recovery_prefix(self):
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_READBACK_SOURCE,[ref]$tokens,[ref]$errors)
if($errors){throw 'Readback source parse failed'}
foreach($name in @('Assert-IndependentRetainedMaterial','Assert-IndependentMetadataCollisionPrefix')) {
 $function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
  $n.Name -eq $name},$true)
 . ([scriptblock]::Create($function.Extent.Text))
}
function Copy-PrefixFixture($value){$value|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json}
$drive='E:\';$sid='S-1-5-80-1-2-3-4-5';$rootId='ffffffffffffffff:root';$destinationId='ffffffffffffffff:destination'
$prepared=[ordered]@{schema='usk.publisher.lab_phase_evidence.v2';phase='lab_prepared_evidence';service_sid=$sid;
 source_file_id=$rootId;destination_parent_file_id=$destinationId;destination_name='visible';
 selected_file_set_digest=('c'*64);source_binding=[ordered]@{reviewed_plan_digest=('d'*64);reviewed_plan_snapshot_sha256=('e'*64)}}
$before=[pscustomobject]@{rows=@(
 [pscustomobject]@{path='E:\publication\journal\lab-prepared-evidence.json';directory=$false;sha256=('a'*64);content_json=($prepared|ConvertTo-Json -Depth 32 -Compress)},
 [pscustomobject]@{path='E:\publication\destination';directory=$true;file_id=$destinationId},
 [pscustomobject]@{path='E:\publication\destination\visible';directory=$true;file_id=$rootId})}
$visible=[ordered]@{schema='usk.publisher.lab_phase_evidence.v2';phase='lab_visible_evidence';
 prepared_record_sha256=('a'*64);source_file_id=$rootId;destination_parent_file_id=$destinationId;
 destination_name='visible';selected_file_set_digest=('c'*64)}
$visibleRow=[pscustomobject]@{path='E:\publication\journal\lab-visible-evidence.json';directory=$false;sha256=('b'*64);content_json=($visible|ConvertTo-Json -Compress)}
$completion=[ordered]@{schema='usk.publisher.lab_installed_state.v2';phase='lab_installed_state';service_sid=$sid;
 prepared_record_sha256=('a'*64);visible_record_sha256=('b'*64);visible_root_file_id=$rootId;
 destination_parent_file_id=$destinationId;destination_name='visible';selected_file_set_digest=('c'*64);
 source_binding=$prepared.source_binding;volume_serial=[uint64]::MaxValue}
$completionRow=[pscustomobject]@{path='E:\publication\state\lab-installed-state.json';directory=$false;sha256=('f'*64);content_json=($completion|ConvertTo-Json -Depth 32 -Compress)}
$visibleOnly=Copy-PrefixFixture $before;$visibleOnly.rows+=@(Copy-PrefixFixture $visibleRow)
$both=Copy-PrefixFixture $visibleOnly;$both.rows+=@(Copy-PrefixFixture $completionRow)
Assert-IndependentMetadataCollisionPrefix $before $before $drive $sid
Assert-IndependentMetadataCollisionPrefix $before $visibleOnly $drive $sid
Assert-IndependentMetadataCollisionPrefix $before $both $drive $sid
Assert-IndependentRetainedMaterial $visibleOnly $both
function Set-PrefixField($row,[string]$field,$value) {
 $record=$row.content_json|ConvertFrom-Json;$record.$field=$value
 $row.content_json=$record|ConvertTo-Json -Depth 32 -Compress
}
$refused=0
foreach($mutation in @(
 {param($r) $r.rows[3].path='E:\publication\journal\unexpected.json'},
 {param($r) $r.rows[3].path='E:\setup-state\audit\chains\foreign'},
 {param($r) $r.rows[3].path='E:\setup-state\state\ownership\foreign.json'},
 {param($r) $r.rows[3].directory=$true},
 {param($r) Set-PrefixField $r.rows[3] 'prepared_record_sha256' ('0'*64)},
 {param($r) Set-PrefixField $r.rows[3] 'source_file_id' 'foreign'},
 {param($r) Set-PrefixField $r.rows[3] 'destination_parent_file_id' 'foreign'},
 {param($r) Set-PrefixField $r.rows[4] 'visible_record_sha256' ('0'*64)},
 {param($r) Set-PrefixField $r.rows[4] 'service_sid' 'foreign'},
 {param($r) Set-PrefixField $r.rows[4] 'visible_root_file_id' 'foreign'},
 {param($r) Set-PrefixField $r.rows[4] 'selected_file_set_digest' ('0'*64)},
 {param($r) Set-PrefixField $r.rows[4] 'source_binding' @{reviewed_plan_digest='foreign'}},
 {param($r) $r.rows[4].content_json=$r.rows[4].content_json.Replace('18446744073709551615','18446744073709551614')},
 {param($r) $r.rows=@($r.rows[0],$r.rows[1],$r.rows[2],$r.rows[4])})) {
 $bad=Copy-PrefixFixture $both;& $mutation $bad
 try {Assert-IndependentMetadataCollisionPrefix $before $bad $drive $sid;throw 'Foreign prefix admitted'}
 catch {if($_.Exception.Message -ceq 'Foreign prefix admitted'){throw};++$refused}
}
$bad=Copy-PrefixFixture $both;Set-PrefixField $bad.rows[3] 'prepared_record_sha256' ('0'*64)
try {Assert-IndependentRetainedMaterial $visibleOnly $bad;throw 'Admitted predecessor rewritten'}
catch {if($_.Exception.Message -ceq 'Admitted predecessor rewritten'){throw};++$refused}
@{positive=4;refused=$refused;scope='synthetic metadata collision prefix only'}|ConvertTo-Json -Compress
"""
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell):
                environment = dict(os.environ, USK_READBACK_SOURCE=str(root / 'tests/windows_publisher_metadata_readback.ps1'))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'positive': 4, 'refused': 15, 'scope': 'synthetic metadata collision prefix only'})

    def test_retained_material_comparison_limits_the_controlled_fault(self):
        root = Path(__file__).resolve().parents[1]
        code = r"""$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:USK_READBACK_SOURCE,[ref]$tokens,[ref]$errors)
if($errors){throw 'Readback source parse failed'}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $n.Name -eq 'Assert-IndependentRetainedMaterial'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$before=[pscustomobject]@{rows=@([pscustomobject][ordered]@{path='E:\owned\payload.bin';directory=$false;
 file_id='retained';sha256=('a'*64);bytes=3;link_count=1;raw_security='original';streams=@('::$DATA')})}
function Copy-RetentionFixture($value){$value|ConvertTo-Json -Depth 16 -Compress|ConvertFrom-Json}
$same=Copy-RetentionFixture $before
Assert-IndependentRetainedMaterial $before $same -NoAdditionalRows
$changed=Copy-RetentionFixture $before;$changed.rows[0].sha256='b'*64
Assert-IndependentRetainedMaterial $before $changed -ChangedPayloadPath 'E:\owned\payload.bin' -ChangedPayloadSha256 ('b'*64) -NoAdditionalRows
$more=Copy-RetentionFixture $before;$extra=Copy-RetentionFixture $before.rows[0];$extra.path='E:\owned\metadata';$more.rows=@($more.rows)+@($extra)
Assert-IndependentRetainedMaterial $before $more
$refused=0
foreach($mutation in @(
 {param($r) $r.rows[0].file_id='foreign'},
 {param($r) $r.rows[0].sha256='c'*64},
 {param($r) $r.rows[0].bytes=4},
 {param($r) $r.rows[0].link_count=2},
 {param($r) $r.rows[0].raw_security='different'},
 {param($r) $r.rows[0].streams=@('::$DATA',':extra:$DATA')},
 {param($r) $r.rows=@()},
 {param($r) $r.rows=@($r.rows)+@($r.rows[0])})) {
 $bad=Copy-RetentionFixture $before;& $mutation $bad
 try {Assert-IndependentRetainedMaterial $before $bad -NoAdditionalRows;throw 'Invalid retention was accepted'}
 catch {if($_.Exception.Message -ceq 'Invalid retention was accepted'){throw};++$refused}
}
try {Assert-IndependentRetainedMaterial $before $more -NoAdditionalRows;throw 'Extra rows admitted'}
catch {if($_.Exception.Message -ceq 'Extra rows admitted'){throw};++$refused}
try {Assert-IndependentRetainedMaterial $before $same -ChangedPayloadPath 'E:\owned\payload.bin' -ChangedPayloadSha256 ('a'*64);throw 'Non-drift admitted'}
catch {if($_.Exception.Message -ceq 'Non-drift admitted'){throw};++$refused}
@{positive=3;refused=$refused;scope='synthetic retention oracle only'}|ConvertTo-Json -Compress
"""
        for shell in [shutil.which('pwsh'), shutil.which('powershell.exe')]:
            self.assertIsNotNone(shell)
            with self.subTest(shell=shell):
                environment = dict(os.environ, USK_READBACK_SOURCE=str(root / 'tests/windows_publisher_metadata_readback.ps1'))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'positive': 3, 'refused': 10, 'scope': 'synthetic retention oracle only'})

    def test_effective_rights_bind_live_token_and_distinguish_grants_from_denials(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'tests/windows_publisher_metadata_readback.ps1').read_text(encoding='utf-8')
        native = source.split('Add-Type -TypeDefinition @"', 1)[1].split('\n"@', 1)[0]
        shells = [shutil.which('pwsh'), shutil.which('powershell.exe')]
        self.assertTrue(all(shells), 'Both qualification observer runtimes are required')
        code = r"""$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:USK_RIGHTS_SOURCE))
$process=Get-Process -Id $PID
$created=$process.StartTime.ToUniversalTime().ToFileTimeUtc()
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$service='S-1-5-80-1-2-3-4-5'
$rights=[UskPublisherEffectiveRights]::new($PID,$created,$sid,$service)
try {
 $file=Join-Path $env:USK_RIGHTS_ROOT 'owned.bin'
 [IO.File]::WriteAllBytes($file,[byte[]]@(0x55,0x53,0x4b))
 $own=$rights.Read($file)
 $facts=[UskMetadataFacts]::Read($file)
 $sha=[Security.Cryptography.SHA256]::Create()
 try {$expectedDigest=[BitConverter]::ToString($sha.ComputeHash([byte[]]$facts[1])).Replace('-','').ToLowerInvariant()}
 finally {$sha.Dispose()}
 if($own['owner_dacl_sha256'] -cne $expectedDigest){throw 'Held owner/DACL digest differs from independent stored bytes'}
 if(-not $own['checks']['filtered']['write_or_add_file']['allowed']) {
  throw 'Positive owned-file control failed to observe granted write access'
 }
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$service+')')
 $descriptor=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($descriptor,0)
 $closed=$rights.CheckDescriptor($descriptor)
 $count=0
 foreach($entry in $closed['filtered'].GetEnumerator()) {
  if($entry.Value['allowed'] -or $entry.Value['granted'] -ne 0) {throw 'Closed descriptor granted the filtered invoking token'}
  ++$count
 }
 if($rights.TokenFacts['initiating']['user_sid'] -cne $sid -or
    $rights.TokenFacts['filtered']['user_sid'] -cne $sid) {throw 'Token observation lost the actual invoking identity'}
 $refused=0
 foreach($bad in @(@(($created+1),$sid),@($created,'S-1-5-21-1-2-3-1001'))) {
  $unexpected=$null
  try {$unexpected=[UskPublisherEffectiveRights]::new($PID,$bad[0],$bad[1],$service)}
  catch {++$refused}
  finally {if($unexpected){$unexpected.Dispose()}}
 }
 if($refused -ne 2){throw 'Contradictory process/token context was admitted'}
 @{positive_write=$true;closed_checks=$count;contradictory_contexts_refused=$refused}|ConvertTo-Json -Compress
} finally {$rights.Dispose()}
"""
        for shell in shells:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='usk-rights-readback-') as temporary:
                native_path = Path(temporary) / 'native.cs'
                native_path.write_text(native, encoding='utf-8')
                environment = dict(os.environ, USK_RIGHTS_ROOT=temporary,
                                   USK_RIGHTS_SOURCE=str(native_path))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'positive_write': True, 'closed_checks': 9, 'contradictory_contexts_refused': 2})

    def test_native_closure_reader_distinguishes_identity_links_and_streams(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'tests/windows_publisher_metadata_readback.ps1').read_text()
        native = source.split('Add-Type -TypeDefinition @"', 1)[1].split('\n"@', 1)[0]
        shells = [shutil.which('pwsh'), shutil.which('powershell.exe')]
        self.assertTrue(all(shells), 'Both observer and cancellation PowerShell runtimes are required')
        for shell in shells:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='usk-native-readback-') as temporary:
                directory = Path(temporary)
                (directory / 'native.cs').write_text(native, encoding='utf-8')
                code = r"""$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:USK_READBACK_NATIVE))
$root=$env:USK_READBACK_ROOT
$file=Join-Path $root 'payload.bin'
$moved=Join-Path $root 'moved.bin'
[IO.File]::WriteAllBytes($file,[byte[]]@(0x55,0x53,0x4b))
$initial=[UskMetadataFacts]::ReadClosure($file)
$parent=[UskMetadataFacts]::ReadClosure($root)
if($initial[3] -ne 1 -or $initial[4] -or @($initial[5]).Count -ne 1 -or
 $initial[5][0]['name'] -cne '::$DATA' -or $initial[5][0]['size'] -ne 3 -or
 $initial[7] -ne 3 -or $initial[8] -cne $file.Substring(2) -or
 ($parent[2] -band 16) -eq 0 -or $parent[4] -or @($parent[5]).Count -ne 0) {
 throw 'Initial native file/directory facts differ'
}
[IO.File]::Move($file,$moved)
[IO.File]::WriteAllBytes($file,[byte[]]@(0x55,0x53,0x4b))
$foreign=[UskMetadataFacts]::ReadClosure($file)
$retained=[UskMetadataFacts]::ReadClosure($moved)
if($initial[0] -ceq $foreign[0] -or $initial[6] -cne $foreign[6] -or
 $initial[0] -cne $retained[0] -or $retained[8] -cne $moved.Substring(2)) {
 throw 'Native identity reader confused equal bytes with the retained object'
}
New-Item -ItemType HardLink -Path (Join-Path $root 'linked.bin') -Target $file|Out-Null
Set-Content -LiteralPath $file -Stream probe -Value 'AB' -Encoding Ascii -NoNewline
$linked=[UskMetadataFacts]::ReadClosure($file)
if($linked[3] -ne 2 -or @($linked[5]).Count -ne 2 -or
 @($linked[5]|Where-Object {$_['name'] -ceq ':probe:$DATA' -and $_['size'] -eq 2}).Count -ne 1) {
 throw 'Native link/stream observations omitted distinct facts'
}
@{identity_distinguished=$true;rename_identity_retained=$true;links=$linked[3];streams=@($linked[5]).Count}|ConvertTo-Json -Compress
"""
                environment = dict(os.environ, USK_READBACK_NATIVE=str(directory / 'native.cs'),
                                   USK_READBACK_ROOT=str(directory))
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', code],
                                        env=environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'identity_distinguished': True, 'rename_identity_retained': True,
                    'links': 2, 'streams': 2})

    def test_incomplete_cim_creation_time_waits_for_disappearance(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh")
        self.assertIsNotNone(shell)
        child = base64.b64encode("Start-Sleep -Seconds 30".encode("utf-16-le")).decode("ascii")
        environment = dict(os.environ, USK_CHILD_COMMAND=child,
                           USK_PROCESS_HELPER=str(root / "tests/windows_publisher_owned_process.ps1"))
        code = """$ErrorActionPreference='Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_PROCESS_HELPER)))
$p=Start-Process (Get-Command pwsh).Source -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$env:USK_CHILD_COMMAND) -PassThru -WindowStyle Hidden
try {
 $p|Add-Member -NotePropertyName UskOwnedTree -NotePropertyValue @([pscustomobject]@{ProcessId=$p.Id;CreationDate=$p.StartTime.ToUniversalTime();ExecutablePath='recorded';CommandLine='recorded'})
 $script:reads=0
 function Get-CimInstance {param([string]$Filter) $script:reads++; if($script:reads -eq 1){[pscustomobject]@{CreationDate=$null;ExecutablePath=$null;CommandLine=$null}}}
 $result=Stop-OwnedPublisherProcessTree $p
 if(-not $result.confirmed -or $script:reads -ne 2){throw 'Incomplete live CIM row was counted as an exited process'}
 $result|ConvertTo-Json -Compress
} finally {if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()}}
"""
        result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", code],
                                env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["confirmed"])

    def test_owned_wrapper_and_child_termination_is_confirmed(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh")
        self.assertIsNotNone(shell, "PowerShell 7 is required for process-tree cancellation")
        encode = lambda value: base64.b64encode(value.encode("utf-16-le")).decode("ascii")
        child = encode("Start-Sleep -Seconds 30")
        wrapper = encode("$c=Start-Process (Get-Command pwsh).Source -ArgumentList "
                         "@('-NoProfile','-NonInteractive','-EncodedCommand','" + child + "') "
                         "-PassThru -WindowStyle Hidden; "
                         "[IO.File]::WriteAllText($env:USK_CHILD_ID,[string]$c.Id); $c.WaitForExit()")
        with tempfile.TemporaryDirectory() as temporary:
            environment = dict(os.environ, USK_CHILD_ID=str(Path(temporary) / "child-id"),
                               USK_WRAPPER=wrapper,
                               USK_PROCESS_HELPER=str(root / "tests/windows_publisher_owned_process.ps1"))
            code = """$ErrorActionPreference='Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_PROCESS_HELPER)))
$p=Start-Process (Get-Command pwsh).Source -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$env:USK_WRAPPER) -PassThru -WindowStyle Hidden
try {
 $until=[DateTime]::UtcNow.AddSeconds(10)
 while(-not (Test-Path -LiteralPath $env:USK_CHILD_ID)) {
  if([DateTime]::UtcNow -ge $until){throw 'Owned child did not start'}
  Start-Sleep -Milliseconds 50
 }
 $result=Stop-OwnedPublisherProcessTree $p
 if(-not $result.confirmed -or $result.terminated -lt 2){throw 'Owned descendant termination was not established'}
 $result|ConvertTo-Json -Compress
} finally {if(-not $p.HasExited){Stop-OwnedPublisherProcessTree $p|Out-Null}}
"""
            result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", code],
                                    env=environment, capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["confirmed"])

    def test_exited_wrapper_does_not_forget_a_live_recorded_child(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh")
        self.assertIsNotNone(shell)
        encode = lambda value: base64.b64encode(value.encode("utf-16-le")).decode("ascii")
        child = encode("Start-Sleep -Seconds 30")
        wrapper = encode("$c=Start-Process (Get-Command pwsh).Source -ArgumentList "
                         "@('-NoProfile','-NonInteractive','-EncodedCommand','" + child + "') "
                         "-PassThru -WindowStyle Hidden; "
                         "[IO.File]::WriteAllText($env:USK_CHILD_ID,[string]$c.Id)")
        with tempfile.TemporaryDirectory() as temporary:
            environment = dict(os.environ, USK_CHILD_ID=str(Path(temporary) / "child-id"),
                               USK_WRAPPER=wrapper,
                               USK_PROCESS_HELPER=str(root / "tests/windows_publisher_owned_process.ps1"))
            code = """$ErrorActionPreference='Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_PROCESS_HELPER)))
$p=Start-Process (Get-Command pwsh).Source -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$env:USK_WRAPPER) -PassThru -WindowStyle Hidden
$child=$null
try {
 if(-not $p.WaitForExit(10000)){throw 'Owned wrapper did not exit'}
 $child=Get-Process -Id ([int][IO.File]::ReadAllText($env:USK_CHILD_ID))
 $record=Get-CimInstance Win32_Process -Filter ('ProcessId='+$child.Id)
 $p|Add-Member -NotePropertyName UskOwnedTree -NotePropertyValue @($record)
 $refused=$false
 try {Stop-OwnedPublisherProcessTree $p|Out-Null} catch {
  if($_.Exception.Message -notmatch 'Owned process descendants remain'){throw}
  $refused=$true
 }
 if(-not $refused -or $child.HasExited){throw 'Exited wrapper erased a live owned child'}
 $child.Kill();$child.WaitForExit()
 $result=Stop-OwnedPublisherProcessTree $p
 if(-not $result.confirmed){throw 'Final child exit was not confirmed'}
 $result|ConvertTo-Json -Compress
} finally {
 if($child -and -not $child.HasExited){$child.Kill();$child.WaitForExit()}
 if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()}
}
"""
            result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", code],
                                    env=environment, capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["confirmed"])

    def test_record_substitution_and_failed_cleanup_are_refused(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh") or shutil.which("powershell.exe")
        self.assertIsNotNone(shell, "Installed Windows PowerShell is required")
        environment = dict(os.environ, USK_METADATA_SOURCE=str(root),
                           USK_METADATA_TEST=str(root / "tests/windows_publisher_metadata_readback_smoke.ps1"))
        # Read this repository test as trusted command input. No execution
        # policy override or machine-wide configuration change is used.
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference='Stop'; & ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_METADATA_TEST))) -SourceRoot $env:USK_METADATA_SOURCE"],
            env=environment, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual((observed["positive"], observed["refused"]), (5, 24))
        self.assertIn("no VM/runtime qualification", observed["scope"])


if __name__ == "__main__":
    unittest.main()
