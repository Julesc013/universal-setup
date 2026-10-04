# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

import json
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == "nt", "Windows PowerShell readback oracle")
class PublisherMetadataReadbackTests(unittest.TestCase):
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
 Assert-PublicVolumeBoundary $observed $boundary 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service
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
  try {Assert-PublicVolumeBoundary $observed $bad 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service}catch {$refused=$true}
  if(-not $refused){throw 'Contradictory volume namespace/device facts were admitted'}
  ++$badBoundaries
 }
 # These are explicit pure observation controls, not unrelated-login evidence.
 $three=$boundary|ConvertTo-Json -Depth 16|ConvertFrom-Json
 $three.root.effective_rights|Add-Member NoteProperty unrelated $three.root.effective_rights.filtered
 $three.device.checks|Add-Member NoteProperty unrelated $three.device.checks.filtered
 Assert-PublicVolumeBoundary $observed $three 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service -RequireUnrelated
 $unrelatedRefusals=0
 foreach($location in @('root','device')) {
  foreach($missing in @('all','maximum_allowed','write_or_add_file','append_or_add_directory','write_ea','delete_child','write_attributes','delete','write_dac','write_owner')) {
   $bad=$three|ConvertTo-Json -Depth 16|ConvertFrom-Json
   $checks=if($location -ceq 'root'){$bad.root.effective_rights}else{$bad.device.checks}
   if($missing -ceq 'all'){$checks.PSObject.Properties.Remove('unrelated')}
   else {$checks.unrelated.PSObject.Properties.Remove($missing)}
   $refused=$false
   try {Assert-PublicVolumeBoundary $observed $bad 'Q:\' ($boundary.device.path+'\') 7 16777216 520028160 $service -RequireUnrelated}catch {$refused=$true}
   if(-not $refused){throw 'Missing unrelated boundary evidence was admitted'}
   ++$unrelatedRefusals
  }
 }
 @{owned_token_control=$true;extent_refusals=$badExtents;boundary_refusals=$badBoundaries;missing_unrelated_refusals=$unrelatedRefusals}|ConvertTo-Json -Compress
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
                    'missing_unrelated_refusals': 20})

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
