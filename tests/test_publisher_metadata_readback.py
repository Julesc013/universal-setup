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
