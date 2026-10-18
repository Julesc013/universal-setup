# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Run the actual fixture enrollment control flow with a data-only controller."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh') or shutil.which('powershell')
POWERSHELLS = tuple(dict.fromkeys(filter(None, (shutil.which('powershell'), shutil.which('pwsh')))))
SCRIPT = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_standard_public_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Standard fixture parse failed'}
$nodes=@($ast.FindAll({param($node)
    ($node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -cin @('$approvedOperations',"`$receipt['original_installation_enrollment']")) -or
    ($node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses[0].Item1.Extent.Text -ceq '$StalePlanQualification' -and
        $node.Clauses[0].Item2.Statements.Count -eq 1 -and
        $node.Clauses[0].Item2.Statements[0] -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Clauses[0].Item2.Statements[0].Left.Extent.Text -cin
            @('$approvedOperations','$receipt.changed_state_revision.enrolled_at_file_time')) -or
    ($node -is [Management.Automation.Language.ForEachStatementAst] -and
        $node.Variable.Extent.Text -ceq '$approved' -and
        $node.Condition.Extent.Text -ceq '$approvedOperations')
},$true)|Where-Object {
    # Keep the controlling if, rather than execute its nested assignment alone.
    -not ($_.Parent -is [Management.Automation.Language.StatementBlockAst] -and
        $_.Parent.Parent -is [Management.Automation.Language.IfStatementAst])
}|Sort-Object {$_.Extent.StartOffset})
if($nodes.Count -ne 5){throw 'Original enrollment control flow differs'}
function Observe-Enrollment {
    param($Verb,$Name,$Envelope,$Digest,$Apply)
    if($Verb -cne '--enroll-reviewed-operation' -or $Name -cne $service){throw 'Controller invocation differs'}
    $script:calls.Add(@{envelope=$Envelope;digest=$Digest;apply=$Apply})
    $global:LASTEXITCODE=if($mode -ceq 'exit_failure'){1}else{0}
    @{status=$(if($mode -ceq 'status_failure'){'failed'}else{'reviewed_operation_enrolled'});
      service=$(if($mode -ceq 'service_failure'){'another_service'}else{$Name});
      approval=@{request=$Apply}}|ConvertTo-Json -Compress
}
$ServiceControlBinary='Observe-Enrollment';$service='synthetic_service'
$binding=@{envelope_file='B.envelope';envelope_sha256=('b'*64);apply_file='B.apply'}
$bindingA=@{envelope_file='A.envelope';envelope_sha256=('a'*64);apply_file='A.apply'}
$results=@()
foreach($StalePlanQualification in @($false,$true)) {
    foreach($mode in @('ok','exit_failure','status_failure','service_failure')) {
        $script:calls=[Collections.Generic.List[object]]::new()
        $receipt=@{changed_state_revision=@{enrollments=[Collections.Generic.List[object]]::new()}}
        $refused=$false
        try {foreach($node in $nodes){Invoke-Expression $node.Extent.Text}}
        catch {$refused=$true}
        $results+=@{stale=$StalePlanQualification;mode=$mode;refused=$refused;
            calls=@($script:calls);recorded=$receipt.ContainsKey('original_installation_enrollment');
            original=$receipt.original_installation_enrollment;
            stale_enrollments=@($receipt.changed_state_revision.enrollments)}
    }
}
ConvertTo-Json -InputObject @($results) -Depth 8 -Compress
'''


@unittest.skipUnless(POWERSHELL, 'PowerShell unavailable on this platform')
class PublisherPowerShellEnrollmentTests(unittest.TestCase):
    def test_controller_attempt_retains_native_failure_without_stale_success(self):
        # Run the actual capture helpers on each installed supported shell.
        # Native children are inert Python fixtures, never product controllers.
        code = r"""
param([string]$Root,[string]$OutputRoot,[string]$Python)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Controller fixture parse failed'}
$functions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -cin @('Read-BoundedDiagnostic','Invoke-ObservedPublisherControl')
},$true))
if($functions.Count -ne 2){throw 'Exact diagnostic helpers required'}
foreach($function in $functions){. ([scriptblock]::Create($function.Extent.Text))}
$readerDefinition=@($functions|Where-Object Name -ceq 'Read-BoundedDiagnostic')[0].Extent.Text
$root=$OutputRoot;$service='synthetic_service';$ServiceControlBinary=$Python
$receipt=@{control_attempts=[Collections.Generic.List[object]]::new()};$results=@()
$native=Join-Path $OutputRoot 'native-control.py'
foreach($case in @(@(0,0),@(0,1),@(3,1),@(5,1))) {
    $exitCode=$case[0];$noisy=$case[1]
    $id=[guid]::NewGuid().ToString('N');$global:LASTEXITCODE=0
    $observed=Invoke-ObservedPublisherControl -Phase target_admission -Arguments @($native,$exitCode,$noisy)
    $attempt=$receipt.control_attempts[$receipt.control_attempts.Count-1]
    $results+=@{requested=$exitCode;noisy=$noisy;observed=$observed.native_exit_code;recorded=$attempt.native_exit_code;
        typed_exit=($observed.native_exit_code -is [int]);preference_restored=($ErrorActionPreference -ceq 'Stop');
        stdout=($observed.output -join "§n");stderr_bytes=$attempt.stderr_observed_bytes;
        prefix_chars=([string]$attempt.stderr_prefix).Length;
        native_prefix=([string]$attempt.stderr_prefix).Contains('native admission detail:');
        capture_failure=$attempt.capture_failure;invocation_failure=$attempt.invocation_failure}
}
$failures=@()
foreach($scenario in @('missing','capture','missing_and_capture')) {
    $ServiceControlBinary=if($scenario -ceq 'capture'){$Python}else{Join-Path $OutputRoot 'missing-native-command.exe'}
    if($scenario -cne 'missing'){function Read-BoundedDiagnostic {throw 'controlled diagnostic capture failure'}}
    $id=[guid]::NewGuid().ToString('N');$global:LASTEXITCODE=0;$refused=$false;$message=$null
    if($scenario -ceq 'missing_and_capture'){
        [IO.File]::WriteAllText((Join-Path $root ('installation_enrollment-'+$id+'.stderr.txt')),'seeded diagnostic')
    }
    try{Invoke-ObservedPublisherControl -Phase installation_enrollment -Arguments @($native,3,1)|Out-Null}
    catch{$refused=$true;$message=$_.Exception.Message}
    $attempt=$receipt.control_attempts[$receipt.control_attempts.Count-1]
    $failures+=@{scenario=$scenario;refused=$refused;exit_code=$attempt.native_exit_code;message=$message;
        invocation_failure=$attempt.invocation_failure;capture_failure=$attempt.capture_failure;
        preference_restored=($ErrorActionPreference -ceq 'Stop')}
    . ([scriptblock]::Create($readerDefinition))
}
$encodingResults=@()
$expected='bounded-'+[char]0x03c0+[char]0x4e2d
foreach($encoding in @([Text.UTF8Encoding]::new($false),[Text.UTF8Encoding]::new($true),[Text.Encoding]::Unicode)) {
    $file=Join-Path $OutputRoot ('encoding-'+[guid]::NewGuid().ToString('N')+'.txt')
    [IO.File]::WriteAllText($file,$expected,$encoding)
    $encodingResults+=@((Read-BoundedDiagnostic $file 16384) -ceq $expected)
}
@{native=@($results);failures=@($failures);encoding_results=@($encodingResults);
    powershell=$PSVersionTable.PSVersion.ToString();
    phases=@($receipt.control_attempts|ForEach-Object phase)}|ConvertTo-Json -Depth 5 -Compress
""".replace('§', chr(96))
        native = ("import sys\n"
                  "sys.stdout.write('native stdout')\n"
                  "if int(sys.argv[2]): sys.stderr.write('native admission detail:'+('x'*20000))\n"
                  "sys.exit(int(sys.argv[1]))\n")
        for shell in POWERSHELLS:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / 'control-observation.ps1'
                script.write_text(code, encoding='utf-8')
                (Path(directory) / 'native-control.py').write_text(native, encoding='utf-8')
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(script), '-Root', str(ROOT), '-OutputRoot', directory,
                    '-Python', sys.executable], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(len(observed['native']), 4)
                for row in observed['native']:
                    self.assertEqual(row['observed'], row['requested'])
                    self.assertEqual(row['recorded'], row['requested'])
                    self.assertTrue(row['typed_exit'])
                    self.assertTrue(row['preference_restored'])
                    self.assertEqual(row['stdout'], 'native stdout')
                    self.assertIsNone(row['capture_failure'])
                    self.assertIsNone(row['invocation_failure'])
                    if row['noisy']:
                        self.assertGreater(row['stderr_bytes'], 16384)
                        self.assertGreater(row['prefix_chars'], 0)
                        self.assertLessEqual(row['prefix_chars'], 16384)
                        self.assertTrue(row['native_prefix'])
                        if observed['powershell'].startswith('7.'):
                            self.assertEqual(row['prefix_chars'], 16384)
                    else:
                        self.assertEqual(row['prefix_chars'], 0)
                        self.assertIn(row['stderr_bytes'], (0, 2))
                self.assertEqual(observed['encoding_results'], [True] * 3)
                self.assertEqual(len(observed['failures']), 3)
                for row in observed['failures']:
                    self.assertTrue(row['refused'])
                    self.assertTrue(row['preference_restored'])
                    if row['scenario'] == 'capture':
                        self.assertEqual(row['exit_code'], 3)
                        self.assertIn('capture is incomplete', row['message'])
                    else:
                        self.assertIsNone(row['exit_code'])
                    if row['scenario'] != 'missing':
                        self.assertIn('controlled diagnostic capture failure', row['capture_failure'])
                    if row['scenario'] == 'missing_and_capture':
                        self.assertEqual(row['message'][:1024], row['invocation_failure'])
                        self.assertNotIn('controlled diagnostic capture failure', row['message'])
                self.assertEqual(observed['phases'], ['target_admission'] * 4 + ['installation_enrollment'] * 3)

    def test_admitted_refusal_preserves_native_and_state_checks_across_host_wrapping(self):
        code = r"""
param([string]$Root,[string]$OutputRoot,[string]$Python)
$ErrorActionPreference='Stop'
# Match the hosted display width within this disposable test process.
$PSDefaultParameterValues=@{'Out-File:Width'=80}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Fixture parse failed'}
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -cin @('Read-BoundedDiagnostic','Invoke-ObservedPublisherControl','Assert-AdmittedStartRefusal')},$true))
if($functions.Count -ne 3){throw 'Exact admission helpers required'}
foreach($function in $functions){. ([scriptblock]::Create($function.Extent.Text))}
$root=$OutputRoot;$service='inert-service';$AdmittedTarget=$true
$expectedRegisteredCommand='inert exact registered command'
$diagnostic='service-admitted start requires completed safe-original target admission'
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    if($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='$service'"){throw 'Unexpected service lookup'}
    $script:stateReads++
    return [pscustomobject]@{
        State=$(if($mode -ceq 'running' -and $script:stateReads -eq 2){'Running'}else{'Stopped'});
        PathName=$(if($mode -ceq 'command' -and $script:stateReads -eq 2){'changed command'}else{$expectedRegisteredCommand});
        StartName=$(if($mode -ceq 'account' -and $script:stateReads -eq 2){'changed account'}else{'inert account'});
        ServiceType=$(if($mode -ceq 'type' -and $script:stateReads -eq 2){'changed type'}else{'Own Process'})}
}
$rows=@()
foreach($mode in @('expected','wrapped','wrong_detail','zero','other_exit','stdout','running','command','account','type','native_file','missing')) {
    $id=[guid]::NewGuid().ToString('N');$script:stateReads=0
    $receipt=@{control_attempts=[Collections.Generic.List[object]]::new()}
    $nativePath=Join-Path $OutputRoot ($id+'.native')
    if($mode -ceq 'native_file'){[IO.File]::WriteAllText($nativePath,'owned test completion')}
    $ServiceControlBinary=if($mode -ceq 'missing'){Join-Path $OutputRoot 'missing.exe'}else{$Python}
    $global:LASTEXITCODE=3
    $exit=if($mode -ceq 'zero'){0}elseif($mode -ceq 'other_exit'){5}else{3}
    $caught=$null
    try {
        Assert-AdmittedStartRefusal -Phase start_without_admission -Diagnostic $diagnostic -Arguments @(
            (Join-Path $OutputRoot 'admission-control.py'),$exit,$mode)
    } catch {$caught=$_}
    $rows+=@{mode=$mode;rejected=($null -ne $caught);state_reads=$script:stateReads;
        native_exit=$(if($receipt.control_attempts.Count){$receipt.control_attempts[0].native_exit_code}else{$null});
        preference_restored=($ErrorActionPreference -ceq 'Stop')}
    if($mode -ceq 'native_file'){[IO.File]::Delete($nativePath)}
}
$rows|ConvertTo-Json -Compress
"""
        native = (
            "import sys\n"
            "mode=sys.argv[2]\n"
            "message='service-admitted start requires completed safe-original target admission'\n"
            "if mode=='wrapped': message=('host-width padding '*12)+message\n"
            "if mode=='wrong_detail': message='different native refusal'\n"
            "sys.stderr.write('usk_publisher_service_control: '+message+'\\n')\n"
            "if mode=='stdout': sys.stdout.write('unexpected response')\n"
            "sys.exit(int(sys.argv[1]))\n"
        )
        for shell in POWERSHELLS:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / 'admitted-refusal.ps1'
                script.write_text(code, encoding='utf-8')
                (Path(directory) / 'admission-control.py').write_text(native, encoding='utf-8')
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(script), '-Root', str(ROOT), '-OutputRoot', directory,
                    '-Python', sys.executable], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                rows = json.loads(result.stdout)
                self.assertEqual(len(rows), 12)
                for row in rows:
                    self.assertEqual(row['rejected'], row['mode'] not in ('expected', 'wrapped'), row)
                    self.assertTrue(row['preference_restored'], row)
                    if row['mode'] in ('expected', 'wrapped'):
                        self.assertEqual(row['native_exit'], 3)
                        self.assertEqual(row['state_reads'], 2)
                    elif row['mode'] in ('native_file', 'missing'):
                        self.assertIsNone(row['native_exit'], row)

    def test_early_failure_cleanup_uses_loaded_retirement_and_graceful_preopened_release(self):
        code = r"""
param([string]$Root,[string]$OutputRoot,[string]$Python)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Fixture parse failed'}
$outer=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally})
if($outer.Count -ne 1){throw 'Outer fixture cleanup is ambiguous'}
$imports=@($ast.EndBlock.Statements|Where-Object {
    $_.Extent.Text -ceq ". (Join-Path §$PSScriptRoot 'windows_publisher_controller_maintenance_probe.ps1')"})
if($imports.Count -ne 1 -or $imports[0].Extent.EndOffset -ge $outer[0].Extent.StartOffset){
    throw 'Retirement definitions must load before the outer protected body'}
$module=Join-Path $Root 'tests/windows_publisher_controller_maintenance_probe.ps1'
$moduleAst=[Management.Automation.Language.Parser]::ParseFile($module,[ref]$tokens,[ref]$errors)
if($errors.Count -or @($moduleAst.EndBlock.Statements|Where-Object {
    $_ -isnot [Management.Automation.Language.FunctionDefinitionAst]}).Count){
    throw 'Early maintenance import must remain definitions only'}
$early=& {
    param($Source,$Module)
    function Join-Path($Path,$ChildPath) {
        if($ChildPath -cne 'windows_publisher_controller_maintenance_probe.ps1'){throw 'Unexpected imported module'}
        return $Module
    }
    . ([scriptblock]::Create($Source))
    $AdmittedTarget=$true;$ControllerApply=$true;$admittedPackagedProfile=$false
    $script:clientCleanupConfirmed=$true;$receipt=@{}
    try {Invoke-ControllerOwnedRetirement;throw 'Uninstalled-history precondition was bypassed'}
    catch {
        if($_.Exception.Message -cne 'Owned retirement requires the completed independently observed uninstall'){throw}
    }
    return 'retirement_precondition_retained'
} $imports[0].Extent.Text $module
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -ceq 'Close-OwnedPreopenedRootProbe'},$true))
if($functions.Count -ne 1){throw 'Exact preopened release helper required'}
. ([scriptblock]::Create($functions[0].Extent.Text))
. (Join-Path $Root 'tests/windows_publisher_owned_process.ps1')
$cleanup=@($outer[0].Finally.Statements|Where-Object {
    $_ -is [Management.Automation.Language.IfStatementAst] -and
    $_.Clauses[0].Item1.Extent.Text -ceq '$preopenedRootProcess'})
if($cleanup.Count -ne 1){throw 'Exact early-failure release caller required'}
$cleanupBody=[scriptblock]::Create($cleanup[0].Extent.Text)
$rows=@()
foreach($exit in @(0,7)) {
    $preopenedRelease=Join-Path $OutputRoot ('release-'+$exit+'.txt')
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Python
    $info.Arguments='"'+(Join-Path $OutputRoot 'release-actor.py')+'" "'+$preopenedRelease+'" '+$exit
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $preopenedRootProcess=[Diagnostics.Process]::Start($info);$saved=$preopenedRootProcess
    $receipt=@{primary_failure='original refusal'};$failure=$null;$clientCleanupConfirmed=$true
    try {
        . $cleanupBody
        $rows+=@{exit=$exit;cleared=($null -eq $preopenedRootProcess);
            cleanup_confirmed=$clientCleanupConfirmed;failure=$failure;primary=$receipt.primary_failure;
            release=[IO.File]::ReadAllText($preopenedRelease)}
    } finally {
        if($preopenedRootProcess){
            if(-not $saved.WaitForExit(10000)){throw 'Owned test actor did not reach its bounded exit'}
            $saved.Dispose();$preopenedRootProcess=$null
        }
    }
}
@{early=$early;cleanup=$rows}|ConvertTo-Json -Compress
""".replace('§', chr(96))
        actor = (
            "import pathlib,sys,time\n"
            "path=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+8\n"
            "while not path.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
            "assert path.read_text(encoding='utf-8')=='usk.publisher.release_preopened_root.v1\\n'\n"
            "sys.exit(int(sys.argv[2]))\n"
        )
        for shell in POWERSHELLS:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / 'early-cleanup.ps1'
                script.write_text(code, encoding='utf-8')
                (Path(directory) / 'release-actor.py').write_text(actor, encoding='utf-8')
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(script), '-Root', str(ROOT), '-OutputRoot', directory,
                    '-Python', sys.executable], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(observed['early'], 'retirement_precondition_retained')
                self.assertEqual(len(observed['cleanup']), 2)
                for row in observed['cleanup']:
                    self.assertEqual(row['cleared'], row['exit'] == 0, row)
                    self.assertEqual(row['cleanup_confirmed'], row['exit'] == 0, row)
                    self.assertEqual(row['primary'], 'original refusal')
                    self.assertEqual(row['release'], 'usk.publisher.release_preopened_root.v1\n')
                    if row['exit'] == 0:
                        self.assertIsNone(row['failure'])
                    else:
                        self.assertIn('Preopened-root attacker failed after release', row['failure'])

    def test_existing_refusal_predicates_reject_success_unknown_and_changed_state(self):
        # Execute each actual condition with an actual shared-helper result.
        # Only the read-only service/file lookups inside the predicate are inert.
        code = r"""
param([string]$Root,[string]$OutputRoot,[string]$Python)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Fixture parse failed'}
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -cin @('Read-BoundedDiagnostic','Invoke-ObservedPublisherControl')},$true))
if($functions.Count -ne 2){throw 'Exact native helpers required'}
foreach($function in $functions){. ([scriptblock]::Create($function.Extent.Text))}
$cases=@(
    @('wrongBinaryAttempt','register_wrong_digest'),
    @('blockedStartAttempt','start_control_lock'),
    @('crossVolumeAttempt','register_control_lock'),
    @('changedApplyAttempt','changed_apply'),
    @('wrongStartAttempt','start_wrong_caller'),
    @('wrongModeAttempt','start_wrong_mode'),
    @('preopenedStartAttempt','start_preopened_root'),
    @('wrongCallerAttempt','recover_wrong_caller'),
    @('blockedRemoveAttempt','unregister_control_lock'),
    @('wrongRemoveAttempt','unregister_wrong_caller'),
    @('liveRetirementAttempt','retire_live_service'),
    @('wrongRetireDigestAttempt','retire_wrong_digest'),
    @('wrongRetireSidAttempt','retire_wrong_sid'))
$root=$OutputRoot;$service='synthetic_service';$drive='V:\'
$installedServiceBinary=Join-Path $root 'synthetic-installed.exe'
$beforeControl='fixed configuration'
$crossVolumeError='cross-volume.txt';$changedError='changed.txt';$blockedStartError='blocked.txt'
$receipt=@{control_attempts=[Collections.Generic.List[object]]::new()}
$native=Join-Path $OutputRoot 'native-refusal.py'
function Test-Predicate([scriptblock]$Predicate) {
    function Get-Service {
        param($Name,$ErrorAction)
        if($phase -ceq 'register_wrong_digest' -and $mode -cne 'changed'){return $null}
        if($mode -ceq 'changed' -and $phase -cin @('unregister_control_lock','unregister_wrong_caller')){return $null}
        [pscustomobject]@{Status=$(if($mode -ceq 'changed'){'Running'}else{'Stopped'})}
    }
    function Get-CimInstance {param($ClassName,$Filter,$ErrorAction)
        [pscustomobject]@{PathName=$(if($mode -ceq 'changed'){'substituted configuration'}else{$beforeControl})}}
    function Test-Path {
        param($LiteralPath,$PathType)
        if($LiteralPath -ceq $installedServiceBinary){
            if($phase -ceq 'register_wrong_digest'){return $mode -ceq 'changed'}
            return $mode -cne 'changed'
        }
        if($LiteralPath -ceq $blockedStartError){return $true}
        return $mode -ceq 'changed'
    }
    function Get-Item {param($LiteralPath) [pscustomobject]@{Length=32}}
    function Get-Content {param($LiteralPath,[switch]$Raw)
        if($mode -ceq 'changed'){return 'substituted diagnostic'}
        return 'control is active; apply request differs; pre-opened file or cannot be locked'
    }
    & $Predicate
}
$results=@()
foreach($case in $cases) {
    $variable=$case[0];$phase=$case[1]
    $assignments=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq ('$'+$variable)},$true))
    if($assignments.Count -ne 1){throw 'Actual refusal invocation is ambiguous'}
    $assignment=$assignments[0]
    if($assignment.Right.Extent.Text -cnotmatch ('^Invoke-ObservedPublisherControl -Phase '+$phase+'\b')){
        throw 'Actual refusal bypassed the shared native helper'}
    $siblings=@($assignment.Parent.Statements);$index=[array]::IndexOf($siblings,$assignment)
    if($index -lt 0 -or $siblings[$index+1] -isnot [Management.Automation.Language.IfStatementAst]){
        throw 'Actual refusal condition is no longer adjacent'}
    $predicate=[scriptblock]::Create($siblings[$index+1].Extent.Text)
    foreach($mode in @('refusal','zero','changed','missing')) {
        $id=[guid]::NewGuid().ToString('N');$global:LASTEXITCODE=0
        $ServiceControlBinary=if($mode -ceq 'missing'){Join-Path $root 'missing-native-command.exe'}else{$Python}
        $refused=$false;$reached=$false;$observedExit=$null
        try {
            $attempt=Invoke-ObservedPublisherControl -Phase $phase -Arguments @($native,$(if($mode -ceq 'zero'){0}else{3}))
            $observedExit=$attempt.native_exit_code
            Set-Variable -Name $variable -Value $attempt -Scope Script
            $reached=$true;Test-Predicate $predicate
        } catch {$refused=$true}
        $results+=@{phase=$phase;mode=$mode;refused=$refused;reached=$reached;exit_code=$observedExit;
            preference_restored=($ErrorActionPreference -ceq 'Stop')}
    }
}
ConvertTo-Json -InputObject @($results) -Depth 4 -Compress
"""
        for shell in POWERSHELLS:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / 'refusal-predicates.ps1'
                script.write_text(code, encoding='utf-8')
                (Path(directory) / 'native-refusal.py').write_text(
                    "import sys\nsys.stderr.write('controlled refusal')\nsys.exit(int(sys.argv[1]))\n",
                    encoding='utf-8')
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(script), '-Root', str(ROOT), '-OutputRoot', directory,
                    '-Python', sys.executable], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                rows = json.loads(result.stdout)
                self.assertEqual(len(rows), 52)
                self.assertEqual(len({row['phase'] for row in rows}), 13)
                for row in rows:
                    with self.subTest(phase=row['phase'], mode=row['mode']):
                        self.assertEqual(row['refused'], row['mode'] != 'refusal')
                        self.assertTrue(row['preference_restored'])
                        if row['mode'] == 'missing':
                            self.assertFalse(row['reached'])
                            self.assertIsNone(row['exit_code'])
                        else:
                            self.assertTrue(row['reached'])
                            self.assertEqual(row['exit_code'], 0 if row['mode'] == 'zero' else 3)

    def test_original_enrollment_precedes_source_free_work_for_every_fixture(self):
        # No service, target, token or approval is created by this test.
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'enrollment.ps1'
            script.write_text(SCRIPT, encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), '-Root', str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 8)
        for row in rows:
            with self.subTest(stale=row['stale'], mode=row['mode']):
                ok = row['mode'] == 'ok'
                self.assertEqual(row['refused'], not ok)
                self.assertEqual(row['recorded'], ok)
                if ok:
                    expected = ['A', 'B'] if row['stale'] else ['B']
                    self.assertEqual(row['calls'], [dict(envelope=x+'.envelope', digest=x.lower()*64,
                        apply=x+'.apply') for x in expected])
                    self.assertEqual(row['original']['approval']['request'], 'B.apply')
                    self.assertEqual(len(row['stale_enrollments']), 2 if row['stale'] else 0)
                else:
                    self.assertEqual(len(row['calls']), 1)
                    self.assertEqual(row['stale_enrollments'], [])


if __name__ == '__main__':
    unittest.main()
