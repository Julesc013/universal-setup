# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Failure-only child census controls; no SCM, volume, or native termination."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELLS = tuple(dict.fromkeys(filter(None, (shutil.which("powershell"), shutil.which("pwsh")))))
PURE = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_production_rename_observer.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actual observer parse failed'}
$f=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -ceq 'Get-OwnedEffectChildCensusDiagnostic'},$true))
$branch=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -ceq '$children.Count -gt 1'},$true))
if($f.Count -ne 1 -or $branch.Count -ne 1){throw 'Actual failed preselection branch is ambiguous'}
. ([scriptblock]::Create($f[0].Extent.Text))
$reject=[scriptblock]::Create($branch[0].Extent.Text)
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
// Inert facade for the actual PS failure path; native sampler tested separately.
public sealed class UskOwnedEffectChildObserver {
    public static int Calls,Instances;
    public static bool Fail;
    public UskOwnedEffectChildObserver(){Instances++;throw new Exception("No pair allowed");}
    public static Dictionary<string,object> ObservePreselectionCensus(uint p,long b,uint[] ids,string image) {
        Calls++;
        if(ids.Length>8)throw new Exception("Sampler capacity exceeded");
        if(Fail)throw new InvalidOperationException("Inert capture failure");
        return new Dictionary<string,object>{{"test_only",true},{"candidate_count",ids.Length}};
    }
}
'@
$birth=[DateTime]::UtcNow.ToFileTimeUtc()
$config=[pscustomobject]@{process_id=123;process_executable='C:\inert\owner.exe'}
$secret='credential-not-for-diagnostics'
foreach($mode in @('two','older','missing','wrong_image','duplicates','capacity','beyond','native_failure')) {
    $count=if($mode -ceq 'capacity'){8}elseif($mode -ceq 'beyond'){9}else{2}
    $children=@(1..$count|ForEach-Object {[pscustomobject]@{
        ProcessId=[uint32](200+$_);ParentProcessId=123;CreationDate=[DateTime]::UtcNow;
        ExecutablePath=$config.process_executable;CommandLine=$secret}})
    if($mode -ceq 'older'){$children[0].CreationDate=[DateTime]::UtcNow.AddYears(-2)}
    if($mode -ceq 'missing'){$children[0].CreationDate=$null;$children[0].ExecutablePath=$null;$children[0].CommandLine=$null}
    if($mode -ceq 'wrong_image'){$children[0].ExecutablePath='C:\inert\other.exe'}
    if($mode -ceq 'duplicates'){$children[1]=$children[0]}
    [UskOwnedEffectChildObserver]::Fail=($mode -ceq 'native_failure')
    $result=[ordered]@{process_creation_file_time=$birth.ToString('x16')}
    $caught=$false
    try{. $reject}catch{
        if($_.Exception.Message -cne 'Owned SCM has an ambiguous native effect-child population'){throw}
        $caught=$true
    }
    $d=$result.effect_child_preselection_census
    if(-not $caught -or -not $d -or $d.qualification_granted -ne $false -or -not $d.selection_unchanged -or
        $d.total_cim_rows -ne $count -or $d.row_limit -ne 8 -or $d.rows.Count -ne [Math]::Min($count,8) -or
        $d.rows_truncated -ne ($count -gt 8) -or $d.sampling -cne 'sequential_non_atomic') {
        throw 'Failed census changed refusal, membership or declared limits'
    }
    if(($d|ConvertTo-Json -Depth 8 -Compress).Contains($secret)){throw 'Command content escaped into diagnostics'}
    if($mode -ceq 'native_failure' -and (-not $d.native_capture_failure -or $null -ne $d.native)) {
        throw 'Native capture failure was lost or projected as authority'
    }
}
[UskOwnedEffectChildObserver]::Fail=$false
$before=[UskOwnedEffectChildObserver]::Calls
foreach($children in @(@(),@([pscustomobject]@{ProcessId=201}))) {
    $result=[ordered]@{process_creation_file_time=$birth.ToString('x16')}
    . $reject
    if($result.Contains('effect_child_preselection_census')){throw 'Non-ambiguous path gained diagnostics'}
}
if([UskOwnedEffectChildObserver]::Calls -ne $before -or [UskOwnedEffectChildObserver]::Instances -ne 0) {
    throw 'Failure diagnostics instantiated an observer or entered another path'
}
function Get-OwnedEffectChildCensusDiagnostic {throw 'Deliberate diagnostic construction failure'}
$children=@(1,2);$result=[ordered]@{process_creation_file_time=$birth.ToString('x16')}
$caught=$false
try{. $reject}catch{
    if($_.Exception.Message -cne 'Owned SCM has an ambiguous native effect-child population'){throw}
    $caught=$true
}
if(-not $caught -or $result.Contains('effect_child_preselection_census')){throw 'Diagnostic failure replaced the original refusal'}
'actual failed-preselection controls passed'
'''
NATIVE = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'tests/windows_publisher_owned_effect_child.ps1')
$current=[Diagnostics.Process]::GetCurrentProcess()
$image=$current.MainModule.FileName
$birth=$current.StartTime.ToUniversalTime().ToFileTimeUtc()
$r=[UskOwnedEffectChildObserver]::ObservePreselectionCensus(
    [uint32]$PID,$birth,[uint32[]]@($PID,0),$image)
if($r.qualification_granted -ne $false -or $r.sampling -cne 'sequential_non_atomic' -or
    $r.requested_access -ne 0x00101400 -or $r.children.Count -ne 2 -or
    $r.parent_before.native_process_id -ne $PID -or $r.parent_before.native_birth_file_time -cne $birth.ToString('x16') -or
    $r.parent_before.native_wait_result -ne 258 -or $r.parent_after.native_wait_result -ne 258 -or
    -not $r.parent_observer_close_confirmed -or -not $r.children[0].observer_close_confirmed -or
    $r.children[0].facts.native_process_id -ne $PID -or $r.children[1].status -cne 'open_unavailable') {
    throw 'Actual read-only live/unavailable sample or closure differs'
}
$wrong=[UskOwnedEffectChildObserver]::ObservePreselectionCensus([uint32]$PID,($birth+1),[uint32[]]@($PID),$image)
if($wrong.status -cne 'parent_instance_unavailable' -or $wrong.children.Count -ne 0 -or
    -not $wrong.parent_observer_close_confirmed){throw 'Parent birth mismatch gained samples or leaked observation'}
$caught=$false
try{$null=[UskOwnedEffectChildObserver]::ObservePreselectionCensus(
    [uint32]$PID,$birth,[uint32[]](1..9),$image)}catch{$caught=$true}
if(-not $caught){throw 'Native row capacity was widened'}
# A separate owned, inert stdin child supplies an actual retained ended instance.
$flags=[Reflection.BindingFlags]'NonPublic,Static'
$type=[UskOwnedEffectChildObserver]
$open=$type.GetMethod('OpenProcess',$flags);$close=$type.GetMethod('CloseHandle',$flags)
$facts=$type.GetMethod('PreselectionFacts',$flags)
$child=[Diagnostics.Process]::new()
$child.StartInfo.FileName=$image
$child.StartInfo.Arguments='-NoLogo -NoProfile -NonInteractive -Command "[Console]::WriteLine(''ready''); $null=[Console]::ReadLine()"'
$child.StartInfo.UseShellExecute=$false;$child.StartInfo.CreateNoWindow=$true
$child.StartInfo.RedirectStandardInput=$true;$child.StartInfo.RedirectStandardOutput=$true
$handle=[IntPtr]::Zero;$started=$false
try {
    $started=$child.Start()
    if(-not $started){throw 'Owned inert child did not start'}
    $ready=$child.StandardOutput.ReadLineAsync()
    if(-not $ready.Wait(10000) -or $ready.Result -cne 'ready'){throw 'Owned inert child did not become ready'}
    $handle=$open.Invoke($null,@([uint32]0x00101400,$false,[uint32]$child.Id))
    if($handle -eq [IntPtr]::Zero){throw 'Owned inert read-only handle unavailable'}
    $before=$facts.Invoke($null,@($handle,[uint32]$child.Id,$image))
    $child.StandardInput.WriteLine('exit')
    if(-not $child.WaitForExit(10000)){throw 'Owned inert child did not end'}
    $after=$facts.Invoke($null,@($handle,[uint32]$child.Id,$image))
    if($before.native_wait_result -ne 258 -or $after.native_wait_result -ne 0 -or
        $before.native_birth_file_time -cne $after.native_birth_file_time -or
        $before.native_process_id -ne $after.native_process_id){throw 'Retained ended native instance was not observed'}
} finally {
    if($handle -ne [IntPtr]::Zero -and -not $close.Invoke($null,@($handle))){throw 'Owned inert read-only handle close failed'}
    if($started -and -not $child.HasExited){$child.Kill();$child.WaitForExit()}
    $child.Dispose();$current.Dispose()
}
'actual native read-only live/ended controls passed'
'''


@unittest.skipUnless(SHELLS, "PowerShell is unavailable")
class PublisherEffectChildCensusTests(unittest.TestCase):
    def run_control(self, script, shell):
        with tempfile.TemporaryDirectory(prefix="usk-child-census-") as temp:
            path = Path(temp) / "control.ps1"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(path), "-Root", str(ROOT)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-4000:])

    def test_actual_ambiguous_branch_retains_bounded_diagnostics_and_refuses(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                self.run_control(PURE, shell)

    @unittest.skipUnless(os.name == "nt", "Native sampler uses Windows query APIs")
    def test_actual_read_only_sampler_live_ended_and_unavailable_instances(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                self.run_control(NATIVE, shell)
