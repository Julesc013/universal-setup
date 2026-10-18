# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Exercise the actual sampled-interval collector and evidence admission."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELLS = tuple(dict.fromkeys(filter(None, (shutil.which("powershell"), shutil.which("pwsh")))))
STAGE_SCRIPT = r'''
param([string]$Root,[string]$ObserverFile)
$ErrorActionPreference='Stop'
if(-not $ObserverFile){$ObserverFile=Join-Path $Root 'tests/windows_publisher_stage_observer.ps1'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ObserverFile,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Observer parse failed'}
$collect=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -ceq '$staged'
},$true))
if($collect.Count -ne 1){throw 'Actual staged interval collector differs'}
$sample=[scriptblock]::Create($collect[0].Extent.Text)
$functions=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Admission parse failed'}
$overlap=@($functions.FindAll({param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -ceq 'Test-LiveStageAttemptOverlap'
},$true))
if($overlap.Count -ne 1){throw 'Actual interval admission helper differs'}
. ([scriptblock]::Create($overlap[0].Extent.Text))
$frequency=[Diagnostics.Stopwatch]::Frequency
function Tick([long]$ms){return [long]($ms*$frequency/1000)}
function Collect($times) {
    $runs=[Collections.Generic.List[object]]::new()
    $first=0L;$last=0L;$count=0;$maximumGap=0L
    # Old source lacks this assignment: the unchanged consumer still supplies
    # the same 200ms bound for the local old-source counterfactual.
    $maximumObservedGap=[long]($frequency/5)
    foreach($ms in $times){$staged=$true;$tick=Tick $ms;. $sample}
    $staged=$false;. $sample
    return [pscustomobject]@{clock_frequency=$frequency;runs=$runs.ToArray()}
}
function Matches($observation,[long]$start,[long]$end) {
    return Test-LiveStageAttemptOverlap $observation @(@{start_tick=(Tick $start);end_tick=(Tick $end)})
}
$ordinary=Collect @(100,150,200,250)
if($ordinary.runs.Count -ne 1 -or -not (Matches $ordinary 125 130)){
    throw 'Ordinary continuous observations lost their admitted interval'
}
$split=Collect @(100,150,200,450,500,550)
if($split.runs.Count -ne 2 -or -not (Matches $split 125 130) -or -not (Matches $split 475 480)){
    throw 'Valid intervals on both sides of the excessive gap were discarded'
}
if((Matches $split 190 460) -or (Matches $split 350 360)){
    throw 'An attempt crossing or inside the excluded sampling gap was admitted'
}
if(@($split.runs|Where-Object {$_.maximum_gap_ticks -gt [long]($frequency/5)}).Count){
    throw 'The original maximum gap was relaxed'
}
$edge=Collect @(100,300,500)
if($edge.runs.Count -ne 1 -or -not (Matches $edge 125 130)){
    throw 'The original inclusive200ms boundary changed'
}
$isolated=Collect @(100,450,800)
if($isolated.runs.Count -ne 3 -or (Matches $isolated 101 102)){
    throw 'Isolated observations became a continuous interval'
}
$bounded=Collect @(1..64|ForEach-Object {$_*1000})
if($bounded.runs.Count -ne 64){throw 'The existing64 interval capacity changed'}
$declined=$false
try{$null=Collect @(1..65|ForEach-Object {$_*1000})}
catch{if($_.Exception.Message -notlike '*interval bound exceeded*'){throw};$declined=$true}
if(-not $declined){throw 'Interval exhaustion was silently clipped or accepted'}
'actual sampled-interval controls passed'
'''
ADMISSION_SCRIPT = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Admission parse failed'}
$nodes=@($ast.FindAll({param($n)
    ($n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -cin @("§$receipt['concurrent_hostile_rights_candidate']","§$receipt['concurrent_hostile_rights']")) -or
    ($n -is [Management.Automation.Language.IfStatementAst] -and
        $n.Extent.Text.Contains("throw 'Concurrent hostile-rights observation differs from the actual client'"))
},$true)|Where-Object {
    # Select the exact predicate, not any enclosing branch containing it.
    $_ -isnot [Management.Automation.Language.IfStatementAst] -or
        $_.Clauses[0].Item1.Extent.Text.StartsWith('$concurrent.schema -cne')
}|Sort-Object {$_.Extent.StartOffset})
if($nodes.Count -ne 3){throw 'Actual candidate/admission ordering differs'}
$admit=[scriptblock]::Create(($nodes.Extent.Text -join "§n"))
$consumerSid='S-1-5-21-1-2-3-1001';$concurrentAttacker=@{Id=7}
$ProductionConcurrentRights=$false
foreach($mode in @('ok','schema','status','coverage','sid','admin','service_sid','pid','destination','visible','cycles')) {
    $receipt=@{};$coverage=$true
    $concurrent=@{schema='usk.publisher.unprivileged_access_probe.v1';status='access_denied_observed';
        user_sid=$consumerSid;administrator=$false;service_sid_present=$false;process_id=7;
        concurrent=@{destination_create=@{denied=4};visible_write=@{denied_after_completion=3};cycles_after_completion=3}}
    switch($mode) {
        'schema'{$concurrent.schema='wrong'}
        'status'{$concurrent.status='wrong'}
        'coverage'{$coverage=$false}
        'sid'{$concurrent.user_sid='another'}
        'admin'{$concurrent.administrator=$true}
        'service_sid'{$concurrent.service_sid_present=$true}
        'pid'{$concurrent.process_id=8}
        'destination'{$concurrent.concurrent.destination_create.denied=3}
        'visible'{$concurrent.concurrent.visible_write.denied_after_completion=2}
        'cycles'{$concurrent.concurrent.cycles_after_completion=2}
    }
    $refused=$false
    try{. $admit}catch{
        if($_.Exception.Message -cne 'Concurrent hostile-rights observation differs from the actual client'){throw}
        $refused=$true
    }
    if(-not $receipt.ContainsKey('concurrent_hostile_rights_candidate')){throw 'Rejected raw evidence was lost'}
    if($refused -ne ($mode -cne 'ok') -or $receipt.ContainsKey('concurrent_hostile_rights') -ne ($mode -ceq 'ok')){
        throw ('Unvalidated candidate escaped admission: '+$mode)
    }
}
'actual candidate retention and admission controls passed'
'''.replace("§", chr(96))


@unittest.skipUnless(SHELLS, "PowerShell is required for the actual fixture controls")
class StageObserverTests(unittest.TestCase):
    def run_actual(self, script):
        for shell in SHELLS:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "probe.ps1"
                path.write_text(script, encoding="utf-8")
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-File", str(path), "-Root", str(ROOT)],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_interval_collection_and_admission(self):
        self.run_actual(STAGE_SCRIPT)

    def test_actual_candidate_retention_preserves_admission(self):
        self.run_actual(ADMISSION_SCRIPT)


if __name__ == "__main__":
    unittest.main()
