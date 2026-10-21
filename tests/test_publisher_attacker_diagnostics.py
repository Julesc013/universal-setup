# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Inert actual-code controls, never native attacker or publisher qualification."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh') or shutil.which('powershell')
SCRIPT = r'''
param([string]$Root,[string]$Scratch)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$metadata=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Metadata fixture parse failed'}
foreach($name in @('Read-BoundedDiagnostic','Read-ConcurrentAttackerDiagnostic')) {
    $f=@($metadata.FindAll({param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if($f.Count -ne 1){throw 'Diagnostic function is missing or ambiguous'}
    . ([scriptblock]::Create($f[0].Extent.Text))
}
$failed=@($metadata.FindAll({param($n)
    $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text.Contains('$unrelatedAttacker.ExitCode -ne 0')},$true))
if($failed.Count -ne 1){throw 'Unrelated failure branch is missing or ambiguous'}
$text=$failed[0].Clauses[0].Item2.Extent.Text
$failureFlow=[scriptblock]::Create($text.Substring(1,$text.Length-2))
$unrelatedAttackOutput=$null
$unrelatedError=Join-Path $Scratch 'attacker.stderr'
[IO.File]::WriteAllText($unrelatedError,'fallback diagnostic')
$rows=@()
foreach($case in @('failed','malformed','oversized','missing')) {
    $unrelatedAttackOutput=Join-Path $Scratch ($case+'.json')
    if(Test-Path -LiteralPath $unrelatedAttackOutput){throw 'Inert fixture path is not fresh'}
    if($case -ceq 'failed') {
        @{schema='usk.publisher.unprivileged_access_probe.v1';status='failed';
          failure='production native rename attacker did not overlap the publisher call';
          process_id=123;user_sid='S-1-5-21-1-2-3-1001';
          concurrent=@{native_rename_overlap=@{attempt_count=2;overlap_count=0;
            target_start_tick=200;target_end_tick=250;nearest_before_attempt=@(100,150);
            nearest_after_attempt=@(300,350)}}}|
            ConvertTo-Json -Depth 8|Set-Content -LiteralPath $unrelatedAttackOutput -Encoding utf8
    } elseif($case -ceq 'malformed') {[IO.File]::WriteAllText($unrelatedAttackOutput,'{')}
    elseif($case -ceq 'oversized') {[IO.File]::WriteAllText($unrelatedAttackOutput,('x'*(512KB+1)))}
    $receipt=[ordered]@{};$unrelatedAttacker=[pscustomobject]@{ExitCode=1};$message=$null
    try {$null=& $failureFlow} catch {$message=$_.Exception.Message}
    $rows+=@{case=$case;failure=$message;observation=$receipt.unrelated_attacker_failure}
}
$probe=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_unprivileged_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Attacker fixture parse failed'}
$native=@($probe.FindAll({param($n)
    $n -is [Management.Automation.Language.StringConstantExpressionAst] -and
    $n.Value.Contains('public static class USKPublisherRenameRace')},$true))
if($native.Count -ne 1){throw 'Rename worker source is missing or ambiguous'}
# Seed only the stopped telemetry collector. Start/Loop/MoveFileExW are never
# invoked. Reflection here creates no protected context or runtime authority.
$inertSource=@'
public static class UskInertRenameHistory {
    public static Dictionary<string,object> Observe(long[] starts, long[] ends,
        long targetStart, long targetEnd, bool wrapped) {
        Type type = typeof(USKPublisherRenameRace);
        System.Reflection.BindingFlags flags = System.Reflection.BindingFlags.Static |
            System.Reflection.BindingFlags.NonPublic;
        long[] first = (long[])type.GetField("Starts",flags).GetValue(null);
        long[] last = (long[])type.GetField("Ends",flags).GetValue(null);
        int count = wrapped ? first.Length + 2 : starts.Length;
        for (int i=0; i<count; ++i) {
            first[i % first.Length] = wrapped ? i*10L : starts[i];
            last[i % last.Length] = wrapped ? i*10L+4 : ends[i];
        }
        type.GetField("attempts",flags).SetValue(null,(long)count);
        type.GetField("failure",flags).SetValue(null,null);
        Thread worker = new Thread(delegate() {});
        worker.Start(); worker.Join();
        type.GetField("worker",flags).SetValue(null,worker);
        return USKPublisherRenameRace.Stop(targetStart,targetEnd);
    }
}
'@
Add-Type -TypeDefinition ($native[0].Value+[Environment]::NewLine+$inertSource)
$ranges=[ordered]@{
    gap=[UskInertRenameHistory]::Observe(@(100,300),@(150,350),200,250,$false);
    overlap=[UskInertRenameHistory]::Observe(@(100,190,300),@(150,220,350),200,250,$false);
    touching=[UskInertRenameHistory]::Observe(@(100,250),@(200,300),200,250,$false);
    empty=[UskInertRenameHistory]::Observe(@(),@(),200,250,$false);
    evicted=[UskInertRenameHistory]::Observe(@(),@(),8,9,$true)}
$closing=@($probe.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and
 $n.Finally -and $n.Finally.Extent.Text.Contains('[USKPublisherRenameRace]::Stop(0,0)')},$true))
if($closing.Count -ne 1){throw 'Actual unmatched-collector cleanup is ambiguous'}
$text=$closing[0].Finally.Extent.Text
$closeFlow=[scriptblock]::Create($text.Substring(1,$text.Length-2))
$closed=@()
foreach($mode in @('unmatched','collector_failure')) {
 if($mode -ceq 'unmatched') {
  $null=[UskInertRenameHistory]::Observe(@(100,300),@(150,350),0,0,$false)
 } else {
  [USKPublisherRenameRace].GetField('worker',[Reflection.BindingFlags]'Static,NonPublic').SetValue($null,$null)
 }
 $Stage='ProductionConcurrent';$renameRaceStarted=$true;$renameRaceSummary=$null
 $OutputPath=Join-Path $Scratch ('unmatched-'+$mode+'.json')
 $receipt=[ordered]@{schema='usk.publisher.unprivileged_access_probe.v1';status='failed';
  failure='original_terminal_target_missing';process_id=124;user_sid='S-1-5-21-1-2-3-1001';
  concurrent=[ordered]@{observation_window=[ordered]@{scope='attacker_observation_only';finished_utc=$null}}}
 . $closeFlow
 $observation=[ordered]@{}
 $message=Read-ConcurrentAttackerDiagnostic $OutputPath $unrelatedError $observation
 $closed+=@{mode=$mode;primary=$message;receipt=(Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json);
  diagnostic=$observation}
}
@{failures=$rows;ranges=$ranges;failed_cleanup=$closed}|ConvertTo-Json -Depth 14 -Compress
'''


WINDOW_SCRIPT = r"""
param([string]$Root)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
 (Join-Path $Root 'tests/windows_publisher_unprivileged_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actual attacker source is invalid'}
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $n.Name -ceq 'Get-PublisherAttackerObservationDeadline'},$true))
$start=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text.Contains('-not $receipt.concurrent.started_seen_utc')},$true))
if($f.Count -ne 1 -or $start.Count -ne 1){throw 'Actual deadline/start branch is ambiguous'}
. ([scriptblock]::Create($f[0].Extent.Text))
$startFlow=[scriptblock]::Create($start[0].Extent.Text)
$observerPreparedAt=[DateTime]::new(2026,10,21,0,0,0,[DateTimeKind]::Utc)
$valid=0;$repeated=0
foreach($offset in @(0,6.430087,119)) {
 $Stage='ProductionConcurrent';$afterRelease=$false;$now=$observerPreparedAt.AddSeconds($offset)
 $receipt=[ordered]@{concurrent=[ordered]@{started_seen_utc=$null;observation_window=[ordered]@{
  started_utc=$null;observation_deadline_utc=$null}}}
 $deadline=Get-PublisherAttackerObservationDeadline $observerPreparedAt
 $original=$deadline
 . $startFlow
 if($deadline -ne $original -or $receipt.concurrent.started_seen_utc){throw 'Missing start extended observation'}
 $afterRelease=$true
 . $startFlow
 $bound=$deadline;$first=$receipt.concurrent.started_seen_utc
 # The client completes within its original 120s contract even when the
 # earlier preparation-based deadline could expire before that completion.
 $completion=$now.AddSeconds(119)
 if($completion -ge $bound -or ($bound-$now).TotalSeconds -ne 130){throw 'Full valid client contract was not observed'}
 if($offset -gt 1 -and $completion -le $original){throw 'Regression does not discriminate the old bound'}
 if(($bound-$observerPreparedAt).TotalSeconds -gt 250){throw 'Observer became unbounded'}
 $valid++
 $now=$now.AddSeconds(100)
 . $startFlow
 if($deadline -ne $bound -or $receipt.concurrent.started_seen_utc -cne $first){throw 'Repeated start reset the bound'}
 $repeated++
}
$bad=@(
 @($observerPreparedAt,$observerPreparedAt.AddSeconds(-1)),
 @($observerPreparedAt,$observerPreparedAt.AddSeconds(120)),
 @($observerPreparedAt,$observerPreparedAt.AddSeconds(121)),
 @([DateTime]::SpecifyKind($observerPreparedAt,[DateTimeKind]::Unspecified),$null),
 @($observerPreparedAt,[DateTime]::SpecifyKind($observerPreparedAt,[DateTimeKind]::Unspecified)))
$refused=0
foreach($pair in $bad) {
 $caught=$false
 try {$null=Get-PublisherAttackerObservationDeadline $pair[0] $pair[1]}catch {$caught=$true}
 if(-not $caught){throw 'Expired/backwards/ambiguous clock was accepted'}
 $refused++
}
@{valid_requests=$valid;repeated_start_preserved=$repeated;invalid_clocks_refused=$refused;
 client_contract_seconds=120;maximum_observer_span_seconds=250}|ConvertTo-Json -Compress
"""


@unittest.skipUnless(POWERSHELL, 'PowerShell unavailable on this platform')
class PublisherAttackerDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / 'attacker-diagnostics.ps1'
            script.write_text(SCRIPT, encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), '-Root', str(ROOT), '-Scratch', folder],
                capture_output=True, text=True, encoding='utf-8', timeout=45)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.result = json.loads(result.stdout)

    def test_failed_actual_branch_retains_bounded_candidate_and_still_throws(self):
        self.assertEqual(len(self.result['failures']), 4)
        for row in self.result['failures']:
            with self.subTest(case=row['case']):
                self.assertTrue(row['failure'].startswith('Unrelated concurrent attacker failed: '))
                observation = row['observation']
                self.assertEqual(observation['exit_code'], 1)
                if row['case'] == 'failed':
                    candidate = observation['receipt_summary']
                    self.assertEqual(candidate['status'], 'failed')
                    self.assertEqual(candidate['process_id'], 123)
                    self.assertEqual(candidate['rename_race']['overlap_count'], 0)
                    self.assertEqual(candidate['rename_race']['nearest_before_attempt'], [100, 150])
                    self.assertIn('did not overlap', row['failure'])
                else:
                    self.assertNotIn('receipt_summary', observation)
                    self.assertTrue(row['failure'].endswith('fallback diagnostic'))

    def test_full_started_request_window_and_failure_observations(self):
        for shell in (shutil.which('pwsh'), shutil.which('powershell')):
            if not shell:
                continue
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as folder:
                script = Path(folder) / 'observer-window.ps1'
                script.write_text(WINDOW_SCRIPT, encoding='utf-8')
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
                    str(script), '-Root', str(ROOT)], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'valid_requests': 3, 'repeated_start_preserved': 3, 'invalid_clocks_refused': 5,
                    'client_contract_seconds': 120, 'maximum_observer_span_seconds': 250})

    def test_unmatched_stopped_attempts_remain_failed_and_have_no_target(self):
        self.assertEqual(len(self.result['failed_cleanup']), 2)
        for row in self.result['failed_cleanup']:
            with self.subTest(mode=row['mode']):
                self.assertEqual(row['primary'], 'original_terminal_target_missing')
                self.assertEqual(row['receipt']['status'], 'failed')
                self.assertEqual(row['receipt']['failure'], row['primary'])
                concurrent = row['receipt']['concurrent']
                self.assertNotIn('native_rename_overlap', concurrent)
                self.assertIsNotNone(concurrent['observation_window']['finished_utc'])
                if row['mode'] == 'unmatched':
                    unmatched = concurrent['unmatched_native_rename_attempts']
                    self.assertEqual(unmatched['attempt_count'], 2)
                    self.assertEqual(unmatched['overlap_count'], 0)
                    self.assertEqual(unmatched['target_start_tick'], 0)
                    self.assertEqual(unmatched['target_end_tick'], 0)
                    self.assertIsNone(unmatched['overlap_attempt'])
                    self.assertEqual(row['diagnostic']['receipt_summary']['unmatched_rename_attempts'], unmatched)
                else:
                    self.assertNotIn('unmatched_native_rename_attempts', concurrent)
                    self.assertTrue(concurrent['rename_worker_cleanup_failure'])
                    self.assertEqual(row['diagnostic']['receipt_summary']['rename_worker_cleanup_failure'],
                        concurrent['rename_worker_cleanup_failure'])

    def test_stopped_history_nearest_attempts_do_not_invent_overlap(self):
        ranges = self.result['ranges']
        for case in ('gap', 'touching', 'empty', 'evicted'):
            with self.subTest(case=case):
                self.assertEqual(ranges[case]['overlap_count'], 0)
                self.assertIsNone(ranges[case]['overlap_attempt'])
        gap = ranges['gap']
        self.assertEqual([gap['target_start_tick'], gap['target_end_tick']], [200, 250])
        self.assertEqual(gap['nearest_before_attempt'], [100, 150])
        self.assertEqual(gap['nearest_after_attempt'], [300, 350])
        self.assertEqual(ranges['overlap']['overlap_count'], 1)
        self.assertEqual(ranges['overlap']['overlap_attempt'], [190, 220])
        self.assertEqual(ranges['touching']['nearest_before_attempt'], [100, 200])
        self.assertEqual(ranges['touching']['nearest_after_attempt'], [250, 300])
        self.assertIsNone(ranges['empty']['nearest_before_attempt'])
        self.assertIsNone(ranges['empty']['nearest_after_attempt'])
        self.assertGreater(ranges['evicted']['retained_first_tick'], 9)
        self.assertEqual(ranges['evicted']['nearest_after_attempt'], [20, 24])


if __name__ == '__main__':
    unittest.main()
