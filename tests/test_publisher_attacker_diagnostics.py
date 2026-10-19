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
@{failures=$rows;ranges=$ranges}|ConvertTo-Json -Depth 12 -Compress
'''


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
