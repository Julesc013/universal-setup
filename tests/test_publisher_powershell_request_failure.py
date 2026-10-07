# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Exercise actual request catch/finally blocks with inert failure scenarios."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh') or shutil.which('powershell')
SCRIPT = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_standard_public_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Standard fixture parse failed'}
$functions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-StandardRequest'
},$true))
if($functions.Count -ne 1){throw 'Original request function is ambiguous'}
$tries=@($functions[0].Body.FindAll({param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally -and
    $node.CatchClauses.Count -eq 1 -and $node.CatchClauses[0].Body.Extent.Text.Contains('$requestFailure=$_')
},$true))
if($tries.Count -ne 1){throw 'Original request failure control flow is ambiguous'}
$node=$tries[0];$text=$node.Extent.Text
$start=$node.Body.Extent.StartOffset-$node.Extent.StartOffset
# Replace only the effectful body. Actual catch/finally code is unchanged.
$text=$text.Remove($start,$node.Body.Extent.Text.Length).Insert($start,
    "{if(`$primaryFails){throw 'Synthetic original request failure'};'synthetic successful body'}")
$flow=[scriptblock]::Create($text)
# Assignments are separate AST statements even when they share a source line.
$initializers=@($functions[0].Body.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
    $_.Left.Extent.Text -cin @('$requestFailure','$diagnosticObserverClosed')
})
if($initializers.Count -ne 2){throw 'Original failure/closure initialization is ambiguous'}
$initialize=[scriptblock]::Create(($initializers.Extent.Text -join ';'))
function Read-NativeSnapshot {
    param([switch]$IncludeMovedMaintenanceRoot)
    $events.Add('readback')
    $script:observersClosed=-not $readbackFails
    if(-not $IncludeMovedMaintenanceRoot){throw 'Maintenance diagnostic root scope differs'}
    if($readbackFails){throw 'Synthetic readback failure'}
    return @{scope='synthetic_readback';qualification_granted=$false}
}
function Close-StandardPublisherClient($Process,$Launch,$LaunchAttempted) {
    $events.Add('cleanup');$script:clientsClosed=$false
    if($cleanupFails){throw 'Synthetic cleanup failure'}
    $script:clientsClosed=$true
}
function Remove-OwnedProductionBoundaryObserver($Observer) {
    $events.Add('bootstrap_cleanup')
    if($bootstrapCase -ceq 'removal_failure'){throw 'Synthetic bootstrap cleanup failure'}
    $Observer.removed=$true
}
$results=@()
foreach($primaryFails in @($false,$true)) {
    foreach($cleanupFails in @($false,$true)) {
        foreach($readbackFails in @($false,$true)) {
          foreach($bootstrapCase in @('absent_closed','absent_unknown','removal_success','removal_failure')) {
            $receipt=[ordered]@{};. $initialize
            $events=[Collections.Generic.List[string]]::new();$script:clientsClosed=$false
            $script:observersClosed=$bootstrapCase -ceq 'absent_closed'
            $Command='repair.apply';$requestId='synthetic.request';$MaintenanceQualification=$true
            $launch=@{ProcessId=123;CreationFileTime=[long]456};$launchAttempted=$true
            $process=[pscustomobject]@{HasExited=$false};$bootstrapObserver=$null
            if($bootstrapCase.StartsWith('removal_')){$bootstrapObserver=@{removed=$false}}
            $stdout=Join-Path $Root 'absent.synthetic.stdout';$stderr=Join-Path $Root 'absent.synthetic.stderr'
            $nativeOutput=Join-Path $Root 'absent.synthetic.native'
            $errorMessage=$null;$bodyOutput=$null
            try {$bodyOutput=& $flow} catch {$errorMessage=$_.Exception.Message}
            $results+=@{primary=$primaryFails;cleanup=$cleanupFails;readback=$readbackFails;
                bootstrap=$bootstrapCase;
                error=$errorMessage;body_output=$bodyOutput;events=@($events);clients_closed=$script:clientsClosed;
                observers_closed=$script:observersClosed;
                failure=$receipt.request_execution_failure}
          }
        }
    }
}
ConvertTo-Json -InputObject @($results) -Depth 10 -Compress
'''


@unittest.skipUnless(POWERSHELL, 'PowerShell unavailable on this platform')
class PublisherPowerShellRequestFailureTests(unittest.TestCase):
    def test_primary_failure_survives_diagnostic_and_cleanup_failures(self):
        # No client, native reader, process cancellation or target is invoked.
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'request-failure.ps1'
            script.write_text(SCRIPT, encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), '-Root', str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 32)
        for row in rows:
            with self.subTest(primary=row['primary'], cleanup=row['cleanup'],
                              readback=row['readback'], bootstrap=row['bootstrap']):
                bootstrap_present = row['bootstrap'].startswith('removal_')
                bootstrap_failed = row['bootstrap'] == 'removal_failure'
                expected = ('Synthetic original request failure' if row['primary'] else
                    'Synthetic cleanup failure' if row['cleanup'] else
                    'Synthetic bootstrap cleanup failure' if bootstrap_failed else None)
                self.assertEqual(row['error'], expected)
                self.assertEqual(row['clients_closed'], not row['cleanup'])
                self.assertEqual(row['observers_closed'],
                    row['bootstrap'] in ('absent_closed', 'removal_success') and
                    (not row['primary'] or not row['readback']))
                events = ['readback'] if row['primary'] else []
                if bootstrap_present:
                    events.append('bootstrap_cleanup')
                self.assertEqual(row['events'], events + ['cleanup'])
                if row['primary']:
                    failure = row['failure']
                    self.assertEqual(failure['failure'], 'Synthetic original request failure')
                    self.assertFalse(failure['qualification_granted'])
                    self.assertEqual(failure['command'], 'repair.apply')
                    self.assertEqual(failure['client_process_id'], 123)
                    self.assertEqual(failure['client_creation_file_time'], '456')
                    self.assertFalse(failure['original_client_has_exited'])
                    self.assertEqual('readback_failure' in failure, row['readback'])
                    self.assertEqual('cleanup_failure' in failure, row['cleanup'] or bootstrap_failed)
                    self.assertEqual(set(failure['output_files']), {'stdout', 'stderr', 'native_response'})
                    self.assertTrue(all(not v['exists'] for v in failure['output_files'].values()))
                else:
                    self.assertIsNone(row['failure'])
                    if not row['cleanup'] and not bootstrap_failed:
                        self.assertEqual(row['body_output'], 'synthetic successful body')


if __name__ == '__main__':
    unittest.main()
