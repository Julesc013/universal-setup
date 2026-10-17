# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Run the actual fixture enrollment control flow with a data-only controller."""
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
