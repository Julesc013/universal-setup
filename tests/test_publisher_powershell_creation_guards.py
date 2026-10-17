# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Execute the actual PowerShell evidence guards on closed data-only reports."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh') or shutil.which('powershell')
SCRIPT = r'''
param([string]$Root,[string]$InputFile)
$ErrorActionPreference='Stop'
$cases=Get-Content -LiteralPath $InputFile -Raw|ConvertFrom-Json
$results=@()
foreach($reader in @('standard','public')) {
    $leaf=if($reader -ceq 'standard'){'windows_publisher_standard_public_probe.ps1'}else{'windows_publisher_public_path_probe.ps1'}
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Join-Path $Root 'tests') $leaf),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Evidence reader parse failed'}
    $selectors=@($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -cin @('$phaseSchema','$childEvidence','$reportSchema','$creatorSchema')
    },$true)|Sort-Object {$_.Extent.StartOffset})
    $expectedSelectors=if($reader -ceq 'standard'){4}else{3}
    if($selectors.Count -ne $expectedSelectors){throw 'Evidence selector set differs'}
    $messages=if($reader -ceq 'standard'){@(
        "throw 'Standard native creation/worker evidence is incomplete'",
        "throw 'Standard native child evidence lacks separate original broker/creator bindings'"
    )}else{@(
        "throw 'Independent execution reconciliation result differs'",
        "throw 'Independent native child evidence lacks separate original broker/creator bindings'"
    )}
    $guards=@($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        @($messages|Where-Object {$node.Extent.Text.Contains($_)}).Count -gt 0
    },$true)|Sort-Object {$_.Extent.StartOffset})
    if($guards.Count -ne 2){throw 'Evidence guard set differs'}
    foreach($case in $cases) {
        $record=[pscustomobject]@{schema=$case.phase}
        $prepared=@([pscustomobject]@{content_json=($record|ConvertTo-Json -Compress)})
        $report=$case.report;$executionReport=$case.report
        foreach($selector in $selectors){Invoke-Expression $selector.Extent.Text}
        $refused=$false
        foreach($guard in $guards) {
            $condition=[scriptblock]::Create($guard.Clauses[0].Item1.Extent.Text)
            $value=@(& $condition)
            if($value.Count -ne 1 -or $value[0] -isnot [bool]){throw 'Evidence condition did not return one boolean'}
            if($value[0]){$refused=$true}
        }
        $results+=@{reader=$reader;name=$case.name;refused=$refused}
    }
}
ConvertTo-Json -InputObject @($results) -Depth 8 -Compress
'''


@unittest.skipUnless(POWERSHELL, 'PowerShell unavailable on this platform')
class PublisherPowerShellCreationGuardTests(unittest.TestCase):
    def test_current_and_legacy_families_keep_creator_and_broker_floor(self):
        # These reports are synthetic. Running the actual selector/conditions
        # supplies no native observation, SCM actor or publisher authority.
        report = {
            'schema': 'usk.publisher_execution_reconciliation.v5',
            'status': 'bindings_consistent', 'profile_qualified': False,
            'held_roles_per_phase': 7, 'phase_count': 5,
            'process_bound_phase_count': 5, 'worker_security_phase_count': 5,
            'effect_worker_phase_count': 5, 'broker_process_ids': [500],
            'worker_process_ids': [600],
            'creation_observation': {
                'schema': 'usk.publisher_creation_reconciliation.v5',
                'status': 'bindings_consistent', 'profile_qualified': False,
                'process_boundary_checked': True, 'worker_security_checked': True,
                'original_broker_checked': True, 'created_object_count': 6,
            },
        }
        cases = []

        def case(name, phase, value, refused):
            cases.append(dict(name=name, phase=phase, report=copy.deepcopy(value), refused=refused))

        current = 'usk.publisher.lab_phase_evidence.v11'
        old_child = 'usk.publisher.lab_phase_evidence.v10'
        case('native_retirement_family', current, report, False)
        prior = copy.deepcopy(report)
        prior['creation_observation']['schema'] = 'usk.publisher_creation_reconciliation.v4'
        case('original_child_family', old_child, prior, False)
        case('new_phase_old_creator_refuses', current, prior, True)
        case('old_phase_new_creator_refuses', old_child, report, True)
        legacy = copy.deepcopy(prior)
        legacy['schema'] = 'usk.publisher_execution_reconciliation.v4'
        legacy['creation_observation']['schema'] = 'usk.publisher_creation_reconciliation.v3'
        case('legacy_family', 'usk.publisher.lab_phase_evidence.v9', legacy, False)
        for field, value in [('original_broker_checked', False), ('worker_security_checked', False)]:
            forged = copy.deepcopy(report)
            forged['creation_observation'][field] = value
            case(field + '_refuses', current, forged, True)
        for field, value in [('broker_process_ids', []), ('worker_process_ids', []), ('effect_worker_phase_count', 4)]:
            forged = copy.deepcopy(report)
            forged[field] = value
            case(field + '_refuses', current, forged, True)
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'guards.ps1'
            inputs = Path(directory) / 'reports.json'
            script.write_text(SCRIPT, encoding='utf-8')
            inputs.write_text(json.dumps(cases), encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), '-Root', str(ROOT), '-InputFile', str(inputs)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = json.loads(result.stdout)
        self.assertEqual(len(actual), 2 * len(cases))
        expected = {(reader, item['name']): item['refused']
                    for reader in ('standard', 'public') for item in cases}
        self.assertEqual({(item['reader'], item['name']): item['refused'] for item in actual}, expected)


if __name__ == '__main__':
    unittest.main()
