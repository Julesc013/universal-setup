# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Hosted WPR's Profiles schema orders collectors, providers, then profiles."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent


class PublisherWprProfileCompatibilityTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Actual PowerShell diagnostic routing')
    def test_sdk_recovery_uses_separate_owned_capture_and_existing_sdk_route(self):
        # Execute the actual argument/guard expressions without invoking WPR,
        # a service, a process or the lab. Keep private and SDK cohorts distinct.
        code = r'''$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$source=Join-Path $env:USK_TEST_SOURCE 'windows_publisher_maintenance_thread_trace_probe.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Trace wrapper parse failed'}
$text=[IO.File]::ReadAllText($source)
function Assignment([string]$Name) {
 $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
  $n.Left.Extent.Text -ceq $Name},$true))
 if($nodes.Count -ne 1){throw ('Actual assignment is ambiguous: '+$Name)}
 $nodes[0]
}
$identity=Assignment '$identity'
$guards=[scriptblock]::Create($text.Substring($ast.ParamBlock.Extent.EndOffset,
 $identity.Extent.StartOffset-$ast.ParamBlock.Extent.EndOffset))
$directory=[scriptblock]::Create((Assignment '$traceDirectory').Extent.Text)
$profile=[scriptblock]::Create((Assignment '$profileName').Extent.Text)
$arguments=Assignment '$probeArguments'
$invoke=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and
 $n.Extent.Text -ceq "& (Join-Path `$PSScriptRoot 'windows_publisher_lab_probe.ps1') @probeArguments"},$true))
if($invoke.Count -ne 1){throw 'Actual lab invocation is ambiguous'}
$route=[scriptblock]::Create($text.Substring($arguments.Extent.StartOffset,
 $invoke[0].Extent.StartOffset-$arguments.Extent.StartOffset))
$rows=@()
foreach($case in @('legacy','private_cpu','fresh','sdk','sdk_no_cpu','sdk_fresh','mixed')) {
 $FreshQualification=$case -cin @('fresh','sdk_fresh','mixed')
 $RecoveryCpuDiagnostic=$case -cin @('private_cpu','sdk','sdk_fresh','mixed')
 $SdkRecoveryQualification=$case -cin @('sdk','sdk_no_cpu','sdk_fresh')
 $failure=$null;$probeArguments=$null;$traceDirectory=$null;$profileName=$null
 try { . $guards;. $directory;. $profile;. $route } catch {$failure=$_.Exception.Message}
 $rows+=@{case=$case;failure=$failure;directory=$traceDirectory;profile=$profileName;arguments=$probeArguments}
}
$rows|ConvertTo-Json -Depth 8 -Compress
'''
        result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-Command', code],
                                env=dict(os.environ, USK_TEST_SOURCE=str(ROOT)),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = {row['case']: row for row in json.loads(result.stdout)}
        for case in ('sdk_no_cpu', 'sdk_fresh', 'mixed'):
            self.assertIsNotNone(rows[case]['failure'], rows[case])
            self.assertIsNone(rows[case]['arguments'], rows[case])
        self.assertEqual(len({rows[c]['directory'] for c in ('private_cpu', 'fresh', 'sdk')}), 3)
        for case in ('legacy', 'private_cpu', 'fresh', 'sdk'):
            row = rows[case]
            self.assertIsNone(row['failure'], row)
            arguments = row['arguments']
            self.assertIs(arguments['PublicInstallation'], True)
            self.assertIs(arguments['PublicStandardClient'], True)
            self.assertIs(arguments.get('PublicStandardMaintenanceQualification', False), case == 'fresh')
            self.assertIs(arguments.get('PublicStandardMaintenanceRecoveryQualification', False), case != 'fresh')
            self.assertIs(arguments.get('PublicStandardSdkRecoveryQualification', False), case == 'sdk')
            if case == 'sdk':
                self.assertEqual(arguments['ExpectedQualificationDiagnostics'], 'ON')
                self.assertEqual(row['profile'], 'USKRecoveryCPU')
            else:
                self.assertNotIn('ExpectedQualificationDiagnostics', arguments)

    @unittest.skipUnless(os.name == 'nt', 'Actual PowerShell trace receipt projection')
    def test_sdk_trace_projection_keeps_failed_attempt_and_complete_six_call_sequence(self):
        code = r'''$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
 (Join-Path $env:USK_TEST_SOURCE 'windows_publisher_maintenance_thread_trace_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Trace wrapper parse failed'}
$nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses.Count -eq 1 -and $n.Clauses[0].Item1.Extent.Text -ceq '$SdkRecoveryQualification' -and
 $n.Extent.Text.Contains('$sdkRequests=')},$true))
if($nodes.Count -ne 1){throw 'Actual SDK trace projection is ambiguous'}
$project=[scriptblock]::Create($nodes[0].Extent.Text)
$commands=@('recovery.inspect','recovery.plan','recovery.apply','recovery.apply','recovery.apply','installed.verify')
$seed=@(for($i=0;$i -lt $commands.Count;$i++) {
 @{request_id=('public.'+$i.ToString('x32'));command=$commands[$i];image_sha256=('a'*64);
 request_sha256=('b'*64);status='completed';client_cleanup_confirmed=$true;
 client_capture=@{process_id=100+$i;creation_file_time='123';captured_before_primary_thread_resume=$true}}
})|ConvertTo-Json -Depth 8 -Compress
$SdkRecoveryQualification=$true;$rows=@()
foreach($case in @('failed_fifth','complete_sixth','empty','seventh','wrong_order','malformed_id')) {
 $requests=@($seed|ConvertFrom-Json)
 switch($case) {
  failed_fifth {$requests=@($requests|Select-Object -First 5);$requests[4].status='failed';
   $requests[4].client_cleanup_confirmed=$false;$requests[4]|Add-Member failure 'unchanged deadline';
   $requests[4]|Add-Member cleanup_failure 'identity changed'}
  empty {$requests=@()}
  seventh {$requests+=@($requests[0])}
  wrong_order {$requests[0].command='recovery.apply'}
  malformed_id {$requests[4].request_id='foreign'}
 }
 $original=@{service_observation=@{sdk_requests=$requests}};$receipt=@{};$failure=$null
 try {. $project} catch {$failure=$_.Exception.Message}
 $rows+=@{case=$case;failure=$failure;observations=$receipt.sdk_request_observations}
}
$rows|ConvertTo-Json -Depth 12 -Compress
'''
        result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-Command', code],
                                env=dict(os.environ, USK_TEST_SOURCE=str(ROOT)),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = {row['case']: row for row in json.loads(result.stdout)}
        for case, count in (('failed_fifth', 5), ('complete_sixth', 6)):
            self.assertIsNone(rows[case]['failure'], rows[case])
            self.assertEqual(len(rows[case]['observations']), count)
        failed = rows['failed_fifth']['observations'][-1]
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(failed['failure'], 'unchanged deadline')
        self.assertIs(failed['client_cleanup_confirmed'], False)
        self.assertEqual(failed['cleanup_failure'], 'identity changed')
        self.assertEqual(rows['complete_sixth']['observations'][-1]['command'], 'installed.verify')
        for case in ('empty', 'seventh', 'wrong_order', 'malformed_id'):
            self.assertIsNotNone(rows[case]['failure'], rows[case])
            self.assertIsNone(rows[case]['observations'], rows[case])

    def test_definition_groups_follow_hosted_wpr_schema_order(self):
        # Hosted WPR 2022 actually rejected a collector after SystemProvider
        # (0xc00ce014). Newer WPR -profiledetails did not detect that ordering.
        # Check the schema groups independently of any specific profile layout.
        groups = {
            "SystemCollector": 0, "EventCollector": 0,
            "SystemProvider": 1, "MicroArchitecturalConfig": 1,
            "HardwareCounter": 1, "EventProvider": 1, "HeapEventProvider": 1,
            "Profile": 2,
        }
        paths = list(ROOT.glob("windows_publisher_*trace.wprp"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(profile=path.name):
                definitions = ET.parse(path).getroot().find("Profiles")
                self.assertIsNotNone(definitions)
                order = [groups[node.tag] for node in definitions]
                self.assertEqual(order, sorted(order),
                                 "Collectors must precede providers and profile references")


    def test_recovery_cpu_route_has_bounded_identity_and_phase_capture(self):
        definitions = ET.parse(ROOT / "windows_publisher_maintenance_fresh_cpu_trace.wprp").getroot().find("Profiles")
        nodes = {node.attrib["Id"]: node for node in definitions}
        profiles = [node for node in definitions.findall("Profile")
                    if node.attrib["Name"] == "USKRecoveryCPU"]
        self.assertEqual({node.attrib["LoggingMode"] for node in profiles}, {"Memory", "File"})
        self.assertEqual(len(profiles), 2)
        for profile in profiles:
            collector_ref = profile.find("Collectors/SystemCollectorId")
            provider = nodes[collector_ref.find("SystemProviderId").attrib["Value"]]
            self.assertEqual({node.attrib["Value"] for node in provider.findall("Keywords/Keyword")},
                             {"ProcessThread", "Loader", "SampledProfile"})
            self.assertEqual({node.attrib["Value"] for node in provider.findall("Stacks/Stack")},
                             {"ThreadCreate", "SampledProfile"})
            collector = nodes[collector_ref.attrib["Value"]]
            self.assertEqual(int(collector.find("BufferSize").attrib["Value"]) *
                             int(collector.find("Buffers").attrib["Value"]), 512 * 128)
            event_ref = profile.find("Collectors/EventCollectorId")
            events = event_ref.findall("EventProviders/EventProviderId")
            self.assertEqual(len(events), 1)
            self.assertEqual(nodes[events[0].attrib["Value"]].attrib["Name"],
                             "7e4a4d0e-4d53-4c2d-93a3-6ba61cf46711")
            self.assertEqual(nodes[events[0].attrib["Value"]].attrib["Level"], "4")
            self.assertEqual([keyword.attrib["Value"] for keyword in
                              nodes[events[0].attrib["Value"]].findall("Keywords/Keyword")],
                             ["0x1"])
            event_collector = nodes[event_ref.attrib["Value"]]
            self.assertEqual(int(event_collector.find("BufferSize").attrib["Value"]) *
                             int(event_collector.find("Buffers").attrib["Value"]), 64 * 128)
        # Existing fresh capture keeps scheduler observations for its distinct task.
        fresh = next(node for node in definitions.findall("Profile")
                     if node.attrib["Name"] == "USKFreshCPU" and node.attrib["LoggingMode"] == "Memory")
        fresh_event_ref = fresh.find("Collectors/EventCollectorId/EventProviders/EventProviderId")
        self.assertEqual(nodes[fresh_event_ref.attrib["Value"]].attrib["Level"], "5")
        provider_ref = fresh.find("Collectors/SystemCollectorId/SystemProviderId")
        self.assertEqual({node.attrib["Value"] for node in nodes[provider_ref.attrib["Value"]].findall("Keywords/Keyword")},
                         {"ProcessThread", "Loader", "SampledProfile", "CSwitch", "ReadyThread"})


if __name__ == "__main__":
    unittest.main()
