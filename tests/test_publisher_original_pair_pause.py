# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Exercise actual fixture orchestration with actorless role and provider controls.

These controls do not open processes, suspend threads, query SCM or mount disks.
They establish ordering, refusal and returned-custody behavior, not qualification.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh') or shutil.which('powershell')

ORCHESTRATION = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
public sealed class OriginalParentControl {
    public int Id {get{return 10;}}
    public DateTime StartTime {get{return DateTime.FromFileTimeUtc(700);}}
    public bool HasExited {get{return PausePairControl.Case=="parent_ended";}}
}
public sealed class PausePairControl {
    public static string Case;
    public static readonly List<string> Events=new List<string>();
    public bool ParentAcquisitionEnabled;public uint Id;public ulong Birth;
    public PausePairControl(uint id,ulong birth,string image):this(id,birth,image,false) {}
    public PausePairControl(uint id,ulong birth,string image,bool parent) {
        Events.Add(parent?"parent_constructor":"child_constructor");
        if((parent && (Case=="parent_constructor" || Case=="diagnostic_failure")) ||
            (!parent && Case=="child_constructor"))throw new Exception("original constructor refusal");
        Id=id;Birth=birth;ParentAcquisitionEnabled=parent;
    }
    public void CaptureParentThreads(int checkpoint) {
        Events.Add("capture"+checkpoint);
        if(checkpoint==1 && Case=="capture_failure")throw new Exception("original capture refusal");
    }
    public Dictionary<string,object> ParentAcquisitionIdentity() {
        return new Dictionary<string,object>{{"process_id",Case=="parent_identity"?(uint)99:Id},
            {"process_creation_file_time",Birth.ToString()},{"acquisition_ready",false}};
    }
    public void RequirePaused() {
        Events.Add(ParentAcquisitionEnabled?"parent_strict":"child_strict");
        if(!ParentAcquisitionEnabled && Case=="child_not_paused")throw new Exception("original pause refusal");
    }
}
public sealed class OriginalPairControl {
    public int Calls;
    public uint ChildProcessId {get{return 20;}}
    public string ChildProcessBirth {get{return ((ulong)800).ToString("x16");}}
    public Dictionary<string,object> ObserveOriginalLivePair() {
        PausePairControl.Events.Add("pair");Calls++;
        if(PausePairControl.Case=="pair_before_parent" && Calls==3)throw new Exception("original pair refusal");
        return new Dictionary<string,object>{{"parent_process_id",(uint)10},{"effect_process_id",(uint)20},
            {"parent_process_birth",((ulong)(PausePairControl.Case=="parent_birth"?701:700)).ToString("x16")},
            {"effect_process_birth",ChildProcessBirth},{"both_live",PausePairControl.Case!="pair_ended"},
            {"original_image_path",PausePairControl.Case=="pair_image"?"C:\\wrong.exe":Environment.GetEnvironmentVariable("USK_TEST_IMAGE")}};
    }
    public Dictionary<string,object> ObserveOriginalPairFailure() {
        PausePairControl.Events.Add("failure_sample");
        if(PausePairControl.Case=="diagnostic_failure")throw new Exception("optional diagnostic refusal");
        return new Dictionary<string,object>{{"qualification_granted",false},{"atomic_snapshot",false}};
    }
}
'@
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_active_worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actual orchestration source syntax differs'}
$functions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq 'Start-OwnedPublisherOriginalPairPause'
},$true))
if($functions.Count -ne 1){throw 'Actual original pair orchestration is ambiguous'}
# Only actor types and the controlled host identity are replaced. All target
# predicates, ordering, attempts, reference custody and failure handling run.
$identity='[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'
if($functions[0].Extent.Text.Split(@($identity),[StringSplitOptions]::None).Count -ne 2) {
    throw 'Controlled host identity replacement is ambiguous'
}
$definition=$functions[0].Extent.Text.Replace('[Diagnostics.Process]','[OriginalParentControl]').
    Replace('UskPublisherPausedWorker','PausePairControl').Replace('UskOwnedEffectChildObserver','OriginalPairControl').
    Replace($identity,"'S-1-5-18'")
Invoke-Expression $definition
$env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted'
$env:RUNNER_TEMP='C:\usk-runner';$env:ProgramW6432='C:\usk-program'
$service='USK_PUB_'+('a'*32);$lab='C:\usk-runner\usk-wu006-'+('b'*32)
$image=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$service+'.exe')
$env:USK_TEST_IMAGE=$image
$volumeRoot='\\?\Volume{00000000-0000-0000-0000-000000000001}\'
$command='"'+$image+'" --service '+$service+' --no-receipt '+$volumeRoot+' owned'
function Get-DiskImage {
    param($ImagePath,$ErrorAction)
    [PausePairControl]::Events.Add('disk_image')
    [pscustomobject]@{Attached=([PausePairControl]::Case -cne 'detached')}
}
function Get-Disk {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    [PausePairControl]::Events.Add('disk')
    [pscustomobject]@{IsBoot=([PausePairControl]::Case -ceq 'boot_disk');IsSystem=$false}
}
function Get-Partition {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    [PausePairControl]::Events.Add('partition')
    if([PausePairControl]::Case -cne 'no_partition'){[pscustomobject]@{DriveLetter='Z'}}
}
function Get-Volume {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    [PausePairControl]::Events.Add('volume')
    [pscustomobject]@{UniqueId=$(if([PausePairControl]::Case -ceq 'volume_identity'){'wrong'}else{$volumeRoot});
        FileSystem=$(if([PausePairControl]::Case -ceq 'filesystem'){'FAT32'}else{'NTFS'})}
}
function Get-FileHash {
    param($LiteralPath,$Algorithm)
    [PausePairControl]::Events.Add('image_hash')
    [pscustomobject]@{Hash=$(if([PausePairControl]::Case -ceq 'image_hash'){'c'*64}else{'d'*64})}
}
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    [PausePairControl]::Events.Add('scm')
    if($ClassName -cne 'Win32_Service' -or $Filter -cne ("Name='"+$service+"'")){throw 'Unexpected provider query'}
    [pscustomobject]@{ProcessId=$(if([PausePairControl]::Case -ceq 'service_pid'){99}else{10});
        State='Running';StartName=$(if([PausePairControl]::Case -ceq 'service_account'){'wrong'}else{'LocalSystem'});
        PathName=$(if([PausePairControl]::Case -ceq 'service_command'){'wrong'}else{$command})}
}
function Initialize-OwnedPublisherWorkerPause {[PausePairControl]::Events.Add('initialize')}
$results=@()
foreach($case in @('valid','parent_ended','parent_birth','pair_ended','wrong_lab','detached','boot_disk',
    'no_partition','volume_identity','filesystem','pair_image','image_hash','service_pid','service_account',
    'service_command','child_constructor','child_not_paused','pair_before_parent','parent_constructor',
    'capture_failure','parent_identity','diagnostic_failure')) {
    [PausePairControl]::Case=$case;[PausePairControl]::Events.Clear()
    $parent=$null;$child=$null;$parentAttempted=$false;$childAttempted=$false;$failure=$null
    $script:activeRetainedChildPause=$null;$originalError=$null
    $vhd=Join-Path $lab 'owned.vhdx'
    if($case -ceq 'wrong_lab'){$vhd='C:\outside\owned.vhdx'}
    try {
        Start-OwnedPublisherOriginalPairPause -ParentWorker ([OriginalParentControl]::new()) -EffectPair ([OriginalPairControl]::new()) -Service $service -VhdPath $vhd -VolumeRoot $volumeRoot -ExpectedServiceCommand $command -ExpectedImagePath $image -ExpectedImageSha256 ('d'*64) -ParentPause ([ref]$parent) -ChildPause ([ref]$child) -ParentPauseAttempted ([ref]$parentAttempted) -ChildPauseAttempted ([ref]$childAttempted) -FailureDiagnostic ([ref]$failure)
    } catch {$originalError=$_.Exception.Message}
    $results+=@{case=$case;error=$originalError;events=@([PausePairControl]::Events);
        parent_attempted=$parentAttempted;child_attempted=$childAttempted;
        parent_returned=[bool]$parent;child_returned=[bool]$child;
        child_retained=[object]::ReferenceEquals($child,$script:activeRetainedChildPause);
        diagnostic=$failure}
}
ConvertTo-Json -InputObject @($results) -Depth 6 -Compress
'''

SAMPLE_CONTROLS = r'''
    static int lastError;public static string Mode;public static int Calls;
    static uint GetProcessId(IntPtr handle) {
        Calls++;lastError=6;return Mode=="id_error"?0u:10u;
    }
    static bool GetProcessTimes(IntPtr handle,out long birth,out long exit,out long kernel,out long user) {
        Calls++;lastError=5;birth=700;exit=999;kernel=0;user=0;return Mode!="birth_error";
    }
    static uint WaitForSingleObject(IntPtr handle,uint wait) {
        Calls++;lastError=7;return Mode=="wait_error"?UInt32.MaxValue:Mode=="ended"?0u:258u;
    }
    static bool GetExitCodeProcess(IntPtr handle,out uint exitCode) {
        Calls++;lastError=8;exitCode=Mode=="ended"?5u:259u;return Mode!="exit_error";
    }
    public static Dictionary<string,object> Run(string mode) {
        Mode=mode;Calls=0;
        return FailureRole(mode=="no_handle"?IntPtr.Zero:new IntPtr(123),10,700);
    }
'''


@unittest.skipUnless(POWERSHELL, 'PowerShell unavailable on this platform')
class PublisherOriginalPairPauseTests(unittest.TestCase):
    def run_script(self, text, *args):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'controls.ps1'
            script.write_text(text, encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), *args], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    @unittest.skipUnless(os.name == 'nt', 'Windows fixture path semantics required')
    def test_actual_orchestration_orders_owned_target_child_and_parent(self):
        rows = self.run_script(ORCHESTRATION, '-Root', str(ROOT))
        self.assertEqual(len(rows), 22)
        for row in rows:
            with self.subTest(case=row['case']):
                case, events = row['case'], row['events']
                self.assertEqual(row['error'] is None, case == 'valid', row)
                if case == 'valid':
                    self.assertEqual(events, ['pair', 'disk_image', 'disk', 'partition',
                        'volume', 'image_hash', 'scm', 'initialize', 'pair', 'child_constructor',
                        'child_strict', 'pair', 'parent_constructor', 'capture1', 'pair',
                        'child_strict', 'pair', 'capture2'])
                    self.assertTrue(row['parent_returned'] and row['child_returned'])
                    self.assertIsNone(row['diagnostic'])
                elif case in {'parent_constructor', 'capture_failure', 'parent_identity', 'diagnostic_failure'}:
                    self.assertTrue(row['parent_attempted'] and row['child_attempted'])
                    self.assertTrue(row['child_returned'] and row['child_retained'])
                    self.assertEqual(row['parent_returned'], case in {'capture_failure', 'parent_identity'})
                elif case in {'child_not_paused', 'pair_before_parent'}:
                    self.assertTrue(row['child_attempted'] and row['child_returned'] and row['child_retained'])
                    self.assertFalse(row['parent_attempted'] or row['parent_returned'])
                elif case == 'child_constructor':
                    self.assertTrue(row['child_attempted'])
                    self.assertFalse(row['child_returned'] or row['parent_attempted'] or row['parent_returned'])
                else:
                    self.assertFalse(row['child_attempted'] or row['parent_attempted'])
                    self.assertNotIn('child_constructor', events)
                    self.assertNotIn('parent_constructor', events)
                if row['error']:
                    self.assertFalse(row['diagnostic']['qualification_granted'])
                    self.assertFalse(row['diagnostic']['atomic_snapshot'])
                    self.assertEqual(row['diagnostic']['parent_custody_returned'], row['parent_returned'])
                    self.assertEqual(row['diagnostic']['child_custody_returned'], row['child_returned'])
                if case == 'diagnostic_failure':
                    self.assertIn('original constructor refusal', row['error'])
                    self.assertNotIn('optional diagnostic refusal', row['error'])
                    self.assertEqual(row['diagnostic']['pair_capture_status'], 'capture_failed')

    def test_actual_failure_sampler_retains_independent_errors_and_unknown_facts(self):
        source = (ROOT / 'tests/windows_publisher_owned_effect_child.ps1').read_text(encoding='utf-8')
        match = re.search(r'(    static Dictionary<string,object> FailureRole\(.*?\n    \})\n'
            r'    public Dictionary<string,object> ObserveOriginalPairFailure', source, re.S)
        self.assertIsNotNone(match)
        # The actual method body runs; only native calls are deterministic.
        body = match[1].replace('Marshal.GetLastWin32Error()', 'lastError')
        model = 'using System;using System.Collections.Generic;public static class FailureSampleControl {\n'
        model += body + SAMPLE_CONTROLS + '\n}'
        script = "Add-Type -TypeDefinition @'\n" + model + "\n'@\n$rows=@()\n"
        script += r'''
foreach($mode in @('no_handle','ended','birth_error','id_error','wait_error','exit_error')) {
    $facts=[FailureSampleControl]::Run($mode)
    $rows+=@{case=$mode;facts=$facts;calls=[FailureSampleControl]::Calls}
}
ConvertTo-Json -InputObject @($rows) -Depth 5 -Compress
'''
        rows = self.run_script(script)
        self.assertEqual(len(rows), 6)
        for row in rows:
            facts = row['facts']
            self.assertEqual(facts['expected_process_id'], 10)
            self.assertEqual(facts['expected_process_birth'], '00000000000002bc')
            self.assertEqual(row['calls'], 0 if row['case'] == 'no_handle' else 4)
            if row['case'] == 'no_handle':
                self.assertFalse(facts['handle_retained'])
                self.assertIsNone(facts['wait_result'])
                self.assertIsNone(facts['exit_code'])
            elif row['case'] == 'ended':
                self.assertEqual((facts['wait_result'], facts['exit_code']), (0, 5))
            elif row['case'] == 'birth_error':
                self.assertFalse(facts['birth_query_succeeded'])
                self.assertIsNone(facts['process_birth'])
                self.assertEqual(facts['birth_query_error'], 5)
                self.assertEqual((facts['wait_result'], facts['exit_code']), (258, 259))
            elif row['case'] == 'id_error':
                self.assertEqual((facts['process_id'], facts['process_id_error']), (0, 6))
            elif row['case'] == 'wait_error':
                self.assertEqual((facts['wait_result'], facts['wait_error']), (4294967295, 7))
            elif row['case'] == 'exit_error':
                self.assertFalse(facts['exit_code_query_succeeded'])
                self.assertIsNone(facts['exit_code'])
                self.assertEqual(facts['exit_code_query_error'], 8)


if __name__ == '__main__':
    unittest.main()
