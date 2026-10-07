# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Run the actual pause algorithm with actorless native-call controls.

Only P/Invoke declarations are replaced. These controls establish algorithm and
custody behavior, not live suspension, kernel-I/O retirement or qualification.
"""
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh') or shutil.which('powershell')
NATIVE_NAMES = {
    'OpenProcess', 'OpenThread', 'GetProcessIdOfThread', 'GetProcessTimes',
    'GetThreadTimes', 'QueryFullProcessImageName', 'CreateToolhelp32Snapshot',
    'Thread32First', 'Thread32Next', 'SuspendThread', 'ResumeThread',
    'WaitForSingleObject', 'CloseHandle',
}

NATIVE_CONTROLS = r'''
    sealed class ModelThread {
        public uint id,owner=10,count; public ulong birth; public bool live=true;
    }
    static Dictionary<uint,ModelThread> modelThreads;
    static Dictionary<IntPtr,ModelThread> modelHandles;
    static Dictionary<IntPtr,List<ThreadEntry>> modelSnapshots;
    static Dictionary<IntPtr,int> modelPositions;
    static int nextHandle,snapshots,opened,closedHandles,suspends,resumes,lastError;
    static uint failOpen,failTimes,failSuspend,failResume,wrongOwner,hiddenThread,duplicateThread;
    static bool failClose,processLive; static ulong processBirth; static int extraRows;
    public static void Reset() {
        modelThreads=new Dictionary<uint,ModelThread>();modelHandles=new Dictionary<IntPtr,ModelThread>();
        modelSnapshots=new Dictionary<IntPtr,List<ThreadEntry>>();modelPositions=new Dictionary<IntPtr,int>();
        nextHandle=2000;snapshots=opened=closedHandles=suspends=resumes=0;lastError=18;
        failOpen=failTimes=failSuspend=failResume=wrongOwner=hiddenThread=duplicateThread=0;
        failClose=false;processLive=true;processBirth=700;extraRows=0;Add(11,1100,0);
    }
    public static void Add(uint id,ulong birth,uint count) {
        modelThreads[id]=new ModelThread {id=id,birth=birth,count=count};
    }
    public static void Control(string kind,uint id,ulong value) {
        switch(kind) {
            case "open":failOpen=id;break;case "times":failTimes=id;break;
            case "suspend":failSuspend=id;break;case "resume":failResume=id;break;
            case "owner":wrongOwner=id;break;case "hidden":hiddenThread=id;break;
            case "duplicate":duplicateThread=id;break;case "close":failClose=true;break;
            case "birth":modelThreads[id].birth=value;break;case "ended":modelThreads[id].live=false;break;
            case "process_birth":processBirth=value;break;case "process_ended":processLive=false;break;
            case "rows":extraRows=(int)value;break;default:throw new Exception("Unknown control");
        }
    }
    public static uint Count(uint id) { return modelThreads[id].count; }
    public static int Suspends { get { return suspends; } }
    public static int Resumes { get { return resumes; } }
    public static int Outstanding { get { return opened-closedHandles; } }
    public static int Snapshots { get { return snapshots; } }
    static Times Birth(ulong value) { return new Times {low=(uint)value,high=(uint)(value>>32)}; }
    static IntPtr OpenProcess(uint access,bool inherit,uint id) {
        if(access!=0x101000 || inherit || id!=10)throw new Exception("Process rights changed");
        opened++;return new IntPtr(1000);
    }
    static IntPtr OpenThread(uint access,bool inherit,uint id) {
        if(access!=0x100802 || inherit)throw new Exception("Thread rights changed");
        if(id==failOpen)return IntPtr.Zero;
        var handle=new IntPtr(++nextHandle);modelHandles.Add(handle,modelThreads[id]);opened++;return handle;
    }
    static uint GetProcessIdOfThread(IntPtr thread) {
        var item=modelHandles[thread];return item.id==wrongOwner?99:item.owner;
    }
    static bool GetProcessTimes(IntPtr process,out Times birth,out Times exit,out Times kernel,out Times user) {
        birth=Birth(processBirth);exit=kernel=user=Birth(123);return true;
    }
    static bool GetThreadTimes(IntPtr thread,out Times birth,out Times exit,out Times kernel,out Times user) {
        var item=modelHandles[thread];birth=Birth(item.birth);exit=kernel=user=Birth(987654);
        return item.id!=failTimes;
    }
    static bool QueryFullProcessImageName(IntPtr process,uint flags,System.Text.StringBuilder image,ref uint length) {
        image.Append("original.exe");length=(uint)image.Length;return true;
    }
    static IntPtr CreateToolhelp32Snapshot(uint flags,uint process) {
        if(flags!=4 || process!=0)throw new Exception("Census scope changed");
        var handle=new IntPtr(++nextHandle);var rows=new List<ThreadEntry>();
        foreach(var item in modelThreads.Values) {
            if(!item.live || item.id==hiddenThread)continue;
            rows.Add(new ThreadEntry {id=item.id,owner=item.owner});
            if(item.id==duplicateThread)rows.Add(new ThreadEntry {id=item.id,owner=item.owner});
        }
        for(int i=0;i<extraRows;i++)rows.Add(new ThreadEntry {id=(uint)(50000+i),owner=99});
        modelSnapshots.Add(handle,rows);modelPositions.Add(handle,0);snapshots++;opened++;return handle;
    }
    static bool Thread32First(IntPtr snapshot,ref ThreadEntry entry) {
        var rows=modelSnapshots[snapshot];if(rows.Count==0){lastError=18;return false;}entry=rows[0];return true;
    }
    static bool Thread32Next(IntPtr snapshot,ref ThreadEntry entry) {
        var rows=modelSnapshots[snapshot];int index=++modelPositions[snapshot];
        if(index>=rows.Count){lastError=18;return false;}entry=rows[index];return true;
    }
    static uint SuspendThread(IntPtr thread) {
        var item=modelHandles[thread];suspends++;if(item.id==failSuspend)return 0xffffffff;
        return item.count++;
    }
    static uint ResumeThread(IntPtr thread) {
        var item=modelHandles[thread];resumes++;if(item.id==failResume)return 0xffffffff;
        uint prior=item.count;if(prior>0)item.count--;return prior;
    }
    static uint WaitForSingleObject(IntPtr handle,uint milliseconds) {
        if(milliseconds!=0)throw new Exception("A wait was introduced");
        return handle.ToInt64()==1000 ? (processLive?258u:0u) : (modelHandles[handle].live?258u:0u);
    }
    static bool CloseHandle(IntPtr handle) {
        closedHandles++;return !failClose;
    }
'''

ALGORITHM_CONTROLS = r'''
public static class PauseAcquisitionControls {
    static void Check(bool value,string message) {if(!value)throw new Exception(message);}
    static void Refuse(Action action,string message) {
        bool refused=false;try {action();} catch(InvalidOperationException){refused=true;}
        Check(refused,message);
    }
    static UskPublisherPausedWorkerModel Parent() {return new UskPublisherPausedWorkerModel(10,700,"original.exe",true);}
    static void Closed(UskPublisherPausedWorkerModel pause) {
        pause.Dispose();Check(UskPublisherPausedWorkerModel.Outstanding==0,"Handle leaked");
    }
    public static string[] Run() {
        var passed=new System.Collections.Generic.List<string>();
        UskPublisherPausedWorkerModel.Reset();
        var p=Parent();
        Check(!((bool)p.ParentAcquisitionIdentity()["acquisition_ready"]),"Acquisition claimed readiness");
        Refuse(()=>p.RequirePaused(),"Unsealed pause accepted");Refuse(()=>p.Observation(),"Unsealed observation accepted");
        UskPublisherPausedWorkerModel.Add(12,1200,0);p.CaptureParentThreads(1);
        UskPublisherPausedWorkerModel.Add(13,1300,0);p.CaptureParentThreads(2);
        UskPublisherPausedWorkerModel.Add(14,1400,0);p.CaptureParentThreads(3);
        Check(UskPublisherPausedWorkerModel.Suspends==4,"Original threads were resuspended");
        int census=UskPublisherPausedWorkerModel.Snapshots;
        p.SealParentThreads();Check(UskPublisherPausedWorkerModel.Snapshots==census+1,"Seal lacks independent census");
        p.RequirePaused();Check((int)p.Observation()["paused_threads"]==4,"New custody was omitted");
        Closed(p);Check(UskPublisherPausedWorkerModel.Resumes==4,"Custody not restored exactly once");
        for(uint id=11;id<=14;id++)Check(UskPublisherPausedWorkerModel.Count(id)==0,"Suspension leaked");
        p.Dispose();Check(UskPublisherPausedWorkerModel.Resumes==4,"Dispose repeated mutation");
        passed.Add("three captures, independent seal, original handles and checked restoration");

        UskPublisherPausedWorkerModel.Reset();p=Parent();p.CaptureParentThreads(1);p.CaptureParentThreads(2);p.CaptureParentThreads(3);
        UskPublisherPausedWorkerModel.Add(12,1200,0);
        Refuse(()=>p.SealParentThreads(),"Seal admitted a late thread");
        Check(UskPublisherPausedWorkerModel.Count(12)==0,"Seal suspended a new thread");
        Refuse(()=>p.CaptureParentThreads(3),"Failed seal reopened acquisition");Closed(p);
        passed.Add("arrival between last capture and seal refuses without mutation");

        UskPublisherPausedWorkerModel.Reset();p=Parent();p.CaptureParentThreads(1);p.CaptureParentThreads(2);p.CaptureParentThreads(3);p.SealParentThreads();
        UskPublisherPausedWorkerModel.Add(12,1200,0);
        Refuse(()=>p.RequirePaused(),"Post-seal arrival accepted");
        Check(UskPublisherPausedWorkerModel.Suspends==1,"Strict observation admitted a thread");Closed(p);
        passed.Add("post-seal arrival remains strictly observation-only");

        foreach(string kind in new[]{"hidden","ended","birth","owner","times"}) {
            UskPublisherPausedWorkerModel.Reset();p=Parent();UskPublisherPausedWorkerModel.Control(kind,11,999);
            Refuse(()=>p.CaptureParentThreads(1),"Original identity loss accepted: "+kind);
            Refuse(()=>p.CaptureParentThreads(1),"Failed capture retried");Closed(p);
        }
        passed.Add("lost, ended, reused, wrong-owner and inaccessible original thread refuse");

        UskPublisherPausedWorkerModel.Reset();p=Parent();
        UskPublisherPausedWorkerModel.Control("ended",11,0);UskPublisherPausedWorkerModel.Add(11,9999,0);
        Refuse(()=>p.CaptureParentThreads(1),"Replacement with the same thread ID accepted");Closed(p);
        Check(UskPublisherPausedWorkerModel.Count(11)==0,"Replacement thread was mutated");
        passed.Add("literal same-ID replacement cannot replace the original held handle");

        foreach(string kind in new[]{"open","times","owner","suspend","duplicate"}) {
            UskPublisherPausedWorkerModel.Reset();p=Parent();UskPublisherPausedWorkerModel.Add(12,1200,0);
            UskPublisherPausedWorkerModel.Control(kind,12,0);
            Refuse(()=>p.CaptureParentThreads(1),"New-thread query failure accepted: "+kind);
            Refuse(()=>p.CaptureParentThreads(1),"Failed new custody retried");Closed(p);
            Check(UskPublisherPausedWorkerModel.Count(11)==0 && UskPublisherPausedWorkerModel.Count(12)==0,"Partial acquisition leaked");
        }
        passed.Add("new-thread failures retain and restore partial custody");

        UskPublisherPausedWorkerModel.Reset();p=Parent();UskPublisherPausedWorkerModel.Add(12,1200,2);
        Refuse(()=>p.CaptureParentThreads(1),"Pre-suspended new member accepted");Closed(p);
        Check(UskPublisherPausedWorkerModel.Count(12)==2,"Preexisting suspension count altered");
        passed.Add("preexisting suspension refuses and original count is restored");

        UskPublisherPausedWorkerModel.Reset();p=Parent();
        for(uint id=12;id<=138;id++)UskPublisherPausedWorkerModel.Add(id,id*100,0);
        p.CaptureParentThreads(1);Check(UskPublisherPausedWorkerModel.Suspends==128,"128 custody bound changed");
        UskPublisherPausedWorkerModel.Add(139,13900,0);
        Refuse(()=>p.CaptureParentThreads(2),"129th member accepted");Closed(p);
        passed.Add("cumulative owned-thread bound remains 128");

        UskPublisherPausedWorkerModel.Reset();p=Parent();UskPublisherPausedWorkerModel.Control("rows",0,16384);
        Refuse(()=>p.CaptureParentThreads(1),"System row overflow accepted");Closed(p);
        passed.Add("system census bound remains 16384");

        foreach(int checkpoint in new[]{0,2,4}) {
            UskPublisherPausedWorkerModel.Reset();p=Parent();
            Refuse(()=>p.CaptureParentThreads(checkpoint),"Out-of-order capture accepted");Closed(p);
        }
        UskPublisherPausedWorkerModel.Reset();p=Parent();p.CaptureParentThreads(1);
        Refuse(()=>p.SealParentThreads(),"Early seal accepted");Closed(p);
        passed.Add("finite ordered checkpoints and incomplete sealing refuse");

        foreach(string kind in new[]{"process_birth","process_ended"}) {
            UskPublisherPausedWorkerModel.Reset();p=Parent();UskPublisherPausedWorkerModel.Control(kind,0,999);
            Refuse(()=>p.CaptureParentThreads(1),"Original process binding changed");Closed(p);
        }
        passed.Add("original process birth and liveness remain required");

        UskPublisherPausedWorkerModel.Reset();p=Parent();p.CaptureParentThreads(1);p.CaptureParentThreads(2);p.CaptureParentThreads(3);p.SealParentThreads();
        Refuse(()=>p.CaptureParentThreads(1),"Sealed acquisition reopened");Closed(p);
        passed.Add("sealed acquisition cannot reopen");

        foreach(string kind in new[]{"resume","close"}) {
            UskPublisherPausedWorkerModel.Reset();p=Parent();UskPublisherPausedWorkerModel.Add(12,1200,0);p.CaptureParentThreads(1);
            UskPublisherPausedWorkerModel.Control(kind,12,0);
            bool unknown=false;try {p.Dispose();} catch(Exception){unknown=true;}
            Check(unknown && UskPublisherPausedWorkerModel.Outstanding==0 &&
                UskPublisherPausedWorkerModel.Resumes==2,"Unknown cleanup stopped remaining attempts");
        }
        passed.Add("unknown restoration and closure attempt all retained handles");

        UskPublisherPausedWorkerModel.Reset();
        p=new UskPublisherPausedWorkerModel(10,700,"original.exe");
        p.RequirePaused();UskPublisherPausedWorkerModel.Add(12,1200,0);
        Refuse(()=>p.RequirePaused(),"Legacy child pause admitted a new thread");
        Check(!p.ParentAcquisitionEnabled && UskPublisherPausedWorkerModel.Suspends==1,"Legacy behavior changed");Closed(p);
        passed.Add("three-argument child path retains strict original behavior");
        return passed.ToArray();
    }
}
'''

SCRIPT = r'''
param([string]$ModelFile)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($ModelFile))
ConvertTo-Json -InputObject @([PauseAcquisitionControls]::Run()) -Compress
'''

COMPLETION_SCRIPT = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
# These role controls expose no handles, P/Invoke, SCM, VHD or process actors.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
public sealed class PauseCompletionControl {
    public bool ParentAcquisitionEnabled,Live=true;
    public uint Id; public ulong Birth;
    public static readonly List<string> Events=new List<string>();
    public Dictionary<string,object> ParentAcquisitionIdentity() {
        return new Dictionary<string,object>{{"process_id",Id},{"process_creation_file_time",Birth.ToString()},
            {"acquisition_ready",false}};
    }
    public Dictionary<string,object> Observation() {
        Events.Add("child_observation");
        return new Dictionary<string,object>{{"process_id",Id},{"process_creation_file_time",Birth.ToString()},
            {"identity_live_while_paused",Live}};
    }
    public void CaptureParentThreads(int checkpoint) {
        if(checkpoint!=3)throw new Exception("Unexpected capture checkpoint");
        Events.Add("capture3");
    }
    public void SealParentThreads() {Events.Add("seal");}
    public void RequirePaused() {Events.Add(ParentAcquisitionEnabled?"parent_strict":"child_strict");}
}
public sealed class PairCompletionControl {
    public uint Parent=10,Child=20; public ulong ParentBirth=700,ChildBirth=800; public bool Live=true;
    public Dictionary<string,object> ObserveOriginalLivePair() {
        PauseCompletionControl.Events.Add("original_pair");
        return new Dictionary<string,object>{{"parent_process_id",Parent},{"effect_process_id",Child},
            {"parent_process_birth",ParentBirth.ToString("x16")},{"effect_process_birth",ChildBirth.ToString("x16")},
            {"both_live",Live}};
    }
}
'@
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_active_worker.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actual custody source syntax differs'}
$completion=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq 'Complete-OwnedPublisherParentPause'
},$true))
if($completion.Count -ne 1){throw 'Actual completion function is ambiguous'}
$definition=$completion[0].Extent.Text.Replace('UskPublisherPausedWorker','PauseCompletionControl').
    Replace('UskOwnedEffectChildObserver','PairCompletionControl')
Invoke-Expression $definition
$results=@()
foreach($case in @('valid','parent_id','parent_birth','child_id','child_birth','pair_ended','child_not_paused',
    'parent_mode','child_mode','same_custody')) {
    [PauseCompletionControl]::Events.Clear()
    $parent=[PauseCompletionControl]::new();$parent.Id=10;$parent.Birth=700;$parent.ParentAcquisitionEnabled=$true
    $child=[PauseCompletionControl]::new();$child.Id=20;$child.Birth=800
    $pair=[PairCompletionControl]::new()
    switch($case) {
        'parent_id' {$parent.Id=99};'parent_birth' {$parent.Birth=701}
        'child_id' {$child.Id=99};'child_birth' {$child.Birth=801}
        'pair_ended' {$pair.Live=$false};'child_not_paused' {$child.Live=$false}
        'parent_mode' {$parent.ParentAcquisitionEnabled=$false}
        'child_mode' {$child.ParentAcquisitionEnabled=$true}
        'same_custody' {$child=$parent}
    }
    $refused=$false
    try {Complete-OwnedPublisherParentPause -ParentPause $parent -ChildPause $child -EffectPair $pair}
    catch {$refused=$true}
    $results+=@{case=$case;refused=$refused;events=@([PauseCompletionControl]::Events)}
}
ConvertTo-Json -InputObject @($results) -Depth 4 -Compress
'''


@unittest.skipUnless(POWERSHELL, 'PowerShell unavailable on this platform')
class PublisherParentPauseAcquisitionTests(unittest.TestCase):
    def test_actual_fixture_type_compiles_in_each_available_powershell(self):
        # Compile the unmodified real P/Invoke type, invoking no constructor,
        # so the actual legacy fixture compiler is covered as well as pwsh.
        script_text = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'tests/windows_publisher_active_worker.ps1')
Initialize-OwnedPublisherWorkerPause
Initialize-OwnedPublisherWorkerPause
if([UskPublisherPausedWorker].GetConstructors().Count -ne 2) {
    throw 'Actual inert fixture constructors differ'
}
'compiled; no native constructor or actor invoked'
'''
        shells = list(dict.fromkeys(filter(None, (
            shutil.which('powershell'), shutil.which('pwsh')))))
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'inert-compile.ps1'
            script.write_text(script_text, encoding='utf-8')
            for shell in shells:
                with self.subTest(shell=shell):
                    result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                        '-File', str(script), '-Root', str(ROOT)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('no native constructor or actor invoked', result.stdout)

    def test_actual_algorithm_custody_and_seal_with_controlled_native_calls(self):
        text = (ROOT / 'tests/windows_publisher_active_worker.ps1').read_text(encoding='utf-8')
        matches = re.findall(r"Add-Type -TypeDefinition @'\n(.*?)\n'@", text, re.S)
        self.assertEqual(len(matches), 1)
        source = matches[0]
        declaration = re.compile(
            r'^[ \t]*\[DllImport\([^\n]+\)\] static extern [^\n]+? (\w+)\([^\n]*;',
            re.M)
        self.assertEqual(set(declaration.findall(source)), NATIVE_NAMES)
        self.assertEqual(len(declaration.findall(source)), len(NATIVE_NAMES))
        source = declaration.sub('', source)
        source = source.replace('Marshal.GetLastWin32Error()', 'lastError')
        source = source.replace('UskPublisherPausedWorker', 'UskPublisherPausedWorkerModel')
        self.assertTrue(source.endswith('\n}'))
        source = source[:-2] + NATIVE_CONTROLS + '\n}\n' + ALGORITHM_CONTROLS
        self.assertNotIn('DllImport', source)
        self.assertNotIn(' extern ', source)
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'controls.ps1'
            model = Path(directory) / 'model.cs'
            script.write_text(SCRIPT, encoding='utf-8')
            model.write_text(source, encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), '-ModelFile', str(model)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        cases = json.loads(result.stdout)
        self.assertEqual(len(cases), 14)
        self.assertEqual(len(set(cases)), 14)

    def test_actual_completion_requires_original_pair_before_sealing(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'completion.ps1'
            script.write_text(COMPLETION_SCRIPT, encoding='utf-8')
            result = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', str(script), '-Root', str(ROOT)],
                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 10)
        for row in rows:
            self.assertEqual(row['refused'], row['case'] != 'valid', row)
            if row['case'] == 'valid':
                self.assertEqual(row['events'], [
                    'capture3', 'child_observation', 'original_pair', 'child_strict',
                    'seal', 'parent_strict', 'child_strict', 'original_pair'])
            else:
                self.assertNotIn('seal', row['events'], row)


if __name__ == '__main__':
    unittest.main()
