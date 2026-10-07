# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Defines checked custody for an already launched, owned hosted fixture worker.
# Importing this file does not pause or launch a process.
# Compile the inert custody type before a live observation window.
# This initializer creates no process, handle, pause or native actor.
function Initialize-OwnedPublisherWorkerPause {
    if(-not ('UskPublisherPausedWorker' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
public sealed class UskPublisherPausedWorker : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct Times { public uint low,high; }
    [StructLayout(LayoutKind.Sequential)] struct ThreadEntry {
        public uint size,usage,id,owner; public int priority,delta; public uint flags;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint id);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint id);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessIdOfThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out Times birth,out Times exit,out Times kernel,out Times user);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetThreadTimes(IntPtr thread,out Times birth,out Times exit,out Times kernel,out Times user);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,System.Text.StringBuilder image,ref uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool Thread32First(IntPtr snapshot,ref ThreadEntry entry);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool Thread32Next(IntPtr snapshot,ref ThreadEntry entry);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    sealed class HeldThread { public uint id,prior; public IntPtr handle; public bool paused; public ulong birth; }
    IntPtr process;
    readonly uint processId;
    readonly ulong creationTime;
    readonly List<HeldThread> threads=new List<HeldThread>();
    bool closed;
    bool parentAcquisition,parentSealed,acquisitionFailed;
    int parentCaptures;
    static void Require(bool condition,string message) { if(!condition) throw new InvalidOperationException(message); }
    public UskPublisherPausedWorker(uint id,ulong birth,string expectedImage) {
        processId=id;creationTime=birth;
        try {
            process=OpenProcess(0x101000,false,id);
            Require(process!=IntPtr.Zero,"Owned pause process query failed");
            RequireBoundLiveWorker();
            uint length=32768;var image=new System.Text.StringBuilder((int)length);
            Require(QueryFullProcessImageName(process,0,image,ref length) &&
                String.Equals(image.ToString(),expectedImage,StringComparison.OrdinalIgnoreCase),
                "Owned pause process image differs");
            foreach(uint threadId in ObserveThreads()) {
                RequireBoundLiveWorker();
                IntPtr handle=OpenThread(0x100802,false,threadId);
                Require(handle!=IntPtr.Zero,"Owned pause thread query failed");
                var held=new HeldThread {id=threadId,handle=handle};threads.Add(held);
                Require(GetProcessIdOfThread(handle)==processId,"Owned pause thread owner differs");
                uint prior=SuspendThread(handle);
                Require(prior!=0xffffffff,"Owned pause thread suspension failed");
                held.prior=prior;held.paused=true;
                Require(prior==0,"Owned pause found a preexisting suspension");
            }
            Require(threads.Count>0,"Owned pause found no worker threads");
            RequirePaused();
        } catch { Dispose();throw; }
    }
    // Only the original SCM fixture parent opts in. The three-argument child
    // and ordinary pause retain their original immediate strict behavior.
    public UskPublisherPausedWorker(uint id,ulong birth,string expectedImage,bool acquireParent)
        : this(id,birth,expectedImage) {
        if(!acquireParent)return;
        parentAcquisition=true;
        try {
            foreach(var held in threads) held.birth=ReadLiveThreadBirth(held);
            RequireHeldParentThreads();
        } catch { acquisitionFailed=true;Dispose();throw; }
    }
    public bool ParentAcquisitionEnabled { get { return parentAcquisition; } }
    ulong ReadLiveThreadBirth(HeldThread held) {
        RequireBoundLiveWorker();
        Times birth=new Times(),exit,kernel,user;
        Require(held.handle!=IntPtr.Zero && GetProcessIdOfThread(held.handle)==processId &&
            WaitForSingleObject(held.handle,0)==258 &&
            GetThreadTimes(held.handle,out birth,out exit,out kernel,out user),
            "Owned parent thread identity ended or query failed");
        // The exit-time output is undefined for a live thread; liveness comes
        // from the original synchronized handle, never that output field.
        ulong value=((ulong)birth.high<<32)|birth.low;
        Require(value!=0,"Owned parent thread birth is unavailable");
        return value;
    }
    void RequireHeldParentThreads() {
        RequireBoundLiveWorker();
        Require(threads.Count>0 && threads.Count<=128,"Owned parent retained thread set exceeds bound");
        var ids=new HashSet<uint>();
        foreach(var held in threads) {
            Require(ids.Add(held.id) && held.paused && held.prior==0 && held.birth!=0 &&
                ReadLiveThreadBirth(held)==held.birth,"Owned parent retained thread identity differs");
        }
    }
    void RequireAcquiringParent() {
        Require(parentAcquisition && !parentSealed && !acquisitionFailed && !closed,
            "Owned parent acquisition is unavailable or already sealed");
        RequireHeldParentThreads();
    }
    void RequireParentMembership(List<uint> observed,bool exact) {
        RequireHeldParentThreads();
        foreach(var held in threads)
            Require(observed.Contains(held.id),"Owned parent lost a retained thread");
        if(exact)Require(observed.Count==threads.Count,"Owned worker acquired an unpaused thread");
    }
    public Dictionary<string,object> ParentAcquisitionIdentity() {
        try {
            RequireAcquiringParent();
            // This binding is explicitly not an observation of a ready pause.
            return new Dictionary<string,object> {{"process_id",processId},
                {"process_creation_file_time",creationTime.ToString()}, {"acquisition_ready",false}};
        } catch { acquisitionFailed=true;throw; }
    }
    public void CaptureParentThreads(int checkpoint) {
        try {
            RequireAcquiringParent();
            Require(checkpoint>=1 && checkpoint<=3 && checkpoint==parentCaptures+1,
                "Owned parent acquisition checkpoint differs");
            var observed=ObserveThreads();RequireParentMembership(observed,false);
            foreach(uint id in observed) {
                if(threads.Exists(retained=>retained.id==id))continue;
                Require(threads.Count<128,"Owned parent cumulative thread custody exceeds bound");
                RequireBoundLiveWorker();
                // Allocate and retain custody before opening a raw handle.
                // An allocation failure must not leave an untracked handle.
                var held=new HeldThread {id=id};threads.Add(held);
                held.handle=OpenThread(0x100802,false,id);
                Require(held.handle!=IntPtr.Zero,"Owned parent new thread query failed");
                held.birth=ReadLiveThreadBirth(held);
                uint prior=SuspendThread(held.handle);
                Require(prior!=0xffffffff,"Owned parent new thread suspension failed");
                held.prior=prior;held.paused=true;
                Require(prior==0,"Owned parent new thread was already suspended");
            }
            RequireParentMembership(observed,true);parentCaptures++;
        } catch { acquisitionFailed=true;throw; }
    }
    public void SealParentThreads() {
        try {
            RequireAcquiringParent();
            Require(parentCaptures==3,"Owned parent acquisition is incomplete");
            // A separate final census admits nothing. Later observations never
            // capture, refresh original handles or reopen this acquisition.
            RequireParentMembership(ObserveThreads(),true);parentSealed=true;
        } catch { acquisitionFailed=true;throw; }
    }
    void RequireBoundLiveWorker() {
        Times birth,exit,kernel,user;
        Require(!closed && process!=IntPtr.Zero && WaitForSingleObject(process,0)==258 &&
            GetProcessTimes(process,out birth,out exit,out kernel,out user) &&
            (((ulong)birth.high<<32)|birth.low)==creationTime,"Owned pause worker identity ended or changed");
    }
    List<uint> ObserveThreads() {
        IntPtr snapshot=CreateToolhelp32Snapshot(4,0);
        Require(snapshot!=new IntPtr(-1),"Owned pause thread snapshot failed");
        try {
            var result=new List<uint>();var entry=new ThreadEntry();entry.size=(uint)Marshal.SizeOf(typeof(ThreadEntry));
            bool present=Thread32First(snapshot,ref entry);int rows=0;
            while(present) {
                Require(++rows<=16384,"Owned pause thread observation exceeds bound");
                if(entry.owner==processId) {
                    Require(result.Count<128 && !result.Contains(entry.id),"Owned pause worker thread set exceeds bound");
                    result.Add(entry.id);
                }
                entry.size=(uint)Marshal.SizeOf(typeof(ThreadEntry));present=Thread32Next(snapshot,ref entry);
            }
            Require(Marshal.GetLastWin32Error()==18,"Owned pause thread enumeration failed");
            return result;
        } finally { Require(CloseHandle(snapshot),"Owned pause snapshot closure failed"); }
    }
    public void RequirePaused() {
        RequireBoundLiveWorker();
        if(parentAcquisition) {
            Require(parentSealed && !acquisitionFailed,"Owned parent pause is not sealed");
            RequireParentMembership(ObserveThreads(),true);return;
        }
        var held=new HashSet<uint>();foreach(var thread in threads) if(thread.paused) held.Add(thread.id);
        foreach(uint id in ObserveThreads()) Require(held.Contains(id),"Owned worker acquired an unpaused thread");
    }
    public Dictionary<string,object> Observation() {
        RequirePaused();
        return new Dictionary<string,object> {{"process_id",processId},
            {"process_creation_file_time",creationTime.ToString()}, {"paused_threads",threads.Count},
            {"identity_live_while_paused",true}};
    }
    public void Dispose() {
        if(closed)return;
        Exception failure=null;
        for(int index=threads.Count-1;index>=0;index--) {
            var held=threads[index];
            if(held.paused) {
                uint prior=ResumeThread(held.handle);
                if(prior!=held.prior+1 && failure==null) failure=new InvalidOperationException("Owned worker thread restoration is unconfirmed");
                held.paused=false;
            }
            if(held.handle!=IntPtr.Zero) {
                if(!CloseHandle(held.handle) && failure==null) failure=new Win32Exception(Marshal.GetLastWin32Error(),"Owned worker thread closure failed");
                held.handle=IntPtr.Zero;
            }
        }
        if(process!=IntPtr.Zero) {
            if(!CloseHandle(process) && failure==null) failure=new Win32Exception(Marshal.GetLastWin32Error(),"Owned worker query closure failed");
            process=IntPtr.Zero;
        }
        closed=true;if(failure!=null)throw failure;
    }
}
'@
    }
}
function Start-OwnedPublisherWorkerPause {
    param([Parameter(Mandatory=$true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory=$true)][string]$Service,
        [Parameter(Mandatory=$true)][string]$VhdPath,
        [Parameter(Mandatory=$true)][string]$VolumeRoot,
        [Parameter(Mandatory=$true)][string]$ExpectedServiceCommand,
        [Parameter(Mandatory=$true)][string]$ExpectedImagePath,
        [Parameter(Mandatory=$true)][string]$ExpectedImageSha256,
        [switch]$AcquireParentThreads)
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
        throw 'Owned worker pause requires the hosted SYSTEM fixture context'
    }
    $lab=[IO.Path]::GetFullPath((Split-Path -Parent $VhdPath))
    $runner=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
    if(-not $lab.StartsWith($runner,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or
        $Service -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or
        $ExpectedImageSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Owned worker pause target differs'
    }
    $image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
    $disk=$image|Get-Disk -ErrorAction Stop
    $parts=@($disk|Get-Partition|Where-Object DriveLetter)
    if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $parts.Count -ne 1) {
        throw 'Owned worker pause target is not a disposable mounted volume'
    }
    $volume=$parts[0]|Get-Volume
    if($volume.UniqueId -cne $VolumeRoot -or $volume.FileSystem -cne 'NTFS') {
        throw 'Owned worker pause volume identity differs'
    }
    $privateImage=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$Service+'.exe')
    if(-not [string]::Equals([IO.Path]::GetFullPath($ExpectedImagePath),$privateImage,
        [StringComparison]::OrdinalIgnoreCase) -or
        (Get-FileHash -LiteralPath $privateImage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedImageSha256) {
        throw 'Owned worker pause private executable differs'
    }
    $registration=Get-CimInstance Win32_Service -Filter ("Name='"+$Service+"'") -ErrorAction Stop
    $commandPrefix='"'+$privateImage+'" --service '+$Service+' --no-receipt '+$VolumeRoot+' '
    if(-not $registration -or $registration.State -cne 'Running' -or
        $registration.ProcessId -ne $Process.Id -or $registration.StartName -cne 'LocalSystem' -or
        $registration.PathName -cne $ExpectedServiceCommand -or
        -not $ExpectedServiceCommand.StartsWith($commandPrefix,[StringComparison]::Ordinal)) {
        throw 'Owned worker pause is not the retained running fixture service'
    }
    $null=$Process.Handle
    if($Process.HasExited){throw 'Owned worker exited before pause'}
    $creation=$Process.StartTime.ToUniversalTime().ToFileTimeUtc()
    Initialize-OwnedPublisherWorkerPause
    if($AcquireParentThreads) {
        return [UskPublisherPausedWorker]::new([uint32]$Process.Id,[uint64]$creation,$privateImage,$true)
    }
    return [UskPublisherPausedWorker]::new([uint32]$Process.Id,[uint64]$creation,$privateImage)
}

function Start-OwnedPublisherEffectChildPause {
    param([Parameter(Mandatory=$true)][Diagnostics.Process]$ParentWorker,
        [Parameter(Mandatory=$true)]$ParentPause,[Parameter(Mandatory=$true)]$EffectPair,
        [Parameter(Mandatory=$true)][string]$Service,[Parameter(Mandatory=$true)][string]$VhdPath,
        [Parameter(Mandatory=$true)][string]$VolumeRoot,[Parameter(Mandatory=$true)][string]$ExpectedServiceCommand,
        [Parameter(Mandatory=$true)][string]$ExpectedImagePath,[Parameter(Mandatory=$true)][string]$ExpectedImageSha256)
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
        throw 'Owned child pause requires the hosted SYSTEM fixture context'
    }
    if($ParentPause -isnot [UskPublisherPausedWorker] -or $EffectPair -isnot [UskOwnedEffectChildObserver]) {
        throw 'Owned child pause lacks the held original parent pause/query pair'
    }
    if($ParentPause.ParentAcquisitionEnabled) {
        $ParentPause.CaptureParentThreads(1)
        $parentObservation=$ParentPause.ParentAcquisitionIdentity()
    } else {
        $ParentPause.RequirePaused();$parentObservation=$ParentPause.Observation()
    }
    $pair=$EffectPair.ObserveOriginalLivePair()
    if($pair.parent_process_id -ne $ParentWorker.Id -or
        $pair.parent_process_birth -cne $ParentWorker.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16') -or
        $parentObservation.process_id -ne $ParentWorker.Id -or
        $parentObservation.process_creation_file_time -cne $ParentWorker.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -or
        $pair.effect_process_id -ne $EffectPair.ChildProcessId -or $pair.effect_process_birth -cne $EffectPair.ChildProcessBirth -or
        $pair.effect_process_id -eq $ParentWorker.Id -or $pair.effect_process_id -eq $PID -or
        $pair.effect_process_birth -cnotmatch '^[0-9a-f]{16}$' -or -not $pair.both_live) {
        throw 'Owned child pause original native pair differs'
    }
    $lab=[IO.Path]::GetFullPath((Split-Path -Parent $VhdPath))
    $runner=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
    if(-not $lab.StartsWith($runner,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or $Service -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or
        $ExpectedImageSha256 -cnotmatch '^[0-9a-f]{64}$') {throw 'Owned child pause target differs'}
    $image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop;$disk=$image|Get-Disk -ErrorAction Stop
    $parts=@($disk|Get-Partition|Where-Object DriveLetter)
    if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $parts.Count -ne 1) {
        throw 'Owned child pause target is not a disposable mounted volume'
    }
    $volume=$parts[0]|Get-Volume
    if($volume.UniqueId -cne $VolumeRoot -or $volume.FileSystem -cne 'NTFS') {throw 'Owned child pause volume identity differs'}
    $privateImage=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$Service+'.exe')
    if(-not [string]::Equals([IO.Path]::GetFullPath($ExpectedImagePath),$privateImage,[StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($pair.original_image_path,$privateImage,[StringComparison]::OrdinalIgnoreCase) -or
        (Get-FileHash -LiteralPath $privateImage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedImageSha256) {
        throw 'Owned child pause private executable differs'
    }
    $registration=Get-CimInstance Win32_Service -Filter ("Name='"+$Service+"'") -ErrorAction Stop
    if(-not $registration -or $registration.State -cne 'Running' -or $registration.ProcessId -ne $ParentWorker.Id -or
        $registration.StartName -cne 'LocalSystem' -or $registration.PathName -cne $ExpectedServiceCommand -or
        -not $ExpectedServiceCommand.StartsWith(('"'+$privateImage+'" --service '+$Service+' --no-receipt '+$VolumeRoot+' '),
            [StringComparison]::Ordinal)) {throw 'Owned child pause original private SCM registration differs'}
    if($ParentPause.ParentAcquisitionEnabled) {$ParentPause.CaptureParentThreads(2)}
    else {$ParentPause.RequirePaused()}
    $null=$EffectPair.ObserveOriginalLivePair()
    # Separate suspend custody; the original child observer remains query-only.
    # This sampled pause does not imply that outstanding kernel I/O has retired.
    return [UskPublisherPausedWorker]::new([uint32]$pair.effect_process_id,
        [Convert]::ToUInt64($pair.effect_process_birth,16),$privateImage)
}

function Start-OwnedPublisherOriginalPairPause {
    param([Parameter(Mandatory=$true)][Diagnostics.Process]$ParentWorker,
        [Parameter(Mandatory=$true)]$EffectPair,
        [Parameter(Mandatory=$true)][string]$Service,[Parameter(Mandatory=$true)][string]$VhdPath,
        [Parameter(Mandatory=$true)][string]$VolumeRoot,[Parameter(Mandatory=$true)][string]$ExpectedServiceCommand,
        [Parameter(Mandatory=$true)][string]$ExpectedImagePath,[Parameter(Mandatory=$true)][string]$ExpectedImageSha256,
        [Parameter(Mandatory=$true)][ref]$ParentPause,[Parameter(Mandatory=$true)][ref]$ChildPause,
        [Parameter(Mandatory=$true)][ref]$ParentPauseAttempted,[Parameter(Mandatory=$true)][ref]$ChildPauseAttempted,
        [Parameter(Mandatory=$true)][ref]$FailureDiagnostic)
    $timer=[Diagnostics.Stopwatch]::StartNew();$phase='host_context'
    try {
        if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
            throw 'Owned original pair pause requires the hosted SYSTEM fixture context'
        }
        if($EffectPair -isnot [UskOwnedEffectChildObserver] -or $ParentPause.Value -or $ChildPause.Value -or
            $ParentPauseAttempted.Value -or $ChildPauseAttempted.Value) {
            throw 'Owned original pair pause lacks untouched separate native custody'
        }
        $phase='original_pair_before_target'
        $pair=$EffectPair.ObserveOriginalLivePair()
        $creation=$ParentWorker.StartTime.ToUniversalTime().ToFileTimeUtc()
        if($ParentWorker.HasExited -or $pair.parent_process_id -ne $ParentWorker.Id -or
            $pair.parent_process_birth -cne $creation.ToString('x16') -or
            $pair.effect_process_id -ne $EffectPair.ChildProcessId -or
            $pair.effect_process_birth -cne $EffectPair.ChildProcessBirth -or
            $pair.effect_process_id -eq $ParentWorker.Id -or $pair.effect_process_id -eq $PID -or
            $pair.effect_process_birth -cnotmatch '^[0-9a-f]{16}$' -or -not $pair.both_live) {
            throw 'Owned original pair pause native process instances differ'
        }
        # Check the complete parent/child owned-target predicate union while
        # both processes can still service their existing bounded transports.
        # No serialized readiness object can bypass any of these checks.
        $phase='owned_target'
        $lab=[IO.Path]::GetFullPath((Split-Path -Parent $VhdPath))
        $runner=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
        if(-not $lab.StartsWith($runner,[StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or
            $Service -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or
            $ExpectedImageSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Owned original pair pause target differs'
        }
        $image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
        $disk=$image|Get-Disk -ErrorAction Stop
        $parts=@($disk|Get-Partition|Where-Object DriveLetter)
        if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $parts.Count -ne 1) {
            throw 'Owned original pair pause target is not a disposable mounted volume'
        }
        $volume=$parts[0]|Get-Volume
        if($volume.UniqueId -cne $VolumeRoot -or $volume.FileSystem -cne 'NTFS') {
            throw 'Owned original pair pause volume identity differs'
        }
        $phase='private_image_and_scm'
        $privateImage=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$Service+'.exe')
        if(-not [string]::Equals([IO.Path]::GetFullPath($ExpectedImagePath),$privateImage,[StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($pair.original_image_path,$privateImage,[StringComparison]::OrdinalIgnoreCase) -or
            (Get-FileHash -LiteralPath $privateImage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedImageSha256) {
            throw 'Owned original pair pause private executable differs'
        }
        $registration=Get-CimInstance Win32_Service -Filter ("Name='"+$Service+"'") -ErrorAction Stop
        $commandPrefix='"'+$privateImage+'" --service '+$Service+' --no-receipt '+$VolumeRoot+' '
        if(-not $registration -or $registration.State -cne 'Running' -or
            $registration.ProcessId -ne $ParentWorker.Id -or $registration.StartName -cne 'LocalSystem' -or
            $registration.PathName -cne $ExpectedServiceCommand -or
            -not $ExpectedServiceCommand.StartsWith($commandPrefix,[StringComparison]::Ordinal)) {
            throw 'Owned original pair pause is not the retained running fixture service'
        }
        Initialize-OwnedPublisherWorkerPause
        $phase='original_pair_before_child'
        $pair=$EffectPair.ObserveOriginalLivePair()
        # Pause the effect child first, leaving its original broker running.
        # Retain returned custody before attempting the parent, so every later
        # failure reaches checked restoration of the actual original child.
        $phase='child_constructor';$ChildPauseAttempted.Value=$true
        $ChildPause.Value=[UskPublisherPausedWorker]::new([uint32]$pair.effect_process_id,
            [Convert]::ToUInt64($pair.effect_process_birth,16),$privateImage)
        $script:activeRetainedChildPause=$ChildPause.Value
        $phase='child_paused_before_parent'
        $ChildPause.Value.RequirePaused();$null=$EffectPair.ObserveOriginalLivePair()
        $phase='parent_constructor';$ParentPauseAttempted.Value=$true
        $ParentPause.Value=[UskPublisherPausedWorker]::new([uint32]$ParentWorker.Id,[uint64]$creation,$privateImage,$true)
        $phase='parent_capture1'
        $ParentPause.Value.CaptureParentThreads(1)
        $parent=$ParentPause.Value.ParentAcquisitionIdentity()
        $pair=$EffectPair.ObserveOriginalLivePair()
        if($parent.process_id -ne $pair.parent_process_id -or
            ([Convert]::ToUInt64($parent.process_creation_file_time)).ToString('x16') -cne $pair.parent_process_birth) {
            throw 'Owned original pair pause parent acquisition identity differs'
        }
        $phase='child_paused_after_parent'
        $ChildPause.Value.RequirePaused();$null=$EffectPair.ObserveOriginalLivePair()
        $phase='parent_capture2'
        $ParentPause.Value.CaptureParentThreads(2)
        # The caller still performs capture3, a separate no-admission seal,
        # strict native pair checks and all unchanged whole-state frame checks.
        # Suspension does not prove retired kernel I/O or continuous exclusion.
    } catch {
        $originalFailure=$_
        try {
            $FailureDiagnostic.Value=[ordered]@{scope='original_pair_pause_acquisition_failure';
                qualification_granted=$false;atomic_snapshot=$false;phase=$phase;
                elapsed_milliseconds=$timer.ElapsedMilliseconds;
                parent_pause_attempted=[bool]$ParentPauseAttempted.Value;child_pause_attempted=[bool]$ChildPauseAttempted.Value;
                parent_custody_returned=[bool]$ParentPause.Value;child_custody_returned=[bool]$ChildPause.Value;
                original_pair=$null;pair_capture_status='unavailable'}
            if($EffectPair -is [UskOwnedEffectChildObserver]) {
                $FailureDiagnostic.Value.original_pair=$EffectPair.ObserveOriginalPairFailure()
                $FailureDiagnostic.Value.pair_capture_status='original_handles_sampled_after_failure'
            }
        } catch {
            try {if($FailureDiagnostic.Value){$FailureDiagnostic.Value.pair_capture_status='capture_failed'}}
            catch {} # Optional later samples cannot replace the primary failure.
        }
        throw $originalFailure
    } finally {$timer.Stop()}
}

function Complete-OwnedPublisherParentPause {
    param([Parameter(Mandatory=$true)]$ParentPause,[Parameter(Mandatory=$true)]$ChildPause,
        [Parameter(Mandatory=$true)]$EffectPair)
    if($ParentPause -isnot [UskPublisherPausedWorker] -or $ChildPause -isnot [UskPublisherPausedWorker] -or
        $EffectPair -isnot [UskOwnedEffectChildObserver] -or -not $ParentPause.ParentAcquisitionEnabled -or
        $ChildPause.ParentAcquisitionEnabled -or [object]::ReferenceEquals($ParentPause,$ChildPause)) {
        throw 'Owned parent completion lacks separate original parent/child custody'
    }
    $ParentPause.CaptureParentThreads(3)
    $parent=$ParentPause.ParentAcquisitionIdentity();$child=$ChildPause.Observation()
    $pair=$EffectPair.ObserveOriginalLivePair()
    if(-not $pair.both_live -or -not $child.identity_live_while_paused -or
        $parent.process_id -ne $pair.parent_process_id -or $child.process_id -ne $pair.effect_process_id -or
        $parent.process_id -eq $child.process_id -or
        ([Convert]::ToUInt64($parent.process_creation_file_time)).ToString('x16') -cne $pair.parent_process_birth -or
        ([Convert]::ToUInt64($child.process_creation_file_time)).ToString('x16') -cne $pair.effect_process_birth) {
        throw 'Owned parent completion original native pair differs'
    }
    $ChildPause.RequirePaused()
    $ParentPause.SealParentThreads()
    $ParentPause.RequirePaused();$ChildPause.RequirePaused();$null=$EffectPair.ObserveOriginalLivePair()
}
