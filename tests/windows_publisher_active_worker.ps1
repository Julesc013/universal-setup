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
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,System.Text.StringBuilder image,ref uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool Thread32First(IntPtr snapshot,ref ThreadEntry entry);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool Thread32Next(IntPtr snapshot,ref ThreadEntry entry);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    sealed class HeldThread { public uint id,prior; public IntPtr handle; public bool paused; }
    IntPtr process;
    readonly uint processId;
    readonly ulong creationTime;
    readonly List<HeldThread> threads=new List<HeldThread>();
    bool closed;
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
        [Parameter(Mandatory=$true)][string]$ExpectedImageSha256)
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
    return [UskPublisherPausedWorker]::new([uint32]$Process.Id,[uint64]$creation,$privateImage)
}
