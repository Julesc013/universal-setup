# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Hosted probe support only; compile both native observation classes together.
# Loading the helper creates no observer or native actor.
if (-not ('UskOwnedEffectChildObserver' -as [type])) {
    Add-Type -TypeDefinition @'
// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// Read-only child observation beside the already validated, held SCM owner.
// The private numeric argv values are checked as text, never adopted as handles.
public sealed class UskOwnedEffectChildObserver : IDisposable {
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessBasicInformation {
        public IntPtr ExitStatus, PebBaseAddress, AffinityMask, BasePriority;
        public UIntPtr UniqueProcessId, InheritedFromUniqueProcessId;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ObjectBasicInformation {
        public uint Attributes, GrantedAccess, HandleCount, PointerCount;
        public uint Reserved0, Reserved1, Reserved2, Reserved3, Reserved4;
        public uint Reserved5, Reserved6, Reserved7, Reserved8, Reserved9;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint GetProcessId(IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(IntPtr process, out long birth, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetHandleInformation(IntPtr handle, out uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr process, int informationClass,
        out ProcessBasicInformation information, uint informationBytes, out uint returnedBytes);
    [DllImport("ntdll.dll")]
    static extern int NtQueryObject(IntPtr handle, int informationClass,
        out ObjectBasicInformation information, uint informationBytes, out uint returnedBytes);

    readonly Process parentOwner;
    readonly IntPtr parentHandle;
    readonly uint parentId, childId;
    readonly long parentBirth, childBirth;
    readonly uint childGrantedAccess;
    readonly string originalImage;
    IntPtr childHandle;
    bool closeAttempted, ended;

    static long Birth(IntPtr process) {
        long birth, exit, kernel, user;
        if(!GetProcessTimes(process,out birth,out exit,out kernel,out user) || birth<=0)
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Owned native process birth unavailable");
        return birth;
    }
    static string Image(IntPtr process) {
        var image=new StringBuilder(32768);
        uint size=32768;
        if(!QueryFullProcessImageName(process,0,image,ref size) || size==0 || size>=32768)
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Owned native process image unavailable");
        return image.ToString();
    }
    static void RequireLive(IntPtr handle,uint processId,long birth) {
        if(handle==IntPtr.Zero || GetProcessId(handle)!=processId || Birth(handle)!=birth ||
            WaitForSingleObject(handle,0)!=258)
            throw new InvalidOperationException("Owned original native process PID/birth/liveness differs");
    }
    // The actual native launcher emits exactly this closed spelling. No general
    // shell/parser expansion or transport-handle adoption is needed here.
    static bool PrivateCommand(string command,string image) {
        string prefix="\""+image+"\" --usk-private-effect-worker-transport-v1 ";
        if(command==null || command.Length>32768 || !command.StartsWith(prefix,StringComparison.Ordinal)) return false;
        string[] values=command.Substring(prefix.Length).Split(' ');
        if(values.Length!=3) return false;
        var seen=new HashSet<ulong>();
        foreach(string value in values) {
            ulong number;
            if(value.Length==0 || value.Length>20 || value[0]=='0') return false;
            foreach(char ch in value) if(ch<'0' || ch>'9') return false;
            if(!UInt64.TryParse(value,out number) || number==0 || !seen.Add(number)) return false;
        }
        return true;
    }
    public UskOwnedEffectChildObserver(Process actualParent,uint actualParentId,long actualParentBirth,
        uint observedChildId,long observedChildUtcTicks,string expectedImage,string observedPrivateCommand) {
        if(!Environment.Is64BitProcess || actualParent==null || actualParentId==0 || observedChildId==0 ||
            actualParentBirth<=0 || actualParentId==observedChildId || actualParentId==(uint)Process.GetCurrentProcess().Id ||
            observedChildId==(uint)Process.GetCurrentProcess().Id || String.IsNullOrEmpty(expectedImage) ||
            !PrivateCommand(observedPrivateCommand,expectedImage))
            throw new InvalidOperationException("Owned native pair requires distinct checked x64 process instances/private command");
        parentOwner=actualParent;
        parentHandle=actualParent.Handle;
        parentId=actualParentId;parentBirth=actualParentBirth;
        childId=observedChildId;originalImage=expectedImage;
        RequireLive(parentHandle,parentId,parentBirth);
        // QUERY_INFORMATION | QUERY_LIMITED_INFORMATION | SYNCHRONIZE.
        // This original observer cannot terminate the child.
        childHandle=OpenProcess(0x00101400,false,childId);
        if(childHandle==IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Owned native child observer unavailable");
        try {
            // Retain the exact native FILETIME; CIM supplies an independent
            // rounded timestamp comparison, never the exact retained birth.
            childBirth=Birth(childHandle);
            long childTicks=DateTime.FromFileTimeUtc(childBirth).Ticks;
            if(observedChildUtcTicks<=0 || Math.Abs(childTicks-observedChildUtcTicks)>10000)
                throw new InvalidOperationException("Owned child native/CIM birth differs");
            RequireLive(childHandle,childId,childBirth);
            uint flags;
            ProcessBasicInformation basic;
            ObjectBasicInformation objectBasic;
            uint returned;
            if(!GetHandleInformation(childHandle,out flags) || flags!=0 || childBirth<parentBirth ||
                NtQueryInformationProcess(childHandle,0,out basic,48,out returned)!=0 || returned!=48 ||
                NtQueryObject(childHandle,0,out objectBasic,56,out returned)!=0 || returned!=56 ||
                objectBasic.GrantedAccess!=0x00101400 ||
                basic.UniqueProcessId.ToUInt64()!=childId || basic.InheritedFromUniqueProcessId.ToUInt64()!=parentId ||
                !String.Equals(Image(parentHandle),originalImage,StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(Image(childHandle),originalImage,StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Owned child native ancestry/image/observer differs");
            childGrantedAccess=objectBasic.GrantedAccess;
            RequireLive(parentHandle,parentId,parentBirth);
            RequireLive(childHandle,childId,childBirth);
        } catch {
            Dispose();
            throw;
        }
        GC.KeepAlive(parentOwner);
    }
    public uint ChildProcessId { get { return childId; } }
    public string ChildProcessBirth { get { return childBirth.ToString("x16"); } }
    public bool ObserverCloseConfirmed { get { return closeAttempted && childHandle==IntPtr.Zero; } }
    public void RequireOriginalLivePair() {
        if(closeAttempted || ended) throw new InvalidOperationException("Owned native pair is no longer live");
        RequireLive(parentHandle,parentId,parentBirth);
        RequireLive(childHandle,childId,childBirth);
        GC.KeepAlive(parentOwner);
    }
    public Dictionary<string,object> ObserveOriginalLivePair() {
        RequireOriginalLivePair();
        uint flags, returned;
        ProcessBasicInformation basic;
        ObjectBasicInformation objectBasic;
        if(!GetHandleInformation(childHandle,out flags) || flags!=0 ||
            NtQueryInformationProcess(childHandle,0,out basic,48,out returned)!=0 || returned!=48 ||
            basic.UniqueProcessId.ToUInt64()!=childId || basic.InheritedFromUniqueProcessId.ToUInt64()!=parentId ||
            NtQueryObject(childHandle,0,out objectBasic,56,out returned)!=0 || returned!=56 ||
            objectBasic.GrantedAccess!=childGrantedAccess ||
            !String.Equals(Image(parentHandle),originalImage,StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(Image(childHandle),originalImage,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Original live pair native ancestry/image/observer changed");
        RequireOriginalLivePair();
        return new Dictionary<string,object> {
            {"schema","usk.publisher_owned_live_process_pair.v1"},{"scope","held_scm_parent_and_original_live_effect_child"},
            {"parent_process_id",parentId},{"parent_process_birth",parentBirth.ToString("x16")},
            {"effect_process_id",childId},{"effect_process_birth",childBirth.ToString("x16")},
            {"native_parent_process_id",parentId},{"original_image_path",originalImage},{"both_live",true},
            {"child_observer_access",objectBasic.GrantedAccess},{"child_observer_handle_flags",flags}};
    }
    public Dictionary<string,object> TerminateOriginalScmOwner() {
        RequireOriginalLivePair();
        // Kill ONLY the original held SCM owner. Original child end must follow
        // without Kill(true), TerminateProcess(child) or reopening its PID.
        if(!TerminateProcess(parentHandle,1))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Owned held SCM termination failed");
        uint parentWait=WaitForSingleObject(parentHandle,5000);
        uint childWait=WaitForSingleObject(childHandle,5000);
        if(parentWait!=0 || childWait!=0)
            throw new InvalidOperationException("Owned original SCM/child end is unconfirmed; retain original custody");
        ended=true;
        Dispose();
        GC.KeepAlive(parentOwner);
        return new Dictionary<string,object> {
            {"schema","usk.publisher_owned_native_process_pair.v1"},
            {"scope","held_scm_parent_termination_and_original_effect_child_end"},
            {"parent_process_id",parentId},{"parent_process_birth",parentBirth.ToString("x16")},
            {"effect_process_id",childId},{"effect_process_birth",childBirth.ToString("x16")},
            {"native_parent_process_id",parentId},{"original_image_path",originalImage},
            {"both_live_before_termination",true},{"parent_termination_invoked",true},
            {"child_termination_invoked",false},{"parent_native_wait_result",parentWait},
            {"child_native_wait_result",childWait},{"child_observer_access",childGrantedAccess},
            {"child_observer_handle_flags",0u},{"child_observer_close_confirmed",true}};
    }
    public void Dispose() {
        if(closeAttempted) return;
        closeAttempted=true;
        if(childHandle!=IntPtr.Zero) {
            if(!CloseHandle(childHandle))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"Owned native child observer close unknown");
            childHandle=IntPtr.Zero;
        }
        // Unknown close retains the numeric observer until process disposal;
        // no destructor/finalizer retry or reopened PID can claim confirmation.
        GC.KeepAlive(parentOwner);
    }
}

public sealed class UskOwnedPreservationBoundary {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFileAttributes(string path);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint GetProcessId(IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(IntPtr process, out long birth, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    readonly Process ownedProcess;
    readonly UskOwnedEffectChildObserver effectPair;
    readonly IntPtr handle;
    readonly uint processId;
    readonly long creationTime;
    readonly string publication, retained, preservation, reservation, candidate, journal, visible;
    public UskOwnedPreservationBoundary(Process owned, UskOwnedEffectChildObserver pair, uint expectedProcessId, long expectedCreationTime,
        string publicationPath, string operationPrefix) {
        if(owned == null || expectedProcessId == (uint)Process.GetCurrentProcess().Id)
            throw new InvalidOperationException("Owned boundary requires a separate held worker");
        ownedProcess=owned;
        effectPair=pair;
        if(pair==null) throw new InvalidOperationException("Original held effect child is absent");
        handle=owned.Handle;
        processId=expectedProcessId;
        creationTime=expectedCreationTime;
        publication=publicationPath;
        retained=operationPrefix+"-retained-g00000000000000000001";
        preservation=operationPrefix+"-preserve-g00000000000000000001.json";
        reservation=operationPrefix+"-bootstrap-g00000000000000000002.json";
        candidate=publication+"\\staging\\candidate";
        journal=publication+"\\journal\\lab-prepared-evidence.json";
        visible=publication+"\\destination\\visible";
        RequireBoundLiveWorker();
    }
    void RequireBoundLiveWorker() {
        effectPair.RequireOriginalLivePair();
        long birth, exit, kernel, user;
        if(GetProcessId(handle)!=processId || !GetProcessTimes(handle,out birth,out exit,out kernel,out user) ||
            birth!=creationTime || WaitForSingleObject(handle,0)!=258)
            throw new InvalidOperationException("Owned boundary held PID/birth/liveness differs");
        GC.KeepAlive(ownedProcess);
    }
    static bool Present(string path, bool directory, bool parentMayBeAbsent) {
        uint attributes=GetFileAttributes(path);
        if(attributes==0xffffffff) {
            int error=Marshal.GetLastWin32Error();
            if(error==2 || (parentMayBeAbsent && error==3)) return false;
            throw new Win32Exception(error,"Owned boundary path observation failed");
        }
        if((attributes&1024)!=0 || ((attributes&16)!=0)!=directory)
            throw new InvalidOperationException("Owned boundary object type or reparse differs");
        return true;
    }
    public Dictionary<string,object> ObserveAndTerminate() {
        var timer=Stopwatch.StartNew();
        while(timer.ElapsedMilliseconds<120000) {
            RequireBoundLiveWorker();
            if(!Present(retained,true,false)) { Thread.SpinWait(128); continue; }
            var result=new Dictionary<string,object>();
            result["boundary_seen_utc"]=DateTime.UtcNow.ToString("o");
            result["retained_before_kill"]=true;
            result["preservation_before_kill"]=Present(preservation,false,false);
            result["publication_before_kill"]=Present(publication,true,false);
            result["replacement_reservation_before_kill"]=Present(reservation,false,false);
            result["candidate_before_kill"]=Present(candidate,true,true);
            result["journal_before_kill"]=Present(journal,false,true);
            if(!(bool)result["preservation_before_kill"] || (bool)result["publication_before_kill"] ||
                (bool)result["replacement_reservation_before_kill"] || (bool)result["candidate_before_kill"] ||
                (bool)result["journal_before_kill"]) {
                result["status"]="window_missed_preservation_already_passed";
                return result;
            }
            RequireBoundLiveWorker();
            result["native_process_pair"]=effectPair.TerminateOriginalScmOwner();
            uint wait=0;
            result["termination"]=new Dictionary<string,object> {
                {"confirmed",true},{"terminated",1},{"kill_invoked",true},
                {"method","TerminateProcess_owned_held_root"},
                {"process_id",processId},{"process_creation_file_time",creationTime.ToString("x16")},
                {"native_wait_result",wait}};
            result["retained_after_kill"]=Present(retained,true,false);
            result["preservation_after_kill"]=Present(preservation,false,false);
            result["publication_after_kill"]=Present(publication,true,false);
            result["replacement_reservation_after_kill"]=Present(reservation,false,false);
            result["candidate_after_kill"]=Present(candidate,true,true);
            result["journal_after_kill"]=Present(journal,false,true);
            result["visible_after_kill"]=Present(visible,true,true);
            result["status"]=(bool)result["retained_after_kill"] && (bool)result["preservation_after_kill"] &&
                !(bool)result["publication_after_kill"] && !(bool)result["replacement_reservation_after_kill"] &&
                !(bool)result["candidate_after_kill"] && !(bool)result["journal_after_kill"] &&
                !(bool)result["visible_after_kill"] ? "terminated_publication_preserved" :
                    "window_missed_preservation_raced_kill";
            GC.KeepAlive(ownedProcess);
            return result;
        }
        throw new TimeoutException("Owned preservation boundary deadline expired");
    }
}
'@ -ErrorAction Stop
}
