// SPDX-FileCopyrightText: 2026 Jules C
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

// Read-only qualification oracle. Bind a live invoking process/token, then
// inspect held descriptors with AccessCheck. The filtered derivative has
// Administrators deny-only, privileges removed except ChangeNotify, and no
// added restricting SID that could manufacture denials. No impersonation,
// target mutation, process launch or account change is performed here.
public sealed class UskPublisherEffectiveRights : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct Mapping { public uint Read, Write, Execute, All; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disableCount,
        [In] SidAttributes[] disable, uint deleteCount, IntPtr delete, uint restrictCount, IntPtr restrict, out IntPtr filtered);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int information, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeName(string system, IntPtr luid, StringBuilder name, ref uint size);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint requested,
        ref Mapping mapping, IntPtr privileges, ref uint size, out uint granted, out bool allowed);
    [DllImport("advapi32.dll")] static extern void MapGenericMask(ref uint access, ref Mapping mapping);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetKernelObjectSecurity(IntPtr handle, uint requested, byte[] buffer, uint size, out uint needed);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr handle, int information, byte[] bytes, uint size);

    static readonly string[] Names = {"write_or_add_file", "append_or_add_directory", "write_ea", "delete_child", "write_attributes", "delete", "write_dac", "write_owner"};
    static readonly uint[] Masks = {2, 4, 16, 64, 256, 65536, 262144, 524288};
    IntPtr process, initiating, filtered;
    public Dictionary<string, object> TokenFacts { get; private set; }

    static void Require(bool ok, string operation) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }
    static Dictionary<string, object> Facts(IntPtr token) {
        Dictionary<string, object> result = new Dictionary<string, object>();
        foreach (int information in new int[]{1, 2, 3}) {
            uint needed;
            if (GetTokenInformation(token, information, IntPtr.Zero, 0, out needed) ||
                Marshal.GetLastWin32Error()!=122 || needed<4 || needed>65536)
                throw new Exception("Token facts size unavailable or unbounded");
            IntPtr buffer=Marshal.AllocHGlobal((int)needed);
            try {
                uint returned;
                Require(GetTokenInformation(token, information, buffer, needed, out returned), "Read token facts");
                if (returned!=needed) throw new Exception("Token facts changed during observation");
                if (information==1) {
                    result["user_sid"]=new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
                } else {
                    uint count=(uint)Marshal.ReadInt32(buffer);
                    int offset=information==2 ? (IntPtr.Size==8 ? 8 : 4) : 4;
                    int stride=information==2 ? Marshal.SizeOf(typeof(SidAttributes)) : 12;
                    if (count>2048 || (ulong)offset+(ulong)count*(uint)stride>needed) throw new Exception("Token entries exceed their buffer");
                    List<Dictionary<string, object>> rows=new List<Dictionary<string, object>>();
                    for (uint index=0;index<count;++index) {
                        IntPtr entry=IntPtr.Add(buffer,offset+(int)index*stride);
                        Dictionary<string, object> row=new Dictionary<string, object>();
                        if (information==2) {
                            SidAttributes group=(SidAttributes)Marshal.PtrToStructure(entry,typeof(SidAttributes));
                            row["sid"]=new SecurityIdentifier(group.Sid).Value;row["attributes"]=group.Attributes;
                        } else {
                            uint length=256;StringBuilder name=new StringBuilder((int)length);
                            Require(LookupPrivilegeName(null,entry,name,ref length),"Read privilege name");
                            row["name"]=name.ToString();row["attributes"]=(uint)Marshal.ReadInt32(entry,8);
                        }
                        rows.Add(row);
                    }
                    result[information==2 ? "groups" : "privileges"]=rows.ToArray();
                }
            } finally {Marshal.FreeHGlobal(buffer);}
        }
        return result;
    }
    static bool EnabledGroup(Dictionary<string, object> facts, string sid) {
        foreach (Dictionary<string, object> row in (Dictionary<string, object>[])facts["groups"])
            if ((string)row["sid"]==sid && (((uint)row["attributes"] & 4)!=0) && (((uint)row["attributes"] & 16)==0)) return true;
        return false;
    }
    public UskPublisherEffectiveRights(uint pid, long creation, string callerSid, string serviceSid) {
        IntPtr source=IntPtr.Zero, derivative=IntPtr.Zero;
        try {
            process=OpenProcess(0x101000,false,pid);
            Require(process!=IntPtr.Zero,"Hold invoking process");
            long observed,exit,kernel,user;
            Require(GetProcessTimes(process,out observed,out exit,out kernel,out user),"Read invoking process creation");
            if (observed!=creation || WaitForSingleObject(process,0)!=258) throw new Exception("Invoking process identity changed or exited");
            Require(OpenProcessToken(process,10,out source),"Hold invoking token");
            Require(DuplicateToken(source,2,out initiating),"Duplicate invoking token for AccessCheck");
            byte[] admin=new byte[new SecurityIdentifier("S-1-5-32-544").BinaryLength];
            new SecurityIdentifier("S-1-5-32-544").GetBinaryForm(admin,0);
            GCHandle pinned=GCHandle.Alloc(admin,GCHandleType.Pinned);
            try {
                Require(CreateRestrictedToken(source,1,1,new SidAttributes[]{new SidAttributes{Sid=pinned.AddrOfPinnedObject(),Attributes=0}},
                    0,IntPtr.Zero,0,IntPtr.Zero,out derivative),"Create explicit filtered derivative");
            } finally {pinned.Free();}
            Require(DuplicateToken(derivative,2,out filtered),"Duplicate filtered token for AccessCheck");
            Dictionary<string, object> initialFacts=Facts(initiating), filteredFacts=Facts(filtered);
            if ((string)initialFacts["user_sid"]!=callerSid || (string)filteredFacts["user_sid"]!=callerSid ||
                callerSid=="S-1-5-18" || callerSid==serviceSid || EnabledGroup(filteredFacts,"S-1-5-32-544") ||
                EnabledGroup(filteredFacts,"S-1-5-18") || EnabledGroup(filteredFacts,serviceSid))
                throw new Exception("Invoking/filtered token principal differs from qualification context");
            foreach(Dictionary<string, object> privilege in (Dictionary<string, object>[])filteredFacts["privileges"])
                if (((uint)privilege["attributes"] & 2)!=0 && (string)privilege["name"]!="SeChangeNotifyPrivilege")
                    throw new Exception("Filtered token retains a mutation/bypass privilege");
            TokenFacts=new Dictionary<string, object>{{"process_id",pid},{"creation_file_time",creation.ToString()},
                {"basis","held invoking process token; Administrators deny-only; DISABLE_MAX_PRIVILEGE; no restricting SIDs added"},
                {"initiating",initialFacts},{"filtered",filteredFacts}};
        } catch {Dispose();throw;}
        finally {if(source!=IntPtr.Zero)CloseHandle(source);if(derivative!=IntPtr.Zero)CloseHandle(derivative);}
    }
    static Dictionary<string, object> Check(byte[] descriptor, IntPtr token) {
        Mapping mapping=new Mapping{Read=0x120089,Write=0x120116,Execute=0x1200a0,All=0x1f01ff};
        Dictionary<string, object> result=new Dictionary<string, object>();
        IntPtr privileges=Marshal.AllocHGlobal(4096);
        try {
            for(int index=0;index<=Masks.Length;++index) {
                uint requested=index==Masks.Length ? 0x02000000 : Masks[index];
                MapGenericMask(ref requested,ref mapping);
                uint size=4096,granted;bool allowed;
                Require(AccessCheck(descriptor,token,requested,ref mapping,privileges,ref size,out granted,out allowed),"Evaluate descriptor access");
                if(size>4096 || (!allowed && granted!=0)) throw new Exception("AccessCheck returned contradictory/unbounded facts");
                result[index==Masks.Length ? "maximum_allowed" : Names[index]]=new Dictionary<string, object>{
                    {"requested",requested},{"allowed",allowed},{"granted",granted}};
            }
        } finally {Marshal.FreeHGlobal(privileges);}
        return result;
    }
    public Dictionary<string, object> CheckDescriptor(byte[] descriptor) {
        if(process==IntPtr.Zero || WaitForSingleObject(process,0)!=258) throw new Exception("Invoking process exited before access observation");
        RawSecurityDescriptor raw=new RawSecurityDescriptor(descriptor,0);
        if(raw.Owner==null || raw.Group==null || raw.DiscretionaryAcl==null) throw new Exception("AccessCheck requires exact owner/group/DACL");
        return new Dictionary<string, object>{{"initiating",Check(descriptor,initiating)},{"filtered",Check(descriptor,filtered)}};
    }
    public Dictionary<string, object> Read(string path) {
        IntPtr file=CreateFile(path,0x20080,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        Require(file!=new IntPtr(-1),"Hold descriptor object");
        try {
            byte[] tag=new byte[8],id=new byte[24];
            Require(GetFileInformationByHandleEx(file,9,tag,8),"Read descriptor object tag");
            if((BitConverter.ToUInt32(tag,0)&0x400)!=0 || BitConverter.ToUInt32(tag,4)!=0) throw new Exception("Descriptor object is a reparse point");
            Require(GetFileInformationByHandleEx(file,18,id,24),"Read descriptor object identity");
            uint needed;
            if(GetKernelObjectSecurity(file,7,null,0,out needed) || Marshal.GetLastWin32Error()!=122 || needed<20 || needed>65536)
                throw new Exception("Effective-right descriptor size unavailable or unbounded");
            byte[] bytes=new byte[needed];uint returned;
            Require(GetKernelObjectSecurity(file,7,bytes,needed,out returned),"Read stored effective-right descriptor");
            if(returned!=needed)throw new Exception("Effective-right descriptor changed during observation");
            string identity=BitConverter.ToUInt64(id,0).ToString("x16")+":"+BitConverter.ToString(id,8,16).Replace("-","").ToLowerInvariant();
            RawSecurityDescriptor raw=new RawSecurityDescriptor(bytes,0);
            return new Dictionary<string, object>{{"file_id",identity},{"security",raw.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access)},
                {"group_sid",raw.Group==null ? null : raw.Group.Value},{"checks",CheckDescriptor(bytes)}};
        } finally {CloseHandle(file);}
    }
    public void Dispose() {
        if(filtered!=IntPtr.Zero){CloseHandle(filtered);filtered=IntPtr.Zero;}
        if(initiating!=IntPtr.Zero){CloseHandle(initiating);initiating=IntPtr.Zero;}
        if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}
    }
}
