# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Owned hosted fixture primitives. Definitions alone cause no native effects.
function Initialize-OwnedDurableStateWriter {
    if('UskOwnedDurableStateWriter' -as [type]){return}
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
public static class UskOwnedDurableStateWriter {
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public uint Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileId {public ulong Volume;public ulong Low;public ulong High;}
    [StructLayout(LayoutKind.Sequential)] struct TagInfo {public uint Attributes;public uint ReparseTag;}
    [StructLayout(LayoutKind.Sequential)] struct Disposition {public byte Delete;}
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path,uint access,uint share,ref SecurityAttributes security,
        uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,out FileId id,uint size);
    [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetTag(SafeFileHandle file,int kind,out TagInfo info,uint size);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteFile(SafeFileHandle file,byte[] bytes,uint count,out uint written,IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushFileBuffers(SafeFileHandle file);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file,int kind,ref Disposition disposition,uint size);
    [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
    static Exception Failure(string operation){return new Win32Exception(Marshal.GetLastWin32Error(),operation);}
    static void RequireDirectory(SafeFileHandle file,string expected) {
        if(file.IsInvalid)throw Failure("Hold exact owned durable fixture directory");
        FileId id;TagInfo tag;
        if(!GetFileInformationByHandleEx(file,18,out id,(uint)Marshal.SizeOf(typeof(FileId))) ||
            !GetTag(file,9,out tag,(uint)Marshal.SizeOf(typeof(TagInfo))))throw Failure("Observe owned durable fixture directory");
        string actual=id.Volume.ToString("x16")+":"+
            BitConverter.ToString(BitConverter.GetBytes(id.Low)).Replace("-","").ToLowerInvariant()+
            BitConverter.ToString(BitConverter.GetBytes(id.High)).Replace("-","").ToLowerInvariant();
        if(actual!=expected || (tag.Attributes&16)==0 || (tag.Attributes&1024)!=0 || tag.ReparseTag!=0)
            throw new InvalidOperationException("Owned durable fixture directory binding differs");
    }
    public static void CreateRecord(string parent,string expectedParent,string leaf,byte[] descriptor,byte[] bytes) {
        if(!Regex.IsMatch(leaf,@"^(operation-[0-9a-f]{64}-(preserve-g00000000000000000001|bootstrap-g00000000000000000002)\.json|bootstrap-[1-9][0-9]*-[0-9]+-[1-9][0-9]*)$") ||
            descriptor==null || descriptor.Length==0 || descriptor.Length>65536 || bytes==null || bytes.Length>1024*1024)
            throw new ArgumentException("Owned durable record shape differs");
        IntPtr memory=Marshal.AllocHGlobal(descriptor.Length);
        try {
            Marshal.Copy(descriptor,0,memory,descriptor.Length);
            SecurityAttributes security=new SecurityAttributes {
                Length=(uint)Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=memory,Inherit=false};
            using(SafeFileHandle held=CreateFileW(parent,0x20080,3,ref security,3,0x02200000,IntPtr.Zero)) {
                RequireDirectory(held,expectedParent);
                using(SafeFileHandle file=CreateFileW(parent+"\\"+leaf,0x40000000,0,ref security,1,0x00200080,IntPtr.Zero)) {
                    if(file.IsInvalid)throw Failure("Create new owned durable fixture record");
                    uint written;
                    if(bytes.Length>0 && (!WriteFile(file,bytes,(uint)bytes.Length,out written,IntPtr.Zero) || written!=bytes.Length))
                        throw Failure("Write owned durable fixture bytes");
                    if(!FlushFileBuffers(file))throw Failure("Flush owned durable fixture bytes");
                }
            }
        } finally {Marshal.FreeHGlobal(memory);}
    }
    public static void RemoveExactEmptyRoot(string path,string expectedId) {
        if(!Regex.IsMatch(path,@"^[A-Z]:\\publication$"))throw new ArgumentException("Owned empty root path differs");
        SecurityAttributes security=new SecurityAttributes {Length=(uint)Marshal.SizeOf(typeof(SecurityAttributes))};
        using(SafeFileHandle held=CreateFileW(path,0x30081,3,ref security,3,0x02200000,IntPtr.Zero)) {
            RequireDirectory(held,expectedId);
            // Kernel refuses a nonempty directory. Exact root identity remains
            // held; this cannot recursively delete, replace or follow a link.
            uint size=(uint)Marshal.SizeOf(typeof(Disposition));
            if(size!=1)throw new InvalidOperationException("FILE_DISPOSITION_INFO BOOLEAN layout differs");
            Disposition disposition=new Disposition {Delete=1};
            if(!SetFileInformationByHandle(held,4,ref disposition,size))
                throw Failure("Remove exact empty owned fixture root");
        }
    }
}
'@
}
