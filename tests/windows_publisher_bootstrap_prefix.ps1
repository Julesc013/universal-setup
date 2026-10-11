# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Owned hosted fault fixture, called only after the real empty-root process loss.
function New-OwnedBootstrapPrefix {
    param([Parameter(Mandatory=$true)][string]$Case,[Parameter(Mandatory=$true)]$OriginalReadback)
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
        throw 'Constructed prefix requires the owned hosted SYSTEM fixture'
    }
    $currentDisk=(Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop)|Get-Disk -ErrorAction Stop
    $parts=@($currentDisk|Get-Partition|Where-Object DriveLetter)
    if($currentDisk.IsBoot -or $currentDisk.IsSystem -or $currentDisk.Number -ne $disk.Number -or $parts.Count -ne 1 -or
        ($parts[0]|Get-Volume).UniqueId -cne $VolumeRoot) {throw 'Constructed prefix disposable target differs'}
    $scm=Get-CimInstance Win32_Service -Filter ("Name='"+$service+"'") -ErrorAction Stop
    if($scm.State -cne 'Stopped' -or $scm.ProcessId -ne 0 -or $scm.PathName -cnotlike ('*'+$installedBinary+'*')) {
        throw 'Constructed prefix registered worker is not stopped'
    }
    $rows=@($OriginalReadback.independent.rows)
    $root=$drive+'publication'
    $rootRows=@($rows|Where-Object {$_.path -ceq $root -and $_.directory})
    if($rootRows.Count -ne 1 -or @($rows|Where-Object {$_.path.StartsWith($root+'\',[StringComparison]::Ordinal)}).Count -ne 0) {
        throw 'Constructed prefix lacks an independently observed empty publication root'
    }
    $suffix='-bootstrap-g00000000000000000001.json'
    $reservations=@($rows|Where-Object {-not $_.directory -and $_.path.EndsWith($suffix,[StringComparison]::Ordinal)})
    if($reservations.Count -ne 1){throw 'Constructed prefix original reservation is ambiguous'}
    $contextPath=$reservations[0].path.Substring(0,$reservations[0].path.Length-$suffix.Length)+'.json'
    $contexts=@($rows|Where-Object {$_.path -ceq $contextPath -and -not $_.directory})
    if($contexts.Count -ne 1){throw 'Constructed prefix original operation context is absent'}
    $prepared=@{case=$Case;context_row=$contexts[0]}|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_bootstrap_prefix_evidence.py') --prepare
    if($LASTEXITCODE -ne 0){throw 'Constructed prefix canonical byte preparation failed'}
    $shape=($prepared -join "`n")|ConvertFrom-Json
    if(-not ('UskOwnedBootstrapPrefixWriter' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class UskOwnedBootstrapPrefixWriter {
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public uint Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileId {
        public ulong Volume; public ulong Low; public ulong High;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path,uint access,uint share,ref SecurityAttributes security,
        uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CreateDirectoryW(string path,ref SecurityAttributes security);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file,int kind,out FileId id,uint size);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteFile(SafeFileHandle file,byte[] bytes,uint count,out uint written,IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushFileBuffers(SafeFileHandle file);
    static Exception Failure(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(),operation); }
    public static void Create(string root,string expectedId,byte[] descriptor,int count,byte[] snapshot) {
        if(count<1 || count>4 || (snapshot!=null && (count!=4 || snapshot.Length>4*1024*1024)) ||
            descriptor==null || descriptor.Length==0 || descriptor.Length>65536)
            throw new ArgumentException("Owned prefix shape differs");
        IntPtr memory=Marshal.AllocHGlobal(descriptor.Length);
        try {
            Marshal.Copy(descriptor,0,memory,descriptor.Length);
            SecurityAttributes security=new SecurityAttributes {
                Length=(uint)Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=memory,Inherit=false};
            // OPEN_EXISTING and no DELETE sharing retain the actual original root.
            using(SafeFileHandle held=CreateFileW(root,0x20080,3,ref security,3,0x02200000,IntPtr.Zero)) {
                if(held.IsInvalid)throw Failure("Hold original owned prefix root");
                FileId id;
                if(!GetFileInformationByHandleEx(held,18,out id,(uint)Marshal.SizeOf(typeof(FileId))))
                    throw Failure("Observe original prefix root identity");
                byte[] low=BitConverter.GetBytes(id.Low),high=BitConverter.GetBytes(id.High);
                string identity=id.Volume.ToString("x16")+":"+BitConverter.ToString(low).Replace("-","").ToLowerInvariant()+
                    BitConverter.ToString(high).Replace("-","").ToLowerInvariant();
                if(identity!=expectedId)throw new InvalidOperationException("Original prefix root identity differs");
                string[] anchors={"staging","destination","state","journal"};
                for(int index=0;index<count;index++)
                    if(!CreateDirectoryW(root+"\\"+anchors[index],ref security))throw Failure("Create owned prefix anchor");
                if(snapshot!=null) {
                    using(SafeFileHandle file=CreateFileW(root+"\\journal\\lab-reviewed-plan.json",0x40000000,0,
                        ref security,1,0x00200080,IntPtr.Zero)) {
                        if(file.IsInvalid)throw Failure("Create new owned prefix snapshot");
                        uint written;
                        if(!WriteFile(file,snapshot,(uint)snapshot.Length,out written,IntPtr.Zero) || written!=snapshot.Length)
                            throw Failure("Write exact owned snapshot prefix");
                        if(!FlushFileBuffers(file))throw Failure("Flush owned snapshot prefix");
                    }
                }
            }
        } finally {Marshal.FreeHGlobal(memory);}
    }
}
'@
    }
    $descriptor=(Get-Acl -LiteralPath $root).GetSecurityDescriptorBinaryForm()
    $snapshot=$null
    if($null -ne $shape.snapshot_base64){$snapshot=[Convert]::FromBase64String($shape.snapshot_base64)}
    [UskOwnedBootstrapPrefixWriter]::Create($root,$rootRows[0].file_id,$descriptor,[int]$shape.anchor_count,$snapshot)
    return [ordered]@{schema='usk.publisher_constructed_bootstrap_prefix.v1';
        scope='system_constructed_ordered_prefix_after_observed_empty_root_process_loss';case=$Case;
        fixture_actor=@{identity='S-1-5-18';process_id=$PID;creation_file_time=$ownerCreation;service=$service;
            service_stopped=$true;publication_root_file_id=$rootRows[0].file_id};
        anchor_count=[int]$shape.anchor_count;snapshot_size_bytes=$shape.snapshot_size_bytes;
        created_at_file_time=[DateTime]::UtcNow.ToFileTimeUtc().ToString();readback=Read-NativeSnapshot}
}
