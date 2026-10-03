# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Assert-IndependentProtectedRows {
    param($Rows,[string]$ServiceSid,[string]$ConsumerSid='',[string]$VisibleRoot='',[switch]$AllowPartial)
    foreach($row in $Rows) {
        $visible=$ConsumerSid -and ($row.path -ceq $VisibleRoot -or $row.path.StartsWith($VisibleRoot+'\',[StringComparison]::Ordinal))
        $readers=@($row.aces|Where-Object sid -eq $ConsumerSid)
        $required=if($visible -and (-not $AllowPartial -or $readers.Count)){3}else{2}
        $system=@($row.aces|Where-Object sid -eq 'S-1-5-18')
        $service=@($row.aces|Where-Object sid -eq $ServiceSid)
        if($row.owner -ne 'S-1-5-18' -or -not $row.protected -or $row.aces.Count -ne $required -or
            $row.aces[0].sid -cne 'S-1-5-18' -or $system.Count -ne 1 -or $service.Count -ne 1 -or
            $readers.Count -ne ($required - 2) -or
            @($row.aces|Where-Object {$_.type -ne 'Allow' -or $_.inherited -or $_.inheritance -ne 0 -or $_.propagation -ne 0}).Count) {
            throw ('Independent owner/DACL differs: '+$row.path+' owner='+$row.owner+
                ' protected='+$row.protected+' ACEs='+($row.aces|ConvertTo-Json -Compress -Depth 4))
        }
        if($system[0].rights -ne 2032127 -or $service[0].rights -ne 2032127 -or
            ($required -eq 3 -and $readers[0].rights -ne 1179817)) {
            throw ('Independent authority/consumer rights differ: '+$row.path)
        }
    }
}
function Assert-IndependentRetainedMaterial {
    param($Before,$After,[string]$ChangedPayloadPath='',[string]$ChangedPayloadSha256='',
        [switch]$NoAdditionalRows)
    $beforeRows=@($Before.rows);$afterRows=@($After.rows)
    if($beforeRows.Count -eq 0 -or $afterRows.Count -lt $beforeRows.Count -or
        ($NoAdditionalRows -and $beforeRows.Count -ne $afterRows.Count) -or
        @($beforeRows.path|Sort-Object -Unique).Count -ne $beforeRows.Count -or
        @($afterRows.path|Sort-Object -Unique).Count -ne $afterRows.Count) {
        throw 'Independent retained material has missing, additional or duplicate rows'
    }
    if(($ChangedPayloadPath -and $ChangedPayloadSha256 -cnotmatch '^[0-9a-f]{64}$') -or
        (-not $ChangedPayloadPath -and $ChangedPayloadSha256)) {throw 'Retained payload drift witness is incomplete'}
    $changed=0
    foreach($row in $beforeRows) {
        $expected=$row|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
        if($row.path -ceq $ChangedPayloadPath) {
            if($row.directory -or $row.sha256 -ceq $ChangedPayloadSha256) {throw 'Retained payload witness is not actual regular-file drift'}
            $expected.sha256=$ChangedPayloadSha256;++$changed
        }
        $found=@($afterRows|Where-Object path -ceq $row.path)
        if($found.Count -ne 1 -or ($found[0]|ConvertTo-Json -Depth 64 -Compress) -cne
            ($expected|ConvertTo-Json -Depth 64 -Compress)) {
            throw ('Retained native material changed: '+$row.path)
        }
    }
    if($ChangedPayloadPath -and $changed -ne 1) {throw 'Retained payload drift witness has no unique native object'}
}
function Assert-IndependentMetadataCollisionPrefix {
    param($Before,$After,[string]$DriveRoot,[string]$ServiceSid)
    Assert-IndependentRetainedMaterial -Before $Before -After $After
    # The installed-path directory collision is read before public audit or
    # ownership creation. Only the two private forward-recovery records may
    # precede that refusal; neither establishes public installed completion.
    $visiblePath=$DriveRoot+'publication\journal\lab-visible-evidence.json'
    $completionPath=$DriveRoot+'publication\state\lab-installed-state.json'
    foreach($row in @($After.rows|Where-Object {$_.path -cnotin @($Before.rows.path)})) {
        if($row.directory -or $row.path -cnotin @($visiblePath,$completionPath)) {
            throw ('Metadata refusal created an unexpected path or type: '+$row.path)
        }
    }
    $preparedRows=@($After.rows|Where-Object path -ceq ($DriveRoot+'publication\journal\lab-prepared-evidence.json'))
    $destination=@($After.rows|Where-Object path -ceq ($DriveRoot+'publication\destination'))
    $root=@($After.rows|Where-Object path -ceq ($DriveRoot+'publication\destination\visible'))
    if($preparedRows.Count -ne 1 -or $preparedRows[0].directory -or
        $destination.Count -ne 1 -or -not $destination[0].directory -or
        $root.Count -ne 1 -or -not $root[0].directory) {throw 'Metadata refusal lost its retained operation anchors'}
    $prepared=$preparedRows[0].content_json|ConvertFrom-Json
    if($prepared.schema -cne 'usk.publisher.lab_phase_evidence.v2' -or
        $prepared.phase -cne 'lab_prepared_evidence' -or $prepared.service_sid -cne $ServiceSid -or
        $prepared.source_file_id -cne $root[0].file_id -or
        $prepared.destination_parent_file_id -cne $destination[0].file_id -or
        $prepared.destination_name -cne 'visible' -or
        $prepared.selected_file_set_digest -cnotmatch '^[0-9a-f]{64}$' -or
        $null -eq $prepared.source_binding) {throw 'Metadata refusal prepared operation binding differs'}
    $visibleRows=@($After.rows|Where-Object path -ceq $visiblePath)
    $completionRows=@($After.rows|Where-Object path -ceq $completionPath)
    if($visibleRows.Count -gt 1 -or $completionRows.Count -gt 1 -or
        ($completionRows.Count -and -not $visibleRows.Count)) {throw 'Metadata refusal private record prefix differs'}
    if($visibleRows.Count) {
        $visible=$visibleRows[0].content_json|ConvertFrom-Json
        if($visibleRows[0].directory -or $visible.schema -cne 'usk.publisher.lab_phase_evidence.v2' -or
            $visible.phase -cne 'lab_visible_evidence' -or
            $visible.prepared_record_sha256 -cne $preparedRows[0].sha256 -or
            $visible.source_file_id -cne $root[0].file_id -or
            $visible.destination_parent_file_id -cne $destination[0].file_id -or
            $visible.destination_name -cne 'visible' -or
            $visible.selected_file_set_digest -cne $prepared.selected_file_set_digest) {
            throw 'Metadata refusal visible record has a foreign operation binding'
        }
    }
    if($completionRows.Count) {
        $completion=$completionRows[0].content_json|ConvertFrom-Json
        $serial=@([regex]::Matches($completionRows[0].content_json,'"volume_serial":([0-9]+)'))
        if($completionRows[0].directory -or $completion.schema -cne 'usk.publisher.lab_installed_state.v2' -or
            $completion.phase -cne 'lab_installed_state' -or $completion.service_sid -cne $ServiceSid -or
            $completion.prepared_record_sha256 -cne $preparedRows[0].sha256 -or
            $completion.visible_record_sha256 -cne $visibleRows[0].sha256 -or
            $completion.visible_root_file_id -cne $root[0].file_id -or
            $completion.destination_parent_file_id -cne $destination[0].file_id -or
            $completion.destination_name -cne 'visible' -or
            $completion.selected_file_set_digest -cne $prepared.selected_file_set_digest -or
            ($completion.source_binding|ConvertTo-Json -Depth 64 -Compress) -cne
                ($prepared.source_binding|ConvertTo-Json -Depth 64 -Compress) -or
            $serial.Count -ne 1 -or
            [uint64]::Parse($serial[0].Groups[1].Value,[Globalization.CultureInfo]::InvariantCulture) -ne
                [Convert]::ToUInt64($root[0].file_id.Split(':')[0],16)) {
            throw 'Metadata refusal private completion has a foreign operation binding'
        }
    }
}
function Assert-IndependentMetadataProbe {
    param($Result,[switch]$AllowPartialConsumerGrant)
    $drive=$Result.volume_drive_root
    if($drive -cnotmatch '^[A-Z]:\\$'){throw 'Exact observed volume drive root required'}
    $visibleRoot=([string]$Result.plan.target.root).Replace('/','\')
    if($visibleRoot -cnotmatch '^[A-Z]:\\publication\\destination\\[A-Za-z0-9_.-]+$' -or
        -not $visibleRoot.StartsWith($drive+'publication\destination\',[StringComparison]::Ordinal)) {
        throw 'Reviewed visible target is outside the observed protected destination'
    }
    $destinationPrefix=$drive+'publication\destination\'
    $destinationChildren=@($Result.independent.rows|Where-Object {
        $_.path.StartsWith($destinationPrefix,[StringComparison]::Ordinal) -and
        $_.path.Substring($destinationPrefix.Length).IndexOf('\') -lt 0
    })
    if($destinationChildren.Count -ne 1 -or
        $destinationChildren[0].path -cne $visibleRoot -or
        -not $destinationChildren[0].directory) {
        throw 'Independent protected destination has an unexpected child'
    }
    $expectedStatus=if($AllowPartialConsumerGrant){'recovery_required'}else{'pass'}
    if($AllowPartialConsumerGrant -and (-not $Result.consumer_sid -or $Result.native.error -notmatch 'injected interruption after first consumer grant')){throw 'Partial-grant witness is not the admitted injected failure'}
    if ($Result.native.status -ne $expectedStatus -or -not $Result.observer_task_removed -or
        $Result.independent.identity -ne 'S-1-5-18') { throw 'Service, observer identity or confirmed task cleanup differs' }
    Assert-IndependentProtectedRows -Rows $Result.independent.rows -ServiceSid $Result.service_sid -ConsumerSid ([string]$Result.consumer_sid) -VisibleRoot $visibleRoot -AllowPartial:$AllowPartialConsumerGrant
    function Get-ExactRecord([string]$Path) {
        $found=@($Result.independent.rows|Where-Object { $_.path -ceq $Path -and -not $_.directory })
        if ($found.Count -ne 1 -or -not $found[0].content_json) { throw ('Missing independent record: ' + $Path) }
        $found[0].content_json | ConvertFrom-Json
    }
    $snapshot=Get-ExactRecord ($drive + 'publication\journal\lab-reviewed-plan.json')
    $completion=Get-ExactRecord ($drive + 'publication\state\lab-installed-state.json')
    $completionRow=@($Result.independent.rows|Where-Object path -ceq ($drive + 'publication\state\lab-installed-state.json'))[0]
    if ($snapshot.plan_digest -ne $Result.plan.plan_digest -or $snapshot.archive_sha256 -ne $Result.archive_sha256 -or
        $completion.source_binding.reviewed_plan_digest -ne $snapshot.plan_digest) { throw 'Independent reviewed source binding differs' }
    if ($Result.apply_request -and ($snapshot.transaction_id -ne $Result.apply_request.transaction_id -or
        $snapshot.applied_at -ne $Result.apply_request.applied_at)) { throw 'Independent caller operation binding differs' }
    if($Result.consumer_sid -and ($snapshot.schema -cne 'usk.publisher.lab_reviewed_plan_snapshot.v4' -or
        $snapshot.consumer_read_sid -cne $Result.consumer_sid -or
        (-not $AllowPartialConsumerGrant -and ($Result.native.consumer_access.consumer_sid -cne $Result.consumer_sid -or
        $Result.native.consumer_access.status -cne 'read_execute_granted')))){throw 'Independent durable consumer policy differs'}
    $transaction=$snapshot.transaction_id
    $installId=$Result.request.install_id
    $installedPath=($drive + 'setup-state\state\installed\') + $installId + '.' + $transaction + '.json'
    $installed=Get-ExactRecord $installedPath
    $ownershipPath=($drive + 'setup-state\state\') + $installed.ownership_manifest_ref.Replace('/','\')
    $ownership=Get-ExactRecord $ownershipPath
    $marker=Get-ExactRecord ($drive + 'setup-state\.usk-owned-root.v1.json')
    $auditRoot=($drive + 'setup-state\audit\chains\') + $installed.audit_chain_id + '\'
    $validatedPath=$auditRoot+'00000000000000000000.event.json'
    $completedPath=$auditRoot+'00000000000000000001.event.json'
    $validated=Get-ExactRecord $validatedPath
    $completed=Get-ExactRecord $completedPath
    $publicFiles=@($Result.independent.rows|Where-Object { -not $_.directory -and $_.path.StartsWith(($drive + 'setup-state\'),[StringComparison]::Ordinal) })
    $expected=@(($drive + 'setup-state\.usk-owned-root.v1.json'),$installedPath,$ownershipPath,$validatedPath,$completedPath)
    if ($publicFiles.Count -ne 5 -or @($publicFiles|Where-Object {$_.path -cnotin $expected}).Count -ne 0) { throw 'Independent public record closure differs' }
    $target=$Result.plan.target.root.Replace('/','\')
    if ($marker.schema -ne 'usk.setup_owned_root.v1' -or $marker.acceptance_root.Replace('/','\') -cne ($drive + '') -or
        $installed.schema -ne 'usk.installed_state.v1' -or $installed.install_id -ne $installId -or
        $installed.transaction_id -ne $transaction -or $installed.created_at -ne $snapshot.applied_at -or
        $installed.target_root.Replace('/','\') -cne $target -or $installed.source_archive_digest -ne $Result.archive_sha256 -or
        $installed.recipe_digest -ne $Result.request.recipe.recipe_digest -or $installed.product_id -ne $Result.request.recipe.product_id -or
        $installed.product_version -ne $Result.request.recipe.product_version -or $installed.lifecycle_status -ne 'installed' -or
        ($installed.component_selection|ConvertTo-Json -Compress) -cne ($Result.request.recipe.components|ConvertTo-Json -Compress) -or
        $ownership.schema -ne 'usk.ownership_manifest.v1' -or $ownership.install_id -ne $installId -or
        $ownership.created_by_transaction_id -ne $transaction -or $ownership.target_root.Replace('/','\') -cne $target -or
        $ownership.manifest_digest -ne $installed.ownership_manifest_digest -or
        $installed.ownership_manifest_ref -cne ('ownership/'+$ownership.manifest_id+'.json') -or
        $installed.last_verification.status -ne 'pass') { throw 'Independent installed/ownership/marker binding differs' }
    if ($validated.phase -ne 'validated' -or $validated.status -ne 'pass' -or $validated.sequence -ne 0 -or
        $validated.details_digest -ne $completionRow.sha256 -or $validated.subject.subject_id -ne $Result.plan.plan_id -or
        $validated.subject.subject_type -ne 'journal' -or $null -ne $validated.previous_event_digest -or
        $completed.phase -ne 'completed' -or $completed.status -ne 'pass' -or $completed.sequence -ne 1 -or
        $completed.previous_event_digest -ne $validated.event_digest -or $completed.subject.subject_id -ne $installId -or
        $completed.subject.subject_type -ne 'installation' -or
        $completed.details_digest -ne $installed.last_verification.report_digest) { throw 'Independent audit linkage differs' }
    foreach ($event in @($validated,$completed)) {
        if ($event.schema -ne 'usk.audit_event.v1' -or $event.operation -ne 'install_local' -or
            $event.transaction_id -ne $transaction -or $event.plan_id -ne $Result.plan.plan_id -or
            $event.created_at -ne $snapshot.applied_at -or $event.audit_chain_id -ne $installed.audit_chain_id) {
            throw 'Independent audit operation binding differs'
        }
    }
    $entries=@($Result.plan.planned_entries|Where-Object entry_type -eq file)
    if ($ownership.files.Count -ne $entries.Count) { throw 'Independent ownership file count differs' }
    $expectedPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedDirectories=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$expectedDirectories.Add($visibleRoot)
    foreach($entry in $entries) {
        $path=$visibleRoot+'\'+$entry.relative_path.Replace('/','\')
        if(-not $expectedPaths.Add($path)){throw 'Duplicate planned visible file'}
        $parent=[IO.Path]::GetDirectoryName($path)
        while($parent.StartsWith($visibleRoot+'\',[StringComparison]::Ordinal)) {
            [void]$expectedDirectories.Add($parent)
            $parent=[IO.Path]::GetDirectoryName($parent)
        }
    }
    $visibleRows=@($Result.independent.rows|Where-Object {
        $_.path -ceq $visibleRoot -or $_.path.StartsWith($visibleRoot+'\',[StringComparison]::Ordinal)
    })
    if(@($visibleRows|Where-Object { -not $_.directory }).Count -ne $entries.Count -or
        @($visibleRows|Where-Object { if($_.directory){-not $expectedDirectories.Contains($_.path)}else{-not $expectedPaths.Contains($_.path)} }).Count -ne 0) {
        throw 'Independent visible payload closure differs'
    }
    foreach ($entry in $entries) {
        $path=$visibleRoot+'\'+$entry.relative_path.Replace('/','\')
        $found=@($Result.independent.rows|Where-Object path -ceq $path)
        $owned=@($ownership.files|Where-Object relative_path -ceq $entry.relative_path)
        if ($found.Count -ne 1 -or $owned.Count -ne 1 -or $found[0].sha256 -ne $entry.sha256 -or
            $found[0].bytes -ne $entry.size_bytes -or $owned[0].sha256 -ne $entry.sha256 -or $owned[0].size_bytes -ne $entry.size_bytes) {
            throw ('Independent selected payload/ownership differs: ' + $path)
        }
    }
}
function Invoke-IndependentMetadataReadback {
    param([string]$DriveRoot,[string]$OutputRoot,[string]$RunId,[switch]$MetadataOnly,
        [uint32]$CallerProcessId=0,[string]$CallerCreationFileTime='',
        [string]$CallerSid='',[string]$ServiceSid='')
    if($DriveRoot -cnotmatch '^[A-Z]:\\$' -or $RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Exact observed volume alias and owned observer identity required'
    }
    if($CallerProcessId -ne 0 -and ($MetadataOnly -or $CallerCreationFileTime -cnotmatch '^[1-9][0-9]{16,18}$' -or
        $CallerSid -cnotmatch '^S-1-5-21-([0-9]+-){3}[0-9]+$' -or
        $ServiceSid -cnotmatch '^S-1-5-80-([0-9]+-){4}[0-9]+$')) {
        throw 'Effective-right observation requires the exact live invoking process and account/service principals'
    }
    if($CallerProcessId -eq 0 -and ($CallerCreationFileTime -or $CallerSid -or $ServiceSid)) {
        throw 'Partial effective-right process binding is unavailable'
    }
    $name='USK_METADATA_OBSERVER_'+$RunId
    $script=Join-Path $OutputRoot ('metadata-observer-'+$RunId+'.ps1')
    $output=Join-Path $OutputRoot ('metadata-observed-'+$RunId+'.json')
    if((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $script) -or (Test-Path -LiteralPath $output)) { throw 'Observer collision' }
    $observer=@'
param([string]$Output,[string]$DriveRoot,[switch]$MetadataOnly,
    [uint32]$CallerProcessId=0,[string]$CallerCreationFileTime='',[string]$CallerSid='',[string]$ServiceSid='')
$ErrorActionPreference='Stop'
 Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class UskMetadataFacts {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sa,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int k,byte[] b,uint n);
 [DllImport("advapi32.dll", SetLastError=true)]
 static extern bool GetKernelObjectSecurity(SafeFileHandle h,uint i,byte[] b,uint n,out uint needed);
 public static object[] Read(string path) {
  using(var h=CreateFile(path,0x20080,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
   return ReadHandle(h);
  }
 }
 static object[] ReadHandle(SafeFileHandle h) {
   if(h.IsInvalid) throw new InvalidOperationException("Independent metadata handle unavailable");
   var id=new byte[24]; var tag=new byte[8]; uint needed;
   if(!GetFileInformationByHandleEx(h,18,id,24) || !GetFileInformationByHandleEx(h,9,tag,8) ||
      BitConverter.ToUInt32(tag,4)!=0 || (BitConverter.ToUInt32(tag,0)&0x400)!=0)
    throw new InvalidOperationException("Independent metadata identity or ordinary-object facts unavailable");
   if(GetKernelObjectSecurity(h,5,null,0,out needed) || Marshal.GetLastWin32Error()!=122 || needed<20 || needed>65536)
    throw new InvalidOperationException("Independent metadata security size unavailable");
   var security=new byte[needed]; uint returned;
   if(!GetKernelObjectSecurity(h,5,security,needed,out returned) || returned!=needed)
    throw new InvalidOperationException("Independent metadata security changed during observation");
   return new object[]{BitConverter.ToUInt64(id,0).ToString("x16")+":"+
    BitConverter.ToString(id,8,16).Replace("-","").ToLowerInvariant(),security,BitConverter.ToUInt32(tag,0)};
 }
 static byte[] Query(SafeFileHandle h,int kind,int size) {
  var b=new byte[size];
  if(!GetFileInformationByHandleEx(h,kind,b,(uint)size))
   throw new InvalidOperationException("Independent native closure query failed: "+kind+"/"+Marshal.GetLastWin32Error());
  return b;
 }
 static object[] Streams(SafeFileHandle h,bool directory) {
  byte[] b=null;
  for(int size=4096;size<=1048576;size*=2) {
   b=new byte[size];
   if(GetFileInformationByHandleEx(h,7,b,(uint)size)) break;
   int error=Marshal.GetLastWin32Error();
   if(directory && error==38) return new object[0];
   if((error!=122 && error!=234) || size==1048576)
    throw new InvalidOperationException("Independent stream query unavailable or exceeds bound: "+error);
  }
  var rows=new List<object>(); var names=new HashSet<string>(StringComparer.Ordinal); int offset=0;
  while(true) {
   if(offset<0 || b.Length-offset<24) throw new InvalidOperationException("Independent stream header truncated");
   uint next=BitConverter.ToUInt32(b,offset), length=BitConverter.ToUInt32(b,offset+4);
   long size=BitConverter.ToInt64(b,offset+8), allocated=BitConverter.ToInt64(b,offset+16);
   long available=next==0 ? (long)(b.Length-offset) : next;
   if(available<24 || available>b.Length-offset || length%2!=0 || length==0 ||
      length>available-24 || size<0 || allocated<0 || (next!=0 && next%8!=0))
    throw new InvalidOperationException("Independent stream record malformed");
   string name=Encoding.Unicode.GetString(b,offset+24,(int)length);
   if(!names.Add(name)) throw new InvalidOperationException("Independent stream name repeated");
   rows.Add(new Dictionary<string,object>{{"name",name},{"size",size},{"allocation_size",allocated}});
   if(next==0) break;
   offset=checked(offset+(int)next);
  }
  return rows.ToArray();
 }
 public static object[] ReadClosure(string path) {
  using(var h=CreateFile(path,0x20081,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
   object[] facts=ReadHandle(h);
   var standard=Query(h,1,24); uint attributes=(uint)facts[2];
   bool directory=(attributes&16)!=0;
   long bytes=BitConverter.ToInt64(standard,8); uint links=BitConverter.ToUInt32(standard,16);
   if(standard[20]!=0 || (standard[21]!=0)!=directory || bytes<0 || (!directory && bytes>134217728))
    throw new InvalidOperationException("Independent closure type/size exceeds fixture bound");
   uint caseFlags=directory ? BitConverter.ToUInt32(Query(h,23,4),0) : 0;
   if((caseFlags&~1U)!=0) throw new InvalidOperationException("Independent case flags unsupported");
   bool caseSensitive=(caseFlags&1)!=0;
   var filename=Query(h,2,4096); uint nameBytes=BitConverter.ToUInt32(filename,0);
   if(nameBytes==0 || nameBytes%2!=0 || nameBytes>filename.Length-4)
    throw new InvalidOperationException("Independent native name unavailable");
   string nativeName=Encoding.Unicode.GetString(filename,4,(int)nameBytes);
   object[] streams=Streams(h,directory); string digest=null;
   if(!directory) {
    using(var file=new FileStream(h,FileAccess.Read)) using(var sha=SHA256.Create()) {
     var buffer=new byte[65536]; long total=0;
     while(total<bytes) {
      int count=file.Read(buffer,0,(int)Math.Min(buffer.Length,bytes-total));
      if(count==0) throw new InvalidOperationException("Independent file truncated during hashing");
      sha.TransformBlock(buffer,0,count,buffer,0); total+=count;
     }
     if(file.ReadByte()!=-1) throw new InvalidOperationException("Independent file grew during bounded hashing");
     sha.TransformFinalBlock(new byte[0],0,0);
     digest=BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
     var after=Query(h,1,24);
     if(file.Position!=bytes || BitConverter.ToInt64(after,8)!=bytes ||
        BitConverter.ToUInt32(after,16)!=links)
      throw new InvalidOperationException("Independent file size/link facts changed during hashing");
    }
   }
   return new object[]{facts[0],facts[1],attributes,links,caseSensitive,streams,digest,
    directory ? 0L : bytes,nativeName};
  }
 }
}
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

"@

$effectiveRights=$null
if($CallerProcessId -ne 0) {
 $effectiveRights=[UskPublisherEffectiveRights]::new($CallerProcessId,[long]$CallerCreationFileTime,$CallerSid,$ServiceSid)
}
try {
$rows=[Collections.Generic.List[object]]::new()
$pending=[Collections.Generic.Stack[object]]::new()
if(-not $MetadataOnly) {
foreach($top in @(($DriveRoot+'setup-state'),($DriveRoot+'publication'))) {
 if(-not (Test-Path -LiteralPath $top -PathType Container)) {
  if($top -ceq ($DriveRoot+'setup-state')){continue}
  throw 'Protected publication root is absent during independent readback'
 }
 $pending.Push((Get-Item -LiteralPath $top -Force))
 while($pending.Count -gt 0) {
  $p=$pending.Pop()
  if(($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected readback link' }
  if($rows.Count -ge 10000 -or (-not $p.PSIsContainer -and $p.Extension -eq '.json' -and $p.Length -gt 16MB)) {throw 'Independent readback exceeds its record budget'}
  $facts=[UskMetadataFacts]::ReadClosure($p.FullName)
  $raw=[Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$facts[1],0)
  $rawAces=@($raw.DiscretionaryAcl|ForEach-Object {
   [ordered]@{type=[int]$_.AceType;flags=[int]$_.AceFlags;access_mask=$_.AccessMask;sid=$_.SecurityIdentifier.Value}
  })
  $a=Get-Acl -LiteralPath $p.FullName
  $aces=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
   [ordered]@{sid=$_.IdentityReference.Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}
  })
  $row=[ordered]@{path=$p.FullName;directory=$p.PSIsContainer;
   file_id=[string]$facts[0];native_name=[string]$facts[8];attributes=[uint32]$facts[2];
   link_count=[uint32]$facts[3];case_sensitive=[bool]$facts[4];streams=@($facts[5]);raw_aces=$rawAces;
   raw_security=$raw.GetSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access);owner=$raw.Owner.Value;protected=[bool]($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected);aces=$aces;
   bytes=[long]$facts[7];sha256=$facts[6];
   content_json=$(if(-not $p.PSIsContainer -and $p.Extension -eq '.json'){[IO.File]::ReadAllText($p.FullName)}else{$null})}
  if($effectiveRights) {
   $checked=$effectiveRights.Read($p.FullName)
   if($checked['file_id'] -cne $row.file_id -or $checked['security'] -cne $row.raw_security) {
    throw 'Effective-right descriptor observation differs from independent native closure'
   }
   $row['effective_rights']=$checked['checks']
   $row['effective_right_group_sid']=$checked['group_sid']
  }
  $rows.Add($row)
  if($p.PSIsContainer){foreach($child in Get-ChildItem -LiteralPath $p.FullName -Force){$pending.Push($child)}}
 }
}
}
$volumeMetadata=[Collections.Generic.List[object]]::new()
if($MetadataOnly) {
 $top=$DriveRoot+'System Volume Information'
 if(Test-Path -LiteralPath $top) {
  $objects=@((Get-Item -LiteralPath $top -Force))+@(Get-ChildItem -LiteralPath $top -Force)
  if($objects.Count -gt 4){throw 'Independent volume metadata exceeds its flat bound'}
  foreach($object in $objects) {
   if(($object.FullName -cne $top -and $object.PSIsContainer) -or
      ($object.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Independent metadata has a nested directory or reparse point'}
   $facts=[UskMetadataFacts]::Read($object.FullName)
   $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$facts[1],0)
   $row=[ordered]@{path=$object.FullName.Substring($DriveRoot.Length);file_id=[string]$facts[0];
    security=$descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access);
    attributes=[uint32]$facts[2]}
   if(-not $object.PSIsContainer) {
    if($object.Length -gt 1MB){throw 'Independent metadata file exceeds its bound'}
    $row['size']=[string]$object.Length
    $row['sha256']=(Get-FileHash -LiteralPath $object.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
   }
   $volumeMetadata.Add($row)
  }
 }
}
$result=[ordered]@{schema='usk.publisher.metadata_independent_readback.v1';identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rows=$rows;volume_metadata=$volumeMetadata;
 runtime=@{powershell=$PSVersionTable.PSVersion.ToString();clr=[Environment]::Version.ToString()};observed_utc=[DateTime]::UtcNow.ToString('o')}
if($effectiveRights){$result['effective_right_tokens']=$effectiveRights.TokenFacts}
$temporary=$Output+'.pending'
$stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 10))
 $stream.Write($bytes,0,$bytes.Length)
 $stream.Flush($true)
} finally { $stream.Dispose() }
# Only the closed, complete result becomes visible to the caller. File.Move
# refuses an existing destination in the installed Windows PowerShell runtime.
[IO.File]::Move($temporary,$Output)
} finally {if($effectiveRights){$effectiveRights.Dispose()}}
'@
    [IO.File]::WriteAllText($script,$observer,[Text.UTF8Encoding]::new($false))
    # Use the installed SYSTEM policy without changing execution policy. The
    # reviewed script is passed as data to a -Command script block.
    $command="& ([scriptblock]::Create([IO.File]::ReadAllText('"+$script.Replace("'","''")+"'))) -Output '"+
        $output.Replace("'","''")+"' -DriveRoot '"+$DriveRoot+"'"
    if($MetadataOnly){$command+=' -MetadataOnly'}
    if($CallerProcessId -ne 0) {
        $command+=' -CallerProcessId '+$CallerProcessId+' -CallerCreationFileTime '+$CallerCreationFileTime+
            " -CallerSid '"+$CallerSid+"' -ServiceSid '"+$ServiceSid+"'"
    }
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $name -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $name
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
        while(-not (Test-Path -LiteralPath $output) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $output)){throw 'Independent observer receipt absent'}
        $observed=Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $name -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Owned observer cleanup failed'}
        }
    }
    [pscustomobject]@{independent=$observed;observer_task_removed=$true}
}
