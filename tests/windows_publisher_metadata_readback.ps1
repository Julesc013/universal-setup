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
    param([string]$DriveRoot,[string]$OutputRoot,[string]$RunId,[switch]$MetadataOnly)
    if($DriveRoot -cnotmatch '^[A-Z]:\\$' -or $RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Exact observed volume alias and owned observer identity required'
    }
    $name='USK_METADATA_OBSERVER_'+$RunId
    $script=Join-Path $OutputRoot ('metadata-observer-'+$RunId+'.ps1')
    $output=Join-Path $OutputRoot ('metadata-observed-'+$RunId+'.json')
    if((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $script) -or (Test-Path -LiteralPath $output)) { throw 'Observer collision' }
    $observer=@'
param([string]$Output,[string]$DriveRoot,[switch]$MetadataOnly)
$ErrorActionPreference='Stop'
 Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
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
"@

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
  $rows.Add([ordered]@{path=$p.FullName;directory=$p.PSIsContainer;
   file_id=[string]$facts[0];native_name=[string]$facts[8];attributes=[uint32]$facts[2];
   link_count=[uint32]$facts[3];case_sensitive=[bool]$facts[4];streams=@($facts[5]);raw_aces=$rawAces;
   raw_security=$raw.GetSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access);owner=$raw.Owner.Value;protected=[bool]($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected);aces=$aces;
   bytes=[long]$facts[7];sha256=$facts[6];
   content_json=$(if(-not $p.PSIsContainer -and $p.Extension -eq '.json'){[IO.File]::ReadAllText($p.FullName)}else{$null})})
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
'@
    [IO.File]::WriteAllText($script,$observer,[Text.UTF8Encoding]::new($false))
    # Use the installed SYSTEM policy without changing execution policy. The
    # reviewed script is passed as data to a -Command script block.
    $command="& ([scriptblock]::Create([IO.File]::ReadAllText('"+$script.Replace("'","''")+"'))) -Output '"+
        $output.Replace("'","''")+"' -DriveRoot '"+$DriveRoot+"'"
    if($MetadataOnly){$command+=' -MetadataOnly'}
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
