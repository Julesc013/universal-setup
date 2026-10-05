# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Initialize-PublisherMetadataNativeTypes {
    if('UskPublisherEffectiveRights' -as [type]){return}
    $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1'))
    $marker='Add-Type -TypeDefinition @'+'"'
    $start=$source.IndexOf($marker,[StringComparison]::Ordinal)
    if($start -lt 0){throw 'Independent native readback source is absent'}
    $start+=$marker.Length
    $end=$source.IndexOf("`n"+'"@',$start,[StringComparison]::Ordinal)
    if($end -le $start){throw 'Independent native readback source is incomplete'}
    Add-Type -TypeDefinition $source.Substring($start,$end-$start)
}
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
    if($prepared.schema -cnotin @('usk.publisher.lab_phase_evidence.v2','usk.publisher.lab_phase_evidence.v3','usk.publisher.lab_phase_evidence.v4','usk.publisher.lab_phase_evidence.v5','usk.publisher.lab_phase_evidence.v6','usk.publisher.lab_phase_evidence.v7','usk.publisher.lab_phase_evidence.v8','usk.publisher.lab_phase_evidence.v9') -or
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
        if($visibleRows[0].directory -or $visible.schema -cne $prepared.schema -or
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
    param($Result,[switch]$AllowPartialConsumerGrant,[switch]$RequireInstallationLease)
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
    $leaseFiles=@($publicFiles|Where-Object {$_.path.StartsWith(($drive+'setup-state\state\leases\'),[StringComparison]::Ordinal)})
    $contextFiles=@($Result.independent.rows|Where-Object {$_.path.StartsWith(($drive+'installation-operations\'),[StringComparison]::Ordinal)})
    if($RequireInstallationLease -or $leaseFiles.Count -gt 0 -or $contextFiles.Count -gt 0) {
        $leaseRequest=@{mode='snapshot';rows=$Result.independent.rows;drive=$drive;installed=$installed;
            volume_root_id=$Result.independent.volume_boundary.root.file_id;allow_active=[bool]$AllowPartialConsumerGrant}
        $leaseOutput=$leaseRequest|ConvertTo-Json -Depth 64 -Compress|
            & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_installation_lease_evidence.py') --input -
        if($LASTEXITCODE -ne 0){throw 'Independent installation lease/context closure differs'}
        $leaseReport=($leaseOutput -join "`n")|ConvertFrom-Json
        $expected+=@($leaseReport.coordination.files|Where-Object {$_.StartsWith(($drive+'setup-state\'),[StringComparison]::Ordinal)})
    }
    if ($publicFiles.Count -ne $expected.Count -or @($publicFiles|Where-Object {$_.path -cnotin $expected}).Count -ne 0) { throw 'Independent public record closure differs' }
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
        [string]$CallerSid='',[string]$ServiceSid='',
        [string]$ClientCaptureFile='',[string]$ClientCaptureSha256='',
        [string]$ExpectedVolumeRoot='',[uint32]$ExpectedDiskNumber=[uint32]::MaxValue,
        [string]$AbsentPublicationPreservationPrefix='',
        [string]$AbsentPublicationReservationPrefix='',
        [ValidateSet(0,1,2)][int]$AbsentPublicationReservationGeneration=0)
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
    if(($ClientCaptureFile -ne '') -ne ($ClientCaptureSha256 -ne '') -or
        ($ClientCaptureFile -and ($CallerProcessId -eq 0 -or $MetadataOnly -or
            $ClientCaptureSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [IO.Path]::GetFullPath($ClientCaptureFile) -cne [IO.Path]::GetFullPath((Join-Path $OutputRoot 'public-client-token.json'))))) {
        throw 'Held machine-client observation requires the exact owned capture file and digest'
    }
    if(($ExpectedVolumeRoot -ne '') -ne ($ExpectedDiskNumber -ne [uint32]::MaxValue) -or
        ($ExpectedVolumeRoot -and (-not $ClientCaptureFile -or
            $ExpectedVolumeRoot -cnotmatch '^\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\$'))) {
        throw 'Volume boundary observation requires the complete held-client and volume binding'
    }
    if($AbsentPublicationPreservationPrefix -and ($MetadataOnly -or -not $ExpectedVolumeRoot -or
        -not $ClientCaptureFile -or $CallerProcessId -eq 0 -or
        $AbsentPublicationPreservationPrefix -cnotmatch ('^'+[regex]::Escape($DriveRoot)+
            'installation-operations\\install-[0-9a-f]{64}\\operation-[0-9a-f]{64}$'))) {
        throw 'Publication-absent readback requires the bound preservation operation and volume'
    }
    if(($AbsentPublicationReservationPrefix -ne '') -ne ($AbsentPublicationReservationGeneration -ne 0) -or
        ($AbsentPublicationReservationPrefix -and ($AbsentPublicationPreservationPrefix -or $MetadataOnly -or
            -not $ExpectedVolumeRoot -or -not $ClientCaptureFile -or $CallerProcessId -eq 0 -or
            $AbsentPublicationReservationPrefix -cnotmatch ('^'+[regex]::Escape($DriveRoot)+
                'installation-operations\\install-[0-9a-f]{64}\\operation-[0-9a-f]{64}$')))) {
        throw 'Publication reserved-absence readback requires its exact generation, operation and native volume'
    }
    $name='USK_METADATA_OBSERVER_'+$RunId
    $script=Join-Path $OutputRoot ('metadata-observer-'+$RunId+'.ps1')
    $output=Join-Path $OutputRoot ('metadata-observed-'+$RunId+'.json')
    if((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $script) -or (Test-Path -LiteralPath $output)) { throw 'Observer collision' }
    $observer=@'
param([string]$Output,[string]$DriveRoot,[switch]$MetadataOnly,
    [uint32]$CallerProcessId=0,[string]$CallerCreationFileTime='',[string]$CallerSid='',[string]$ServiceSid='',
    [string]$ClientCaptureFile='',[string]$ClientCaptureSha256='',
    [string]$ExpectedVolumeRoot='',[uint32]$ExpectedDiskNumber=[uint32]::MaxValue,
    [string]$AbsentPublicationPreservationPrefix='',
        [string]$AbsentPublicationReservationPrefix='',
        [ValidateSet(0,1,2)][int]$AbsentPublicationReservationGeneration=0)
$ErrorActionPreference='Stop'
function Test-PublisherHeldCaptureRequestContext([string]$RequestId,[string]$Command) {
    return (($RequestId -cmatch '^public\.[0-9a-f]{32}$' -and
        $Command -cin @('install_local.apply','install_local.recover','installed.verify')) -or
        ($RequestId -cmatch '^contention\.[0-9a-f]{32}$' -and $Command -ceq 'registered_contention'))
}
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
 public static uint RequireAbsentLeaf(string path) {
  using(var h=CreateFile(path,0x80,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
   int error=Marshal.GetLastWin32Error();
   if(!h.IsInvalid || error!=2)
    throw new InvalidOperationException("Independent leaf absence is not ERROR_FILE_NOT_FOUND: "+error);
   return (uint)error;
  }
 }
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetProcessId(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source,
        IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(
        IntPtr process, uint flags, StringBuilder path, ref uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool GetVolumeNameForVolumeMountPoint(
        string mount, StringBuilder volume, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DeviceIoControl(IntPtr device, uint code,
        IntPtr input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
    [DllImport("advapi32.dll", EntryPoint="LogonUserW", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LogonUser(
        string account, string domain, IntPtr password, uint kind, uint provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetHandleInformation(IntPtr handle, out uint flags);
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
    IntPtr process, initiating, filtered, capturedProcess, unrelated;
    readonly List<IntPtr> pendingTokens=new List<IntPtr>();
    public Dictionary<string, object> TokenFacts { get; private set; }

    static void Require(bool ok, string operation) {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }
    static Dictionary<string, object> Facts(IntPtr token) {
        Dictionary<string, object> result = new Dictionary<string, object>();
        foreach (int information in new int[]{1, 2, 3, 10}) {
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
                } else if(information==10) {
                    if(needed<56)throw new Exception("Token statistics are incomplete");
                    result["token_id"]=unchecked((ulong)Marshal.ReadInt64(buffer,0)).ToString("x16");
                    result["authentication_id"]=unchecked((ulong)Marshal.ReadInt64(buffer,8)).ToString("x16");
                    int tokenType=Marshal.ReadInt32(buffer,24);
                    if(tokenType!=1 && tokenType!=2)throw new Exception("Observed token type is unsupported");
                    result["token_type"]=tokenType;
                    result["impersonation_level"]=tokenType==2 ? (object)Marshal.ReadInt32(buffer,28) : null;
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
    public static Dictionary<string,object> ObserveOwnedStandardPrimary(IntPtr token, string expectedSid) {
        Dictionary<string,object> facts=Facts(token);
        if((string)facts["user_sid"]!=expectedSid || (int)facts["token_type"]!=1 ||
            !expectedSid.StartsWith("S-1-5-21-",StringComparison.Ordinal))
            throw new Exception("Owned standard primary token identity differs");
        foreach(Dictionary<string,object> group in (Dictionary<string,object>[])facts["groups"])
            if((string)group["sid"]=="S-1-5-32-544" || (string)group["sid"]=="S-1-5-18" ||
                ((string)group["sid"]).StartsWith("S-1-5-80-",StringComparison.Ordinal))
                throw new Exception("Owned standard primary token contains privileged/service membership");
        foreach(Dictionary<string,object> privilege in (Dictionary<string,object>[])facts["privileges"])
            if(Array.IndexOf(new string[]{"SeBackupPrivilege","SeRestorePrivilege","SeDebugPrivilege","SeImpersonatePrivilege",
                "SeAssignPrimaryTokenPrivilege","SeTcbPrivilege","SeLoadDriverPrivilege","SeCreateTokenPrivilege",
                "SeTakeOwnershipPrivilege","SeManageVolumePrivilege","SeRelabelPrivilege","SeSecurityPrivilege",
                "SeDelegateSessionUserImpersonatePrivilege"},(string)privilege["name"])>=0 ||
                (((uint)privilege["attributes"] & 2)!=0 && (string)privilege["name"]!="SeChangeNotifyPrivilege"))
                throw new Exception("Owned standard primary token retains a bypass privilege");
        return facts;
    }
    public static Dictionary<string,object> ObserveOwnedStandardLauncher() {
        IntPtr token=IntPtr.Zero;
        try {
            Require(OpenProcessToken(GetCurrentProcess(),8,out token),"Read owned standard launcher token");
            Dictionary<string,object> facts=Facts(token);
            if((string)facts["user_sid"]!="S-1-5-18" || (int)facts["token_type"]!=1)
                throw new Exception("Owned standard launcher is not SYSTEM");
            foreach(string required in new string[]{"SeAssignPrimaryTokenPrivilege","SeIncreaseQuotaPrivilege"}) {
                bool found=false;
                foreach(Dictionary<string,object> privilege in (Dictionary<string,object>[])facts["privileges"])
                    if((string)privilege["name"]==required && (((uint)privilege["attributes"] & 4)==0))found=true;
                if(!found)throw new Exception("Owned standard launcher lacks its documented creation privilege");
            }
            return facts;
        } finally {if(token!=IntPtr.Zero)Require(CloseHandle(token),"Close owned launcher token query");}
    }
    static void ValidateUnrelated(Dictionary<string,object> facts, string expectedSid, string callerSid, string serviceSid) {
        if(String.IsNullOrEmpty(expectedSid) || expectedSid==callerSid || expectedSid==serviceSid ||
            expectedSid=="S-1-5-18" || expectedSid=="S-1-5-32-544" ||
            (string)facts["user_sid"]!=expectedSid || (int)facts["token_type"]!=2 ||
            (int)facts["impersonation_level"]!=2 || EnabledGroup(facts,"S-1-5-32-544") ||
            EnabledGroup(facts,"S-1-5-18") || EnabledGroup(facts,serviceSid))
            throw new Exception("Unrelated local-login token has foreign or privileged authority");
        foreach(Dictionary<string,object> privilege in (Dictionary<string,object>[])facts["privileges"])
            if(((uint)privilege["attributes"] & 2)!=0 && (string)privilege["name"]!="SeChangeNotifyPrivilege")
                throw new Exception("Unrelated local-login token retains a mutation/bypass privilege");
    }
    // Authentication is permitted only for the fixture's generated account.
    // This token is never impersonated and never used for native mutation.
    public Dictionary<string,object> HoldOwnedLocalLogin(string account, System.Security.SecureString password,
        string expectedSid, string serviceSid) {
        if(process==IntPtr.Zero || WaitForSingleObject(process,0)!=258 || unrelated!=IntPtr.Zero ||
            !System.Text.RegularExpressions.Regex.IsMatch(account ?? "", "^USKOBS_[0-9a-f]{13}$") ||
            password==null || password.Length<16 || String.IsNullOrEmpty(expectedSid) ||
            !expectedSid.StartsWith("S-1-5-21-",StringComparison.Ordinal))
            throw new Exception("Owned local-login binding is incomplete or already held");
        IntPtr secret=IntPtr.Zero, primary=IntPtr.Zero, duplicate=IntPtr.Zero;
        try {
            secret=Marshal.SecureStringToGlobalAllocUnicode(password);
            Require(LogonUser(account,".",secret,2,0,out primary),"Authenticate owned local interactive login");
            Require(DuplicateToken(primary,2,out duplicate),"Hold owned local-login AccessCheck token");
            uint flags;Require(GetHandleInformation(duplicate,out flags),"Read local-login handle flags");
            if((flags & 1)!=0)throw new Exception("Local-login token handle is inheritable");
            Dictionary<string,object> facts=Facts(duplicate);
            ValidateUnrelated(facts,expectedSid,(string)((Dictionary<string,object>)TokenFacts["initiating"])["user_sid"],serviceSid);
            unrelated=duplicate;duplicate=IntPtr.Zero;TokenFacts["unrelated"]=facts;
            return new Dictionary<string,object>{{"account_name",account},{"user_sid",expectedSid},
                {"token_handle",unrelated.ToInt64()},{"token_id",facts["token_id"]},
                {"authentication_id",facts["authentication_id"]},{"logon_type",2},
                {"basis","actual LogonUserW local interactive token; DuplicateToken for read-only AccessCheck"}};
        } finally {
            try {if(secret!=IntPtr.Zero)Marshal.ZeroFreeGlobalAllocUnicode(secret);}
            finally {
                Exception failure=null;CloseTemporary(ref primary,ref failure);CloseTemporary(ref duplicate,ref failure);
                if(failure!=null)throw failure;
            }
        }
    }
    public void BindUnrelatedToken(long handle, string tokenId, string authenticationId, string expectedSid, string serviceSid) {
        if(process==IntPtr.Zero || WaitForSingleObject(process,0)!=258 || unrelated!=IntPtr.Zero || handle<=0 ||
            String.IsNullOrEmpty(tokenId) || String.IsNullOrEmpty(authenticationId))
            throw new Exception("Retained unrelated-login token binding is incomplete");
        IntPtr duplicate=IntPtr.Zero;
        try {
            Require(DuplicateHandle(process,new IntPtr(handle),GetCurrentProcess(),out duplicate,0,false,2),"Duplicate held unrelated-login token");
            Dictionary<string,object> facts=Facts(duplicate);
            ValidateUnrelated(facts,expectedSid,(string)((Dictionary<string,object>)TokenFacts["initiating"])["user_sid"],serviceSid);
            if((string)facts["token_id"]!=tokenId || (string)facts["authentication_id"]!=authenticationId ||
                (string)facts["authentication_id"]==(string)((Dictionary<string,object>)TokenFacts["initiating"])["authentication_id"])
                throw new Exception("Retained unrelated-login token or authentication identity differs");
            unrelated=duplicate;duplicate=IntPtr.Zero;TokenFacts["unrelated"]=facts;
        } finally {Exception failure=null;CloseTemporary(ref duplicate,ref failure);if(failure!=null)throw failure;}
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
        finally {
            Exception failure=null;CloseTemporary(ref source,ref failure);CloseTemporary(ref derivative,ref failure);
            if(failure!=null){try {Dispose();}finally {throw failure;}}
        }
    }
    // Export only owned, non-inheritable token/process handles to the trusted
    // SYSTEM observer. These are client-token duplicates, never publisher
    // service or protected filesystem handles. Capture must finish while the
    // real machine client is alive; a missed window fails qualification.
    public Dictionary<string, object> CaptureBinding(uint ownerPid, long ownerCreation, string expectedImage) {
        if(process==IntPtr.Zero || WaitForSingleObject(process,0)!=258)throw new Exception("Client exited before token capture");
        StringBuilder image=new StringBuilder(32768);uint size=32768;
        Require(QueryFullProcessImageName(process,0,image,ref size),"Read live captured client image");
        if(!String.Equals(image.ToString(),Path.GetFullPath(expectedImage),StringComparison.OrdinalIgnoreCase))
            throw new Exception("Captured client image differs from the invoked machine binary");
        if(WaitForSingleObject(process,0)!=258)throw new Exception("Client exited during token capture");
        return new Dictionary<string, object>{{"schema","usk.publisher.held_client_token.v1"},
            {"owner_process_id",ownerPid},{"owner_creation_file_time",ownerCreation.ToString()},
            {"client_process_id",TokenFacts["process_id"]},{"client_creation_file_time",TokenFacts["creation_file_time"]},
            {"client_image_path",image.ToString()},{"client_process_handle",process.ToInt64()},
            {"initiating_handle",initiating.ToInt64()},{"filtered_handle",filtered.ToInt64()},
            {"initiating_token_id",((Dictionary<string,object>)TokenFacts["initiating"])["token_id"]},
            {"filtered_token_id",((Dictionary<string,object>)TokenFacts["filtered"])["token_id"]}};
    }
    public UskPublisherEffectiveRights(uint ownerPid, long ownerCreation, string callerSid, string serviceSid,
        uint clientPid, long clientCreation, long clientProcessHandle, long initiatingHandle, long filteredHandle,
        string initiatingId, string filteredId) {
        try {
            if(clientPid==0 || clientProcessHandle<=0 || initiatingHandle<=0 || filteredHandle<=0 ||
                String.IsNullOrEmpty(initiatingId) || String.IsNullOrEmpty(filteredId))throw new Exception("Held client token binding is incomplete");
            process=OpenProcess(0x101040,false,ownerPid);
            Require(process!=IntPtr.Zero,"Hold client-token owner process");
            long observed,exit,kernel,user;
            Require(GetProcessTimes(process,out observed,out exit,out kernel,out user),"Read client-token owner creation");
            if(observed!=ownerCreation || WaitForSingleObject(process,0)!=258)throw new Exception("Client-token owner changed or exited");
            Require(DuplicateHandle(process,new IntPtr(clientProcessHandle),GetCurrentProcess(),out capturedProcess,0,false,2),"Duplicate held client process");
            Require(GetProcessTimes(capturedProcess,out observed,out exit,out kernel,out user),"Read retained client creation");
            if(GetProcessId(capturedProcess)!=clientPid || observed!=clientCreation)throw new Exception("Retained client identity differs");
            Require(DuplicateHandle(process,new IntPtr(initiatingHandle),GetCurrentProcess(),out initiating,0,false,2),"Duplicate held actual client token");
            Require(DuplicateHandle(process,new IntPtr(filteredHandle),GetCurrentProcess(),out filtered,0,false,2),"Duplicate held filtered client token");
            Dictionary<string,object> initialFacts=Facts(initiating),filteredFacts=Facts(filtered);
            if((string)initialFacts["token_id"]!=initiatingId || (string)filteredFacts["token_id"]!=filteredId ||
                (string)initialFacts["user_sid"]!=callerSid || (string)filteredFacts["user_sid"]!=callerSid ||
                (int)initialFacts["token_type"]!=2 || (int)filteredFacts["token_type"]!=2 ||
                (int)initialFacts["impersonation_level"]<1 || (int)filteredFacts["impersonation_level"]<1 ||
                callerSid=="S-1-5-18" || callerSid==serviceSid || EnabledGroup(filteredFacts,"S-1-5-32-544") ||
                EnabledGroup(filteredFacts,"S-1-5-18") || EnabledGroup(filteredFacts,serviceSid))
                throw new Exception("Held client token identity or filtered authority differs");
            foreach(Dictionary<string,object> privilege in (Dictionary<string,object>[])filteredFacts["privileges"])
                if(((uint)privilege["attributes"] & 2)!=0 && (string)privilege["name"]!="SeChangeNotifyPrivilege")
                    throw new Exception("Held filtered client retains a mutation/bypass privilege");
            TokenFacts=new Dictionary<string,object>{{"process_id",ownerPid},{"creation_file_time",ownerCreation.ToString()},
                {"basis","retained live machine-client token duplicates; explicit filtered derivative; SYSTEM DuplicateHandle readback"},
                {"captured_client",new Dictionary<string,object>{{"process_id",clientPid},{"creation_file_time",clientCreation.ToString()},
                    {"initiating_token_id",initiatingId},{"filtered_token_id",filteredId},{"exited_at_observation",WaitForSingleObject(capturedProcess,0)==0}}},
                {"initiating",initialFacts},{"filtered",filteredFacts}};
        } catch {Dispose();throw;}
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
        Dictionary<string,object> checks=new Dictionary<string,object>{{"initiating",Check(descriptor,initiating)},{"filtered",Check(descriptor,filtered)}};
        if(unrelated!=IntPtr.Zero)checks["unrelated"]=Check(descriptor,unrelated);
        return checks;
    }
    static string OwnerDaclDigest(IntPtr held, RawSecurityDescriptor observed) {
        uint needed;
        if(GetKernelObjectSecurity(held,5,null,0,out needed) || Marshal.GetLastWin32Error()!=122 || needed<20 || needed>65536)
            throw new Exception("Held owner/DACL digest size unavailable or unbounded");
        byte[] bytes=new byte[needed];uint returned;
        Require(GetKernelObjectSecurity(held,5,bytes,needed,out returned),"Read held owner/DACL digest bytes");
        if(returned!=needed)throw new Exception("Held owner/DACL digest changed during observation");
        RawSecurityDescriptor raw=new RawSecurityDescriptor(bytes,0);
        var sections=AccessControlSections.Owner|AccessControlSections.Access;
        if(raw.GetSddlForm(sections)!=observed.GetSddlForm(sections))
            throw new Exception("Held owner/DACL digest differs from access observation");
        using(var sha=System.Security.Cryptography.SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();
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
                {"owner_dacl_sha256",OwnerDaclDigest(file,raw)},
                {"group_sid",raw.Group==null ? null : raw.Group.Value},{"checks",CheckDescriptor(bytes)}};
        } finally {CloseHandle(file);}
    }
    public static Dictionary<string, object> ParseSingleExtent(byte[] bytes, uint returned, uint expectedDisk) {
        // VOLUME_DISK_EXTENTS with its single 8-byte-aligned DISK_EXTENT.
        if(bytes==null || returned!=32 || returned>bytes.Length || BitConverter.ToUInt32(bytes,0)!=1 ||
            BitConverter.ToUInt32(bytes,8)!=expectedDisk || BitConverter.ToInt64(bytes,16)<0 ||
            BitConverter.ToInt64(bytes,24)<=0 || BitConverter.ToInt64(bytes,16)>Int64.MaxValue-BitConverter.ToInt64(bytes,24))
            throw new Exception("Raw volume single-extent binding is unavailable or differs");
        return new Dictionary<string,object>{{"disk_number",expectedDisk},{"offset",BitConverter.ToInt64(bytes,16)},
            {"length",BitConverter.ToInt64(bytes,24)}};
    }
    public Dictionary<string, object> ReadVolumeDevice(string driveRoot, string expectedVolume, uint expectedDisk) {
        StringBuilder volume=new StringBuilder(64);
        Require(GetVolumeNameForVolumeMountPoint(driveRoot,volume,64),"Read observed drive volume GUID");
        if(!String.Equals(volume.ToString(),expectedVolume,StringComparison.OrdinalIgnoreCase))
            throw new Exception("Observed drive differs from the owned volume GUID");
        string path=expectedVolume.TrimEnd('\\');
        IntPtr device=CreateFile(path,0x20000,7,IntPtr.Zero,3,0,IntPtr.Zero);
        Require(device!=new IntPtr(-1),"Hold read-only raw volume descriptor");
        try {
            byte[] extent=new byte[32];uint returned;
            Require(DeviceIoControl(device,0x00560000,IntPtr.Zero,0,extent,32,out returned,IntPtr.Zero),"Read held raw volume extent");
            Dictionary<string,object> binding=ParseSingleExtent(extent,returned,expectedDisk);
            uint needed;
            if(GetKernelObjectSecurity(device,7,null,0,out needed) || Marshal.GetLastWin32Error()!=122 || needed<20 || needed>65536)
                throw new Exception("Raw volume descriptor size unavailable or unbounded");
            byte[] bytes=new byte[needed];
            Require(GetKernelObjectSecurity(device,7,bytes,needed,out returned),"Read held raw volume owner/group/DACL");
            if(returned!=needed)throw new Exception("Raw volume descriptor changed during observation");
            RawSecurityDescriptor raw=new RawSecurityDescriptor(bytes,0);
            // Only descriptor/token rights are measured; no write or mutating
            // device control is attempted, and FILE_ANY_ACCESS IOCTL behaviour
            // is outside this observation.
            return new Dictionary<string,object>{{"path",path},{"extent",binding},
                {"raw_security",raw.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access)},
                {"owner_dacl_sha256",OwnerDaclDigest(device,raw)},
                {"checks",CheckDescriptor(bytes)},{"basis","held volume-device descriptor and single extent; file generic mapping; no mutating IOCTL"}};
        } finally {CloseHandle(device);}
    }
    static void CloseOwned(ref IntPtr handle, ref Exception failure) {
        if(handle==IntPtr.Zero)return;
        if(CloseHandle(handle))handle=IntPtr.Zero;
        else if(failure==null)failure=new Win32Exception(Marshal.GetLastWin32Error(),"Close owned effective-right token/process handle");
    }
    void CloseTemporary(ref IntPtr handle, ref Exception failure) {
        CloseOwned(ref handle,ref failure);
        // A failed close remains owned by this lease, so Dispose can retry it
        // and cannot acknowledge completion while any duplicate remains.
        if(handle!=IntPtr.Zero){pendingTokens.Add(handle);handle=IntPtr.Zero;}
    }
    public void Dispose() {
        Exception failure=null;
        CloseOwned(ref unrelated,ref failure);CloseOwned(ref capturedProcess,ref failure);
        CloseOwned(ref filtered,ref failure);CloseOwned(ref initiating,ref failure);CloseOwned(ref process,ref failure);
        for(int index=0;index<pendingTokens.Count;index++) {
            IntPtr token=pendingTokens[index];CloseOwned(ref token,ref failure);pendingTokens[index]=token;
        }
        if(failure!=null)throw failure;
    }
}

public static class UskPublisherServiceSecurityReadback {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool QueryServiceObjectSecurity(IntPtr service,uint information,byte[] bytes,uint size,out uint needed);
    [DllImport("advapi32.dll")]static extern bool CloseServiceHandle(IntPtr handle);
    public static string Read(string name) {
        if(!System.Text.RegularExpressions.Regex.IsMatch(name ?? "","^USK_PUB_[0-9a-f]{32}$"))
            throw new Exception("Owned service security name differs");
        IntPtr manager=IntPtr.Zero,service=IntPtr.Zero;
        try {
            manager=OpenSCManager(null,null,1);
            if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error(),"Read owned SCM");
            service=OpenService(manager,name,0x20000);
            if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error(),"Read owned service security");
            uint size;
            if(QueryServiceObjectSecurity(service,5,null,0,out size) || Marshal.GetLastWin32Error()!=122 || size<20 || size>1024*1024)
                throw new Exception("Owned service security size unavailable");
            byte[] bytes=new byte[size];uint returned;
            if(!QueryServiceObjectSecurity(service,5,bytes,size,out returned) || returned>size)
                throw new Win32Exception(Marshal.GetLastWin32Error(),"Read owned service owner/DACL");
            RawSecurityDescriptor descriptor=new RawSecurityDescriptor(bytes,0);
            return descriptor.GetSddlForm(AccessControlSections.Owner|AccessControlSections.Access);
        } finally {
            try {if(service!=IntPtr.Zero && !CloseServiceHandle(service))throw new Exception("Owned service query handle close failed");}
            finally {if(manager!=IntPtr.Zero && !CloseServiceHandle(manager))throw new Exception("Owned manager query handle close failed");}
        }
    }
}
public sealed class UskPublisherPausedClient : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public uint Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [StructLayout(LayoutKind.Sequential)] struct Startup {
        public uint Size;public IntPtr Reserved,Desktop,Title;
        public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
        public ushort Show,ReservedCount;public IntPtr ReservedBytes,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup Info;public IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread;public uint ProcessId,ThreadId; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFile(string path,uint access,uint share,ref SecurityAttributes security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool InitializeProcThreadAttributeList(IntPtr list,uint count,uint flags,ref IntPtr size);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")]static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcess(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupEx startup,out ProcessInfo process);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcessAsUser(IntPtr token,string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref StartupEx startup,out ProcessInfo process);
    [DllImport("advapi32.dll",EntryPoint="LogonUserW",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool LogonUser(string account,string domain,IntPtr password,int type,int provider,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",EntryPoint="GetTokenInformation",SetLastError=true)]static extern bool GetTokenSession(IntPtr token,int information,out uint session,uint size,out uint returned);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool ProcessIdToSessionId(uint process,out uint session);
    [DllImport("userenv.dll",SetLastError=true)]static extern bool CreateEnvironmentBlock(out IntPtr environment,IntPtr token,bool inherit);
    [DllImport("userenv.dll",SetLastError=true)]static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true)]static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(IntPtr process,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool TerminateProcess(IntPtr process,uint exit);
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr handle);
    IntPtr process,thread,ownedLoginPrimary,pendingEnvironment;bool resumed;
    readonly List<IntPtr> pendingHandles=new List<IntPtr>();
    public uint ProcessId {get;private set;}
    public long CreationFileTime {get;private set;}
    public bool IsResumed {get{return resumed;}}
    public Dictionary<string,object> OwnedStandardPrimaryFacts {get;private set;}
    public Dictionary<string,object> OwnedStandardLauncherFacts {get;private set;}
    static void Require(bool ok,string operation){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error(),operation);}
    public UskPublisherPausedClient(string image,string arguments,string stdout,string stderr)
        : this(image,arguments,stdout,stderr,IntPtr.Zero,null) {}
    public static UskPublisherPausedClient CreateOwnedStandard(string image,string arguments,string stdout,string stderr,
        string account,System.Security.SecureString password,string expectedSid) {
        if(!System.Text.RegularExpressions.Regex.IsMatch(account ?? "","^USKCLI_[0-9a-f]{13}$") ||
            password==null || password.Length<16 || String.IsNullOrEmpty(expectedSid))
            throw new Exception("Owned standard login binding is incomplete");
        IntPtr secret=IntPtr.Zero,token=IntPtr.Zero;
        try {
            Dictionary<string,object> launcher=UskPublisherEffectiveRights.ObserveOwnedStandardLauncher();
            secret=Marshal.SecureStringToGlobalAllocUnicode(password);
            Require(LogonUser(account,".",secret,2,0,out token),"Authenticate owned standard client");
            Dictionary<string,object> login=UskPublisherEffectiveRights.ObserveOwnedStandardPrimary(token,expectedSid);
            uint session,returned,ownerSession;
            Require(GetTokenSession(token,12,out session,4,out returned),"Read owned login session");
            Require(ProcessIdToSessionId((uint)System.Diagnostics.Process.GetCurrentProcess().Id,out ownerSession),"Read owned launcher session");
            if(returned!=4 || session!=ownerSession)throw new Exception("Owned standard stdio inheritance crosses sessions");
            UskPublisherPausedClient launch=new UskPublisherPausedClient(image,arguments,stdout,stderr,token,expectedSid);
            launch.ownedLoginPrimary=token;token=IntPtr.Zero;
            launch.OwnedStandardLauncherFacts=launcher;
            if((string)launch.OwnedStandardPrimaryFacts["authentication_id"]!=(string)login["authentication_id"]) {
                launch.Dispose();throw new Exception("Owned standard client authentication identity differs from login");
            }
            return launch;
        } finally {
            if(secret!=IntPtr.Zero)Marshal.ZeroFreeGlobalAllocUnicode(secret);
            if(token!=IntPtr.Zero)Require(CloseHandle(token),"Close owned standard login primary token");
        }
    }
    UskPublisherPausedClient(string image,string arguments,string stdout,string stderr,IntPtr primary,string expectedSid) {
        IntPtr input=IntPtr.Zero,output=IntPtr.Zero,error=IntPtr.Zero,list=IntPtr.Zero,handles=IntPtr.Zero,environment=IntPtr.Zero;bool initialized=false;
        try {
            image=Path.GetFullPath(image);stdout=Path.GetFullPath(stdout);stderr=Path.GetFullPath(stderr);
            if(image.IndexOf('"')>=0 || !File.Exists(image) || String.Equals(stdout,stderr,StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(Path.GetDirectoryName(stdout),Path.GetDirectoryName(stderr),StringComparison.OrdinalIgnoreCase))
                throw new Exception("Owned paused client image/output binding is invalid");
            StringBuilder command=new StringBuilder("\""+image+"\" "+arguments);
            if(command.Length>=32767)throw new Exception("Owned paused client command exceeds its bound");
            SecurityAttributes security=new SecurityAttributes{Length=(uint)Marshal.SizeOf(typeof(SecurityAttributes)),Inherit=true};
            input=CreateFile("NUL",0x80000000,3,ref security,3,0,IntPtr.Zero);Require(input!=new IntPtr(-1),"Open owned client input");
            output=CreateFile(stdout,0x40000000,1,ref security,1,0x80,IntPtr.Zero);Require(output!=new IntPtr(-1),"Create owned client output");
            error=CreateFile(stderr,0x40000000,1,ref security,1,0x80,IntPtr.Zero);Require(error!=new IntPtr(-1),"Create owned client error output");
            IntPtr size=IntPtr.Zero;
            if(InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size) || Marshal.GetLastWin32Error()!=122 || size.ToInt64()<1 || size.ToInt64()>65536)
                throw new Exception("Owned client inheritance list size is unavailable");
            list=Marshal.AllocHGlobal(size);Require(InitializeProcThreadAttributeList(list,1,0,ref size),"Initialize owned client handle list");initialized=true;
            handles=Marshal.AllocHGlobal(3*IntPtr.Size);Marshal.WriteIntPtr(handles,0,input);Marshal.WriteIntPtr(handles,IntPtr.Size,output);Marshal.WriteIntPtr(handles,2*IntPtr.Size,error);
            Require(UpdateProcThreadAttribute(list,0,new IntPtr(0x20002),handles,new IntPtr(3*IntPtr.Size),IntPtr.Zero,IntPtr.Zero),"Bind only owned client stdio handles");
            StartupEx startup=new StartupEx{Info=new Startup{Size=(uint)Marshal.SizeOf(typeof(StartupEx)),Flags=0x100,Input=input,Output=output,Error=error},Attributes=list};
            ProcessInfo created;
            // CREATE_SUSPENDED, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT.
            if(primary==IntPtr.Zero) {
                Require(CreateProcess(image,command,IntPtr.Zero,IntPtr.Zero,true,0x08080004,IntPtr.Zero,Path.GetDirectoryName(stdout),ref startup,out created),"Create owned paused client");
            } else {
                Require(CreateEnvironmentBlock(out environment,primary,false),"Create isolated owned standard environment");
                Require(CreateProcessAsUser(primary,image,command,IntPtr.Zero,IntPtr.Zero,true,0x08080404,environment,Path.GetDirectoryName(stdout),ref startup,out created),"Create owned standard paused client");
            }
            process=created.Process;thread=created.Thread;ProcessId=created.ProcessId;
            long creation,exit,kernel,user;Require(GetProcessTimes(process,out creation,out exit,out kernel,out user),"Read owned paused client creation");CreationFileTime=creation;
            if(primary!=IntPtr.Zero) {
                IntPtr actual=IntPtr.Zero;
                try {
                    Require(OpenProcessToken(process,8,out actual),"Read actual paused standard client token");
                    OwnedStandardPrimaryFacts=UskPublisherEffectiveRights.ObserveOwnedStandardPrimary(actual,expectedSid);
                } finally {if(actual!=IntPtr.Zero)Require(CloseHandle(actual),"Close actual paused standard token query");}
            }
            if(environment!=IntPtr.Zero) {
                Require(DestroyEnvironmentBlock(environment),"Close isolated standard environment");environment=IntPtr.Zero;
            }
        } catch {Dispose();throw;}
        finally {
            if(initialized)DeleteProcThreadAttributeList(list);if(list!=IntPtr.Zero)Marshal.FreeHGlobal(list);if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);
            Exception failure=null;
            CloseTemporary(ref input,ref failure);CloseTemporary(ref output,ref failure);CloseTemporary(ref error,ref failure);
            if(environment!=IntPtr.Zero && !DestroyEnvironmentBlock(environment)) {
                pendingEnvironment=environment;
                if(failure==null)failure=new Win32Exception(Marshal.GetLastWin32Error(),"Close retained standard environment");
            }
            if(failure!=null) {try {Dispose();} catch(Exception cleanup) {throw new AggregateException(failure,cleanup);}throw failure;}
        }
    }
    void CloseTemporary(ref IntPtr handle,ref Exception failure) {
        if(handle==IntPtr.Zero || handle==new IntPtr(-1)){handle=IntPtr.Zero;return;}
        if(!CloseHandle(handle)) {pendingHandles.Add(handle);if(failure==null)failure=new Win32Exception(Marshal.GetLastWin32Error(),"Close owned client stdio handle");}
        handle=IntPtr.Zero;
    }
    static void CloseOwned(ref IntPtr handle,string operation,ref Exception failure) {
        if(handle==IntPtr.Zero)return;
        if(CloseHandle(handle))handle=IntPtr.Zero;
        else if(failure==null)failure=new Win32Exception(Marshal.GetLastWin32Error(),operation);
    }
    public void Resume() {
        if(resumed || thread==IntPtr.Zero)throw new Exception("Owned client primary thread can resume only once");
        uint prior=ResumeThread(thread);Require(prior!=0xffffffff,"Resume owned client primary thread");
        if(prior!=1)throw new Exception("Owned client suspension count differs");
        resumed=true;Exception failure=null;CloseOwned(ref thread,"Close resumed owned client thread",ref failure);if(failure!=null)throw failure;
    }
    public void Dispose() {
        if(process!=IntPtr.Zero && WaitForSingleObject(process,0)!=0) {
            if(resumed)throw new Exception("Owned resumed client is still live; launch handles retained");
            Require(TerminateProcess(process,125),"Terminate never-resumed owned client");
            if(WaitForSingleObject(process,5000)!=0)throw new Exception("Never-resumed owned client termination unconfirmed");
        }
        Exception failure=null;
        CloseOwned(ref thread,"Close owned client thread",ref failure);
        CloseOwned(ref process,"Close owned client process",ref failure);
        CloseOwned(ref ownedLoginPrimary,"Close owned standard login token",ref failure);
        for(int index=pendingHandles.Count-1;index>=0;--index) {
            if(CloseHandle(pendingHandles[index]))pendingHandles.RemoveAt(index);
            else if(failure==null)failure=new Win32Exception(Marshal.GetLastWin32Error(),"Close retained owned client stdio handle");
        }
        if(pendingEnvironment!=IntPtr.Zero) {
            if(DestroyEnvironmentBlock(pendingEnvironment))pendingEnvironment=IntPtr.Zero;
            else if(failure==null)failure=new Win32Exception(Marshal.GetLastWin32Error(),"Close retained standard environment");
        }
        if(failure!=null)throw failure;
    }
}

"@

$effectiveRights=$null
if($CallerProcessId -ne 0) {
 if($ClientCaptureFile) {
  $item=Get-Item -LiteralPath $ClientCaptureFile -Force -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 8KB -or
   [IO.Path]::GetFullPath($ClientCaptureFile) -cne [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Output) 'public-client-token.json')) -or
   (Get-FileHash -LiteralPath $ClientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ClientCaptureSha256) {
   throw 'Held client capture file identity or digest differs'
  }
  $capture=Get-Content -LiteralPath $ClientCaptureFile -Raw|ConvertFrom-Json
  if($capture.schema -cne 'usk.publisher.held_client_token.v1' -or
   $capture.owner_process_id -ne $CallerProcessId -or $capture.owner_creation_file_time -cne $CallerCreationFileTime -or
   $capture.client_creation_file_time -cnotmatch '^[1-9][0-9]{16,18}$' -or
   -not (Test-PublisherHeldCaptureRequestContext $capture.request_id $capture.command) -or
   $capture.client_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
   (Get-FileHash -LiteralPath $capture.client_image_path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $capture.client_sha256) {
   throw 'Held client capture context differs'
  }
  $effectiveRights=[UskPublisherEffectiveRights]::new($CallerProcessId,[long]$CallerCreationFileTime,$CallerSid,$ServiceSid,
   [uint32]$capture.client_process_id,[long]$capture.client_creation_file_time,[long]$capture.client_process_handle,
   [long]$capture.initiating_handle,[long]$capture.filtered_handle,[string]$capture.initiating_token_id,[string]$capture.filtered_token_id)
  $effectiveRights.TokenFacts['capture_context']=[ordered]@{schema=$capture.schema;image_path=$capture.client_image_path;
   image_sha256=$capture.client_sha256;capture_sha256=$ClientCaptureSha256;request_id=$capture.request_id;command=$capture.command;
   image_observation='live launcher capture; current file digest independently rechecked'}
  if($capture.unrelated_local_login) {
   $login=$capture.unrelated_local_login
   if($login.account_name -cnotmatch '^USKOBS_[0-9a-f]{13}$' -or $login.logon_type -ne 2 -or
    $login.user_sid -cnotmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' -or
    $login.token_id -cnotmatch '^[0-9a-f]{16}$' -or $login.authentication_id -cnotmatch '^[0-9a-f]{16}$') {
    throw 'Owned unrelated local-login context is incomplete'
   }
   $bindingRefusals=0
   foreach($variant in 0..6) {
    $badHandle=[long]$login.token_handle;$badToken=[string]$login.token_id
    $badAuthentication=[string]$login.authentication_id;$badSid=[string]$login.user_sid
    switch($variant) {
     0 {$badToken='0000000000000000'}
     1 {$badAuthentication='0000000000000000'}
     2 {$badSid=$CallerSid}
     3 {$badSid=$ServiceSid}
     4 {$badHandle=0}
     5 {$badHandle=[long]$capture.client_process_handle}
     6 {$badHandle=[long]$capture.filtered_handle}
    }
    $negative=$null
    try {
     $negative=[UskPublisherEffectiveRights]::new($CallerProcessId,[long]$CallerCreationFileTime,$CallerSid,$ServiceSid,
      [uint32]$capture.client_process_id,[long]$capture.client_creation_file_time,[long]$capture.client_process_handle,
      [long]$capture.initiating_handle,[long]$capture.filtered_handle,[string]$capture.initiating_token_id,[string]$capture.filtered_token_id)
     $negative.BindUnrelatedToken($badHandle,$badToken,$badAuthentication,$badSid,$ServiceSid)
     throw 'Contradictory unrelated-login binding was admitted'
    } catch {
     if($_.Exception.Message -ceq 'Contradictory unrelated-login binding was admitted'){throw}
     ++$bindingRefusals
    } finally {if($negative){$negative.Dispose()}}
   }
   $effectiveRights.BindUnrelatedToken([long]$login.token_handle,[string]$login.token_id,
    [string]$login.authentication_id,[string]$login.user_sid,$ServiceSid)
   $effectiveRights.TokenFacts['unrelated_logon_context']=[ordered]@{account_name=$login.account_name;
    user_sid=$login.user_sid;token_id=$login.token_id;authentication_id=$login.authentication_id;logon_type=2;
    contradictory_bindings_refused=$bindingRefusals;
    basis='actual owned local interactive logon token retained by launcher; SYSTEM DuplicateHandle readback'}
  }
 } else {
  $effectiveRights=[UskPublisherEffectiveRights]::new($CallerProcessId,[long]$CallerCreationFileTime,$CallerSid,$ServiceSid)
 }
}
try {
$rows=[Collections.Generic.List[object]]::new()
$pending=[Collections.Generic.Stack[object]]::new()
$absenceBefore=$null;$absenceRoot=$null
if($AbsentPublicationPreservationPrefix) {
 if($MetadataOnly -or -not $effectiveRights -or -not $ExpectedVolumeRoot -or
  $AbsentPublicationPreservationPrefix -cnotmatch ('^'+[regex]::Escape($DriveRoot)+
   'installation-operations\\install-[0-9a-f]{64}\\operation-[0-9a-f]{64}$')) {
  throw 'Independent publication absence mode binding differs'
 }
}
if(($AbsentPublicationReservationPrefix -ne '') -ne ($AbsentPublicationReservationGeneration -ne 0) -or
 ($AbsentPublicationReservationPrefix -and ($AbsentPublicationPreservationPrefix -or $MetadataOnly -or
  -not $effectiveRights -or -not $ExpectedVolumeRoot -or
  $AbsentPublicationReservationPrefix -cnotmatch ('^'+[regex]::Escape($DriveRoot)+
   'installation-operations\\install-[0-9a-f]{64}\\operation-[0-9a-f]{64}$')))) {
 throw 'Independent reserved publication absence mode binding differs'
}
if($AbsentPublicationPreservationPrefix -or $AbsentPublicationReservationPrefix) {
 $absenceRoot=[UskMetadataFacts]::ReadClosure($DriveRoot)
 $absenceBefore=[UskMetadataFacts]::RequireAbsentLeaf($DriveRoot+'publication')
}
if(-not $MetadataOnly) {
foreach($top in @(($DriveRoot+'setup-state'),($DriveRoot+'publication'),($DriveRoot+'installation-operations'))) {
 if(-not (Test-Path -LiteralPath $top -PathType Container)) {
  if($top -ceq ($DriveRoot+'setup-state') -or $top -ceq ($DriveRoot+'installation-operations')){continue}
  if(($AbsentPublicationPreservationPrefix -or $AbsentPublicationReservationPrefix) -and $top -ceq ($DriveRoot+'publication')){continue}
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
   $row['owner_dacl_sha256']=$checked['owner_dacl_sha256']
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
if($ExpectedVolumeRoot) {
 $facts=[UskMetadataFacts]::ReadClosure($DriveRoot)
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$facts[1],0)
 $root=[ordered]@{path=$DriveRoot;directory=$true;file_id=[string]$facts[0];native_name=[string]$facts[8];
  attributes=[uint32]$facts[2];link_count=[uint32]$facts[3];case_sensitive=[bool]$facts[4];streams=@($facts[5]);
  raw_security=$raw.GetSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access);
  owner=$raw.Owner.Value;protected=[bool]($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected);
  raw_aces=@($raw.DiscretionaryAcl|ForEach-Object {[ordered]@{type=[int]$_.AceType;flags=[int]$_.AceFlags;access_mask=$_.AccessMask;sid=$_.SecurityIdentifier.Value}})}
 $checked=$effectiveRights.Read($DriveRoot)
 if($checked['file_id'] -cne $root.file_id -or $checked['security'] -cne $root.raw_security) {
  throw 'Volume-root descriptor differs from independent native boundary'
 }
 $root['effective_rights']=$checked['checks'];$root['effective_right_group_sid']=$checked['group_sid']
 $root['owner_dacl_sha256']=$checked['owner_dacl_sha256']
 $result['volume_boundary']=[ordered]@{root=$root;device=$effectiveRights.ReadVolumeDevice($DriveRoot,$ExpectedVolumeRoot,$ExpectedDiskNumber)}
}
if($AbsentPublicationPreservationPrefix) {
 $absenceAfter=[UskMetadataFacts]::RequireAbsentLeaf($DriveRoot+'publication')
 $retained=$AbsentPublicationPreservationPrefix+'-retained-g00000000000000000001'
 $preservation=$AbsentPublicationPreservationPrefix+'-preserve-g00000000000000000001.json'
 if([string]$absenceRoot[0] -cne $result.volume_boundary.root.file_id -or
  @($rows|Where-Object {$_.path -ceq $retained -and $_.directory}).Count -ne 1 -or
  @($rows|Where-Object {$_.path -ceq $preservation -and -not $_.directory}).Count -ne 1 -or
  @($rows|Where-Object {$_.path -ceq ($AbsentPublicationPreservationPrefix+'-bootstrap-g00000000000000000002.json')}).Count -ne 0) {
  throw 'Independent publication absence lost its original preserved object or root binding'
 }
 $result['publication_absence']=[ordered]@{schema='usk.publisher_preserved_publication_absence.v1';
  path=($DriveRoot+'publication');parent_root_identity=$result.volume_boundary.root.file_id;
  win32_error_before=$absenceBefore;win32_error_after=$absenceAfter;
  preservation_record_path=$preservation;retained_root_path=$retained}
}
if($AbsentPublicationReservationPrefix) {
 $absenceAfter=[UskMetadataFacts]::RequireAbsentLeaf($DriveRoot+'publication')
 $generation=$AbsentPublicationReservationGeneration.ToString('D20')
 $reservation=$AbsentPublicationReservationPrefix+'-bootstrap-g'+$generation+'.json'
 $installName=Split-Path -Leaf (Split-Path -Parent $AbsentPublicationReservationPrefix)
 $ownership=$DriveRoot+'setup-state\state\leases\'+$installName+'\g'+$generation+'-active.json'
 $reservationRows=@($rows|Where-Object {$_.path -ceq $reservation -and -not $_.directory})
 $ownershipRows=@($rows|Where-Object {$_.path -ceq $ownership -and -not $_.directory})
 if([string]$absenceRoot[0] -cne $result.volume_boundary.root.file_id -or
  $reservationRows.Count -ne 1 -or $ownershipRows.Count -ne 1 -or
  @($rows|Where-Object {$_.path -ceq ($AbsentPublicationReservationPrefix+'-preserve-g'+$generation+'.json') -or
   $_.path -ceq ($AbsentPublicationReservationPrefix+'-retained-g'+$generation)}).Count -ne 0) {
  throw 'Independent reserved absence lost its exact current reservation, native ownership or volume binding'
 }
 $reserved=$reservationRows[0].content_json|ConvertFrom-Json
 $active=$ownershipRows[0].content_json|ConvertFrom-Json
 if($reserved.schema -cne 'usk.publication_bootstrap_reservation.v1' -or $reserved.publication_absent -ne $true -or
  -not ($active.generation -is [int] -or $active.generation -is [long]) -or
  $active.generation -ne $AbsentPublicationReservationGeneration -or $active.status -cne 'active' -or
  ($reserved.ownership|ConvertTo-Json -Depth 64 -Compress) -cne ($active|ConvertTo-Json -Depth 64 -Compress)) {
  throw 'Independent reserved absence has contradictory native reservation/active ownership'
 }
 $priorRetained=$AbsentPublicationReservationPrefix+'-retained-g00000000000000000001'
 $priorPreservation=$AbsentPublicationReservationPrefix+'-preserve-g00000000000000000001.json'
 $retainedRows=@($rows|Where-Object {$_.path -ceq $priorRetained -and $_.directory})
 $preservationRows=@($rows|Where-Object {$_.path -ceq $priorPreservation -and -not $_.directory})
 if(($AbsentPublicationReservationGeneration -eq 1 -and ($retainedRows.Count -ne 0 -or $preservationRows.Count -ne 0)) -or
  ($AbsentPublicationReservationGeneration -eq 2 -and ($retainedRows.Count -ne 1 -or $preservationRows.Count -ne 1))) {
  throw 'Independent reserved absence prior preservation shape differs'
 }
 $result['publication_absence']=[ordered]@{schema='usk.publisher_reserved_publication_absence.v1';
  path=($DriveRoot+'publication');parent_root_identity=$result.volume_boundary.root.file_id;
  win32_error_before=$absenceBefore;win32_error_after=$absenceAfter;
  generation=$AbsentPublicationReservationGeneration;reservation_record_path=$reservation;ownership_record_path=$ownership;
  previous_preservation_record_path=$(if($AbsentPublicationReservationGeneration -eq 2){$priorPreservation}else{$null});
  previous_retained_root_path=$(if($AbsentPublicationReservationGeneration -eq 2){$priorRetained}else{$null})}
}
if($effectiveRights -and $ExpectedVolumeRoot) {
 # Evaluate a reconstructed descriptor from the native phase's closed
 # owner/DACL facts and the separately reobserved group. This is explicitly
 # not a live AccessCheck at that earlier phase, or retained raw phase bytes.
 $preparedRows=@($rows|Where-Object path -ceq ($DriveRoot+'publication\journal\lab-prepared-evidence.json'))
 if($preparedRows.Count -eq 1) {
  $prepared=$preparedRows[0].content_json|ConvertFrom-Json
  if($prepared.schema -cin @('usk.publisher.lab_phase_evidence.v7','usk.publisher.lab_phase_evidence.v8','usk.publisher.lab_phase_evidence.v9')) {
   $anchors=$prepared.protected_anchors;$tree=$prepared.sealed_tree
   $objects=@($anchors.boundary)+@($anchors.chain|ForEach-Object object)+
    @($anchors.staging,$anchors.destination_parent,$anchors.state,$anchors.journal,$tree.root)+
    @($tree.descendants|ForEach-Object object)
   if($objects.Count -gt 10000){throw 'Native descriptor projection exceeds its object bound'}
   $projected=[Collections.Generic.List[object]]::new()
   foreach($nativeObject in $objects) {
    if($nativeObject.owner_sid -cne 'S-1-5-18' -or $nativeObject.dacl_protected -ne $true -or
       @($nativeObject.dacl_aces).Count -ne 2){throw 'Native descriptor projection is not the closed private policy'}
    $expectedSids=@('S-1-5-18',$ServiceSid)
    for($aceIndex=0;$aceIndex -lt 2;++$aceIndex) {
     $ace=$nativeObject.dacl_aces[$aceIndex]
     if($ace.type -ne 0 -or $ace.flags -ne 0 -or $ace.access_mask -ne 0x1f01ff -or
        $ace.sid -cne $expectedSids[$aceIndex]){throw 'Native descriptor projection ACE differs'}
    }
    $matched=@(@($rows)+@($result.volume_boundary.root)|Where-Object file_id -ceq $nativeObject.file_id)
    if($matched.Count -ne 1){throw 'Native descriptor projection lacks an independent identity/group binding'}
    $group=[Security.Principal.SecurityIdentifier]::new([string]$matched[0].effective_right_group_sid)
    if($group.Value -cne $matched[0].effective_right_group_sid){throw 'Observed group is not canonical'}
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new(
     ('O:SYG:'+ $group.Value +'D:P(A;;FA;;;SY)(A;;FA;;;'+$ServiceSid+')'))
    $descriptorBytes=New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($descriptorBytes,0)
    $projected.Add([ordered]@{native_object=$nativeObject;observed_group_sid=$group.Value;
     reconstructed_descriptor_hex=([BitConverter]::ToString($descriptorBytes)).Replace('-','').ToLowerInvariant();
     checks=$effectiveRights.CheckDescriptor($descriptorBytes)})
   }
   $result['native_phase_descriptor_access']=[ordered]@{schema='usk.publisher.phase_descriptor_access.v1';
    basis='native_closed_owner_dacl_with_independently_observed_group';
    live_phase_access_check=$false;prepared_record_sha256=$preparedRows[0].sha256;objects=$projected}
  }
 }
}
$temporary=$Output+'.pending'
# Closing all observer-owned token/process duplicates is part of the success
# barrier. A missed observer emits no acknowledgement; its caller retains the
# generated login until exact close can be established or runner disposal.
if($effectiveRights){$effectiveRights.Dispose();$effectiveRights=$null}
$result['observer_token_handles_closed']=$true
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
    if($ClientCaptureFile) {
        $command+=" -ClientCaptureFile '"+$ClientCaptureFile.Replace("'","''")+"' -ClientCaptureSha256 '"+$ClientCaptureSha256+"'"
    }
    if($ExpectedVolumeRoot) {
        $command+=" -ExpectedVolumeRoot '"+$ExpectedVolumeRoot+"' -ExpectedDiskNumber "+$ExpectedDiskNumber
    }
    if($AbsentPublicationPreservationPrefix) {
        $command+=" -AbsentPublicationPreservationPrefix '"+$AbsentPublicationPreservationPrefix+"'"
    }
    if($AbsentPublicationReservationPrefix) {
        $command+=" -AbsentPublicationReservationPrefix '"+$AbsentPublicationReservationPrefix+"' -AbsentPublicationReservationGeneration "+$AbsentPublicationReservationGeneration
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
