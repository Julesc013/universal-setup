# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Owned hosted fixture. Definition only; no local native execution.
function New-OwnedBootstrapDurableState {
    param([Parameter(Mandatory=$true)][ValidateSet('move_intent','pending_empty','pending_middle','pending_full',
        'publication_absent','next_reservation_absent')][string]$Case,
        [Parameter(Mandatory=$true)]$OriginalReadback)
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
        throw 'Durable state construction requires the owned hosted SYSTEM fixture'
    }
    $currentDisk=(Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop)|Get-Disk -ErrorAction Stop
    $parts=@($currentDisk|Get-Partition|Where-Object DriveLetter)
    if($currentDisk.IsBoot -or $currentDisk.IsSystem -or $currentDisk.Number -ne $disk.Number -or $parts.Count -ne 1 -or
        ($parts[0]|Get-Volume).UniqueId -cne $VolumeRoot) {throw 'Durable fixture disposable target differs'}
    $scm=Get-CimInstance Win32_Service -Filter ("Name='"+$service+"'") -ErrorAction Stop
    if($scm.State -cne 'Stopped' -or $scm.ProcessId -ne 0 -or $scm.PathName -cnotlike ('*'+$installedBinary+'*')) {
        throw 'Durable fixture registered worker is not stopped'
    }
    $loss=if($Case -ceq 'next_reservation_absent'){$receipt.bootstrap_preservation_loss}else{$receipt.bootstrap_loss}
    $phase=if($Case -ceq 'next_reservation_absent'){'bootstrap_preserved'}else{'bootstrap'}
    $status=if($Case -ceq 'next_reservation_absent'){'terminated_publication_preserved'}else{'terminated_publication_bootstrap'}
    if(-not $loss -or $loss.readback -ne $OriginalReadback -or $loss.boundary.phase -cne $phase -or
        $loss.boundary.status -cne $status -or $loss.boundary.service_name -cne $service -or
        $loss.boundary.volume_guid_root -cne $VolumeRoot -or
        $loss.boundary.service_binary_sha256 -cne $receipt.service_sha256 -or
        $loss.boundary.termination.confirmed -ne $true -or $loss.boundary.termination.kill_invoked -ne $true -or
        -not ($loss.boundary.termination.terminated -is [int] -or $loss.boundary.termination.terminated -is [long]) -or
        $loss.boundary.termination.terminated -lt 1 -or $loss.boundary.termination.terminated -gt 1024) {
        throw 'Durable fixture lacks the actual completed owned process-loss readback'
    }
    if($Case -ceq 'next_reservation_absent' -and
        ($loss.boundary.termination.method -cne 'TerminateProcess_owned_held_root' -or
            $loss.boundary.termination.process_id -ne $loss.boundary.service_pid -or
            $loss.boundary.termination.process_creation_file_time -cne $loss.boundary.process_creation_file_time -or
            $loss.boundary.termination.native_wait_result -ne 0)) {throw 'Durable fixture original preservation holder is unconfirmed'}
    $rows=@($OriginalReadback.independent.rows)
    $suffix='-bootstrap-g00000000000000000001.json'
    $reservations=@($rows|Where-Object {-not $_.directory -and $_.path.EndsWith($suffix,[StringComparison]::Ordinal)})
    if($reservations.Count -ne 1){throw 'Durable fixture original reservation is ambiguous'}
    $prefix=$reservations[0].path.Substring(0,$reservations[0].path.Length-$suffix.Length)
    $parent=Split-Path -Parent $prefix
    $generation=if($Case -ceq 'next_reservation_absent'){2}else{1}
    $activePath=$drive+'setup-state\state\leases\'+(Split-Path -Leaf $parent)+'\g'+$generation.ToString('D20')+'-active.json'
    $activeRows=@($rows|Where-Object {$_.path -ceq $activePath -and -not $_.directory})
    if($activeRows.Count -ne 1){throw 'Durable fixture ended native ownership is ambiguous'}
    $active=$activeRows[0].content_json|ConvertFrom-Json
    $pairInput=@{mode='ended_pair';boundary=$loss.boundary}
    $pairProof=$pairInput|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_process_pair_evidence.py') --input -
    if($LASTEXITCODE -ne 0){throw 'Durable fixture lacks the original held SCM/effect-child closure'}
    $ended=($pairProof -join "`n")|ConvertFrom-Json
    if($active.holder.process_id -ne $ended.holder.process_id -or
        $active.holder.process_creation_time -cne $ended.holder.process_creation_time) {
        throw 'Durable fixture active journal does not name the actually ended worker'
    }
    Initialize-OwnedDurableStateWriter
    $pendingName='bootstrap-'+$PID+'-'+[UskOwnedDurableStateWriter]::GetTickCount64()+'-1'
    $request=@{case=$Case;rows=$rows;drive=$drive;
        installed=@{install_id=$apply.plan_request.install_id;transaction_id=$apply.transaction_id};
        volume_id=$OriginalReadback.independent.volume_boundary.root.file_id;pending_name=$pendingName}
    $prepared=$request|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_bootstrap_durable_state_fixture.py') --prepare
    if($LASTEXITCODE -ne 0){throw 'Durable fixture canonical byte preparation failed'}
    $shape=($prepared -join "`n")|ConvertFrom-Json
    $expectedPath=switch -CaseSensitive ($Case) {
        'move_intent' {$prefix+'-preserve-g00000000000000000001.json'}
        'publication_absent' {$drive+'publication'}
        'next_reservation_absent' {$prefix+'-bootstrap-g00000000000000000002.json'}
        default {$parent+'\pending\'+$pendingName}
    }
    if($shape.case -cne $Case -or $shape.path -cne $expectedPath){throw 'Durable fixture exact owned destination differs'}
    $script:bootstrapOperationPrefix=$prefix
    $root=$null;$parentIdentity=$null
    if($Case -ceq 'publication_absent') {
        $root=@($rows|Where-Object {$_.path -ceq $expectedPath -and $_.directory})
        if($shape.action -cne 'remove_exact_empty_owned_root' -or $root.Count -ne 1 -or
            $shape.file_id -cne $root[0].file_id) {throw 'Durable fixture exact empty root differs'}
        [UskOwnedDurableStateWriter]::RemoveExactEmptyRoot($expectedPath,$root[0].file_id)
    } else {
        $expectedParent=Split-Path -Parent $expectedPath
        $parentRows=@($rows|Where-Object {$_.path -ceq $expectedParent -and $_.directory})
        if($shape.action -cne 'create_new_protected_record' -or $shape.parent -cne $expectedParent -or
            $parentRows.Count -ne 1 -or $shape.parent_file_id -cne $parentRows[0].file_id) {
            throw 'Durable fixture exact held parent differs'
        }
        $bytes=[Convert]::FromBase64String($shape.content_base64)
        if($bytes.Length -ne $shape.bytes -or $bytes.Length -gt 1048576){throw 'Durable fixture byte count differs'}
        $hash=[Security.Cryptography.SHA256]::Create()
        try {$actualHash=[BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}
        finally {$hash.Dispose()}
        if($actualHash -cne $shape.sha256){throw 'Durable fixture bytes differ from prepared digest'}
        $descriptor=(Get-Acl -LiteralPath $expectedParent).GetSecurityDescriptorBinaryForm()
        $parentIdentity=$parentRows[0].file_id
        [UskOwnedDurableStateWriter]::CreateRecord($expectedParent,$parentIdentity,
            (Split-Path -Leaf $expectedPath),$descriptor,$bytes)
    }
    $readback=if($Case -ceq 'publication_absent'){Read-NativeSnapshot -PublicationReservedAbsentGeneration 1}
        elseif($Case -ceq 'next_reservation_absent'){Read-NativeSnapshot -PublicationReservedAbsentGeneration 2}
        else {Read-NativeSnapshot}
    return [ordered]@{schema='usk.publisher_constructed_bootstrap_durable_state.v1';
        scope='system_constructed_durable_state_after_observed_bootstrap_process_loss';case=$Case;
        fixture_actor=@{identity='S-1-5-18';process_id=$PID;creation_file_time=$ownerCreation;service=$service;
            service_stopped=$true;parent_file_id=$parentIdentity;
            removed_root_file_id=$(if($root){$root[0].file_id}else{$null})};
        pending_name=$(if($Case.StartsWith('pending_')){$pendingName}else{$null});
        created_at_file_time=[DateTime]::UtcNow.ToFileTimeUtc().ToString();readback=$readback}
}
