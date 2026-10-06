# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Called only from the existing hosted, owned Standard maintenance fixture.
function Invoke-StandardEndedRepairRecovery($Replacement,$SourceRoot) {
    $case=[ordered]@{schema='usk.publisher_ended_repair_recovery_probe.v1';
        profile_qualified=$false;recovery_qualified=$false;status='running';
        before=$null;interrupted=$null;after=$null;response=$null}
    $receipt['maintenance_recovery']=$case
    $before=Read-NativeSnapshot
    $case.before=$before
    $root=[IO.Path]::GetFullPath([string]$installed.target_root)
    $selected=@($before.independent.rows|Where-Object path -ceq ($root+'\bin\core.bin'))
    if($selected.Count -ne 1 -or $selected[0].directory -or $selected[0].sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Ended repair requires the actual independently observed owned core file'
    }
    $case['damage']=Invoke-IndependentOwnedPayloadDamage -VhdPath $VhdPath -VolumeRoot $VolumeRoot `
        -DriveRoot $drive -VisibleRoot $root -PayloadRelativePath 'bin/core.bin' -ExpectedSha256 $selected[0].sha256
    $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if($stamp -cle ([DateTime]$installed.created_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) {
        Start-Sleep -Milliseconds 1100
        $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        if($stamp -cle ([DateTime]$installed.created_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) {
            throw 'Ended repair timestamp did not advance the installed revision'
        }
    }
    $planRequest=[ordered]@{schema='usk.repair_plan_request.v1';request_id=('request.repair.loss.'+$id);
        plan_id=('plan.repair.loss.'+$id);install_id=[string]$installed.install_id;created_at=$stamp;
        archive=@{format='zip';path=[string]$Replacement.archive_file;
            expected_sha256=[string]$Replacement.archive_sha256;strip_prefix='pkg'}}
    $requestPath=Join-Path $lab 'maintenance-loss-plan.json'
    Write-Json $requestPath @{schema='usk.oneshot_request.v1';request_id=$planRequest.request_id;
        command='repair.plan';payload=$planRequest;dry_run=$true}
    $planned=& $MachineBinary --machine --request-file $requestPath --context-file $context
    $case['planner_exit_code']=$LASTEXITCODE
    $plan=($planned -join "`n")|ConvertFrom-Json
    $case['plan']=$plan
    if($case.planner_exit_code -ne 0 -or $plan.status -cne 'ok' -or $plan.result.status -cne 'ok' -or
        $plan.result.payload.plan_id -cne $planRequest.plan_id -or
        $plan.result.payload.plan_digest -cnotmatch '^[0-9a-f]{64}$') {throw 'Ended repair real planner refused its original plan'}
    $apply=[ordered]@{schema='usk.repair_apply_request.v1';plan_request=$planRequest;
        reviewed_plan_id=$planRequest.plan_id;reviewed_plan_digest=$plan.result.payload.plan_digest;
        transaction_id=('maintenance.repair.'+$id);applied_at=$stamp;confirmation='APPLY'}
    $case['request']=$apply
    $envelopePath=Join-Path $lab 'maintenance-loss-envelope.json'
    Write-Json $envelopePath @{schema='usk.publisher.maintenance_reviewed_plan_envelope.v1';
        activation='operator_acceptance_candidate';state_root=($drive+'setup-state');acceptance_root=$drive;
        plan_request=$planRequest;reviewed_plan_digest=$apply.reviewed_plan_digest;apply_request=$apply}
    $applyPath=Join-Path $lab 'maintenance-loss-apply.json'
    Write-Json $applyPath $apply
    $envelopeSha=(Get-FileHash -LiteralPath $envelopePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $enrolled=& $ServiceControlBinary --enroll-reviewed-operation $service $envelopePath $envelopeSha $applyPath
    if($LASTEXITCODE -ne 0){throw 'Ended repair original administrator enrollment refused'}
    $case['enrollment']=($enrolled -join "`n")|ConvertFrom-Json
    if($case.enrollment.status -cne 'reviewed_operation_enrolled' -or $case.enrollment.service -cne $service) {
        throw 'Ended repair original administrator enrollment differs'
    }
    $case['interrupted_response']=Invoke-StandardRequest 'repair.apply' $apply 5 -MaintenanceProcessLoss
    $interrupted=Read-NativeSnapshot
    $case.interrupted=$interrupted
    $boundary=$receipt.maintenance_process_loss.boundary
    $documents=@($interrupted.independent.rows|Where-Object content_json|ForEach-Object {$_.content_json|ConvertFrom-Json})
    # Native custody retains historical transaction snapshots with the same
    # schema/TX. Only the exact authoritative journal is current state.
    $journalPath=$drive+'setup-state\state\transactions\'+$apply.transaction_id+'.journal.json'
    $journal=@($interrupted.independent.rows|Where-Object {$_.path -ceq $journalPath -and $_.content_json}|
        ForEach-Object {$_.content_json|ConvertFrom-Json})
    $original=@($interrupted.independent.rows|Where-Object {
        $_.path -ceq ($drive+'setup-state\state\transactions\'+$apply.transaction_id+'.native-maintenance-created.json')})
    $confirm=@($interrupted.independent.rows|Where-Object {
        $_.path -ceq ($drive+'setup-state\state\transactions\'+$apply.transaction_id+'.native-maintenance-custody\00000000000000000000.json')})
    $oldLease=$boundary.maintenance_writer_lease_ownership
    $completedBefore=@($documents|Where-Object {$_.schema -ceq 'usk.installation_lease_ownership.v1' -and
        $_.operation_id -ceq $apply.transaction_id -and $_.status -ceq 'completed'})
    if($journal.Count -ne 1 -or $journal[0].schema -cne 'usk.transaction_journal.v1' -or
        $journal[0].transaction_id -cne $apply.transaction_id -or $journal[0].current_state -ceq 'completed' -or
        $completedBefore.Count -ne 0 -or
        $original.Count -ne 1 -or $confirm.Count -ne 1 -or
        $confirm[0].sha256 -cne $boundary.maintenance_confirmation_sha256 -or
        $oldLease.holder.process_id -ne $boundary.service_pid -or
        $oldLease.holder.process_creation_time -cne $boundary.process_creation_file_time -or
        (Get-Service $service).Status -ne 'Stopped') {
        throw 'Ended repair lacks the actual incomplete original worker custody'
    }
    # Retire the exact generated source only after actual worker termination.
    $source=[IO.Path]::GetFullPath([string]$Replacement.archive_file)
    $sourceRootPath=[IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
    $retired=[IO.Path]::GetFullPath((Join-Path $sourceRootPath 'retired-ended-repair-source.zip'))
    if((Split-Path -Parent $source) -cne $sourceRootPath -or (Split-Path -Parent $retired) -cne $sourceRootPath -or
        (Test-Path -LiteralPath $retired) -or
        ((Get-Item -LiteralPath $sourceRootPath).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ((Get-Item -LiteralPath $source).Attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -or
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Replacement.archive_sha256) {
        throw 'Ended repair source retirement escaped its actual owned archive'
    }
    Move-Item -LiteralPath $source -Destination $retired -ErrorAction Stop
    if((Test-Path -LiteralPath $source) -or
        (Get-FileHash -LiteralPath $retired -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Replacement.archive_sha256) {
        throw 'Ended repair original source absence is unconfirmed'
    }
    $case['source_retired']=@{original_path=$source;retired_path=$retired;archive_sha256=$Replacement.archive_sha256}
    $selector=@{schema='usk.publisher_maintenance_recovery_request.v1';operation='repair';
        install_id=[string]$installed.install_id;transaction_id=$apply.transaction_id}
    $case.response=Invoke-StandardRequest 'repair.recover' $selector
    $after=Read-NativeSnapshot
    $case.after=$after
    $documents=@($after.independent.rows|Where-Object content_json|ForEach-Object {$_.content_json|ConvertFrom-Json})
    $journalAfter=@($after.independent.rows|Where-Object {
        if($_.path -cne $journalPath -or -not $_.content_json){return $false};$d=$_.content_json|ConvertFrom-Json
        return $d.schema -ceq 'usk.transaction_journal.v1' -and $d.transaction_id -ceq $apply.transaction_id -and $d.current_state -ceq 'completed'})
    $sealed=@($documents|Where-Object {$_.schema -ceq 'usk.maintenance_effect_record.v1' -and
        $_.transaction_id -ceq $apply.transaction_id -and $_.phase -ceq 'sealed'})
    $state=@($documents|Where-Object {$_.schema -ceq 'usk.installed_state.v1' -and
        $_.install_id -ceq $installed.install_id -and $_.transaction_id -ceq $apply.transaction_id})
    $completed=@($documents|Where-Object {$_.schema -ceq 'usk.installation_lease_ownership.v1' -and
        $_.operation_id -ceq $apply.transaction_id -and $_.status -ceq 'completed'})
    $createdAfter=@($after.independent.rows|Where-Object path -ceq $original[0].path)
    $restored=@($after.independent.rows|Where-Object path -ceq $selected[0].path)
    $report=$case.response.result.payload
    if($journalAfter.Count -ne 1 -or $sealed.Count -ne 1 -or $state.Count -ne 1 -or
        @($completed.ownership_sha256|Sort-Object -Unique).Count -ne 1 -or
        $completed[0].generation -le $oldLease.generation -or
        $completed[0].operation_context_sha256 -cne $oldLease.operation_context_sha256 -or
        ($completed[0].holder.process_id -eq $oldLease.holder.process_id -and
            $completed[0].holder.process_creation_time -ceq $oldLease.holder.process_creation_time) -or
        $createdAfter.Count -ne 1 -or $createdAfter[0].sha256 -cne $original[0].sha256 -or
        $restored.Count -ne 1 -or $restored[0].sha256 -cne $selected[0].sha256 -or
        $report.schema -cne 'usk.maintenance_recovery_report.v1' -or $report.status -cne 'completed' -or
        $report.operation -cne 'repair' -or $report.install_id -cne $installed.install_id -or
        $report.transaction_id -cne $apply.transaction_id -or $report.plan_id -cne $apply.reviewed_plan_id -or
        $report.plan_digest -cne $apply.reviewed_plan_digest -or
        $report.transaction_snapshot_sha256 -cne $journalAfter[0].sha256 -or
        $report.effect_history_sha256 -cne $sealed[0].digest -or (Test-Path -LiteralPath $source)) {
        throw 'Ended repair source-free recovery lost its original custody, new generation or actual result'
    }
    $case['original_generation']=$oldLease.generation
    $case['completed_generation']=$completed[0].generation
    # Verify the actual recovered transaction through the same held ordinary
    # client, after the original package path has been retired. This reads
    # current completion; it grants no authority to the recovery selector.
    $verify=@{schema='usk.publisher_installed_verify_request.v1';
        request_id='verify.maintenance.loss.'+$id;install_id=$installed.install_id;
        transaction_id=$apply.transaction_id;report_id='verify.maintenance.loss.'+$id;
        verified_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
    $case['verification']=Invoke-StandardRequest 'installed.verify' $verify
    $verification=$case.verification.result.payload
    if($verification.schema -cne 'usk.verification_report.v1' -or $verification.status -cne 'pass' -or
        $verification.install_id -cne $verify.install_id -or $verification.report_id -cne $verify.report_id -or
        $verification.verified_at -cne $verify.verified_at) {
        throw 'Source-free recovered repair verification did not return its bound ordinary report'
    }
    $afterVerification=Read-NativeSnapshot
    $beforeVerifyText=$after.independent.rows|ConvertTo-Json -Depth 64 -Compress
    $afterVerifyText=$afterVerification.independent.rows|ConvertTo-Json -Depth 64 -Compress
    if($beforeVerifyText -cne $afterVerifyText -or (Test-Path -LiteralPath $source) -or
        (Get-FileHash -LiteralPath $retired -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Replacement.archive_sha256) {
        throw 'Source-free recovered repair verification changed native state or retired source'
    }
    $digest=[Security.Cryptography.SHA256]::Create()
    try {
        $case['verification_native_rows_sha256']=([BitConverter]::ToString($digest.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($afterVerifyText)))).Replace('-','').ToLowerInvariant()
    } finally {$digest.Dispose()}
    $case['verification_native_rows']=@($afterVerification.independent.rows).Count
    $case.status='ended_worker_source_free_repair_observed'
    return $case
}
