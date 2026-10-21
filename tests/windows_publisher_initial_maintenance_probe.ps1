# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Called only from the existing hosted, owned Standard maintenance fixture.
function Invoke-StandardInitialRepairInterruption($Replacement,$SourceRoot) {
    $case=[ordered]@{schema='usk.publisher_initial_repair_interruption_probe.v1';
        profile_qualified=$false;recovery_qualified=$false;status='running';
        before=$null;interrupted=$null;after=$null;response=$null}
    $receipt['maintenance_initial_boundary']=$case
    $before=Read-NativeSnapshot
    $case.before=$before
    $root=[IO.Path]::GetFullPath([string]$installed.target_root)
    $selected=@($before.independent.rows|Where-Object path -ceq ($root+'\bin\core.bin'))
    if($selected.Count -ne 1 -or $selected[0].directory -or $selected[0].sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Initial repair requires the actual independently observed owned core file'
    }
    $case['damage']=Invoke-IndependentOwnedPayloadDamage -VhdPath $VhdPath -VolumeRoot $VolumeRoot `
        -DriveRoot $drive -VisibleRoot $root -PayloadRelativePath 'bin/core.bin' -ExpectedSha256 $selected[0].sha256
    $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if($stamp -cle ([DateTime]$installed.created_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) {
        Start-Sleep -Milliseconds 1100
        $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        if($stamp -cle ([DateTime]$installed.created_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) {
            throw 'Initial repair timestamp did not advance the installed revision'
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
        $plan.result.payload.plan_digest -cnotmatch '^[0-9a-f]{64}$') {throw 'Initial repair real planner refused its original plan'}
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
    if($LASTEXITCODE -ne 0){throw 'Initial repair original administrator enrollment refused'}
    $case['enrollment']=($enrolled -join "`n")|ConvertFrom-Json
    if($case.enrollment.status -cne 'reviewed_operation_enrolled' -or $case.enrollment.service -cne $service) {
        throw 'Initial repair original administrator enrollment differs'
    }
    $beforeApply=Read-NativeSnapshot
    $case['before_apply']=$beforeApply
    # The observer checks the real protected original context and root binding;
    # the public plan report does not expose internal state/staging/audit roots.
    $case['interrupted_response']=Invoke-StandardRequest 'repair.apply' $apply 5 `
        -MaintenanceInitialProcessLoss
    $interrupted=Read-NativeSnapshot
    $case.interrupted=$interrupted
    $boundary=$receipt.maintenance_process_loss.boundary
    $journalPath=$drive+'setup-state\state\transactions\'+$apply.transaction_id+'.journal.json'
    $originalPath=$drive+'setup-state\state\transactions\'+$apply.transaction_id+'.native-maintenance-original.json'
    $rows=@($interrupted.independent.rows)
    $journal=@($rows|Where-Object {$_.path -ceq $journalPath -and $_.content_json})
    $original=@($rows|Where-Object {$_.path -ceq $originalPath -and $_.content_json})
    if($journal.Count -ne 1 -or $original.Count -ne 1 -or
        $boundary.phase -cne 'maintenance_initial' -or
        $boundary.status -cne 'terminated_initial_maintenance_before_staging' -or
        $boundary.initial_snapshot_sha256 -cne $journal[0].sha256 -or
        $boundary.original_custody_sha256 -cne $original[0].sha256 -or
        $boundary.maintenance_transaction_id -cne $apply.transaction_id -or
        $boundary.maintenance_plan_digest -cne $apply.reviewed_plan_digest -or
        $boundary.staging_before_kill -ne $false -or $boundary.staging_after_kill -ne $false -or
        $boundary.target_before_kill -ne $false -or $boundary.target_after_kill -ne $false) {
        throw 'Initial repair lacks unchanged independent shared intent and exact ended-owner boundary'
    }
    $provenanceInput=@{mode='original_maintenance_provenance';
        original=($original[0].content_json|ConvertFrom-Json);request=$apply;service_name=$service;boundary=$boundary}
    $provenance=$provenanceInput|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_process_pair_evidence.py') --input -
    if($LASTEXITCODE -ne 0){throw 'Initial ended original child/native broker provenance differs'}
    $case['original_provenance']=($provenance -join "`n")|ConvertFrom-Json
    if($case.original_provenance.original_pair_closure_checked -ne $true -or
        $case.original_provenance.native_restoration_qualified -ne $false) {
        throw 'Initial original native pair closure is unconfirmed or was overpromoted'
    }
    $document=$journal[0].content_json|ConvertFrom-Json
    if($document.current_state -cne 'staging' -or @($document.transitions).Count -ne 4 -or
        $document.plan_id -cne $apply.reviewed_plan_id -or $document.plan_digest -cne $apply.reviewed_plan_digest -or
        $document.operation -cne 'repair' -or $document.transaction_id -cne $apply.transaction_id -or
        $null -ne $document.recovery_metadata.staging_identity -or
        @($document.recovery_metadata.staged_files).Count -ne 0 -or
        @($document.recovery_metadata.stream_journal.entries).Count -ne 0 -or
        $document.recovery_metadata.stream_journal.publication_root_identity -or
        $document.recovery_metadata.commit_cleanup_policy -cne 'retain_only') {
        throw 'Initial independent journal is not the complete pre-staging shared snapshot'
    }
    $stage=$drive+'setup-state\staging\.usk-stage-'+$apply.transaction_id
    $target=$drive+'publication\destination\.usk-repair-'+$apply.transaction_id
    if(@($rows|Where-Object {$_.path -ceq $stage -or $_.path.StartsWith($stage+'\',[StringComparison]::Ordinal) -or
        $_.path -ceq $target -or $_.path.StartsWith($target+'\',[StringComparison]::Ordinal)}).Count) {
        throw 'Initial interruption left a staging or replacement effect'
    }
    # Compare the target after intentional fixture damage, using a fresh read
    # immediately before apply; the earlier pre-damage snapshot is no oracle.
    $prefix=$root.TrimEnd('\')+'\'
    $targetBefore=@($beforeApply.independent.rows|Where-Object {$_.path -ceq $root -or $_.path.StartsWith($prefix,[StringComparison]::Ordinal)})
    $targetAfter=@($rows|Where-Object {$_.path -ceq $root -or $_.path.StartsWith($prefix,[StringComparison]::Ordinal)})
    if(-not $targetBefore.Count -or ($targetBefore|ConvertTo-Json -Depth 64 -Compress) -cne
        ($targetAfter|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Initial interrupted original repair changed protected target rows'
    }
    $contextPrefix=Get-PublisherInitialOperationPrefix $drive ([string]$installed.install_id) $apply.transaction_id
    $originalContext=@($rows|Where-Object path -ceq ($contextPrefix+'.json'))
    $originalRoots=@($rows|Where-Object path -ceq ($contextPrefix+'-roots.json'))
    if($originalContext.Count -ne 1 -or $originalRoots.Count -ne 1){throw 'Initial independent original context/root records are absent'}
    $input=@{schema='usk.publisher_initial_maintenance_evidence_input.v1';drive=$drive;request=$apply;
        service_name=$service;boundary=$boundary;journal=$journal[0];original=$original[0];
        context=$originalContext[0];roots=$originalRoots[0]}
    $decoded=$input|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_initial_maintenance_evidence.py') --input -
    if($LASTEXITCODE -ne 0){throw 'Initial retained raw snapshot/context/root/intent bindings differ'}
    $case['initial_evidence']=($decoded -join "`n")|ConvertFrom-Json
    if($case.initial_evidence.shared_initial_snapshot_checked -ne $true -or
        $case.initial_evidence.native_restoration_qualified -ne $false -or
        $case.initial_evidence.profile_qualified -ne $false) {throw 'Initial evidence was omitted or promoted into authority'}
    # Source-free continuation cannot manufacture missing original creator or
    # commit custody. Retire only this generated fixture's exact original ZIP.
    $source=[IO.Path]::GetFullPath([string]$Replacement.archive_file)
    $sourceRootPath=[IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
    $retired=[IO.Path]::GetFullPath((Join-Path $sourceRootPath 'retired-initial-repair-source.zip'))
    if((Split-Path -Parent $source) -cne $sourceRootPath -or (Split-Path -Parent $retired) -cne $sourceRootPath -or
        (Test-Path -LiteralPath $retired) -or
        ((Get-Item -LiteralPath $sourceRootPath).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ((Get-Item -LiteralPath $source).Attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -or
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Replacement.archive_sha256) {
        throw 'Initial repair source retirement escaped its actual owned archive'
    }
    Move-Item -LiteralPath $source -Destination $retired -ErrorAction Stop
    if((Test-Path -LiteralPath $source) -or
        (Get-FileHash -LiteralPath $retired -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Replacement.archive_sha256) {
        throw 'Initial repair original source absence is unconfirmed'
    }
    $case['source_retired']=@{original_path=$source;retired_path=$retired;archive_sha256=$Replacement.archive_sha256}
    $selector=@{schema='usk.publisher_maintenance_recovery_request.v1';operation='repair';
        install_id=[string]$installed.install_id;transaction_id=$apply.transaction_id}
    $case.response=Invoke-StandardRequest 'repair.recover' $selector 5 -MaintenanceInitialRecoveryRetention
    $after=Read-NativeSnapshot
    $case.after=$after
    $afterRows=@($after.independent.rows)
    $afterTarget=@($afterRows|Where-Object {$_.path -ceq $root -or $_.path.StartsWith($prefix,[StringComparison]::Ordinal)})
    if(($targetBefore|ConvertTo-Json -Depth 64 -Compress) -cne ($afterTarget|ConvertTo-Json -Depth 64 -Compress) -or
        (Test-Path -LiteralPath $source) -or
        (Get-FileHash -LiteralPath $retired -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Replacement.archive_sha256) {
        throw 'Initial source-free retention changed payload rows or original source absence'
    }
    foreach($record in @($journal[0],$original[0],$originalContext[0],$originalRoots[0])) {
        $retained=@($afterRows|Where-Object path -ceq $record.path)
        if($retained.Count -ne 1 -or $retained[0].sha256 -cne $record.sha256) {
            throw 'Initial source-free retention replaced its original durable intent'
        }
    }
    if(@($afterRows|Where-Object {$_.path -ceq $stage -or $_.path.StartsWith($stage+'\',[StringComparison]::Ordinal) -or
        $_.path -ceq $target -or $_.path.StartsWith($target+'\',[StringComparison]::Ordinal) -or
        $_.path -ceq ($drive+'setup-state\state\transactions\'+$apply.transaction_id+'.native-maintenance-created.json') -or
        $_.path -ceq ($drive+'setup-state\state\transactions\'+$apply.transaction_id+'.maintenance-plan.json')}).Count) {
        throw 'Initial source-free retention manufactured staging, creator or reviewed-plan completion'
    }
    foreach($row in $afterRows) {
        if(-not $row.content_json){continue}
        $value=$row.content_json|ConvertFrom-Json
        if(($value.transaction_id -ceq $apply.transaction_id -and $value.schema -ceq 'usk.maintenance_effect_record.v1') -or
            ($value.operation_id -ceq $apply.transaction_id -and $value.schema -ceq 'usk.installation_lease_ownership.v1' -and
                $value.status -ceq 'completed') -or
            ($value.transaction_id -ceq $apply.transaction_id -and $value.schema -ceq 'usk.installed_state.v1')) {
            throw 'Initial source-free retention acquired a creator/effect or completed installed outcome'
        }
    }
    $case.status='initial_shared_intent_retained_without_payload_replay'
    $case['scope']='one_shared_initial_snapshot_and_original_native_pair_process_loss; source-free recovery_required retention'
    return $case
}
