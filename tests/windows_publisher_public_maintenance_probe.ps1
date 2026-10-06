# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Uses the existing held ordinary caller, one-request transport and independent
# native reader. No public value supplies native maintenance authority.
function Invoke-StandardFreshMaintenance {
    if(-not $MaintenanceQualification -or $env:GITHUB_ACTIONS -cne 'true' -or
        $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        (Get-Service $service).Status -ne 'Stopped') {
        throw 'Maintenance observation requires the owned hosted standard public journey'
    }
    . (Join-Path $PSScriptRoot 'windows_publisher_owned_payload_damage.ps1')
    $result=[ordered]@{schema='usk.publisher_standard_fresh_maintenance_probe.v1';
        scope='three_fresh_original_registered_operations';profile_qualified=$false;
        recovery_qualified=$false;cases=[Collections.Generic.List[object]]::new();status='running'}
    $receipt['maintenance']=$result # Retain an incomplete observation on failure.
    $result['completed_retries']=[Collections.Generic.List[object]]::new()
    function Invoke-CompletedMaintenanceRetry($OriginalCase,$BeforeRetry,[bool]$IncludeMovedRoot) {
        $retry=[ordered]@{operation=$OriginalCase.operation;transaction_id=$OriginalCase.request.transaction_id;
            response=$null;before_rows=@($BeforeRetry.independent.rows).Count;after_rows=$null;
            before_rows_sha256=$null;after_rows_sha256=$null;status='running'}
        $result.completed_retries.Add($retry)
        $selector=@{schema='usk.publisher_maintenance_recovery_request.v1';operation=$OriginalCase.operation;
            install_id=[string]$installed.install_id;transaction_id=$OriginalCase.request.transaction_id}
        $retry.response=Invoke-StandardRequest ($OriginalCase.operation+'.recover') $selector
        $historical=$retry.response.result.payload
        $originalJournal=@($BeforeRetry.independent.rows|Where-Object {
            if(-not $_.content_json){return $false}
            $document=$_.content_json|ConvertFrom-Json
            return $document.schema -ceq 'usk.transaction_journal.v1' -and
                $document.transaction_id -ceq $selector.transaction_id -and $document.current_state -ceq 'completed'
        })
        $originalSeal=@($BeforeRetry.independent.rows|Where-Object {
            if(-not $_.content_json){return $false}
            $document=$_.content_json|ConvertFrom-Json
            return $document.schema -ceq 'usk.maintenance_effect_record.v1' -and
                $document.transaction_id -ceq $selector.transaction_id -and $document.phase -ceq 'sealed'
        })
        if($originalJournal.Count -ne 1 -or $originalSeal.Count -ne 1 -or
            $historical.schema -cne 'usk.maintenance_recovery_report.v1' -or $historical.status -cne 'completed' -or
            $historical.operation -cne $selector.operation -or $historical.install_id -cne $selector.install_id -or
            $historical.transaction_id -cne $selector.transaction_id -or
            $historical.plan_id -cne $OriginalCase.request.reviewed_plan_id -or
            $historical.plan_digest -cne $OriginalCase.request.reviewed_plan_digest -or
            $historical.transaction_snapshot_sha256 -cne $originalJournal[0].sha256 -or
            $historical.effect_history_sha256 -cne ($originalSeal[0].content_json|ConvertFrom-Json).digest) {
            throw 'Completed maintenance retry lost its original historical result'
        }
        $afterRetry=Read-NativeSnapshot -IncludeMovedMaintenanceRoot:$IncludeMovedRoot
        $retry.after_rows=@($afterRetry.independent.rows).Count
        $beforeText=$BeforeRetry.independent.rows|ConvertTo-Json -Depth 64 -Compress
        $afterText=$afterRetry.independent.rows|ConvertTo-Json -Depth 64 -Compress
        $digest=[Security.Cryptography.SHA256]::Create()
        try {
            $retry.before_rows_sha256=([BitConverter]::ToString($digest.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes($beforeText)))).Replace('-','').ToLowerInvariant()
            $retry.after_rows_sha256=([BitConverter]::ToString($digest.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes($afterText)))).Replace('-','').ToLowerInvariant()
        } finally { $digest.Dispose() }
        if($beforeText -cne $afterText){throw 'Completed maintenance retry changed the native namespace or record bytes'}
        $retry.status='historical_completed_without_effects'
        return $afterRetry
    }
    $sourceRoot=Join-Path $lab 'maintenance-authored-inputs'
    if(Test-Path -LiteralPath $sourceRoot){throw 'Maintenance source fixture already exists'}
    New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    # The initial install's source-free checks have already completed. Produce
    # a newly authored replacement archive now, from the same finite product.
    $generated=& $PythonBinary -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $sourceRoot --target ($drive+'publication\destination\visible') --request-id ('maintenance.source.'+$id)
    if($LASTEXITCODE -ne 0){throw 'Maintenance replacement authoring failed'}
    $replacement=($generated -join "`n")|ConvertFrom-Json
    $result['replacement_archive']=$replacement
    if($replacement.archive_sha256 -cne $installed.source_archive_digest) {
        throw 'Newly authored maintenance archive differs from the actual installed source binding'
    }
    $sourceAcl=Get-Acl -LiteralPath $sourceRoot
    $sourceAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),
        'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $sourceRoot -AclObject $sourceAcl
    if($MaintenanceRecoveryQualification){
        $result['scope']='one_original_ended_worker_source_free_repair'
        $result['ended_repair']=Invoke-StandardEndedRepairRecovery $replacement $sourceRoot
        $result.status='ended_worker_source_free_repair_observed'
        return $result
    }
    $currentRoot=[IO.Path]::GetFullPath([string]$installed.target_root)
    $currentInstalled=$installed
    $movedRoot=$drive+'publication\destination\maintenance-moved'
    foreach($operation in @('repair','move','uninstall')) {
        $case=[ordered]@{operation=$operation;request=$null;plan=$null;enrollment=$null;response=$null;
            before=$null;after=$null;damage=$null;status='running'}
        $result.cases.Add($case)
        $before=Read-NativeSnapshot -IncludeMovedMaintenanceRoot:($operation -ceq 'uninstall')
        $case.before=$before
        if($operation -ceq 'repair') {
            $selected=@($before.independent.rows|Where-Object path -ceq ($currentRoot+'\bin\core.bin'))
            if($selected.Count -ne 1 -or $selected[0].directory -or $selected[0].sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Maintenance damage requires the independently observed owned core file'
            }
            $case.damage=Invoke-IndependentOwnedPayloadDamage -VhdPath $VhdPath -VolumeRoot $VolumeRoot `
                -DriveRoot $drive -VisibleRoot $currentRoot -PayloadRelativePath 'bin/core.bin' -ExpectedSha256 $selected[0].sha256
        }
        $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $priorStamp=([DateTime]$currentInstalled.created_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        if($stamp -cle $priorStamp) {
            Start-Sleep -Milliseconds 1100
            $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            if($stamp -cle $priorStamp){throw 'Maintenance timestamp did not advance the actual installed revision'}
        }
        $planRequest=[ordered]@{schema=('usk.'+$operation+'_plan_request.v1');request_id=('request.'+$operation+'.'+$id);
            plan_id=('plan.'+$operation+'.'+$id);install_id=[string]$installed.install_id;created_at=$stamp}
        if($operation -ceq 'repair') {
            $planRequest.archive=@{format='zip';path=[string]$replacement.archive_file;
                expected_sha256=[string]$replacement.archive_sha256;strip_prefix='pkg'}
        } elseif($operation -ceq 'move') {$planRequest.new_target=@{class='operator_acceptance';root=$movedRoot}}
        $requestPath=Join-Path $lab ('maintenance-plan-'+$operation+'.json')
        Write-Json $requestPath @{schema='usk.oneshot_request.v1';request_id=$planRequest.request_id;
            command=($operation+'.plan');payload=$planRequest;dry_run=$true}
        $planned=& $MachineBinary --machine --request-file $requestPath --context-file $context
        $plannerExit=$LASTEXITCODE
        $plan=($planned -join "`n")|ConvertFrom-Json
        $case.plan=$plan
        $case['plan_request']=$planRequest
        $case['planner_exit_code']=$plannerExit
        if($plannerExit -ne 0){throw ('Maintenance real planner refused '+$operation+': '+($plan|ConvertTo-Json -Compress -Depth 16))}
        if($plan.status -cne 'ok' -or $plan.result.status -cne 'ok' -or
            $plan.result.payload.plan_id -cne $planRequest.plan_id -or
            $plan.result.payload.plan_digest -cnotmatch '^[0-9a-f]{64}$') {throw 'Maintenance real plan binding differs'}
        $applyMaintenance=[ordered]@{schema=('usk.'+$operation+'_apply_request.v1');plan_request=$planRequest;
            reviewed_plan_id=$planRequest.plan_id;reviewed_plan_digest=$plan.result.payload.plan_digest;
            transaction_id=('maintenance.'+$operation+'.'+$id);applied_at=$stamp;confirmation='APPLY'}
        $case.request=$applyMaintenance
        $envelopePath=Join-Path $lab ('maintenance-envelope-'+$operation+'.json')
        Write-Json $envelopePath @{schema='usk.publisher.maintenance_reviewed_plan_envelope.v1';
            activation='operator_acceptance_candidate';state_root=($drive+'setup-state');acceptance_root=$drive;
            plan_request=$planRequest;reviewed_plan_digest=$applyMaintenance.reviewed_plan_digest;apply_request=$applyMaintenance}
        $applyPath=Join-Path $lab ('maintenance-apply-'+$operation+'.json')
        Write-Json $applyPath $applyMaintenance
        $envelopeSha=(Get-FileHash -LiteralPath $envelopePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $enrolled=& $ServiceControlBinary --enroll-reviewed-operation $service $envelopePath $envelopeSha $applyPath
        if($LASTEXITCODE -ne 0){throw ('Maintenance administrator enrollment refused '+$operation)}
        $case.enrollment=($enrolled -join "`n")|ConvertFrom-Json
        if($case.enrollment.status -cne 'reviewed_operation_enrolled' -or $case.enrollment.service -cne $service) {
            throw 'Maintenance administrator enrollment binding differs'
        }
        $case.response=Invoke-StandardRequest ($operation+'.apply') $applyMaintenance
        $report=$case.response.result.payload
        $expectedStatus=if($operation -ceq 'move'){'new_committed_old_retained'}else{'completed'}
        if($report.schema -cne ('usk.'+$operation+'_report.v1') -or $report.status -cne $expectedStatus -or
            $report.install_id -cne $installed.install_id -or $report.transaction_id -cne $applyMaintenance.transaction_id -or
            $report.plan_id -cne $planRequest.plan_id -or $report.completed_at -cne $stamp) {
            throw 'Maintenance completed public report differs from its actual request'
        }
        $after=Read-NativeSnapshot -IncludeMovedMaintenanceRoot:($operation -cne 'repair')
        $case.after=$after
        $documents=@($after.independent.rows|Where-Object {$_.content_json}|ForEach-Object {$_.content_json|ConvertFrom-Json})
        $state=@($documents|Where-Object {$_.schema -ceq 'usk.installed_state.v1' -and
            $_.install_id -ceq $installed.install_id -and $_.transaction_id -ceq $applyMaintenance.transaction_id})
        $lease=@($documents|Where-Object {$_.schema -ceq 'usk.installation_lease_ownership.v1' -and
            $_.install_id -ceq $installed.install_id -and $_.operation_id -ceq $applyMaintenance.transaction_id -and
            $_.operation -ceq $operation -and $_.status -ceq 'completed'})
        $journal=@($documents|Where-Object {$_.schema -ceq 'usk.transaction_journal.v1' -and
            $_.transaction_id -ceq $applyMaintenance.transaction_id -and $_.plan_digest -ceq $applyMaintenance.reviewed_plan_digest -and
            $_.current_state -ceq 'completed'})
        $sealed=@($documents|Where-Object {$_.schema -ceq 'usk.maintenance_effect_record.v1' -and
            $_.transaction_id -ceq $applyMaintenance.transaction_id -and $_.phase -ceq 'sealed'})
        if($state.Count -ne 1 -or @($lease.ownership_sha256|Sort-Object -Unique).Count -ne 1 -or
            $journal.Count -ne 1 -or $sealed.Count -ne 1){throw 'Maintenance actual installed/lease/completed/sealed native records differ'}
        if($operation -ceq 'repair') {
            $restored=@($after.independent.rows|Where-Object path -ceq ($currentRoot+'\bin\core.bin'))
            if($restored.Count -ne 1 -or $restored[0].sha256 -cne $selected[0].sha256 -or
                @($report.repaired_files|Where-Object relative_path -ceq 'bin/core.bin').Count -ne 1) {
                throw 'Maintenance repair did not restore the actual selected original bytes'
            }
        } elseif($operation -ceq 'move') {
            if([IO.Path]::GetFullPath([string]$state[0].target_root) -cne $movedRoot -or
                @($after.independent.rows|Where-Object path -ceq $movedRoot).Count -ne 1 -or
                @($after.independent.rows|Where-Object path -ceq $currentRoot).Count -ne 1) {
                throw 'Maintenance move failed to retain old root and publish the new closure'
            }
            $originalClosure=@($before.independent.rows|Where-Object {
                $_.path -ceq $currentRoot -or $_.path.StartsWith($currentRoot+'\',[StringComparison]::Ordinal)})
            $retainedClosure=@($after.independent.rows|Where-Object {
                $_.path -ceq $currentRoot -or $_.path.StartsWith($currentRoot+'\',[StringComparison]::Ordinal)})
            $movedClosure=@($after.independent.rows|Where-Object {
                $_.path -ceq $movedRoot -or $_.path.StartsWith($movedRoot+'\',[StringComparison]::Ordinal)})
            if($originalClosure.Count -eq 0 -or $retainedClosure.Count -ne $originalClosure.Count -or
                $movedClosure.Count -ne $originalClosure.Count){throw 'Maintenance move native closure count differs'}
            $originalFields=@('directory','file_id','native_name','attributes','link_count','case_sensitive','streams',
                'raw_security','raw_aces','owner','protected','aces','bytes','sha256')
            foreach($originalRow in $originalClosure) {
                $oldRow=@($retainedClosure|Where-Object path -ceq $originalRow.path)
                $newRow=@($movedClosure|Where-Object path -ceq ($movedRoot+$originalRow.path.Substring($currentRoot.Length)))
                if($oldRow.Count -ne 1 -or $newRow.Count -ne 1 -or
                    ($oldRow[0]|Select-Object $originalFields|ConvertTo-Json -Compress -Depth 16) -cne
                    ($originalRow|Select-Object $originalFields|ConvertTo-Json -Compress -Depth 16) -or
                    $newRow[0].file_id -ceq $originalRow.file_id -or
                    $newRow[0].directory -ne $originalRow.directory -or $newRow[0].bytes -ne $originalRow.bytes -or
                    $newRow[0].sha256 -cne $originalRow.sha256) {
                    throw ('Maintenance move retained or copied native object differs: '+$originalRow.path)
                }
            }
            $case['moved_native_object_count']=$movedClosure.Count
            $currentRoot=$movedRoot
        } elseif($state[0].lifecycle_status -cne 'retired' -or
            @($after.independent.rows|Where-Object path -ceq $currentRoot).Count -ne 0) {
            throw 'Maintenance uninstall did not remove the current owned root'
        }
        $currentInstalled=$state[0]
        $case.status='observed_completed'
        $null=Invoke-CompletedMaintenanceRetry $case $after ($operation -cne 'repair')
    }
    # After move and uninstall, older payload names and later lease generations
    # differ. Their completed records still provide only the original result.
    $originalArchive=[IO.Path]::GetFullPath([string]$replacement.archive_file)
    $sourceBoundary=[IO.Path]::GetFullPath($sourceRoot).TrimEnd('\')+'\'
    $retiredArchive=[IO.Path]::GetFullPath((Join-Path $sourceRoot 'retired-maintenance-source.zip'))
    if(-not $originalArchive.StartsWith($sourceBoundary,[StringComparison]::OrdinalIgnoreCase) -or
        -not $retiredArchive.StartsWith($sourceBoundary,[StringComparison]::OrdinalIgnoreCase) -or
        (Test-Path -LiteralPath $retiredArchive) -or
        ((Get-Item -LiteralPath $originalArchive).Attributes -band
            ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -ne 0 -or
        (Get-FileHash -LiteralPath $originalArchive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $replacement.archive_sha256) {
        throw 'Completed retry source retirement lacks the exact owned generated archive'
    }
    Move-Item -LiteralPath $originalArchive -Destination $retiredArchive -ErrorAction Stop
    $result['completed_retry_source_retired']=@{original_path=$originalArchive;retired_path=$retiredArchive;
        archive_sha256=$replacement.archive_sha256}
    $late=Read-NativeSnapshot -IncludeMovedMaintenanceRoot
    foreach($oldCase in @($result.cases|Where-Object operation -cne 'uninstall')) {
        $late=Invoke-CompletedMaintenanceRetry $oldCase $late $true
    }
    $result.status='three_fresh_operations_observed'
    return $result
}
