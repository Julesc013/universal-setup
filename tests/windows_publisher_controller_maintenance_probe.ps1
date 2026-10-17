# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Use the controller's actual owned installation and enrolled public operations.
# Successful uninstall remains separate from privileged publisher retirement.
function Invoke-ControllerMaintenanceRequest {
    param([string]$RequestPath,[string]$RequestId,$Case)
    $responsePath=$RequestPath+'.response';$failurePath=$RequestPath+'.error'
    $nativePath=$RequestPath+'.native'
    $process=$null;$primary=$null;$cleanup=$null
    $script:clientCleanupConfirmed=$false
    try {
        $process=Start-Process -FilePath $MachineBinary -ArgumentList @('--machine','--publisher',$service,
            '--request-file',('"'+$RequestPath+'"'),'--publisher-observation-file',('"'+$nativePath+'"')) `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput $responsePath -RedirectStandardError $failurePath
        # The outer fixture must retain this exact owner even if local closure fails.
        $script:requestClient=[pscustomobject]@{process=$process}
        if(-not $process.WaitForExit(120000)){throw 'Owned public maintenance request timed out'}
        $process.WaitForExit()
        $Case['client_exit_code']=$process.ExitCode
        $file=Get-Item -LiteralPath $responsePath
        if($file.Length -eq 0 -or $file.Length -gt 4MB){throw 'Owned maintenance response exceeds its bound'}
        $Case['response_sha256']=(Get-FileHash -LiteralPath $responsePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $Case.response=Get-Content -LiteralPath $responsePath -Raw|ConvertFrom-Json
        if($process.ExitCode -ne 0 -or $Case.response.schema -cne 'usk.oneshot_response.v1' -or
            $Case.response.request_id -cne $RequestId -or $Case.response.status -cne 'ok' -or
            $Case.response.result.status -cne 'ok') {
            throw 'Owned public maintenance request did not complete; retain its actual response and authority'
        }
        # A missing native capture after an uncertain reply is not another
        # operation verdict. Require this additional match only for success.
        $file=Get-Item -LiteralPath $nativePath
        if($file.Length -eq 0 -or $file.Length -gt 4MB){throw 'Owned native maintenance response exceeds its bound'}
        $Case['native_response']=Get-Content -LiteralPath $nativePath -Raw|ConvertFrom-Json
        $Case['native_response_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if($process.ExitCode -ne 0 -or $Case.response.schema -cne 'usk.oneshot_response.v1' -or
            $Case.response.request_id -cne $RequestId -or $Case.response.status -cne 'ok' -or
            $Case.response.result.status -cne 'ok' -or
            $Case.native_response.schema -cne 'usk.publisher_lab_service_observation.v1' -or
            $Case.native_response.status -cne 'pass' -or
            ($Case.native_response.apply_response|ConvertTo-Json -Depth 64 -Compress) -cne
                ($Case.response.result|ConvertTo-Json -Depth 64 -Compress)) {
            throw 'Owned public maintenance request did not return its matching terminal'
        }
    } catch {
        $primary=$_;$Case['request_failure']=$_.Exception.Message
    } finally {
        if($process) {
            try {
                $closed=Stop-OwnedPublisherProcessTree $process
                if($closed.confirmed -ne $true){throw 'Owned maintenance client closure is unconfirmed'}
                $process.Dispose()
                $script:requestClient=$null;$script:clientCleanupConfirmed=$true
            } catch {
                $cleanup=$_;$Case['client_cleanup_failure']=$_.Exception.Message
                # Keep both the held process and the false shared barrier for outer cleanup.
            }
        }
    }
    if($primary){throw $primary}
    if($cleanup){throw $cleanup}
}

# Validate the existing closed lease postimage; a pair is historical metadata,
# never proof of native membership, current revision or retirement authority.
function Assert-ControllerMaintenanceLeasePair {
    param($Active,$Completed,[string]$PythonBinary)
    $ErrorActionPreference='Stop'
    $OutputEncoding=[Text.UTF8Encoding]::new($false)
    $output=@{mode='completed_pair';active=$Active;completed=$Completed}|ConvertTo-Json -Depth 16 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_installation_lease_evidence.py') --input -
    if($LASTEXITCODE -ne 0){throw 'Owned maintenance lease terminal postimage differs'}
    $proof=($output -join [Environment]::NewLine)|ConvertFrom-Json
    if($proof.status -cne 'bindings_consistent' -or $proof.coordination.status -cne 'completed' -or
        $proof.profile_qualified -isnot [bool] -or $proof.profile_qualified -or
        $proof.publication_authority_granted -isnot [bool] -or $proof.publication_authority_granted) {
        throw 'Owned maintenance lease pair projection differs'
    }
    return $proof
}

function Invoke-ControllerOwnedUninstall {
    if(-not $AdmittedTarget -or -not $ControllerApply -or -not $packageRoot -or
        $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $callerSid -or
        (Get-Service $service).Status -ne 'Stopped') {
        throw 'Owned uninstall requires the existing admitted hosted controller journey'
    }
    $result=[ordered]@{schema='usk.publisher_controller_owned_uninstall_probe.v1';status='running';
        scope='fresh_enrolled_repair_and_uninstall_without_move';profile_qualified=$false;
        retirement_qualified=$false;cases=[Collections.Generic.List[object]]::new()}
    $receipt['owned_uninstall']=$result
    $currentInstalled=$installedResponse.payload
    $currentRoot=[IO.Path]::GetFullPath([string]$currentInstalled.target_root)
    if($currentRoot -cne $visibleRoot -or $currentInstalled.lifecycle_status -cne 'installed' -or
        $damaged.before_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Owned uninstall lacks the actual installed state and damaged-file witness'
    }
    $before=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
    Assert-OwnedVolume
    # These unpublished-only commands must retain authority for a live install.
    $errorFile=Join-Path $root 'owned-live-unregister-error.txt'
    & $ServiceControlBinary --unregister $service $ServiceBinary $VolumeRoot $callerSid $registeredMode 2>$errorFile|Out-Null
    if($LASTEXITCODE -eq 0 -or -not (Get-Service $service -ErrorAction SilentlyContinue)) {
        throw 'Installed publisher unexpectedly lost its service through unpublished retirement'
    }
    $result['live_unregister_refusal']=Read-BoundedDiagnostic $errorFile 4096
    $errorFile=Join-Path $root 'owned-live-binary-retirement-error.txt'
    & $ServiceControlBinary --retire-binary $service $installedServiceBinary $sourceServiceHash $sid 2>$errorFile|Out-Null
    if($LASTEXITCODE -eq 0 -or -not (Test-Path -LiteralPath $installedServiceBinary -PathType Leaf)) {
        throw 'Installed publisher unexpectedly lost its protected executable'
    }
    $result['live_binary_retirement_refusal']=Read-BoundedDiagnostic $errorFile 4096
    $errorFile=Join-Path $root 'owned-live-retirement-error.txt'
    & $ServiceControlBinary --retire-owned $service 2>$errorFile|Out-Null
    if($LASTEXITCODE -eq 0 -or -not (Get-Service $service -ErrorAction SilentlyContinue) -or
        -not (Test-Path -LiteralPath $installedServiceBinary -PathType Leaf)) {
        throw 'Owned retirement accepted an installation with live payload'
    }
    $result['live_owned_retirement_refusal']=Read-BoundedDiagnostic $errorFile 4096
    $afterRefusals=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
    if(($before.independent.rows|ConvertTo-Json -Depth 64 -Compress) -cne
        ($afterRefusals.independent.rows|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Refused live retirement changed the actual installation namespace'
    }
    $result['live_refusals_unchanged_rows']=@($afterRefusals.independent.rows).Count

    # Original inputs were withheld for the preceding source-free observations.
    # Reauthor the same finite product; never repair by directly replacing bytes.
    $sourceRoot=Join-Path $root ('owned-maintenance-inputs-'+$id)
    if(Test-Path -LiteralPath $sourceRoot){throw 'Owned maintenance source already exists'}
    New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    $generated=& $PythonBinary -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $sourceRoot --target $visibleRoot --request-id ('owned.maintenance.source.'+$id)
    if($LASTEXITCODE -ne 0){throw 'Owned maintenance source authoring failed'}
    $replacement=($generated -join "`n")|ConvertFrom-Json
    # The package installs the canonical flat selected archive, not prefixed.zip.
    $replacementArchive=Join-Path (Split-Path -Parent $replacement.bundle_file) 'payload.zip'
    $replacementDigest=(Get-FileHash -LiteralPath $replacementArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if($replacementDigest -cne $currentInstalled.source_archive_digest) {
        throw 'Reauthored replacement differs from the original installed archive'
    }
    $sourceAcl=Get-Acl -LiteralPath $sourceRoot
    $sourceAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),
        'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $sourceRoot -AclObject $sourceAcl
    $result['replacement_archive_sha256']=$replacementDigest
    $context=Join-Path $root ('owned-maintenance-context-'+$id+'.json')
    if(Test-Path -LiteralPath $context){throw 'Owned maintenance context already exists'}
    [IO.File]::WriteAllText($context,(@{schema='usk.oneshot_context.v1';state_root=$drive+'setup-state';
        authorized_acceptance_root=$drive;target_policy_activation='operator_acceptance_candidate'}|
        ConvertTo-Json -Compress)+"`n",$utf8)

    foreach($operation in @('repair','uninstall')) {
        $case=[ordered]@{operation=$operation;status='running';plan=$null;request=$null;
            enrollment=$null;response=$null;before=$null;after=$null}
        $result.cases.Add($case)
        Assert-OwnedVolume
        $before=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $case.before=$before
        $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $previousStamp=([DateTime]$currentInstalled.created_at).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        if($stamp -cle $previousStamp) {
            Start-Sleep -Milliseconds 1100
            $stamp=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            if($stamp -cle $previousStamp){throw 'Owned maintenance timestamp did not advance'}
        }
        $planRequest=[ordered]@{schema=('usk.'+$operation+'_plan_request.v1');
            request_id=('request.owned.'+$operation+'.'+$id);plan_id=('plan.owned.'+$operation+'.'+$id);
            install_id=[string]$currentInstalled.install_id;created_at=$stamp}
        if($operation -ceq 'repair') {
            $planRequest.archive=@{format='zip';path=$replacementArchive;
                expected_sha256=$replacementDigest;strip_prefix=''}
        }
        $requestPath=Join-Path $root ('owned-'+$operation+'-plan.json')
        [IO.File]::WriteAllText($requestPath,(@{schema='usk.oneshot_request.v1';
            request_id=$planRequest.request_id;command=($operation+'.plan');payload=$planRequest;dry_run=$true}|
            ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
        $planningBinding=@{schema='usk.controller_readonly_maintenance_plan.v1';
            machine=$MachineBinary;machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
            request=$requestPath;request_sha256=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant();
            context=$context;context_sha256=(Get-FileHash -LiteralPath $context -Algorithm SHA256).Hash.ToLowerInvariant()}
        $encodedPlanning=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
            ($planningBinding|ConvertTo-Json -Compress)))
        try {
            $planned=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N')) -MaintenancePlanningBinding $encodedPlanning
        } catch {
            $script:clientCleanupConfirmed=$false
            $case['planning_failure']=$_.Exception.Message
            throw
        }
        $case['planning_observation']=$planned
        $observation=$planned.independent.maintenance_plan
        if($planned.independent.identity -cne 'S-1-5-18' -or -not $planned.observer_task_removed -or
            $observation.schema -cne 'usk.controller_readonly_maintenance_plan_observation.v1' -or
            $observation.planner_exited -ne $true -or
            $observation.request_sha256 -cne $planningBinding.request_sha256 -or
            $observation.context_sha256 -cne $planningBinding.context_sha256 -or
            $observation.machine_sha256 -cne $planningBinding.machine_sha256) {
            throw 'Owned SYSTEM maintenance planning binding differs'
        }
        $case.plan=$observation.response_json|ConvertFrom-Json
        $plannerExit=0
        $case['planner_exit_code']=$plannerExit
        if($plannerExit -ne 0 -or $case.plan.status -cne 'ok' -or $case.plan.result.status -cne 'ok' -or
            $case.plan.result.payload.plan_id -cne $planRequest.plan_id -or
            $case.plan.result.payload.plan_digest -cnotmatch '^[0-9a-f]{64}$') {
            throw ('Owned real maintenance planner refused '+$operation)
        }
        $apply=[ordered]@{schema=('usk.'+$operation+'_apply_request.v1');plan_request=$planRequest;
            reviewed_plan_id=$planRequest.plan_id;reviewed_plan_digest=$case.plan.result.payload.plan_digest;
            transaction_id=('owned.'+$operation+'.'+$id);applied_at=$stamp;confirmation='APPLY'}
        $case.request=$apply
        $applyPath=Join-Path $root ('owned-'+$operation+'-apply.json')
        $envelopePath=Join-Path $root ('owned-'+$operation+'-envelope.json')
        [IO.File]::WriteAllText($applyPath,($apply|ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
        [IO.File]::WriteAllText($envelopePath,(@{schema='usk.publisher.maintenance_reviewed_plan_envelope.v1';
            activation='operator_acceptance_candidate';state_root=$drive+'setup-state';acceptance_root=$drive;
            plan_request=$planRequest;reviewed_plan_digest=$apply.reviewed_plan_digest;apply_request=$apply}|
            ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
        $envelopeDigest=(Get-FileHash -LiteralPath $envelopePath -Algorithm SHA256).Hash.ToLowerInvariant()
        $enrolled=& $ServiceControlBinary --enroll-reviewed-operation $service $envelopePath $envelopeDigest $applyPath
        $enrollmentExit=$LASTEXITCODE
        $case.enrollment=($enrolled -join "`n")|ConvertFrom-Json
        if($enrollmentExit -ne 0 -or $case.enrollment.status -cne 'reviewed_operation_enrolled' -or
            $case.enrollment.service -cne $service) {throw 'Owned maintenance enrollment differs'}

        $publicRequest=Join-Path $root ('owned-'+$operation+'-request.json')
        $requestId='owned.'+$operation+'.'+$id
        [IO.File]::WriteAllText($publicRequest,(@{schema='usk.oneshot_request.v1';request_id=$requestId;
            command=($operation+'.apply');payload=$apply;dry_run=$false}|ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
        Invoke-ControllerMaintenanceRequest -RequestPath $publicRequest -RequestId $requestId -Case $case
        $report=$case.response.result.payload
        if($report.schema -cne ('usk.'+$operation+'_report.v1') -or $report.status -cne 'completed' -or
            $report.install_id -cne $currentInstalled.install_id -or $report.transaction_id -cne $apply.transaction_id -or
            $report.plan_id -cne $planRequest.plan_id -or $report.completed_at -cne $stamp) {
            throw 'Owned maintenance report differs from the actual enrolled request'
        }
        $stopDeadline=[DateTime]::UtcNow.AddSeconds(30)
        while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $stopDeadline){Start-Sleep -Milliseconds 100}
        $scm=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($scm.State -cne 'Stopped' -or $scm.ProcessId -ne 0 -or $scm.ExitCode -ne 0 -or
            $scm.PathName -cne $expectedRegisteredCommand){throw 'Owned maintenance service did not stop under its original command'}
        $after=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $case.after=$after
        if($after.independent.identity -cne 'S-1-5-18' -or -not $after.observer_task_removed -or
            $after.independent.native_volume_root_file_id -cne $before.independent.native_volume_root_file_id) {
            throw 'Owned maintenance independent observer or volume identity differs'
        }
        Assert-IndependentProtectedRows -Rows $after.independent.rows -ServiceSid $sid -ConsumerSid $consumerSid -VisibleRoot $visibleRoot
        $documents=@($after.independent.rows|Where-Object content_json|ForEach-Object {$_.content_json|ConvertFrom-Json})
        $state=@($documents|Where-Object {$_.schema -ceq 'usk.installed_state.v1' -and
            $_.install_id -ceq $currentInstalled.install_id -and $_.transaction_id -ceq $apply.transaction_id})
        $leases=@($documents|Where-Object {$_.schema -ceq 'usk.installation_lease_ownership.v1' -and
            $_.install_id -ceq $currentInstalled.install_id -and $_.operation_id -ceq $apply.transaction_id -and $_.operation -ceq $operation})
        $active=@($leases|Where-Object status -ceq 'active');$completed=@($leases|Where-Object status -ceq 'completed')
        $journal=@($documents|Where-Object {$_.schema -ceq 'usk.transaction_journal.v1' -and
            $_.transaction_id -ceq $apply.transaction_id -and $_.plan_digest -ceq $apply.reviewed_plan_digest -and $_.current_state -ceq 'completed'})
        $sealed=@($documents|Where-Object {$_.schema -ceq 'usk.maintenance_effect_record.v1' -and
            $_.transaction_id -ceq $apply.transaction_id -and $_.phase -ceq 'sealed'})
        $audit=@($documents|Where-Object {$_.schema -ceq 'usk.audit_event.v1' -and $_.transaction_id -ceq $apply.transaction_id -and
            $_.operation -ceq $operation -and $_.phase -ceq 'completed' -and $_.status -ceq 'pass' -and $_.plan_id -ceq $planRequest.plan_id})
        if($state.Count -ne 1 -or $leases.Count -ne 2 -or $active.Count -ne 1 -or $completed.Count -ne 1 -or
            $active[0].generation -ne $completed[0].generation -or
            $journal.Count -ne 1 -or $sealed.Count -ne 1 -or $audit.Count -ne 1) {
            throw 'Owned maintenance lacks independent state, completed lease, journal, sealed effects or audit'
        }
        $case['lease_pair']=Assert-ControllerMaintenanceLeasePair -Active $active[0] -Completed $completed[0] -PythonBinary $PythonBinary
        if($operation -ceq 'repair') {
            $restored=@($after.independent.rows|Where-Object path -ceq $damaged.path)
            if($restored.Count -ne 1 -or $restored[0].sha256 -cne $damaged.before_sha256 -or
                @($report.repaired_files|Where-Object relative_path -ceq $damageEntries[0].relative_path).Count -ne 1 -or
                $state[0].lifecycle_status -cne 'verified') {throw 'Owned repair did not restore the exact damaged bytes'}
        } else {
            $remaining=@($after.independent.rows|Where-Object {
                $_.path -ceq $currentRoot -or $_.path.StartsWith($currentRoot+'\',[StringComparison]::Ordinal)})
            $rootIntent=@($documents|Where-Object {$_.schema -ceq 'usk.maintenance_effect_record.v1' -and
                $_.transaction_id -ceq $apply.transaction_id -and $_.phase -ceq 'intent' -and
                $_.details.kind -ceq 'remove_directory' -and $_.details.effect.root_role -ceq 'installed' -and
                $_.details.effect.relative_path -ceq ''})
            $rootComplete=@($documents|Where-Object {$_.schema -ceq 'usk.maintenance_effect_record.v1' -and
                $_.transaction_id -ceq $apply.transaction_id -and $_.phase -ceq 'complete' -and
                $rootIntent.Count -eq 1 -and $_.details.intent_sequence -eq $rootIntent[0].sequence -and $_.details.outcome -ceq 'applied'})
            if($state[0].lifecycle_status -cne 'retired' -or $remaining.Count -ne 0 -or
                @($report.retained_changed_owned_files).Count -ne 0 -or @($report.retained_unknown_paths).Count -ne 0 -or
                @($report.retained_directories).Count -ne 0 -or @($report.deleted_owned_files).Count -ne 2 -or
                $rootIntent.Count -ne 1 -or $rootComplete.Count -ne 1) {
                throw 'Owned uninstall did not remove its complete root with completed removal evidence'
            }
        }
        $currentInstalled=$state[0]
        $case.status='observed_completed'
    }
    $result.status='owned_uninstall_observed_retirement_pending'
    return $result
}

# Called only after the independent uninstall checks and service-end ACL check.
# This fixture observation supplies no authority to the administrative command.
function Invoke-ControllerOwnedRetirement {
    if(-not $AdmittedTarget -or -not $ControllerApply -or -not $script:clientCleanupConfirmed -or
        $receipt.owned_uninstall.status -cne 'owned_uninstall_observed_retirement_pending' -or
        $receipt.owned_uninstall.cases.Count -ne 2 -or
        $receipt.owned_uninstall.cases[-1].status -cne 'observed_completed' -or
        (Get-Service $service).Status -ne 'Stopped') {
        throw 'Owned retirement requires the completed independently observed uninstall'
    }
    $baseline=$receipt.owned_uninstall.cases[-1].after.independent.rows
    $errorFile=Join-Path $root 'owned-retirement-error.txt'
    $retired=& $ServiceControlBinary --retire-owned $service 2>$errorFile
    if($LASTEXITCODE -ne 0) {
        $receipt['product_retirement_failure']=Read-BoundedDiagnostic $errorFile 16384
        throw 'Owned publisher retirement incomplete; retain its actual state for revalidation'
    }
    $reply=$retired|ConvertFrom-Json
    if($reply.schema -cne 'usk.publisher_service_control.v1' -or $reply.status -cne 'owned_retired' -or
        $reply.service -cne $service -or (Get-Service $service -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $installedServiceBinary)) {
        throw 'Owned retirement lacks matching completion and independent service/image absence'
    }
    Assert-OwnedVolume
    $after=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
    if(($baseline|ConvertTo-Json -Depth 64 -Compress) -cne
        ($after.independent.rows|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Owned retirement changed retained lifecycle evidence'
    }
    $receipt['product_owned_retirement']=$reply
    $receipt['protected_service_binary_removed']=$true
    $receipt.owned_uninstall['retirement_observed']=$true
    $receipt.owned_uninstall['after_retirement']=$after
    $receipt.owned_uninstall.status='owned_uninstall_and_retirement_observed'
}
