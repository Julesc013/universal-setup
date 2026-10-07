# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Start-OwnedProductionBoundaryObserver {
    param([ValidateSet('bootstrap','bootstrap_preserved','prepublish','postrename','maintenance_published')][string]$Phase,
        [string]$Service,[string]$ObserverRoot,[string]$VhdPath,[string]$VolumeRoot,
        [string]$DriveRoot,[string]$VisibleRoot,[string]$ServiceCommand,[string]$ServiceBinarySha256,
        [string]$BootstrapOperationPrefix='',
        [string]$MaintenanceTransactionId='', [string]$MaintenancePlanDigest='')
    $utf8=[Text.UTF8Encoding]::new($false)
    if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
        $Service -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or $DriveRoot -cnotmatch '^[A-Z]:\\$' -or
        $VisibleRoot -cne ($DriveRoot+'publication\destination\visible') -or
        $ServiceBinarySha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Production boundary observer requires the exact owned hosted service and target'
    }
    $backing=[IO.Path]::GetFullPath($VhdPath)
    $labRoot=Split-Path -Parent $backing
    $runnerRoot=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
    if(-not $backing.StartsWith($runnerRoot,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $labRoot) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or
        (Split-Path -Leaf $backing) -cne 'publisher.vhdx' -or
        ((Get-Item -LiteralPath $labRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ((Get-Item -LiteralPath $backing).Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ((Get-Item -LiteralPath $ObserverRoot).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Production boundary observer backing or inputs differ from the fresh runner lab'
    }
    $image=Get-DiskImage -ImagePath $backing -ErrorAction Stop
    $disk=$image|Get-Disk -ErrorAction Stop
    $partitions=@($disk|Get-Partition|Where-Object DriveLetter)
    if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $partitions.Count -ne 1) {
        throw 'Production boundary observer volume is not the attached disposable data disk'
    }
    $volume=$partitions[0]|Get-Volume -ErrorAction Stop
    if($volume.UniqueId -cne $VolumeRoot -or $volume.FileSystem -cne 'NTFS' -or
        ([string]$volume.DriveLetter+':\') -cne $DriveRoot) {
        throw 'Production boundary observer volume identity differs'
    }
    if($Phase -cnotin @('bootstrap','bootstrap_preserved','prepublish','postrename','maintenance_published')){throw 'Unknown production boundary phase'}
    if($Phase -ceq 'maintenance_published') {
        if($MaintenanceTransactionId -cnotmatch '^maintenance\.repair\.[0-9a-f]{32}$' -or
            $MaintenancePlanDigest -cnotmatch '^[0-9a-f]{64}$'){throw 'Maintenance boundary requires its exact enrolled repair'}
    } elseif($MaintenanceTransactionId -or $MaintenancePlanDigest){throw 'Unexpected maintenance boundary binding'}
    if($Phase -ceq 'bootstrap_preserved' -and
        $BootstrapOperationPrefix -cnotmatch ('^'+[regex]::Escape($DriveRoot)+
            'installation-operations\\install-[0-9a-f]{64}\\operation-[0-9a-f]{64}$')) {
        throw 'Preservation observer operation prefix differs from the owned native layout'
    }
    if($Phase -cne 'bootstrap_preserved' -and $BootstrapOperationPrefix) {throw 'Unexpected preservation operation prefix'}
    $taskName='USK_RENAME_OBSERVER_'+$Service.Substring(8)
    $scriptPath=Join-Path $observerRoot 'production-rename-observer.ps1'
    $ownedProcessPath=Join-Path $observerRoot 'owned-process.ps1'
    $childObserverPath=Join-Path $observerRoot 'owned-effect-child.ps1'
    $configPath=Join-Path $observerRoot 'production-rename-config.json'
    $readyPath=Join-Path $observerRoot 'production-rename-ready.txt'
    $outputPath=Join-Path $observerRoot 'production-rename-observation.json'
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $scriptPath) -or (Test-Path -LiteralPath $ownedProcessPath) -or (Test-Path -LiteralPath $childObserverPath) -or (Test-Path -LiteralPath $configPath) -or
        (Test-Path -LiteralPath $readyPath) -or (Test-Path -LiteralPath $outputPath)) {
        throw 'Owned production rename observer collision'
    }
    $serviceRow=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
    $processRow=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serviceRow.ProcessId) -ErrorAction Stop
    if($serviceRow.State -cne 'Running' -or $serviceRow.ProcessId -le 0 -or
        $serviceRow.PathName -cne $ServiceCommand -or
        -not $processRow -or -not $processRow.CreationDate -or
        -not $processRow.ExecutablePath -or -not $processRow.CommandLine -or
        (Get-FileHash -LiteralPath $processRow.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $ServiceBinarySha256) {
        throw 'Production rename observer service identity differs before request'
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_publisher_production_rename_observer.ps1') `
        -Destination $scriptPath -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_publisher_owned_process.ps1') `
        -Destination $ownedProcessPath -ErrorAction Stop
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_publisher_owned_effect_child.ps1') `
        -Destination $childObserverPath -ErrorAction Stop
    $config=[ordered]@{schema='usk.publisher.production_rename_observer_config.v2';phase=$Phase;
        service_name=$service;service_command=$serviceRow.PathName;
        process_id=$serviceRow.ProcessId;process_command=$processRow.CommandLine;
        process_executable=$processRow.ExecutablePath;
        process_creation_ticks=$processRow.CreationDate.ToUniversalTime().Ticks;
        service_binary_sha256=$ServiceBinarySha256;
        drive_letter=$DriveRoot.Substring(0,1);volume_guid_root=$VolumeRoot;
        visible_path=$visibleRoot;journal_path=($DriveRoot+'publication\journal\lab-'+
            $(if($Phase -cin @('bootstrap','bootstrap_preserved','prepublish')){'prepared'}else{'visible'})+'-evidence.json');
        ready_path=$readyPath;output_path=$outputPath}
    if($Phase -ceq 'bootstrap_preserved') {$config['bootstrap_operation_prefix']=$BootstrapOperationPrefix}
    if($Phase -ceq 'maintenance_published') {
        $heldWorker=Get-Process -Id $serviceRow.ProcessId -ErrorAction Stop
        try {
            if($heldWorker.HasExited -or [math]::Abs(($heldWorker.StartTime.ToUniversalTime().Ticks)-
                    $processRow.CreationDate.ToUniversalTime().Ticks) -gt 10000) {
                throw 'Maintenance observer worker birth differs before registration'
            }
            $config['process_creation_file_time']=$heldWorker.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16')
        } finally {$heldWorker.Dispose()}
        $config.journal_path=$DriveRoot+'setup-state\state\transactions\'+$MaintenanceTransactionId+
            '.native-maintenance-custody\00000000000000000000.json'
        $config['maintenance_transaction_id']=$MaintenanceTransactionId
        $config['maintenance_plan_digest']=$MaintenancePlanDigest
    }
    [IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Depth 5 -Compress)+"`n",$utf8)
    # Use the held native SCM parent and query-only child observer.
    # The child must end without a separate child/tree termination.
    $action=New-ScheduledTaskAction -Execute (Get-Command pwsh -ErrorAction Stop).Source -Argument (
        '-NoProfile -NonInteractive -File "'+$scriptPath+'" -ConfigPath "'+$configPath+'"')
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $taskName
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while(-not (Test-Path -LiteralPath $readyPath) -and
            -not (Test-Path -LiteralPath $outputPath) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 25
        }
        if(-not (Test-Path -LiteralPath $readyPath) -or
            [IO.File]::ReadAllText($readyPath) -cne "usk.publisher.production_rename_observer_ready.v1`n") {
            $reason=if(Test-Path -LiteralPath $outputPath){
                (Get-Content -LiteralPath $outputPath -Raw|ConvertFrom-Json).failure
            }else{'bounded observer output absent'}
            throw ('Production rename observer did not become ready: '+$reason)
        }
        return [pscustomobject]@{task=$taskName;output=$outputPath;ready=$readyPath;
            config=$configPath;executable=$action.Execute;arguments=$action.Arguments;removed=$false;
            maintenance_transaction_id=$MaintenanceTransactionId;maintenance_plan_digest=$MaintenancePlanDigest;
            process_id=$config.process_id;process_executable=$config.process_executable;
            process_creation_file_time=$(if($Phase -ceq 'maintenance_published'){$config.process_creation_file_time}else{''})}
    } catch {
        if($registered) {
            Remove-OwnedProductionBoundaryObserver ([pscustomobject]@{task=$taskName;
                executable=$action.Execute;arguments=$action.Arguments;removed=$false})
        }
        throw
    }
}
function Complete-OwnedProductionBoundaryObserver($Observer,[ValidateSet('bootstrap','bootstrap_preserved','prepublish','postrename','maintenance_published')][string]$Phase) {
    $deadline=[DateTime]::UtcNow.AddSeconds(150)
    while(-not (Test-Path -LiteralPath $Observer.output) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 25
    }
    if(-not (Test-Path -LiteralPath $Observer.output) -or
        (Get-Item -LiteralPath $Observer.output).Length -gt 16KB) {
        throw 'Production rename observer did not produce bounded output'
    }
    $result=Get-Content -LiteralPath $Observer.output -Raw|ConvertFrom-Json
    Remove-OwnedProductionBoundaryObserver $Observer
    $expectedStatus=if($Phase -ceq 'bootstrap'){
        'terminated_publication_bootstrap'
    }elseif($Phase -ceq 'bootstrap_preserved'){
        'terminated_publication_preserved'
    }elseif($Phase -ceq 'prepublish'){
        'terminated_prepared_prerename'
    }elseif($Phase -ceq 'maintenance_published'){'terminated_confirmed_maintenance_publication'}
    else{'terminated_postrename_prejournal'}
    if($result.schema -cne 'usk.publisher.production_rename_observer.v2' -or
        $result.service_pid -ne $Observer.process_id -or
        $result.original_pair_closure_confirmed -ne $true -or
        $result.native_process_pair.schema -cne 'usk.publisher_owned_native_process_pair.v1' -or
        $result.native_process_pair.scope -cne 'held_scm_parent_termination_and_original_effect_child_end' -or
        $result.native_process_pair.parent_process_id -ne $result.service_pid -or
        $result.native_process_pair.native_parent_process_id -ne $result.service_pid -or
        $result.native_process_pair.parent_process_birth -cne $result.process_creation_file_time -or
        $result.native_process_pair.effect_process_id -ne $result.effect_holder.process_id -or
        $result.native_process_pair.effect_process_birth -cne $result.effect_holder.process_creation_time -or
        $result.native_process_pair.original_image_path -cne $Observer.process_executable -or
        $result.service_executable -cne $Observer.process_executable -or
        $result.effect_holder.process_id -le 0 -or $result.effect_holder.process_id -eq $result.service_pid -or
        $result.effect_holder.process_creation_time -cnotmatch '^[0-9a-f]{16}$' -or
        $result.native_process_pair.both_live_before_termination -ne $true -or
        $result.native_process_pair.parent_termination_invoked -ne $true -or
        $result.native_process_pair.child_termination_invoked -ne $false -or
        $result.native_process_pair.parent_native_wait_result -ne 0 -or
        $result.native_process_pair.child_native_wait_result -ne 0 -or
        $result.native_process_pair.child_observer_access -ne 0x101400 -or
        $result.native_process_pair.child_observer_handle_flags -ne 0 -or
        $result.native_process_pair.child_observer_close_confirmed -ne $true -or
        $result.identity -cne 'S-1-5-18' -or
        $result.phase -cne $Phase -or $result.status -cne $expectedStatus -or
        -not $result.termination.confirmed -or -not $result.termination.kill_invoked -or
        ($Phase -ceq 'maintenance_published' -and
            (-not $result.journal_before_kill -or -not $result.journal_after_kill -or
                $result.maintenance_confirmation_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $result.process_creation_file_time -cnotmatch '^[0-9a-f]{16}$' -or
                $result.process_creation_file_time -cne $Observer.process_creation_file_time -or
                $result.maintenance_transaction_id -cne $Observer.maintenance_transaction_id -or
                $result.maintenance_plan_digest -cne $Observer.maintenance_plan_digest -or
                $result.maintenance_writer_lease_ownership.schema -cne 'usk.installation_lease_ownership.v1' -or
                $result.maintenance_writer_lease_ownership.status -cne 'active' -or
                $result.maintenance_writer_lease_ownership.operation -cne 'repair' -or
                $result.maintenance_writer_lease_ownership.operation_id -cne $Observer.maintenance_transaction_id -or
                $result.maintenance_writer_lease_ownership.holder.process_id -ne $result.effect_holder.process_id -or
                $result.maintenance_writer_lease_ownership.holder.process_creation_time -cne
                    $result.effect_holder.process_creation_time)) -or
        ($Phase -ceq 'bootstrap' -and
            (-not $result.publication_before_kill -or -not $result.publication_after_kill -or
                $result.candidate_before_kill -or $result.candidate_after_kill -or
                $result.journal_before_kill -or $result.journal_after_kill -or $result.visible_after_kill -or
                $result.process_creation_file_time -cnotmatch '^[0-9a-f]{16}$')) -or
        ($Phase -ceq 'bootstrap_preserved' -and
            ($result.publication_before_kill -or $result.publication_after_kill -or
                $result.termination.method -cne 'TerminateProcess_owned_held_root' -or
                $result.termination.process_id -ne $result.service_pid -or
                $result.termination.process_creation_file_time -cne $result.process_creation_file_time -or
                $result.termination.native_wait_result -ne 0 -or
                -not $result.retained_before_kill -or -not $result.retained_after_kill -or
                -not $result.preservation_before_kill -or -not $result.preservation_after_kill -or
                $result.replacement_reservation_before_kill -or $result.replacement_reservation_after_kill -or
                $result.candidate_before_kill -or $result.candidate_after_kill -or
                $result.journal_before_kill -or $result.journal_after_kill -or $result.visible_after_kill -or
                $result.process_creation_file_time -cnotmatch '^[0-9a-f]{16}$')) -or
        ($Phase -ceq 'prepublish' -and
            (-not $result.prepared_exclusive_observed -or
                -not $result.journal_before_kill -or -not $result.journal_after_kill -or
                $result.visible_after_kill -or
                $result.prepared_record_sha256 -cnotmatch '^[0-9a-f]{64}$')) -or
        ($Phase -ceq 'postrename' -and
            ($result.journal_before_kill -or $result.journal_after_kill -or
                -not $result.visible_after_kill))) {
        throw ('Production rename observer did not capture the required window: '+
            ($result|ConvertTo-Json -Depth 5 -Compress))
    }
    return $result
}
function Remove-OwnedProductionBoundaryObserver($Observer) {
    if(-not $Observer -or $Observer.removed){return}
    $task=Get-ScheduledTask -TaskName $Observer.task -ErrorAction SilentlyContinue
    if($task) {
        $principal=if($task.Principal.UserId -match '^S-1-') {
            [Security.Principal.SecurityIdentifier]::new($task.Principal.UserId)
        } else {
            [Security.Principal.NTAccount]::new($task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])
        }
        if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $Observer.executable -or
            $task.Actions[0].Arguments -cne $Observer.arguments -or
            $principal.Value -cne 'S-1-5-18') {
            throw 'Owned production boundary observer task identity changed; retain its inputs'
        }
        if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $Observer.task -ErrorAction Stop}
        Unregister-ScheduledTask -TaskName $Observer.task -Confirm:$false -ErrorAction Stop
    }
    if(Get-ScheduledTask -TaskName $Observer.task -ErrorAction SilentlyContinue) {
        throw 'Owned production boundary observer task remains registered'
    }
    $Observer.removed=$true
}
