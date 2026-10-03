# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Start-OwnedProductionBoundaryObserver {
    param([ValidateSet('prepublish','postrename')][string]$Phase,
        [string]$Service,[string]$ObserverRoot,[string]$VhdPath,[string]$VolumeRoot,
        [string]$DriveRoot,[string]$VisibleRoot,[string]$ServiceCommand,[string]$ServiceBinarySha256)
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
    if($Phase -cnotin @('prepublish','postrename')){throw 'Unknown production boundary phase'}
    $taskName='USK_RENAME_OBSERVER_'+$Service.Substring(8)
    $scriptPath=Join-Path $observerRoot 'production-rename-observer.ps1'
    $ownedProcessPath=Join-Path $observerRoot 'owned-process.ps1'
    $configPath=Join-Path $observerRoot 'production-rename-config.json'
    $readyPath=Join-Path $observerRoot 'production-rename-ready.txt'
    $outputPath=Join-Path $observerRoot 'production-rename-observation.json'
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $scriptPath) -or (Test-Path -LiteralPath $ownedProcessPath) -or (Test-Path -LiteralPath $configPath) -or
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
    $config=[ordered]@{schema='usk.publisher.production_rename_observer_config.v1';phase=$Phase;
        service_name=$service;service_command=$serviceRow.PathName;
        process_id=$serviceRow.ProcessId;process_command=$processRow.CommandLine;
        process_executable=$processRow.ExecutablePath;
        process_creation_ticks=$processRow.CreationDate.ToUniversalTime().Ticks;
        service_binary_sha256=$ServiceBinarySha256;
        drive_letter=$DriveRoot.Substring(0,1);volume_guid_root=$VolumeRoot;
        visible_path=$visibleRoot;journal_path=($DriveRoot+'publication\journal\lab-'+
            $(if($Phase -ceq 'prepublish'){'prepared'}else{'visible'})+'-evidence.json');
        ready_path=$readyPath;output_path=$outputPath}
    [IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Depth 5 -Compress)+"`n",$utf8)
    # The shared owned-process helper needs PowerShell 7's .NET Kill(true)
    # overload to terminate the exact held process tree.
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
            config=$configPath;executable=$action.Execute;arguments=$action.Arguments;removed=$false}
    } catch {
        if($registered) {
            Remove-OwnedProductionBoundaryObserver ([pscustomobject]@{task=$taskName;
                executable=$action.Execute;arguments=$action.Arguments;removed=$false})
        }
        throw
    }
}
function Complete-OwnedProductionBoundaryObserver($Observer,[ValidateSet('prepublish','postrename')][string]$Phase) {
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
    $expectedStatus=if($Phase -ceq 'prepublish'){
        'terminated_prepared_prerename'
    }else{'terminated_postrename_prejournal'}
    if($result.schema -cne 'usk.publisher.production_rename_observer.v1' -or
        $result.identity -cne 'S-1-5-18' -or
        $result.phase -cne $Phase -or $result.status -cne $expectedStatus -or
        -not $result.termination.confirmed -or -not $result.termination.kill_invoked -or
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
