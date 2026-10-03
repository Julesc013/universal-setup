# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$ServiceControlBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Public publisher qualification requires the owned hosted runner lab'
}
$lab=[IO.Path]::GetFullPath((Split-Path -Parent $VhdPath))
$runner=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
if(-not $lab.StartsWith($runner,[StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$') {
    throw 'Public publisher backing file is outside the newly created runner lab'
}
$image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
$disk=$image|Get-Disk -ErrorAction Stop
$partitions=@($disk|Get-Partition|Where-Object DriveLetter)
if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $partitions.Count -ne 1) {
    throw 'Public publisher target is not the exact attached disposable data volume'
}
$actual=$partitions[0]|Get-Volume
if($actual.UniqueId -cne $VolumeRoot -or $actual.FileSystem -cne 'NTFS') {
    throw 'Public publisher target volume differs from the owned VHD'
}
$drive=[string]$actual.DriveLetter+':\'
$id=[guid]::NewGuid().ToString('N')
$service='USK_PUB_'+$id
$caller=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$utf8=[Text.UTF8Encoding]::new($false)
$receipt=[ordered]@{schema='usk.publisher_public_path_probe.v1';status='not_run';
    service=$service;volume_root=$VolumeRoot;volume_drive_root=$drive;
    partition_layout=@($disk|Get-Partition|Select-Object PartitionNumber,Offset,Size,GptType,MbrType,IsBoot,IsSystem);
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    service_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    client_cleanup_confirmed=$false}
$created=$false
$installedBinary=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$service+'.exe')
function Write-Json([string]$Path,$Value) {
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
}
function Invoke-PublicRequest([string]$Command,$Payload,[int]$ExpectedExit=0) {
    $request=Join-Path $lab ('public-request-'+[guid]::NewGuid().ToString('N')+'.json')
    $requestId='public.'+[guid]::NewGuid().ToString('N')
    Write-Json $request ([ordered]@{schema='usk.oneshot_request.v1';request_id=$requestId;
        command=$Command;payload=$Payload;dry_run=$false})
    $output=& $MachineBinary --machine --publisher $service --request-file $request
    $exit=$LASTEXITCODE
    $result=($output -join "`n")|ConvertFrom-Json
    if($exit -ne $ExpectedExit -or $result.schema -cne 'usk.oneshot_response.v1' -or
        $result.request_id -cne $requestId -or
        ($exit -eq 0 -and ($result.status -cne 'ok' -or
            $result.result.schema -cne 'usk.command_response.v1' -or $result.result.status -cne 'ok')) -or
        ($output -join "`n") -match 'usk.publisher_lab_service_observation|dacl_aces|private_phase_evidence') {
        throw ('Ordinary public response differs: '+($output -join "`n"))
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    if((Get-Service $service).Status -ne 'Stopped'){throw 'Public one-request service did not stop'}
    return $result
}
function Read-IndependentState {
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab `
        -RunId ([guid]::NewGuid().ToString('N'))
    if(-not $readback.observer_task_removed -or $readback.independent.identity -cne 'S-1-5-18') {
        throw 'Independent public-path readback identity or cleanup differs'
    }
    Assert-IndependentProtectedRows -Rows $readback.independent.rows -ServiceSid $sid
    foreach($entry in @($plan.planned_entries|Where-Object entry_type -eq 'file')) {
        $expected=([string]$plan.target.root).Replace('/','\')+'\'+$entry.relative_path.Replace('/','\')
        $rows=@($readback.independent.rows|Where-Object path -ceq $expected)
        if($rows.Count -ne 1 -or $rows[0].sha256 -cne $entry.sha256 -or $rows[0].bytes -ne $entry.size_bytes) {
            throw 'Public install payload differs from independently read planned bytes'
        }
    }
    return $readback.independent
}
try {
    $fixture=Join-Path $lab 'authored-inputs'
    New-Item -ItemType Directory -Path $fixture -ErrorAction Stop|Out-Null
    $generated=& python -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $fixture --target ($drive+'publication\destination\visible') --request-id ('public.'+$id)
    if($LASTEXITCODE -ne 0){throw 'Public-path authored fixture failed'}
    $inputs=($generated -join "`n")|ConvertFrom-Json
    $context=Join-Path $lab 'context.json'
    Write-Json $context @{schema='usk.oneshot_context.v1';state_root=$drive+'setup-state';
        authorized_acceptance_root=$drive;target_policy_activation='operator_acceptance_candidate'}
    $output=& $MachineBinary --machine --request-file $inputs.request_file --context-file $context
    if($LASTEXITCODE -ne 0){throw 'Public-path native planning failed'}
    $planned=($output -join "`n")|ConvertFrom-Json
    $plan=$planned.result.payload
    if($plan.required_commit_authority -cne 'staged_child_bound_v1' -or $plan.commit_authority_available -ne $false) {
        throw 'Unqualified plan claimed publisher availability'
    }
    $planResponse=Join-Path $lab 'plan-response.json'
    [IO.File]::WriteAllText($planResponse,($output -join "`n")+"`n",$utf8)
    $bound=& python -B (Join-Path $PSScriptRoot '..\tools\usk_bundle_apply_binding.py') `
        --request-file $inputs.request_file --response-file $planResponse --acceptance-root $drive `
        --state-root ($drive+'setup-state') --transaction-id ('install.'+$id) `
        --applied-at ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) --output-dir (Join-Path $fixture 'binding')
    if($LASTEXITCODE -ne 0){throw 'Public-path reviewed binding failed'}
    $binding=($bound -join "`n")|ConvertFrom-Json
    $apply=Get-Content -LiteralPath $binding.apply_file -Raw|ConvertFrom-Json
    $registered=& $ServiceControlBinary --register $service $ServiceBinary $VolumeRoot `
        $binding.envelope_file $binding.envelope_sha256 $caller $receipt.service_sha256
    if($LASTEXITCODE -ne 0 -or ($registered|ConvertFrom-Json).status -cne 'registered') {
        throw 'Public-path persistent registration failed'
    }
    $created=$true
    $sid=[Security.Principal.NTAccount]::new('NT SERVICE\'+$service).Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt['service_sid']=$sid
    # The package input is deliberately readable by the new restricted
    # service. These are fresh test input files outside the target volume;
    # this grants no target mutation rights and does not protect its boundary.
    $inputAcl=Get-Acl -LiteralPath $fixture
    $inputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $fixture -AclObject $inputAcl
    $command=(Get-CimInstance Win32_Service -Filter "Name='$service'").PathName
    $display=(Get-CimInstance Win32_Service -Filter "Name='$service'").DisplayName
    $registrationRecord=Join-Path (Split-Path -Parent $installedBinary) ($service+'.binding.json')
    $retainedRegistration=Get-Content -LiteralPath $registrationRecord -Raw
    $retainedRegistrationHash=(Get-FileHash -LiteralPath $registrationRecord -Algorithm SHA256).Hash
    # Model interruption after SCM/SID/executable creation but before the
    # completion record. Only this newly created owned registration is edited;
    # this fixture is not a process-kill or power-loss result.
    Remove-Item -LiteralPath $registrationRecord -ErrorAction Stop
    $resumed=& $ServiceControlBinary --register $service $ServiceBinary $VolumeRoot `
        $binding.envelope_file $binding.envelope_sha256 $caller $receipt.service_sha256
    if($LASTEXITCODE -ne 0 -or ($resumed|ConvertFrom-Json).status -cne 'registered' -or
        (Get-Content -LiteralPath $registrationRecord -Raw) -cne $retainedRegistration -or
        (Get-FileHash -LiteralPath $registrationRecord -Algorithm SHA256).Hash -cne $retainedRegistrationHash -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").DisplayName -cne $display) {
        throw 'Owned registration completion recovery differs from retained creation intent'
    }
    $receipt['registration_completion_reentry']='same protected binding and tagged SCM identity'
    $marker=$drive+'preexisting-public-marker.bin'
    [IO.File]::WriteAllBytes($marker,[byte[]]@(0x55,0x53,0x4b,0x2d,0x50,0x52,0x45))
    $rootBefore=(Get-Acl -LiteralPath $VolumeRoot).Sddl
    $markerBefore=(Get-Acl -LiteralPath $marker).Sddl
    $markerHash=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
    $held=[IO.File]::Open($marker,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        & $ServiceControlBinary --provision-target $service --confirm-empty-volume 2>$null|Out-Null
        if($LASTEXITCODE -ne 3 -or (Get-Acl -LiteralPath $VolumeRoot).Sddl -cne $rootBefore) {
            throw 'Public target admission accepted an open file or changed root security'
        }
    } finally {$held.Dispose()}
    & $ServiceControlBinary --provision-target $service --confirm-empty-volume 2>$null|Out-Null
    if($LASTEXITCODE -ne 3 -or (Get-Acl -LiteralPath $VolumeRoot).Sddl -cne $rootBefore -or
        (Get-Acl -LiteralPath $marker).Sddl -cne $markerBefore -or
        (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash -cne $markerHash) {
        throw 'Public target admission altered a preexisting marker before refusing it'
    }
    $receipt['preexisting_target_refused_unchanged']=$true
    Remove-Item -LiteralPath $marker -ErrorAction Stop
    # No lab helper changes the volume-root or raw-device ACL. The product
    # controller owns this admitted-target transition and its durable records.
    $provisioned=& $ServiceControlBinary --provision-target $service --confirm-empty-volume
    if($LASTEXITCODE -ne 0 -or ($provisioned|ConvertFrom-Json).status -cne 'target_admitted') {
        throw 'Product target admission failed'
    }
    $receipt['provisioning']=$provisioned|ConvertFrom-Json
    & $ServiceControlBinary --verify $service $installedBinary $VolumeRoot $caller|Out-Null
    if($LASTEXITCODE -ne 3 -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command) {
        throw 'Legacy mode change altered an admitted public registration'
    }
    # Repeat the admission before publication to check immutable-intent reentry.
    & $ServiceControlBinary --provision-target $service --confirm-empty-volume|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Product target admission reentry failed'}
    $receipt['apply']=Invoke-PublicRequest 'install_local.apply' $apply
    $installed=$receipt.apply.result.payload
    if($installed.install_id -cne $apply.plan_request.install_id -or
        $installed.transaction_id -cne $apply.transaction_id -or $installed.lifecycle_status -cne 'installed') {
        throw 'Ordinary public installation identity differs'
    }
    $before=Read-IndependentState
    $receipt['installed_readback']=$before
    & $ServiceControlBinary --unregister $service $installedBinary $VolumeRoot $caller|Out-Null
    if($LASTEXITCODE -ne 3 -or (Get-Service $service).Status -ne 'Stopped' -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command -or
        (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.service_sha256) {
        throw 'Installed public publisher recovery authority was removed'
    }
    $receipt['installed_authority_retirement_refused']=$true
    # Remove only the exact fresh fixture below this run's already checked lab.
    $exactFixture=[IO.Path]::GetFullPath($fixture)
    if($exactFixture -cne (Join-Path $lab 'authored-inputs') -or
        (Get-Item -LiteralPath $exactFixture).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Source-free recovery cleanup escaped the owned fixture'
    }
    Remove-Item -LiteralPath $exactFixture -Recurse -Force -ErrorAction Stop
    if(Test-Path -LiteralPath $binding.envelope_file){throw 'Original reviewed source remains'}
    $recovery=@{schema='usk.publisher_recovery_request.v1';request_id='recover.'+$id;
        install_id=$installed.install_id;transaction_id=$installed.transaction_id}
    $receipt['recovery']=Invoke-PublicRequest 'install_local.recover' $recovery
    $receipt['replayed_apply']=Invoke-PublicRequest 'install_local.apply' $apply
    foreach($terminal in @($receipt.recovery,$receipt.replayed_apply)) {
        if(($terminal.result.payload|ConvertTo-Json -Depth 64 -Compress) -cne
            ($installed|ConvertTo-Json -Depth 64 -Compress)) {throw 'Source-free public reentry changed installed state'}
    }
    $after=Read-IndependentState
    if(($before.rows|ConvertTo-Json -Depth 64 -Compress) -cne ($after.rows|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Source-free public recovery changed independently read target state'
    }
    $receipt['recovered_readback']=$after
    $verify=@{schema='usk.publisher_installed_verify_request.v1';install_id=$installed.install_id;
        transaction_id=$installed.transaction_id;report_id='verify.'+$id;
        verified_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
    $receipt['verification']=Invoke-PublicRequest 'installed.verify' $verify
    if($receipt.verification.result.payload.status -cne 'pass' -or
        $receipt.verification.result.payload.report_id -cne $verify.report_id) {
        throw 'Ordinary public verification did not return the bound passing report'
    }
    if((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command) {
        throw 'Public apply/recovery/verification reconfigured SCM'
    }
    $receipt.status='public_install_verified_recovered'
} catch {
    $receipt.status='failed';$receipt['failure']=$_.Exception.Message
} finally {
    if($created -and (Get-Service $service -ErrorAction SilentlyContinue)) {
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 50}
        if((Get-Service $service).Status -eq 'Stopped') {
            # Every synchronous client has returned and the own-process
            # service has stopped. The independent observer removed its task.
            # Retain SCM, executable and protected registration records for
            # disposable runner shutdown. Disposing this owned test volume is
            # laboratory cleanup, not qualified installed-authority retirement.
            $receipt.client_cleanup_confirmed=$true
            $receipt['retained_authority_cleanup']='stopped SCM entry, executable and records retained until owned runner disposal'
        }
    }
    Write-Json $OutputPath $receipt
}
if($receipt.status -cne 'public_install_verified_recovered' -or -not $receipt.client_cleanup_confirmed) {
    throw ('Public publisher qualification failed: '+$receipt.failure)
}
