# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [string]$ServiceControlBinary = '',
    [Parameter(Mandatory=$true)][string]$DeviceAclBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$PublicApplyBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$ClientBinary = '',
    [string]$PayloadBinary = '',
    [switch]$ConsumerAccess,
    [switch]$InterruptDuringConsumerAccess,
    [switch]$InterruptAfterVisibleRecord,
    [switch]$InterruptAfterRename,
    [switch]$InterruptBeforePublish,
    [switch]$InterruptAfterStage,
    [switch]$TerminateAtPoststage,
    [switch]$TerminateAtPostrename,
    [switch]$ReviewedSource,
    [switch]$RegisteredService,
    [switch]$ReuseRegistration,
    [switch]$MachineRequestClient,
    [switch]$ControllerApply,
    [switch]$NonAdminClient,
    [switch]$ProductionConcurrentRights,
    [switch]$ProductionPostpublishRights,
    [switch]$ProductionPostrenameTermination,
    [switch]$ProductionPreparedTermination,
    [switch]$ExpectUnprotectedRefusal,
    [switch]$ExpectPreexistingAnchorRefusal,
    [switch]$HostileRights,
    [switch]$HostilePostrename
)
$ErrorActionPreference='Stop'
if($HostilePostrename) {
    if($HostileRights){throw 'Select one hostile-rights phase'}
    $HostileRights=$true
}
if($ReuseRegistration -and ($InterruptAfterStage -or $TerminateAtPostrename)) {
    throw 'Fault injection restores the owned service command before recovery'
}
function Read-BoundedDiagnostic([string]$Path,[int]$Limit) {
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    try {
        $bytes=[byte[]]::new($Limit)
        $count=$stream.Read($bytes,0,$Limit)
        return [Text.Encoding]::UTF8.GetString($bytes,0,$count)
    } finally {$stream.Dispose()}
}
if(([int][bool]$InterruptAfterVisibleRecord+[int][bool]$InterruptAfterRename+[int][bool]$InterruptBeforePublish+[int][bool]$InterruptAfterStage) -gt 1){throw 'Select one interruption window'}
if($InterruptDuringConsumerAccess -and (-not $ConsumerAccess -or $InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage)){throw 'Consumer interruption requires its exclusive consumer profile'}
if($ConsumerAccess -and (-not $ClientBinary -or -not $PayloadBinary)){throw 'Consumer profile requires client and actual executable'}
if($InterruptAfterStage -and -not $ClientBinary){throw 'Snapshot-only replay requires an authenticated client'}
if($TerminateAtPoststage -and (-not $InterruptAfterStage -or -not $RegisteredService -or $MachineRequestClient -or $NonAdminClient -or $ConsumerAccess)){throw 'Poststage process termination requires the registered publisher client and its exclusive interruption window'}
if($TerminateAtPostrename -and (-not $InterruptAfterRename -or -not $RegisteredService -or $MachineRequestClient -or $NonAdminClient -or $ConsumerAccess)){throw 'Postrename process termination requires the registered publisher client and its exclusive interruption window'}
if($ReviewedSource -and -not $ClientBinary){throw 'Reviewed source selection requires an authenticated client'}
if($ExpectUnprotectedRefusal -and (-not $ReviewedSource -or $ConsumerAccess -or $HostileRights -or
    $InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage)) {
    throw 'Unprotected-root refusal requires only the reviewed-source hosted profile'
}
if($ExpectPreexistingAnchorRefusal -and (-not $RegisteredService -or -not $ReviewedSource -or
    $ExpectUnprotectedRefusal -or $ConsumerAccess -or $NonAdminClient -or $HostileRights -or
    $InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or
    $InterruptAfterStage -or $ProductionConcurrentRights -or $ProductionPostpublishRights -or
    $ProductionPostrenameTermination -or $ProductionPreparedTermination -or
    $MachineRequestClient -or $ControllerApply -or $ReuseRegistration)) {
    throw 'Preexisting-anchor refusal requires only the uninterrupted registered reviewed-source profile'
}
if($RegisteredService -and (-not $ReviewedSource -or -not $ClientBinary -or -not $ServiceControlBinary -or
    $ExpectUnprotectedRefusal -or
    $InterruptAfterVisibleRecord -or ($InterruptAfterRename -and -not $TerminateAtPostrename) -or
    $InterruptBeforePublish -or
    $InterruptDuringConsumerAccess)) {
    throw 'Registered service probe requires a reviewed-source request and an admitted interruption window'
}
if($MachineRequestClient -and (-not $RegisteredService -or -not $MachineBinary -or
    $NonAdminClient -or $InterruptAfterStage -or $HostileRights)) {
    throw 'Packaged machine request client requires uninterrupted registered same-user service profile'
}
if($ControllerApply -and (-not $RegisteredService -or $MachineRequestClient -or
    $NonAdminClient -or $ConsumerAccess -or $ProductionConcurrentRights -or
    $HostileRights -or $InterruptAfterStage -or $InterruptAfterVisibleRecord -or
    $InterruptAfterRename -or $InterruptBeforePublish)) {
    throw 'Controller apply requires uninterrupted registered same-user service profile'
}
if($RegisteredService -and $HostileRights -and -not $NonAdminClient) {
    throw 'Registered hostile-rights proof requires the same owned non-admin client identity'
}
function Read-ConcurrentAttackerDiagnostic([string]$ReceiptPath,[string]$ErrorPath) {
    if((Test-Path -LiteralPath $ReceiptPath -PathType Leaf) -and
        (Get-Item -LiteralPath $ReceiptPath).Length -le 512KB) {
        try {
            $attack=Get-Content -LiteralPath $ReceiptPath -Raw|ConvertFrom-Json
            if($attack.schema -ceq 'usk.publisher.unprivileged_access_probe.v1' -and
                $attack.status -ceq 'failed' -and $attack.failure) {
                return ([string]$attack.failure).Substring(0,
                    [math]::Min(512,([string]$attack.failure).Length))
            }
        } catch {}
    }
    if(Test-Path -LiteralPath $ErrorPath -PathType Leaf) {
        $diagnostic=Read-BoundedDiagnostic $ErrorPath 2048
        if($diagnostic){return $diagnostic}
    }
    return 'bounded attacker diagnostic absent'
}
if($ProductionConcurrentRights -and (-not $RegisteredService -or -not $ReviewedSource -or
    -not ($NonAdminClient -or ($ConsumerAccess -and $MachineRequestClient)) -or $HostileRights -or
    $InterruptAfterStage -or $TerminateAtPoststage -or $TerminateAtPostrename -or
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_service.exe')) {
    throw 'Production concurrent rights probe requires the registered service and its non-admin client'
}
if($ProductionPostpublishRights -and (-not $ProductionConcurrentRights -or -not $NonAdminClient -or
    $ConsumerAccess -or $HostileRights -or $ProductionPostrenameTermination)) {
    throw 'Production postpublish rights probe requires the exact non-admin production operation'
}
if(($ProductionPostrenameTermination -or $ProductionPreparedTermination) -and
    (-not $RegisteredService -or -not $ReviewedSource -or
    -not $ClientBinary -or $NonAdminClient -or $ConsumerAccess -or $MachineRequestClient -or
    $ProductionConcurrentRights -or $HostileRights -or $ControllerApply -or
    $InterruptAfterStage -or $InterruptAfterRename -or $InterruptBeforePublish -or
    $InterruptAfterVisibleRecord -or $TerminateAtPoststage -or $TerminateAtPostrename -or
    ($ProductionPostrenameTermination -and $ProductionPreparedTermination) -or
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_service.exe')) {
    throw 'Production boundary termination requires the registered production service'
}
if($RegisteredService -and ($InterruptAfterStage -or $TerminateAtPostrename) -and
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_lab_service_fault.exe') {
    throw 'Registered interruption requires the separately built fault-test service'
}
if($RegisteredService -and $HostileRights -and
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_lab_service_fault.exe') {
    throw 'Registered hostile-rights proof requires the separately built fault-test service'
}
if($NonAdminClient -and (-not $RegisteredService -or $ConsumerAccess)) {
    throw 'Non-admin client requires the registered service without consumer payload rights'
}
$registeredMode=if($ConsumerAccess){'--grant-client-read'}elseif($NonAdminClient){'--admit-client-observer'}else{''}
$script:controllerPending=[bool]$ControllerApply
$script:controllerMode='apply'
$recover=$InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage -or $InterruptDuringConsumerAccess -or $ProductionPostrenameTermination -or $ProductionPreparedTermination
if($HostileRights -and $recover){throw 'Hostile-rights observation requires an uninterrupted operation'}
$gate=if($InterruptAfterStage){'poststage'}elseif($InterruptBeforePublish -or $ProductionPreparedTermination){'prepublish'}elseif($InterruptAfterRename -or $ProductionPostrenameTermination){'postrename'}else{'postjournal'}
$readyContent=if($InterruptAfterStage){"usk.publisher.lab_snapshot_and_stage_sealed.v1`n"}elseif($InterruptBeforePublish){"usk.publisher.lab_prepared.v1`n"}elseif($InterruptAfterRename){"usk.publisher.lab_renamed_unconfirmed.v1`n"}else{"usk.publisher.lab_visible_recorded.v1`n"}
$recoveryDecision=if($InterruptAfterStage){'snapshot_only_completed_forward'}elseif($InterruptDuringConsumerAccess){'already_visible_bound'}elseif($InterruptAfterVisibleRecord){'installed_state_completed_forward'}else{'visible_bound_forward'}
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_payload_damage.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_process.ps1')
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Metadata execution requires the administrative disposable hosted Windows VM'
}
$vhd=[IO.Path]::GetFullPath($VhdPath)
$temp=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
if(-not $vhd.StartsWith($temp+'\',[StringComparison]::OrdinalIgnoreCase) -or
    ((Get-Item -LiteralPath $vhd).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Owned runner VHD required'
}
$image=Get-DiskImage -ImagePath $vhd
$disk=@($image|Get-Disk)
$partitions=@($disk|Get-Partition|Where-Object DriveLetter)
if(-not $image.Attached -or $disk.Count -ne 1 -or $disk[0].IsBoot -or $disk[0].IsSystem -or
    $partitions.Count -ne 1 -or (Get-Volume -Partition $partitions[0]).UniqueId -ne $VolumeRoot -or
    (Get-Volume -Partition $partitions[0]).FileSystem -ne 'NTFS') { throw 'Owned NTFS VHD identity differs' }
$disk=$disk[0]
$drive=[string]$partitions[0].DriveLetter+':\'
$visibleLeaf=if($ProductionConcurrentRights -or ($RegisteredService -and $InterruptAfterStage)){'selected-app'}else{'visible'}
$visibleRoot=$drive+'publication\destination\'+$visibleLeaf
function Assert-OwnedVolume {
    $liveImage=Get-DiskImage -ImagePath $vhd
    $live=@($liveImage|Get-Disk)
    if(-not $liveImage.Attached -or $live.Count -ne 1 -or $live[0].Path -ne $disk.Path -or
        $live[0].UniqueId -ne $disk.UniqueId -or $live[0].IsBoot -or $live[0].IsSystem -or
        (Get-Volume -DriveLetter $partitions[0].DriveLetter).UniqueId -ne $VolumeRoot) {
        throw 'Owned VHD changed before privileged operation'
    }
}
function Get-OwnedVolumeRootSddl([string]$Phase) {
    if($Phase -notin @('service-start','service-end') -or
        $VolumeRoot -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') {
        throw 'Owned root ACL observer arguments differ'
    }
    Assert-OwnedVolume
    $taskName='USK_ROOT_ACL_'+$id+'_'+$Phase
    $observation=Join-Path $observerRoot ('root-acl-'+$Phase+'.json')
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $observation)) { throw 'Owned root ACL observer collision' }
    $command='$ErrorActionPreference=''Stop'';if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne ''S-1-5-18''){throw ''SYSTEM root ACL observer required''};'+
        '$sddl=(Get-Acl -LiteralPath '''+$VolumeRoot.Replace("'","''")+''').Sddl;'+
        '[IO.File]::WriteAllText('''+$observation.Replace("'","''")+''',(@{identity=''S-1-5-18'';sddl=$sddl}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $taskName
        $deadline=[DateTime]::UtcNow.AddSeconds(45)
        while(-not (Test-Path -LiteralPath $observation) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $observation)){throw 'Owned root ACL observer receipt absent'}
        $result=Get-Content -LiteralPath $observation -Raw|ConvertFrom-Json
        if($result.identity -ne 'S-1-5-18' -or [string]::IsNullOrWhiteSpace($result.sddl)) {
            throw 'Owned root ACL observer identity or descriptor differs'
        }
        return $result.sddl
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Owned root ACL observer cleanup failed'}
        }
        if(Test-Path -LiteralPath $observation){Remove-Item -LiteralPath $observation -Force -ErrorAction Stop}
    }
}
function Get-OwnedPreexistingAnchorObservation {
    if($VolumeRoot -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') {
        throw 'Owned anchor observer volume argument differs'
    }
    Assert-OwnedVolume
    $taskName='USK_ANCHOR_'+$id
    $observation=Join-Path $observerRoot 'preexisting-anchor-end.json'
    $pending=$observation+'.pending'
    $failurePath=$observation+'.failure.json'
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $observation) -or (Test-Path -LiteralPath $pending) -or
        (Test-Path -LiteralPath $failurePath)) {
        throw 'Owned anchor observer collision'
    }
    $anchor=$drive+'publication'
    $marker=Join-Path $anchor 'preexisting-owner-marker.bin'
    $state=$drive+'setup-state'
    $command='$ErrorActionPreference=''Stop'';'+
        '$who=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;'+
        'if($who -ne ''S-1-5-18''){throw ''SYSTEM anchor observer required''};'+
        '$anchor='''+$anchor.Replace("'","''")+''';'+
        '$marker='''+$marker.Replace("'","''")+''';'+
        '$state='''+$state.Replace("'","''")+''';'+
        '$a=Get-Item -LiteralPath $anchor -Force;'+
        '$m=Get-Item -LiteralPath $marker -Force;'+
        'if(-not $a.PSIsContainer -or ($a.Attributes -band [IO.FileAttributes]::ReparsePoint) -or '+
        '$m.PSIsContainer -or ($m.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw ''Anchor shape changed''};'+
        '$result=@{identity=$who;anchor_path=$a.FullName;'+
        'child_count=@(Get-ChildItem -LiteralPath $anchor -Force).Count;'+
        'marker_bytes=$m.Length;'+
        'marker_sha256=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash.ToLowerInvariant();'+
        'anchor_sddl=(Get-Acl -LiteralPath $anchor).Sddl;'+
        'marker_sddl=(Get-Acl -LiteralPath $marker).Sddl;'+
        'setup_state_present=(Test-Path -LiteralPath $state)};'+
        '$pending='''+$pending.Replace("'","''")+''';'+
        '$final='''+$observation.Replace("'","''")+''';'+
        '[IO.File]::WriteAllText($pending,($result|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false));'+
        '[IO.File]::Move($pending,$final)'
    $failureCommand='$failurePath='''+$failurePath.Replace("'","''")+''';'+
        'try{'+$command+'}catch{'+
        '$message=$_.Exception.Message;'+
        'if($message.Length -gt 512){$message=$message.Substring(0,512)};'+
        '$result=@{schema=''usk.publisher.anchor_observer_failure.v1'';message=$message};'+
        '[IO.File]::WriteAllText($failurePath,($result|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false));'+
        'exit 2}'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($failureCommand))
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $taskName
        $deadline=[DateTime]::UtcNow.AddSeconds(45)
        while(-not (Test-Path -LiteralPath $observation) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $observation)){
            $taskResult=(Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop).LastTaskResult
            $detail=''
            if(Test-Path -LiteralPath $failurePath){
                if((Get-Item -LiteralPath $failurePath).Length -gt 2KB){
                    throw 'Owned anchor observer failure record exceeds bound'
                }
                $record=Get-Content -LiteralPath $failurePath -Raw|ConvertFrom-Json
                if($record.schema -cne 'usk.publisher.anchor_observer_failure.v1'){
                    throw 'Owned anchor observer failure record differs'
                }
                $detail=': '+$record.message
            }
            throw ('Owned anchor observer receipt absent; task result '+$taskResult+$detail)
        }
        if((Get-Item -LiteralPath $observation).Length -gt 16KB){throw 'Owned anchor observation exceeds bound'}
        $result=Get-Content -LiteralPath $observation -Raw|ConvertFrom-Json
        if($result.identity -cne 'S-1-5-18') {throw 'Owned anchor observer identity differs'}
        return $result
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Owned anchor observer cleanup failed'}
        }
        if(Test-Path -LiteralPath $pending){Remove-Item -LiteralPath $pending -Force -ErrorAction Stop}
        if(Test-Path -LiteralPath $failurePath){Remove-Item -LiteralPath $failurePath -Force -ErrorAction Stop}
        if(Test-Path -LiteralPath $observation){Remove-Item -LiteralPath $observation -Force -ErrorAction Stop}
    }
}
function Start-StageObserver {
    Assert-OwnedVolume
    $taskName='USK_STAGE_OBSERVER_'+$id
    $scriptPath=Join-Path $observerRoot 'stage-observer.ps1'
    $readyPath=Join-Path $observerRoot 'stage-ready.txt'
    $stopPath=Join-Path $observerRoot 'stage-stop.txt'
    $outputPath=Join-Path $observerRoot 'stage-observation.json'
    $stagePath=$VolumeRoot+'publication\staging\candidate\'+$attackRelative.Replace('/','\')
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $scriptPath) -or (Test-Path -LiteralPath $readyPath) -or
        (Test-Path -LiteralPath $stopPath) -or (Test-Path -LiteralPath $outputPath)) {
        throw 'Owned stage observer collision'
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_publisher_stage_observer.ps1') `
        -Destination $scriptPath -ErrorAction Stop
    $arguments='-NoProfile -NonInteractive -File "'+$scriptPath+'" -StagePath "'+
        $stagePath+'" -VisiblePath "'+$visibleRoot+'" -ReadyPath "'+$readyPath+'" -StopPath "'+$stopPath+
        '" -OutputPath "'+$outputPath+'" -SourcePath "'+$attackSource+'"'
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $taskName
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while(-not (Test-Path -LiteralPath $readyPath) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 25
        }
        if(-not (Test-Path -LiteralPath $readyPath) -or
            [IO.File]::ReadAllText($readyPath) -cne "usk.publisher.stage_observer_ready.v1`n") {
            throw 'SYSTEM stage observer did not become ready'
        }
        return [pscustomobject]@{task=$taskName;script=$scriptPath;ready=$readyPath;
            stop=$stopPath;output=$outputPath;removed=$false}
    } catch {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if($task -and $task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        }
        throw
    }
}
function Complete-StageObserver($Observer) {
    [IO.File]::WriteAllText($Observer.stop,"usk.publisher.stage_observer_stop.v1`n",
        [Text.UTF8Encoding]::new($false))
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while(-not (Test-Path -LiteralPath $Observer.output) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 25
    }
    if(-not (Test-Path -LiteralPath $Observer.output) -or
        (Get-Item -LiteralPath $Observer.output).Length -gt 16KB) {
        throw 'SYSTEM stage observer did not produce a bounded result'
    }
    $result=Get-Content -LiteralPath $Observer.output -Raw|ConvertFrom-Json
    $task=Get-ScheduledTask -TaskName $Observer.task -ErrorAction Stop
    if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $Observer.task -ErrorAction Stop}
    Unregister-ScheduledTask -TaskName $Observer.task -Confirm:$false -ErrorAction Stop
    if(Get-ScheduledTask -TaskName $Observer.task -ErrorAction SilentlyContinue) {
        throw 'SYSTEM stage observer task remains registered'
    }
    $Observer.removed=$true
    if($result.schema -cne 'usk.publisher.stage_observer.v1' -or
        $result.identity -cne 'S-1-5-18' -or -not $result.stopped) {
        throw 'SYSTEM stage observer identity or terminal marker differs'
    }
    if($result.clock -cne 'qpc' -or $result.clock_frequency -le 0 -or
        $result.transition.last_staged_only_start_tick -le 0 -or
        $result.transition.last_staged_only_end_tick -le 0 -or
        $result.transition.first_visible_start_tick -le
            $result.transition.last_staged_only_end_tick -or
        $result.transition.first_visible_end_tick -lt
            $result.transition.first_visible_start_tick -or
        $result.transition.visible_before_stage -or
        $result.transition.stage_after_visible -or
        $result.transition.ambiguous_samples -gt 1) {
        throw 'SYSTEM stage-to-visible transition is absent or ambiguous'
    }
    return $result
}
function Start-ProductionRenameObserver([string]$Phase='postrename') {
    if($Phase -cnotin @('prepublish','postrename')){throw 'Unknown production boundary phase'}
    Assert-OwnedVolume
    $taskName='USK_RENAME_OBSERVER_'+$id
    $scriptPath=Join-Path $observerRoot 'production-rename-observer.ps1'
    $ownedProcessPath=Join-Path $observerRoot 'owned-process.ps1'
    $configPath=Join-Path $observerRoot 'production-rename-config.json'
    $readyPath=Join-Path $observerRoot 'production-rename-ready.txt'
    $outputPath=Join-Path $observerRoot 'production-rename-observation.json'
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $scriptPath) -or (Test-Path -LiteralPath $configPath) -or
        (Test-Path -LiteralPath $readyPath) -or (Test-Path -LiteralPath $outputPath)) {
        throw 'Owned production rename observer collision'
    }
    $serviceRow=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
    $processRow=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serviceRow.ProcessId) -ErrorAction Stop
    if($serviceRow.State -cne 'Running' -or $serviceRow.ProcessId -le 0 -or
        $serviceRow.PathName -cne $expectedRegisteredCommand -or
        -not $processRow -or -not $processRow.CreationDate -or
        -not $processRow.ExecutablePath -or -not $processRow.CommandLine -or
        (Get-FileHash -LiteralPath $processRow.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $sourceServiceHash) {
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
        service_binary_sha256=$sourceServiceHash;
        drive_letter=$drive.Substring(0,1);volume_guid_root=$VolumeRoot;
        visible_path=$visibleRoot;journal_path=($drive+'publication\journal\lab-'+
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
            config=$configPath;removed=$false}
    } catch {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if($task -and $task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        }
        throw
    }
}
function Complete-ProductionRenameObserver($Observer,[string]$Phase='postrename') {
    $deadline=[DateTime]::UtcNow.AddSeconds(150)
    while(-not (Test-Path -LiteralPath $Observer.output) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 25
    }
    if(-not (Test-Path -LiteralPath $Observer.output) -or
        (Get-Item -LiteralPath $Observer.output).Length -gt 16KB) {
        throw 'Production rename observer did not produce bounded output'
    }
    $result=Get-Content -LiteralPath $Observer.output -Raw|ConvertFrom-Json
    $task=Get-ScheduledTask -TaskName $Observer.task -ErrorAction Stop
    if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $Observer.task -ErrorAction Stop}
    Unregister-ScheduledTask -TaskName $Observer.task -Confirm:$false -ErrorAction Stop
    if(Get-ScheduledTask -TaskName $Observer.task -ErrorAction SilentlyContinue) {
        throw 'Owned production rename observer task remains registered'
    }
    $Observer.removed=$true
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
function Test-LiveStageAttemptOverlap($Observation,$Attempts) {
    foreach($run in @($Observation.runs)) {
        if($run.samples -lt 2 -or
            $run.maximum_gap_ticks -gt [long]($Observation.clock_frequency/5)){continue}
        foreach($attempt in @($Attempts)) {
            if([long]$attempt.start_tick -gt [long]$run.first_tick -and
                [long]$attempt.end_tick -ge [long]$attempt.start_tick -and
                [long]$attempt.end_tick -lt [long]$run.last_tick) {
                return $true
            }
        }
    }
    return $false
}
function Get-TransitionAttemptCoverage($Observation,$Attempts) {
    $transition=$Observation.transition
    $frequency=[long]$Observation.clock_frequency
    $last=[long]$transition.last_staged_only_end_tick
    $first=[long]$transition.first_visible_start_tick
    if($first -le $last -or $first-$last -gt [long]($frequency/2)) {
        return $null
    }
    $before=0L;$after=[long]::MaxValue
    foreach($attempt in @($Attempts)) {
        $start=[long]$attempt.start_tick;$end=[long]$attempt.end_tick
        if($end -lt $start){return $null}
        if($end -le $last -and $end -gt $before){$before=$end}
        if($start -ge $first -and $start -lt $after){$after=$start}
    }
    if($before -eq 0 -or $after -eq [long]::MaxValue -or
        $last-$before -gt [long]($frequency/2) -or
        $after-$first -gt [long]($frequency/2)) {
        return $null
    }
    return [ordered]@{last_denied_before_tick=$before;
        first_denied_after_tick=$after;gap_ticks=$after-$before}
}
$vmId=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters').VirtualMachineId
if($vmId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw 'Observed hosted VM identity unavailable' }
$id=[guid]::NewGuid().ToString('N')
$service=$(if($RegisteredService){'USK_PUB_'}else{'USK_VM_'})+$id
$root='C:\USK-Lab'
if(Test-Path -LiteralPath $root){throw 'Unexpected existing hosted campaign input root'}
New-Item -ItemType Directory -Path $root|Out-Null
$fixture=Join-Path $root ('metadata-inputs-'+$id)
New-Item -ItemType Directory -Path $fixture|Out-Null
$nativePath=Join-Path $root ('vm-selected-'+$id+'.json')
$sourceDir=if($ReviewedSource){Join-Path $root 'authored-product'}else{$root}
if($ReviewedSource){New-Item -ItemType Directory -Path $sourceDir|Out-Null}
$archive=Join-Path $sourceDir ($(if($ReviewedSource){'product-'+$id+'.zip'}else{'selected-'+$id+'.zip'}))
$envelope=Join-Path $root ('plan-'+$id+'.json')
$out=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $out){throw 'Metadata receipt collision'}
$observerRoot=Join-Path (Split-Path -Parent $vhd) ('root-acl-observer-'+$id)
if((Split-Path -Parent $out) -ine (Split-Path -Parent $vhd) -or
    (Test-Path -LiteralPath $observerRoot)) { throw 'Owned root ACL observer output root differs' }
New-Item -ItemType Directory -Path $observerRoot -ErrorAction Stop|Out-Null
$runnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$observerAcl=[Security.AccessControl.DirectorySecurity]::new()
$observerAcl.SetSecurityDescriptorSddlForm('O:'+$runnerSid+'G:'+$runnerSid+
    'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+$runnerSid+')')
Set-Acl -LiteralPath $observerRoot -AclObject $observerAcl
$observedAcl=Get-Acl -LiteralPath $observerRoot
$observerRules=@($observedAcl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
if(-not $observedAcl.AreAccessRulesProtected -or $observerRules.Count -ne 2 -or
    @($observerRules|Where-Object {$_.IdentityReference.Value -eq 'S-1-5-18'}).Count -ne 1 -or
    @($observerRules|Where-Object {$_.IdentityReference.Value -eq $runnerSid}).Count -ne 1) {
    throw 'Owned SYSTEM observer output directory has an unexpected ACL'
}
$receipt=[ordered]@{schema='usk.publisher.metadata_vm_probe.v1';status='not_run';vm_id=$vmId;
    runner_environment=$env:RUNNER_ENVIRONMENT;os_build=[Environment]::OSVersion.Version.ToString();
    disk_unique_id=$disk.UniqueId;volume_guid_root=$VolumeRoot;volume_drive_root=$drive;service=$service;
    service_sid=$null;binary_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    archive_sha256=$null;strip_prefix='pkg';request=$null;plan=$null;native=$null;independent=$null;
    observer_task_removed=$false;service_removed=$false;failure=$null;power_loss_test=$false}
$created=$false
$registrationAttempted=$false
$expectedRegisteredCommand=''
$installedServiceBinary=''
$sourceServiceHash=''
$failure=$null
$requestClient=$null
$clientNumber=0
$consumerCreated=$false
$consumerCredential=$null
$consumerSid=''
$consumerProcess=$null
$concurrentAttacker=$null
$unrelatedAttacker=$null
$unrelatedAccountCreated=$false
$unrelatedAccountName=''
$unrelatedSid=''
$unrelatedCredential=$null
$unrelatedOutputRoot=Join-Path $root 'unrelated-output'
$unrelatedAttackOutput=Join-Path $unrelatedOutputRoot 'concurrent-attack.json'
$unrelatedReady=Join-Path $unrelatedOutputRoot 'concurrent-ready.txt'
$unrelatedCompleted=Join-Path $unrelatedOutputRoot 'concurrent-completed.txt'
$unrelatedStart=Join-Path $unrelatedOutputRoot 'production-start.txt'
$unrelatedError=Join-Path $unrelatedOutputRoot 'concurrent-stderr.txt'
$preopenedRootProcess=$null
$concurrentOutput=''
$concurrentError=''
$concurrentCompleted=''
$stageObserver=$null
$postrenameObserver=$null
$clientCleanupConfirmed=$true
$consumerOutput=Join-Path $root 'consumer-output'
$consumerScript=Join-Path $root 'consumer-client.ps1'
function Read-NativeReceipt([string]$Path) {
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while($true) {
        try { $raw=[IO.File]::ReadAllText($Path); break }
        catch [IO.IOException] {
            if([DateTime]::UtcNow -ge $deadline){throw}
            Start-Sleep -Milliseconds 100
        }
    }
    if(-not $raw -or $raw.Length -gt 4MB){throw 'Native service receipt is empty or exceeds bound'}
    return $raw|ConvertFrom-Json
}
function Read-ClientObservation($client) {
    $replyFile=Get-Item -LiteralPath $client.response -ErrorAction Stop
    if($replyFile.Length -eq 0 -or $replyFile.Length -gt 4MB) {
        throw 'Authenticated client response is empty or exceeds its bound'
    }
    $parsed=Get-Content -LiteralPath $client.response -Raw|ConvertFrom-Json
    if($client.client_mode -ne 'machine-one-shot') {
        return [pscustomobject]@{service=$parsed;envelope=$null}
    }
    if($parsed.schema -cne 'usk.oneshot_response.v1' -or
        $parsed.request_id -cne $client.request_id -or
        $parsed.result.schema -cne 'usk.publisher_lab_service_observation.v1') {
        throw 'Machine client envelope or service result differs'
    }
    $expectedExit=switch([string]$parsed.status) {
        'ok' {0}
        'refused' {4}
        'recovery_required' {5}
        default {throw 'Machine client response has an unknown or invalid terminal status'}
    }
    if($client.process.ExitCode -ne $expectedExit -or
        ($parsed.status -eq 'refused' -and $parsed.result.status -cne 'failed') -or
        ($parsed.status -eq 'recovery_required' -and
            $parsed.result.status -cne 'recovery_required') -or
        ($parsed.status -eq 'ok' -and $parsed.result.status -cne 'pass' -and
            -not ($parsed.result.status -ceq 'failed' -and
                $parsed.result.verify_response.status -ceq 'ok' -and
                $parsed.result.verify_response.payload.status -in @('fail','warn','unknown') -and
                $parsed.result.verify_response.payload.report_digest -ceq
                    $parsed.result.bound_report_digest))) {
        throw 'Machine client terminal status differs from authenticated service result'
    }
    return [pscustomobject]@{service=$parsed.result;envelope=$parsed}
}
function Start-RegisteredPublisher {
    if($script:controllerPending){return}
    $startArgs=@('--start',$service,$ServiceBinary,$VolumeRoot,$callerSid)
    if($registeredMode){$startArgs+=$registeredMode}
    $started=& $ServiceControlBinary @startArgs
    if($LASTEXITCODE -ne 0 -or ($started|ConvertFrom-Json).status -ne 'start_requested') {
        throw 'Product service control did not start the matching publisher'
    }
}
function Start-RequestClient($submitted=$applyRequest) {
    $script:clientNumber++
    $prefix=Join-Path $(if($ConsumerAccess -or $NonAdminClient){$consumerOutput}else{$root}) ('client-'+$clientNumber)
    $clientRequest=$prefix+'-request.json'
    $clientDocument=if($MachineRequestClient -and -not $script:controllerPending) {
        $command=switch([string]$submitted.schema) {
            'usk.install_local_apply_request.v1' {'install_local.apply'}
            'usk.publisher_installed_verify_request.v1' {'installed.verify'}
            'usk.publisher_recovery_request.v1' {'install_local.recover'}
            default {throw 'Machine candidate request schema is unavailable'}
        }
        [ordered]@{schema='usk.oneshot_request.v1';request_id=('hosted-'+$script:clientNumber);
            command=$command;payload=$submitted;dry_run=$false}
    } else {$submitted}
    [IO.File]::WriteAllText($clientRequest,($clientDocument|ConvertTo-Json -Depth 32 -Compress),$utf8)
    $controllerRequest=$script:controllerPending
    $requestBinary=if($controllerRequest){$ServiceControlBinary}elseif($MachineRequestClient){$MachineBinary}else{$ClientBinary}
    $clientMode=if($controllerRequest){'controller_'+$script:controllerMode+'_registered'}elseif($MachineRequestClient){'machine-one-shot'}else{'service'}
    $binaryDigest=(Get-FileHash -LiteralPath $requestBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $requestArgs=if($controllerRequest){
        if($script:controllerMode -eq 'apply') {
            @('--apply-registered',$service,('"'+$ServiceBinary+'"'),$VolumeRoot,
                ('"'+$envelope+'"'),$receipt.envelope_sha256,$callerSid,$sourceServiceHash,('"'+$clientRequest+'"'))
        } else {
            $controllerVerb='--'+$script:controllerMode+'-registered'
            @($controllerVerb,$service,('"'+$ServiceBinary+'"'),
                $VolumeRoot,$callerSid,$sourceServiceHash,('"'+$clientRequest+'"'))
        }
    }
        elseif($MachineRequestClient){@('--machine','--candidate-service',$service,'--request-file',('"'+$clientRequest+'"'))}
        else{@('--service',$service,'--request-file',('"'+$clientRequest+'"'))}
    if($controllerRequest) {
        $expectedArgs=if($script:controllerMode -eq 'apply'){9}else{7}
        if($requestArgs.Count -ne $expectedArgs){throw 'Registered controller argument shape differs'}
    }
    if($controllerRequest -and $registeredMode){$requestArgs+=$registeredMode}
    $options=@{FilePath=$requestBinary;ArgumentList=$requestArgs;
        WindowStyle='Hidden';PassThru=$true;RedirectStandardOutput=$prefix+'-response.json';RedirectStandardError=$prefix+'-error.txt'}
    $identityPath=$prefix+'-identity.json'
    if($ConsumerAccess -or $NonAdminClient) {
        $options.FilePath=(Get-Command pwsh).Source
        $options.ArgumentList=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$consumerScript,
            '-ExpectedUserSid',$consumerSid,'-IdentityPath',$identityPath,'-ClientBinary',$requestBinary,
            '-ClientMode',$clientMode,'-ExpectedClientSha256',$binaryDigest,
            '-ServiceName',$service,'-RequestFile',$clientRequest)
        $options['Credential']=$consumerCredential
        $options['WorkingDirectory']=$consumerOutput
    }
    $process=Start-Process @options
    if($controllerRequest){$script:controllerPending=$false}
    return [pscustomobject]@{process=$process;response=$prefix+'-response.json';error=$prefix+'-error.txt';
        identity=$identityPath;binary_path=[IO.Path]::GetFullPath($requestBinary);
        binary_sha256=$binaryDigest;client_mode=$clientMode;
        request_id=if($clientMode -eq 'machine-one-shot'){'hosted-'+$script:clientNumber}else{''}}
}
function Assert-RequestClientImage($client) {
    if(-not ($ConsumerAccess -or $NonAdminClient)){return $null}
    $actual=Get-Content -LiteralPath $client.identity -Raw|ConvertFrom-Json
    if($actual.user_sid -cne $consumerSid -or $actual.administrator -or
        $actual.client_binary_path -cne $client.binary_path -or
        $actual.client_binary_sha256 -cne $client.binary_sha256 -or
        $actual.client_mode -cne $client.client_mode) {
        throw 'Actual client identity, executable or request mode differs'
    }
    return $actual
}
function Complete-RequestClient($client,[bool]$expectSuccess,[bool]$requireFailureResponse=$false) {
    if(-not $client.process.WaitForExit(120000)) {
        Stop-OwnedPublisherProcessTree $client.process|Out-Null;throw 'Owned request client timed out'
    }
    $client.process.WaitForExit()
    if(($client.process.ExitCode -eq 0) -ne $expectSuccess) {
        throw ('Request client exit differs: '+$client.process.ExitCode+'; '+[IO.File]::ReadAllText($client.error))
    }
    $result=[ordered]@{exit_code=$client.process.ExitCode;binary_sha256=(Get-FileHash -LiteralPath $client.binary_path -Algorithm SHA256).Hash.ToLowerInvariant();
        caller_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    if($ConsumerAccess -or $NonAdminClient) {
        $actual=Assert-RequestClientImage $client
        $result.caller_sid=$actual.user_sid
        $result['caller_observation']=$actual
    }
    $hasResponse=(Get-Item -LiteralPath $client.response).Length -gt 0
    if($expectSuccess -or $hasResponse) {
        if((Get-Item -LiteralPath $client.response).Length -gt 4MB) {
            throw 'Authenticated client result exceeds the response bound'
        }
        $matching=if($client.client_mode -eq 'machine-one-shot') {
            $check='import json,sys; c=json.load(open(sys.argv[1],encoding="utf-8")); n=json.load(open(sys.argv[2],encoding="utf-8")); expected=("ok",) if sys.argv[3]=="true" else ("refused","recovery_required"); sys.exit(0 if c.get("schema")=="usk.oneshot_response.v1" and c.get("status") in expected and c.get("result")==n else 1)'
            & python -c $check $client.response $nativePath ([string]$expectSuccess).ToLowerInvariant()
            $LASTEXITCODE -eq 0
        } else {
            [IO.File]::ReadAllText($client.response).Trim() -ceq [IO.File]::ReadAllText($nativePath).Trim()
        }
        if(-not $matching) {
            throw 'Authenticated client result differs from independently retained service result'
        }
        $result['response_sha256']=(Get-FileHash -LiteralPath $client.response -Algorithm SHA256).Hash.ToLowerInvariant()
        $result['delivery']='response_received'
    } elseif($requireFailureResponse -or [IO.File]::ReadAllText($client.error) -notmatch 'outcome unknown') {
        throw 'Request client did not deliver a structured failure or explicitly report unknown outcome'
    } else {
        $result['delivery']='outcome_unknown'
    }
    return $result
}
try {
    if($ConsumerAccess -or $NonAdminClient) {
        $consumerName='USKUSR_'+[guid]::NewGuid().ToString('N').Substring(0,13)
        if(Get-LocalUser -Name $consumerName -ErrorAction SilentlyContinue){throw 'Consumer account collision'}
        $secure=ConvertTo-SecureString ('Aa1!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
        $account=New-LocalUser -Name $consumerName -Password $secure -PasswordNeverExpires
        $consumerCreated=$true;$consumerSid=$account.SID.Value
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member $account
        $consumerCredential=[Management.Automation.PSCredential]::new($env:COMPUTERNAME+'\'+$consumerName,$secure)
        $receipt['consumer_account_sid']=$consumerSid
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_publisher_consumer_client.ps1') -Destination $consumerScript
        $clientCopy=Join-Path $root 'consumer-client.exe'
        if(-not ($RegisteredService -and $ConsumerAccess)) {
            Copy-Item -LiteralPath $ClientBinary -Destination $clientCopy
            $ClientBinary=$clientCopy
        }
        New-Item -ItemType Directory -Path $consumerOutput|Out-Null
        $rootAcl=Get-Acl -LiteralPath $root
        $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($consumerSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $root -AclObject $rootAcl
        $outputAcl=Get-Acl -LiteralPath $consumerOutput
        $outputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($consumerSid),'Modify','ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $consumerOutput -AclObject $outputAcl
    }
    Assert-OwnedVolume
    if(Test-Path -LiteralPath ($drive+'publication')){throw 'Hosted metadata disk is not fresh'}
    $fixtureArgs=if($ProductionPostrenameTermination -or $ProductionPreparedTermination){
        @('--core-bytes','33554432','--addon-bytes','33554432')
    }elseif($ConsumerAccess){
        @('--application-binary',$PayloadBinary)+$(if($ProductionConcurrentRights){
            @('--addon-bytes','33554432')
        }else{@()})
    }
        elseif($ProductionConcurrentRights){@('--core-bytes','33554432')}else{@()}
    $generated=& python -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $fixture --target $visibleRoot --request-id ('metadata.'+$id) @fixtureArgs
    if($LASTEXITCODE -ne 0){throw 'Public authoring input generation failed'}
    $inputs=$generated|ConvertFrom-Json
    $packageRoot=''
    if($RegisteredService -and -not $NonAdminClient -and -not $InterruptAfterStage -and
        -not $TerminateAtPostrename -and -not $HostileRights) {
        # Exercise the actual emitted native package through installation.
        # The fault-test service and externally admitted VHD ACL helper are
        # deliberately outside this ordinary candidate package.
        $packageRoot=Join-Path $root ('candidate-package-'+$id)
        New-Item -ItemType Directory -Path $packageRoot -ErrorAction Stop|Out-Null
        $packed=& python -B (Join-Path $PSScriptRoot '..\tools\usk_selected_candidate_package.py') build `
            --bundle $inputs.bundle_file --machine $MachineBinary --service $ServiceBinary `
            --control $ServiceControlBinary --client $ClientBinary --output-dir $packageRoot
        if($LASTEXITCODE -ne 0){throw 'Selected native candidate package build failed'}
        $package=$packed|ConvertFrom-Json
        if($package.schema -ne 'usk.selected_ntfs_candidate_package.v1' -or
            $package.installation_mode -ne 'selected_ntfs_candidate' -or
            $package.service_mode -ne 'requires_executable_probe' -or
            $package.product_id -ne 'org.example.metadata') {
            throw 'Selected candidate package identity differs'
        }
        $MachineBinary=Join-Path $packageRoot 'inspect\usk_machine.exe'
        $ServiceBinary=Join-Path $packageRoot 'publisher\usk_publisher_service.exe'
        $ServiceControlBinary=Join-Path $packageRoot 'publisher\usk_publisher_service_control.exe'
        $ClientBinary=Join-Path $packageRoot 'publisher\usk_publisher_client.exe'
        $packagedServiceHash=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        if($packagedServiceHash -cne $package.entries.'publisher/usk_publisher_service.exe'.sha256) {
            throw 'Packaged service bytes differ from candidate manifest'
        }
        & python -B (Join-Path $PSScriptRoot 'native\usk_publisher_service_mode_probe.py') $ServiceBinary
        if($LASTEXITCODE -ne 0) {throw 'Packaged service did not enforce production grammar'}
        if((Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $packagedServiceHash) {throw 'Packaged service changed after production grammar probe'}
        $receipt['candidate_service_mode_probe']=[ordered]@{status='passed';service_sha256=$packagedServiceHash}
        if($ConsumerAccess) {
            Copy-Item -LiteralPath $ClientBinary -Destination $clientCopy
            if((Get-FileHash -LiteralPath $ClientBinary -Algorithm SHA256).Hash -cne
                (Get-FileHash -LiteralPath $clientCopy -Algorithm SHA256).Hash) {
                throw 'Non-admin client copy differs from emitted package'
            }
            $ClientBinary=$clientCopy
        }
        $archive=Join-Path $packageRoot 'inspect\payload.zip'
        $inputs.archive_sha256=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $receipt['strip_prefix']=''
        $receipt['candidate_package_manifest_sha256']=(Get-FileHash -LiteralPath `
            (Join-Path $packageRoot 'setup-package.manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $productInfo=& $MachineBinary --product-info (Join-Path $packageRoot 'inspect\product.bundle.json')
        if($LASTEXITCODE -ne 0 -or ($productInfo|ConvertFrom-Json).payload_sha256 -cne
            $inputs.archive_sha256) {throw 'Packaged native product inspection differs'}
    } else {
        Copy-Item -LiteralPath $inputs.archive_file -Destination $archive
    }
    $request=Get-Content -LiteralPath $inputs.request_file -Raw|ConvertFrom-Json
    $request.payload.archive.path=$archive
    if($packageRoot) {
        $request.payload.archive.strip_prefix=''
        $request.payload.archive.expected_sha256=$inputs.archive_sha256
        $request.payload.archive.budgets.max_depth=([int]$request.payload.archive.budgets.max_depth)-1
    }
    $requestPath=Join-Path $root ('metadata-request-'+$id+'.json')
    $contextPath=Join-Path $root ('metadata-context-'+$id+'.json')
    $utf8=[Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($requestPath,($request|ConvertTo-Json -Depth 32 -Compress)+"`n",$utf8)
    [IO.File]::WriteAllText($contextPath,(@{schema='usk.oneshot_context.v1';state_root=$drive+'setup-state';
        authorized_acceptance_root=$drive;target_policy_activation='operator_acceptance_candidate'}|ConvertTo-Json -Compress)+"`n",$utf8)
    $output=& $MachineBinary --machine --request-file $requestPath --context-file $contextPath 2>&1
    if($LASTEXITCODE -ne 0){throw ('Native plan failed: '+($output -join '; '))}
    $response=($output -join "`n")|ConvertFrom-Json
    $plan=$response.result.payload
    if($response.status -ne 'ok' -or $response.result.status -ne 'ok' -or
        $plan.required_commit_authority -ne 'staged_child_bound_v1' -or $plan.commit_authority_available -ne $false -or
        @($plan.planned_entries|Where-Object entry_type -eq file).Count -ne 2 -or
        @($plan.component_selection).Count -ne 2 -or
        @(Compare-Object @('addon','core') @($plan.component_selection)).Count -ne 0) {
        throw 'Actual selected native plan differs'
    }
    $receipt.request=$request.payload;$receipt.plan=$plan;$receipt.archive_sha256=$inputs.archive_sha256
    $receipt['source_mode']=if($RegisteredService){'registered_reviewed_service'}elseif($ReviewedSource){'authenticated_reviewed_envelope'}else{'legacy_scm_source_binding'}
    $responsePath=Join-Path $root ('metadata-plan-response-'+$id+'.json')
    [IO.File]::WriteAllText($responsePath,($output -join "`n")+"`n",$utf8)
    $bindingDir=Join-Path $root ('authored-binding-'+$id)
    $bound=& python -B (Join-Path $PSScriptRoot '..\tools\usk_bundle_apply_binding.py') `
        --request-file $requestPath --response-file $responsePath `
        --acceptance-root $drive --state-root ($drive+'setup-state') `
        --transaction-id ('install.'+$id) `
        --applied-at ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) `
        --output-dir $bindingDir
    if($LASTEXITCODE -ne 0){throw 'Authored native plan could not bind a protected apply'}
    $binding=$bound|ConvertFrom-Json
    if($binding.schema -ne 'usk.publisher.candidate_binding.v1' -or
        $binding.apply_file -cne (Join-Path $bindingDir 'apply.json') -or
        $binding.envelope_file -cne (Join-Path $bindingDir 'envelope.json')) {
        throw 'Authored apply binding output differs'
    }
    $applyRequest=Get-Content -LiteralPath $binding.apply_file -Raw|ConvertFrom-Json
    $recoveryRequest=[ordered]@{
        schema='usk.publisher_recovery_request.v1'
        request_id='recover.'+$id
        install_id=$applyRequest.plan_request.install_id
        transaction_id=$applyRequest.transaction_id
    }
    if($RegisteredService) {
        $envelope=$binding.envelope_file
    } else {
        # The existing disposable service grammar admits only plan-ID files
        # directly beneath C:\USK-Lab. Keep the authored bytes and digest.
        Copy-Item -LiteralPath $binding.envelope_file -Destination $envelope -ErrorAction Stop
    }
    if((Get-FileHash -LiteralPath $envelope -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $binding.envelope_sha256) {throw 'Authored apply envelope identity differs'}
    $receipt['apply_request']=$applyRequest
    $receipt['public_apply_binary_sha256']=(Get-FileHash -LiteralPath $PublicApplyBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    # The identical ordinary request must refuse outside the admitted service,
    # before creating payload or setup state. No public activation mints authority.
    $ordinaryPath=Join-Path $root ('ordinary-apply-'+$id+'.json')
    [IO.File]::WriteAllText($ordinaryPath,($applyRequest|ConvertTo-Json -Depth 32 -Compress)+"`n",$utf8)
    # usk_machine remains inspect-only. Exercise the actual C ABI instead of
    # interpreting its earlier command_unavailable as publisher evidence.
    $ordinary=& $PublicApplyBinary --apply-probe $ordinaryPath ($drive+'setup-state') $drive
    $receipt['ordinary_apply_exit_code']=$LASTEXITCODE
    $receipt['ordinary_apply_response']=($ordinary -join "`n")|ConvertFrom-Json
    if($receipt.ordinary_apply_exit_code -eq 0 -or ($ordinary -join "`n") -notmatch 'commit_authority_unavailable' -or
        (Test-Path -LiteralPath ($drive+'setup-state')) -or (Test-Path -LiteralPath ($drive+'publication'))) {
        throw 'Ordinary apply did not refuse before mutation outside the service'
    }
    $sourceInputs=@($archive,$envelope,$inputs.archive_file,$inputs.request_file,
        $requestPath,$contextPath,$ordinaryPath,$responsePath,$binding.apply_file)+@($inputs.source_files)
    if($envelope -cne $binding.envelope_file){$sourceInputs+=@($binding.envelope_file)}
    if($packageRoot) {
        $sourceInputs+=@((Join-Path $packageRoot 'inspect\product.bundle.json'),
            (Join-Path $packageRoot 'inspect\prefab.manifest.json'),
            (Join-Path $packageRoot 'setup-package.manifest.json'))
    }
    $receipt['envelope_sha256']=$binding.envelope_sha256
    $selectedClientArguments=if($ReviewedSource){
        ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256+' --campaign-vm-id '+$vmId
    }else{
        ' --selected-zip "'+$archive+'" '+$inputs.archive_sha256+' --campaign-vm-id '+$vmId+
            ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256
    }
    $command='"'+$ServiceBinary+'" --service '+$service+' "'+$nativePath+'" '+$VolumeRoot+$selectedClientArguments
    if($recover -and -not $InterruptDuringConsumerAccess){$command+=' --'+$gate+'-gate'}
    if($HostileRights){$command+=$(if($HostilePostrename){' --postrename-gate'}else{' --prepublish-gate'})}
    if($InterruptDuringConsumerAccess){$command+=' --interrupt-consumer-grant'}
    if($ClientBinary) {
        $callerSid=if($ConsumerAccess -or $NonAdminClient){$consumerSid}else{[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
        $clientArguments=' --authorized-client-sid '+$callerSid
        if($ConsumerAccess){$clientArguments+=' --grant-client-read'}
        $command+=$clientArguments
    }
    if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Service collision'}
    if($RegisteredService) {
        if(-not $env:ProgramW6432){throw 'Protected Program Files root is unavailable'}
        $installedServiceBinary=Join-Path $env:ProgramW6432 `
            ('Universal Setup\Publisher\'+$service+'.exe')
        $sourceServiceHash=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        $expectedRegisteredCommand='"'+$installedServiceBinary+'" --service '+$service+' --no-receipt '+$VolumeRoot+
            ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256+
            $(if($NonAdminClient){' --admit-client-observer'}else{''})+
            ' --authorized-client-sid '+$callerSid+
            $(if($ConsumerAccess){' --grant-client-read'}else{''})
        $controlArgs=@('--register',$service,$ServiceBinary,$VolumeRoot,$envelope,
            $receipt.envelope_sha256,$callerSid,$sourceServiceHash)
        if($registeredMode){$controlArgs+=$registeredMode}
        $wrongBinaryHash=@($controlArgs)
        $wrongBinaryHash[7]='0000000000000000000000000000000000000000000000000000000000000000'
        & $ServiceControlBinary @wrongBinaryHash 2>$null|Out-Null
        if($LASTEXITCODE -eq 0 -or
            (Test-Path -LiteralPath $installedServiceBinary) -or
            (Get-Service $service -ErrorAction SilentlyContinue)) {
            throw 'Publisher registration retained a mismatched executable'
        }
        $receipt['wrong_binary_digest_refused']=$true
        $orphanPending=$installedServiceBinary+'.pending'
        [IO.File]::WriteAllBytes($orphanPending,[byte[]]@(0x4d,0x5a))
        $orphanAcl=[Security.AccessControl.FileSecurity]::new()
        $orphanAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
        Set-Acl -LiteralPath $orphanPending -AclObject $orphanAcl
        $registrationAttempted=$true
        $registered=& $ServiceControlBinary @controlArgs
        if($LASTEXITCODE -ne 0){throw 'Product service control did not register the reviewed publisher'}
        $created=$true
        if(($registered|ConvertFrom-Json).status -ne 'registered') {
            throw 'Product service control did not register the reviewed publisher'
        }
        if((Get-FileHash -LiteralPath $installedServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $sourceServiceHash){throw 'Protected installed service differs from packaged source'}
        if(Test-Path -LiteralPath $orphanPending){throw 'Interrupted publisher copy was not reclaimed'}
        $receipt['interrupted_copy_reclaimed']=$true
        $ServiceBinary=$installedServiceBinary
        $receipt['protected_service_binary_sha256']=$sourceServiceHash
        $receipt['service_control_binary_sha256']=(Get-FileHash -LiteralPath $ServiceControlBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        if($ProductionConcurrentRights) {
            if(-not $env:ProgramW6432){throw 'Protected Program Files root is unavailable'}
            $controlLocks=Join-Path $env:ProgramW6432 'Universal Setup\PublisherControl'
            $controlLock=Join-Path $controlLocks ($service+'.lock')
            if(-not (Test-Path -LiteralPath $controlLock -PathType Leaf)) {
                throw 'Product service control lock file is absent'
            }
            $held=[IO.File]::Open($controlLock,[IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            try {
                $blockedStart=@('--start',$service,$ServiceBinary,$VolumeRoot,$callerSid)
                if($registeredMode){$blockedStart+=$registeredMode}
                & $ServiceControlBinary @blockedStart 2>$null|Out-Null
                if($LASTEXITCODE -eq 0 -or (Get-Service $service).Status -ne 'Stopped') {
                    throw 'Publisher service start bypassed held control lock'
                }
                $otherFirstDigit=if($VolumeRoot[11] -ceq '0'){'1'}else{'0'}
                $otherVolume=$VolumeRoot.Substring(0,11)+$otherFirstDigit+$VolumeRoot.Substring(12)
                $crossVolumeError=Join-Path $root ('cross-volume-register-'+$id+'.txt')
                $crossVolumeArgs=@('--register',$service,$ServiceBinary,$otherVolume,
                    $envelope,$receipt.envelope_sha256,$callerSid,$sourceServiceHash)
                if($registeredMode){$crossVolumeArgs+=$registeredMode}
                & $ServiceControlBinary @crossVolumeArgs 2>$crossVolumeError|Out-Null
                if($LASTEXITCODE -eq 0 -or
                    -not ((Get-Content -LiteralPath $crossVolumeError -Raw) -clike '*control is active*')) {
                    throw 'Cross-volume registration did not use the service-name lock'
                }
                $receipt['cross_volume_service_lock_refusal']=$true
            } finally { $held.Dispose() }
            $receipt['service_control_lock_start_refusal']=$true
        }
    } else {
        & sc.exe create $service type= own start= demand obj= LocalSystem binPath= $command|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned service creation failed'}
        & sc.exe sidtype $service restricted|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Restricted service configuration failed'}
    }
    $created=$true
    $sid=[Security.Principal.NTAccount]::new('NT SERVICE\'+$service).Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt.service_sid=$sid
    # Only this newly created input directory in the disposable hosted VM is
    # writable by the service. The independent observer lives elsewhere.
    $acl=Get-Acl -LiteralPath $root
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),'Modify',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $root -AclObject $acl
    if($ReviewedSource) {
        $sourceAcl=Get-Acl -LiteralPath $sourceDir
        $sourceAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute',
            'ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $sourceDir -AclObject $sourceAcl
    }
    $configured=Get-CimInstance Win32_Service -Filter "Name='$service'"
    if($configured.ServiceType -ne 'Own Process' -or $configured.StartName -ne 'LocalSystem' -or
        (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$service").ServiceSidType -ne 3) {
        throw 'Effective service configuration differs'
    }
    $serviceInputs=if($RegisteredService){@($archive,$envelope)}else{@($ServiceBinary,$archive,$envelope)}
    foreach($path in $serviceInputs) {
        $acl=Get-Acl -LiteralPath $path
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute','Allow'))
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    Assert-OwnedVolume
    if($ProductionConcurrentRights) {
        # The attack originates from a writable file on this same disposable
        # NTFS volume. Its ACL is explicit; the volume root stays protected.
        $scratch=Join-Path $drive 'attacker-scratch'
        $scratchFile=Join-Path $scratch 'replacement.bin'
        if((Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $scratchFile)) {
            throw 'Owned same-volume attack source is not fresh'
        }
        New-Item -ItemType Directory -Path $scratch -ErrorAction Stop|Out-Null
        [IO.File]::WriteAllBytes($scratchFile,[byte[]]@(0x42))
        $scratchSha256=(Get-FileHash -LiteralPath $scratchFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $consumerIdentity=[Security.Principal.SecurityIdentifier]::new($consumerSid)
        $systemIdentity=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        foreach($path in @($scratch,$scratchFile)) {
            $scratchAcl=Get-Acl -LiteralPath $path
            $scratchAcl.SetAccessRuleProtection($true,$false)
            $inherit=if($path -ceq $scratch){'ContainerInherit,ObjectInherit'}else{'None'}
            $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $systemIdentity,'FullControl',$inherit,'None','Allow'))
            $scratchAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $consumerIdentity,'Modify',$inherit,'None','Allow'))
            Set-Acl -LiteralPath $path -AclObject $scratchAcl
        }
        $attackSource=$VolumeRoot+'attacker-scratch\replacement.bin'
        $receipt['same_volume_attacker_source']=[ordered]@{
            path=$attackSource;volume_root=$VolumeRoot;size_bytes=1;
            sha256=$scratchSha256}
    }
    $receipt['root_acl_before']=(Get-Acl -LiteralPath $VolumeRoot).Sddl
    if($ExpectPreexistingAnchorRefusal) {
        # This object is created only on the newly formatted campaign VHD.
        # Its marker makes an accidental replacement visible after refusal.
        $poisonedAnchor=$drive+'publication'
        $poisonedMarker=Join-Path $poisonedAnchor 'preexisting-owner-marker.bin'
        if(Test-Path -LiteralPath $poisonedAnchor){throw 'Preexisting-anchor input is not fresh'}
        New-Item -ItemType Directory -Path $poisonedAnchor -ErrorAction Stop|Out-Null
        [IO.File]::WriteAllBytes($poisonedMarker,[byte[]]@(0x55,0x53,0x4b,0x2d,0x50,0x52,0x45))
        $poisonedMarkerHash=(Get-FileHash -LiteralPath $poisonedMarker -Algorithm SHA256).Hash.ToLowerInvariant()
        $poisonedAnchorAcl=(Get-Acl -LiteralPath $poisonedAnchor).Sddl
        $poisonedMarkerAcl=(Get-Acl -LiteralPath $poisonedMarker).Sddl
        $receipt['preexisting_anchor_before']=[ordered]@{path=$poisonedAnchor;
            marker_sha256=$poisonedMarkerHash;marker_bytes=7;
            anchor_sddl=$poisonedAnchorAcl;marker_sddl=$poisonedMarkerAcl}
        Assert-OwnedVolume
    }
    if($ProductionConcurrentRights) {
        $preopenedReady=Join-Path $consumerOutput 'preopened-root-ready.txt'
        $preopenedRelease=Join-Path $consumerOutput 'preopened-root-release.txt'
        if((Test-Path -LiteralPath $preopenedReady) -or
            (Test-Path -LiteralPath $preopenedRelease)) {
            throw 'Preopened-root attacker markers are not fresh'
        }
        $preopenedScript=Join-Path $PSScriptRoot 'windows_publisher_preopened_root_probe.ps1'
        $preopenedRootProcess=Start-Process -FilePath (Get-Command pwsh).Source `
            -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',('"'+$preopenedScript+'"'),'-VolumeRoot',('"'+$VolumeRoot.TrimEnd('\')+'"'),
                '-ExpectedUserSid',$consumerSid,'-ServiceSid',$sid,
                '-ReadyPath',('"'+$preopenedReady+'"'),
                '-ReleasePath',('"'+$preopenedRelease+'"')) `
            -Credential $consumerCredential -PassThru -WindowStyle Hidden `
            -WorkingDirectory $consumerOutput -ErrorAction Stop
        $preopenedDeadline=[DateTime]::UtcNow.AddSeconds(30)
        while(-not (Test-Path -LiteralPath $preopenedReady) -and
            [DateTime]::UtcNow -lt $preopenedDeadline) {
            if($preopenedRootProcess.HasExited) {
                throw 'Non-admin preopened-root attacker exited before readiness'
            }
            Start-Sleep -Milliseconds 25
        }
        if(-not (Test-Path -LiteralPath $preopenedReady) -or
            [IO.File]::ReadAllText($preopenedReady) -cne
                ("usk.publisher.preopened_root.v1 "+$preopenedRootProcess.Id+" "+$consumerSid+"`n")) {
            throw 'Non-admin preopened-root attacker did not hold the exact volume root'
        }
        $preopenedIdentity=Get-CimInstance Win32_Process -Filter `
            ('ProcessId='+$preopenedRootProcess.Id) -ErrorAction Stop
        $preopenedOwner=Invoke-CimMethod -InputObject $preopenedIdentity -MethodName GetOwnerSid
        if($preopenedOwner.ReturnValue -ne 0 -or $preopenedOwner.Sid -cne $consumerSid -or
            -not $preopenedIdentity.CommandLine.Contains('windows_publisher_preopened_root_probe.ps1')) {
            throw 'Preopened-root process differs from the non-admin client identity'
        }
        $receipt['preopened_root_process_id']=$preopenedRootProcess.Id
        $receipt['preopened_root_user_sid']=$consumerSid
    }
    if(-not $ExpectUnprotectedRefusal) {
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$sid+')')
        Set-Acl -LiteralPath $VolumeRoot -AclObject $acl
    }
    $receipt['root_acl_at_service_start']=Get-OwnedVolumeRootSddl 'service-start'
    Assert-OwnedVolume
    $device=& $DeviceAclBinary --owned-hosted-vm-vhd-volume $VolumeRoot $service ([int]$disk.Number) $vhd $vmId 2>&1
    if($LASTEXITCODE -ne 0){throw ('Owned VHD device ACL failed: '+($device -join '; '))}
    $deviceText=$device -join "`n"
    if($deviceText.Length -gt 16KB){throw 'Owned VHD device ACL receipt exceeds bound'}
    $deviceAdmission=$deviceText|ConvertFrom-Json
    if($deviceAdmission.service_sid -cne $sid -or
        [string]::IsNullOrWhiteSpace($deviceAdmission.before_dacl) -or
        [string]::IsNullOrWhiteSpace($deviceAdmission.after_dacl)) {
        throw 'Owned VHD device ACL receipt differs'
    }
    $receipt['device_acl_admission']=$deviceAdmission
    if($ControllerApply) {
        $changedApply=Join-Path $root ('changed-apply-'+$id+'.json')
        $changedError=Join-Path $root ('changed-apply-'+$id+'.txt')
        $changed=$applyRequest|ConvertTo-Json -Depth 32|ConvertFrom-Json
        $changed.transaction_id=$changed.transaction_id+'.substituted'
        [IO.File]::WriteAllText($changedApply,
            ($changed|ConvertTo-Json -Depth 32 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
        & $ServiceControlBinary --apply-registered $service $ServiceBinary $VolumeRoot `
            $envelope $receipt.envelope_sha256 $callerSid $sourceServiceHash $changedApply `
            2>$changedError|Out-Null
        if($LASTEXITCODE -ne 3 -or (Get-Service $service).Status -ne 'Stopped' -or
            (Test-Path -LiteralPath ($drive+'publication')) -or
            (Get-Content -LiteralPath $changedError -Raw) -notmatch 'apply request differs') {
            throw 'Changed reviewed apply reached the protected publisher'
        }
        $receipt['changed_controller_apply_refused_before_start']=$true
    }
    if($RegisteredService) {
        $wrongStartError=Join-Path $root ('wrong-start-'+$id+'.txt')
        $wrongStartArgs=@('--start',$service,$ServiceBinary,$VolumeRoot,'S-1-5-18')
        if($registeredMode){$wrongStartArgs+=$registeredMode}
        & $ServiceControlBinary @wrongStartArgs 2>$wrongStartError|Out-Null
        if($LASTEXITCODE -eq 0 -or (Get-Service $service).Status -ne 'Stopped') {
            throw 'Registered publisher accepted a different start caller'
        }
        $receipt['wrong_caller_start_refused']=$true
        if($ConsumerAccess) {
            $wrongModeError=Join-Path $root ('wrong-mode-'+$id+'.txt')
            & $ServiceControlBinary --start $service $ServiceBinary $VolumeRoot $callerSid `
                --admit-client-observer 2>$wrongModeError|Out-Null
            if($LASTEXITCODE -eq 0 -or (Get-Service $service).Status -ne 'Stopped') {
                throw 'Registered publisher accepted a weaker caller mode'
            }
            $receipt['wrong_caller_mode_refused']=$true
        }
        if($InterruptAfterStage -or $HostileRights -or $TerminateAtPostrename) {
            $registeredGate=if($HostilePostrename -or $TerminateAtPostrename){'--postrename-gate'}elseif($HostileRights){'--prepublish-gate'}else{'--poststage-gate'}
            $testCommand='"'+$ServiceBinary+'" --service '+$service+' --no-receipt '+$VolumeRoot+
                ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256+
                ' --test-gate-receipt "'+$nativePath+'" '+$registeredGate+
                $(if($NonAdminClient){' --admit-client-observer'}else{''})+
                ' --authorized-client-sid '+$callerSid
            & sc.exe config $service binPath= $testCommand|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned fault-test service configuration failed'}
            if((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $testCommand) {
                throw 'Owned fault-test service command readback differs'
            }
            try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        } elseif($ProductionConcurrentRights) {
            # This elevated product controller must refuse SCM start while the
            # non-admin process retains its pre-hardening volume-root handle.
            $blockedStartError=Join-Path $root ('preopened-start-'+$id+'.txt')
            $blockedStartArgs=@('--start',$service,$ServiceBinary,$VolumeRoot,$callerSid)
            if($registeredMode){$blockedStartArgs+=$registeredMode}
            & $ServiceControlBinary @blockedStartArgs 2>$blockedStartError|Out-Null
            if($LASTEXITCODE -eq 0 -or (Get-Service $service).Status -ne 'Stopped' -or
                -not (Test-Path -LiteralPath $blockedStartError -PathType Leaf) -or
                (Get-Item -LiteralPath $blockedStartError).Length -gt 16KB -or
                (Get-Content -LiteralPath $blockedStartError -Raw) -notmatch
                    'pre-opened file or cannot be locked' -or
                (Test-Path -LiteralPath ($drive+'publication')) -or
                (Test-Path -LiteralPath ($drive+'setup-state'))) {
                throw 'Product control did not refuse a preopened-root handle before SCM start'
            }
            $receipt['preopened_root_refusal']=[ordered]@{
                status='start_refused_before_effects';
                controller_error=(Get-Content -LiteralPath $blockedStartError -Raw)}
            [IO.File]::WriteAllText($preopenedRelease,
                "usk.publisher.release_preopened_root.v1`n",[Text.UTF8Encoding]::new($false))
            if(-not $preopenedRootProcess.WaitForExit(30000)) {
                throw 'Preopened-root attacker did not release its held handle'
            }
            $preopenedRootProcess.WaitForExit()
            if($preopenedRootProcess.ExitCode -ne 0) {
                throw 'Preopened-root attacker failed after release'
            }
            $preopenedRootProcess=$null
            Start-RegisteredPublisher
            $receipt['preopened_root_clean_retry_started']=$true
        } else { Start-RegisteredPublisher }
    } else {
        try{Start-Service $service}catch{
            if($recover){throw ('Interruption service start failed: '+$_.Exception.Message)}
            if((Get-Service $service).Status -ne 'Stopped'){throw}
        }
    }
    if($TerminateAtPoststage -or $TerminateAtPostrename) {
        # Hold the exact service process before sending the request. The
        # handle prevents a later PID from becoming our termination target.
        $serviceAtStart=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($serviceAtStart.State -cne 'Running' -or $serviceAtStart.ProcessId -le 0 -or
            $serviceAtStart.PathName -cne $testCommand) {
            throw 'Owned fault-test service did not start with its exact configuration'
        }
        $heldServiceProcess=Get-Process -Id $serviceAtStart.ProcessId -ErrorAction Stop
        $null=$heldServiceProcess.Handle
        $serviceProcessAtStart=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serviceAtStart.ProcessId) -ErrorAction Stop
        if(-not $serviceProcessAtStart -or -not $serviceProcessAtStart.CreationDate -or
            $serviceProcessAtStart.CommandLine -cne $testCommand -or
            -not [string]::Equals([IO.Path]::GetFullPath($serviceProcessAtStart.ExecutablePath),
                [IO.Path]::GetFullPath($ServiceBinary),[StringComparison]::OrdinalIgnoreCase) -or
            [math]::Abs(($serviceProcessAtStart.CreationDate.ToUniversalTime()-
                $heldServiceProcess.StartTime.ToUniversalTime()).Ticks) -gt 10000) {
            throw 'Owned fault-test process differs before client submission'
        }
        $heldServiceIdentity=[pscustomobject]@{pid=$serviceAtStart.ProcessId;
            created=$serviceProcessAtStart.CreationDate;
            executable=$serviceProcessAtStart.ExecutablePath;
            command=$serviceProcessAtStart.CommandLine;
            started_utc=$heldServiceProcess.StartTime.ToUniversalTime().ToString('o')}
    }
    $terminalServiceProcess=$null
    if($RegisteredService -and -not $HostileRights -and -not $recover -and -not $script:controllerPending) {
        $terminalAtStart=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($terminalAtStart.State -cne 'Running' -or $terminalAtStart.ProcessId -le 0 -or
            $terminalAtStart.PathName -cne $expectedRegisteredCommand) {
            throw 'Terminal service did not start with its registered command'
        }
        $terminalServiceProcess=Get-Process -Id $terminalAtStart.ProcessId -ErrorAction Stop
        $null=$terminalServiceProcess.Handle
        $terminalProcessAtStart=Get-CimInstance Win32_Process -Filter ('ProcessId='+$terminalAtStart.ProcessId) -ErrorAction Stop
        if(-not $terminalProcessAtStart -or -not $terminalProcessAtStart.CreationDate -or
            $terminalProcessAtStart.CommandLine -cne $expectedRegisteredCommand -or
            -not [string]::Equals([IO.Path]::GetFullPath($terminalProcessAtStart.ExecutablePath),
                [IO.Path]::GetFullPath($ServiceBinary),[StringComparison]::OrdinalIgnoreCase) -or
            [math]::Abs(($terminalProcessAtStart.CreationDate.ToUniversalTime()-
                $terminalServiceProcess.StartTime.ToUniversalTime()).Ticks) -gt 10000) {
            throw 'Terminal service process differs from registered command'
        }
        $receipt['terminal_service_process_id']=$terminalAtStart.ProcessId
    }
    if($ProductionConcurrentRights) {
        $attackRelative=if($ConsumerAccess){'bin/addon.bin'}else{'bin/core.bin'}
        if(@($plan.planned_entries|Where-Object relative_path -ceq $attackRelative).Count -ne 1) {
            throw 'Production concurrent payload is absent from the reviewed plan'
        }
        $productionStart=Join-Path $root ('production-'+$id+'-production-start.txt')
        $concurrentOutput=Join-Path $consumerOutput 'concurrent-attack.json'
        $concurrentError=Join-Path $consumerOutput 'concurrent-stderr.txt'
        $concurrentReady=Join-Path $consumerOutput 'concurrent-ready.txt'
        $concurrentCompleted=Join-Path $consumerOutput 'concurrent-completed.txt'
        $stageObserver=Start-StageObserver
        $unrelatedAccountName='USKATK_'+[guid]::NewGuid().ToString('N').Substring(0,13)
        if(Get-LocalUser -Name $unrelatedAccountName -ErrorAction SilentlyContinue){
            throw 'Unrelated production attacker account collision'
        }
        $unrelatedPassword=ConvertTo-SecureString `
            ('Aa1!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
        $unrelatedAccount=New-LocalUser -Name $unrelatedAccountName `
            -Password $unrelatedPassword -PasswordNeverExpires -ErrorAction Stop
        $unrelatedAccountCreated=$true
        $unrelatedSid=$unrelatedAccount.SID.Value
        if($unrelatedSid -ceq $consumerSid){throw 'Unrelated attacker reused the client SID'}
        # The same-volume replacement source was initially granted only to
        # the submitting login. Give the second login the identical narrow
        # source grant; the protected publication subtree remains unchanged.
        $unrelatedIdentity=[Security.Principal.SecurityIdentifier]::new($unrelatedSid)
        foreach($path in @($scratch,$scratchFile)) {
            $sourceAcl=Get-Acl -LiteralPath $path
            $inherit=if($path -ceq $scratch){'ContainerInherit,ObjectInherit'}else{'None'}
            $sourceAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $unrelatedIdentity,'Modify',$inherit,'None','Allow'))
            Set-Acl -LiteralPath $path -AclObject $sourceAcl
        }
        $receipt['unrelated_same_volume_source_acl']=[ordered]@{
            directory=(Get-Acl -LiteralPath $scratch).Sddl;
            file=(Get-Acl -LiteralPath $scratchFile).Sddl}
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name `
            -Member $unrelatedAccount -ErrorAction Stop
        $unrelatedCredential=[Management.Automation.PSCredential]::new(
            $env:COMPUTERNAME+'\'+$unrelatedAccountName,$unrelatedPassword)
        $unrelatedPassword=$null
        $rootAcl=Get-Acl -LiteralPath $root
        $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($unrelatedSid),'Traverse',
            'None','None','Allow'))
        Set-Acl -LiteralPath $root -AclObject $rootAcl
        if(Test-Path -LiteralPath $unrelatedOutputRoot){
            throw 'Unrelated attacker output root is not fresh'
        }
        New-Item -ItemType Directory -Path $unrelatedOutputRoot -ErrorAction Stop|Out-Null
        $unrelatedAcl=Get-Acl -LiteralPath $unrelatedOutputRoot
        $unrelatedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($unrelatedSid),'Modify',
            'ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $unrelatedOutputRoot -AclObject $unrelatedAcl
        $receipt['unrelated_concurrent_attacker_sid']=$unrelatedSid
        foreach($path in @($productionStart,$concurrentOutput,$concurrentError,
            $concurrentReady,$concurrentCompleted,$unrelatedAttackOutput,
            $unrelatedReady,$unrelatedCompleted,$unrelatedStart,$unrelatedError)) {
            if(Test-Path -LiteralPath $path){throw 'Production concurrent attacker input is not fresh'}
        }
        $attackArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',('"'+(Join-Path $PSScriptRoot 'windows_publisher_unprivileged_probe.ps1')+'"'),
            '-VolumeRoot',('"'+$VolumeRoot.TrimEnd('\')+'"'),'-ExpectedUserSid',$consumerSid,
            '-ServiceSid',$sid,'-OutputPath',('"'+$concurrentOutput+'"'),
            '-Stage','ProductionConcurrent','-ReleasePath',('"'+$productionStart+'"'),
            '-PayloadRelativePath',$attackRelative,'-VisibleLeaf',$visibleLeaf,
            '-SameVolumeSource',('"'+$attackSource+'"'),
            '-ExpectedSameVolumeSourceSha256',$scratchSha256)
        $concurrentAttacker=Start-Process -FilePath (Get-Command pwsh).Source `
            -ArgumentList $attackArgs -Credential $consumerCredential -PassThru `
            -WindowStyle Hidden -WorkingDirectory $consumerOutput `
            -RedirectStandardError $concurrentError -ErrorAction Stop
        $unrelatedArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',('"'+(Join-Path $PSScriptRoot 'windows_publisher_unprivileged_probe.ps1')+'"'),
            '-VolumeRoot',('"'+$VolumeRoot.TrimEnd('\')+'"'),'-ExpectedUserSid',$unrelatedSid,
            '-ServiceSid',$sid,'-OutputPath',('"'+$unrelatedAttackOutput+'"'),
            '-Stage','ProductionConcurrent','-ReleasePath',('"'+$unrelatedStart+'"'),
            '-PayloadRelativePath',$attackRelative,'-VisibleLeaf',$visibleLeaf,
            '-SameVolumeSource',('"'+$attackSource+'"'),
            '-ExpectedSameVolumeSourceSha256',$scratchSha256,'-UnrelatedConcurrent')
        $unrelatedAttacker=Start-Process -FilePath (Get-Command pwsh).Source `
            -ArgumentList $unrelatedArgs -Credential $unrelatedCredential -PassThru `
            -WindowStyle Hidden -WorkingDirectory $unrelatedOutputRoot `
            -RedirectStandardError $unrelatedError -ErrorAction Stop
        $attackerDeadline=[DateTime]::UtcNow.AddSeconds(30)
        while(-not (Test-Path -LiteralPath $concurrentReady) -and
            [DateTime]::UtcNow -lt $attackerDeadline) {
            if($concurrentAttacker.HasExited) {
                $diagnostic=Read-ConcurrentAttackerDiagnostic $concurrentOutput $concurrentError
                throw ('Production concurrent attacker exited before readiness: '+$diagnostic)
            }
            Start-Sleep -Milliseconds 25
        }
        if(-not (Test-Path -LiteralPath $concurrentReady) -or
            [IO.File]::ReadAllText($concurrentReady) -cne "usk.publisher.concurrent_ready.v1`n") {
            $diagnostic=Read-ConcurrentAttackerDiagnostic $concurrentOutput $concurrentError
            throw ('Production concurrent attacker did not become ready: '+$diagnostic)
        }
        $attackerProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$concurrentAttacker.Id) -ErrorAction Stop
        $attackerOwner=Invoke-CimMethod -InputObject $attackerProcess -MethodName GetOwnerSid
        if(-not $attackerProcess -or $attackerOwner.ReturnValue -ne 0 -or
            $attackerOwner.Sid -cne $consumerSid -or
            -not $attackerProcess.CommandLine.Contains('windows_publisher_unprivileged_probe.ps1')) {
            throw 'Production concurrent attacker differs from the submitting non-admin process'
        }
        $receipt['concurrent_attacker_process_id']=$concurrentAttacker.Id
        $receipt['concurrent_attacker_sid']=$attackerOwner.Sid
        $attackerDeadline=[DateTime]::UtcNow.AddSeconds(30)
        while(-not (Test-Path -LiteralPath $unrelatedReady) -and
            [DateTime]::UtcNow -lt $attackerDeadline) {
            if($unrelatedAttacker.HasExited) {
                $diagnostic=Read-ConcurrentAttackerDiagnostic $unrelatedAttackOutput $unrelatedError
                throw ('Unrelated concurrent attacker exited before readiness: '+$diagnostic)
            }
            Start-Sleep -Milliseconds 25
        }
        if(-not (Test-Path -LiteralPath $unrelatedReady) -or
            [IO.File]::ReadAllText($unrelatedReady) -cne "usk.publisher.concurrent_ready.v1`n") {
            $diagnostic=Read-ConcurrentAttackerDiagnostic $unrelatedAttackOutput $unrelatedError
            throw ('Unrelated concurrent attacker did not become ready: '+$diagnostic)
        }
        $unrelatedProcess=Get-CimInstance Win32_Process -Filter `
            ('ProcessId='+$unrelatedAttacker.Id) -ErrorAction Stop
        $unrelatedOwner=Invoke-CimMethod -InputObject $unrelatedProcess -MethodName GetOwnerSid
        if(-not $unrelatedProcess -or $unrelatedOwner.ReturnValue -ne 0 -or
            $unrelatedOwner.Sid -cne $unrelatedSid -or
            $unrelatedOwner.Sid -ceq $consumerSid -or
            -not $unrelatedProcess.CommandLine.Contains(
                'windows_publisher_unprivileged_probe.ps1')) {
            throw 'Unrelated concurrent attacker differs from its owned local login'
        }
        $receipt['unrelated_concurrent_attacker_process_id']=$unrelatedAttacker.Id
        Assert-OwnedVolume
    }
    if($ProductionPostrenameTermination -or $ProductionPreparedTermination) {
        $postrenameObserver=Start-ProductionRenameObserver -Phase $gate
        $receipt['production_rename_observer_ready_sha256']=(Get-FileHash `
            -LiteralPath $postrenameObserver.ready -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if($ClientBinary){$requestClient=Start-RequestClient}
    if($ProductionConcurrentRights) {
        if(-not $requestClient -or $requestClient.process.HasExited) {
            throw 'Production request client did not remain live at attacker marker'
        }
        [IO.File]::WriteAllText($productionStart,
            "usk.publisher.production_request_start.v1`n",[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($unrelatedStart,
            "usk.publisher.production_request_start.v1`n",[Text.UTF8Encoding]::new($false))
    }
    if($ExpectUnprotectedRefusal -or $ExpectPreexistingAnchorRefusal) {
        if($ExpectPreexistingAnchorRefusal) {
            # The registered production service deliberately uses --no-receipt.
            # Its authenticated client response is the terminal observation.
            if(-not $requestClient.process.WaitForExit(120000)) {
                throw 'Registered preexisting-anchor client timed out'
            }
            $requestClient.process.WaitForExit()
            if($requestClient.process.ExitCode -ne 3 -or
                -not (Test-Path -LiteralPath $requestClient.response -PathType Leaf) -or
                (Get-Item -LiteralPath $requestClient.response).Length -eq 0 -or
                (Get-Item -LiteralPath $requestClient.response).Length -gt 4MB -or
                (Test-Path -LiteralPath $nativePath)) {
                throw 'Registered preexisting-anchor refusal was not delivered by the client'
            }
            $receipt.native=(Read-ClientObservation $requestClient).service
            $receipt['refused_client']=[ordered]@{exit_code=3;caller_sid=$callerSid;
                binary_sha256=$requestClient.binary_sha256;
                response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant();
                delivery='response_received'}
            $requestClient=$null
            if(-not $terminalServiceProcess.WaitForExit(30000)) {
                throw 'Registered preexisting-anchor service retained after terminal refusal'
            }
            $terminalAtEnd=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
            if($terminalAtEnd.State -cne 'Stopped' -or $terminalAtEnd.ProcessId -ne 0) {
                throw 'Registered preexisting-anchor service did not stop after refusal'
            }
            $receipt['root_acl_after_service']=Get-OwnedVolumeRootSddl 'service-end'
            $anchorAfter=Get-OwnedPreexistingAnchorObservation
            if($receipt.native.schema -cne 'usk.publisher_lab_service_observation.v1' -or
                $receipt.native.status -cne 'recovery_required' -or
                $receipt.native.error -notmatch 'publisher exact anchor sibling is unavailable|publisher parent-bound child open failed' -or
                $receipt.root_acl_at_service_start -cne $receipt.root_acl_after_service -or
                -not [string]::Equals($anchorAfter.anchor_path,$poisonedAnchor,[StringComparison]::OrdinalIgnoreCase) -or
                $anchorAfter.child_count -ne 1 -or
                $anchorAfter.marker_bytes -ne 7 -or
                $anchorAfter.marker_sha256 -cne $poisonedMarkerHash -or
                $anchorAfter.anchor_sddl -cne $poisonedAnchorAcl -or
                $anchorAfter.marker_sddl -cne $poisonedMarkerAcl -or
                $anchorAfter.setup_state_present) {
                throw 'Preexisting publication anchor was changed or admitted'
            }
            $receipt['preexisting_anchor_after']=$anchorAfter
            $receipt.status='preexisting_anchor_recovery_required_observed'
        } else {
            $deadline=[DateTime]::UtcNow.AddSeconds(90)
            while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
            if(-not (Test-Path -LiteralPath $nativePath)){throw 'Unprotected-root refusal receipt absent'}
            $receipt.native=Read-NativeReceipt $nativePath
            $receipt['refused_client']=Complete-RequestClient $requestClient $false $true
            $requestClient=$null
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
            $receipt['root_acl_after']=(Get-Acl -LiteralPath $VolumeRoot).Sddl
            if($receipt.native.status -ne 'failed' -or
                $receipt.native.error -notmatch 'publisher protected object shape differs|publisher protected DACL ACEs differ|cannot open admitted publisher volume root' -or
                $receipt.root_acl_before -cne $receipt.root_acl_after -or
                (Test-Path -LiteralPath ($drive+'publication')) -or
                (Test-Path -LiteralPath ($drive+'setup-state'))) {
                throw 'Unprotected boundary was changed or admitted before publication'
            }
            $receipt.status='preprotected_boundary_refusal_observed'
        }
    } else {
    if($HostileRights) {
        $attackRelative=if($ConsumerAccess){'bin/core.exe'}else{'bin/core.bin'}
        if(@($plan.planned_entries|Where-Object relative_path -ceq $attackRelative).Count -ne 1){
            throw 'Selected hostile-rights payload is absent from the reviewed plan'
        }
        $hostilePhase=if($HostilePostrename){'postrename'}else{'prepublish'}
        $hostileStage=if($HostilePostrename){'Postpublish'}else{'Prepublish'}
        $hostileReady=if($HostilePostrename){"usk.publisher.lab_renamed_unconfirmed.v1`n"}else{"usk.publisher.lab_prepared.v1`n"}
        $ready=$nativePath.Substring(0,$nativePath.Length-5)+'-'+$hostilePhase+'-ready.txt'
        $release=$nativePath.Substring(0,$nativePath.Length-5)+'-'+$hostilePhase+'-release.txt'
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $ready) -or
            [IO.File]::ReadAllText($ready) -cne $hostileReady -or
            (Test-Path -LiteralPath $release)) {throw ('Selected publisher did not pause at protected '+$hostilePhase)}
        Assert-OwnedVolume
        $pausedBefore=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($pausedBefore.independent.identity -ne 'S-1-5-18' -or -not $pausedBefore.observer_task_removed){throw ('Protected '+$hostilePhase+' observation unavailable')}
        Assert-IndependentProtectedRows -Rows $pausedBefore.independent.rows -ServiceSid $sid
        if($HostilePostrename) {
            $preparedRow=$drive+'publication\journal\lab-prepared-evidence.json'
            $visibleRow=$drive+'publication\journal\lab-visible-evidence.json'
            if(@($pausedBefore.independent.rows|Where-Object path -ceq $preparedRow).Count -ne 1 -or
                @($pausedBefore.independent.rows|Where-Object path -ceq $visibleRow).Count -ne 0) {
                throw 'Independent journal rows do not bound the postrename prejournal window'
            }
        }
        $hostilePayloadPath=if($HostilePostrename){
            $drive+'publication\destination\visible\'+$attackRelative.Replace('/','\')
        }else{$drive+'publication\staging\candidate\'+$attackRelative.Replace('/','\')}
        if(@($pausedBefore.independent.rows|Where-Object path -ceq $hostilePayloadPath).Count -ne 1){
            throw ('Selected '+$hostilePhase+' payload was absent before hostile-rights probe')
        }
        $receipt[$hostilePhase+'_before_attack']=$pausedBefore.independent
        # The owned runner has fixed phase output names. Its later completed
        # check may reuse the Postpublish file; keep this paused receipt here.
        $attackOutput=Join-Path (Split-Path -Parent $vhd) $(if($HostilePostrename){
            'unprivileged-attack.json'
        }else{'unprivileged-prepublish.json'})
        $attackIdentity=if($RegisteredService -and $NonAdminClient){
            @{ExistingCredential=$consumerCredential;ExistingSid=$consumerSid}
        }else{@{}}
        & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid -OutputPath $attackOutput -Stage $hostileStage -PayloadRelativePath $attackRelative @attackIdentity
        $attack=Get-Content -LiteralPath $attackOutput -Raw|ConvertFrom-Json
        $receipt[$hostilePhase+'_hostile_rights']=$attack
        if($attack.status -ne 'unprivileged_access_denied_observed' -or $attack.payload_relative_path -cne $attackRelative){
            throw ('Selected '+$hostilePhase+' attacker result differs')
        }
        if($RegisteredService -and ($attack.account_sid -cne $consumerSid -or
            $attack.account_origin -cne 'existing_owned_client')) {
            throw ('Registered '+$hostilePhase+' attacker did not use the submitting client identity')
        }
        $pausedAfter=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt[$hostilePhase+'_after_attack']=$pausedAfter.independent
        if($pausedAfter.independent.identity -ne 'S-1-5-18' -or -not $pausedAfter.observer_task_removed -or
            ($pausedBefore.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($pausedAfter.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw ('Selected '+$hostilePhase+' hostile attempts changed protected state')
        }
        if($RegisteredService -and $NonAdminClient -and -not $HostilePostrename) {
            # The existing concurrent runner is bound to the prepublish
            # release marker and a still-staged payload. The postrename mode
            # instead challenges the actual visible tree while it is paused.
            $concurrentOutput=Join-Path $consumerOutput 'concurrent-attack.json'
            $concurrentError=Join-Path $consumerOutput 'concurrent-stderr.txt'
            $concurrentReady=Join-Path $consumerOutput 'concurrent-ready.txt'
            $concurrentCompleted=Join-Path $consumerOutput 'concurrent-completed.txt'
            if((Test-Path -LiteralPath $concurrentOutput) -or
                (Test-Path -LiteralPath $concurrentError) -or
                (Test-Path -LiteralPath $concurrentReady) -or
                (Test-Path -LiteralPath $concurrentCompleted)) {
                throw 'Concurrent attacker output is not fresh'
            }
            $attackArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',('"'+(Join-Path $PSScriptRoot 'windows_publisher_unprivileged_probe.ps1')+'"'),
                '-VolumeRoot',('"'+$VolumeRoot.TrimEnd('\')+'"'),'-ExpectedUserSid',$consumerSid,
                '-ServiceSid',$sid,'-OutputPath',('"'+$concurrentOutput+'"'),
                '-Stage','Concurrent','-ReleasePath',('"'+$release+'"'),
                '-PayloadRelativePath',$attackRelative)
            $concurrentAttacker=Start-Process -FilePath (Get-Command pwsh).Source `
                -ArgumentList $attackArgs -Credential $consumerCredential -PassThru `
                -WindowStyle Hidden -WorkingDirectory $consumerOutput `
                -RedirectStandardError $concurrentError -ErrorAction Stop
            $attackerDeadline=[DateTime]::UtcNow.AddSeconds(30)
            while(-not (Test-Path -LiteralPath $concurrentReady) -and
                [DateTime]::UtcNow -lt $attackerDeadline) {
                if($concurrentAttacker.HasExited){
                    $concurrentAttacker.WaitForExit()
                    $receipt['concurrent_attacker_exit_code']=$concurrentAttacker.ExitCode
                    if((Test-Path -LiteralPath $concurrentOutput -PathType Leaf) -and
                        (Get-Item -LiteralPath $concurrentOutput).Length -le 16KB) {
                        try {
                            $receipt['concurrent_attacker_early_receipt']=
                                Get-Content -LiteralPath $concurrentOutput -Raw|ConvertFrom-Json
                        } catch {
                            $receipt['concurrent_attacker_receipt_parse_error']=$_.Exception.Message
                        }
                    }
                    if((Test-Path -LiteralPath $concurrentError -PathType Leaf) -and
                        (Get-Item -LiteralPath $concurrentError).Length -le 16KB) {
                        $receipt['concurrent_attacker_stderr']=
                            [IO.File]::ReadAllText($concurrentError)
                    }
                    $reason=if($receipt.concurrent_attacker_early_receipt){
                        $receipt.concurrent_attacker_early_receipt.failure
                    }elseif($receipt.concurrent_attacker_stderr){
                        $receipt.concurrent_attacker_stderr
                    }elseif($receipt.concurrent_attacker_receipt_parse_error){
                        $receipt.concurrent_attacker_receipt_parse_error
                    }else{'exit_code='+$concurrentAttacker.ExitCode}
                    throw ('Concurrent attacker exited before readiness: '+$reason)
                }
                Start-Sleep -Milliseconds 25
            }
            if(-not (Test-Path -LiteralPath $concurrentReady) -or
                [IO.File]::ReadAllText($concurrentReady) -cne "usk.publisher.concurrent_ready.v1`n") {
                throw 'Concurrent attacker did not establish prepublish denial'
            }
            $attackerProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$concurrentAttacker.Id) -ErrorAction Stop
            $attackerOwner=Invoke-CimMethod -InputObject $attackerProcess -MethodName GetOwnerSid
            if(-not $attackerProcess -or $attackerOwner.ReturnValue -ne 0 -or
                $attackerOwner.Sid -cne $consumerSid -or
                -not $attackerProcess.CommandLine.Contains('windows_publisher_unprivileged_probe.ps1')) {
                throw 'Concurrent attacker differs from the submitting non-admin process'
            }
            $receipt['concurrent_attacker_process_id']=$concurrentAttacker.Id
            $receipt['concurrent_attacker_sid']=$attackerOwner.Sid
        }
        Assert-OwnedVolume
        $releaseTemp=$release+'.tmp'
        $releaseValue=if($HostilePostrename){
            "usk.publisher.lab_continue_after_rename.v1`n"
        }else{"usk.publisher.lab_continue.v1`n"}
        $releaseBytes=[Text.Encoding]::ASCII.GetBytes($releaseValue)
        $stream=[IO.FileStream]::new($releaseTemp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($releaseBytes,0,$releaseBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        [IO.File]::Move($releaseTemp,$release)
    }
    if($recover -and -not $InterruptDuringConsumerAccess) {
        # An external SYSTEM observer can terminate the uninstrumented
        # production service only after seeing the visible rename. It records
        # a missed window rather than treating a late kill as evidence.
        if($ProductionPostrenameTermination -or $ProductionPreparedTermination) {
            $observedTermination=Complete-ProductionRenameObserver $postrenameObserver $gate
            $receipt['production_rename_observer']=$observedTermination
            $receipt['production_rename_observer_task_removed']=$postrenameObserver.removed
            $ready=$postrenameObserver.output
        } else {
            # Controlled service cancellation at a flushed test readiness marker.
            # Neither path is physical-host power-loss evidence.
            $ready=$nativePath.Substring(0,$nativePath.Length-5)+'-'+$gate+'-ready.txt'
            $deadline=[DateTime]::UtcNow.AddSeconds(90)
            while(-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline){
                if((Test-Path -LiteralPath $nativePath) -and
                    (Get-Service $service -ErrorAction SilentlyContinue).Status -eq 'Stopped'){break}
                Start-Sleep -Milliseconds 250
            }
            if(-not (Test-Path -LiteralPath $ready) -or
                [IO.File]::ReadAllText($ready) -cne $readyContent) {
                $nativeError=if(Test-Path -LiteralPath $nativePath){
                    Read-BoundedDiagnostic $nativePath 2048
                }else{'native receipt absent'}
                $clientError=if($requestClient -and (Test-Path -LiteralPath $requestClient.error)){
                    Read-BoundedDiagnostic $requestClient.error 1024
                }else{'client error absent'}
                $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction SilentlyContinue
                throw ('Selected interruption window was not reached: '+$gate+
                    '; service='+$serviceInfo.State+'; exit_code='+$serviceInfo.ExitCode+
                    '; service_exit_code='+$serviceInfo.ServiceSpecificExitCode+
                    '; native='+$nativeError+'; client='+$clientError)
            }
        }
        if($ProductionPostrenameTermination -or $ProductionPreparedTermination) {
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
            if((Get-Service $service).Status -ne 'Stopped'){
                throw 'SCM retained externally terminated production service'
            }
        } elseif($TerminateAtPoststage -or $TerminateAtPostrename) {
            # This deliberately kills only the held, exact campaign service
            # process. It is a transport-loss test, never power-loss evidence.
            $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
            $serviceProcessAtGate=Get-CimInstance Win32_Process -Filter ('ProcessId='+$heldServiceIdentity.pid) -ErrorAction Stop
            if($heldServiceProcess.HasExited -or $serviceInfo.State -cne 'Running' -or
                $serviceInfo.ProcessId -ne $heldServiceIdentity.pid -or
                $serviceInfo.PathName -cne $testCommand -or
                -not $serviceProcessAtGate -or
                $serviceProcessAtGate.CreationDate -ne $heldServiceIdentity.created -or
                $serviceProcessAtGate.ExecutablePath -cne $heldServiceIdentity.executable -or
                $serviceProcessAtGate.CommandLine -cne $heldServiceIdentity.command) {
                throw 'Held owned service process changed before required termination'
            }
            $terminated=Stop-OwnedPublisherProcessTree $heldServiceProcess -RequireLiveKill
            if(-not $terminated.confirmed -or -not $terminated.kill_invoked -or
                $terminated.terminated -lt 1) {
                throw 'Owned fault-test service was not killed and confirmed'
            }
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
            if((Get-Service $service).Status -ne 'Stopped'){throw 'SCM retained the terminated test service'}
        } else {
            Stop-Service $service -ErrorAction Stop
        }
        if($requestClient) {
            $receipt['interrupted_client']=Complete-RequestClient $requestClient $false
            $requestClient=$null
            if(($TerminateAtPoststage -or $TerminateAtPostrename -or
                $ProductionPostrenameTermination -or $ProductionPreparedTermination) -and
                ($receipt.interrupted_client.exit_code -ne 5 -or
                 $receipt.interrupted_client.delivery -cne 'outcome_unknown')) {
                throw 'Terminated client did not report unknown outcome'
            }
        }
        if($ProductionPostrenameTermination -or $ProductionPreparedTermination) {
            if(Test-Path -LiteralPath $nativePath){throw 'Terminated production service wrote a lab receipt'}
            $receipt['interruption']=[ordered]@{kind='controlled_process_termination';window=$gate;
                service_pid=$observedTermination.service_pid;
                service_executable_sha256=$observedTermination.service_binary_sha256;
                readiness_sha256=(Get-FileHash -LiteralPath $ready -Algorithm SHA256).Hash.ToLowerInvariant();
                observer='independent_system_protected_namespace'}
        } elseif($TerminateAtPoststage -or $TerminateAtPostrename) {
            if(Test-Path -LiteralPath $nativePath){throw 'Killed service wrote a terminal native receipt'}
            $receipt['interruption']=[ordered]@{kind='controlled_process_termination';window=$gate;
                service_pid=$heldServiceIdentity.pid;service_started_utc=$heldServiceIdentity.started_utc;
                service_executable_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
                readiness_sha256=(Get-FileHash -LiteralPath $ready -Algorithm SHA256).Hash.ToLowerInvariant()}
        } else {
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
            if(-not (Test-Path -LiteralPath $nativePath)){throw 'Interrupted operation receipt absent'}
            $interrupted=Read-NativeReceipt $nativePath
            $expectedInterruption=if($InterruptAfterStage){'poststage gate stopped before forced VM poweroff'}else{$gate+' gate interrupted'}
            if($interrupted.status -ne 'recovery_required' -or $interrupted.error -notmatch $expectedInterruption -or
                $interrupted.error -notmatch '"code":"recovery_required"') {
                throw 'Interrupted ordinary apply did not truthfully retain recovery material'
            }
            $receipt['interruption']=[ordered]@{kind='controlled_service_cancellation';window=$gate;native=$interrupted;
                readiness_sha256=(Get-FileHash -LiteralPath $ready -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
        $before=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) `
            -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['interrupted_independent']=$before.independent
        $receipt['interrupted_observer_task_removed']=$before.observer_task_removed
        $publicBefore=@($before.independent.rows|Where-Object { -not $_.directory -and
            $_.path.StartsWith(($drive+'setup-state\'),[StringComparison]::Ordinal) })
        # The poststage window precedes setup-root bootstrap. Later windows
        # retain only its marker; none may have installed/audit completion.
        $expectedPublicCount=if($InterruptAfterStage){0}else{1}
        if($before.independent.identity -ne 'S-1-5-18' -or -not $before.observer_task_removed -or
            $publicBefore.Count -ne $expectedPublicCount -or
            ($expectedPublicCount -eq 1 -and $publicBefore[0].path -cne ($drive+'setup-state\.usk-owned-root.v1.json')) -or
            @($before.independent.rows|Where-Object path -ceq ($drive+'publication\state\lab-installed-state.json')).Count -ne 0) {
            throw ('Independent interrupted metadata differs: public_files='+($publicBefore.path -join ',')+
                '; identity='+$before.independent.identity+'; observer_removed='+$before.observer_task_removed)
        }
        Assert-IndependentProtectedRows -Rows $before.independent.rows -ServiceSid $sid
        $visibleRecords=@($before.independent.rows|Where-Object path -ceq ($drive+'publication\journal\lab-visible-evidence.json'))
        $expectedVisibleRecords=if($InterruptAfterVisibleRecord){1}else{0}
        if($visibleRecords.Count -ne $expectedVisibleRecords){throw 'Interrupted visible-journal boundary differs from selected window'}
        if($ProductionPreparedTermination) {
            $preparedRecords=@($before.independent.rows|Where-Object {
                $_.path -ceq ($drive+'publication\journal\lab-prepared-evidence.json')})
            if($preparedRecords.Count -ne 1 -or
                $preparedRecords[0].sha256 -cne $observedTermination.prepared_record_sha256) {
                throw 'Independent prepared intent differs from terminated production observer'
            }
        }
        $payloadPrefix=if($InterruptBeforePublish -or $InterruptAfterStage -or $ProductionPreparedTermination){$drive+'publication\staging\candidate\'}else{$visibleRoot+'\'}
        $absentPrefix=if($InterruptBeforePublish -or $InterruptAfterStage -or $ProductionPreparedTermination){$visibleRoot}else{$drive+'publication\staging\candidate'}
        if(@($before.independent.rows|Where-Object {$_.path -ceq $absentPrefix -or $_.path.StartsWith($absentPrefix+'\',[StringComparison]::Ordinal)}).Count -ne 0){throw 'Interrupted payload namespace differs from selected window'}
        foreach($entry in $plan.planned_entries|Where-Object entry_type -eq 'file') {
            $path=$payloadPrefix+$entry.relative_path.Replace('/','\')
            $row=@($before.independent.rows|Where-Object path -ceq $path)
            if($row.Count -ne 1 -or $row[0].sha256 -ne $entry.sha256 -or $row[0].bytes -ne $entry.size_bytes) {
                throw 'Independent interrupted visible payload differs'
            }
        }
        $snapshot=@($before.independent.rows|Where-Object path -ceq ($drive+'publication\journal\lab-reviewed-plan.json'))
        if($snapshot.Count -ne 1){throw 'Independent caller-bound snapshot absent'}
        $snapshotValue=$snapshot[0].content_json|ConvertFrom-Json
        if($snapshotValue.schema -ne $(if($ConsumerAccess){'usk.publisher.lab_reviewed_plan_snapshot.v4'}else{'usk.publisher.lab_reviewed_plan_snapshot.v3'}) -or
            $snapshotValue.transaction_id -ne $applyRequest.transaction_id -or
            $snapshotValue.applied_at -ne $applyRequest.applied_at -or
            $snapshotValue.plan_digest -ne $plan.plan_digest) {throw 'Interrupted snapshot caller binding differs'}
        # Delete only regular input files within this freshly created VM root;
        # retain minimal parsed inputs and independent observations in receipt.
        $removed=[Collections.Generic.List[string]]::new()
        foreach($path in $sourceInputs) {
            $exact=[IO.Path]::GetFullPath($path)
            $item=Get-Item -LiteralPath $exact -Force
            if(-not $exact.StartsWith(($root+'\'),[StringComparison]::OrdinalIgnoreCase) -or
                $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Source-removal target escaped the newly created hosted input root'
            }
            Remove-Item -LiteralPath $exact -Force
            if(Test-Path -LiteralPath $exact){throw 'Original input remains after source removal'}
            $removed.Add($exact)
        }
        $receipt['removed_source_inputs']=$removed.ToArray()
        $recoveryPath=Join-Path $root ('vm-recovery-'+$id+'.json')
        $recoveryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$recoveryPath+'" '+$VolumeRoot+
            ' --recover-visible-bound --campaign-vm-id '+$vmId
        if($ClientBinary) {
            $recoveryPath=Join-Path $root ('vm-recovery-reviewed-'+$id+'.json')
            $recoveryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$recoveryPath+'" '+$VolumeRoot+
                ' --recover-reviewed --campaign-vm-id '+$vmId+$clientArguments
        }
        if($RegisteredService) {
            # Remove only the test-only gate from the exact generated service.
            # The ordinary control then validates the original binding and
            # configures its source-free recovery command.
            & sc.exe config $service binPath= $expectedRegisteredCommand|Out-Null
            if($LASTEXITCODE -ne 0 -or
                (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
                throw 'Owned fault-test command could not be restored'
            }
            $controlArgs=@('--recover',$service,$ServiceBinary,$VolumeRoot,$callerSid)
            if($registeredMode){$controlArgs+=$registeredMode}
            $configuredRecovery=& $ServiceControlBinary @controlArgs
            if($LASTEXITCODE -ne 0 -or ($configuredRecovery|ConvertFrom-Json).status -ne 'recovery_configured') {
                throw 'Product service control did not configure incomplete-phase recovery'
            }
            $nativePath=$recoveryPath
            Start-RegisteredPublisher
            $requestClient=Start-RequestClient $recoveryRequest
        } else {
            & sc.exe config $service binPath= $recoveryCommand|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned service recovery configuration failed'}
            try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
            $nativePath=$recoveryPath
            if($ClientBinary){$requestClient=Start-RequestClient}
        }
    }
    if($InterruptDuringConsumerAccess) {
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Partial consumer grant receipt absent'}
        $partial=Read-NativeReceipt $nativePath
        $receipt['partial_grant_native']=$partial
        if($partial.status -ne 'recovery_required' -or $partial.error -notmatch 'first consumer grant'){
            throw ('Expected injected grant interruption absent; native status='+$partial.status+'; error='+$partial.error)
        }
        $receipt['interrupted_consumer_client']=Complete-RequestClient $requestClient $false $true
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $before=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['partial_before_replay_independent']=$before.independent
        Assert-IndependentProtectedRows -Rows $before.independent.rows -ServiceSid $sid -ConsumerSid $consumerSid -VisibleRoot $visibleRoot -AllowPartial
        $granted=@($before.independent.rows|Where-Object {@($_.aces|Where-Object sid -eq $consumerSid).Count -eq 1})
        if($granted.Count -ne 1){throw 'First-grant interruption did not leave exactly one readable payload object'}
        $partialWitness=[pscustomobject]@{volume_drive_root=$drive;native=$partial;service_sid=$sid;consumer_sid=$consumerSid;
            independent=$before.independent;observer_task_removed=$before.observer_task_removed;plan=$plan;archive_sha256=$inputs.archive_sha256;
            apply_request=$applyRequest;request=$request.payload}
        Assert-IndependentMetadataProbe $partialWitness -AllowPartialConsumerGrant
        $receipt['partial_consumer_grant']=[ordered]@{native=$partial;independent=$before.independent;observer_task_removed=$before.observer_task_removed;granted_objects=$granted.Count}
        $removed=[Collections.Generic.List[string]]::new()
        foreach($path in $sourceInputs) {
            $exact=[IO.Path]::GetFullPath($path);$item=Get-Item -LiteralPath $exact -Force
            if(-not $exact.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Consumer source removal target escaped owned root'}
            Remove-Item -LiteralPath $exact -Force
            if(Test-Path -LiteralPath $exact){throw 'Consumer source input remains'}
            $removed.Add($exact)
        }
        $receipt['removed_source_inputs']=$removed.ToArray()
        $nativePath=Join-Path $root ('vm-selected-consumer-reconnect-'+$id+'.json')
        $recoveryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$nativePath+'" '+$VolumeRoot+$selectedClientArguments+$clientArguments
        & sc.exe config $service binPath= $recoveryCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Consumer reconnect configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        $requestClient=Start-RequestClient
    }
    if($RegisteredService) {
        if(-not $requestClient.process.WaitForExit(120000)){throw 'Registered service client timed out'}
        $requestClient.process.WaitForExit()
        if($requestClient.process.ExitCode -ne 0 -or
            -not (Test-Path -LiteralPath $requestClient.response -PathType Leaf) -or
            (Get-Item -LiteralPath $requestClient.response).Length -gt 4MB -or
            ((Test-Path -LiteralPath $nativePath) -and -not $HostileRights)) {
            $diagnostic=[ordered]@{exit_code=$requestClient.process.ExitCode;
                response=if(Test-Path -LiteralPath $requestClient.response -PathType Leaf){
                    Read-BoundedDiagnostic $requestClient.response 4096}else{'response absent'};
                stderr=if(Test-Path -LiteralPath $requestClient.error -PathType Leaf){
                    Read-BoundedDiagnostic $requestClient.error 2048}else{'stderr absent'};
                lab_receipt_present=(Test-Path -LiteralPath $nativePath)}
            $receipt['registered_client_failure']=$diagnostic
            throw ('Registered service client failed or wrote a lab receipt: '+
                ($diagnostic|ConvertTo-Json -Compress))
        }
        $clientObservation=Read-ClientObservation $requestClient
        $receipt.native=$clientObservation.service
        if($clientObservation.envelope) {
            $receipt['machine_one_shot_apply']=[ordered]@{
                request_id=$clientObservation.envelope.request_id;
                status=$clientObservation.envelope.status;
                response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
        if($HostileRights) {
            if(-not (Test-Path -LiteralPath $nativePath) -or
                [IO.File]::ReadAllText($requestClient.response).Trim() -cne
                [IO.File]::ReadAllText($nativePath).Trim()) {
                throw 'Registered hostile service receipt differs from authenticated client result'
            }
            $receipt['native_receipt_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
            $nativePath=Join-Path $root ('registered-no-receipt-'+$id+'.json')
            if(Test-Path -LiteralPath $nativePath) {
                throw 'Registered recovery absence marker already exists'
            }
        }
        if($ConsumerAccess -or $NonAdminClient) {
            $actual=Assert-RequestClientImage $requestClient
            $receipt['registered_client_identity']=$actual
        }
        $requestBinary=$requestClient.binary_path
        $receipt['authenticated_client']=[ordered]@{exit_code=0;caller_sid=$callerSid;
            binary_sha256=(Get-FileHash -LiteralPath $requestBinary -Algorithm SHA256).Hash.ToLowerInvariant();
            response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant();
            delivery='response_received'}
        if($clientObservation.envelope) {
            $receipt['machine_one_shot_response_sha256']=$receipt.authenticated_client.response_sha256
        } else {
            $receipt['native_response_sha256']=$receipt.authenticated_client.response_sha256
        }
        $requestClient=$null
        if($concurrentAttacker) {
            if($ProductionConcurrentRights) {
                $nativeCall=$receipt.native.protected_anchors.publication_probe.native_rename_call
                if(-not $nativeCall -or $nativeCall.clock -cne 'qpc') {
                    throw 'Production native rename call interval is unavailable'
                }
                $raceTarget=[ordered]@{schema='usk.publisher.rename_race_target.v1';
                    clock='qpc';frequency=$nativeCall.frequency;
                    start_tick=$nativeCall.start_tick;end_tick=$nativeCall.end_tick}
                $completedBytes="usk.publisher.concurrent_completed.v2`n"+
                    ($raceTarget|ConvertTo-Json -Compress)+"`n"
                $completedTemp=$concurrentCompleted+'.tmp'
                [IO.File]::WriteAllText($completedTemp,$completedBytes,
                    [Text.UTF8Encoding]::new($false))
                [IO.File]::Move($completedTemp,$concurrentCompleted)
                $unrelatedCompletedTemp=$unrelatedCompleted+'.tmp'
                [IO.File]::WriteAllText($unrelatedCompletedTemp,$completedBytes,
                    [Text.UTF8Encoding]::new($false))
                [IO.File]::Move($unrelatedCompletedTemp,$unrelatedCompleted)
            }else{
                [IO.File]::WriteAllText($concurrentCompleted,
                    "usk.publisher.concurrent_completed.v1`n",[Text.UTF8Encoding]::new($false))
            }
            if($ProductionConcurrentRights) {
                $stageObservation=Complete-StageObserver $stageObserver
                $receipt['production_stage_observation']=$stageObservation
                $receipt['production_stage_observer_task_removed']=$stageObserver.removed
                if($stageObservation.source_sha256_at_start -cne $scratchSha256 -or
                    $stageObservation.source_sha256_at_stop -cne $scratchSha256) {
                    throw 'SYSTEM observer found changed same-volume attacker source'
                }
            }
            if(-not $concurrentAttacker.WaitForExit(30000)) {
                throw 'Concurrent attacker remained after terminal publisher reply'
            }
            $concurrentAttacker.WaitForExit()
            if($concurrentAttacker.ExitCode -ne 0 -or
                -not (Test-Path -LiteralPath $concurrentOutput -PathType Leaf) -or
                (Get-Item -LiteralPath $concurrentOutput).Length -gt
                    $(if($ProductionConcurrentRights){512KB}else{16KB})) {
                $attackDiagnostic=[ordered]@{
                    exit_code=$concurrentAttacker.ExitCode;
                    receipt_present=(Test-Path -LiteralPath $concurrentOutput -PathType Leaf);
                    receipt_bytes=if(Test-Path -LiteralPath $concurrentOutput -PathType Leaf){
                        (Get-Item -LiteralPath $concurrentOutput).Length}else{$null};
                    receipt_prefix=if(Test-Path -LiteralPath $concurrentOutput -PathType Leaf){
                        Read-BoundedDiagnostic $concurrentOutput 512}else{$null};
                    stderr_prefix=if(Test-Path -LiteralPath $concurrentError -PathType Leaf){
                        Read-BoundedDiagnostic $concurrentError 2048}else{$null}}
                if($attackDiagnostic.receipt_present -and
                    $attackDiagnostic.receipt_bytes -le 512KB) {
                    try {
                        $attackReceipt=Get-Content -LiteralPath $concurrentOutput -Raw|
                            ConvertFrom-Json
                        $attackDiagnostic['receipt_summary']=[ordered]@{
                            status=$attackReceipt.status;
                            failure=$attackReceipt.failure;
                            rename_race=$attackReceipt.concurrent.native_rename_overlap;
                            ready_utc=$attackReceipt.concurrent.ready_utc;
                            started_seen_utc=$attackReceipt.concurrent.started_seen_utc;
                            completed_seen_utc=$attackReceipt.concurrent.completed_seen_utc;
                            cycles_after_start=$attackReceipt.concurrent.cycles_after_start_before_observed_reply;
                            destination_denied_after_start=$attackReceipt.concurrent.destination_create.denied_after_start_before_observed_reply;
                            staged_denied_after_start=$attackReceipt.concurrent.staged_write.denied_after_start_before_observed_reply}
                    }catch{
                        $attackDiagnostic['receipt_parse_failure']=$_.Exception.Message
                    }
                }
                $receipt['concurrent_attacker_failure']=$attackDiagnostic
                throw ('Concurrent attacker did not produce a bounded successful receipt: '+
                    ($attackDiagnostic|ConvertTo-Json -Compress -Depth 5))
            }
            $concurrent=Get-Content -LiteralPath $concurrentOutput -Raw|ConvertFrom-Json
            $coverage=if($ProductionConcurrentRights) {
                $nativeCall=$receipt.native.protected_anchors.publication_probe.native_rename_call
                $nativeStart=[long]$nativeCall.start_tick
                $nativeEnd=[long]$nativeCall.end_tick
                $nativeOverlap=$concurrent.concurrent.native_rename_overlap
                $overlapAttempt=@($nativeOverlap.overlap_attempt)
                $nativeOverlapCovered=$nativeOverlap.operation -ceq 'publication_rename' -and
                    $nativeOverlap.clock -ceq 'qpc' -and
                    [long]$nativeOverlap.clock_frequency -eq [long]$nativeCall.frequency -and
                    -not $nativeOverlap.failure -and
                    $nativeEnd -gt $nativeStart -and
                    [long]$nativeOverlap.attempt_count -ge 1 -and
                    [long]$nativeOverlap.overlap_count -ge 1 -and
                    $overlapAttempt.Count -eq 2 -and
                    [long]$overlapAttempt[0] -lt $nativeEnd -and
                    [long]$overlapAttempt[1] -gt $nativeStart -and
                    [long]$overlapAttempt[1] -gt [long]$overlapAttempt[0]
                $transitionCoverage=[ordered]@{}
                $transitionCovered=$nativeCall.clock -ceq 'qpc' -and
                    [long]$nativeCall.frequency -eq [long]$stageObservation.clock_frequency -and
                    $nativeStart -gt 0 -and $nativeEnd -gt $nativeStart -and
                    $nativeEnd-$nativeStart -le [long]($stageObservation.clock_frequency/2) -and
                    $nativeStart -ge [long]$stageObservation.transition.last_staged_only_start_tick -and
                    $nativeEnd -le [long]$stageObservation.transition.first_visible_end_tick -and
                    $concurrent.concurrent.clock -ceq 'qpc' -and
                    [long]$concurrent.concurrent.clock_frequency -eq
                        [long]$stageObservation.clock_frequency
                foreach($operation in @('destination_create',
                        'publication_rename','publication_write_dac')) {
                    $matched=Get-TransitionAttemptCoverage $stageObservation `
                        $concurrent.concurrent.PSObject.Properties[$operation].Value.denied_attempts
                    $transitionCoverage[$operation]=$matched
                    if(-not $matched){$transitionCovered=$false}
                }
                $receipt['production_transition_coverage']=[ordered]@{
                    schema='usk.publisher.production_transition_coverage.v1';
                    clock='qpc';clock_frequency=$stageObservation.clock_frequency;
                    last_staged_only_start_tick=$stageObservation.transition.last_staged_only_start_tick;
                    last_staged_only_end_tick=$stageObservation.transition.last_staged_only_end_tick;
                    first_visible_start_tick=$stageObservation.transition.first_visible_start_tick;
                    first_visible_end_tick=$stageObservation.transition.first_visible_end_tick;
                    native_call=$nativeCall;
                    hostile_rename_overlap=$nativeOverlap;
                    staged_replace_source_delete_access=$concurrent.same_volume_source_delete_access;
                    denied_attempts=$transitionCoverage}
                # The protected ancestor masks absence as ACCESS_DENIED for
                # this caller. Correlate its denied writes with independent
                # SYSTEM samples of the actual staged file.
                $overlap=Test-LiveStageAttemptOverlap $stageObservation `
                    $concurrent.concurrent.staged_write.denied_attempts
                $insertOverlap=Test-LiveStageAttemptOverlap $stageObservation `
                    $concurrent.concurrent.staged_insert.denied_attempts
                $streamOverlap=Test-LiveStageAttemptOverlap $stageObservation `
                    $concurrent.concurrent.staged_ads_write.denied_attempts
                $renameOverlap=Test-LiveStageAttemptOverlap $stageObservation `
                    $concurrent.concurrent.publication_rename.denied_attempts
                $dacOverlap=Test-LiveStageAttemptOverlap $stageObservation `
                    $concurrent.concurrent.publication_write_dac.denied_attempts
                $extendedStageCovered=$true
                $extendedStageCoverage=[ordered]@{}
                foreach($operation in @('staged_delete','staged_rename','staged_hardlink',
                        'staged_write_owner','staged_write_attributes',
                        'candidate_delete_child')) {
                    $attempts=$concurrent.concurrent.PSObject.Properties[$operation].Value.denied_attempts
                    $matched=Test-LiveStageAttemptOverlap $stageObservation $attempts
                    $extendedStageCoverage[$operation]=$matched
                    if(-not $matched){$extendedStageCovered=$false}
                }
                $receipt['production_extended_stage_coverage']=$extendedStageCoverage
                $concurrent.stage -ceq 'ProductionConcurrent' -and
                $concurrent.concurrent.started_seen_utc -and
                $stageObserver.removed -and $transitionCovered -and $nativeOverlapCovered -and
                $overlap -and
                $insertOverlap -and $streamOverlap -and
                $renameOverlap -and $dacOverlap -and $extendedStageCovered -and
                $stageObservation.source_sha256_at_start -ceq $scratchSha256 -and
                $stageObservation.source_sha256_at_stop -ceq $scratchSha256 -and
                $concurrent.concurrent.destination_create.denied_after_start_before_observed_reply -ge 1 -and
                $concurrent.concurrent.staged_write.denied_after_start_before_observed_reply -ge 1 -and
                $concurrent.concurrent.staged_insert.denied_after_start_before_observed_reply -ge 1 -and
                $concurrent.concurrent.staged_ads_write.denied_after_start_before_observed_reply -ge 1 -and
                $concurrent.concurrent.publication_rename.denied_after_start_before_observed_reply -ge 1 -and
                $concurrent.concurrent.publication_write_dac.denied_after_start_before_observed_reply -ge 1 -and
                $concurrent.concurrent.cycles_after_start_before_observed_reply -ge 1
            }else{
                $concurrent.stage -ceq 'Concurrent' -and
                $concurrent.concurrent.destination_create.denied_after_gate_before_observed_reply -ge 1 -and
                $concurrent.concurrent.cycles_after_gate_before_observed_reply -ge 1 -and
                $concurrent.concurrent.staged_write.denied -ge 1
            }
            if($concurrent.schema -cne 'usk.publisher.unprivileged_access_probe.v1' -or
                $concurrent.status -cne 'access_denied_observed' -or
                -not $coverage -or
                $concurrent.user_sid -cne $consumerSid -or $concurrent.administrator -or
                ($ProductionConcurrentRights -and (
                    -not $concurrent.same_volume_source_read_confirmed -or
                    $concurrent.same_volume_source_sha256 -cne $scratchSha256 -or
                    $concurrent.same_volume_source_delete_access -cne 'denied' -or
                    $concurrent.same_volume_source_delete_error -ne 5)) -or
                $concurrent.service_sid_present -or
                $concurrent.process_id -ne $concurrentAttacker.Id -or
                $concurrent.concurrent.destination_create.denied -lt 4 -or
                $concurrent.concurrent.visible_write.denied_after_completion -lt 3 -or
                $concurrent.concurrent.cycles_after_completion -lt 3) {
                throw 'Concurrent hostile-rights observation differs from the actual client'
            }
            $receipt['concurrent_hostile_rights']=$concurrent
            if($ProductionConcurrentRights) {
                if(-not $unrelatedAttacker.WaitForExit(30000)) {
                    throw 'Unrelated concurrent attacker retained after publisher reply'
                }
                $unrelatedAttacker.WaitForExit()
                if($unrelatedAttacker.ExitCode -ne 0 -or
                    -not (Test-Path -LiteralPath $unrelatedAttackOutput -PathType Leaf) -or
                    (Get-Item -LiteralPath $unrelatedAttackOutput).Length -gt 512KB) {
                    $diagnostic=Read-ConcurrentAttackerDiagnostic `
                        $unrelatedAttackOutput $unrelatedError
                    throw ('Unrelated concurrent attacker failed: '+$diagnostic)
                }
                $unrelated=Get-Content -LiteralPath $unrelatedAttackOutput -Raw|ConvertFrom-Json
                $unrelatedOverlap=$unrelated.concurrent.native_rename_overlap
                $unrelatedAttempt=@($unrelatedOverlap.overlap_attempt)
                $unrelatedStageCoverage=[ordered]@{}
                $unrelatedStageCovered=$true
                foreach($operation in @('staged_write','staged_insert',
                        'staged_ads_write','staged_delete','staged_rename',
                        'staged_hardlink','staged_write_owner',
                        'staged_write_attributes','candidate_delete_child',
                        'publication_rename','publication_write_dac')) {
                    $matched=Test-LiveStageAttemptOverlap $stageObservation `
                        $unrelated.concurrent.PSObject.Properties[$operation].Value.denied_attempts
                    $unrelatedStageCoverage[$operation]=$matched
                    if(-not $matched){$unrelatedStageCovered=$false}
                }
                if($unrelated.schema -cne 'usk.publisher.unprivileged_access_probe.v1' -or
                    $unrelated.status -cne 'access_denied_observed' -or
                    $unrelated.user_sid -cne $unrelatedSid -or
                    -not $unrelated.same_volume_source_read_confirmed -or
                    $unrelated.same_volume_source_sha256 -cne $scratchSha256 -or
                    $unrelated.same_volume_source_delete_access -cne 'denied' -or
                    $unrelated.same_volume_source_delete_error -ne 5 -or
                    $unrelated.user_sid -ceq $consumerSid -or
                    $unrelated.process_id -ne $unrelatedAttacker.Id -or
                    $unrelated.administrator -or $unrelated.service_sid_present -or
                    $unrelated.concurrent.started_seen_utc -eq $null -or
                    $unrelated.concurrent.visible_write.denied_after_completion -lt 3 -or
                    $unrelatedOverlap.operation -cne 'publication_rename' -or
                    $unrelatedOverlap.clock -cne 'qpc' -or
                    [long]$unrelatedOverlap.clock_frequency -ne [long]$nativeCall.frequency -or
                    [long]$unrelatedOverlap.overlap_count -lt 1 -or
                    $unrelatedAttempt.Count -ne 2 -or
                    [long]$unrelatedAttempt[0] -ge $nativeEnd -or
                    [long]$unrelatedAttempt[1] -le $nativeStart -or
                    -not $unrelatedStageCovered) {
                    throw 'Unrelated attacker did not cover live staging and native rename'
                }
                $receipt['production_unrelated_concurrent_stage_coverage']=$unrelatedStageCoverage
                $receipt['production_unrelated_concurrent_hostile_rights']=$unrelated
                $receipt['concurrent_qualification_limit']=
                    'two_local_nonadmin_sids_denied_during_staging_and_native_rename_staged_replace_source_delete_denied_not_target_proof_other_profile_cases_remain'
                $unrelatedAttacker=$null
            }
            $concurrentAttacker=$null
        }
    } else {
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Native service receipt absent'}
        $receipt.native=Read-NativeReceipt $nativePath
        if($requestClient) {
            $receipt['authenticated_client']=Complete-RequestClient $requestClient $true
            $requestClient=$null
        }
        $receipt['native_receipt_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $receipt['consumer_sid']=if($ConsumerAccess){$consumerSid}else{''}
    if($RegisteredService -and -not $HostileRights -and -not $recover) {
        # The packaged client has received the terminal reply and closed its
        # authenticated pipe. The one-request service must now stop itself
        # before install-to-verify reconfiguration, without an SCM stop call.
        if($ControllerApply) {
            $stopDeadline=[DateTime]::UtcNow.AddSeconds(30)
            while((Get-Service $service).Status -ne 'Stopped' -and
                [DateTime]::UtcNow -lt $stopDeadline){Start-Sleep -Milliseconds 100}
        } elseif(-not $terminalServiceProcess.WaitForExit(30000)) {
            throw 'Original registered publisher process retained after terminal client disconnect'
        }
        $terminalAtEnd=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($terminalAtEnd.State -cne 'Stopped' -or $terminalAtEnd.ProcessId -ne 0 -or
            $terminalAtEnd.ExitCode -ne 0) {
            throw 'Registered publisher did not stop cleanly after terminal client disconnect'
        }
        $receipt['registered_terminal_shutdown']=[ordered]@{
            original_process_exited=if($ControllerApply){$null}else{$true};scm_state=$terminalAtEnd.State;
            scm_exit_code=$terminalAtEnd.ExitCode}
    } elseif((Get-Service $service).Status -ne 'Stopped') {Stop-Service $service}
    if($RegisteredService -and $HostileRights) {
        # Restore the registered command before using product recovery/verify
        # control. Only the separately built fault-test binary admits the gate.
        & sc.exe config $service binPath= $expectedRegisteredCommand|Out-Null
        if($LASTEXITCODE -ne 0 -or
            (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
            throw 'Registered hostile service command restoration failed'
        }
    }
    if($receipt.native.status -ne 'pass'){throw ('Native metadata operation failed: '+$receipt.native.error)}
    if($RegisteredService -and -not $recover -and
        ($receipt.native.install_operation_guard_held -ne $true -or
         $receipt.native.install_operation_guard_abandoned -ne $false)) {
        throw 'Authenticated install did not hold its installation operation guard'
    }
    $installedResponse=if($recover){$receipt.native.recovery_installed_response}else{$receipt.native.apply_response}
    if($recover -and $receipt.native.recovery_observation.decision -ne $recoveryDecision) {
        throw 'Source-free recovery did not perform the pending installed-state completion'
    }
    if($installedResponse.status -ne 'ok' -or
        $installedResponse.payload.schema -ne 'usk.installed_state.v1' -or
        $installedResponse.payload.transaction_id -ne $applyRequest.transaction_id -or
        $installedResponse.payload.created_at -ne $applyRequest.applied_at -or
        $installedResponse.payload.last_verification.status -ne 'pass') {
        throw 'Protected ordinary apply did not preserve caller identities and verified installed result'
    }
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId $id
    $receipt.independent=$readback.independent;$receipt.observer_task_removed=$readback.observer_task_removed
    Assert-IndependentMetadataProbe ([pscustomobject]$receipt)
    if($RegisteredService -and $recover) {
        $stagedRoot=$drive+'publication\staging\candidate'
        foreach($row in $before.independent.rows) {
            $completedPath=$row.path
            if($row.path -ceq $stagedRoot -or
                $row.path.StartsWith($stagedRoot+'\',[StringComparison]::Ordinal)) {
                $completedPath=$visibleRoot+$row.path.Substring($stagedRoot.Length)
            }
            $matching=@($receipt.independent.rows|Where-Object path -ceq $completedPath)
            if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or
                $matching[0].bytes -ne $row.bytes) {
                throw 'Registered recovery changed retained payload or durable intent'
            }
        }
        $receipt['source_free_recovery']=[ordered]@{action=$recoveryDecision;
            interrupted_independent=$before.independent;completed_independent=$receipt.independent;
            completed_row_count=@($receipt.independent.rows).Count}
    }
    if($NonAdminClient -and @($receipt.independent.rows|Where-Object {
        @($_.aces|Where-Object sid -eq $consumerSid).Count -ne 0
    }).Count -ne 0) {
        throw 'Non-admin request caller acquired published payload or private-state ACL rights'
    }
    if($RegisteredService) {
        # Keep the same SCM service identity and durable request while withholding
        # every original authoring/source input. This exercises the production
        # service grammar against the existing source-free recovery engine.
        if(-not $recover) {
            $removed=[Collections.Generic.List[string]]::new()
            foreach($path in $sourceInputs) {
                $exact=[IO.Path]::GetFullPath($path)
                $item=Get-Item -LiteralPath $exact -Force
                if(-not $exact.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or
                    $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw 'Registered recovery source removal escaped owned input root'
                }
                Remove-Item -LiteralPath $exact -Force
                if(Test-Path -LiteralPath $exact){throw 'Registered recovery source input remains'}
                $removed.Add($exact)
            }
            $receipt['removed_source_inputs']=$removed.ToArray()
        } else {
            foreach($path in $sourceInputs) {
                if(Test-Path -LiteralPath $path){throw 'Original source returned before registered replay'}
            }
        }
        if($callerSid -eq 'S-1-5-18'){throw 'Registered client unexpectedly uses SYSTEM identity'}
        $beforeControl=(Get-CimInstance Win32_Service -Filter "Name='$service'").PathName
        $wrongCallerError=Join-Path $root ('wrong-caller-'+$id+'.txt')
        $wrongArgs=@('--recover',$service,$ServiceBinary,$VolumeRoot,'S-1-5-18')
        if($registeredMode){$wrongArgs+=$registeredMode}
        & $ServiceControlBinary @wrongArgs 2>$wrongCallerError|Out-Null
        if($LASTEXITCODE -eq 0 -or
            (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $beforeControl) {
            throw 'Registered recovery accepted a different caller or changed service configuration'
        }
        $receipt['wrong_caller_recovery_refused']=$true
        if($ControllerApply) {
            $script:controllerMode='recover'
            $script:controllerPending=$true
        } elseif($ReuseRegistration) {
            if($beforeControl -cne $expectedRegisteredCommand) {
                throw 'Registered publisher command changed before source-free recovery'
            }
            $receipt['source_free_recovery_without_reconfiguration']=$true
        } else {
            $controlArgs=@('--recover',$service,$ServiceBinary,$VolumeRoot,$callerSid)
            if($registeredMode){$controlArgs+=$registeredMode}
            $configuredRecovery=& $ServiceControlBinary @controlArgs
            if($LASTEXITCODE -ne 0 -or ($configuredRecovery|ConvertFrom-Json).status -ne 'recovery_configured') {
                throw 'Product service control did not configure source-free recovery'
            }
        }
        Start-RegisteredPublisher
        $submittedRecovery=$recoveryRequest
        $requestClient=Start-RequestClient $submittedRecovery
        if(-not $requestClient.process.WaitForExit(120000)){throw 'Registered recovery client timed out'}
        $requestClient.process.WaitForExit()
        $recoveryClientIdentity=Assert-RequestClientImage $requestClient
        if($requestClient.process.ExitCode -ne 0 -or
            (Get-Item -LiteralPath $requestClient.response).Length -gt 4MB) {
            throw ('Registered recovery client failed: '+[IO.File]::ReadAllText($requestClient.error))
        }
        $recoveredResult=Read-ClientObservation $requestClient
        $recovered=$recoveredResult.service
        if($recovered.status -ne 'pass' -or
            $recovered.recovery_observation.decision -ne 'already_visible_bound' -or
            $recovered.install_operation_guard_held -ne $true -or
            $recovered.install_operation_guard_abandoned -ne $false -or
            $recovered.recovery_installed_response.status -ne 'ok' -or
            $recovered.recovery_installed_response.payload.transaction_id -ne $applyRequest.transaction_id -or
            (Test-Path -LiteralPath $nativePath)) {
            throw 'Registered source-free recovery did not preserve the bound installed result'
        }
        if($ReuseRegistration -and
            (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
            throw 'Registered publisher command changed during source-free recovery'
        }
        $receipt['registered_source_free_reentry']=[ordered]@{
            status=$recovered.status;decision=$recovered.recovery_observation.decision;
            one_shot_status=$(if($recoveredResult.envelope){$recoveredResult.envelope.status}else{$null});
            request_schema=$submittedRecovery.schema;
            client_exit_code=$requestClient.process.ExitCode;
            client_mode=$requestClient.client_mode;
            client_binary_sha256=$requestClient.binary_sha256;
            client_observation=$recoveryClientIdentity;
            response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $repeat=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($repeat.independent.identity -ne 'S-1-5-18' -or -not $repeat.observer_task_removed -or
            ($receipt.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($repeat.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Registered source-free reentry changed independently observed installed rows'
        }
        $receipt.registered_source_free_reentry['unchanged_independent_rows']=@($repeat.independent.rows).Count
        $staleRecovery=[ordered]@{
            schema='usk.publisher_recovery_request.v1'
            request_id='recover.stale.'+$id
            install_id=$recoveryRequest.install_id
            transaction_id=$recoveryRequest.transaction_id+'.changed'
        }
        if($ControllerApply){$script:controllerPending=$true}
        Start-RegisteredPublisher
        $requestClient=Start-RequestClient $staleRecovery
        if(-not $requestClient.process.WaitForExit(120000)) {
            throw 'Stale recovery client timed out'
        }
        $requestClient.process.WaitForExit()
        $staleClientIdentity=Assert-RequestClientImage $requestClient
        $staleResult=Read-ClientObservation $requestClient
        $stale=$staleResult.service
        if($requestClient.process.ExitCode -eq 0 -or $stale.status -ne 'failed' -or
            $stale.error -cne 'reviewed install reentry differs from durable plan and source') {
            throw 'Changed minimal recovery request was admitted'
        }
        $receipt['stale_minimal_recovery_refused']=[ordered]@{
            status=$stale.status;client_mode=$requestClient.client_mode;
            one_shot_status=$(if($staleResult.envelope){$staleResult.envelope.status}else{$null});
            client_binary_sha256=$requestClient.binary_sha256;
            client_observation=$staleClientIdentity;
            response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $afterStale=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($afterStale.independent.identity -ne 'S-1-5-18' -or -not $afterStale.observer_task_removed -or
            ($repeat.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($afterStale.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Changed minimal recovery request altered installed state'
        }
    }
    if($RegisteredService -and -not $InterruptAfterStage) {
        # The ordinary packaged client asks the restricted service to verify
        # the completed installation. The caller receives no private-state ACL.
        $verifyRequest=[ordered]@{schema='usk.publisher_installed_verify_request.v1';
            request_id='verify.'+$id;install_id=$applyRequest.plan_request.install_id;
            transaction_id=$applyRequest.transaction_id;report_id='verify.'+$id;
            verified_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
        if($ControllerApply) {
            $script:controllerMode='verify'
            $script:controllerPending=$true
        } elseif($ReuseRegistration) {
            if((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
                throw 'Registered publisher command changed before bound verification'
            }
            $receipt['verification_without_reconfiguration']=$true
        } else {
            $verifyArgs=@('--verify',$service,$ServiceBinary,$VolumeRoot,$callerSid)
            if($registeredMode){$verifyArgs+=$registeredMode}
            $configuredVerify=& $ServiceControlBinary @verifyArgs
            if($LASTEXITCODE -ne 0 -or ($configuredVerify|ConvertFrom-Json).status -ne 'verify_configured') {
                throw 'Product service control did not configure read-only verification'
            }
        }
        Start-RegisteredPublisher
        $requestClient=Start-RequestClient $verifyRequest
        $verifyClient=$requestClient
        if(-not $verifyClient.process.WaitForExit(120000)){throw 'Registered verification client timed out'}
        $verifyClient.process.WaitForExit()
        $requestClient=$null
        if($verifyClient.process.ExitCode -ne 0 -or
            (Get-Item -LiteralPath $verifyClient.response).Length -gt 4MB) {
            throw ('Registered verification client failed: '+[IO.File]::ReadAllText($verifyClient.error))
        }
        $verifiedResult=Read-ClientObservation $verifyClient
        $verified=$verifiedResult.service
        if($verified.status -ne 'pass' -or $verified.transaction_id -cne $applyRequest.transaction_id -or
            $verified.verify_response.status -ne 'ok' -or
            $verified.verify_response.payload.status -ne 'pass' -or
            $verified.verify_response.payload.install_id -cne $verifyRequest.install_id -or
            $verified.verify_response.payload.report_id -cne $verifyRequest.report_id -or
            $verified.bound_report_digest -cne $verified.verify_response.payload.report_digest -or
            (Test-Path -LiteralPath $nativePath)) {
            throw 'Authenticated read-only verification differs from completed installation'
        }
        if($ReuseRegistration -and
            (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
            throw 'Registered publisher command changed during read-only verification'
        }
        $receipt['registered_installed_verify']=[ordered]@{status=$verified.status;
            one_shot_status=$(if($verifiedResult.envelope){$verifiedResult.envelope.status}else{$null});
            report_digest=$verified.verify_response.payload.report_digest;
            bound_report_digest=$verified.bound_report_digest;
            client_exit_code=$verifyClient.process.ExitCode;
            client_mode=$verifyClient.client_mode;
            response_sha256=(Get-FileHash -LiteralPath $verifyClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
        $staleVerify=[ordered]@{}
        foreach($key in $verifyRequest.Keys){$staleVerify[$key]=$verifyRequest[$key]}
        $staleVerify.transaction_id='install.'+[guid]::NewGuid().ToString('N')
        if($ControllerApply){$script:controllerPending=$true}
        Start-RegisteredPublisher
        $requestClient=Start-RequestClient $staleVerify
        $staleClient=$requestClient
        if(-not $staleClient.process.WaitForExit(120000)){throw 'Stale verification client timed out'}
        $staleClient.process.WaitForExit()
        $requestClient=$null
        $staleVerifyResult=Read-ClientObservation $staleClient
        $staleResponse=$staleVerifyResult.service
        if($staleClient.process.ExitCode -eq 0 -or $staleResponse.status -ne 'failed' -or
            $staleResponse.error -notmatch 'differs from completed install') {
            throw 'Stale authenticated verification request was not refused'
        }
        $receipt.registered_installed_verify['stale_transaction_refused']=$true
        if($staleVerifyResult.envelope) {
            $receipt.registered_installed_verify['stale_one_shot_status']=$staleVerifyResult.envelope.status
        }
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
        $verifyRows=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($verifyRows.independent.identity -ne 'S-1-5-18' -or -not $verifyRows.observer_task_removed -or
            ($receipt.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($verifyRows.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Read-only verification changed independently observed installed rows'
        }
        $receipt.registered_installed_verify['unchanged_independent_rows']=@($verifyRows.independent.rows).Count
        if(-not $HostileRights) {
            $damageEntries=@($plan.planned_entries|Where-Object {
                $_.entry_type -ceq 'file' -and $_.relative_path -ceq $(
                    if($ConsumerAccess -or $ProductionConcurrentRights){'bin/addon.bin'}else{'bin/core.bin'})
            })
            if($damageEntries.Count -ne 1){throw 'Selected owned damage file is absent from reviewed plan'}
            Assert-OwnedVolume
            $damaged=Invoke-IndependentOwnedPayloadDamage -VhdPath $vhd -VolumeRoot $VolumeRoot `
                -DriveRoot $drive -VisibleRoot $visibleRoot -PayloadRelativePath $damageEntries[0].relative_path `
                -ExpectedSha256 $damageEntries[0].sha256
            $damageVerify=[ordered]@{}
            foreach($key in $verifyRequest.Keys){$damageVerify[$key]=$verifyRequest[$key]}
            $damageVerify.request_id='verify.damaged.'+$id
            $damageVerify.report_id='verify.damaged.'+$id
            if($ControllerApply){$script:controllerPending=$true}
            Start-RegisteredPublisher
            $requestClient=Start-RequestClient $damageVerify
            $damageClient=$requestClient
            if(-not $damageClient.process.WaitForExit(120000)){throw 'Damaged verification client timed out'}
            $damageClient.process.WaitForExit()
            $requestClient=$null
            if((Get-Item -LiteralPath $damageClient.response).Length -gt 4MB){
                throw 'Damaged verification response exceeds client budget'
            }
            $damageResult=Read-ClientObservation $damageClient
            $damageResponse=$damageResult.service
            $damagedFiles=@($damageResponse.verify_response.payload.files|Where-Object {
                $_.relative_path -ceq $damageEntries[0].relative_path
            })
            $expectedDamageExit=if($damageClient.client_mode -eq 'machine-one-shot'){0}else{3}
            if($damageClient.process.ExitCode -ne $expectedDamageExit -or
                $damageResponse.status -cne 'failed' -or
                $damageResponse.transaction_id -cne $applyRequest.transaction_id -or
                $damageResponse.verify_response.status -cne 'ok' -or
                $damageResponse.verify_response.payload.status -cne 'fail' -or
                $damageResponse.verify_response.payload.install_id -cne $verifyRequest.install_id -or
                $damageResponse.verify_response.payload.report_id -cne $damageVerify.report_id -or
                $damageResponse.bound_report_digest -cne $damageResponse.verify_response.payload.report_digest -or
                $damageResponse.verify_response.payload.summary.modified_files -ne 1 -or
                $damageResponse.verify_response.payload.summary.missing_files -ne 0 -or
                $damageResponse.verify_response.payload.summary.unknown_paths -ne 0 -or
                $damagedFiles.Count -ne 1 -or $damagedFiles[0].status -cne 'modified' -or
                $damagedFiles[0].expected_sha256 -cne $damaged.before_sha256 -or
                $damagedFiles[0].actual_sha256 -cne $damaged.after_sha256) {
                throw ('Authenticated damaged-file verification did not report exact drift: '+
                    [IO.File]::ReadAllText($damageClient.error))
            }
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
            $damageRows=Invoke-IndependentMetadataReadback -DriveRoot $drive `
                -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
            $beforeFile=@($verifyRows.independent.rows|Where-Object path -ceq $damaged.path)
            $afterFile=@($damageRows.independent.rows|Where-Object path -ceq $damaged.path)
            $otherBefore=@($verifyRows.independent.rows|Where-Object path -cne $damaged.path)
            $otherAfter=@($damageRows.independent.rows|Where-Object path -cne $damaged.path)
            if($damageRows.independent.identity -cne 'S-1-5-18' -or
                -not $damageRows.observer_task_removed -or $beforeFile.Count -ne 1 -or
                $afterFile.Count -ne 1 -or $beforeFile[0].sha256 -cne $damaged.before_sha256 -or
                $afterFile[0].sha256 -cne $damaged.after_sha256 -or
                $afterFile[0].bytes -ne $beforeFile[0].bytes -or
                ($beforeFile[0].aces|ConvertTo-Json -Depth 8 -Compress) -cne
                    ($afterFile[0].aces|ConvertTo-Json -Depth 8 -Compress) -or
                $beforeFile[0].owner -cne $afterFile[0].owner -or
                $beforeFile[0].protected -ne $afterFile[0].protected -or
                ($otherBefore|ConvertTo-Json -Depth 32 -Compress) -cne
                    ($otherAfter|ConvertTo-Json -Depth 32 -Compress)) {
                throw 'Damaged verification changed protected metadata or another installed object'
            }
            $receipt.registered_installed_verify['damaged_owned_file']=[ordered]@{
                path=$damageEntries[0].relative_path;before_sha256=$damaged.before_sha256;
                after_sha256=$damaged.after_sha256;report_digest=$damageResponse.verify_response.payload.report_digest;
                bound_report_digest=$damageResponse.bound_report_digest;
                status=$damageResponse.verify_response.payload.status;
                one_shot_status=$(if($damageResult.envelope){$damageResult.envelope.status}else{$null});
                unchanged_other_rows=$otherAfter.Count;client_exit_code=$damageClient.process.ExitCode}
        }
    }
    if($HostileRights -or $ProductionPostpublishRights) {
        $attackOutput=Join-Path (Split-Path -Parent $vhd) 'unprivileged-attack.json'
        $attackIdentity=if($RegisteredService -and $NonAdminClient){
            @{ExistingCredential=$consumerCredential;ExistingSid=$consumerSid}
        }else{@{}}
        & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid -OutputPath $attackOutput -Stage Postpublish -PayloadRelativePath $attackRelative -VisibleLeaf $visibleLeaf @attackIdentity
        $attack=Get-Content -LiteralPath $attackOutput -Raw|ConvertFrom-Json
        $attackReceiptKey=if($ProductionPostpublishRights){'production_postpublish_hostile_rights'}else{'postpublish_hostile_rights'}
        $receipt[$attackReceiptKey]=$attack
        if($attack.status -ne 'unprivileged_access_denied_observed' -or
            $attack.payload_relative_path -cne $attackRelative -or
            $attack.observation.visible_leaf -cne $visibleLeaf){
            throw 'Selected postpublish attacker result differs'
        }
        if($RegisteredService -and ($attack.account_sid -cne $consumerSid -or
            $attack.account_origin -cne 'existing_owned_client')) {
            throw 'Registered postpublish attacker did not use the submitting client identity'
        }
        $afterAttack=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['postpublish_after_attack']=$afterAttack.independent
        # The production run intentionally damages addon.bin for its later
        # verification probe. Compare the hostile attempt against that exact
        # independently observed state, not the earlier intact install.
        $beforeAttackRows=if($ProductionPostpublishRights){$damageRows.independent.rows}else{$receipt.independent.rows}
        if($afterAttack.independent.identity -ne 'S-1-5-18' -or -not $afterAttack.observer_task_removed -or
            (-not $beforeAttackRows) -or
            ($beforeAttackRows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($afterAttack.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Selected postpublish hostile attempts changed published state'
        }
        if($ProductionPostpublishRights) {
            # The submitting login and a second local login are distinct
            # adversaries in the admitted profile. Reuse the same installed
            # volume and binary; the runner owns and removes only its account.
            $unrelatedOutput=Join-Path (Split-Path -Parent $vhd) 'unprivileged-unrelated.json'
            & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') `
                -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid `
                -OutputPath $unrelatedOutput -Stage Postpublish `
                -PayloadRelativePath $attackRelative -VisibleLeaf $visibleLeaf `
                -UnrelatedProductionAccount
            $unrelated=Get-Content -LiteralPath $unrelatedOutput -Raw|ConvertFrom-Json
            $receipt['production_unrelated_postpublish_hostile_rights']=$unrelated
            if($unrelated.status -cne 'unprivileged_access_denied_observed' -or
                $unrelated.account_origin -cne 'created_attacker' -or
                $unrelated.account_sid -ceq $consumerSid -or
                $unrelated.observation.visible_leaf -cne $visibleLeaf -or
                $unrelated.observation.payload_relative_path -cne $attackRelative -or
                $unrelated.cleanup -notmatch 'generated local account deleted') {
                throw 'Unrelated postpublish attacker or owned cleanup differs'
            }
            $afterUnrelated=Invoke-IndependentMetadataReadback -DriveRoot $drive `
                -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
            $receipt['postpublish_after_unrelated_attack']=$afterUnrelated.independent
            if($afterUnrelated.independent.identity -cne 'S-1-5-18' -or
                -not $afterUnrelated.observer_task_removed -or
                ($afterAttack.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
                ($afterUnrelated.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
                throw 'Unrelated postpublish hostile attempts changed published state'
            }
        }
    }
    if($recover -and -not $RegisteredService) {
        foreach($row in $before.independent.rows) {
            $completedPath=$row.path
            $stagedRoot=$drive+'publication\staging\candidate'
            if(($InterruptBeforePublish -or $InterruptAfterStage -or $ProductionPreparedTermination) -and ($row.path -ceq $stagedRoot -or $row.path.StartsWith($stagedRoot+'\',[StringComparison]::Ordinal))) {
                $completedPath=$visibleRoot+$row.path.Substring($stagedRoot.Length)
            }
            $matching=@($receipt.independent.rows|Where-Object path -ceq $completedPath)
            if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or $matching[0].bytes -ne $row.bytes) {
                throw 'Recovery changed independently observed published payload or durable intent'
            }
        }
        # Re-enter the same source-free recovery operation. No published record
        # or public installed/audit record may change or acquire a duplicate.
        $repeatPath=Join-Path $root ('vm-recovery-repeat-'+$id+'.json')
        $repeatCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$repeatPath+'" '+$VolumeRoot+
            ' --recover-visible-bound --campaign-vm-id '+$vmId
        if($ClientBinary) {
            $repeatPath=Join-Path $root ('vm-recovery-reviewed-repeat-'+$id+'.json')
            $repeatCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$repeatPath+'" '+$VolumeRoot+
                ' --recover-reviewed --campaign-vm-id '+$vmId+$clientArguments
        }
        & sc.exe config $service binPath= $repeatCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned service repeat configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        if($ClientBinary){$requestClient=Start-RequestClient}
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $repeatPath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $repeatPath)){throw 'Repeated recovery receipt absent'}
        $repeat=Read-NativeReceipt $repeatPath
        if($requestClient) {
            $nativePath=$repeatPath
            $receipt['authenticated_client_repeat']=Complete-RequestClient $requestClient $true
            $requestClient=$null
        }
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        if($repeat.status -ne 'pass' -or $repeat.recovery_observation.decision -ne 'already_visible_bound' -or
            $repeat.recovery_installed_response.payload.transaction_id -ne $applyRequest.transaction_id -or
            $repeat.recovery_installed_response.payload.last_verification.status -ne 'pass') {
            throw 'Repeated source-free recovery did not preserve completed caller state'
        }
        $after=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $repeatResult=[pscustomobject]@{volume_drive_root=$drive;native=$repeat;service_sid=$sid;independent=$after.independent;
            observer_task_removed=$after.observer_task_removed;plan=$plan;archive_sha256=$inputs.archive_sha256;
            apply_request=$applyRequest;request=$request.payload;consumer_sid=$consumerSid}
        $repeatResult|Add-Member -NotePropertyName consumer_sid -NotePropertyValue $consumerSid -Force
        Assert-IndependentMetadataProbe $repeatResult
        if($after.independent.rows.Count -ne $receipt.independent.rows.Count){throw 'Repeated recovery changed record closure'}
        foreach($row in $receipt.independent.rows) {
            $matching=@($after.independent.rows|Where-Object path -ceq $row.path)
            if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or $matching[0].bytes -ne $row.bytes) {
                throw 'Repeated recovery changed a completed record or payload'
            }
        }
        if($ReviewedSource) {
            # Reissue the original source-derived service command after both
            # input files were removed. Its durable request must select the
            # same completed generation without reopening those paths.
            $reentryPath=Join-Path $root ('vm-selected-reconnect-'+$id+'.json')
            $reentryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$reentryPath+'" '+$VolumeRoot+
                $selectedClientArguments+$clientArguments
            & sc.exe config $service binPath= $reentryCommand|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Reviewed source reentry configuration failed'}
            try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
            $nativePath=$reentryPath
            $requestClient=Start-RequestClient
            $receipt['reviewed_source_reentry_client']=Complete-RequestClient $requestClient $true
            $requestClient=$null
            $reentry=Read-NativeReceipt $reentryPath
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
            if($reentry.status -ne 'pass' -or
                $reentry.recovery_observation.decision -ne 'already_visible_bound' -or
                $reentry.recovery_installed_response.payload.transaction_id -ne $applyRequest.transaction_id) {
                throw 'Source-derived command did not reenter completed durable request'
            }
            $reentryReadback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
            if($after.independent.rows.Count -ne $reentryReadback.independent.rows.Count -or
                -not $reentryReadback.observer_task_removed) {
                throw 'Source-derived reentry changed completed record count or observer state'
            }
            foreach($row in $after.independent.rows) {
                $matching=@($reentryReadback.independent.rows|Where-Object path -ceq $row.path)
                if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or
                    $matching[0].bytes -ne $row.bytes -or
                    ($matching[0].aces|ConvertTo-Json -Depth 10 -Compress) -cne
                    ($row.aces|ConvertTo-Json -Depth 10 -Compress)) {
                    throw 'Source-derived reentry changed completed protected or public state'
                }
            }
            $receipt['reviewed_source_reentry']=[ordered]@{native=$reentry;unchanged_rows=$reentryReadback.independent.rows.Count;
                observer_task_removed=$reentryReadback.observer_task_removed}
        }
        $receipt['source_free_recovery']=[ordered]@{action=$recoveryDecision;repeat=$repeat;
            independent_repeat=$after.independent;repeat_observer_task_removed=$after.observer_task_removed;
            unchanged_row_count=$after.independent.rows.Count}
    }
    if($recover -and $ClientBinary -and -not $RegisteredService) {
        # A genuine authenticated peer cannot change the durable request merely
        # by reusing this endpoint after successful recovery.
        $tampered=$applyRequest|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json
        $tampered.transaction_id='install.'+[guid]::NewGuid().ToString('N')
        $stalePath=Join-Path $root ('vm-recovery-reviewed-stale-'+$id+'.json')
        $staleCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$stalePath+'" '+$VolumeRoot+
            ' --recover-reviewed --campaign-vm-id '+$vmId+$clientArguments
        & sc.exe config $service binPath= $staleCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned stale-client service configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        $requestClient=Start-RequestClient $tampered
        $nativePath=$stalePath
        $receipt['stale_authenticated_client']=Complete-RequestClient $requestClient $false $true
        $requestClient=$null
        $stale=Read-NativeReceipt $stalePath
        if($stale.status -ne 'failed' -or $stale.error -cne 'reviewed install reentry differs from durable plan and source') {
            throw 'Stale authenticated request was not refused by durable binding'
        }
        $unchanged=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) `
            -RunId ([guid]::NewGuid().ToString('N'))
        if(($after.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($unchanged.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Stale authenticated request changed retained installation records'
        }
        $receipt['stale_authenticated_request_unchanged_rows']=$unchanged.independent.rows.Count
        $receipt['stale_observer_task_removed']=$unchanged.observer_task_removed
    }
    if($ConsumerAccess) {
        # The registered path has already damaged only the non-executable
        # addon and independently recorded that new state. Keep the neutral
        # executable intact for the non-admin execution check.
        $accessBaseline=if($RegisteredService){$damageRows.independent.rows}elseif($recover){$after.independent.rows}else{$receipt.independent.rows}
        $identityPath=Join-Path $consumerOutput 'payload-identity.json'
        $accessPath=Join-Path $consumerOutput 'payload-access.json'
        $accessError=Join-Path $consumerOutput 'payload-access-error.txt'
        $accessStdout=Join-Path $consumerOutput 'payload-access-output.txt'
        $consumerProcess=Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList @(
            '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$consumerScript,
            '-ExpectedUserSid',$consumerSid,'-IdentityPath',$identityPath,
            '-PayloadRoot',$visibleRoot,'-AccessReceipt',$accessPath) -Credential $consumerCredential -PassThru -WindowStyle Hidden -WorkingDirectory $consumerOutput `
            -RedirectStandardError $accessError -RedirectStandardOutput $accessStdout
        if(-not $consumerProcess.WaitForExit(45000)){Stop-OwnedPublisherProcessTree $consumerProcess|Out-Null;throw 'Consumer payload probe timed out'}
        $consumerProcess.WaitForExit()
        if($consumerProcess.ExitCode -ne 0){
            throw ('Non-admin payload access probe failed: '+
                (Read-BoundedDiagnostic $accessError 2048))
        }
        $access=Get-Content -LiteralPath $accessPath -Raw|ConvertFrom-Json
        if($access.status -ne 'pass' -or $access.identity.user_sid -cne $consumerSid -or $access.identity.administrator){throw 'Consumer access identity/result differs'}
        foreach($file in $access.files) {
            $row=@($accessBaseline|Where-Object path -ceq $file.path)
            if($row.Count -ne 1 -or $row[0].sha256 -cne $file.sha256){throw 'Consumer-read bytes differ from independent SYSTEM readback'}
        }
        $receipt['consumer_access_observation']=$access
        $afterAccess=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if(($accessBaseline|ConvertTo-Json -Depth 32 -Compress) -cne ($afterAccess.independent.rows|ConvertTo-Json -Depth 32 -Compress)){throw 'Consumer access attempts changed installed bytes/ACLs'}
        $receipt['consumer_attempts_unchanged_rows']=$afterAccess.independent.rows
        $receipt['consumer_attempts_observer_removed']=$afterAccess.observer_task_removed
    }
    if($ReviewedSource) {
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
        if((Get-Service $service).Status -ne 'Stopped') { throw 'Reviewed service remains active during root ACL observation' }
        $receipt['root_acl_after_service']=Get-OwnedVolumeRootSddl 'service-end'
        if($receipt.root_acl_at_service_start -cne $receipt.root_acl_after_service) {
            throw 'Reviewed-source service changed the preprotected volume root ACL'
        }
    }
    $receipt.status='protected_metadata_observed'
    }
} catch {
    $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'
} finally {
    if($requestClient) {
        try { Stop-OwnedPublisherProcessTree $requestClient.process|Out-Null }
        catch { $clientCleanupConfirmed=$false;$failure='Owned client cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($consumerProcess) {
        try {Stop-OwnedPublisherProcessTree $consumerProcess|Out-Null}
        catch {$clientCleanupConfirmed=$false;$failure='Consumer payload process cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($concurrentAttacker) {
        try {Stop-OwnedPublisherProcessTree $concurrentAttacker|Out-Null}
        catch {$clientCleanupConfirmed=$false;$failure='Concurrent attacker cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($unrelatedAttacker) {
        try {Stop-OwnedPublisherProcessTree $unrelatedAttacker|Out-Null}
        catch {$clientCleanupConfirmed=$false;$failure='Unrelated attacker cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($preopenedRootProcess) {
        try {Stop-OwnedPublisherProcessTree $preopenedRootProcess|Out-Null}
        catch {$clientCleanupConfirmed=$false;$failure='Preopened-root attacker cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($stageObserver -and -not $stageObserver.removed) {
        try {
            $task=Get-ScheduledTask -TaskName $stageObserver.task -ErrorAction SilentlyContinue
            if($task) {
                if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $stageObserver.task -ErrorAction Stop}
                Unregister-ScheduledTask -TaskName $stageObserver.task -Confirm:$false -ErrorAction Stop
            }
            if(Get-ScheduledTask -TaskName $stageObserver.task -ErrorAction SilentlyContinue) {
                throw 'Owned stage observer task remains registered'
            }
            $stageObserver.removed=$true
        } catch {$failure='Owned stage observer cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($postrenameObserver -and -not $postrenameObserver.removed) {
        try {
            $task=Get-ScheduledTask -TaskName $postrenameObserver.task -ErrorAction SilentlyContinue
            if($task) {
                if($task.State -eq 'Running'){
                    Stop-ScheduledTask -TaskName $postrenameObserver.task -ErrorAction Stop
                }
                Unregister-ScheduledTask -TaskName $postrenameObserver.task -Confirm:$false -ErrorAction Stop
            }
            if(Get-ScheduledTask -TaskName $postrenameObserver.task -ErrorAction SilentlyContinue) {
                throw 'Owned production rename observer task remains registered'
            }
            $postrenameObserver.removed=$true
        } catch {
            $failure='Owned production rename observer cleanup failed: '+$_.Exception.Message
            $receipt.failure=$failure;$receipt.status='failed'
        }
    }
    $receipt['client_cleanup_confirmed']=$clientCleanupConfirmed
    if($consumerCreated -and $clientCleanupConfirmed) {
        try {Remove-LocalUser -Name $consumerName -ErrorAction Stop;$receipt['consumer_account_removed']=$true}
        catch {$failure='Owned consumer account cleanup failed';$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($consumerCreated -and -not $clientCleanupConfirmed){$receipt['consumer_account_retained']=$consumerName}
    $consumerCredential=$null
    if($unrelatedAccountCreated -and $clientCleanupConfirmed) {
        try {
            Remove-LocalUser -Name $unrelatedAccountName -ErrorAction Stop
            if(Get-LocalUser -Name $unrelatedAccountName -ErrorAction SilentlyContinue) {
                throw 'Unrelated attacker account remains after deletion'
            }
            $receipt['unrelated_concurrent_account_removed']=$true
        } catch {
            $failure='Unrelated attacker account cleanup failed: '+$_.Exception.Message
            $receipt.failure=$failure;$receipt.status='failed'
        }
    }
    if($unrelatedAccountCreated -and -not $clientCleanupConfirmed) {
        $receipt['unrelated_concurrent_account_retained']=$unrelatedAccountName
        $receipt.status='failed'
    }
    $unrelatedCredential=$null
    if($registrationAttempted -and -not $created) {
        try {
            $pendingService=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
            if($pendingService) {
                if($pendingService.PathName -cne $expectedRegisteredCommand) {
                    throw 'Failed registration left a service with an unexpected command; retain for inspection'
                }
                $created=$true
            }
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($created) {
        try {
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
            if($ProductionConcurrentRights -and $receipt.status -eq 'protected_metadata_observed') {
                $held=[IO.File]::Open($controlLock,[IO.FileMode]::Open,
                    [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                try {
                    $blockedRemove=@('--unregister',$service,$ServiceBinary,$VolumeRoot,$callerSid)
                    if($registeredMode){$blockedRemove+=$registeredMode}
                    & $ServiceControlBinary @blockedRemove 2>$null|Out-Null
                    if($LASTEXITCODE -eq 0 -or
                        -not (Get-Service $service -ErrorAction SilentlyContinue)) {
                        throw 'Publisher service unregister bypassed held control lock'
                    }
                } finally { $held.Dispose() }
                $receipt['service_control_lock_unregister_refusal']=$true
                $wrongRemove=@('--unregister',$service,$ServiceBinary,$VolumeRoot,'S-1-5-18')
                if($registeredMode){$wrongRemove+=$registeredMode}
                & $ServiceControlBinary @wrongRemove 2>$null|Out-Null
                if($LASTEXITCODE -eq 0 -or -not (Get-Service $service -ErrorAction SilentlyContinue)) {
                    throw 'Publisher service accepted a different unregister caller'
                }
                & $ServiceControlBinary --retire-binary $service $installedServiceBinary $sourceServiceHash $sid 2>$null|Out-Null
                if($LASTEXITCODE -eq 0 -or
                    -not (Test-Path -LiteralPath $installedServiceBinary -PathType Leaf)) {
                    throw 'Publisher service binary retired while its service was registered'
                }
                $receipt['service_binary_live_retirement_refusal']=$true
                $remove=@('--unregister',$service,$ServiceBinary,$VolumeRoot,$callerSid)
                if($registeredMode){$remove+=$registeredMode}
                $removed=& $ServiceControlBinary @remove
                if($LASTEXITCODE -ne 0 -or
                    ($removed|ConvertFrom-Json).status -cne 'removal_requested') {
                    throw 'Owned product service unregister failed'
                }
                $receipt['product_service_unregister']=$removed|ConvertFrom-Json
            }else{
                & sc.exe delete $service|Out-Null
                if($LASTEXITCODE -ne 0){throw 'Owned service deletion failed'}
            }
            $removeDeadline=[DateTime]::UtcNow.AddSeconds(15)
            while((Get-Service $service -ErrorAction SilentlyContinue) -and
                [DateTime]::UtcNow -lt $removeDeadline){Start-Sleep -Milliseconds 100}
            if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Owned service remains after deletion'}
            $receipt.service_removed=$true
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($RegisteredService -and $installedServiceBinary -and
        -not (Get-Service $service -ErrorAction SilentlyContinue) -and
        (Test-Path -LiteralPath $installedServiceBinary -PathType Leaf)) {
        try {
            $expectedInstalled=Join-Path $env:ProgramW6432 `
                ('Universal Setup\Publisher\'+$service+'.exe')
            if($installedServiceBinary -cne $expectedInstalled -or
                (Get-FileHash -LiteralPath $installedServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                    $sourceServiceHash){throw 'Protected service cleanup identity differs'}
            $wrongDigest=if($sourceServiceHash -cne ('0'*64)){'0'*64}else{'1'*64}
            & $ServiceControlBinary --retire-binary $service $installedServiceBinary $wrongDigest $sid 2>$null|Out-Null
            if($LASTEXITCODE -eq 0 -or
                -not (Test-Path -LiteralPath $installedServiceBinary -PathType Leaf)) {
                throw 'Protected service retirement accepted an incorrect digest'
            }
            $wrongSid='S-1-5-80-1-2-3-4-5'
            if($wrongSid -ceq $sid){$wrongSid='S-1-5-80-5-4-3-2-1'}
            & $ServiceControlBinary --retire-binary $service $installedServiceBinary $sourceServiceHash $wrongSid 2>$null|Out-Null
            if($LASTEXITCODE -eq 0 -or
                -not (Test-Path -LiteralPath $installedServiceBinary -PathType Leaf)) {
                throw 'Protected service retirement accepted a different service SID'
            }
            $retired=& $ServiceControlBinary --retire-binary $service $installedServiceBinary $sourceServiceHash $sid
            if($LASTEXITCODE -ne 0 -or
                ($retired|ConvertFrom-Json).status -cne 'binary_retired' -or
                (Test-Path -LiteralPath $installedServiceBinary)) {
                throw 'Product control did not retire its protected service binary'
            }
            $receipt['product_service_binary_retirement']=$retired|ConvertFrom-Json
            $receipt['protected_service_binary_removed']=$true
        } catch {
            $failure='Protected service binary cleanup failed: '+$_.Exception.Message
            $receipt.failure=$failure;$receipt.status='failed'
            # Keep uncertain material for the disposable runner's teardown.
            # A second cleanup failure must not suppress this receipt.
            $receipt['protected_service_binary_retained_on_failure']=
                [bool](Test-Path -LiteralPath $installedServiceBinary -ErrorAction SilentlyContinue)
        }
    }
    if($receipt.status -in @('protected_metadata_observed','preprotected_boundary_refusal_observed',
        'preexisting_anchor_recovery_required_observed') -and $receipt.service_removed) {
        try {
            if([IO.Path]::GetFullPath($root) -cne 'C:\USK-Lab'){throw 'Owned hosted cleanup root differs'}
            $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($root)
            while($pending.Count) {
                $directory=$pending.Dequeue();$item=Get-Item -LiteralPath $directory -Force
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Hosted cleanup root contains a link'}
                foreach($child in Get-ChildItem -LiteralPath $directory -Force) {
                    if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Hosted cleanup input contains a link'}
                    if($child.PSIsContainer){$pending.Enqueue($child.FullName)}
                }
            }
            Remove-Item -LiteralPath $root -Recurse -Force
            if(Test-Path -LiteralPath $root){throw 'Owned hosted input cleanup did not complete'}
            $receipt['owned_input_root_removed']=$true
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    $receipt['observed_utc']=[DateTime]::UtcNow.ToString('o')
    if(Test-Path -LiteralPath $observerRoot){
        try {
            if($stageObserver -and $stageObserver.removed) {
                foreach($path in @($stageObserver.script,$stageObserver.ready,$stageObserver.stop,$stageObserver.output)) {
                    if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force -ErrorAction Stop}
                }
            }
            if($ProductionPostrenameTermination -or $ProductionPreparedTermination) {
                if(Get-ScheduledTask -TaskName ('USK_RENAME_OBSERVER_'+$id) -ErrorAction SilentlyContinue) {
                    throw 'Production rename observer task remains registered; retain its inputs'
                }
                foreach($leaf in @('production-rename-observer.ps1','owned-process.ps1',
                    'production-rename-config.json','production-rename-ready.txt',
                    'production-rename-observation.json','production-rename-observation.json.tmp')) {
                    $path=Join-Path $observerRoot $leaf
                    if(Test-Path -LiteralPath $path) {
                        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                            -not [string]::Equals((Split-Path -Parent $item.FullName),$observerRoot,
                                [StringComparison]::OrdinalIgnoreCase)) {
                            throw 'Production rename observer cleanup target differs'
                        }
                        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                    }
                }
            }
            Remove-Item -LiteralPath $observerRoot -ErrorAction Stop
        }
        catch { $failure='Owned root ACL observer directory cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    $receipt|ConvertTo-Json -Depth 32|Set-Content -LiteralPath $out -Encoding UTF8
    # The existing outer harness dismounts/deletes only its identified VHD.
    # This entire hosted VM is disposable; no workstation resources are used.
}
if($failure){throw $failure}
Write-Output "Protected selected metadata observed: $out"
