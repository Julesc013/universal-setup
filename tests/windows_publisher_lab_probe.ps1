param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$ServiceBinary = '',
    [string]$ServiceControlBinary = '',
    [string]$DeviceAclBinary = '',
    [string]$MachineBinary = '',
    [string]$PublicApplyBinary = '',
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
    [switch]$PublicInstallation,
    [switch]$PublicStandardClient,
    [switch]$PublicStandardBootstrapLoss,
    [switch]$PublicStandardBootstrapPreservationLoss,
    [ValidateSet('none','prepublish','postrename')][string]$PublicPublicationLoss='none',
    [ValidateSet('none','payload_changed','metadata_collision')][string]$PublicPostRenameRefusal='none',
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

$ErrorActionPreference = 'Stop'
$standardLauncherClosed=$false
if(($PublicStandardBootstrapLoss -or $PublicStandardBootstrapPreservationLoss) -and -not $PublicStandardClient) {throw 'Registered bootstrap loss requires the owned standard fixture'}
if($PublicStandardClient -and (-not $PublicInstallation -or $PublicPublicationLoss -cne 'none' -or $PublicPostRenameRefusal -cne 'none')) {
    throw 'Standard public fixture requires its separate ordinary public installation lab'
}
if($PublicPublicationLoss -cne 'none' -and -not $PublicInstallation) {
    throw 'Ordinary public boundary loss requires the public installation probe'
}
if($PublicPostRenameRefusal -cne 'none' -and (-not $PublicInstallation -or $PublicPublicationLoss -cne 'postrename')) {
    throw 'Public retained refusal requires the ordinary postrename loss fixture'
}
if($HostilePostrename) {
    if($HostileRights){throw 'Select one hostile-rights phase'}
    $HostileRights=$true
}
if ($HostileRights -and (-not $MachineBinary -or -not $ClientBinary -or
    $InterruptDuringConsumerAccess -or $InterruptAfterVisibleRecord -or
    $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage)) {
    throw 'Selected hostile-rights probe requires an uninterrupted reviewed client operation'
}

if($TerminateAtPoststage -and (-not $InterruptAfterStage -or -not $RegisteredService -or -not $ReviewedSource -or -not $ClientBinary -or $MachineRequestClient -or $ConsumerAccess -or $NonAdminClient)) {
    throw 'Transport-loss probe requires the registered reviewed publisher client and poststage gate'
}
if($TerminateAtPostrename -and (-not $InterruptAfterRename -or -not $RegisteredService -or -not $ReviewedSource -or -not $ClientBinary -or $MachineRequestClient -or $ConsumerAccess -or $NonAdminClient)) {
    throw 'Rename-boundary transport-loss probe requires the registered reviewed publisher client'
}
if($ReuseRegistration -and (-not $RegisteredService -or -not $ReviewedSource -or -not $ServiceControlBinary)) {
    throw 'Bound service request probe requires the registered reviewed publisher'
}
if($ReuseRegistration -and $InterruptAfterStage) {
    throw 'Poststage fault injection restores the owned service command before recovery'
}
if($ProductionConcurrentRights -and (-not $RegisteredService -or -not $ReviewedSource -or
    -not ($NonAdminClient -or ($ConsumerAccess -and $MachineRequestClient)) -or $HostileRights -or
    $InterruptAfterStage -or (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_service.exe')) {
    throw 'Production rights probe requires the registered service and non-admin client'
}
if($ProductionPostrenameTermination -and (-not $RegisteredService -or -not $ReviewedSource -or
    -not $ClientBinary -or $NonAdminClient -or $ConsumerAccess -or $MachineRequestClient -or
    $ProductionConcurrentRights -or $HostileRights -or $InterruptAfterStage -or
    $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterVisibleRecord -or
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_service.exe')) {
    throw 'Production rename-loss probe requires the uninterrupted registered production service'
}
if($ProductionPreparedTermination -and (-not $RegisteredService -or -not $ReviewedSource -or
    -not $ClientBinary -or $NonAdminClient -or $ConsumerAccess -or $MachineRequestClient -or
    $ProductionConcurrentRights -or $ProductionPostrenameTermination -or $HostileRights -or
    $InterruptAfterStage -or $InterruptAfterRename -or $InterruptBeforePublish -or
    $InterruptAfterVisibleRecord -or (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_service.exe')) {
    throw 'Production prepared-loss probe requires the uninterrupted registered production service'
}
if($ProductionPostpublishRights -and (-not $ProductionConcurrentRights -or -not $NonAdminClient -or
    $ConsumerAccess -or $HostileRights)) {
    throw 'Production postpublish rights probe requires the exact non-admin production operation'
}

# This script is deliberately limited to a fresh GitHub-hosted Windows VM.
# In particular, no local workstation disk may pass the admission check.
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'WU-006 disposable volume probe requires an administrative GitHub-hosted Windows runner'
}

$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
if (-not (Test-Path -LiteralPath $runnerTemp -PathType Container)) {
    throw 'runner temporary directory does not exist'
}
$id = [Guid]::NewGuid().ToString('N')
$lab = Join-Path $runnerTemp ('usk-wu006-' + $id)
$vhd = Join-Path $lab 'publisher.vhdx'
$out = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Path $lab -ErrorAction Stop | Out-Null

$receipt = [ordered]@{
    schema = 'usk.windows_disposable_lab_probe.v1'
    status = 'not_run'
    created_utc = [DateTime]::UtcNow.ToString('o')
    runner_environment = $env:RUNNER_ENVIRONMENT
    machine_name = $env:COMPUTERNAME
    windows_build = [Environment]::OSVersion.Version.ToString()
    identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    lab_root = $lab
    backing_file = $vhd
    disk_number = $null
    disk_unique_id = $null
    volume_root = $null
    volume_unique_id = $null
    filesystem = $null
    service_observation = $null
    cleanup = 'not_run'
    failure = $null
}
$mounted = $false
$failure = $null

function Read-PublicBuildProfile([string]$Binary) {
    $build=Split-Path -Parent (Split-Path -Parent ([IO.Path]::GetFullPath($Binary)))
    $projectPath=Join-Path $build 'usk_publisher_service.vcxproj'
    $compilerFiles=@(Get-ChildItem -LiteralPath (Join-Path $build 'CMakeFiles') -Directory|ForEach-Object {
        $candidate=Join-Path $_.FullName 'CMakeCXXCompiler.cmake'
        if(Test-Path -LiteralPath $candidate -PathType Leaf){$candidate}
    })
    if($compilerFiles.Count -ne 1){throw 'Public qualification compiler definition is absent or ambiguous'}
    $project=[xml][IO.File]::ReadAllText($projectPath)
    $sdk=@($project.Project.PropertyGroup.WindowsTargetPlatformVersion|Where-Object {$_}|Select-Object -Unique)
    $toolset=@($project.Project.PropertyGroup.PlatformToolset|Where-Object {$_}|Select-Object -Unique)
    $compiler=[IO.File]::ReadAllText($compilerFiles[0])
    $version=[regex]::Match($compiler,'(?m)^set\(CMAKE_CXX_COMPILER_VERSION "([^"]+)"\)').Groups[1].Value
    $compilerId=[regex]::Match($compiler,'(?m)^set\(CMAKE_CXX_COMPILER_ID "([^"]+)"\)').Groups[1].Value
    if($sdk.Count -ne 1 -or $toolset.Count -ne 1 -or -not $version -or -not $compilerId) {
        throw 'Public qualification SDK/compiler facts unavailable'
    }
    $commit=& git -C $env:GITHUB_WORKSPACE rev-parse HEAD
    if($LASTEXITCODE -ne 0){throw 'Public qualification source commit unavailable'}
    $tree=& git -C $env:GITHUB_WORKSPACE rev-parse 'HEAD^{tree}'
    if($LASTEXITCODE -ne 0){throw 'Public qualification source tree unavailable'}
    $event=Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw|ConvertFrom-Json
    [ordered]@{source_commit=$commit;source_tree=$tree;pull_request_head=$event.pull_request.head.sha;
        ci_run_id=$env:GITHUB_RUN_ID;ci_run_attempt=$env:GITHUB_RUN_ATTEMPT;
        windows_sdk=[string]$sdk[0];platform_toolset=[string]$toolset[0];compiler_id=$compilerId;compiler_version=$version;
        compiler_definition_sha256=(Get-FileHash -LiteralPath $compilerFiles[0] -Algorithm SHA256).Hash.ToLowerInvariant();
        project_sha256=(Get-FileHash -LiteralPath $projectPath -Algorithm SHA256).Hash.ToLowerInvariant();
        probe_powershell=$PSVersionTable.PSVersion.ToString();probe_clr=[Environment]::Version.ToString()}
}
function Invoke-StandardPublicSystemTask {
    param([string]$VhdPath,[string]$VolumeRoot,[string]$ServiceBinary,[string]$ServiceControlBinary,
        [string]$MachineBinary,[string]$OutputPath,[string]$LabRoot,[switch]$BootstrapProcessLoss,
        [switch]$BootstrapPreservationProcessLoss)
    # No local invocation can reach this: the outer lab has already required a
    # fresh hosted VM and provisioned the exact disposable data disk.
    $taskName='USK_STANDARD_PUBLIC_'+[guid]::NewGuid().ToString('N')
    $script=Join-Path $LabRoot ($taskName+'.ps1')
    $startBinding=Join-Path $LabRoot ($taskName+'.started.json')
    $quote={param([string]$value) "'"+$value.Replace("'","''")+"'"}
    $probe=Join-Path $PSScriptRoot 'windows_publisher_standard_public_probe.ps1'
    $python=(Get-Command python -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
    if(-not [IO.Path]::IsPathRooted($python) -or -not [IO.File]::Exists($python)){throw 'Owned standard Python interpreter is unavailable'}
    $body=@('$ErrorActionPreference=''Stop''',
        '$env:GITHUB_ACTIONS=''true''', '$env:RUNNER_ENVIRONMENT=''github-hosted''',
        ('$env:RUNNER_TEMP='+(& $quote $env:RUNNER_TEMP)),
        '$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
        'if($identity -cne ''S-1-5-18''){throw ''Owned launcher identity differs''}',
        ('$startBinding='+(& $quote $startBinding)),
        '$process=Get-Process -Id $PID',
        '$binding=@{schema=''usk.publisher_standard_launcher.v1'';process_id=$PID;creation_file_time=$process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();identity=$identity;image=$process.Path}',
        '$pendingBinding=$startBinding+''.pending''',
        '$stream=[IO.File]::Open($pendingBinding,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)',
        'try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($binding|ConvertTo-Json -Compress));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose();$process.Dispose()}',
        '[IO.File]::Move($pendingBinding,$startBinding)',
        ('& '+(& $quote $probe)+' -VhdPath '+(& $quote $VhdPath)+' -VolumeRoot '+(& $quote $VolumeRoot)+
            ' -ServiceBinary '+(& $quote $ServiceBinary)+' -ServiceControlBinary '+(& $quote $ServiceControlBinary)+
            ' -MachineBinary '+(& $quote $MachineBinary)+' -OutputPath '+(& $quote $OutputPath)+' -PythonBinary '+(& $quote $python)+
            $(if($BootstrapProcessLoss){' -BootstrapProcessLoss'}else{''})+
            $(if($BootstrapPreservationProcessLoss){' -BootstrapPreservationProcessLoss'}else{''}))) -join "`n"
    $stream=[IO.File]::Open($script,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes($body);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
    foreach($principalSid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principalSid),'FullControl','Allow'))
    }
    Set-Acl -LiteralPath $script -AclObject $acl
    $command='& '+(& $quote $script)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $taskImage=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $taskArguments='-NoProfile -NonInteractive -EncodedCommand '+$encoded
    $action=New-ScheduledTaskAction -Execute $taskImage -Argument $taskArguments
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    $created=$false;$finished=$false;$launcherProcess=$null;$launcherBinding=$null
    $script:standardLauncherClosed=$false
    $scriptSha256=(Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant()
    $assertOwnedTask={param($task)
        $principal=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        try {$principal=[Security.Principal.SecurityIdentifier]::new([string]$task.Principal.UserId)}
        catch {$principal=[Security.Principal.NTAccount]::new([string]$task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])}
        if($task.TaskName -cne $taskName -or $task.TaskPath -cne '\' -or $principal.Value -cne 'S-1-5-18' -or
            $task.Principal.RunLevel -ne 'Highest' -or @($task.Actions).Count -ne 1 -or
            $task.Actions[0].Execute -cne $taskImage -or $task.Actions[0].Arguments -cne $taskArguments -or
            $task.Actions[0].WorkingDirectory -or
            (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $scriptSha256) {
            throw 'Owned SYSTEM standard task definition or protected wrapper changed'
        }
    }
    $recordUnconfirmed={param([string]$reason)
        $result=if(Test-Path -LiteralPath $OutputPath -PathType Leaf){
            Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json
        }else{[pscustomobject]@{}}
        foreach($item in @{status='failed';failure=$reason;client_cleanup_confirmed=$false;launcher_task_removed=$false}.GetEnumerator()) {
            $result|Add-Member -NotePropertyName $item.Key -NotePropertyValue $item.Value -Force
        }
        [IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 64 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    }
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -User SYSTEM -RunLevel Highest -ErrorAction Stop|Out-Null
        $created=$true
        & $assertOwnedTask (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop)
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $deadline=[DateTime]::UtcNow.AddMinutes(12)
        do {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            & $assertOwnedTask $task
            $info=Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            if(-not $launcherProcess -and (Test-Path -LiteralPath $startBinding -PathType Leaf)) {
                if((Get-Item -LiteralPath $startBinding).Length -gt 4096){throw 'Owned launcher start binding exceeds bound'}
                $launcherBinding=Get-Content -LiteralPath $startBinding -Raw|ConvertFrom-Json
                if($launcherBinding.schema -cne 'usk.publisher_standard_launcher.v1' -or
                    $launcherBinding.identity -cne 'S-1-5-18' -or $launcherBinding.image -cne $taskImage -or
                    $launcherBinding.process_id -le 0 -or $launcherBinding.creation_file_time -cnotmatch '^[1-9][0-9]{16,18}$') {
                    throw 'Owned launcher start identity differs'
                }
                $launcherProcess=Get-Process -Id $launcherBinding.process_id -ErrorAction Stop;$null=$launcherProcess.Handle
                if($launcherProcess.Path -cne $taskImage -or
                    $launcherProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -cne $launcherBinding.creation_file_time) {
                    throw 'Held owned launcher process identity differs'
                }
            }
            if($launcherProcess -and $launcherProcess.HasExited -and $info.LastRunTime.Year -gt 2000 -and
                $task.State -in @('Ready','Disabled')) {$finished=$true;break}
            Start-Sleep -Milliseconds 100
        } while([DateTime]::UtcNow -lt $deadline)
        if(-not $finished -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
            # Keep ownership unconfirmed; outer cleanup must retain backing
            # storage until runner disposal if any client might still be live.
            & $recordUnconfirmed 'owned SYSTEM standard task completion is unconfirmed'
            throw 'Owned SYSTEM standard task did not complete with a receipt'
        }
        if($info.LastTaskResult -ne 0){throw 'Owned SYSTEM standard fixture failed; retained receipt contains its failure'}
    } finally {
        if($created -and $finished) {
            try {
                & $assertOwnedTask (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop)
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Owned standard task remains registered'}
            } catch {
                & $recordUnconfirmed 'owned SYSTEM standard task removal is unconfirmed'
                throw
            }
        }
        if(-not $finished){& $recordUnconfirmed 'owned SYSTEM launcher termination is unconfirmed'}
        if($launcherProcess){$launcherProcess.Dispose()}
    }
    $result=Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json
    $result|Add-Member -NotePropertyName launcher_task_removed -NotePropertyValue $true
    $result|Add-Member -NotePropertyName launcher_task_result -NotePropertyValue ([uint32]$info.LastTaskResult)
    $result|Add-Member -NotePropertyName launcher_task -NotePropertyValue $taskName
    $result|Add-Member -NotePropertyName launcher_process -NotePropertyValue $launcherBinding
    $result|Add-Member -NotePropertyName launcher_process_exit_confirmed -NotePropertyValue $true
    [IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 64 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    $script:standardLauncherClosed=$true
}
try {
    if($PublicInstallation){$receipt['build_profile']=Read-PublicBuildProfile $ServiceBinary}
    $before = @(Get-Disk -ErrorAction Stop | Select-Object -ExpandProperty Number)
    if (Test-Path -LiteralPath $vhd) { throw 'new backing file already exists' }
    if (Get-Command New-VHD -ErrorAction SilentlyContinue) {
        New-VHD -Path $vhd -SizeBytes 512MB -Dynamic -ErrorAction Stop | Out-Null
    } else {
        $scriptPath = Join-Path $lab 'create-vdisk.txt'
        ('create vdisk file="' + $vhd + '" maximum=512 type=expandable') |
            Set-Content -LiteralPath $scriptPath -Encoding ASCII
        $process = Start-Process -FilePath "$env:SystemRoot\System32\diskpart.exe" `
            -ArgumentList ('/s "' + $scriptPath + '"') -WindowStyle Hidden -PassThru -Wait `
            -RedirectStandardOutput (Join-Path $lab 'diskpart-stdout.txt') `
            -RedirectStandardError (Join-Path $lab 'diskpart-stderr.txt')
        if ($process.ExitCode -ne 0) { throw "DiskPart VHD creation failed: $($process.ExitCode)" }
    }
    if (-not (Test-Path -LiteralPath $vhd -PathType Leaf)) {
        throw 'file-backed VHD was not created'
    }

    Mount-DiskImage -ImagePath $vhd -NoDriveLetter -ErrorAction Stop | Out-Null
    $mounted = $true
    $image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
    $disks = @($image | Get-Disk -ErrorAction Stop)
    if ($disks.Count -ne 1) { throw 'VHD did not resolve to exactly one mounted disk' }
    $disk = $disks[0]
    if ($disk.Number -in $before -or $disk.IsBoot -or $disk.IsSystem -or
        $disk.PartitionStyle -ne 'RAW' -or $disk.Size -lt 512MB) {
        throw 'mounted disk is not the new empty disposable VHD'
    }
    $receipt.disk_number = $disk.Number
    $receipt.disk_unique_id = $disk.UniqueId
    $diskPath = $disk.Path
    $diskNumber = $disk.Number

    # Pass the observed CIM disk object to mutating cmdlets. A disk number is
    # reusable if an image detaches, so it is never a sufficient mutation target.
    $initialized = Initialize-Disk -InputObject $disk -PartitionStyle GPT `
        -PassThru -ErrorAction Stop
    $live = @(Get-DiskImage -ImagePath $vhd -ErrorAction Stop |
        Get-Disk -ErrorAction Stop)
    if ($live.Count -ne 1 -or $live[0].Number -ne $diskNumber -or
        $live[0].Path -ne $diskPath -or $live[0].IsBoot -or $live[0].IsSystem -or
        $live[0].PartitionStyle -ne 'GPT' -or
        $initialized.Number -ne $live[0].Number -or
        $initialized.Path -ne $live[0].Path) {
        throw 'initialized disk no longer resolves to the new VHD'
    }
    $partition = New-Partition -InputObject $live[0] -UseMaximumSize `
        -AssignDriveLetter -ErrorAction Stop
    $partitionDisk = @(Get-Disk -Partition $partition -ErrorAction Stop)
    $live = @(Get-DiskImage -ImagePath $vhd -ErrorAction Stop |
        Get-Disk -ErrorAction Stop)
    if ($live.Count -ne 1 -or $partitionDisk.Count -ne 1 -or
        $live[0].Number -ne $diskNumber -or $live[0].Path -ne $diskPath -or
        $partitionDisk[0].Number -ne $live[0].Number -or
        $partitionDisk[0].Path -ne $live[0].Path -or
        $live[0].IsBoot -or $live[0].IsSystem -or
        $partition.DiskNumber -ne $live[0].Number -or -not $partition.DriveLetter) {
        throw 'new partition is not bound to the disposable disk'
    }
    Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'USK_WU006_LAB' `
        -Confirm:$false -Force -ErrorAction Stop | Out-Null
    $volume = $partition | Get-Volume -ErrorAction Stop
    if ($volume.FileSystem -ne 'NTFS' -or $volume.DriveLetter -ne $partition.DriveLetter) {
        throw 'disposable volume did not format as the identified NTFS partition'
    }
    $receipt.volume_root = "$($partition.DriveLetter):\"
    $receipt.volume_unique_id = $volume.UniqueId
    $receipt.filesystem = $volume.FileSystem
    if($PublicInstallation) {
        $admittedDisk=Get-Disk -Number $receipt.disk_number -ErrorAction Stop
        if($admittedDisk.UniqueId -cne $receipt.disk_unique_id){throw 'Public qualification disk identity changed'}
        $receipt['storage_profile']=[ordered]@{bus_type=$admittedDisk.BusType.ToString();
            partition_style=$admittedDisk.PartitionStyle.ToString();logical_sector_bytes=$admittedDisk.LogicalSectorSize;
            physical_sector_bytes=$admittedDisk.PhysicalSectorSize;size_bytes=$admittedDisk.Size}
    }
    $receipt.status = 'volume_provisioned'
    if ($ServiceBinary) {
        if (-not $DeviceAclBinary -and -not $PublicInstallation) { throw 'owned VHD device ACL helper is required' }
        $serviceOutput = Join-Path $lab 'service-probe.json'
        if ($PublicStandardClient) {
            Invoke-StandardPublicSystemTask -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -ServiceControlBinary $ServiceControlBinary `
                -MachineBinary $MachineBinary -OutputPath $serviceOutput -LabRoot $lab `
                -BootstrapProcessLoss:($PublicStandardBootstrapLoss -or $PublicStandardBootstrapPreservationLoss) `
                -BootstrapPreservationProcessLoss:$PublicStandardBootstrapPreservationLoss
        } elseif ($PublicInstallation) {
            & (Join-Path $PSScriptRoot 'windows_publisher_public_path_probe.ps1') `
                -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -ServiceControlBinary $ServiceControlBinary `
                -MachineBinary $MachineBinary -OutputPath $serviceOutput -PublicationLoss $PublicPublicationLoss `
                -PostRenameRefusal $PublicPostRenameRefusal
        } elseif ($MachineBinary) {
            & (Join-Path $PSScriptRoot 'windows_publisher_metadata_hosted_probe.ps1') `
                -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -ServiceControlBinary $ServiceControlBinary -DeviceAclBinary $DeviceAclBinary `
                -MachineBinary $MachineBinary -PublicApplyBinary $PublicApplyBinary -ClientBinary $ClientBinary -PayloadBinary $PayloadBinary -ConsumerAccess:$ConsumerAccess -InterruptDuringConsumerAccess:$InterruptDuringConsumerAccess -OutputPath $serviceOutput `
                -InterruptAfterVisibleRecord:$InterruptAfterVisibleRecord -InterruptAfterRename:$InterruptAfterRename -InterruptBeforePublish:$InterruptBeforePublish -InterruptAfterStage:$InterruptAfterStage -TerminateAtPoststage:$TerminateAtPoststage -TerminateAtPostrename:$TerminateAtPostrename -ReviewedSource:$ReviewedSource -RegisteredService:$RegisteredService -ReuseRegistration:$ReuseRegistration -MachineRequestClient:$MachineRequestClient -ControllerApply:$ControllerApply -NonAdminClient:$NonAdminClient -ProductionConcurrentRights:$ProductionConcurrentRights -ProductionPostpublishRights:$ProductionPostpublishRights -ProductionPostrenameTermination:$ProductionPostrenameTermination -ProductionPreparedTermination:$ProductionPreparedTermination -ExpectUnprotectedRefusal:$ExpectUnprotectedRefusal -ExpectPreexistingAnchorRefusal:$ExpectPreexistingAnchorRefusal -HostileRights:($HostileRights -and -not $HostilePostrename) -HostilePostrename:$HostilePostrename
        } else {
            & (Join-Path $PSScriptRoot 'windows_publisher_service_probe.ps1') `
                -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -DeviceAclBinary $DeviceAclBinary `
                -OutputPath $serviceOutput
        }
        $receipt['service_observation'] = Get-Content -LiteralPath $serviceOutput -Raw |
            ConvertFrom-Json
        $expected = if ($PublicStandardClient) { 'standard_public_install_verified_recovered' } elseif ($PublicPostRenameRefusal -cne 'none') { 'public_refusal_retained' } elseif ($PublicInstallation) { 'public_install_verified_recovered' } elseif ($ExpectUnprotectedRefusal) { 'preprotected_boundary_refusal_observed' } elseif ($ExpectPreexistingAnchorRefusal) { 'preexisting_anchor_recovery_required_observed' } elseif ($MachineBinary) { 'protected_metadata_observed' } else { 'protected_publish_observed' }
        if ($receipt.service_observation.status -ne $expected) {
            throw 'protected publish service probe did not pass'
        }
        $receipt.status = if ($PublicPostRenameRefusal -cne 'none') { 'volume_and_retained_public_refusal_observed' } elseif ($ExpectUnprotectedRefusal) { 'unprotected_boundary_refusal_observed' } elseif ($ExpectPreexistingAnchorRefusal) { 'preexisting_anchor_recovery_required_observed' } else { 'volume_and_protected_publish_observed' }
    }
} catch {
    $failure = $_.Exception.Message
    $receipt.failure = $failure
    $receipt.status = 'failed'
    if ($ServiceBinary -and $serviceOutput -and
        (Test-Path -LiteralPath $serviceOutput -PathType Leaf)) {
        try {
            $receipt.service_observation = Get-Content -LiteralPath $serviceOutput -Raw |
                ConvertFrom-Json
        } catch {}
    }
} finally {
    try {
        if($PublicStandardClient -and -not $standardLauncherClosed){
            throw 'Owned SYSTEM launcher cleanup unconfirmed; retain backing volume until runner VM disposal'
        }
        if($receipt.service_observation -and $receipt.service_observation.client_cleanup_confirmed -eq $false){
            throw 'Owned client cleanup unconfirmed; retain backing volume until runner VM disposal'
        }
        $backingFileExisted = Test-Path -LiteralPath $vhd -PathType Leaf
        if ($mounted) {
            $image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
            if ($image.Attached) { Dismount-DiskImage -ImagePath $vhd -ErrorAction Stop }
        }
        if ($backingFileExisted) {
            Remove-Item -LiteralPath $vhd -Force -ErrorAction Stop
        }
        $receipt.cleanup = if ($backingFileExisted) {
            'owned VHD dismounted if attached and backing file removed; runner VM disposes remaining lab directory'
        } else {
            'no backing file was created; runner VM disposes remaining lab directory'
        }
    } catch {
        $receipt.cleanup = 'failed: ' + $_.Exception.Message
        if (-not $failure) { $failure = 'disposable VHD cleanup failed' }
    }
    $receipt['completed_utc'] = [DateTime]::UtcNow.ToString('o')
    $receipt | ConvertTo-Json -Depth 64 | Set-Content -LiteralPath $out -Encoding UTF8
}

if ($failure) { throw $failure }
Write-Output "WU-006 disposable NTFS volume probe passed: $out"
