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
    [ValidateSet('none','prepublish','postrename')][string]$PublicPublicationLoss='none',
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
if($PublicPublicationLoss -cne 'none' -and -not $PublicInstallation) {
    throw 'Ordinary public boundary loss requires the public installation probe'
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
        if ($PublicInstallation) {
            & (Join-Path $PSScriptRoot 'windows_publisher_public_path_probe.ps1') `
                -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -ServiceControlBinary $ServiceControlBinary `
                -MachineBinary $MachineBinary -OutputPath $serviceOutput -PublicationLoss $PublicPublicationLoss
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
        $expected = if ($PublicInstallation) { 'public_install_verified_recovered' } elseif ($ExpectUnprotectedRefusal) { 'preprotected_boundary_refusal_observed' } elseif ($ExpectPreexistingAnchorRefusal) { 'preexisting_anchor_recovery_required_observed' } elseif ($MachineBinary) { 'protected_metadata_observed' } else { 'protected_publish_observed' }
        if ($receipt.service_observation.status -ne $expected) {
            throw 'protected publish service probe did not pass'
        }
        $receipt.status = if ($ExpectUnprotectedRefusal) { 'unprotected_boundary_refusal_observed' } elseif ($ExpectPreexistingAnchorRefusal) { 'preexisting_anchor_recovery_required_observed' } else { 'volume_and_protected_publish_observed' }
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
    $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $out -Encoding UTF8
}

if ($failure) { throw $failure }
Write-Output "WU-006 disposable NTFS volume probe passed: $out"
