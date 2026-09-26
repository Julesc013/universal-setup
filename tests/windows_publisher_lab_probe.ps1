param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$ServiceBinary = '',
    [string]$DeviceAclBinary = '',
    [string]$MachineBinary = ''
)

$ErrorActionPreference = 'Stop'

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

try {
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
    $receipt.status = 'volume_provisioned'
    if ($ServiceBinary) {
        if (-not $DeviceAclBinary) { throw 'owned VHD device ACL helper is required' }
        $serviceOutput = Join-Path $lab 'service-probe.json'
        if ($MachineBinary) {
            & (Join-Path $PSScriptRoot 'windows_publisher_metadata_hosted_probe.ps1') `
                -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -DeviceAclBinary $DeviceAclBinary `
                -MachineBinary $MachineBinary -OutputPath $serviceOutput
        } else {
            & (Join-Path $PSScriptRoot 'windows_publisher_service_probe.ps1') `
                -VhdPath $vhd -VolumeRoot $receipt.volume_unique_id `
                -ServiceBinary $ServiceBinary -DeviceAclBinary $DeviceAclBinary `
                -OutputPath $serviceOutput
        }
        $receipt['service_observation'] = Get-Content -LiteralPath $serviceOutput -Raw |
            ConvertFrom-Json
        $expected = if ($MachineBinary) { 'protected_metadata_observed' } else { 'protected_publish_observed' }
        if ($receipt.service_observation.status -ne $expected) {
            throw 'protected publish service probe did not pass'
        }
        $receipt.status = 'volume_and_protected_publish_observed'
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
