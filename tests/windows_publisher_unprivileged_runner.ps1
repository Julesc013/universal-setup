param(
    [Parameter(Mandatory = $true)][string]$VhdPath,
    [Parameter(Mandatory = $true)][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][string]$ServiceSid,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$vhd = [IO.Path]::GetFullPath($VhdPath)
$output = [IO.Path]::GetFullPath($OutputPath)
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not $vhd.StartsWith($runnerTemp + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) -or
    $output -ne (Join-Path (Split-Path -Parent $vhd) 'unprivileged-attack.json') -or
    -not (Test-Path -LiteralPath $vhd -PathType Leaf)) {
    throw 'unprivileged access probe requires the owned hosted Windows VHD'
}
$image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
$disk = @($image | Get-Disk -ErrorAction Stop)
$partitions = @($disk | Get-Partition -ErrorAction Stop |
    Where-Object { $_.DriveLetter })
if (-not $image.Attached -or $disk.Count -ne 1 -or
    $disk[0].IsBoot -or $disk[0].IsSystem -or $partitions.Count -ne 1 -or
    (Get-Volume -Partition $partitions[0] -ErrorAction Stop).UniqueId -ne $VolumeRoot) {
    throw 'unprivileged access probe volume is not the attached disposable VHD'
}

$accountName = 'USKATK_' + [Guid]::NewGuid().ToString('N').Substring(0, 13)
$attackFolder = Join-Path $runnerTemp ('USK-WU006-ATTACK-' + [Guid]::NewGuid().ToString('N'))
$childOutput = Join-Path $attackFolder 'access.json'
$receipt = [ordered]@{
    schema = 'usk.publisher.unprivileged_lab_runner.v1'
    status = 'not_run'
    account_name = $accountName
    account_sid = $null
    volume_root = $VolumeRoot
    vhd_disk_number = $disk[0].Number
    process_exit_code = $null
    observation = $null
    cleanup = 'not_run'
    failure = $null
}
$accountCreated = $false
$folderCreated = $false
$process = $null
$failure = $null
try {
    if (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue) {
        throw 'generated local attack account name already exists'
    }
    $plainPassword = 'Aa1!' + [Guid]::NewGuid().ToString('N')
    $password = ConvertTo-SecureString $plainPassword -AsPlainText -Force
    $plainPassword = $null
    $account = New-LocalUser -Name $accountName -Password $password `
        -PasswordNeverExpires -ErrorAction Stop
    $accountCreated = $true
    $receipt.account_sid = $account.SID.Value

    [IO.Directory]::CreateDirectory($attackFolder) | Out-Null
    $folderCreated = $true
    $accountPrincipal = New-Object Security.Principal.NTAccount(
        $env:COMPUTERNAME, $accountName)
    $acl = Get-Acl -LiteralPath $attackFolder
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $accountPrincipal, [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $attackFolder -AclObject $acl

    $credential = New-Object System.Management.Automation.PSCredential(
        "$env:COMPUTERNAME\$accountName", $password)
    $script = Join-Path $PSScriptRoot 'windows_publisher_unprivileged_probe.ps1'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $script + '" -VolumeRoot "' + $VolumeRoot.TrimEnd('\') +
        '" -ExpectedUserSid "' + $receipt.account_sid +
        '" -ServiceSid "' + $ServiceSid +
        '" -OutputPath "' + $childOutput + '"'
    $process = Start-Process -FilePath (Get-Command pwsh).Source `
        -ArgumentList $arguments -Credential $credential -PassThru `
        -WindowStyle Hidden -WorkingDirectory $attackFolder -ErrorAction Stop
    if (-not $process.WaitForExit(45000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        if (-not $process.WaitForExit(5000)) {
            throw 'unprivileged access process remained after termination request'
        }
        throw 'unprivileged access process timed out and was terminated'
    }
    $receipt.process_exit_code = $process.ExitCode
    if (-not (Test-Path -LiteralPath $childOutput -PathType Leaf)) {
        throw 'unprivileged access process emitted no receipt'
    }
    $observation = Get-Content -LiteralPath $childOutput -Raw | ConvertFrom-Json
    $receipt.observation = $observation
    if ($process.ExitCode -ne 0 -or
        $observation.schema -ne 'usk.publisher.unprivileged_access_probe.v1' -or
        $observation.status -ne 'access_denied_observed' -or
        $observation.user_sid -ne $receipt.account_sid -or
        $observation.administrator -or $observation.service_sid_present -or
        $observation.volume_root -ne $VolumeRoot -or
        $observation.process_id -ne $process.Id -or
        @($observation.attempts).Count -ne 4 -or
        @($observation.attempts | Where-Object {
            $_.outcome -ne 'access_denied' -or $_.hresult -ne -2147024891
        }).Count -ne 0 -or
        (@($observation.attempts.name) -join ',') -ne
            'visible_read,visible_write,destination_create,visible_delete') {
        throw 'unprivileged process did not independently observe four access denials'
    }
    $receipt.status = 'unprivileged_access_denied_observed'
} catch {
    $failure = $_.Exception.Message
    $receipt.status = 'failed'
    $receipt.failure = $failure
} finally {
    $cleanupParts = @()
    $processStopped = $true
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $processStopped = $process.WaitForExit(5000)
        if (-not $processStopped) {
            $cleanupParts += 'generated process remained after termination request'
            if (-not $failure) { $failure = 'generated process cleanup failed' }
        }
    }
    if ($accountCreated -and $processStopped) {
        try {
            Remove-LocalUser -Name $accountName -ErrorAction Stop
            $cleanupParts += 'generated local account deleted'
        } catch {
            $cleanupParts += 'account cleanup failed: ' + $_.Exception.Message
            if (-not $failure) { $failure = 'generated local account cleanup failed' }
        }
    }
    if ($folderCreated -and $processStopped) {
        try {
            $fullFolder = [IO.Path]::GetFullPath($attackFolder)
            if (-not $fullFolder.StartsWith(
                    $runnerTemp + [IO.Path]::DirectorySeparatorChar,
                    [StringComparison]::OrdinalIgnoreCase) -or
                -not [IO.Path]::GetFileName($fullFolder).StartsWith(
                    'USK-WU006-ATTACK-', [StringComparison]::Ordinal)) {
                throw 'generated attack folder left the runner temporary root'
            }
            Remove-Item -LiteralPath $fullFolder -Recurse -Force -ErrorAction Stop
            $cleanupParts += 'generated output folder deleted'
        } catch {
            $cleanupParts += 'folder cleanup failed: ' + $_.Exception.Message
            if (-not $failure) { $failure = 'generated attack folder cleanup failed' }
        }
    }
    $receipt.cleanup = $cleanupParts -join '; '
    if ($failure) {
        $receipt.status = 'failed'
        $receipt.failure = $failure
    }
    $receipt | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $output -Encoding utf8
}
if ($failure) { throw $failure }
