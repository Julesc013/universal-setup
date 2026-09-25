param(
    [Parameter(Mandatory = $true)][string]$VhdPath,
    [Parameter(Mandatory = $true)][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][string]$ServiceBinary,
    [Parameter(Mandatory = $true)][string]$DeviceAclBinary,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'WU-006 service probe requires an administrative GitHub-hosted Windows runner'
}
$vhd = [IO.Path]::GetFullPath($VhdPath)
$binary = [IO.Path]::GetFullPath($ServiceBinary)
$deviceAclBinary = [IO.Path]::GetFullPath($DeviceAclBinary)
$out = [IO.Path]::GetFullPath($OutputPath)
$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
if (-not $vhd.StartsWith($runnerTemp + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-Path -LiteralPath $vhd -PathType Leaf) -or
    -not (Test-Path -LiteralPath $binary -PathType Leaf) -or
    -not (Test-Path -LiteralPath $deviceAclBinary -PathType Leaf)) {
    throw 'service probe inputs are not the owned VHD and executable'
}
$image = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
$disk = @($image | Get-Disk -ErrorAction Stop)
$partitions = @($disk | Get-Partition -ErrorAction Stop |
    Where-Object { $_.DriveLetter })
if (-not $image.Attached -or $disk.Count -ne 1 -or $disk[0].IsBoot -or
    $disk[0].IsSystem -or $partitions.Count -ne 1) {
    throw 'service probe volume is not the owned disposable NTFS VHD'
}
$volume = Get-Volume -Partition $partitions[0] -ErrorAction Stop
if ($volume.FileSystem -ne 'NTFS' -or $VolumeRoot -ne $volume.UniqueId -or
    -not $VolumeRoot.StartsWith('\\?\Volume{', [StringComparison]::OrdinalIgnoreCase) -or
    -not $VolumeRoot.EndsWith('}\', [StringComparison]::Ordinal)) {
    throw 'service probe requires the owned VHD volume GUID root'
}
function Assert-OwnedVolume {
    $liveImage = Get-DiskImage -ImagePath $vhd -ErrorAction Stop
    $liveDisks = @($liveImage | Get-Disk -ErrorAction Stop)
    if (-not $liveImage.Attached -or $liveDisks.Count -ne 1 -or
        $liveDisks[0].Number -ne $disk[0].Number -or
        $liveDisks[0].Path -ne $disk[0].Path -or
        $liveDisks[0].UniqueId -ne $disk[0].UniqueId -or
        $liveDisks[0].IsBoot -or $liveDisks[0].IsSystem) {
        throw 'service probe VHD disk binding changed'
    }
    $livePartitions = @($liveDisks[0] | Get-Partition -ErrorAction Stop |
        Where-Object { $_.DriveLetter -eq $partitions[0].DriveLetter })
    if ($livePartitions.Count -ne 1 -or
        (Get-Volume -Partition $livePartitions[0] -ErrorAction Stop).UniqueId -ne $VolumeRoot) {
        throw 'service probe VHD volume binding changed'
    }
}

$serviceName = 'USK_WU006_' + [Guid]::NewGuid().ToString('N')
$serviceReceipt = Join-Path (Split-Path -Parent $vhd) 'restricted-service.json'
$receipt = [ordered]@{
    schema = 'usk.windows_disposable_service_probe.v1'
    status = 'not_run'
    created_utc = [DateTime]::UtcNow.ToString('o')
    runner_environment = $env:RUNNER_ENVIRONMENT
    windows_build = [Environment]::OSVersion.Version.ToString()
    service_name = $serviceName
    service_sid = $null
    service_binary = $binary
    volume_root = $VolumeRoot
    volume_disk_number = $disk[0].Number
    service_process_id = $null
    native_observation = $null
    cleanup = 'not_run'
    failure = $null
}
$created = $false
$failure = $null
try {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw 'generated service name already exists'
    }
    # The validated GUID root contains no whitespace. Leave its terminal
    # backslash unquoted: a quoted trailing backslash escapes the quote in
    # Windows argv parsing and changes the path received by the service.
    $imagePath = '"' + $binary + '" --service ' + $serviceName +
        ' "' + $serviceReceipt + '" ' + $VolumeRoot
    & sc.exe create $serviceName type= own start= demand obj= LocalSystem binPath= $imagePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SCM own-process service creation failed' }
    $created = $true
    & sc.exe sidtype $serviceName restricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SCM restricted service SID configuration failed' }
    $account = New-Object Security.Principal.NTAccount('NT SERVICE\' + $serviceName)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt.service_sid = $sid
    $labRoot = Split-Path -Parent $vhd
    $acl = Get-Acl -LiteralPath $labRoot
    $rights = [Security.AccessControl.FileSystemRights]::Write
    $inheritance = [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $account, $rights, $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $labRoot -AclObject $acl

    # The only volume whose ACL is changed is the newly created VHD. Grant
    # temporary bootstrap access so the service can replace this root DACL
    # with its exact protected SYSTEM/service descriptor on the held handle.
    Assert-OwnedVolume
    $volumeAcl = Get-Acl -LiteralPath $VolumeRoot
    $volumeRule = New-Object Security.AccessControl.FileSystemAccessRule(
        $account, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $volumeAcl.AddAccessRule($volumeRule)
    Assert-OwnedVolume
    Set-Acl -LiteralPath $VolumeRoot -AclObject $volumeAcl
    $receipt['bootstrap_root_sddl'] = (Get-Acl -LiteralPath $VolumeRoot).Sddl

    Assert-OwnedVolume
    $diagnosticChild = $VolumeRoot + 'diagnostic-child'
    if (Test-Path -LiteralPath $diagnosticChild) {
        throw 'fresh VHD unexpectedly contains the diagnostic child'
    }
    [IO.Directory]::CreateDirectory($diagnosticChild) | Out-Null
    $childAcl = Get-Acl -LiteralPath $diagnosticChild
    $childAcl.SetAccessRuleProtection($true, $false)
    $systemAccount = New-Object Security.Principal.NTAccount('SYSTEM')
    foreach ($principalAccount in @($systemAccount, $account)) {
        $childRule = New-Object Security.AccessControl.FileSystemAccessRule(
            $principalAccount, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::None,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $childAcl.AddAccessRule($childRule)
    }
    Set-Acl -LiteralPath $diagnosticChild -AclObject $childAcl
    $receipt['diagnostic_child_sddl'] = (Get-Acl -LiteralPath $diagnosticChild).Sddl
    Assert-OwnedVolume

    # The fresh VHD volume device has its own DACL. The restricted service
    # token must pass that check as well as the NTFS root/child DACLs. This
    # helper mutates only the independently rebound, single-disk VHD device.
    $deviceAclOutput = & $deviceAclBinary --owned-vhd-volume $VolumeRoot `
        $serviceName $disk[0].Number $vhd 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ('owned VHD device ACL provisioning failed: ' +
            ($deviceAclOutput -join '; '))
    }
    $receipt['device_acl_observation'] = $deviceAclOutput | ConvertFrom-Json
    if ($receipt.device_acl_observation.service_sid -ne $sid -or
        $receipt.device_acl_observation.vhd_disk_number -ne $disk[0].Number) {
        throw 'device ACL helper did not bind the expected VHD and dedicated service SID'
    }
    Assert-OwnedVolume

    Start-Service -Name $serviceName -ErrorAction Stop
    for ($attempt = 0; $attempt -lt 30 -and
        -not (Test-Path -LiteralPath $serviceReceipt -PathType Leaf); ++$attempt) {
        Start-Sleep -Seconds 1
    }
    if (-not (Test-Path -LiteralPath $serviceReceipt -PathType Leaf)) {
        throw 'restricted service did not create an observation receipt'
    }
    $native = Get-Content -LiteralPath $serviceReceipt -Raw | ConvertFrom-Json
    Assert-OwnedVolume
    $scm = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $enabled = @($native.process_groups | Where-Object {
        $_.sid -eq $sid -and ($_.attributes -band 4) -ne 0 -and
        ($_.attributes -band 16) -eq 0
    })
    $restricting = @($native.process_restricted_sids | Where-Object {
        $_.sid -eq $sid
    })
    $anchors = $native.protected_anchors
    $anchorIds = @($anchors.boundary_file_id, $anchors.publication_file_id,
        $anchors.staging_file_id, $anchors.destination_file_id,
        $anchors.state_file_id, $anchors.journal_file_id)
    $roles = @('boundary', 'publication', 'staging', 'destination', 'state', 'journal')
    $anchorFactsValid = $true
    for ($index = 0; $index -lt $roles.Count; ++$index) {
        $object = $anchors.objects.($roles[$index])
        $aces = @($object.dacl_aces)
        if (-not $object -or $object.file_id -ne $anchorIds[$index] -or
            -not $object.native_name -or $object.owner_sid -ne 'S-1-5-18' -or
            -not $object.dacl_protected -or $object.link_count -ne 1 -or
            $object.case_sensitive -or ($object.attributes -band 16) -eq 0 -or
            ($object.attributes -band 1024) -ne 0 -or $object.reparse_tag -ne 0 -or
            $aces.Count -ne 2 -or $aces[0].type -ne 0 -or
            $aces[0].flags -ne 0 -or $aces[0].sid -ne 'S-1-5-18' -or
            $aces[1].type -ne 0 -or $aces[1].flags -ne 0 -or
            $aces[1].sid -ne $sid -or $aces[0].access_mask -le 0 -or
            $aces[0].access_mask -ne $aces[1].access_mask) {
            $anchorFactsValid = $false
        }
    }
    $staged = $anchors.staged_tree
    $stageObjects = @($staged.root, $staged.file)
    $stageFactsValid = $staged.relative_path -eq 'payload.bin' -and
        $staged.size -eq 25 -and
        $staged.sha256 -eq '92ca2ba61185c0d9598b81fde8cbef1126ab69477c3f210f44de36fafe30120f' -and
        $staged.root.native_name -eq ($anchors.objects.staging.native_name + '\candidate') -and
        $staged.file.native_name -eq ($staged.root.native_name + '\payload.bin') -and
        @($anchorIds + @($staged.root.file_id, $staged.file.file_id) |
            Where-Object { -not $_ }).Count -eq 0 -and
        @($anchorIds + @($staged.root.file_id, $staged.file.file_id) |
            Sort-Object -Unique).Count -eq 8
    for ($index = 0; $index -lt $stageObjects.Count; ++$index) {
        $object = $stageObjects[$index]
        $aces = @($object.dacl_aces)
        if (-not $object -or $object.owner_sid -ne 'S-1-5-18' -or
            -not $object.dacl_protected -or $object.link_count -ne 1 -or
            ($object.attributes -band 1024) -ne 0 -or $object.reparse_tag -ne 0 -or
            (($object.attributes -band 16) -ne 0) -ne ($index -eq 0) -or
            $aces.Count -ne 2 -or $aces[0].type -ne 0 -or
            $aces[0].flags -ne 0 -or $aces[0].sid -ne 'S-1-5-18' -or
            $aces[1].type -ne 0 -or $aces[1].flags -ne 0 -or
            $aces[1].sid -ne $sid -or $aces[0].access_mask -le 0 -or
            $aces[0].access_mask -ne $aces[1].access_mask) {
            $stageFactsValid = $false
        }
    }
    $publication = $anchors.publication_probe
    $publicationFactsValid = $false
    if ($publication -and $publication.prepared_record -and
        $publication.bound_record) {
        $prepared = $publication.prepared_record | ConvertFrom-Json
        $bound = $publication.bound_record | ConvertFrom-Json
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $preparedHash = [BitConverter]::ToString($sha.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes($publication.prepared_record))).
                Replace('-', '').ToLowerInvariant()
            $boundHash = [BitConverter]::ToString($sha.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes($publication.bound_record))).
                Replace('-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
        $publicationFactsValid =
            $publication.source_file_id -eq $staged.root.file_id -and
            $publication.former_name -eq $staged.root.native_name -and
            $publication.visible_name -eq
                ($anchors.objects.destination.native_name + '\visible') -and
            $publication.visible_root.file_id -eq $staged.root.file_id -and
            $publication.visible_root.native_name -eq $publication.visible_name -and
            $publication.visible_file.file_id -eq $staged.file.file_id -and
            $publication.visible_file.native_name -eq
                ($publication.visible_name + '\payload.bin') -and
            $publication.visible_payload_sha256 -eq $staged.sha256 -and
            $prepared.phase -eq 'lab_prepared_summary' -and
            $prepared.service_sid -eq $sid -and
            $prepared.source_file_id -eq $staged.root.file_id -and
            $prepared.volume_serial -eq $native.volume_file_id_serial -and
            $prepared.destination_parent_file_id -eq $anchors.destination_file_id -and
            $prepared.destination_name -eq 'visible' -and
            $prepared.payload_sha256 -eq $staged.sha256 -and
            $bound.phase -eq 'lab_visible_summary' -and
            $bound.source_file_id -eq $staged.root.file_id -and
            $bound.destination_parent_file_id -eq $anchors.destination_file_id -and
            $bound.destination_name -eq 'visible' -and
            $bound.payload_sha256 -eq $staged.sha256 -and
            $publication.prepared_sha256 -eq $preparedHash -and
            $publication.bound_sha256 -eq $boundHash -and
            $publication.journal_root.file_id -eq $anchors.journal_file_id -and
            $publication.journal_root.native_name -eq
                $anchors.objects.journal.native_name -and
            $publication.prepared_file.native_name -eq
                ($publication.journal_root.native_name + '\lab-prepared-summary.json') -and
            $publication.bound_file.native_name -eq
                ($publication.journal_root.native_name + '\lab-visible-summary.json') -and
            @($anchorIds + @($staged.root.file_id, $staged.file.file_id,
                $publication.prepared_file.file_id, $publication.bound_file.file_id) |
                Sort-Object -Unique).Count -eq 10
        foreach ($object in @($publication.visible_root, $publication.visible_file,
                $publication.journal_root, $publication.prepared_file,
                $publication.bound_file)) {
            $aces = @($object.dacl_aces)
            if (-not $object -or $object.owner_sid -ne 'S-1-5-18' -or
                -not $object.dacl_protected -or $object.link_count -ne 1 -or
                ($object.attributes -band 1024) -ne 0 -or $object.reparse_tag -ne 0 -or
                $aces.Count -ne 2 -or $aces[0].type -ne 0 -or
                $aces[0].flags -ne 0 -or $aces[0].sid -ne 'S-1-5-18' -or
                $aces[1].type -ne 0 -or $aces[1].flags -ne 0 -or
                $aces[1].sid -ne $sid -or $aces[0].access_mask -le 0 -or
                $aces[0].access_mask -ne $aces[1].access_mask) {
                $publicationFactsValid = $false
            }
        }
    }
    if ($native.status -ne 'pass' -or $native.service_sid -ne $sid -or
        $native.service_sid_type -ne 3 -or $native.service_type -ne 16 -or
        $native.process_user_sid -ne 'S-1-5-18' -or
        $native.thread_impersonating -or
        $native.volume_root -ne $VolumeRoot -or
        $native.volume_filesystem -ne 'NTFS' -or
        $enabled.Count -ne 1 -or $restricting.Count -ne 1 -or
        -not $anchorFactsValid -or -not $stageFactsValid -or
        -not $publicationFactsValid -or
        @($anchorIds | Where-Object { -not $_ }).Count -ne 0 -or
        @($anchorIds | Sort-Object -Unique).Count -ne 6 -or
        -not $scm -or $scm.ServiceType -ne 'Own Process' -or
        $scm.StartName -ne 'LocalSystem' -or
        $scm.ProcessId -ne $native.process_id) {
        throw 'native and independent SCM observations disagree'
    }
    $receipt.service_process_id = $scm.ProcessId
    $receipt.native_observation = $native
    $receipt.status = 'protected_publish_observed'
} catch {
    $failure = $_.Exception.Message
    $receipt.failure = $failure
    $receipt.status = 'failed'
    if (Test-Path -LiteralPath $serviceReceipt -PathType Leaf) {
        try {
            $receipt.native_observation = Get-Content -LiteralPath $serviceReceipt -Raw |
                ConvertFrom-Json
        } catch {}
    }
} finally {
    if ($created) {
        try {
            $running = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($running -and $running.Status -ne 'Stopped') {
                Stop-Service -Name $serviceName -ErrorAction Stop
                (Get-Service -Name $serviceName).WaitForStatus('Stopped',
                    [TimeSpan]::FromSeconds(30))
            }
            & sc.exe delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'SCM service deletion failed' }
            $receipt.cleanup = 'owned service stopped and deletion requested; runner VM disposes remaining files'
        } catch {
            $receipt.cleanup = 'failed: ' + $_.Exception.Message
            if (-not $failure) { $failure = 'owned service cleanup failed' }
        }
    } else {
        $receipt.cleanup = 'no service was created'
    }
    $receipt['completed_utc'] = [DateTime]::UtcNow.ToString('o')
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $out -Encoding UTF8
}
if ($failure) { throw $failure }
Write-Output "WU-006 disposable restricted service probe passed: $out"
