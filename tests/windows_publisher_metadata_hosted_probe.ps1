# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$DeviceAclBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
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
function Assert-OwnedVolume {
    $liveImage=Get-DiskImage -ImagePath $vhd
    $live=@($liveImage|Get-Disk)
    if(-not $liveImage.Attached -or $live.Count -ne 1 -or $live[0].Path -ne $disk.Path -or
        $live[0].UniqueId -ne $disk.UniqueId -or $live[0].IsBoot -or $live[0].IsSystem -or
        (Get-Volume -DriveLetter $partitions[0].DriveLetter).UniqueId -ne $VolumeRoot) {
        throw 'Owned VHD changed before privileged operation'
    }
}
$vmId=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters').VirtualMachineId
if($vmId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw 'Observed hosted VM identity unavailable' }
$id=[guid]::NewGuid().ToString('N')
$service='USK_VM_'+$id
$root='C:\USK-Lab'
if(Test-Path -LiteralPath $root){throw 'Unexpected existing hosted campaign input root'}
New-Item -ItemType Directory -Path $root|Out-Null
$fixture=Join-Path $root ('metadata-inputs-'+$id)
New-Item -ItemType Directory -Path $fixture|Out-Null
$nativePath=Join-Path $root ('vm-selected-'+$id+'.json')
$archive=Join-Path $root ('selected-'+$id+'.zip')
$envelope=Join-Path $root ('plan-'+$id+'.json')
$out=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $out){throw 'Metadata receipt collision'}
$receipt=[ordered]@{schema='usk.publisher.metadata_vm_probe.v1';status='not_run';vm_id=$vmId;
    runner_environment=$env:RUNNER_ENVIRONMENT;os_build=[Environment]::OSVersion.Version.ToString();
    disk_unique_id=$disk.UniqueId;volume_guid_root=$VolumeRoot;volume_drive_root=$drive;service=$service;
    service_sid=$null;binary_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    archive_sha256=$null;strip_prefix='pkg';request=$null;plan=$null;native=$null;independent=$null;
    observer_task_removed=$false;service_removed=$false;failure=$null;power_loss_test=$false}
$created=$false
$failure=$null
try {
    Assert-OwnedVolume
    if(Test-Path -LiteralPath ($drive+'publication')){throw 'Hosted metadata disk is not fresh'}
    $generated=& python -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $fixture --target ($drive+'publication\destination\visible') --request-id ('metadata.'+$id)
    if($LASTEXITCODE -ne 0){throw 'Public authoring input generation failed'}
    $inputs=$generated|ConvertFrom-Json
    Copy-Item -LiteralPath $inputs.archive_file -Destination $archive
    $request=Get-Content -LiteralPath $inputs.request_file -Raw|ConvertFrom-Json
    $request.payload.archive.path=$archive
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
    $applyRequest=[ordered]@{schema='usk.install_local_apply_request.v1';plan_request=$request.payload;
        reviewed_plan_id=$plan.plan_id;reviewed_plan_digest=$plan.plan_digest;transaction_id='install.'+$id;
        applied_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ');confirmation='APPLY'}
    $receipt['apply_request']=$applyRequest
    # The identical ordinary request must refuse outside the admitted service,
    # before creating payload or setup state. No public activation mints authority.
    $ordinaryPath=Join-Path $root ('ordinary-apply-'+$id+'.json')
    [IO.File]::WriteAllText($ordinaryPath,([ordered]@{schema='usk.oneshot_request.v1';
        request_id='apply.'+$id;command='install_local.apply';payload=$applyRequest;dry_run=$false}|
        ConvertTo-Json -Depth 32 -Compress)+"`n",$utf8)
    $ordinary=& $MachineBinary --machine --request-file $ordinaryPath --context-file $contextPath 2>&1
    $receipt['ordinary_apply_exit_code']=$LASTEXITCODE
    $receipt['ordinary_apply_response']=($ordinary -join "`n")|ConvertFrom-Json
    if($receipt.ordinary_apply_exit_code -eq 0 -or ($ordinary -join "`n") -notmatch 'commit_authority_unavailable' -or
        (Test-Path -LiteralPath ($drive+'setup-state')) -or (Test-Path -LiteralPath ($drive+'publication'))) {
        throw 'Ordinary apply did not refuse before mutation outside the service'
    }
    [IO.File]::WriteAllText($envelope,([ordered]@{schema='usk.publisher.lab_reviewed_plan_envelope.v2';
        activation='operator_acceptance_candidate';acceptance_root=$drive;state_root=$drive+'setup-state';
        reviewed_plan_digest=$plan.plan_digest;plan_request=$request.payload;apply_request=$applyRequest}|
        ConvertTo-Json -Depth 32 -Compress)+"`n",$utf8)
    $receipt['envelope_sha256']=(Get-FileHash -LiteralPath $envelope -Algorithm SHA256).Hash.ToLowerInvariant()
    $command='"'+$ServiceBinary+'" --service '+$service+' "'+$nativePath+'" '+$VolumeRoot+
        ' --selected-zip "'+$archive+'" '+$inputs.archive_sha256+' --campaign-vm-id '+$vmId+
        ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256
    if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Service collision'}
    & sc.exe create $service type= own start= demand obj= LocalSystem binPath= $command|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Owned service creation failed'}
    $created=$true
    & sc.exe sidtype $service restricted|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Restricted service configuration failed'}
    $sid=[Security.Principal.NTAccount]::new('NT SERVICE\'+$service).Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt.service_sid=$sid
    # Only this newly created input directory in the disposable hosted VM is
    # writable by the service. The independent observer lives elsewhere.
    $acl=Get-Acl -LiteralPath $root
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),'Modify',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $root -AclObject $acl
    $configured=Get-CimInstance Win32_Service -Filter "Name='$service'"
    if($configured.ServiceType -ne 'Own Process' -or $configured.StartName -ne 'LocalSystem' -or
        (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$service").ServiceSidType -ne 3) {
        throw 'Effective service configuration differs'
    }
    foreach($path in @($ServiceBinary,$archive,$envelope)) {
        $acl=Get-Acl -LiteralPath $path
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute','Allow'))
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    Assert-OwnedVolume
    $receipt['root_acl_before']=(Get-Acl -LiteralPath $VolumeRoot).Sddl
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$sid+')')
    Set-Acl -LiteralPath $VolumeRoot -AclObject $acl
    Assert-OwnedVolume
    $device=& $DeviceAclBinary --owned-hosted-vm-vhd-volume $VolumeRoot $service ([int]$disk.Number) $vhd $vmId 2>&1
    if($LASTEXITCODE -ne 0){throw ('Owned VHD device ACL failed: '+($device -join '; '))}
    try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
    if(-not (Test-Path -LiteralPath $nativePath)){throw 'Native service receipt absent'}
    $receipt.native=Get-Content -LiteralPath $nativePath -Raw|ConvertFrom-Json
    $receipt['native_receipt_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
    if($receipt.native.status -ne 'pass'){throw ('Native metadata operation failed: '+$receipt.native.error)}
    if($receipt.native.apply_response.status -ne 'ok' -or
        $receipt.native.apply_response.payload.schema -ne 'usk.installed_state.v1' -or
        $receipt.native.apply_response.payload.transaction_id -ne $applyRequest.transaction_id -or
        $receipt.native.apply_response.payload.created_at -ne $applyRequest.applied_at -or
        $receipt.native.apply_response.payload.last_verification.status -ne 'pass') {
        throw 'Protected ordinary apply did not preserve caller identities and verified installed result'
    }
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId $id
    $receipt.independent=$readback.independent;$receipt.observer_task_removed=$readback.observer_task_removed
    Assert-IndependentMetadataProbe ([pscustomobject]$receipt)
    $receipt.status='protected_metadata_observed'
} catch {
    $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'
} finally {
    if($created) {
        try {
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
            & sc.exe delete $service|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned service deletion failed'}
            if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Owned service remains after deletion'}
            $receipt.service_removed=$true
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    $receipt['observed_utc']=[DateTime]::UtcNow.ToString('o')
    $receipt|ConvertTo-Json -Depth 32|Set-Content -LiteralPath $out -Encoding UTF8
    # The existing outer harness dismounts/deletes only its identified VHD.
    # This entire hosted VM is disposable; no workstation resources are used.
}
if($failure){throw $failure}
Write-Output "Protected selected metadata observed: $out"
