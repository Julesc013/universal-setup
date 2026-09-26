# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$LabRoot,
    [Parameter(Mandatory=$true)][string]$BuildRoot,
    [Parameter(Mandatory=$true)][string]$VolumeReceipt,
    [Parameter(Mandatory=$true)][string]$ArchivePath,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
$vmName = 'USK-R4-VM-709329F7'
$vmId = '6a23c3f9-272c-4711-b846-152f82bf93d2'
$lab = [IO.Path]::GetFullPath($LabRoot)
$volume = Get-Content -LiteralPath $VolumeReceipt -Raw | ConvertFrom-Json
$vm = Get-VM -Name $vmName
if ($vm.Id.ToString() -ne $vmId -or $volume.vm_id -ne $vmId -or
    $vm.State -ne 'Off' -or -not $env:FACMAN_TASK_ROOT -or
    -not $vm.ConfigurationLocation.StartsWith($lab + '\',[StringComparison]::OrdinalIgnoreCase) -or
    $vm.AutomaticCheckpointsEnabled -or (Get-VMMemory -VM $vm).Maximum -gt 2GB) {
    throw 'Exact owned, stopped, memory-bounded campaign VM required'
}
if (Test-Path -LiteralPath $OutputPath) { throw 'Proof receipt collision' }
function Invoke-GuestCommand {
    param([scriptblock]$ScriptBlock,[object[]]$ArgumentList=@(),[int]$TimeoutSeconds=150)
    # Use a local Windows PowerShell process for its installed Direct transport,
    # avoiding a second remote runspace and its ScriptBlock serialization. The
    # child reads the existing DPAPI credential; no key or policy is changed.
    $code = @'
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'BLACKGLASS-WIN1\Jules'){throw 'Expected user context required'}
$credential=Import-Clixml -LiteralPath $env:FACMAN_PROBE_CREDENTIAL_FILE
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:FACMAN_PROBE_SCRIPT))
$arguments=[System.Management.Automation.PSSerializer]::Deserialize($env:FACMAN_PROBE_ARGUMENTS)
$result=Invoke-Command -VMName $env:FACMAN_PROBE_VM_NAME -Credential $credential -ScriptBlock ([scriptblock]::Create($source)) -ArgumentList $arguments
[Console]::WriteLine([System.Management.Automation.PSSerializer]::Serialize($result,64))
'@
    $start = [Diagnostics.ProcessStartInfo]::new('powershell.exe')
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    foreach($arg in @('-NoProfile','-NonInteractive','-Command',$code)) { $start.ArgumentList.Add($arg) }
    $start.Environment['FACMAN_PROBE_CREDENTIAL_FILE']=Join-Path $lab 'guest-credential.dpapi.xml'
    $start.Environment['FACMAN_PROBE_VM_NAME']=$vmName
    $start.Environment['FACMAN_PROBE_SCRIPT']=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ScriptBlock.ToString()))
    $start.Environment['FACMAN_PROBE_ARGUMENTS']=[System.Management.Automation.PSSerializer]::Serialize($ArgumentList,64)
    $child=[Diagnostics.Process]::Start($start)
    try {
        $output=$child.StandardOutput.ReadToEndAsync()
        $errorOutput=$child.StandardError.ReadToEndAsync()
        if(-not $child.WaitForExit($TimeoutSeconds*1000)){ $child.Kill($true); throw 'Guest Direct operation timed out' }
        if($child.ExitCode -ne 0){throw $errorOutput.Result}
        [System.Management.Automation.PSSerializer]::Deserialize($output.Result)
    } finally {
        if(-not $child.HasExited){$child.Kill($true);$child.WaitForExit()}
        $child.Dispose()
    }
}
$serviceBinary = Join-Path $BuildRoot 'Release\usk_publisher_lab_service.exe'
$machineBinary = Join-Path $BuildRoot 'Release\usk_machine.exe'
$serviceSha = (Get-FileHash -LiteralPath $serviceBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$machineSha = (Get-FileHash -LiteralPath $machineBinary -Algorithm SHA256).Hash.ToLowerInvariant()
$archiveSha = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
$runId = [guid]::NewGuid().ToString('N')
$guestService = 'C:\USK-Lab\bin\usk_publisher_lab_service_metadata_' + $serviceSha.Substring(0,12) + '.exe'
$guestMachine = 'C:\USK-Lab\bin\usk_machine_metadata_' + $machineSha.Substring(0,12) + '.exe'
$guestArchive = 'C:\USK-Lab\selected-prefixed-' + $archiveSha.Substring(0,12) + '.zip'
Start-VM -VM $vm | Out-Null
Write-Output 'stage=owned_vm_started; waiting_for_verified_guest'
$deadline = [DateTime]::UtcNow.AddSeconds(90)
while ($true) {
    try {
        $ready = Invoke-GuestCommand -TimeoutSeconds 30 -ScriptBlock {
            (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters').VirtualMachineId
        }
        if ($ready -ine $vmId) { throw 'Guest identity differs' }
        break
    } catch { if ([DateTime]::UtcNow -ge $deadline) { throw }; Start-Sleep -Seconds 2 }
}
Write-Output 'stage=verified_guest_ready; copying_digest_bound_inputs'
foreach ($pair in @(@($serviceBinary,$guestService),@($machineBinary,$guestMachine),@($ArchivePath,$guestArchive))) {
    Copy-VMFile -VM $vm -SourcePath $pair[0] -DestinationPath $pair[1] -FileSource Host -CreateFullPath -Force
}
Write-Output 'stage=guest_plan_and_restricted_service_operation'
$result = Invoke-GuestCommand -ArgumentList `
    $volume,$guestService,$serviceSha,$guestMachine,$machineSha,$guestArchive,$archiveSha,$runId,([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1'))) -ScriptBlock {
    param($Volume,$Binary,$BinarySha,$Machine,$MachineSha,$Archive,$ArchiveSha,$RunId,$ReadbackFunctions)
    $ErrorActionPreference = 'Stop'
    . ([scriptblock]::Create($ReadbackFunctions))
    $vmId = '6a23c3f9-272c-4711-b846-152f82bf93d2'
    $serviceName = 'USK_VM_246a60474dc94475bf617c7da8d09b58'
    $sid = 'S-1-5-80-218465820-1252995847-723511090-1583053768-1586712674'
    # A guest restart can detach its file-backed VHD. Reattach only the exact
    # retained image, then verify the original disk/volume before assigning E.
    # This creates no disk, partition or filesystem.
    if (-not $Volume.vhd_path.StartsWith('C:\USK-Lab\publisher-test-',[StringComparison]::Ordinal) -or
        -not $Volume.vhd_path.EndsWith('.vhdx',[StringComparison]::Ordinal) -or
        ((Get-Item -LiteralPath $Volume.vhd_path).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Retained guest VHD path differs'
    }
    $image=Get-DiskImage -ImagePath $Volume.vhd_path
    if(-not $image.Attached){Mount-DiskImage -ImagePath $Volume.vhd_path -NoDriveLetter|Out-Null}
    $disk = Get-DiskImage -ImagePath $Volume.vhd_path | Get-Disk
    if($disk.UniqueId -ne $Volume.disk_unique_id -or $disk.IsBoot -or $disk.IsSystem){throw 'Retained guest disk identity differs'}
    $partitions=@($disk|Get-Partition|Where-Object Type -eq Basic)
    if($partitions.Count -ne 1){throw 'Retained guest partition shape differs'}
    $retained=Get-Volume -Partition $partitions[0]
    if($retained.UniqueId -ne $Volume.volume_guid_root -or $retained.FileSystem -ne 'NTFS'){throw 'Retained guest volume identity differs'}
    $letter=Get-Volume -DriveLetter E -ErrorAction SilentlyContinue
    if($letter -and $letter.UniqueId -ne $retained.UniqueId){throw 'Guest E is occupied by another volume'}
    if(-not $letter){$partitions[0]|Set-Partition -NewDriveLetter E}
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters').VirtualMachineId -ine $vmId -or
        $disk.UniqueId -ne $Volume.disk_unique_id -or $disk.IsBoot -or $disk.IsSystem -or
        (Get-Volume -DriveLetter E).UniqueId -ne $Volume.volume_guid_root -or
        $service.State -ne 'Stopped' -or $service.ServiceType -ne 'Own Process' -or $service.StartName -ne 'LocalSystem' -or
        (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName").ServiceSidType -ne 3) {
        throw 'Owned guest disk/service configuration differs'
    }
    foreach ($pair in @(@($Binary,$BinarySha),@($Machine,$MachineSha),@($Archive,$ArchiveSha))) {
        if ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pair[1]) {
            throw 'Copied input digest differs'
        }
    }
    if (Test-Path -LiteralPath 'E:\publication') { throw 'Fresh retained test disk already has publication material' }
    $utf8 = [Text.UTF8Encoding]::new($false)
    $requestPath = 'C:\USK-Lab\metadata-request-' + $RunId + '.json'
    $contextPath = 'C:\USK-Lab\metadata-context-' + $RunId + '.json'
    $envelopePath = 'C:\USK-Lab\plan-metadata-' + $RunId + '.json'
    $nativePath = 'C:\USK-Lab\vm-selected-' + $RunId + '.json'
    foreach ($p in @($requestPath,$contextPath,$envelopePath,$nativePath)) {
        if (Test-Path -LiteralPath $p) { throw 'Guest proof output collision' }
    }
    $template = Get-Content -LiteralPath 'C:\USK-Lab\selected-state12-template-f2460e36b6074ea284273434e5ce7c2c.json' -Raw | ConvertFrom-Json
    $template.request_id = 'metadata.' + $RunId
    $template.payload.request_id = $template.request_id
    $template.payload.install_id = 'org.example.metadata.probe'
    $template.payload.created_at = [DateTime]::UtcNow.AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $template.payload.archive.path = $Archive
    $template.payload.archive.expected_sha256 = $ArchiveSha
    $template.payload.archive.strip_prefix = 'pkg'
    [IO.File]::WriteAllText($requestPath,($template | ConvertTo-Json -Depth 32 -Compress) + "`n",$utf8)
    [IO.File]::WriteAllText($contextPath,(@{schema='usk.oneshot_context.v1';state_root='E:\setup-state';
        authorized_acceptance_root='E:\';target_policy_activation='operator_acceptance_candidate'} | ConvertTo-Json -Compress) + "`n",$utf8)
    $output = & $Machine --machine --request-file $requestPath --context-file $contextPath 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Native plan failed: ' + ($output -join '; ')) }
    $response = ($output -join "`n") | ConvertFrom-Json
    $plan = $response.result.payload
    if ($response.status -ne 'ok' -or $response.result.status -ne 'ok' -or
        $plan.required_commit_authority -ne 'staged_child_bound_v1' -or $plan.commit_authority_available -ne $false) {
        throw 'Native strict plan differs'
    }
    [IO.File]::WriteAllText($envelopePath,([ordered]@{schema='usk.publisher.lab_reviewed_plan_envelope.v1';
        activation='operator_acceptance_candidate';acceptance_root='E:\';state_root='E:\setup-state';
        reviewed_plan_digest=$plan.plan_digest;plan_request=$template.payload} | ConvertTo-Json -Depth 32 -Compress) + "`n",$utf8)
    $account = [Security.Principal.SecurityIdentifier]::new($sid)
    foreach ($p in @($Binary,$Archive,$envelopePath)) {
        $acl = Get-Acl -LiteralPath $p
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account,'ReadAndExecute','Allow'))
        Set-Acl -LiteralPath $p -AclObject $acl
    }
    # Only the verified disposable guest VHD root is configured. The complete
    # original root descriptor is retained; no physical or host ACL is touched.
    $rootAclBefore = (Get-Acl -LiteralPath $Volume.volume_guid_root).Sddl
    $rootAcl = [Security.AccessControl.DirectorySecurity]::new()
    $rootAcl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;' + $sid + ')')
    Set-Acl -LiteralPath $Volume.volume_guid_root -AclObject $rootAcl
    $device = & 'C:\USK-Lab\bin\usk_publisher_lab_device_acl_static.exe' --owned-vm-vhd-volume `
        $Volume.volume_guid_root $serviceName ([int]$disk.Number) $Volume.vhd_path $vmId 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Owned VHD device ACL failed: ' + ($device -join '; ')) }
    $envelopeSha = (Get-FileHash -LiteralPath $envelopePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $image = '"' + $Binary + '" --service ' + $serviceName + ' "' + $nativePath + '" ' +
        $Volume.volume_guid_root + ' --selected-zip "' + $Archive + '" ' + $ArchiveSha +
        ' --campaign-vm-id ' + $vmId + ' --reviewed-plan-envelope "' + $envelopePath + '" ' + $envelopeSha
    & sc.exe config $serviceName binPath= $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Owned service command setup failed' }
    try { Start-Service -Name $serviceName } catch { if ((Get-Service $serviceName).Status -ne 'Stopped') { throw } }
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    while (-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path -LiteralPath $nativePath)) { throw 'Native service receipt absent' }
    $native = Get-Content -LiteralPath $nativePath -Raw | ConvertFrom-Json
    if ((Get-Service $serviceName).Status -eq 'Running') { Stop-Service -Name $serviceName }
    $observation = $null
    if ($native.status -eq 'pass') {
        $readback=Invoke-IndependentMetadataReadback -DriveRoot 'E:\' -OutputRoot 'C:\USK-Lab' -RunId $RunId
        $observation=$readback.independent
    }
    [ordered]@{schema='usk.publisher.metadata_vm_probe.v1';vm_id=$vmId;os_build=[Environment]::OSVersion.Version.ToString();
        disk_unique_id=$disk.UniqueId;volume_guid_root=$Volume.volume_guid_root;volume_drive_root='E:\';service=$serviceName;service_sid=$sid;
        binary_sha256=$BinarySha;machine_sha256=$MachineSha;archive_sha256=$ArchiveSha;strip_prefix='pkg';
        envelope_sha256=$envelopeSha;request=$template.payload;plan=$plan;native=$native;independent=$observation;root_acl_before=$rootAclBefore;
        native_receipt=$nativePath;native_receipt_sha256=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant();
        observer_task_removed=($null -eq (Get-ScheduledTask -TaskName ('USK_METADATA_OBSERVER_' + $RunId) -ErrorAction SilentlyContinue));
        observed_utc=[DateTime]::UtcNow.ToString('o')}
}
$result | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Assert-IndependentMetadataProbe $result
[ordered]@{status='pass';receipt=$OutputPath;selected_files=@($result.plan.planned_entries|Where-Object entry_type -eq file).Count;
    independently_observed_objects=$result.independent.rows.Count;binary_sha256=$serviceSha} | ConvertTo-Json -Compress
# The caller owns exact-VM shutdown in an outer finally, including child
# cancellation. This probe must run through that resource-budgeted wrapper.
