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
function Assert-IndependentMetadataProbe {
    param($Result)
    if ($Result.native.status -ne 'pass' -or -not $Result.observer_task_removed -or
        $Result.independent.identity -ne 'S-1-5-18') { throw 'Service, observer identity or confirmed task cleanup differs' }
    foreach ($row in $Result.independent.rows) {
        if ($row.owner -ne 'S-1-5-18' -or -not $row.protected -or $row.aces.Count -ne 2 -or
            @($row.aces|Where-Object sid -eq 'S-1-5-18').Count -ne 1 -or
            @($row.aces|Where-Object sid -eq $Result.service_sid).Count -ne 1 -or
            @($row.aces|Where-Object { $_.rights -ne 2032127 -or $_.type -ne 'Allow' -or
                $_.inherited -or $_.inheritance -ne 0 -or $_.propagation -ne 0 }).Count -ne 0) {
            throw ('Independent owner/DACL differs: ' + $row.path)
        }
    }
    function Get-ExactRecord([string]$Path) {
        $found=@($Result.independent.rows|Where-Object { $_.path -ceq $Path -and -not $_.directory })
        if ($found.Count -ne 1 -or -not $found[0].content_json) { throw ('Missing independent record: ' + $Path) }
        $found[0].content_json | ConvertFrom-Json
    }
    $snapshot=Get-ExactRecord 'E:\publication\journal\lab-reviewed-plan.json'
    $completion=Get-ExactRecord 'E:\publication\state\lab-installed-state.json'
    $completionRow=@($Result.independent.rows|Where-Object path -ceq 'E:\publication\state\lab-installed-state.json')[0]
    if ($snapshot.plan_digest -ne $Result.plan.plan_digest -or $snapshot.archive_sha256 -ne $Result.archive_sha256 -or
        $completion.source_binding.reviewed_plan_digest -ne $snapshot.plan_digest) { throw 'Independent reviewed source binding differs' }
    $transaction=$snapshot.transaction_id
    $installId=$Result.request.install_id
    $installedPath='E:\setup-state\state\installed\' + $installId + '.' + $transaction + '.json'
    $installed=Get-ExactRecord $installedPath
    $ownershipPath='E:\setup-state\state\' + $installed.ownership_manifest_ref.Replace('/','\')
    $ownership=Get-ExactRecord $ownershipPath
    $marker=Get-ExactRecord 'E:\setup-state\.usk-owned-root.v1.json'
    $auditRoot='E:\setup-state\audit\chains\' + $installed.audit_chain_id + '\'
    $validatedPath=$auditRoot+'00000000000000000000.event.json'
    $completedPath=$auditRoot+'00000000000000000001.event.json'
    $validated=Get-ExactRecord $validatedPath
    $completed=Get-ExactRecord $completedPath
    $publicFiles=@($Result.independent.rows|Where-Object { -not $_.directory -and $_.path.StartsWith('E:\setup-state\',[StringComparison]::Ordinal) })
    $expected=@('E:\setup-state\.usk-owned-root.v1.json',$installedPath,$ownershipPath,$validatedPath,$completedPath)
    if ($publicFiles.Count -ne 5 -or @($publicFiles|Where-Object {$_.path -cnotin $expected}).Count -ne 0) { throw 'Independent public record closure differs' }
    $target=$Result.plan.target.root.Replace('/','\')
    if ($marker.schema -ne 'usk.setup_owned_root.v1' -or $marker.acceptance_root.Replace('/','\') -cne 'E:\' -or
        $installed.schema -ne 'usk.installed_state.v1' -or $installed.install_id -ne $installId -or
        $installed.transaction_id -ne $transaction -or $installed.created_at -ne $snapshot.applied_at -or
        $installed.target_root.Replace('/','\') -cne $target -or $installed.source_archive_digest -ne $Result.archive_sha256 -or
        $installed.recipe_digest -ne $Result.request.recipe.recipe_digest -or $installed.product_id -ne $Result.request.recipe.product_id -or
        $installed.product_version -ne $Result.request.recipe.product_version -or $installed.lifecycle_status -ne 'installed' -or
        ($installed.component_selection|ConvertTo-Json -Compress) -cne ($Result.request.recipe.components|ConvertTo-Json -Compress) -or
        $ownership.schema -ne 'usk.ownership_manifest.v1' -or $ownership.install_id -ne $installId -or
        $ownership.created_by_transaction_id -ne $transaction -or $ownership.target_root.Replace('/','\') -cne $target -or
        $ownership.manifest_digest -ne $installed.ownership_manifest_digest -or
        $installed.ownership_manifest_ref -cne ('ownership/'+$ownership.manifest_id+'.json') -or
        $installed.last_verification.status -ne 'pass') { throw 'Independent installed/ownership/marker binding differs' }
    if ($validated.phase -ne 'validated' -or $validated.status -ne 'pass' -or $validated.sequence -ne 0 -or
        $validated.details_digest -ne $completionRow.sha256 -or $validated.subject.subject_id -ne $Result.plan.plan_id -or
        $validated.subject.subject_type -ne 'journal' -or $null -ne $validated.previous_event_digest -or
        $completed.phase -ne 'completed' -or $completed.status -ne 'pass' -or $completed.sequence -ne 1 -or
        $completed.previous_event_digest -ne $validated.event_digest -or $completed.subject.subject_id -ne $installId -or
        $completed.subject.subject_type -ne 'installation' -or
        $completed.details_digest -ne $installed.last_verification.report_digest) { throw 'Independent audit linkage differs' }
    foreach ($event in @($validated,$completed)) {
        if ($event.schema -ne 'usk.audit_event.v1' -or $event.operation -ne 'install_local' -or
            $event.transaction_id -ne $transaction -or $event.plan_id -ne $Result.plan.plan_id -or
            $event.created_at -ne $snapshot.applied_at -or $event.audit_chain_id -ne $installed.audit_chain_id) {
            throw 'Independent audit operation binding differs'
        }
    }
    $entries=@($Result.plan.planned_entries|Where-Object entry_type -eq file)
    if ($ownership.files.Count -ne $entries.Count) { throw 'Independent ownership file count differs' }
    foreach ($entry in $entries) {
        $path='E:\publication\destination\visible\'+$entry.relative_path.Replace('/','\')
        $found=@($Result.independent.rows|Where-Object path -ceq $path)
        $owned=@($ownership.files|Where-Object relative_path -ceq $entry.relative_path)
        if ($found.Count -ne 1 -or $owned.Count -ne 1 -or $found[0].sha256 -ne $entry.sha256 -or
            $found[0].bytes -ne $entry.size_bytes -or $owned[0].sha256 -ne $entry.sha256 -or $owned[0].size_bytes -ne $entry.size_bytes) {
            throw ('Independent selected payload/ownership differs: ' + $path)
        }
    }
}
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
    $volume,$guestService,$serviceSha,$guestMachine,$machineSha,$guestArchive,$archiveSha,$runId -ScriptBlock {
    param($Volume,$Binary,$BinarySha,$Machine,$MachineSha,$Archive,$ArchiveSha,$RunId)
    $ErrorActionPreference = 'Stop'
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
    $template.payload.archive.strip_prefix = 'pkg/'
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
        # A separately launched SYSTEM observer reads original file bytes and
        # security descriptors, independently of the restricted-service writer.
        $observerName = 'USK_METADATA_OBSERVER_' + $RunId
        $observerPath = 'C:\USK-Lab\metadata-observer-' + $RunId + '.ps1'
        $observerOutput = 'C:\USK-Lab\metadata-observed-' + $RunId + '.json'
        $observer = @'
param([string]$Output)
$ErrorActionPreference='Stop'
$rows=[Collections.Generic.List[object]]::new()
$pending=[Collections.Generic.Stack[object]]::new()
foreach($top in @('E:\setup-state','E:\publication')) {
 $pending.Push((Get-Item -LiteralPath $top -Force))
 while($pending.Count -gt 0) {
  $p=$pending.Pop()
  if(($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected readback link' }
  if($rows.Count -ge 10000 -or (-not $p.PSIsContainer -and $p.Extension -eq '.json' -and $p.Length -gt 16MB)) {throw 'Independent readback exceeds its record budget'}
  $a=Get-Acl -LiteralPath $p.FullName
  $aces=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
   [ordered]@{sid=$_.IdentityReference.Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}
  })
  $rows.Add([ordered]@{path=$p.FullName;directory=$p.PSIsContainer;owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;protected=$a.AreAccessRulesProtected;aces=$aces;
   bytes= $(if($p.PSIsContainer){0}else{$p.Length});sha256=$(if($p.PSIsContainer){$null}else{(Get-FileHash -LiteralPath $p.FullName -Algorithm SHA256).Hash.ToLowerInvariant()});
   content_json=$(if(-not $p.PSIsContainer -and $p.Extension -eq '.json'){[IO.File]::ReadAllText($p.FullName)}else{$null})})
  if($p.PSIsContainer){foreach($child in Get-ChildItem -LiteralPath $p.FullName -Force){$pending.Push($child)}}
 }
}
$result=[ordered]@{schema='usk.publisher.metadata_independent_readback.v1';identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rows=$rows;observed_utc=[DateTime]::UtcNow.ToString('o')}
[IO.File]::WriteAllText($Output,($result|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
'@
        [IO.File]::WriteAllText($observerPath,$observer,$utf8)
        if (Get-ScheduledTask -TaskName $observerName -ErrorAction SilentlyContinue) { throw 'Observer task collision' }
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -File "' + $observerPath + '" -Output "' + $observerOutput + '"')
        try {
            Register-ScheduledTask -TaskName $observerName -Action $action -User SYSTEM -RunLevel Highest | Out-Null
            Start-ScheduledTask -TaskName $observerName
            $deadline=[DateTime]::UtcNow.AddSeconds(60)
            while (-not (Test-Path -LiteralPath $observerOutput) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
            if (-not (Test-Path -LiteralPath $observerOutput)) { throw 'Independent observer receipt absent' }
            $observation = Get-Content -LiteralPath $observerOutput -Raw | ConvertFrom-Json
        } finally {
            $task=Get-ScheduledTask -TaskName $observerName -ErrorAction SilentlyContinue
            if($task){
                if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $observerName -ErrorAction Stop}
                Unregister-ScheduledTask -TaskName $observerName -Confirm:$false -ErrorAction Stop
            }
            if(Get-ScheduledTask -TaskName $observerName -ErrorAction SilentlyContinue){throw 'Owned SYSTEM observer cleanup failed'}
        }
    }
    [ordered]@{schema='usk.publisher.metadata_vm_probe.v1';vm_id=$vmId;os_build=[Environment]::OSVersion.Version.ToString();
        disk_unique_id=$disk.UniqueId;volume_guid_root=$Volume.volume_guid_root;service=$serviceName;service_sid=$sid;
        binary_sha256=$BinarySha;machine_sha256=$MachineSha;archive_sha256=$ArchiveSha;strip_prefix='pkg/';
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
