# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$ServiceControlBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateSet('none','prepublish','postrename')][string]$PublicationLoss='none',
    [ValidateSet('none','payload_changed','metadata_collision')][string]$PostRenameRefusal='none'
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_production_boundary.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_payload_damage.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_metadata_collision.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_process.ps1')
if($PostRenameRefusal -cne 'none' -and $PublicationLoss -cne 'postrename') {
    throw 'Retained refusal qualification requires the stock postrename loss boundary'
}
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
$invokingProcess=Get-Process -Id $PID
$invokingCreation=$invokingProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$utf8=[Text.UTF8Encoding]::new($false)
$publisherBuild=Split-Path -Parent (Split-Path -Parent ([IO.Path]::GetFullPath($ServiceBinary)))
$publisherProjectPath=Join-Path $publisherBuild 'usk_publisher_windows_static.vcxproj'
$publisherProject=[xml][IO.File]::ReadAllText($publisherProjectPath)
$publisherSdk=@($publisherProject.Project.PropertyGroup.WindowsTargetPlatformVersion|Where-Object {$_}|Select-Object -Unique)
if($publisherSdk.Count -ne 1 -or $publisherSdk[0] -cnotmatch '^10\.0\.[1-9][0-9]*\.0$') {
    throw 'Native execution reconciliation requires the actual selected publisher build SDK'
}
$executionSdk=[string]$publisherSdk[0]
$receipt=[ordered]@{schema='usk.publisher_public_path_probe.v1';status='not_run';
    service=$service;volume_root=$VolumeRoot;volume_drive_root=$drive;publication_loss=$PublicationLoss;postrename_refusal=$PostRenameRefusal;
    partition_layout=@($disk|Get-Partition|Select-Object PartitionNumber,Offset,Size,GptType,MbrType,IsBoot,IsSystem);
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    service_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    client_cleanup_confirmed=$false;machine_client_captures=[Collections.Generic.List[object]]::new();
    execution_build_context=@{windows_sdk=$executionSdk;
        publisher_project_sha256=(Get-FileHash -LiteralPath $publisherProjectPath -Algorithm SHA256).Hash.ToLowerInvariant()};
    execution_readback_reconciliations=[Collections.Generic.List[object]]::new()}
$created=$false
$boundaryObserver=$null
$clientTokenLease=$null
$unrelatedTokenLease=$null
$unrelatedLoginBinding=$null
$unrelatedAccountCreated=$false
$unrelatedAccountName='USKOBS_'+$id.Substring(0,13)
$unrelatedAccountSid=''
$unrelatedObserversClosed=$true
$clientCaptureFile=Join-Path $lab 'public-client-token.json'
$clientCaptureSha256=''
$volumeBoundaryBaseline=''
$installedBinary=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$service+'.exe')
function Write-Json([string]$Path,$Value) {
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
}
function Invoke-PublicCapability([int]$ExpectedExit=0) {
    # Discovery is a separate read-only client. It is excluded from the
    # captured mutation/verification token corpus and requests no execution lease.
    $requestId='capability.'+[guid]::NewGuid().ToString('N')
    $request=Join-Path $lab ($requestId+'.json')
    Write-Json $request ([ordered]@{schema='usk.oneshot_request.v1';request_id=$requestId;
        command='publisher.inspect';payload=@{schema='usk.publisher_capability_request.v1';request_id=$requestId};dry_run=$true})
    $beforeService=Get-CimInstance Win32_Service -Filter "Name='$service'"
    $beforeMetadata=Read-VolumeMetadata
    $recordPaths=@($registrationRecord,$targetIntentPath,$targetAdmittedPath)
    $recordState=@{}
    foreach($path in $recordPaths) {
        $recordState[$path]=if(Test-Path -LiteralPath $path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}else{''}
    }
    $stdout=Join-Path $lab ($requestId+'.stdout');$stderr=$stdout+'.stderr'
    $launch=$null;$process=$null
    try {
        $launch=[UskPublisherPausedClient]::new($MachineBinary,('--machine --publisher '+$service+
            ' --request-file "'+$request+'"'),$stdout,$stderr)
        $process=Get-Process -Id $launch.ProcessId;$null=$process.Handle
        $launch.Resume()
        if(-not $process.WaitForExit(30000)){throw 'Read-only capability client exceeded its deadline'}
        $exit=$process.ExitCode
        $diagnostic=[IO.File]::ReadAllText($stderr)
        if(($ExpectedExit -eq 0 -and $diagnostic.Length) -or
            ($ExpectedExit -ne 0 -and $diagnostic -cnotmatch '\Ausk_machine: request refused\r?\n\z')) {
            $receipt['capability_diagnostic']=[ordered]@{expected_exit=$ExpectedExit;actual_exit=$exit;
                characters=$diagnostic.Length;prefix=$diagnostic.Substring(0,[Math]::Min(256,$diagnostic.Length))}
            throw 'Read-only capability client emitted an unexpected diagnostic'
        }
        $result=[IO.File]::ReadAllText($stdout)|ConvertFrom-Json
    } finally {
        try {
            if($process -and -not $process.HasExited) {
                if($launch -and -not $launch.IsResumed){$launch.Dispose()}
                else {Stop-OwnedPublisherProcessTree $process|Out-Null}
                if(-not $process.WaitForExit(5000)){throw 'Owned capability client remains live'}
            }
        } finally {if($process){$process.Dispose()};if($launch){$launch.Dispose()}}
    }
    $afterService=Get-CimInstance Win32_Service -Filter "Name='$service'"
    if($afterService.State -cne $beforeService.State -or $afterService.ProcessId -ne $beforeService.ProcessId -or
        $afterService.PathName -cne $beforeService.PathName){throw 'Discovery altered the owned SCM registration or state'}
    Assert-VolumeMetadataSnapshot (Read-VolumeMetadata) $beforeMetadata.volume_metadata
    foreach($path in $recordPaths) {
        $after=if(Test-Path -LiteralPath $path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}else{''}
        if($after -cne $recordState[$path]){throw 'Discovery altered a protected registration or admission record'}
    }
    if($exit -ne $ExpectedExit -or $result.schema -cne 'usk.oneshot_response.v1' -or $result.request_id -cne $requestId) {
        throw 'Read-only capability response binding differs'
    }
    if($ExpectedExit -ne 0) {
        if($result.status -cne 'refused' -or $result.result -ne $null -or
            $result.error.code -cne 'publisher_capability_unavailable'){throw 'Unadmitted target discovery was not refused'}
        return $result
    }
    $capability=$result.result
    if($result.status -cne 'ok' -or $result.error -ne $null -or
        @($capability.PSObject.Properties).Count -ne 20 -or
        $capability.schema -cne 'usk.publisher_capability.v1' -or $capability.request_id -cne $requestId -or
        $capability.provider_id -cne 'windows_nt_x64_local_ntfs_service_sid_noreplace_v1' -or
        $capability.implementation -cne 'partial' -or $capability.realization -cne 'restricted_service' -or
        $capability.availability -ne $false -or $capability.required_privilege -cne 'SeBackupPrivilege_and_disk_read' -or
        $capability.permission -cne 'registered_caller_observed' -or $capability.authority -cne 'not_granted_by_discovery' -or
        $capability.qualification -cne 'incomplete' -or $capability.qualification_scope -cne 'registered_target_observation' -or
        $capability.support -cne 'unsupported' -or $capability.recovery_ceiling -cne 'candidate_source_free_restart' -or
        $capability.power_loss_qualified -ne $false -or $capability.revalidation_required_before_effects -ne $true -or
        $capability.execution_lease_held -ne $false -or @($capability.effects).Count -ne 0 -or
        $capability.service_state -ne 1 -or @($capability.platform.PSObject.Properties).Count -ne 5 -or
        $capability.platform.os_family -cne 'Windows NT' -or $capability.platform.native_arch -cne 'x64' -or
        $capability.platform.process_arch -cne 'x64' -or $capability.platform.minimum_windows_build -ne 17763 -or
        $capability.platform.windows_build -ne [int]([Environment]::OSVersion.Version.Build) -or
        @($capability.binding.PSObject.Properties).Count -ne 8 -or
        $capability.binding.service_name -cne $service -or $capability.binding.service_sid -cne $sid -or
        $capability.binding.caller_sid -cne $caller -or $capability.binding.volume_guid_root -cne $VolumeRoot -or
        $capability.binding.binary_sha256 -cne $receipt.service_sha256) {throw 'Capability dimensions or native identities differ'}
    foreach($field in @('registration_sha256','target_sha256','boundary_sha256')) {
        if($capability.binding.$field -cnotmatch '^[0-9a-f]{64}$'){throw 'Capability binding digest is missing or malformed'}
    }
    return $result
}
function Invoke-PublicRequest([string]$Command,$Payload,[int]$ExpectedExit=0) {
    $request=Join-Path $lab ('public-request-'+[guid]::NewGuid().ToString('N')+'.json')
    $requestId='public.'+[guid]::NewGuid().ToString('N')
    Write-Json $request ([ordered]@{schema='usk.oneshot_request.v1';request_id=$requestId;
        command=$Command;payload=$Payload;dry_run=$false})
    if($Command -cin @('install_local.apply','install_local.recover','installed.verify')) {
        Initialize-PublisherMetadataNativeTypes
        if($clientTokenLease) {
            # Every prior observer returned and removed its task before the
            # next request starts. Retire only our matching capture/handles.
            if(-not (Test-Path -LiteralPath $clientCaptureFile -PathType Leaf) -or
                (Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $clientCaptureSha256) {
                throw 'Prior owned client capture changed before retirement'
            }
            $clientTokenLease.Dispose();$script:clientTokenLease=$null
            [IO.File]::Move($clientCaptureFile,(Join-Path $lab ('retired-client-token-'+[guid]::NewGuid().ToString('N')+'.json')))
        }
        $stdout=Join-Path $lab ('public-client-'+[guid]::NewGuid().ToString('N')+'.stdout')
        $stderr=$stdout+'.stderr'
        $client=$null
        $launch=$null
        try {
            $launch=[UskPublisherPausedClient]::new($MachineBinary,('--machine --publisher '+$service+
                ' --request-file "'+$request+'"'),$stdout,$stderr)
            $client=Get-Process -Id $launch.ProcessId
            # Hold the .NET process handle before resume, so even a fast exit
            # retains its exit code instead of relying on a later PID lookup.
            $null=$client.Handle
            $creation=$launch.CreationFileTime
            $script:clientTokenLease=[UskPublisherEffectiveRights]::new($client.Id,$creation,$caller,$sid)
            $capture=$clientTokenLease.CaptureBinding($PID,[long]$invokingCreation,$MachineBinary)
            $capture['client_sha256']=$receipt.machine_sha256
            $capture['request_id']=$requestId;$capture['command']=$Command
            if($unrelatedLoginBinding){$capture['unrelated_local_login']=$unrelatedLoginBinding}
            if(Test-Path -LiteralPath $clientCaptureFile){throw 'Owned machine-client capture file already exists'}
            Write-Json $clientCaptureFile $capture
            $script:clientCaptureSha256=(Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant()
            $receipt['machine_client_capture']=[ordered]@{process_id=$client.Id;creation_file_time=$creation.ToString();
                request_id=$requestId;command=$Command;
                image_path=$capture.client_image_path;image_sha256=$capture.client_sha256;capture_sha256=$clientCaptureSha256;
                captured_while_alive=$true;captured_before_primary_thread_resume=$true;
                initiating_token_id=$capture.initiating_token_id;filtered_token_id=$capture.filtered_token_id}
            $receipt.machine_client_captures.Add($receipt.machine_client_capture)
            $launch.Resume()
            if(-not $client.WaitForExit(120000)){throw 'Owned public machine client exceeded its request deadline'}
            $client.WaitForExit()
            $exit=$client.ExitCode
            if((Get-Item -LiteralPath $stdout).Length -gt 4MB -or (Get-Item -LiteralPath $stderr).Length -gt 64KB) {
                throw 'Owned public machine client output exceeds its bound'
            }
            $output=[IO.File]::ReadAllText($stdout)
            if([IO.File]::ReadAllText($stderr).Length){throw 'Owned public machine client emitted unexpected stderr'}
        } finally {
            try {
                if($client -and -not $client.HasExited){
                    if($launch -and -not $launch.IsResumed){
                        $launch.Dispose()
                        if(-not $client.WaitForExit(5000)){throw 'Never-resumed owned machine client remains live'}
                    } else {Stop-OwnedPublisherProcessTree $client|Out-Null}
                }
            } finally {
                if($client){$client.Dispose()}
                if($launch){$launch.Dispose()}
            }
        }
    } else {
        throw 'Public qualification client command is outside the closed captured set'
    }
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
function Assert-PublicVolumeBoundary($Observation,$Boundary,[string]$DriveRoot,[string]$VolumeRoot,[uint32]$DiskNumber,[long]$PartitionOffset,[long]$PartitionSize,[string]$ServiceSid,$DeviceIntent,[switch]$RequireUnrelated) {
    $root=$Boundary.root
    $prepared=@($Observation.rows|Where-Object path -ceq ($DriveRoot+'publication\journal\lab-prepared-evidence.json'))
    if($prepared.Count -ne 1){throw 'Volume boundary has no retained prepared binding'}
    $expected=($prepared[0].content_json|ConvertFrom-Json).protected_anchors.boundary
    if($root.path -cne $DriveRoot -or $root.file_id -cne $expected.file_id -or $root.native_name -cne '\' -or
        $root.attributes -ne $expected.attributes -or $root.link_count -ne 1 -or $root.case_sensitive -ne $false -or
        @($root.streams).Count -ne 0 -or $root.owner -cne 'S-1-5-18' -or -not $root.protected -or
        @($root.raw_aces).Count -ne 2 -or @($expected.dacl_aces).Count -ne 2) {
        throw 'Independent volume-root namespace boundary differs'
    }
    for($index=0;$index -lt 2;$index++) {
        $a=$root.raw_aces[$index];$b=$expected.dacl_aces[$index]
        if($a.type -ne 0 -or $a.flags -ne 0 -or $a.access_mask -ne 2032127 -or
            $a.sid -cne @('S-1-5-18',$ServiceSid)[$index] -or $a.type -ne $b.type -or $a.flags -ne $b.flags -or
            $a.access_mask -ne $b.access_mask -or $a.sid -cne $b.sid) {
            throw 'Independent volume-root ordered descriptor differs'
        }
    }
    if($boundary.device.path -cne $VolumeRoot.TrimEnd('\') -or $boundary.device.extent.disk_number -ne $DiskNumber -or
        $boundary.device.extent.offset -ne $PartitionOffset -or $boundary.device.extent.length -ne $PartitionSize) {
        throw 'Independent raw-volume extent differs from the owned VHD partition'
    }
    $deviceRaw=[Security.AccessControl.RawSecurityDescriptor]::new($boundary.device.raw_security)
    if($deviceRaw.Owner.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $null -eq $deviceRaw.DiscretionaryAcl) {
        throw 'Independent raw-volume owner or DACL differs'
    }
    $serviceAces=0
    foreach($ace in $deviceRaw.DiscretionaryAcl) {
        if($ace.AceType -ne 0){throw 'Independent raw-volume ACE is unsupported'}
        if($ace.SecurityIdentifier.Value -ceq $ServiceSid) {
            if($ace.AceFlags -ne 0 -or $ace.AccessMask -ne 2032127){throw 'Independent raw-volume service ACE differs'}
            ++$serviceAces
        } elseif($ace.SecurityIdentifier.Value -cnotin @('S-1-5-18','S-1-5-32-544') -and
            ([uint32]([long]$ace.AccessMask -band 0xffffffff) -band 0x500d0156)) {
            throw 'Independent raw-volume descriptor grants mutation outside trusted principals'
        }
    }
    if($serviceAces -ne 1){throw 'Independent raw-volume service grant absent or repeated'}
    $intended=$DeviceIntent.intended_policy
    if($null -eq $intended -or @($intended.PSObject.Properties).Count -ne 3 -or
        $intended.owner -cne $deviceRaw.Owner.Value -or $intended.dacl_protected -ne $true -or
        -not ($deviceRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -or
        @($intended.aces).Count -ne $deviceRaw.DiscretionaryAcl.Count) {
        throw 'Independent mounted device policy differs from the retained bootstrap intent'
    }
    for($index=0;$index -lt $deviceRaw.DiscretionaryAcl.Count;$index++) {
        $actual=$deviceRaw.DiscretionaryAcl[$index];$expected=$intended.aces[$index]
        if(@($expected.PSObject.Properties).Count -ne 4 -or $expected.type -ne [uint32]$actual.AceType -or
            $expected.flags -ne [uint32]$actual.AceFlags -or $expected.sid -cne $actual.SecurityIdentifier.Value -or
            $expected.mask -ne [uint32]([long]$actual.AccessMask -band 0xffffffff)) {
            throw 'Independent mounted device ordered ACE differs from the retained bootstrap intent'
        }
    }
    foreach($checks in @($root.effective_rights,$boundary.device.checks)) {
        $principals=@('filtered')
        if($RequireUnrelated) {
            if($null -eq $checks.unrelated){throw 'Required unrelated boundary checks are absent'}
            $principals+=@('unrelated')
        }
        foreach($principal in $principals) {
        foreach($right in @('write_or_add_file','append_or_add_directory','write_ea','delete_child',
            'write_attributes','delete','write_dac','write_owner')) {
            if($null -eq $checks.$principal.$right -or $checks.$principal.$right.allowed -or $checks.$principal.$right.granted -ne 0) {
                throw ($principal+' token has boundary mutation access')
            }
        }
        if($null -eq $checks.$principal.maximum_allowed -or ([uint32]$checks.$principal.maximum_allowed.granted -band 0xd0156) -ne 0) {
            throw ($principal+' maximum boundary access includes mutation')
        }
        }
    }
}
function Read-IndependentPublicRows {
    $script:unrelatedObserversClosed=$false
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab `
        -RunId ([guid]::NewGuid().ToString('N')) -CallerProcessId $PID `
        -CallerCreationFileTime $invokingCreation -CallerSid $caller -ServiceSid $sid `
        -ClientCaptureFile $clientCaptureFile -ClientCaptureSha256 $clientCaptureSha256 `
        -ExpectedVolumeRoot $VolumeRoot -ExpectedDiskNumber $disk.Number
    if(-not $readback.observer_task_removed -or $readback.independent.identity -cne 'S-1-5-18' -or
        $readback.independent.observer_token_handles_closed -ne $true) {
        throw 'Independent public-path readback identity or cleanup differs'
    }
    $script:unrelatedObserversClosed=$true
    Assert-IndependentProtectedRows -Rows $readback.independent.rows -ServiceSid $sid
    $tokens=$readback.independent.effective_right_tokens
    if($tokens.process_id -ne $PID -or $tokens.creation_file_time -cne $invokingCreation -or
        $tokens.initiating.user_sid -cne $caller -or $tokens.filtered.user_sid -cne $caller) {
        throw 'Independent effective-right token context differs from the invoking public probe'
    }
    $client=$tokens.captured_client;$capture=$receipt.machine_client_capture
    $login=$tokens.unrelated_logon_context
    if($null -eq $tokens.unrelated -or $null -eq $login -or
        $login.account_name -cne $unrelatedAccountName -or $login.user_sid -cne $unrelatedAccountSid -or
        $login.token_id -cne $unrelatedLoginBinding.token_id -or $login.authentication_id -cne $unrelatedLoginBinding.authentication_id -or
        $tokens.unrelated.user_sid -cne $unrelatedAccountSid -or $tokens.unrelated.token_id -cne $login.token_id -or
        $tokens.unrelated.authentication_id -cne $login.authentication_id -or $login.logon_type -ne 2 -or
        $login.contradictory_bindings_refused -ne 7) {
        throw 'Independent unrelated actual local-login token binding differs'
    }
    if($null -eq $client -or -not $client.exited_at_observation -or
        $client.process_id -ne $capture.process_id -or $client.creation_file_time -cne $capture.creation_file_time -or
        $client.initiating_token_id -cne $capture.initiating_token_id -or $client.filtered_token_id -cne $capture.filtered_token_id -or
        $tokens.capture_context.image_sha256 -cne $receipt.machine_sha256 -or
        $tokens.capture_context.capture_sha256 -cne $clientCaptureSha256 -or
        $tokens.capture_context.request_id -cne $capture.request_id -or $tokens.capture_context.command -cne $capture.command) {
        throw 'Independent held machine-client token binding differs'
    }
    $boundary=$readback.independent.volume_boundary
    Assert-PublicVolumeBoundary $readback.independent $boundary $drive $VolumeRoot $disk.Number $partitions[0].Offset $partitions[0].Size $sid $targetIntent.mounted_device_transition -RequireUnrelated
    $boundaryJson=$boundary|ConvertTo-Json -Depth 16 -Compress
    if($volumeBoundaryBaseline -and $boundaryJson -cne $volumeBoundaryBaseline) {
        throw 'Independent volume-root/device boundary changed across recovery or replay'
    }
    $script:volumeBoundaryBaseline=$boundaryJson
    foreach($row in $readback.independent.rows) {
        foreach($principal in @('filtered','unrelated')) {
        foreach($right in @('write_or_add_file','append_or_add_directory','write_ea','delete_child',
            'write_attributes','delete','write_dac','write_owner')) {
            $check=$row.effective_rights.$principal.$right
            if($null -eq $check -or $check.allowed -or $check.granted -ne 0) {
                throw ($principal+' token obtained protected mutation rights: '+$row.path+' / '+$right)
            }
        }
        if($null -eq $row.effective_rights.$principal.maximum_allowed -or
            ([uint32]$row.effective_rights.$principal.maximum_allowed.granted -band 0xd0156) -ne 0) {
            throw ($principal+' maximum protected access includes mutation: '+$row.path)
        }
        }
    }
    return $readback.independent
}
function Read-IndependentState([string]$PayloadRoot=([string]$plan.target.root).Replace('/','\')) {
    $observation=Read-IndependentPublicRows
    foreach($entry in @($plan.planned_entries|Where-Object entry_type -eq 'file')) {
        $expected=$PayloadRoot+'\'+$entry.relative_path.Replace('/','\')
        $rows=@($observation.rows|Where-Object path -ceq $expected)
        if($rows.Count -ne 1 -or $rows[0].sha256 -cne $entry.sha256 -or $rows[0].bytes -ne $entry.size_bytes) {
            throw 'Public install payload differs from independently read planned bytes'
        }
    }
    Assert-IndependentNativeClosure -Observation $observation -PayloadRoot $PayloadRoot
    return $observation
}
function Read-VolumeMetadata {
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab `
        -RunId ([guid]::NewGuid().ToString('N')) -MetadataOnly
    if(-not $readback.observer_task_removed -or $readback.independent.identity -cne 'S-1-5-18') {
        throw 'Independent volume metadata identity or cleanup differs'
    }
    return $readback.independent
}
function Invoke-PublicRetainedRefusal {
    $initial=$receipt.interrupted_readback
    if($PostRenameRefusal -ceq 'payload_changed') {
        $entry=@($plan.planned_entries|Where-Object entry_type -eq 'file'|Sort-Object relative_path)[0]
        $receipt['controlled_fault']=Invoke-IndependentOwnedPayloadDamage -VhdPath $VhdPath -VolumeRoot $VolumeRoot `
            -DriveRoot $drive -VisibleRoot ($drive+'publication\destination\visible') `
            -PayloadRelativePath $entry.relative_path -ExpectedSha256 $entry.sha256
        $changedPath=$drive+'publication\destination\visible\'+$entry.relative_path.Replace('/','\')
        $baseline=Read-IndependentPublicRows
        Assert-IndependentRetainedMaterial -Before $initial -After $baseline -NoAdditionalRows `
            -ChangedPayloadPath $changedPath -ChangedPayloadSha256 $receipt.controlled_fault.after_sha256
    } else {
        $receipt['controlled_fault']=Invoke-IndependentOwnedMetadataCollision -VhdPath $VhdPath -VolumeRoot $VolumeRoot `
            -DriveRoot $drive -ServiceName $service -ServiceSid $sid -TransactionId $apply.transaction_id
        $baseline=Read-IndependentPublicRows
        Assert-IndependentRetainedMaterial -Before $initial -After $baseline
        $extra=@($baseline.rows|Where-Object {$_.path -cnotin @($initial.rows.path)})
        if($extra.Count -ne 1 -or @($extra|Where-Object {-not $_.directory -or
            $_.path -cnotin @($receipt.controlled_fault.created_paths)}).Count) {
            throw 'Controlled metadata collision altered more than the bound fresh directory'
        }
    }
    $receipt['fault_readback']=$baseline
    $faultBaseline=$baseline
    Remove-OwnedPublicSources
    $recovery=@{schema='usk.publisher_recovery_request.v1';request_id='recover.'+$id;
        install_id=$apply.plan_request.install_id;transaction_id=$apply.transaction_id}
    $attempts=[Collections.Generic.List[object]]::new()
    foreach($attempt in @(@('install_local.recover',$recovery),@('install_local.recover',$recovery),@('install_local.apply',$apply))) {
        $response=Invoke-PublicRequest $attempt[0] $attempt[1] 5
        if($response.status -cne 'recovery_required' -or $response.error.code -cne 'recovery_required' -or
            $null -ne $response.result) {throw 'Public retained refusal invented a terminal or ambiguous result'}
        $observed=Read-IndependentPublicRows
        Assert-IndependentRetainedMaterial -Before $baseline -After $observed `
            -NoAdditionalRows:($PostRenameRefusal -ceq 'payload_changed')
        if($PostRenameRefusal -ceq 'metadata_collision') {
            Assert-IndependentMetadataCollisionPrefix -Before $faultBaseline -After $observed `
                -DriveRoot $drive -ServiceSid $sid
            Assert-IndependentNativeClosure -Observation $observed -PayloadRoot ($drive+'publication\destination\visible')
        }
        $installedPrefix=$drive+'setup-state\state\installed\'
        if(@($observed.rows|Where-Object {-not $_.directory -and
            $_.path.StartsWith($installedPrefix,[StringComparison]::Ordinal)}).Count) {
            throw 'Public retained refusal manufactured an installed-state record'
        }
        $attempts.Add([ordered]@{command=$attempt[0];response=$response;independent=$observed})
        $baseline=$observed
    }
    $receipt['retained_refusal_attempts']=$attempts
    & $ServiceControlBinary --unregister $service $installedBinary $VolumeRoot $caller|Out-Null
    if($LASTEXITCODE -ne 3 -or (Get-Service $service).Status -ne 'Stopped' -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command -or
        (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.service_sha256) {
        throw 'Public retained refusal lost its owned recovery authority'
    }
    $receipt['retained_authority_retirement_refused']=$true
}
function Assert-VolumeMetadataSnapshot($Observation,$Expected) {
    $actual=@($Observation.volume_metadata)
    if($actual.Count -ne @($Expected).Count){throw 'Independent volume metadata count differs'}
    foreach($entry in $Expected) {
        $found=@($actual|Where-Object path -ceq $entry.path)
        if($found.Count -ne 1 -or $found[0].file_id -cne $entry.file_id -or
            $found[0].security -cne $entry.security -or $found[0].attributes -ne $entry.attributes -or
            $found[0].sha256 -cne $entry.sha256 -or $found[0].size -cne $entry.size) {
            throw ('Independent volume metadata identity/security/content differs: '+$entry.path)
        }
    }
}
function Assert-IndependentNativeClosure($Observation,[string]$PayloadRoot) {
    $prepared=@($Observation.rows|Where-Object path -ceq ($drive+'publication\journal\lab-prepared-evidence.json'))
    if($prepared.Count -ne 1){throw 'Independent prepared record absent'}
    $record=$prepared[0].content_json|ConvertFrom-Json
    if($record.schema -cnotin @('usk.publisher.lab_phase_evidence.v4','usk.publisher.lab_phase_evidence.v5','usk.publisher.lab_phase_evidence.v6','usk.publisher.lab_phase_evidence.v7','usk.publisher.lab_phase_evidence.v8','usk.publisher.lab_phase_evidence.v9','usk.publisher.lab_phase_evidence.v10','usk.publisher.lab_phase_evidence.v11') -or
        $record.phase -cne 'lab_prepared_evidence' -or $record.service_sid -cne $sid -or
        $record.source_file_id -cne $record.sealed_tree.root.file_id) {
        $receipt['native_execution_diagnostic']=@{schema=$record.schema;phase=$record.phase;
            service_sid_matches=($record.service_sid -ceq $sid);
            source_file_id_matches=($record.source_file_id -ceq $record.sealed_tree.root.file_id)}
        throw 'Independent prepared tree binding differs'
    }
    $members=@($Observation.rows|Where-Object {
        $_.path -ceq $PayloadRoot -or $_.path.StartsWith($PayloadRoot+'\',[StringComparison]::Ordinal)
    })
    $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $Observation.rows) {
        if($row.file_id -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$' -or -not $ids.Add($row.file_id) -or
            $row.link_count -ne 1 -or $row.case_sensitive -ne $false -or
            $row.native_name -cne $row.path.Substring(2) -or
            [bool]($row.attributes -band 16) -ne $row.directory -or ($row.attributes -band 1024) -or
            ($row.directory -and @($row.streams).Count -ne 0) -or
            (-not $row.directory -and (@($row.streams).Count -ne 1 -or
                $row.streams[0].name -cne '::$DATA' -or $row.streams[0].size -ne $row.bytes))) {
            throw ('Independent native closure facts differ: '+$row.path)
        }
    }
    function Assert-NativeMember($Expected,$Streams,[string]$Path) {
        $found=@($members|Where-Object path -ceq $Path)
        if($found.Count -ne 1){throw 'Independent native member absent'}
        $row=$found[0]
        if($row.file_id -cne $Expected.file_id -or $row.attributes -ne $Expected.attributes -or
            $row.link_count -ne $Expected.link_count -or $row.case_sensitive -ne $Expected.case_sensitive -or
            $row.owner -cne $Expected.owner_sid -or $row.protected -ne $Expected.dacl_protected -or
            $Expected.reparse_tag -ne 0 -or
            @($row.raw_aces).Count -ne @($Expected.dacl_aces).Count -or
            @($row.streams).Count -ne @($Streams).Count) {
            throw 'Independent native member differs from sealed/visible evidence'
        }
        for($i=0;$i -lt @($row.raw_aces).Count;$i++) {
            $a=$row.raw_aces[$i];$b=$Expected.dacl_aces[$i]
            if($a.type -ne $b.type -or $a.flags -ne $b.flags -or $a.access_mask -ne $b.access_mask -or $a.sid -cne $b.sid) {
                throw 'Independent ordered raw ACE differs from sealed/visible evidence'
            }
        }
        for($i=0;$i -lt @($row.streams).Count;$i++) {
            $a=$row.streams[$i];$b=$Streams[$i]
            if($a.name -cne $b.name -or $a.size -ne $b.size -or $a.allocation_size -ne $b.allocation_size) {
                throw 'Independent stream differs from sealed/visible evidence'
            }
        }
    }
    function Assert-NativeTree($Tree,[string]$OriginalRoot) {
        # The retained legacy phase record escapes native names once before
        # JSON serialization. The independent native name is the raw query.
        if(([string]$Tree.root.native_name).Replace('\\','\') -cne $OriginalRoot.Substring(2) -or
            $members.Count -ne 1+@($Tree.descendants).Count) {
            throw 'Independent root name or closure membership differs'
        }
        Assert-NativeMember -Expected $Tree.root -Streams @($Tree.root_streams) -Path $PayloadRoot
        foreach($entry in $Tree.descendants) {
            $relative=$entry.relative_path.Replace('/','\')
            $path=$PayloadRoot+'\'+$relative
            if(([string]$entry.object.native_name).Replace('\\','\') -cne
                ($OriginalRoot+'\'+$relative).Substring(2)) {throw 'Retained native child name differs'}
            Assert-NativeMember -Expected $entry.object -Streams @($entry.streams) -Path $path
            $row=@($members|Where-Object path -ceq $path)[0]
            if($row.bytes -ne $entry.size -or (-not $row.directory -and $row.sha256 -cne $entry.sha256)) {
                throw 'Independent payload bytes differ from sealed/visible evidence'
            }
        }
    }
    Assert-NativeTree $record.sealed_tree ($drive+'publication\staging\candidate')
    $visible=@($Observation.rows|Where-Object path -ceq ($drive+'publication\journal\lab-visible-evidence.json'))
    if($visible.Count -eq 1) {
        $value=$visible[0].content_json|ConvertFrom-Json
        if($value.schema -cne $record.schema -or
            $value.phase -cne 'lab_visible_evidence' -or
            $value.prepared_record_sha256 -cne $prepared[0].sha256 -or
            $value.source_file_id -cne $record.sealed_tree.root.file_id) {
            throw 'Independent visible record differs from prepared binding'
        }
        Assert-NativeTree $value.visible_tree ($drive+'publication\destination\visible')
    } elseif($visible.Count -ne 0){throw 'Independent visible record is ambiguous'}
    $executionInput=Join-Path $lab ('execution-readback-'+[guid]::NewGuid().ToString('N')+'.json')
    $visibleJson=if($visible.Count){[string]$visible[0].content_json}else{$null}
    Write-Json $executionInput @{prepared_json=[string]$prepared[0].content_json;visible_json=$visibleJson;
        service_name=$service;service_sid=$sid;windows_build=[int]([Environment]::OSVersion.Version.Build);
        sdk_version=$executionSdk}
    $executionResult=& python -B (Join-Path $PSScriptRoot 'publisher_execution_evidence.py') --input $executionInput
    if($LASTEXITCODE -ne 0){throw 'Independent native execution record reconciliation failed'}
    $executionReport=($executionResult -join "`n")|ConvertFrom-Json
    $childEvidence=$record.schema -cin @('usk.publisher.lab_phase_evidence.v10','usk.publisher.lab_phase_evidence.v11')
    $reportSchema=if($childEvidence){'usk.publisher_execution_reconciliation.v5'}else{'usk.publisher_execution_reconciliation.v4'}
    $creatorSchema=if($childEvidence){'usk.publisher_creation_reconciliation.v4'}else{'usk.publisher_creation_reconciliation.v3'}
    if($executionReport.schema -cne $reportSchema -or
        $executionReport.status -cne 'bindings_consistent' -or $executionReport.profile_qualified -ne $false -or
        $executionReport.held_roles_per_phase -ne 7 -or
        $executionReport.process_bound_phase_count -ne $executionReport.phase_count -or
        $executionReport.worker_security_phase_count -ne $executionReport.phase_count -or
        $executionReport.creation_observation.schema -cne $creatorSchema -or
        $executionReport.creation_observation.process_boundary_checked -ne $true -or
        $executionReport.creation_observation.worker_security_checked -ne $true -or
        $executionReport.creation_observation.status -cne 'bindings_consistent' -or
        $executionReport.creation_observation.profile_qualified -ne $false -or
        $executionReport.creation_observation.created_object_count -lt 6) {
        throw 'Independent execution reconciliation result differs'
    }
    if($childEvidence -and ($executionReport.effect_worker_phase_count -ne $executionReport.phase_count -or
        $executionReport.creation_observation.original_broker_checked -ne $true -or
        @($executionReport.broker_process_ids).Count -le 0 -or @($executionReport.worker_process_ids).Count -le 0)) {
        throw 'Independent native child evidence lacks separate original broker/creator bindings'
    }
    $receipt.execution_readback_reconciliations.Add(@{result=$executionReport;
        input_sha256=(Get-FileHash -LiteralPath $executionInput -Algorithm SHA256).Hash.ToLowerInvariant();
        prepared_record_sha256=$prepared[0].sha256;
        visible_record_sha256=$(if($visible.Count){$visible[0].sha256}else{$null})})
}
function Remove-OwnedPublicSources {
    $exactFixture=[IO.Path]::GetFullPath($fixture)
    if($exactFixture -cne (Join-Path $lab 'authored-inputs') -or
        (Get-Item -LiteralPath $exactFixture).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Source-free recovery cleanup escaped the owned fixture'
    }
    Remove-Item -LiteralPath $exactFixture -Recurse -Force -ErrorAction Stop
    if(Test-Path -LiteralPath $binding.envelope_file){throw 'Original reviewed source remains'}
}
try {
    $fixture=Join-Path $lab 'authored-inputs'
    New-Item -ItemType Directory -Path $fixture -ErrorAction Stop|Out-Null
    $fixtureArgs=if($PublicationLoss -cne 'none'){@('--core-bytes','33554432','--addon-bytes','33554432')}else{@()}
    $generated=& python -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $fixture --target ($drive+'publication\destination\visible') --request-id ('public.'+$id) @fixtureArgs
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
    Initialize-PublisherMetadataNativeTypes
    if(Get-LocalUser -Name $unrelatedAccountName -ErrorAction SilentlyContinue) {
        throw 'Owned unrelated observation account name already exists'
    }
    $unrelatedObserversClosed=$false
    $secret=ConvertTo-SecureString ('Aa1!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
    try {
        $account=New-LocalUser -Name $unrelatedAccountName -Password $secret -PasswordNeverExpires -ErrorAction Stop
        $unrelatedAccountCreated=$true;$unrelatedAccountSid=$account.SID.Value
        $receipt['unrelated_local_login']=[ordered]@{account_name=$unrelatedAccountName;user_sid=$unrelatedAccountSid;
            token_id=$null;authentication_id=$null;logon_type=2;basis='owned account created; token authentication pending';cleanup='pending'}
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $account -ErrorAction Stop
        $unrelatedTokenLease=[UskPublisherEffectiveRights]::new($PID,[long]$invokingCreation,$caller,$sid)
        $unrelatedLoginBinding=$unrelatedTokenLease.HoldOwnedLocalLogin($unrelatedAccountName,$secret,$unrelatedAccountSid,$sid)
        $receipt['unrelated_local_login']=[ordered]@{account_name=$unrelatedAccountName;user_sid=$unrelatedAccountSid;
            token_id=$unrelatedLoginBinding.token_id;authentication_id=$unrelatedLoginBinding.authentication_id;
            logon_type=2;basis=$unrelatedLoginBinding.basis;cleanup='pending'}
        $unrelatedObserversClosed=$true
    } finally {$secret.Dispose()}
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
    $targetIntentPath=Join-Path (Split-Path -Parent $installedBinary) ($service+'.target-intent.json')
    $targetAdmittedPath=Join-Path (Split-Path -Parent $installedBinary) ($service+'.target-admitted.json')
    $receipt['unadmitted_capability']=Invoke-PublicCapability 2
    $metadataBefore=Read-VolumeMetadata
    # No lab helper changes the volume-root or raw-device ACL. The product
    # controller owns this admitted-target transition and its durable records.
    $provisioned=& $ServiceControlBinary --provision-target $service --confirm-empty-volume
    if($LASTEXITCODE -ne 0 -or ($provisioned|ConvertFrom-Json).status -cne 'target_admitted') {
        throw 'Product target admission failed'
    }
    $receipt['provisioning']=$provisioned|ConvertFrom-Json
    $targetIntentPath=Join-Path (Split-Path -Parent $installedBinary) ($service+'.target-intent.json')
    $targetAdmittedPath=Join-Path (Split-Path -Parent $installedBinary) ($service+'.target-admitted.json')
    $targetIntent=Get-Content -LiteralPath $targetIntentPath -Raw|ConvertFrom-Json
    $targetIntentHash=(Get-FileHash -LiteralPath $targetIntentPath -Algorithm SHA256).Hash
    if($targetIntent.schema -cne 'usk.publisher_target_intent.v3' -or @($targetIntent.PSObject.Properties).Count -ne 5 -or
        @($targetIntent.mounted_device_transition.PSObject.Properties).Count -ne 2 -or
        $targetIntent.mounted_device_transition.original_owner_dacl.Length -gt 8192) {
        throw 'Target transition intent schema or mounted device binding differs'
    }
    $originalDevice=[Security.AccessControl.RawSecurityDescriptor]::new($targetIntent.mounted_device_transition.original_owner_dacl)
    if($null -eq $originalDevice.DiscretionaryAcl -or $originalDevice.Owner.Value -cnotin @('S-1-5-18','S-1-5-32-544')) {
        throw 'Target transition intent has an unavailable original mounted device descriptor'
    }
    Assert-VolumeMetadataSnapshot $metadataBefore $targetIntent.original_metadata
    $metadataAfter=Read-VolumeMetadata
    Assert-VolumeMetadataSnapshot $metadataAfter $targetIntent.identity.metadata
    $receipt['original_volume_metadata']=$metadataBefore
    $receipt['protected_volume_metadata']=$metadataAfter
    & $ServiceControlBinary --verify $service $installedBinary $VolumeRoot $caller|Out-Null
    if($LASTEXITCODE -ne 3 -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command) {
        throw 'Legacy mode change altered an admitted public registration'
    }
    # Model interruption after protection effects but before the completion
    # record. Edit only this newly created owned record; this is not a kill or
    # power-loss result. Reentry must use the retained original/intended state.
    $admittedBefore=Get-Content -LiteralPath $targetAdmittedPath -Raw
    Remove-Item -LiteralPath $targetAdmittedPath -ErrorAction Stop
    & $ServiceControlBinary --provision-target $service --confirm-empty-volume|Out-Null
    if($LASTEXITCODE -ne 0 -or (Get-Content -LiteralPath $targetAdmittedPath -Raw) -cne $admittedBefore -or
        (Get-FileHash -LiteralPath $targetIntentPath -Algorithm SHA256).Hash -cne $targetIntentHash) {
        throw 'Product target admission completion reentry altered its retained intent or result'
    }
    Assert-VolumeMetadataSnapshot (Read-VolumeMetadata) $targetIntent.identity.metadata
    $receipt['target_completion_reentry']='modelled missing completion; same immutable intent and protected metadata'
    $receipt['admitted_capability']=Invoke-PublicCapability
    $receipt['capability_registration_binding']=Get-Content -LiteralPath $registrationRecord -Raw|ConvertFrom-Json
    $receipt['capability_target_admission']=Get-Content -LiteralPath $targetAdmittedPath -Raw|ConvertFrom-Json
    if($PublicationLoss -cne 'none') {
        $observerRoot=Join-Path $lab 'production-boundary'
        New-Item -ItemType Directory -Path $observerRoot -ErrorAction Stop|Out-Null
        & $ServiceControlBinary --start $service $installedBinary $VolumeRoot $caller|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned public service could not start before boundary observation'}
        $boundaryObserver=Start-OwnedProductionBoundaryObserver -Phase $PublicationLoss -Service $service `
            -ObserverRoot $observerRoot -VhdPath $VhdPath -VolumeRoot $VolumeRoot -DriveRoot $drive `
            -VisibleRoot ($drive+'publication\destination\visible') -ServiceCommand $command `
            -ServiceBinarySha256 $receipt.service_sha256 -ObserverFamily legacy_scm_v1
        $receipt['interrupted_apply']=Invoke-PublicRequest 'install_local.apply' $apply 5
        if($receipt.interrupted_apply.status -cne 'unknown' -or
            $receipt.interrupted_apply.error.code -cne 'publisher_outcome_unknown' -or
            $null -ne $receipt.interrupted_apply.result) {throw 'Interrupted ordinary apply invented a terminal result'}
        $receipt['production_boundary']=Complete-OwnedProductionBoundaryObserver $boundaryObserver $PublicationLoss
        $receipt['production_boundary_task_removed']=$boundaryObserver.removed
        $payloadRoot=if($PublicationLoss -ceq 'prepublish'){$drive+'publication\staging\candidate'}else{$drive+'publication\destination\visible'}
        $interrupted=Read-IndependentState $payloadRoot
        $receipt['interrupted_readback']=$interrupted
        $publicFiles=@($interrupted.rows|Where-Object {-not $_.directory -and $_.path.StartsWith($drive+'setup-state\',[StringComparison]::Ordinal)})
        if($publicFiles.Count -ne 1 -or $publicFiles[0].path -cne ($drive+'setup-state\.usk-owned-root.v1.json') -or
            @($interrupted.rows|Where-Object path -ceq ($drive+'publication\state\lab-installed-state.json')).Count -ne 0 -or
            @($interrupted.rows|Where-Object path -ceq ($drive+'publication\journal\lab-visible-evidence.json')).Count -ne 0) {
            throw 'Interrupted ordinary install contains invented completion metadata'
        }
        if($PublicationLoss -ceq 'prepublish' -and
            @($interrupted.rows|Where-Object path -ceq ($drive+'publication\journal\lab-prepared-evidence.json'))[0].sha256 -cne
                $receipt.production_boundary.prepared_record_sha256) {throw 'Independent prepared record differs from observed loss boundary'}
        if($PostRenameRefusal -cne 'none') {
            Invoke-PublicRetainedRefusal
        } else {
        Remove-OwnedPublicSources
        $recovery=@{schema='usk.publisher_recovery_request.v1';request_id='recover.'+$id;
            install_id=$apply.plan_request.install_id;transaction_id=$apply.transaction_id}
        $receipt['boundary_recovery']=Invoke-PublicRequest 'install_local.recover' $recovery
        $installed=$receipt.boundary_recovery.result.payload
        $before=Read-IndependentState
        foreach($row in $interrupted.rows) {
            $expected=$row|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
            if($PublicationLoss -ceq 'prepublish' -and ($expected.path -ceq $payloadRoot -or
                $expected.path.StartsWith($payloadRoot+'\',[StringComparison]::Ordinal))) {
                $expected.path=$drive+'publication\destination\visible'+$expected.path.Substring($payloadRoot.Length)
                $expected.native_name=$expected.path.Substring(2)
            }
            $found=@($before.rows|Where-Object path -ceq $expected.path)
            if($found.Count -ne 1 -or ($found[0]|ConvertTo-Json -Depth 64 -Compress) -cne
                ($expected|ConvertTo-Json -Depth 64 -Compress)) {
                throw ('Source-free boundary recovery changed retained native identity/content: '+$expected.path)
            }
        }
        }
    } else {
        $receipt['apply']=Invoke-PublicRequest 'install_local.apply' $apply
        $installed=$receipt.apply.result.payload
        $before=Read-IndependentState
    }
    if($PostRenameRefusal -ceq 'none') {
    if($installed.install_id -cne $apply.plan_request.install_id -or
        $installed.transaction_id -cne $apply.transaction_id -or $installed.created_at -cne $apply.applied_at -or
        $installed.lifecycle_status -cne 'installed') {
        throw 'Ordinary public installation identity differs'
    }
    $receipt['installed_readback']=$before
    & $ServiceControlBinary --unregister $service $installedBinary $VolumeRoot $caller|Out-Null
    if($LASTEXITCODE -ne 3 -or (Get-Service $service).Status -ne 'Stopped' -or
        (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command -or
        (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.service_sha256) {
        throw 'Installed public publisher recovery authority was removed'
    }
    $receipt['installed_authority_retirement_refused']=$true
    if($PublicationLoss -ceq 'none'){Remove-OwnedPublicSources}
    $recovery=@{schema='usk.publisher_recovery_request.v1';request_id='recover.'+$id;
        install_id=$installed.install_id;transaction_id=$installed.transaction_id}
    $receipt['recovery']=Invoke-PublicRequest 'install_local.recover' $recovery
    $recoveryReadback=Read-IndependentState
    if(($before.rows|ConvertTo-Json -Depth 64 -Compress) -cne ($recoveryReadback.rows|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Source-free public recovery changed independently read target state'
    }
    $receipt['recovery_readback']=$recoveryReadback
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
    $verify=@{schema='usk.publisher_installed_verify_request.v1';request_id='verify.'+$id;install_id=$installed.install_id;
        transaction_id=$installed.transaction_id;report_id='verify.'+$id;
        verified_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
    $receipt['verification']=Invoke-PublicRequest 'installed.verify' $verify
    $receipt['installed_capability']=Invoke-PublicCapability
    if($receipt.verification.result.payload.status -cne 'pass' -or
        $receipt.verification.result.payload.report_id -cne $verify.report_id) {
        throw 'Ordinary public verification did not return the bound passing report'
    }
    $verificationReadback=Read-IndependentState
    if(($after.rows|ConvertTo-Json -Depth 64 -Compress) -cne ($verificationReadback.rows|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Read-only public verification changed independently read target state'
    }
    $receipt['verification_readback']=$verificationReadback
    }
    if((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $command) {
        throw 'Public apply/recovery/verification reconfigured SCM'
    }
    $receipt.status=if($PostRenameRefusal -ceq 'none'){'public_install_verified_recovered'}else{'public_refusal_retained'}
} catch {
    $receipt.status='failed';$receipt['failure']=$_.Exception.Message
    # Retain the product's protected pre-effect snapshot so a late admission
    # refusal can be compared with its actual initial metadata. This is a
    # controller-authored pre-state, not independent post-state evidence.
    if($created) {
        try {
            $intent=Join-Path (Split-Path -Parent $installedBinary) ($service+'.target-intent.json')
            if(Test-Path -LiteralPath $intent -PathType Leaf) {
                if((Get-Item -LiteralPath $intent).Length -gt 16KB){throw 'Target intent exceeds diagnostic bound'}
                $receipt['retained_target_intent']=Get-Content -LiteralPath $intent -Raw|ConvertFrom-Json
                $receipt['retained_target_intent_sha256']=(Get-FileHash -LiteralPath $intent -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        } catch {$receipt['target_intent_diagnostic_error']=$_.Exception.Message}
    }
} finally {
    if($boundaryObserver -and -not $receipt.Contains('production_boundary') -and
        (Test-Path -LiteralPath $boundaryObserver.output -PathType Leaf)) {
        try {
            if((Get-Item -LiteralPath $boundaryObserver.output).Length -gt 16KB) {throw 'Boundary diagnostic exceeds its bound'}
            $receipt['production_boundary']=Get-Content -LiteralPath $boundaryObserver.output -Raw|ConvertFrom-Json
        } catch {$receipt['boundary_diagnostic_error']=$_.Exception.Message}
    }
    if($boundaryObserver -and -not $boundaryObserver.removed) {
        try {Remove-OwnedProductionBoundaryObserver $boundaryObserver}
        catch {$receipt.status='failed';$receipt['failure']='Owned boundary observer cleanup failed: '+$_.Exception.Message}
    }
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
    if($clientTokenLease){
        try {$clientTokenLease.Dispose()}
        catch {$unrelatedObserversClosed=$false;$receipt.status='failed';$receipt['failure']='Owned machine-client token close failed: '+$_.Exception.Message}
    }
    if($unrelatedTokenLease){
        try {$unrelatedTokenLease.Dispose()}
        catch {$unrelatedObserversClosed=$false;$receipt.status='failed';$receipt['failure']='Owned unrelated token close failed: '+$_.Exception.Message}
    }
    $receipt['unrelated_observers_token_close_confirmed']=$unrelatedObserversClosed
    if($unrelatedAccountCreated -and $unrelatedObserversClosed) {
        try {
            $account=Get-LocalUser -Name $unrelatedAccountName -ErrorAction Stop
            if($account.SID.Value -cne $unrelatedAccountSid){throw 'Owned unrelated observation account SID changed'}
            Remove-LocalUser -SID $account.SID -ErrorAction Stop
            if(Get-LocalUser -SID $account.SID -ErrorAction SilentlyContinue){throw 'Owned observation account remained after removal'}
            if($receipt.Contains('unrelated_local_login')){$receipt.unrelated_local_login.cleanup='matching generated account removed after token handles closed'}
        } catch {
            $receipt.status='failed';$receipt['failure']='Owned unrelated login cleanup failed: '+$_.Exception.Message
        }
    } elseif($unrelatedAccountCreated) {
        $receipt.status='failed'
        if($receipt.Contains('unrelated_local_login')){$receipt.unrelated_local_login.cleanup='observer/token close unconfirmed; generated account retained until owned runner disposal'}
    }
    Write-Json $OutputPath $receipt
}
$expectedStatus=if($PostRenameRefusal -ceq 'none'){'public_install_verified_recovered'}else{'public_refusal_retained'}
if($receipt.status -cne $expectedStatus -or -not $receipt.client_cleanup_confirmed) {
    throw ('Public publisher qualification failed: '+$receipt.failure)
}

# Expected recovery/retirement refusals carry nonzero native exit codes. The
# fixture succeeds only after every response, retained row and cleanup check.
# Return that fixture outcome to PowerShell hosts that forward LASTEXITCODE.
$global:LASTEXITCODE=0
