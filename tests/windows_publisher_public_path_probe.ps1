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
$receipt=[ordered]@{schema='usk.publisher_public_path_probe.v1';status='not_run';
    service=$service;volume_root=$VolumeRoot;volume_drive_root=$drive;publication_loss=$PublicationLoss;postrename_refusal=$PostRenameRefusal;
    partition_layout=@($disk|Get-Partition|Select-Object PartitionNumber,Offset,Size,GptType,MbrType,IsBoot,IsSystem);
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    service_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    client_cleanup_confirmed=$false}
$created=$false
$boundaryObserver=$null
$installedBinary=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$service+'.exe')
function Write-Json([string]$Path,$Value) {
    [IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)
}
function Invoke-PublicRequest([string]$Command,$Payload,[int]$ExpectedExit=0) {
    $request=Join-Path $lab ('public-request-'+[guid]::NewGuid().ToString('N')+'.json')
    $requestId='public.'+[guid]::NewGuid().ToString('N')
    Write-Json $request ([ordered]@{schema='usk.oneshot_request.v1';request_id=$requestId;
        command=$Command;payload=$Payload;dry_run=$false})
    $output=& $MachineBinary --machine --publisher $service --request-file $request
    $exit=$LASTEXITCODE
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
function Read-IndependentPublicRows {
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab `
        -RunId ([guid]::NewGuid().ToString('N')) -CallerProcessId $PID `
        -CallerCreationFileTime $invokingCreation -CallerSid $caller -ServiceSid $sid
    if(-not $readback.observer_task_removed -or $readback.independent.identity -cne 'S-1-5-18') {
        throw 'Independent public-path readback identity or cleanup differs'
    }
    Assert-IndependentProtectedRows -Rows $readback.independent.rows -ServiceSid $sid
    $tokens=$readback.independent.effective_right_tokens
    if($tokens.process_id -ne $PID -or $tokens.creation_file_time -cne $invokingCreation -or
        $tokens.initiating.user_sid -cne $caller -or $tokens.filtered.user_sid -cne $caller) {
        throw 'Independent effective-right token context differs from the invoking public probe'
    }
    foreach($row in $readback.independent.rows) {
        foreach($right in @('write_or_add_file','append_or_add_directory','write_ea','delete_child',
            'write_attributes','delete','write_dac','write_owner')) {
            $check=$row.effective_rights.filtered.$right
            if($null -eq $check -or $check.allowed -or $check.granted -ne 0) {
                throw ('Filtered invoking token obtained protected mutation rights: '+$row.path+' / '+$right)
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
    if($record.schema -cne 'usk.publisher.lab_phase_evidence.v2' -or
        $record.phase -cne 'lab_prepared_evidence' -or $record.service_sid -cne $sid -or
        $record.source_file_id -cne $record.sealed_tree.root.file_id) {
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
        if($value.schema -cne 'usk.publisher.lab_phase_evidence.v2' -or
            $value.phase -cne 'lab_visible_evidence' -or
            $value.prepared_record_sha256 -cne $prepared[0].sha256 -or
            $value.source_file_id -cne $record.sealed_tree.root.file_id) {
            throw 'Independent visible record differs from prepared binding'
        }
        Assert-NativeTree $value.visible_tree ($drive+'publication\destination\visible')
    } elseif($visible.Count -ne 0){throw 'Independent visible record is ambiguous'}
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
    if($targetIntent.schema -cne 'usk.publisher_target_intent.v2'){throw 'Target transition intent schema differs'}
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
    if($PublicationLoss -cne 'none') {
        $observerRoot=Join-Path $lab 'production-boundary'
        New-Item -ItemType Directory -Path $observerRoot -ErrorAction Stop|Out-Null
        & $ServiceControlBinary --start $service $installedBinary $VolumeRoot $caller|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned public service could not start before boundary observation'}
        $boundaryObserver=Start-OwnedProductionBoundaryObserver -Phase $PublicationLoss -Service $service `
            -ObserverRoot $observerRoot -VhdPath $VhdPath -VolumeRoot $VolumeRoot -DriveRoot $drive `
            -VisibleRoot ($drive+'publication\destination\visible') -ServiceCommand $command `
            -ServiceBinarySha256 $receipt.service_sha256
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
    if($receipt.verification.result.payload.status -cne 'pass' -or
        $receipt.verification.result.payload.report_id -cne $verify.report_id) {
        throw 'Ordinary public verification did not return the bound passing report'
    }
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
