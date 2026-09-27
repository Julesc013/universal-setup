# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$DeviceAclBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$PublicApplyBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$ClientBinary = '',
    [string]$PayloadBinary = '',
    [switch]$ConsumerAccess,
    [switch]$InterruptDuringConsumerAccess,
    [switch]$InterruptAfterVisibleRecord,
    [switch]$InterruptAfterRename,
    [switch]$InterruptBeforePublish,
    [switch]$InterruptAfterStage,
    [switch]$HostileRights
)
$ErrorActionPreference='Stop'
if(([int][bool]$InterruptAfterVisibleRecord+[int][bool]$InterruptAfterRename+[int][bool]$InterruptBeforePublish+[int][bool]$InterruptAfterStage) -gt 1){throw 'Select one interruption window'}
if($InterruptDuringConsumerAccess -and (-not $ConsumerAccess -or $InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage)){throw 'Consumer interruption requires its exclusive consumer profile'}
if($ConsumerAccess -and (-not $ClientBinary -or -not $PayloadBinary)){throw 'Consumer profile requires client and actual executable'}
if($InterruptAfterStage -and -not $ClientBinary){throw 'Snapshot-only replay requires an authenticated client'}
$recover=$InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage -or $InterruptDuringConsumerAccess
if($HostileRights -and $recover){throw 'Hostile-rights observation requires an uninterrupted operation'}
$gate=if($InterruptAfterStage){'poststage'}elseif($InterruptBeforePublish){'prepublish'}elseif($InterruptAfterRename){'postrename'}else{'postjournal'}
$readyContent=if($InterruptAfterStage){"usk.publisher.lab_snapshot_and_stage_sealed.v1`n"}elseif($InterruptBeforePublish){"usk.publisher.lab_prepared.v1`n"}elseif($InterruptAfterRename){"usk.publisher.lab_renamed_unconfirmed.v1`n"}else{"usk.publisher.lab_visible_recorded.v1`n"}
$recoveryDecision=if($InterruptAfterStage){'snapshot_only_completed_forward'}elseif($InterruptDuringConsumerAccess){'already_visible_bound'}elseif($InterruptAfterVisibleRecord){'installed_state_completed_forward'}else{'visible_bound_forward'}
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_process.ps1')
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
$requestClient=$null
$clientNumber=0
$consumerCreated=$false
$consumerCredential=$null
$consumerSid=''
$consumerProcess=$null
$clientCleanupConfirmed=$true
$consumerOutput=Join-Path $root 'consumer-output'
$consumerScript=Join-Path $root 'consumer-client.ps1'
function Start-RequestClient($submitted=$applyRequest) {
    $script:clientNumber++
    $prefix=Join-Path $(if($ConsumerAccess){$consumerOutput}else{$root}) ('client-'+$clientNumber)
    $clientRequest=$prefix+'-request.json'
    [IO.File]::WriteAllText($clientRequest,($submitted|ConvertTo-Json -Depth 32 -Compress),$utf8)
    $options=@{FilePath=$ClientBinary;ArgumentList=@('--service',$service,'--request-file',('"'+$clientRequest+'"'));
        WindowStyle='Hidden';PassThru=$true;RedirectStandardOutput=$prefix+'-response.json';RedirectStandardError=$prefix+'-error.txt'}
    $identityPath=$prefix+'-identity.json'
    if($ConsumerAccess) {
        $options.FilePath=(Get-Command pwsh).Source
        $options.ArgumentList=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$consumerScript,
            '-ExpectedUserSid',$consumerSid,'-IdentityPath',$identityPath,'-ClientBinary',$ClientBinary,
            '-ServiceName',$service,'-RequestFile',$clientRequest)
        $options['Credential']=$consumerCredential
        $options['WorkingDirectory']=$consumerOutput
    }
    $process=Start-Process @options
    return [pscustomobject]@{process=$process;response=$prefix+'-response.json';error=$prefix+'-error.txt';identity=$identityPath}
}
function Complete-RequestClient($client,[bool]$expectSuccess,[bool]$requireFailureResponse=$false) {
    if(-not $client.process.WaitForExit(120000)) {
        Stop-OwnedPublisherProcessTree $client.process|Out-Null;throw 'Owned request client timed out'
    }
    $client.process.WaitForExit()
    if(($client.process.ExitCode -eq 0) -ne $expectSuccess) {
        throw ('Request client exit differs: '+$client.process.ExitCode+'; '+[IO.File]::ReadAllText($client.error))
    }
    $result=[ordered]@{exit_code=$client.process.ExitCode;binary_sha256=(Get-FileHash -LiteralPath $ClientBinary -Algorithm SHA256).Hash.ToLowerInvariant();
        caller_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    if($ConsumerAccess) {
        $actual=Get-Content -LiteralPath $client.identity -Raw|ConvertFrom-Json
        if($actual.user_sid -cne $consumerSid -or $actual.administrator){throw 'Actual client did not run as admitted non-admin user'}
        $result.caller_sid=$actual.user_sid
        $result['caller_observation']=$actual
    }
    $hasResponse=(Get-Item -LiteralPath $client.response).Length -gt 0
    if($expectSuccess -or $hasResponse) {
        if((Get-Item -LiteralPath $client.response).Length -gt 4MB -or
            [IO.File]::ReadAllText($client.response).Trim() -cne [IO.File]::ReadAllText($nativePath).Trim()) {
            throw 'Authenticated client result differs from independently retained service result'
        }
        $result['response_sha256']=(Get-FileHash -LiteralPath $client.response -Algorithm SHA256).Hash.ToLowerInvariant()
        $result['delivery']='response_received'
    } elseif($requireFailureResponse -or [IO.File]::ReadAllText($client.error) -notmatch 'outcome unknown') {
        throw 'Request client did not deliver a structured failure or explicitly report unknown outcome'
    } else {
        $result['delivery']='outcome_unknown'
    }
    return $result
}
try {
    if($ConsumerAccess) {
        $consumerName='USKUSR_'+[guid]::NewGuid().ToString('N').Substring(0,13)
        if(Get-LocalUser -Name $consumerName -ErrorAction SilentlyContinue){throw 'Consumer account collision'}
        $secure=ConvertTo-SecureString ('Aa1!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
        $account=New-LocalUser -Name $consumerName -Password $secure -PasswordNeverExpires
        $consumerCreated=$true;$consumerSid=$account.SID.Value
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member $account
        $consumerCredential=[Management.Automation.PSCredential]::new($env:COMPUTERNAME+'\'+$consumerName,$secure)
        $receipt['consumer_account_sid']=$consumerSid
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_publisher_consumer_client.ps1') -Destination $consumerScript
        $clientCopy=Join-Path $root 'consumer-client.exe'
        Copy-Item -LiteralPath $ClientBinary -Destination $clientCopy
        $ClientBinary=$clientCopy
        New-Item -ItemType Directory -Path $consumerOutput|Out-Null
        $rootAcl=Get-Acl -LiteralPath $root
        $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($consumerSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $root -AclObject $rootAcl
        $outputAcl=Get-Acl -LiteralPath $consumerOutput
        $outputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($consumerSid),'Modify','ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $consumerOutput -AclObject $outputAcl
    }
    Assert-OwnedVolume
    if(Test-Path -LiteralPath ($drive+'publication')){throw 'Hosted metadata disk is not fresh'}
    $fixtureArgs=if($ConsumerAccess){@('--application-binary',$PayloadBinary)}else{@()}
    $generated=& python -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') `
        --output $fixture --target ($drive+'publication\destination\visible') --request-id ('metadata.'+$id) @fixtureArgs
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
    $receipt['public_apply_binary_sha256']=(Get-FileHash -LiteralPath $PublicApplyBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    # The identical ordinary request must refuse outside the admitted service,
    # before creating payload or setup state. No public activation mints authority.
    $ordinaryPath=Join-Path $root ('ordinary-apply-'+$id+'.json')
    [IO.File]::WriteAllText($ordinaryPath,($applyRequest|ConvertTo-Json -Depth 32 -Compress)+"`n",$utf8)
    # usk_machine remains inspect-only. Exercise the actual C ABI instead of
    # interpreting its earlier command_unavailable as publisher evidence.
    $ordinary=& $PublicApplyBinary --apply-probe $ordinaryPath ($drive+'setup-state') $drive
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
    $selectedClientArguments=' --selected-zip "'+$archive+'" '+$inputs.archive_sha256+' --campaign-vm-id '+$vmId+
        ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256
    if($recover -and -not $InterruptDuringConsumerAccess){$command+=' --'+$gate+'-gate'}
    if($HostileRights){$command+=' --prepublish-gate'}
    if($InterruptDuringConsumerAccess){$command+=' --interrupt-consumer-grant'}
    if($ClientBinary) {
        $callerSid=if($ConsumerAccess){$consumerSid}else{[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
        $clientArguments=' --authorized-client-sid '+$callerSid
        if($ConsumerAccess){$clientArguments+=' --grant-client-read'}
        $command+=$clientArguments
    }
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
    if($ClientBinary){$requestClient=Start-RequestClient}
    if($HostileRights) {
        $attackRelative=if($ConsumerAccess){'bin/core.exe'}else{'bin/core.bin'}
        if(@($plan.planned_entries|Where-Object relative_path -ceq $attackRelative).Count -ne 1){
            throw 'Selected hostile-rights payload is absent from the reviewed plan'
        }
        $ready=$nativePath.Substring(0,$nativePath.Length-5)+'-prepublish-ready.txt'
        $release=$nativePath.Substring(0,$nativePath.Length-5)+'-prepublish-release.txt'
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $ready) -or
            [IO.File]::ReadAllText($ready) -cne "usk.publisher.lab_prepared.v1`n" -or
            (Test-Path -LiteralPath $release)) {throw 'Selected publisher did not pause at the protected prepublish phase'}
        Assert-OwnedVolume
        $pausedBefore=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($pausedBefore.independent.identity -ne 'S-1-5-18' -or -not $pausedBefore.observer_task_removed){throw 'Prepublish independent observation unavailable'}
        Assert-IndependentProtectedRows -Rows $pausedBefore.independent.rows -ServiceSid $sid
        $stagedPath=$drive+'publication\staging\candidate\'+$attackRelative.Replace('/','\')
        if(@($pausedBefore.independent.rows|Where-Object path -ceq $stagedPath).Count -ne 1){
            throw 'Selected staged payload was absent before the hostile-rights probe'
        }
        $receipt['prepublish_before_attack']=$pausedBefore.independent
        $attackOutput=Join-Path (Split-Path -Parent $vhd) 'unprivileged-prepublish.json'
        & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid -OutputPath $attackOutput -Stage Prepublish -PayloadRelativePath $attackRelative
        $attack=Get-Content -LiteralPath $attackOutput -Raw|ConvertFrom-Json
        $receipt['prepublish_hostile_rights']=$attack
        if($attack.status -ne 'unprivileged_access_denied_observed' -or $attack.payload_relative_path -cne $attackRelative){
            throw 'Selected prepublish attacker result differs'
        }
        $pausedAfter=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['prepublish_after_attack']=$pausedAfter.independent
        if($pausedAfter.independent.identity -ne 'S-1-5-18' -or -not $pausedAfter.observer_task_removed -or
            ($pausedBefore.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($pausedAfter.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Selected prepublish hostile attempts changed protected state'
        }
        Assert-OwnedVolume
        $releaseTemp=$release+'.tmp'
        $releaseBytes=[Text.Encoding]::ASCII.GetBytes("usk.publisher.lab_continue.v1`n")
        $stream=[IO.FileStream]::new($releaseTemp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$stream.Write($releaseBytes,0,$releaseBytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
        [IO.File]::Move($releaseTemp,$release)
    }
    if($recover -and -not $InterruptDuringConsumerAccess) {
        # Controlled service cancellation at the selected flushed readiness window.
        # This is neither VM power loss nor physical-host power-loss evidence.
        $ready=$nativePath.Substring(0,$nativePath.Length-5)+'-'+$gate+'-ready.txt'
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $ready) -or
            [IO.File]::ReadAllText($ready) -cne $readyContent) {
            throw ('Selected interruption window was not reached: '+$gate)
        }
        Stop-Service $service -ErrorAction Stop
        if($requestClient) {
            $receipt['interrupted_client']=Complete-RequestClient $requestClient $false
            $requestClient=$null
        }
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Interrupted operation receipt absent'}
        $interrupted=Get-Content -LiteralPath $nativePath -Raw|ConvertFrom-Json
        $expectedInterruption=if($InterruptAfterStage){'poststage gate stopped before forced VM poweroff'}else{$gate+' gate interrupted'}
        if($interrupted.status -ne 'recovery_required' -or $interrupted.error -notmatch $expectedInterruption -or
            $interrupted.error -notmatch '"code":"recovery_required"') {
            throw 'Interrupted ordinary apply did not truthfully retain recovery material'
        }
        $receipt['interruption']=[ordered]@{kind='controlled_service_cancellation';window=$gate;native=$interrupted;
            readiness_sha256=(Get-FileHash -LiteralPath $ready -Algorithm SHA256).Hash.ToLowerInvariant()}
        $before=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) `
            -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['interrupted_independent']=$before.independent
        $receipt['interrupted_observer_task_removed']=$before.observer_task_removed
        $publicBefore=@($before.independent.rows|Where-Object { -not $_.directory -and
            $_.path.StartsWith(($drive+'setup-state\'),[StringComparison]::Ordinal) })
        # The poststage window precedes setup-root bootstrap. Later windows
        # retain only its marker; none may have installed/audit completion.
        $expectedPublicCount=if($InterruptAfterStage){0}else{1}
        if($before.independent.identity -ne 'S-1-5-18' -or -not $before.observer_task_removed -or
            $publicBefore.Count -ne $expectedPublicCount -or
            ($expectedPublicCount -eq 1 -and $publicBefore[0].path -cne ($drive+'setup-state\.usk-owned-root.v1.json')) -or
            @($before.independent.rows|Where-Object path -ceq ($drive+'publication\state\lab-installed-state.json')).Count -ne 0) {
            throw ('Independent interrupted metadata differs: public_files='+($publicBefore.path -join ',')+
                '; identity='+$before.independent.identity+'; observer_removed='+$before.observer_task_removed)
        }
        Assert-IndependentProtectedRows -Rows $before.independent.rows -ServiceSid $sid
        $visibleRecords=@($before.independent.rows|Where-Object path -ceq ($drive+'publication\journal\lab-visible-evidence.json'))
        $expectedVisibleRecords=if($InterruptAfterVisibleRecord){1}else{0}
        if($visibleRecords.Count -ne $expectedVisibleRecords){throw 'Interrupted visible-journal boundary differs from selected window'}
        $payloadPrefix=if($InterruptBeforePublish -or $InterruptAfterStage){$drive+'publication\staging\candidate\'}else{$drive+'publication\destination\visible\'}
        $absentPrefix=if($InterruptBeforePublish -or $InterruptAfterStage){$drive+'publication\destination\visible'}else{$drive+'publication\staging\candidate'}
        if(@($before.independent.rows|Where-Object {$_.path -ceq $absentPrefix -or $_.path.StartsWith($absentPrefix+'\',[StringComparison]::Ordinal)}).Count -ne 0){throw 'Interrupted payload namespace differs from selected window'}
        foreach($entry in $plan.planned_entries|Where-Object entry_type -eq 'file') {
            $path=$payloadPrefix+$entry.relative_path.Replace('/','\')
            $row=@($before.independent.rows|Where-Object path -ceq $path)
            if($row.Count -ne 1 -or $row[0].sha256 -ne $entry.sha256 -or $row[0].bytes -ne $entry.size_bytes) {
                throw 'Independent interrupted visible payload differs'
            }
        }
        $snapshot=@($before.independent.rows|Where-Object path -ceq ($drive+'publication\journal\lab-reviewed-plan.json'))
        if($snapshot.Count -ne 1){throw 'Independent caller-bound snapshot absent'}
        $snapshotValue=$snapshot[0].content_json|ConvertFrom-Json
        if($snapshotValue.schema -ne $(if($ConsumerAccess){'usk.publisher.lab_reviewed_plan_snapshot.v4'}else{'usk.publisher.lab_reviewed_plan_snapshot.v3'}) -or
            $snapshotValue.transaction_id -ne $applyRequest.transaction_id -or
            $snapshotValue.applied_at -ne $applyRequest.applied_at -or
            $snapshotValue.plan_digest -ne $plan.plan_digest) {throw 'Interrupted snapshot caller binding differs'}
        # Delete only regular input files within this freshly created VM root;
        # retain minimal parsed inputs and independent observations in receipt.
        $removed=[Collections.Generic.List[string]]::new()
        foreach($path in @($archive,$envelope,$inputs.archive_file,$inputs.request_file,$requestPath,$ordinaryPath)) {
            $exact=[IO.Path]::GetFullPath($path)
            $item=Get-Item -LiteralPath $exact -Force
            if(-not $exact.StartsWith(($root+'\'),[StringComparison]::OrdinalIgnoreCase) -or
                $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Source-removal target escaped the newly created hosted input root'
            }
            Remove-Item -LiteralPath $exact -Force
            if(Test-Path -LiteralPath $exact){throw 'Original input remains after source removal'}
            $removed.Add($exact)
        }
        $receipt['removed_source_inputs']=$removed.ToArray()
        $recoveryPath=Join-Path $root ('vm-recovery-'+$id+'.json')
        $recoveryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$recoveryPath+'" '+$VolumeRoot+
            ' --recover-visible-bound --campaign-vm-id '+$vmId
        if($ClientBinary) {
            $recoveryPath=Join-Path $root ('vm-selected-reconnect-'+$id+'.json')
            $recoveryCommand=if($InterruptAfterStage){
                '"'+$ServiceBinary+'" --service '+$service+' "'+$recoveryPath+'" '+$VolumeRoot+
                    ' --recover-snapshot-only --campaign-vm-id '+$vmId+$clientArguments
            }else{
                '"'+$ServiceBinary+'" --service '+$service+' "'+$recoveryPath+'" '+$VolumeRoot+
                    $selectedClientArguments+$clientArguments
            }
        }
        & sc.exe config $service binPath= $recoveryCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned service recovery configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        $nativePath=$recoveryPath
        if($ClientBinary){$requestClient=Start-RequestClient}
    }
    if($InterruptDuringConsumerAccess) {
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Partial consumer grant receipt absent'}
        $partial=Get-Content -LiteralPath $nativePath -Raw|ConvertFrom-Json
        $receipt['partial_grant_native']=$partial
        if($partial.status -ne 'recovery_required' -or $partial.error -notmatch 'first consumer grant'){
            throw ('Expected injected grant interruption absent; native status='+$partial.status+'; error='+$partial.error)
        }
        $receipt['interrupted_consumer_client']=Complete-RequestClient $requestClient $false $true
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $before=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['partial_before_replay_independent']=$before.independent
        Assert-IndependentProtectedRows -Rows $before.independent.rows -ServiceSid $sid -ConsumerSid $consumerSid -VisibleRoot ($drive+'publication\destination\visible') -AllowPartial
        $granted=@($before.independent.rows|Where-Object {@($_.aces|Where-Object sid -eq $consumerSid).Count -eq 1})
        if($granted.Count -ne 1){throw 'First-grant interruption did not leave exactly one readable payload object'}
        $partialWitness=[pscustomobject]@{volume_drive_root=$drive;native=$partial;service_sid=$sid;consumer_sid=$consumerSid;
            independent=$before.independent;observer_task_removed=$before.observer_task_removed;plan=$plan;archive_sha256=$inputs.archive_sha256;
            apply_request=$applyRequest;request=$request.payload}
        Assert-IndependentMetadataProbe $partialWitness -AllowPartialConsumerGrant
        $receipt['partial_consumer_grant']=[ordered]@{native=$partial;independent=$before.independent;observer_task_removed=$before.observer_task_removed;granted_objects=$granted.Count}
        $removed=[Collections.Generic.List[string]]::new()
        foreach($path in @($archive,$envelope,$inputs.archive_file,$inputs.request_file,$requestPath,$ordinaryPath)) {
            $exact=[IO.Path]::GetFullPath($path);$item=Get-Item -LiteralPath $exact -Force
            if(-not $exact.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Consumer source removal target escaped owned root'}
            Remove-Item -LiteralPath $exact -Force
            if(Test-Path -LiteralPath $exact){throw 'Consumer source input remains'}
            $removed.Add($exact)
        }
        $receipt['removed_source_inputs']=$removed.ToArray()
        $nativePath=Join-Path $root ('vm-selected-consumer-reconnect-'+$id+'.json')
        $recoveryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$nativePath+'" '+$VolumeRoot+$selectedClientArguments+$clientArguments
        & sc.exe config $service binPath= $recoveryCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Consumer reconnect configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        $requestClient=Start-RequestClient
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
    if(-not (Test-Path -LiteralPath $nativePath)){throw 'Native service receipt absent'}
    $receipt.native=Get-Content -LiteralPath $nativePath -Raw|ConvertFrom-Json
    if($requestClient) {
        $receipt['authenticated_client']=Complete-RequestClient $requestClient $true
        $requestClient=$null
    }
    $receipt['consumer_sid']=$consumerSid
    $receipt['native_receipt_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
    if($receipt.native.status -ne 'pass'){throw ('Native metadata operation failed: '+$receipt.native.error)}
    $installedResponse=if($recover){$receipt.native.recovery_installed_response}else{$receipt.native.apply_response}
    if($recover -and $receipt.native.recovery_observation.decision -ne $recoveryDecision) {
        throw 'Source-free recovery did not perform the pending installed-state completion'
    }
    if($installedResponse.status -ne 'ok' -or
        $installedResponse.payload.schema -ne 'usk.installed_state.v1' -or
        $installedResponse.payload.transaction_id -ne $applyRequest.transaction_id -or
        $installedResponse.payload.created_at -ne $applyRequest.applied_at -or
        $installedResponse.payload.last_verification.status -ne 'pass') {
        throw 'Protected ordinary apply did not preserve caller identities and verified installed result'
    }
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId $id
    $receipt.independent=$readback.independent;$receipt.observer_task_removed=$readback.observer_task_removed
    Assert-IndependentMetadataProbe ([pscustomobject]$receipt)
    if($HostileRights) {
        $attackOutput=Join-Path (Split-Path -Parent $vhd) 'unprivileged-attack.json'
        & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid -OutputPath $attackOutput -Stage Postpublish -PayloadRelativePath $attackRelative
        $attack=Get-Content -LiteralPath $attackOutput -Raw|ConvertFrom-Json
        $receipt['postpublish_hostile_rights']=$attack
        if($attack.status -ne 'unprivileged_access_denied_observed' -or $attack.payload_relative_path -cne $attackRelative){
            throw 'Selected postpublish attacker result differs'
        }
        $afterAttack=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['postpublish_after_attack']=$afterAttack.independent
        if($afterAttack.independent.identity -ne 'S-1-5-18' -or -not $afterAttack.observer_task_removed -or
            ($receipt.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($afterAttack.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Selected postpublish hostile attempts changed published state'
        }
    }
    if($recover) {
        foreach($row in $before.independent.rows) {
            $completedPath=$row.path
            $stagedRoot=$drive+'publication\staging\candidate'
            if(($InterruptBeforePublish -or $InterruptAfterStage) -and ($row.path -ceq $stagedRoot -or $row.path.StartsWith($stagedRoot+'\',[StringComparison]::Ordinal))) {
                $completedPath=$drive+'publication\destination\visible'+$row.path.Substring($stagedRoot.Length)
            }
            $matching=@($receipt.independent.rows|Where-Object path -ceq $completedPath)
            if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or $matching[0].bytes -ne $row.bytes) {
                throw 'Recovery changed independently observed published payload or durable intent'
            }
        }
        # Re-enter the same source-free recovery operation. No published record
        # or public installed/audit record may change or acquire a duplicate.
        $repeatPath=Join-Path $root ('vm-recovery-repeat-'+$id+'.json')
        $repeatCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$repeatPath+'" '+$VolumeRoot+
            ' --recover-visible-bound --campaign-vm-id '+$vmId
        if($ClientBinary) {
            $repeatPath=Join-Path $root ('vm-selected-reconnect-repeat-'+$id+'.json')
            $repeatCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$repeatPath+'" '+$VolumeRoot+
                $selectedClientArguments+$clientArguments
        }
        & sc.exe config $service binPath= $repeatCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned service repeat configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        if($ClientBinary){$requestClient=Start-RequestClient}
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $repeatPath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $repeatPath)){throw 'Repeated recovery receipt absent'}
        $repeat=Get-Content -LiteralPath $repeatPath -Raw|ConvertFrom-Json
        if($requestClient) {
            $nativePath=$repeatPath
            $receipt['authenticated_client_repeat']=Complete-RequestClient $requestClient $true
            $requestClient=$null
        }
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        if($repeat.status -ne 'pass' -or $repeat.recovery_observation.decision -ne 'already_visible_bound' -or
            $repeat.recovery_installed_response.payload.transaction_id -ne $applyRequest.transaction_id -or
            $repeat.recovery_installed_response.payload.last_verification.status -ne 'pass') {
            throw 'Repeated source-free recovery did not preserve completed caller state'
        }
        $after=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $repeatResult=[pscustomobject]@{volume_drive_root=$drive;native=$repeat;service_sid=$sid;independent=$after.independent;
            observer_task_removed=$after.observer_task_removed;plan=$plan;archive_sha256=$inputs.archive_sha256;
            apply_request=$applyRequest;request=$request.payload;consumer_sid=$consumerSid}
        $repeatResult|Add-Member -NotePropertyName consumer_sid -NotePropertyValue $consumerSid -Force
        Assert-IndependentMetadataProbe $repeatResult
        if($after.independent.rows.Count -ne $receipt.independent.rows.Count){throw 'Repeated recovery changed record closure'}
        foreach($row in $receipt.independent.rows) {
            $matching=@($after.independent.rows|Where-Object path -ceq $row.path)
            if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or $matching[0].bytes -ne $row.bytes) {
                throw 'Repeated recovery changed a completed record or payload'
            }
        }
        $receipt['source_free_recovery']=[ordered]@{action=$recoveryDecision;repeat=$repeat;
            independent_repeat=$after.independent;repeat_observer_task_removed=$after.observer_task_removed;
            unchanged_row_count=$after.independent.rows.Count}
    }
    if($recover -and $ClientBinary) {
        # A genuine authenticated peer cannot change the durable request merely
        # by reusing this endpoint after successful recovery.
        $tampered=$applyRequest|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json
        $tampered.transaction_id='install.'+[guid]::NewGuid().ToString('N')
        $stalePath=Join-Path $root ('vm-selected-stale-client-'+$id+'.json')
        $staleCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$stalePath+'" '+$VolumeRoot+
            $selectedClientArguments+$clientArguments
        & sc.exe config $service binPath= $staleCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned stale-client service configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        $requestClient=Start-RequestClient $tampered
        $nativePath=$stalePath
        $receipt['stale_authenticated_client']=Complete-RequestClient $requestClient $false $true
        $requestClient=$null
        $stale=Get-Content -LiteralPath $stalePath -Raw|ConvertFrom-Json
        if($stale.status -ne 'failed' -or $stale.error -cne 'reviewed install reentry differs from durable plan and source') {
            throw 'Stale authenticated request was not refused by durable binding'
        }
        $unchanged=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) `
            -RunId ([guid]::NewGuid().ToString('N'))
        if(($after.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($unchanged.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Stale authenticated request changed retained installation records'
        }
        $receipt['stale_authenticated_request_unchanged_rows']=$unchanged.independent.rows.Count
        $receipt['stale_observer_task_removed']=$unchanged.observer_task_removed
    }
    if($ConsumerAccess) {
        $identityPath=Join-Path $consumerOutput 'payload-identity.json'
        $accessPath=Join-Path $consumerOutput 'payload-access.json'
        $consumerProcess=Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList @(
            '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$consumerScript,
            '-ExpectedUserSid',$consumerSid,'-IdentityPath',$identityPath,
            '-PayloadRoot',($drive+'publication\destination\visible'),'-AccessReceipt',$accessPath) -Credential $consumerCredential -PassThru -WindowStyle Hidden -WorkingDirectory $consumerOutput
        if(-not $consumerProcess.WaitForExit(45000)){Stop-OwnedPublisherProcessTree $consumerProcess|Out-Null;throw 'Consumer payload probe timed out'}
        $consumerProcess.WaitForExit()
        if($consumerProcess.ExitCode -ne 0){throw 'Non-admin payload access probe failed'}
        $access=Get-Content -LiteralPath $accessPath -Raw|ConvertFrom-Json
        if($access.status -ne 'pass' -or $access.identity.user_sid -cne $consumerSid -or $access.identity.administrator){throw 'Consumer access identity/result differs'}
        foreach($file in $access.files) {
            $row=@($receipt.independent.rows|Where-Object path -ceq $file.path)
            if($row.Count -ne 1 -or $row[0].sha256 -cne $file.sha256){throw 'Consumer-read bytes differ from independent SYSTEM readback'}
        }
        $receipt['consumer_access_observation']=$access
        $afterAccess=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $accessBaseline=if($recover){$after.independent.rows}else{$receipt.independent.rows}
        if(($accessBaseline|ConvertTo-Json -Depth 32 -Compress) -cne ($afterAccess.independent.rows|ConvertTo-Json -Depth 32 -Compress)){throw 'Consumer access attempts changed installed bytes/ACLs'}
        $receipt['consumer_attempts_unchanged_rows']=$afterAccess.independent.rows
        $receipt['consumer_attempts_observer_removed']=$afterAccess.observer_task_removed
    }
    $receipt.status='protected_metadata_observed'
} catch {
    $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'
} finally {
    if($requestClient) {
        try { Stop-OwnedPublisherProcessTree $requestClient.process|Out-Null }
        catch { $clientCleanupConfirmed=$false;$failure='Owned client cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($consumerProcess) {
        try {Stop-OwnedPublisherProcessTree $consumerProcess|Out-Null}
        catch {$clientCleanupConfirmed=$false;$failure='Consumer payload process cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    $receipt['client_cleanup_confirmed']=$clientCleanupConfirmed
    if($consumerCreated -and $clientCleanupConfirmed) {
        try {Remove-LocalUser -Name $consumerName -ErrorAction Stop;$receipt['consumer_account_removed']=$true}
        catch {$failure='Owned consumer account cleanup failed';$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($consumerCreated -and -not $clientCleanupConfirmed){$receipt['consumer_account_retained']=$consumerName}
    $consumerCredential=$null
    if($created) {
        try {
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
            & sc.exe delete $service|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned service deletion failed'}
            if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Owned service remains after deletion'}
            $receipt.service_removed=$true
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($receipt.status -eq 'protected_metadata_observed' -and $receipt.service_removed) {
        try {
            if([IO.Path]::GetFullPath($root) -cne 'C:\USK-Lab'){throw 'Owned hosted cleanup root differs'}
            $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($root)
            while($pending.Count) {
                $directory=$pending.Dequeue();$item=Get-Item -LiteralPath $directory -Force
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Hosted cleanup root contains a link'}
                foreach($child in Get-ChildItem -LiteralPath $directory -Force) {
                    if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Hosted cleanup input contains a link'}
                    if($child.PSIsContainer){$pending.Enqueue($child.FullName)}
                }
            }
            Remove-Item -LiteralPath $root -Recurse -Force
            if(Test-Path -LiteralPath $root){throw 'Owned hosted input cleanup did not complete'}
            $receipt['owned_input_root_removed']=$true
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    $receipt['observed_utc']=[DateTime]::UtcNow.ToString('o')
    $receipt|ConvertTo-Json -Depth 32|Set-Content -LiteralPath $out -Encoding UTF8
    # The existing outer harness dismounts/deletes only its identified VHD.
    # This entire hosted VM is disposable; no workstation resources are used.
}
if($failure){throw $failure}
Write-Output "Protected selected metadata observed: $out"
