# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [string]$ServiceControlBinary = '',
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
    [switch]$TerminateAtPoststage,
    [switch]$ReviewedSource,
    [switch]$RegisteredService,
    [switch]$MachineRequestClient,
    [switch]$NonAdminClient,
    [switch]$ExpectUnprotectedRefusal,
    [switch]$HostileRights
)
$ErrorActionPreference='Stop'
function Read-BoundedDiagnostic([string]$Path,[int]$Limit) {
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    try {
        $bytes=[byte[]]::new($Limit)
        $count=$stream.Read($bytes,0,$Limit)
        return [Text.Encoding]::UTF8.GetString($bytes,0,$count)
    } finally {$stream.Dispose()}
}
if(([int][bool]$InterruptAfterVisibleRecord+[int][bool]$InterruptAfterRename+[int][bool]$InterruptBeforePublish+[int][bool]$InterruptAfterStage) -gt 1){throw 'Select one interruption window'}
if($InterruptDuringConsumerAccess -and (-not $ConsumerAccess -or $InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage)){throw 'Consumer interruption requires its exclusive consumer profile'}
if($ConsumerAccess -and (-not $ClientBinary -or -not $PayloadBinary)){throw 'Consumer profile requires client and actual executable'}
if($InterruptAfterStage -and -not $ClientBinary){throw 'Snapshot-only replay requires an authenticated client'}
if($TerminateAtPoststage -and (-not $InterruptAfterStage -or -not $RegisteredService -or $MachineRequestClient -or $NonAdminClient -or $ConsumerAccess)){throw 'Poststage process termination requires the registered publisher client and its exclusive interruption window'}
if($ReviewedSource -and -not $ClientBinary){throw 'Reviewed source selection requires an authenticated client'}
if($ExpectUnprotectedRefusal -and (-not $ReviewedSource -or $ConsumerAccess -or $HostileRights -or
    $InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage)) {
    throw 'Unprotected-root refusal requires only the reviewed-source hosted profile'
}
if($RegisteredService -and (-not $ReviewedSource -or -not $ClientBinary -or -not $ServiceControlBinary -or
    $ExpectUnprotectedRefusal -or
    $InterruptAfterVisibleRecord -or $InterruptAfterRename -or
    $InterruptBeforePublish -or
    $InterruptDuringConsumerAccess)) {
    throw 'Registered service probe requires a reviewed-source request and at most the poststage interruption'
}
if($MachineRequestClient -and (-not $RegisteredService -or -not $MachineBinary -or
    $NonAdminClient -or $InterruptAfterStage -or $HostileRights)) {
    throw 'Packaged machine request client requires uninterrupted registered same-user service profile'
}
if($RegisteredService -and $HostileRights -and -not $NonAdminClient) {
    throw 'Registered hostile-rights proof requires the same owned non-admin client identity'
}
if($RegisteredService -and $InterruptAfterStage -and
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_lab_service_fault.exe') {
    throw 'Registered poststage interruption requires the separately built fault-test service'
}
if($RegisteredService -and $HostileRights -and
    (Split-Path -Leaf $ServiceBinary) -cne 'usk_publisher_lab_service_fault.exe') {
    throw 'Registered hostile-rights proof requires the separately built fault-test service'
}
if($NonAdminClient -and (-not $RegisteredService -or $ConsumerAccess)) {
    throw 'Non-admin client requires the registered service without consumer payload rights'
}
$registeredMode=if($ConsumerAccess){'--grant-client-read'}elseif($NonAdminClient){'--admit-client-observer'}else{''}
$recover=$InterruptAfterVisibleRecord -or $InterruptAfterRename -or $InterruptBeforePublish -or $InterruptAfterStage -or $InterruptDuringConsumerAccess
if($HostileRights -and $recover){throw 'Hostile-rights observation requires an uninterrupted operation'}
$gate=if($InterruptAfterStage){'poststage'}elseif($InterruptBeforePublish){'prepublish'}elseif($InterruptAfterRename){'postrename'}else{'postjournal'}
$readyContent=if($InterruptAfterStage){"usk.publisher.lab_snapshot_and_stage_sealed.v1`n"}elseif($InterruptBeforePublish){"usk.publisher.lab_prepared.v1`n"}elseif($InterruptAfterRename){"usk.publisher.lab_renamed_unconfirmed.v1`n"}else{"usk.publisher.lab_visible_recorded.v1`n"}
$recoveryDecision=if($InterruptAfterStage){'snapshot_only_completed_forward'}elseif($InterruptDuringConsumerAccess){'already_visible_bound'}elseif($InterruptAfterVisibleRecord){'installed_state_completed_forward'}else{'visible_bound_forward'}
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_payload_damage.ps1')
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
function Get-OwnedVolumeRootSddl([string]$Phase) {
    if($Phase -notin @('service-start','service-end') -or
        $VolumeRoot -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') {
        throw 'Owned root ACL observer arguments differ'
    }
    Assert-OwnedVolume
    $taskName='USK_ROOT_ACL_'+$id+'_'+$Phase
    $observation=Join-Path $observerRoot ('root-acl-'+$Phase+'.json')
    if((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $observation)) { throw 'Owned root ACL observer collision' }
    $command='$ErrorActionPreference=''Stop'';if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne ''S-1-5-18''){throw ''SYSTEM root ACL observer required''};'+
        '$sddl=(Get-Acl -LiteralPath '''+$VolumeRoot.Replace("'","''")+''').Sddl;'+
        '[IO.File]::WriteAllText('''+$observation.Replace("'","''")+''',(@{identity=''S-1-5-18'';sddl=$sddl}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $taskName
        $deadline=[DateTime]::UtcNow.AddSeconds(45)
        while(-not (Test-Path -LiteralPath $observation) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $observation)){throw 'Owned root ACL observer receipt absent'}
        $result=Get-Content -LiteralPath $observation -Raw|ConvertFrom-Json
        if($result.identity -ne 'S-1-5-18' -or [string]::IsNullOrWhiteSpace($result.sddl)) {
            throw 'Owned root ACL observer identity or descriptor differs'
        }
        return $result.sddl
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Owned root ACL observer cleanup failed'}
        }
        if(Test-Path -LiteralPath $observation){Remove-Item -LiteralPath $observation -Force -ErrorAction Stop}
    }
}
$vmId=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters').VirtualMachineId
if($vmId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw 'Observed hosted VM identity unavailable' }
$id=[guid]::NewGuid().ToString('N')
$service=$(if($RegisteredService){'USK_PUB_'}else{'USK_VM_'})+$id
$root='C:\USK-Lab'
if(Test-Path -LiteralPath $root){throw 'Unexpected existing hosted campaign input root'}
New-Item -ItemType Directory -Path $root|Out-Null
$fixture=Join-Path $root ('metadata-inputs-'+$id)
New-Item -ItemType Directory -Path $fixture|Out-Null
$nativePath=Join-Path $root ('vm-selected-'+$id+'.json')
$sourceDir=if($ReviewedSource){Join-Path $root 'authored-product'}else{$root}
if($ReviewedSource){New-Item -ItemType Directory -Path $sourceDir|Out-Null}
$archive=Join-Path $sourceDir ($(if($ReviewedSource){'product-'+$id+'.zip'}else{'selected-'+$id+'.zip'}))
$envelope=Join-Path $root ('plan-'+$id+'.json')
$out=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $out){throw 'Metadata receipt collision'}
$observerRoot=Join-Path (Split-Path -Parent $vhd) ('root-acl-observer-'+$id)
if((Split-Path -Parent $out) -ine (Split-Path -Parent $vhd) -or
    (Test-Path -LiteralPath $observerRoot)) { throw 'Owned root ACL observer output root differs' }
New-Item -ItemType Directory -Path $observerRoot -ErrorAction Stop|Out-Null
$runnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$observerAcl=[Security.AccessControl.DirectorySecurity]::new()
$observerAcl.SetSecurityDescriptorSddlForm('O:'+$runnerSid+'G:'+$runnerSid+
    'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+$runnerSid+')')
Set-Acl -LiteralPath $observerRoot -AclObject $observerAcl
$observedAcl=Get-Acl -LiteralPath $observerRoot
$observerRules=@($observedAcl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
if(-not $observedAcl.AreAccessRulesProtected -or $observerRules.Count -ne 2 -or
    @($observerRules|Where-Object {$_.IdentityReference.Value -eq 'S-1-5-18'}).Count -ne 1 -or
    @($observerRules|Where-Object {$_.IdentityReference.Value -eq $runnerSid}).Count -ne 1) {
    throw 'Owned SYSTEM observer output directory has an unexpected ACL'
}
$receipt=[ordered]@{schema='usk.publisher.metadata_vm_probe.v1';status='not_run';vm_id=$vmId;
    runner_environment=$env:RUNNER_ENVIRONMENT;os_build=[Environment]::OSVersion.Version.ToString();
    disk_unique_id=$disk.UniqueId;volume_guid_root=$VolumeRoot;volume_drive_root=$drive;service=$service;
    service_sid=$null;binary_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    archive_sha256=$null;strip_prefix='pkg';request=$null;plan=$null;native=$null;independent=$null;
    observer_task_removed=$false;service_removed=$false;failure=$null;power_loss_test=$false}
$created=$false
$registrationAttempted=$false
$expectedRegisteredCommand=''
$failure=$null
$requestClient=$null
$clientNumber=0
$consumerCreated=$false
$consumerCredential=$null
$consumerSid=''
$consumerProcess=$null
$concurrentAttacker=$null
$concurrentOutput=''
$concurrentCompleted=''
$clientCleanupConfirmed=$true
$consumerOutput=Join-Path $root 'consumer-output'
$consumerScript=Join-Path $root 'consumer-client.ps1'
function Read-NativeReceipt([string]$Path) {
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while($true) {
        try { $raw=[IO.File]::ReadAllText($Path); break }
        catch [IO.IOException] {
            if([DateTime]::UtcNow -ge $deadline){throw}
            Start-Sleep -Milliseconds 100
        }
    }
    if(-not $raw -or $raw.Length -gt 4MB){throw 'Native service receipt is empty or exceeds bound'}
    return $raw|ConvertFrom-Json
}
function Start-RegisteredPublisher {
    $startArgs=@('--start',$service,$ServiceBinary,$VolumeRoot,$callerSid)
    if($registeredMode){$startArgs+=$registeredMode}
    $started=& $ServiceControlBinary @startArgs
    if($LASTEXITCODE -ne 0 -or ($started|ConvertFrom-Json).status -ne 'start_requested') {
        throw 'Product service control did not start the matching publisher'
    }
}
function Start-RequestClient($submitted=$applyRequest) {
    $script:clientNumber++
    $prefix=Join-Path $(if($ConsumerAccess -or $NonAdminClient){$consumerOutput}else{$root}) ('client-'+$clientNumber)
    $clientRequest=$prefix+'-request.json'
    [IO.File]::WriteAllText($clientRequest,($submitted|ConvertTo-Json -Depth 32 -Compress),$utf8)
    $requestBinary=if($MachineRequestClient){$MachineBinary}else{$ClientBinary}
    $clientMode=if($MachineRequestClient){'candidate-service'}else{'service'}
    $binaryDigest=(Get-FileHash -LiteralPath $requestBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $requestArgs=if($MachineRequestClient){@('--candidate-service',$service,'--request-file',('"'+$clientRequest+'"'))}else{@('--service',$service,'--request-file',('"'+$clientRequest+'"'))}
    $options=@{FilePath=$requestBinary;ArgumentList=$requestArgs;
        WindowStyle='Hidden';PassThru=$true;RedirectStandardOutput=$prefix+'-response.json';RedirectStandardError=$prefix+'-error.txt'}
    $identityPath=$prefix+'-identity.json'
    if($ConsumerAccess -or $NonAdminClient) {
        $options.FilePath=(Get-Command pwsh).Source
        $options.ArgumentList=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$consumerScript,
            '-ExpectedUserSid',$consumerSid,'-IdentityPath',$identityPath,'-ClientBinary',$requestBinary,
            '-ClientMode',$clientMode,'-ExpectedClientSha256',$binaryDigest,
            '-ServiceName',$service,'-RequestFile',$clientRequest)
        $options['Credential']=$consumerCredential
        $options['WorkingDirectory']=$consumerOutput
    }
    $process=Start-Process @options
    return [pscustomobject]@{process=$process;response=$prefix+'-response.json';error=$prefix+'-error.txt';
        identity=$identityPath;binary_path=[IO.Path]::GetFullPath($requestBinary);
        binary_sha256=$binaryDigest;client_mode=$clientMode}
}
function Assert-RequestClientImage($client) {
    if(-not ($ConsumerAccess -or $NonAdminClient)){return $null}
    $actual=Get-Content -LiteralPath $client.identity -Raw|ConvertFrom-Json
    if($actual.user_sid -cne $consumerSid -or $actual.administrator -or
        $actual.client_binary_path -cne $client.binary_path -or
        $actual.client_binary_sha256 -cne $client.binary_sha256 -or
        $actual.client_mode -cne $client.client_mode) {
        throw 'Actual client identity, executable or request mode differs'
    }
    return $actual
}
function Complete-RequestClient($client,[bool]$expectSuccess,[bool]$requireFailureResponse=$false) {
    if(-not $client.process.WaitForExit(120000)) {
        Stop-OwnedPublisherProcessTree $client.process|Out-Null;throw 'Owned request client timed out'
    }
    $client.process.WaitForExit()
    if(($client.process.ExitCode -eq 0) -ne $expectSuccess) {
        throw ('Request client exit differs: '+$client.process.ExitCode+'; '+[IO.File]::ReadAllText($client.error))
    }
    $requestBinary=if($MachineRequestClient){$MachineBinary}else{$ClientBinary}
    $result=[ordered]@{exit_code=$client.process.ExitCode;binary_sha256=(Get-FileHash -LiteralPath $requestBinary -Algorithm SHA256).Hash.ToLowerInvariant();
        caller_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    if($ConsumerAccess -or $NonAdminClient) {
        $actual=Assert-RequestClientImage $client
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
    if($ConsumerAccess -or $NonAdminClient) {
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
        if(-not ($RegisteredService -and $ConsumerAccess)) {
            Copy-Item -LiteralPath $ClientBinary -Destination $clientCopy
            $ClientBinary=$clientCopy
        }
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
    $packageRoot=''
    if($RegisteredService -and -not $NonAdminClient -and -not $InterruptAfterStage -and -not $HostileRights) {
        # Exercise the actual emitted native package through installation.
        # The fault-test service and externally admitted VHD ACL helper are
        # deliberately outside this ordinary candidate package.
        $packageRoot=Join-Path $root ('candidate-package-'+$id)
        New-Item -ItemType Directory -Path $packageRoot -ErrorAction Stop|Out-Null
        $packed=& python -B (Join-Path $PSScriptRoot '..\tools\usk_selected_candidate_package.py') build `
            --bundle $inputs.bundle_file --machine $MachineBinary --service $ServiceBinary `
            --control $ServiceControlBinary --client $ClientBinary --output-dir $packageRoot
        if($LASTEXITCODE -ne 0){throw 'Selected native candidate package build failed'}
        $package=$packed|ConvertFrom-Json
        if($package.schema -ne 'usk.selected_ntfs_candidate_package.v1' -or
            $package.installation_mode -ne 'selected_ntfs_candidate' -or
            $package.product_id -ne 'org.example.metadata') {
            throw 'Selected candidate package identity differs'
        }
        $MachineBinary=Join-Path $packageRoot 'inspect\usk_machine.exe'
        $ServiceBinary=Join-Path $packageRoot 'publisher\usk_publisher_lab_service.exe'
        $ServiceControlBinary=Join-Path $packageRoot 'publisher\usk_publisher_service_control.exe'
        $ClientBinary=Join-Path $packageRoot 'publisher\usk_publisher_client.exe'
        if($ConsumerAccess) {
            Copy-Item -LiteralPath $ClientBinary -Destination $clientCopy
            if((Get-FileHash -LiteralPath $ClientBinary -Algorithm SHA256).Hash -cne
                (Get-FileHash -LiteralPath $clientCopy -Algorithm SHA256).Hash) {
                throw 'Non-admin client copy differs from emitted package'
            }
            $ClientBinary=$clientCopy
        }
        $archive=Join-Path $packageRoot 'inspect\payload.zip'
        $inputs.archive_sha256=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        $receipt['strip_prefix']=''
        $receipt['candidate_package_manifest_sha256']=(Get-FileHash -LiteralPath `
            (Join-Path $packageRoot 'setup-package.manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $productInfo=& $MachineBinary --product-info (Join-Path $packageRoot 'inspect\product.bundle.json')
        if($LASTEXITCODE -ne 0 -or ($productInfo|ConvertFrom-Json).payload_sha256 -cne
            $inputs.archive_sha256) {throw 'Packaged native product inspection differs'}
    } else {
        Copy-Item -LiteralPath $inputs.archive_file -Destination $archive
    }
    $request=Get-Content -LiteralPath $inputs.request_file -Raw|ConvertFrom-Json
    $request.payload.archive.path=$archive
    if($packageRoot) {
        $request.payload.archive.strip_prefix=''
        $request.payload.archive.expected_sha256=$inputs.archive_sha256
        $request.payload.archive.budgets.max_depth=([int]$request.payload.archive.budgets.max_depth)-1
    }
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
    $receipt['source_mode']=if($RegisteredService){'registered_reviewed_service'}elseif($ReviewedSource){'authenticated_reviewed_envelope'}else{'legacy_scm_source_binding'}
    $responsePath=Join-Path $root ('metadata-plan-response-'+$id+'.json')
    [IO.File]::WriteAllText($responsePath,($output -join "`n")+"`n",$utf8)
    $bindingDir=Join-Path $root ('authored-binding-'+$id)
    $bound=& python -B (Join-Path $PSScriptRoot '..\tools\usk_bundle_apply_binding.py') `
        --request-file $requestPath --response-file $responsePath `
        --acceptance-root $drive --state-root ($drive+'setup-state') `
        --transaction-id ('install.'+$id) `
        --applied-at ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) `
        --output-dir $bindingDir
    if($LASTEXITCODE -ne 0){throw 'Authored native plan could not bind a protected apply'}
    $binding=$bound|ConvertFrom-Json
    if($binding.schema -ne 'usk.publisher.candidate_binding.v1' -or
        $binding.apply_file -cne (Join-Path $bindingDir 'apply.json') -or
        $binding.envelope_file -cne (Join-Path $bindingDir 'envelope.json')) {
        throw 'Authored apply binding output differs'
    }
    $applyRequest=Get-Content -LiteralPath $binding.apply_file -Raw|ConvertFrom-Json
    $recoveryRequest=[ordered]@{
        schema='usk.publisher_recovery_request.v1'
        request_id='recover.'+$id
        install_id=$applyRequest.plan_request.install_id
        transaction_id=$applyRequest.transaction_id
    }
    if($RegisteredService) {
        $envelope=$binding.envelope_file
    } else {
        # The existing disposable service grammar admits only plan-ID files
        # directly beneath C:\USK-Lab. Keep the authored bytes and digest.
        Copy-Item -LiteralPath $binding.envelope_file -Destination $envelope -ErrorAction Stop
    }
    if((Get-FileHash -LiteralPath $envelope -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $binding.envelope_sha256) {throw 'Authored apply envelope identity differs'}
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
    $sourceInputs=@($archive,$envelope,$inputs.archive_file,$inputs.request_file,
        $requestPath,$contextPath,$ordinaryPath,$responsePath,$binding.apply_file)+@($inputs.source_files)
    if($envelope -cne $binding.envelope_file){$sourceInputs+=@($binding.envelope_file)}
    if($packageRoot) {
        $sourceInputs+=@((Join-Path $packageRoot 'inspect\product.bundle.json'),
            (Join-Path $packageRoot 'inspect\prefab.manifest.json'),
            (Join-Path $packageRoot 'setup-package.manifest.json'))
    }
    $receipt['envelope_sha256']=$binding.envelope_sha256
    $selectedClientArguments=if($ReviewedSource){
        ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256+' --campaign-vm-id '+$vmId
    }else{
        ' --selected-zip "'+$archive+'" '+$inputs.archive_sha256+' --campaign-vm-id '+$vmId+
            ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256
    }
    $command='"'+$ServiceBinary+'" --service '+$service+' "'+$nativePath+'" '+$VolumeRoot+$selectedClientArguments
    if($recover -and -not $InterruptDuringConsumerAccess){$command+=' --'+$gate+'-gate'}
    if($HostileRights){$command+=' --prepublish-gate'}
    if($InterruptDuringConsumerAccess){$command+=' --interrupt-consumer-grant'}
    if($ClientBinary) {
        $callerSid=if($ConsumerAccess -or $NonAdminClient){$consumerSid}else{[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
        $clientArguments=' --authorized-client-sid '+$callerSid
        if($ConsumerAccess){$clientArguments+=' --grant-client-read'}
        $command+=$clientArguments
    }
    if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Service collision'}
    if($RegisteredService) {
        $expectedRegisteredCommand='"'+$ServiceBinary+'" --service '+$service+' --no-receipt '+$VolumeRoot+
            ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256+
            $(if($NonAdminClient){' --admit-client-observer'}else{''})+
            ' --authorized-client-sid '+$callerSid+
            $(if($ConsumerAccess){' --grant-client-read'}else{''})
        $controlArgs=@('--register',$service,$ServiceBinary,$VolumeRoot,$envelope,
            $receipt.envelope_sha256,$callerSid)
        if($registeredMode){$controlArgs+=$registeredMode}
        $registrationAttempted=$true
        $registered=& $ServiceControlBinary @controlArgs
        if($LASTEXITCODE -ne 0){throw 'Product service control did not register the reviewed publisher'}
        $created=$true
        if(($registered|ConvertFrom-Json).status -ne 'registered') {
            throw 'Product service control did not register the reviewed publisher'
        }
        $receipt['service_control_binary_sha256']=(Get-FileHash -LiteralPath $ServiceControlBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    } else {
        & sc.exe create $service type= own start= demand obj= LocalSystem binPath= $command|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned service creation failed'}
        & sc.exe sidtype $service restricted|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Restricted service configuration failed'}
    }
    $created=$true
    $sid=[Security.Principal.NTAccount]::new('NT SERVICE\'+$service).Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt.service_sid=$sid
    # Only this newly created input directory in the disposable hosted VM is
    # writable by the service. The independent observer lives elsewhere.
    $acl=Get-Acl -LiteralPath $root
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sid),'Modify',
        'ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $root -AclObject $acl
    if($ReviewedSource) {
        $sourceAcl=Get-Acl -LiteralPath $sourceDir
        $sourceAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),'ReadAndExecute',
            'ContainerInherit,ObjectInherit','None','Allow'))
        Set-Acl -LiteralPath $sourceDir -AclObject $sourceAcl
    }
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
    if(-not $ExpectUnprotectedRefusal) {
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$sid+')')
        Set-Acl -LiteralPath $VolumeRoot -AclObject $acl
    }
    $receipt['root_acl_at_service_start']=Get-OwnedVolumeRootSddl 'service-start'
    Assert-OwnedVolume
    $device=& $DeviceAclBinary --owned-hosted-vm-vhd-volume $VolumeRoot $service ([int]$disk.Number) $vhd $vmId 2>&1
    if($LASTEXITCODE -ne 0){throw ('Owned VHD device ACL failed: '+($device -join '; '))}
    if($RegisteredService) {
        $wrongStartError=Join-Path $root ('wrong-start-'+$id+'.txt')
        $wrongStartArgs=@('--start',$service,$ServiceBinary,$VolumeRoot,'S-1-5-18')
        if($registeredMode){$wrongStartArgs+=$registeredMode}
        & $ServiceControlBinary @wrongStartArgs 2>$wrongStartError|Out-Null
        if($LASTEXITCODE -eq 0 -or (Get-Service $service).Status -ne 'Stopped') {
            throw 'Registered publisher accepted a different start caller'
        }
        $receipt['wrong_caller_start_refused']=$true
        if($ConsumerAccess) {
            $wrongModeError=Join-Path $root ('wrong-mode-'+$id+'.txt')
            & $ServiceControlBinary --start $service $ServiceBinary $VolumeRoot $callerSid `
                --admit-client-observer 2>$wrongModeError|Out-Null
            if($LASTEXITCODE -eq 0 -or (Get-Service $service).Status -ne 'Stopped') {
                throw 'Registered publisher accepted a weaker caller mode'
            }
            $receipt['wrong_caller_mode_refused']=$true
        }
        if($InterruptAfterStage -or $HostileRights) {
            $registeredGate=if($HostileRights){'--prepublish-gate'}else{'--poststage-gate'}
            $testCommand='"'+$ServiceBinary+'" --service '+$service+' --no-receipt '+$VolumeRoot+
                ' --reviewed-plan-envelope "'+$envelope+'" '+$receipt.envelope_sha256+
                ' --test-gate-receipt "'+$nativePath+'" '+$registeredGate+
                $(if($NonAdminClient){' --admit-client-observer'}else{''})+
                ' --authorized-client-sid '+$callerSid
            & sc.exe config $service binPath= $testCommand|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned fault-test service configuration failed'}
            if((Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $testCommand) {
                throw 'Owned fault-test service command readback differs'
            }
            try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        } else { Start-RegisteredPublisher }
    } else {
        try{Start-Service $service}catch{
            if($recover){throw ('Interruption service start failed: '+$_.Exception.Message)}
            if((Get-Service $service).Status -ne 'Stopped'){throw}
        }
    }
    if($TerminateAtPoststage) {
        # Hold the exact service process before sending the request. The
        # handle prevents a later PID from becoming our termination target.
        $serviceAtStart=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($serviceAtStart.State -cne 'Running' -or $serviceAtStart.ProcessId -le 0 -or
            $serviceAtStart.PathName -cne $testCommand) {
            throw 'Owned fault-test service did not start with its exact configuration'
        }
        $heldServiceProcess=Get-Process -Id $serviceAtStart.ProcessId -ErrorAction Stop
        $null=$heldServiceProcess.Handle
        $serviceProcessAtStart=Get-CimInstance Win32_Process -Filter ('ProcessId='+$serviceAtStart.ProcessId) -ErrorAction Stop
        if(-not $serviceProcessAtStart -or -not $serviceProcessAtStart.CreationDate -or
            $serviceProcessAtStart.CommandLine -cne $testCommand -or
            -not [string]::Equals([IO.Path]::GetFullPath($serviceProcessAtStart.ExecutablePath),
                [IO.Path]::GetFullPath($ServiceBinary),[StringComparison]::OrdinalIgnoreCase) -or
            [math]::Abs(($serviceProcessAtStart.CreationDate.ToUniversalTime()-
                $heldServiceProcess.StartTime.ToUniversalTime()).Ticks) -gt 10000) {
            throw 'Owned fault-test process differs before client submission'
        }
        $heldServiceIdentity=[pscustomobject]@{pid=$serviceAtStart.ProcessId;
            created=$serviceProcessAtStart.CreationDate;
            executable=$serviceProcessAtStart.ExecutablePath;
            command=$serviceProcessAtStart.CommandLine;
            started_utc=$heldServiceProcess.StartTime.ToUniversalTime().ToString('o')}
    }
    $terminalServiceProcess=$null
    if($RegisteredService -and -not $HostileRights -and -not $recover) {
        $terminalAtStart=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($terminalAtStart.State -cne 'Running' -or $terminalAtStart.ProcessId -le 0 -or
            $terminalAtStart.PathName -cne $expectedRegisteredCommand) {
            throw 'Terminal service did not start with its registered command'
        }
        $terminalServiceProcess=Get-Process -Id $terminalAtStart.ProcessId -ErrorAction Stop
        $null=$terminalServiceProcess.Handle
        $terminalProcessAtStart=Get-CimInstance Win32_Process -Filter ('ProcessId='+$terminalAtStart.ProcessId) -ErrorAction Stop
        if(-not $terminalProcessAtStart -or -not $terminalProcessAtStart.CreationDate -or
            $terminalProcessAtStart.CommandLine -cne $expectedRegisteredCommand -or
            -not [string]::Equals([IO.Path]::GetFullPath($terminalProcessAtStart.ExecutablePath),
                [IO.Path]::GetFullPath($ServiceBinary),[StringComparison]::OrdinalIgnoreCase) -or
            [math]::Abs(($terminalProcessAtStart.CreationDate.ToUniversalTime()-
                $terminalServiceProcess.StartTime.ToUniversalTime()).Ticks) -gt 10000) {
            throw 'Terminal service process differs from registered command'
        }
        $receipt['terminal_service_process_id']=$terminalAtStart.ProcessId
    }
    if($ClientBinary){$requestClient=Start-RequestClient}
    if($ExpectUnprotectedRefusal) {
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Unprotected-root refusal receipt absent'}
        $receipt.native=Read-NativeReceipt $nativePath
        $receipt['refused_client']=Complete-RequestClient $requestClient $false $true
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $receipt['root_acl_after']=(Get-Acl -LiteralPath $VolumeRoot).Sddl
        if($receipt.native.status -ne 'failed' -or
            $receipt.native.error -notmatch 'publisher protected object shape differs|publisher protected DACL ACEs differ|cannot open admitted publisher volume root' -or
            $receipt.root_acl_before -cne $receipt.root_acl_after -or
            (Test-Path -LiteralPath ($drive+'publication')) -or
            (Test-Path -LiteralPath ($drive+'setup-state'))) {
            throw 'Unprotected boundary was changed or admitted before publication'
        }
        $receipt.status='preprotected_boundary_refusal_observed'
    } else {
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
        $attackIdentity=if($RegisteredService -and $NonAdminClient){
            @{ExistingCredential=$consumerCredential;ExistingSid=$consumerSid}
        }else{@{}}
        & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid -OutputPath $attackOutput -Stage Prepublish -PayloadRelativePath $attackRelative @attackIdentity
        $attack=Get-Content -LiteralPath $attackOutput -Raw|ConvertFrom-Json
        $receipt['prepublish_hostile_rights']=$attack
        if($attack.status -ne 'unprivileged_access_denied_observed' -or $attack.payload_relative_path -cne $attackRelative){
            throw 'Selected prepublish attacker result differs'
        }
        if($RegisteredService -and ($attack.account_sid -cne $consumerSid -or
            $attack.account_origin -cne 'existing_owned_client')) {
            throw 'Registered prepublish attacker did not use the submitting client identity'
        }
        $pausedAfter=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['prepublish_after_attack']=$pausedAfter.independent
        if($pausedAfter.independent.identity -ne 'S-1-5-18' -or -not $pausedAfter.observer_task_removed -or
            ($pausedBefore.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($pausedAfter.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Selected prepublish hostile attempts changed protected state'
        }
        if($RegisteredService -and $NonAdminClient) {
            # Keep the actual submitting account attacking the protected
            # destination while the held service crosses the rename window.
            $concurrentOutput=Join-Path $consumerOutput 'concurrent-attack.json'
            $concurrentReady=Join-Path $consumerOutput 'concurrent-ready.txt'
            $concurrentCompleted=Join-Path $consumerOutput 'concurrent-completed.txt'
            if((Test-Path -LiteralPath $concurrentOutput) -or
                (Test-Path -LiteralPath $concurrentReady) -or
                (Test-Path -LiteralPath $concurrentCompleted)) {
                throw 'Concurrent attacker output is not fresh'
            }
            $attackArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                '-File',('"'+(Join-Path $PSScriptRoot 'windows_publisher_unprivileged_probe.ps1')+'"'),
                '-VolumeRoot',('"'+$VolumeRoot+'"'),'-ExpectedUserSid',$consumerSid,
                '-ServiceSid',$sid,'-OutputPath',('"'+$concurrentOutput+'"'),
                '-Stage','Concurrent','-ReleasePath',('"'+$release+'"'),
                '-PayloadRelativePath',$attackRelative)
            $concurrentAttacker=Start-Process -FilePath (Get-Command pwsh).Source `
                -ArgumentList $attackArgs -Credential $consumerCredential -PassThru `
                -WindowStyle Hidden -WorkingDirectory $consumerOutput -ErrorAction Stop
            $attackerDeadline=[DateTime]::UtcNow.AddSeconds(30)
            while(-not (Test-Path -LiteralPath $concurrentReady) -and
                [DateTime]::UtcNow -lt $attackerDeadline) {
                if($concurrentAttacker.HasExited){throw 'Concurrent attacker exited before readiness'}
                Start-Sleep -Milliseconds 25
            }
            if(-not (Test-Path -LiteralPath $concurrentReady) -or
                [IO.File]::ReadAllText($concurrentReady) -cne "usk.publisher.concurrent_ready.v1`n") {
                throw 'Concurrent attacker did not establish prepublish denial'
            }
            $attackerProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$concurrentAttacker.Id) -ErrorAction Stop
            $attackerOwner=Invoke-CimMethod -InputObject $attackerProcess -MethodName GetOwnerSid
            if(-not $attackerProcess -or $attackerOwner.ReturnValue -ne 0 -or
                $attackerOwner.Sid -cne $consumerSid -or
                -not $attackerProcess.CommandLine.Contains('windows_publisher_unprivileged_probe.ps1')) {
                throw 'Concurrent attacker differs from the submitting non-admin process'
            }
            $receipt['concurrent_attacker_process_id']=$concurrentAttacker.Id
            $receipt['concurrent_attacker_sid']=$attackerOwner.Sid
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
        while(-not (Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $deadline){
            if((Test-Path -LiteralPath $nativePath) -and
                (Get-Service $service -ErrorAction SilentlyContinue).Status -eq 'Stopped'){break}
            Start-Sleep -Milliseconds 250
        }
        if(-not (Test-Path -LiteralPath $ready) -or
            [IO.File]::ReadAllText($ready) -cne $readyContent) {
            $nativeError=if(Test-Path -LiteralPath $nativePath){
                Read-BoundedDiagnostic $nativePath 2048
            }else{'native receipt absent'}
            $clientError=if($requestClient -and (Test-Path -LiteralPath $requestClient.error)){
                Read-BoundedDiagnostic $requestClient.error 1024
            }else{'client error absent'}
            $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction SilentlyContinue
            throw ('Selected interruption window was not reached: '+$gate+
                '; service='+$serviceInfo.State+'; exit_code='+$serviceInfo.ExitCode+
                '; service_exit_code='+$serviceInfo.ServiceSpecificExitCode+
                '; native='+$nativeError+'; client='+$clientError)
        }
        if($TerminateAtPoststage) {
            # This deliberately kills only the held, exact campaign service
            # process. It is a transport-loss test, never power-loss evidence.
            $serviceInfo=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
            $serviceProcessAtGate=Get-CimInstance Win32_Process -Filter ('ProcessId='+$heldServiceIdentity.pid) -ErrorAction Stop
            if($heldServiceProcess.HasExited -or $serviceInfo.State -cne 'Running' -or
                $serviceInfo.ProcessId -ne $heldServiceIdentity.pid -or
                $serviceInfo.PathName -cne $testCommand -or
                -not $serviceProcessAtGate -or
                $serviceProcessAtGate.CreationDate -ne $heldServiceIdentity.created -or
                $serviceProcessAtGate.ExecutablePath -cne $heldServiceIdentity.executable -or
                $serviceProcessAtGate.CommandLine -cne $heldServiceIdentity.command) {
                throw 'Held owned service process changed before required termination'
            }
            $terminated=Stop-OwnedPublisherProcessTree $heldServiceProcess -RequireLiveKill
            if(-not $terminated.confirmed -or -not $terminated.kill_invoked -or
                $terminated.terminated -lt 1) {
                throw 'Owned fault-test service was not killed and confirmed'
            }
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
            if((Get-Service $service).Status -ne 'Stopped'){throw 'SCM retained the terminated test service'}
        } else {
            Stop-Service $service -ErrorAction Stop
        }
        if($requestClient) {
            $receipt['interrupted_client']=Complete-RequestClient $requestClient $false
            $requestClient=$null
            if($TerminateAtPoststage -and
                ($receipt.interrupted_client.exit_code -ne 5 -or
                 $receipt.interrupted_client.delivery -cne 'outcome_unknown')) {
                throw 'Terminated poststage client did not report unknown outcome'
            }
        }
        if($TerminateAtPoststage) {
            if(Test-Path -LiteralPath $nativePath){throw 'Killed service wrote a terminal native receipt'}
            $receipt['interruption']=[ordered]@{kind='controlled_process_termination';window=$gate;
                service_pid=$heldServiceIdentity.pid;service_started_utc=$heldServiceIdentity.started_utc;
                service_executable_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
                readiness_sha256=(Get-FileHash -LiteralPath $ready -Algorithm SHA256).Hash.ToLowerInvariant()}
        } else {
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
            if(-not (Test-Path -LiteralPath $nativePath)){throw 'Interrupted operation receipt absent'}
            $interrupted=Read-NativeReceipt $nativePath
            $expectedInterruption=if($InterruptAfterStage){'poststage gate stopped before forced VM poweroff'}else{$gate+' gate interrupted'}
            if($interrupted.status -ne 'recovery_required' -or $interrupted.error -notmatch $expectedInterruption -or
                $interrupted.error -notmatch '"code":"recovery_required"') {
                throw 'Interrupted ordinary apply did not truthfully retain recovery material'
            }
            $receipt['interruption']=[ordered]@{kind='controlled_service_cancellation';window=$gate;native=$interrupted;
                readiness_sha256=(Get-FileHash -LiteralPath $ready -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
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
        foreach($path in $sourceInputs) {
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
            $recoveryPath=Join-Path $root ('vm-recovery-reviewed-'+$id+'.json')
            $recoveryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$recoveryPath+'" '+$VolumeRoot+
                ' --recover-reviewed --campaign-vm-id '+$vmId+$clientArguments
        }
        if($RegisteredService) {
            # Remove only the test-only gate from the exact generated service.
            # The ordinary control then validates the original binding and
            # configures its source-free recovery command.
            & sc.exe config $service binPath= $expectedRegisteredCommand|Out-Null
            if($LASTEXITCODE -ne 0 -or
                (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
                throw 'Owned fault-test command could not be restored'
            }
            $controlArgs=@('--recover',$service,$ServiceBinary,$VolumeRoot,$callerSid)
            if($registeredMode){$controlArgs+=$registeredMode}
            $configuredRecovery=& $ServiceControlBinary @controlArgs
            if($LASTEXITCODE -ne 0 -or ($configuredRecovery|ConvertFrom-Json).status -ne 'recovery_configured') {
                throw 'Product service control did not configure incomplete-phase recovery'
            }
            $nativePath=$recoveryPath
            Start-RegisteredPublisher
            $requestClient=Start-RequestClient $recoveryRequest
        } else {
            & sc.exe config $service binPath= $recoveryCommand|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned service recovery configuration failed'}
            try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
            $nativePath=$recoveryPath
            if($ClientBinary){$requestClient=Start-RequestClient}
        }
    }
    if($InterruptDuringConsumerAccess) {
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Partial consumer grant receipt absent'}
        $partial=Read-NativeReceipt $nativePath
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
        foreach($path in $sourceInputs) {
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
    if($RegisteredService) {
        if(-not $requestClient.process.WaitForExit(120000)){throw 'Registered service client timed out'}
        $requestClient.process.WaitForExit()
        if($requestClient.process.ExitCode -ne 0 -or
            (Get-Item -LiteralPath $requestClient.response).Length -gt 4MB -or
            ((Test-Path -LiteralPath $nativePath) -and -not $HostileRights)) {
            throw ('Registered service client failed or wrote a lab receipt: '+[IO.File]::ReadAllText($requestClient.error))
        }
        $receipt.native=Get-Content -LiteralPath $requestClient.response -Raw|ConvertFrom-Json
        if($HostileRights) {
            if(-not (Test-Path -LiteralPath $nativePath) -or
                [IO.File]::ReadAllText($requestClient.response).Trim() -cne
                [IO.File]::ReadAllText($nativePath).Trim()) {
                throw 'Registered hostile service receipt differs from authenticated client result'
            }
            $receipt['native_receipt_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
            $nativePath=Join-Path $root ('registered-no-receipt-'+$id+'.json')
            if(Test-Path -LiteralPath $nativePath) {
                throw 'Registered recovery absence marker already exists'
            }
        }
        if($ConsumerAccess -or $NonAdminClient) {
            $actual=Assert-RequestClientImage $requestClient
            $receipt['registered_client_identity']=$actual
        }
        $requestBinary=if($MachineRequestClient){$MachineBinary}else{$ClientBinary}
        $receipt['authenticated_client']=[ordered]@{exit_code=0;caller_sid=$callerSid;
            binary_sha256=(Get-FileHash -LiteralPath $requestBinary -Algorithm SHA256).Hash.ToLowerInvariant();
            response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant();
            delivery='response_received'}
        $receipt['native_response_sha256']=$receipt.authenticated_client.response_sha256
        $requestClient=$null
        if($concurrentAttacker) {
            [IO.File]::WriteAllText($concurrentCompleted,
                "usk.publisher.concurrent_completed.v1`n",[Text.UTF8Encoding]::new($false))
            if(-not $concurrentAttacker.WaitForExit(30000)) {
                throw 'Concurrent attacker remained after terminal publisher reply'
            }
            $concurrentAttacker.WaitForExit()
            if($concurrentAttacker.ExitCode -ne 0 -or
                -not (Test-Path -LiteralPath $concurrentOutput -PathType Leaf) -or
                (Get-Item -LiteralPath $concurrentOutput).Length -gt 16KB) {
                throw 'Concurrent attacker did not produce a bounded successful receipt'
            }
            $concurrent=Get-Content -LiteralPath $concurrentOutput -Raw|ConvertFrom-Json
            if($concurrent.schema -cne 'usk.publisher.unprivileged_access_probe.v1' -or
                $concurrent.status -cne 'access_denied_observed' -or
                $concurrent.stage -cne 'Concurrent' -or
                $concurrent.user_sid -cne $consumerSid -or $concurrent.administrator -or
                $concurrent.service_sid_present -or
                $concurrent.process_id -ne $concurrentAttacker.Id -or
                $concurrent.concurrent.staged_write.denied -lt 1 -or
                $concurrent.concurrent.destination_create.denied -lt 4 -or
                $concurrent.concurrent.destination_create.denied_during_release -lt 1 -or
                $concurrent.concurrent.cycles_during_release -lt 1 -or
                $concurrent.concurrent.visible_write.denied_after_completion -lt 3 -or
                $concurrent.concurrent.cycles_after_completion -lt 3) {
                throw 'Concurrent hostile-rights observation differs from the actual client'
            }
            $receipt['concurrent_hostile_rights']=$concurrent
            $concurrentAttacker=$null
        }
    } else {
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $nativePath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $nativePath)){throw 'Native service receipt absent'}
        $receipt.native=Read-NativeReceipt $nativePath
        if($requestClient) {
            $receipt['authenticated_client']=Complete-RequestClient $requestClient $true
            $requestClient=$null
        }
        $receipt['native_receipt_sha256']=(Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $receipt['consumer_sid']=if($ConsumerAccess){$consumerSid}else{''}
    if($RegisteredService -and -not $HostileRights -and -not $recover) {
        # The packaged client has received the terminal reply and closed its
        # authenticated pipe. The one-request service must now stop itself
        # before install-to-verify reconfiguration, without an SCM stop call.
        if(-not $terminalServiceProcess.WaitForExit(30000)) {
            throw 'Original registered publisher process retained after terminal client disconnect'
        }
        $terminalAtEnd=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
        if($terminalAtEnd.State -cne 'Stopped' -or $terminalAtEnd.ProcessId -ne 0 -or
            $terminalAtEnd.ExitCode -ne 0) {
            throw 'Registered publisher did not stop cleanly after terminal client disconnect'
        }
        $receipt['registered_terminal_shutdown']=[ordered]@{
            original_process_exited=$true;scm_state=$terminalAtEnd.State;
            scm_exit_code=$terminalAtEnd.ExitCode}
    } elseif((Get-Service $service).Status -ne 'Stopped') {Stop-Service $service}
    if($RegisteredService -and $HostileRights) {
        # Restore the registered command before using product recovery/verify
        # control. Only the separately built fault-test binary admits the gate.
        & sc.exe config $service binPath= $expectedRegisteredCommand|Out-Null
        if($LASTEXITCODE -ne 0 -or
            (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $expectedRegisteredCommand) {
            throw 'Registered hostile service command restoration failed'
        }
    }
    if($receipt.native.status -ne 'pass'){throw ('Native metadata operation failed: '+$receipt.native.error)}
    if($RegisteredService -and -not $recover -and
        ($receipt.native.install_operation_guard_held -ne $true -or
         $receipt.native.install_operation_guard_abandoned -ne $false)) {
        throw 'Authenticated install did not hold its installation operation guard'
    }
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
    if($RegisteredService -and $recover) {
        $stagedRoot=$drive+'publication\staging\candidate'
        foreach($row in $before.independent.rows) {
            $completedPath=$row.path
            if($row.path -ceq $stagedRoot -or
                $row.path.StartsWith($stagedRoot+'\',[StringComparison]::Ordinal)) {
                $completedPath=$drive+'publication\destination\visible'+$row.path.Substring($stagedRoot.Length)
            }
            $matching=@($receipt.independent.rows|Where-Object path -ceq $completedPath)
            if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or
                $matching[0].bytes -ne $row.bytes) {
                throw 'Registered recovery changed retained payload or durable intent'
            }
        }
        $receipt['source_free_recovery']=[ordered]@{action=$recoveryDecision;
            interrupted_independent=$before.independent;completed_independent=$receipt.independent;
            completed_row_count=@($receipt.independent.rows).Count}
    }
    if($NonAdminClient -and @($receipt.independent.rows|Where-Object {
        @($_.aces|Where-Object sid -eq $consumerSid).Count -ne 0
    }).Count -ne 0) {
        throw 'Non-admin request caller acquired published payload or private-state ACL rights'
    }
    if($RegisteredService) {
        # Keep the same SCM service identity and durable request while withholding
        # every original authoring/source input. This exercises the production
        # service grammar against the existing source-free recovery engine.
        if(-not $recover) {
            $removed=[Collections.Generic.List[string]]::new()
            foreach($path in $sourceInputs) {
                $exact=[IO.Path]::GetFullPath($path)
                $item=Get-Item -LiteralPath $exact -Force
                if(-not $exact.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or
                    $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                    throw 'Registered recovery source removal escaped owned input root'
                }
                Remove-Item -LiteralPath $exact -Force
                if(Test-Path -LiteralPath $exact){throw 'Registered recovery source input remains'}
                $removed.Add($exact)
            }
            $receipt['removed_source_inputs']=$removed.ToArray()
        } else {
            foreach($path in $sourceInputs) {
                if(Test-Path -LiteralPath $path){throw 'Original source returned before registered replay'}
            }
        }
        if($callerSid -eq 'S-1-5-18'){throw 'Registered client unexpectedly uses SYSTEM identity'}
        $beforeControl=(Get-CimInstance Win32_Service -Filter "Name='$service'").PathName
        $wrongCallerError=Join-Path $root ('wrong-caller-'+$id+'.txt')
        $wrongArgs=@('--recover',$service,$ServiceBinary,$VolumeRoot,'S-1-5-18')
        if($registeredMode){$wrongArgs+=$registeredMode}
        & $ServiceControlBinary @wrongArgs 2>$wrongCallerError|Out-Null
        if($LASTEXITCODE -eq 0 -or
            (Get-CimInstance Win32_Service -Filter "Name='$service'").PathName -cne $beforeControl) {
            throw 'Registered recovery accepted a different caller or changed service configuration'
        }
        $receipt['wrong_caller_recovery_refused']=$true
        $controlArgs=@('--recover',$service,$ServiceBinary,$VolumeRoot,$callerSid)
        if($registeredMode){$controlArgs+=$registeredMode}
        $configuredRecovery=& $ServiceControlBinary @controlArgs
        if($LASTEXITCODE -ne 0 -or ($configuredRecovery|ConvertFrom-Json).status -ne 'recovery_configured') {
            throw 'Product service control did not configure source-free recovery'
        }
        Start-RegisteredPublisher
        $submittedRecovery=$recoveryRequest
        $requestClient=Start-RequestClient $submittedRecovery
        if(-not $requestClient.process.WaitForExit(120000)){throw 'Registered recovery client timed out'}
        $requestClient.process.WaitForExit()
        $recoveryClientIdentity=Assert-RequestClientImage $requestClient
        if($requestClient.process.ExitCode -ne 0 -or
            (Get-Item -LiteralPath $requestClient.response).Length -gt 4MB) {
            throw ('Registered recovery client failed: '+[IO.File]::ReadAllText($requestClient.error))
        }
        $recovered=Get-Content -LiteralPath $requestClient.response -Raw|ConvertFrom-Json
        if($recovered.status -ne 'pass' -or
            $recovered.recovery_observation.decision -ne 'already_visible_bound' -or
            $recovered.install_operation_guard_held -ne $true -or
            $recovered.install_operation_guard_abandoned -ne $false -or
            $recovered.recovery_installed_response.status -ne 'ok' -or
            $recovered.recovery_installed_response.payload.transaction_id -ne $applyRequest.transaction_id -or
            (Test-Path -LiteralPath $nativePath)) {
            throw 'Registered source-free recovery did not preserve the bound installed result'
        }
        $receipt['registered_source_free_reentry']=[ordered]@{
            status=$recovered.status;decision=$recovered.recovery_observation.decision;
            request_schema=$submittedRecovery.schema;
            client_exit_code=$requestClient.process.ExitCode;
            client_mode=$requestClient.client_mode;
            client_binary_sha256=$requestClient.binary_sha256;
            client_observation=$recoveryClientIdentity;
            response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $repeat=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($repeat.independent.identity -ne 'S-1-5-18' -or -not $repeat.observer_task_removed -or
            ($receipt.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($repeat.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Registered source-free reentry changed independently observed installed rows'
        }
        $receipt.registered_source_free_reentry['unchanged_independent_rows']=@($repeat.independent.rows).Count
        $staleRecovery=[ordered]@{
            schema='usk.publisher_recovery_request.v1'
            request_id='recover.stale.'+$id
            install_id=$recoveryRequest.install_id
            transaction_id=$recoveryRequest.transaction_id+'.changed'
        }
        Start-RegisteredPublisher
        $requestClient=Start-RequestClient $staleRecovery
        if(-not $requestClient.process.WaitForExit(120000)) {
            throw 'Stale recovery client timed out'
        }
        $requestClient.process.WaitForExit()
        $staleClientIdentity=Assert-RequestClientImage $requestClient
        $stale=Get-Content -LiteralPath $requestClient.response -Raw|ConvertFrom-Json
        if($requestClient.process.ExitCode -eq 0 -or $stale.status -ne 'failed' -or
            $stale.error -cne 'reviewed install reentry differs from durable plan and source') {
            throw 'Changed minimal recovery request was admitted'
        }
        $receipt['stale_minimal_recovery_refused']=[ordered]@{
            status=$stale.status;client_mode=$requestClient.client_mode;
            client_binary_sha256=$requestClient.binary_sha256;
            client_observation=$staleClientIdentity;
            response_sha256=(Get-FileHash -LiteralPath $requestClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        $requestClient=$null
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
        $afterStale=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($afterStale.independent.identity -ne 'S-1-5-18' -or -not $afterStale.observer_task_removed -or
            ($repeat.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($afterStale.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Changed minimal recovery request altered installed state'
        }
    }
    if($RegisteredService -and -not $InterruptAfterStage) {
        # The ordinary packaged client asks the restricted service to verify
        # the completed installation. The caller receives no private-state ACL.
        $verifyRequest=[ordered]@{schema='usk.publisher_installed_verify_request.v1';
            request_id='verify.'+$id;install_id=$applyRequest.plan_request.install_id;
            transaction_id=$applyRequest.transaction_id;report_id='verify.'+$id;
            verified_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
        $verifyArgs=@('--verify',$service,$ServiceBinary,$VolumeRoot,$callerSid)
        if($registeredMode){$verifyArgs+=$registeredMode}
        $configuredVerify=& $ServiceControlBinary @verifyArgs
        if($LASTEXITCODE -ne 0 -or ($configuredVerify|ConvertFrom-Json).status -ne 'verify_configured') {
            throw 'Product service control did not configure read-only verification'
        }
        Start-RegisteredPublisher
        $requestClient=Start-RequestClient $verifyRequest
        $verifyClient=$requestClient
        if(-not $verifyClient.process.WaitForExit(120000)){throw 'Registered verification client timed out'}
        $verifyClient.process.WaitForExit()
        $requestClient=$null
        if($verifyClient.process.ExitCode -ne 0 -or
            (Get-Item -LiteralPath $verifyClient.response).Length -gt 4MB) {
            throw ('Registered verification client failed: '+[IO.File]::ReadAllText($verifyClient.error))
        }
        $verified=Get-Content -LiteralPath $verifyClient.response -Raw|ConvertFrom-Json
        if($verified.status -ne 'pass' -or $verified.transaction_id -cne $applyRequest.transaction_id -or
            $verified.verify_response.status -ne 'ok' -or
            $verified.verify_response.payload.status -ne 'pass' -or
            $verified.verify_response.payload.install_id -cne $verifyRequest.install_id -or
            $verified.verify_response.payload.report_id -cne $verifyRequest.report_id -or
            (Test-Path -LiteralPath $nativePath)) {
            throw 'Authenticated read-only verification differs from completed installation'
        }
        $receipt['registered_installed_verify']=[ordered]@{status=$verified.status;
            report_digest=$verified.verify_response.payload.report_digest;
            client_exit_code=$verifyClient.process.ExitCode;
            response_sha256=(Get-FileHash -LiteralPath $verifyClient.response -Algorithm SHA256).Hash.ToLowerInvariant()}
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
        $staleVerify=[ordered]@{}
        foreach($key in $verifyRequest.Keys){$staleVerify[$key]=$verifyRequest[$key]}
        $staleVerify.transaction_id='install.'+[guid]::NewGuid().ToString('N')
        Start-RegisteredPublisher
        $requestClient=Start-RequestClient $staleVerify
        $staleClient=$requestClient
        if(-not $staleClient.process.WaitForExit(120000)){throw 'Stale verification client timed out'}
        $staleClient.process.WaitForExit()
        $requestClient=$null
        $staleResponse=Get-Content -LiteralPath $staleClient.response -Raw|ConvertFrom-Json
        if($staleClient.process.ExitCode -eq 0 -or $staleResponse.status -ne 'failed' -or
            $staleResponse.error -notmatch 'differs from completed install') {
            throw 'Stale authenticated verification request was not refused'
        }
        $receipt.registered_installed_verify['stale_transaction_refused']=$true
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
        $verifyRows=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if($verifyRows.independent.identity -ne 'S-1-5-18' -or -not $verifyRows.observer_task_removed -or
            ($receipt.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($verifyRows.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Read-only verification changed independently observed installed rows'
        }
        $receipt.registered_installed_verify['unchanged_independent_rows']=@($verifyRows.independent.rows).Count
        if(-not $HostileRights) {
            $damageEntries=@($plan.planned_entries|Where-Object {
                $_.entry_type -ceq 'file' -and $_.relative_path -ceq $(if($ConsumerAccess){'bin/addon.bin'}else{'bin/core.bin'})
            })
            if($damageEntries.Count -ne 1){throw 'Selected owned damage file is absent from reviewed plan'}
            Assert-OwnedVolume
            $damaged=Invoke-IndependentOwnedPayloadDamage -VhdPath $vhd -VolumeRoot $VolumeRoot `
                -DriveRoot $drive -PayloadRelativePath $damageEntries[0].relative_path `
                -ExpectedSha256 $damageEntries[0].sha256
            $damageVerify=[ordered]@{}
            foreach($key in $verifyRequest.Keys){$damageVerify[$key]=$verifyRequest[$key]}
            $damageVerify.request_id='verify.damaged.'+$id
            $damageVerify.report_id='verify.damaged.'+$id
            Start-RegisteredPublisher
            $requestClient=Start-RequestClient $damageVerify
            $damageClient=$requestClient
            if(-not $damageClient.process.WaitForExit(120000)){throw 'Damaged verification client timed out'}
            $damageClient.process.WaitForExit()
            $requestClient=$null
            if((Get-Item -LiteralPath $damageClient.response).Length -gt 4MB){
                throw 'Damaged verification response exceeds client budget'
            }
            $damageResponse=Get-Content -LiteralPath $damageClient.response -Raw|ConvertFrom-Json
            $damagedFiles=@($damageResponse.verify_response.payload.files|Where-Object {
                $_.relative_path -ceq $damageEntries[0].relative_path
            })
            if($damageClient.process.ExitCode -ne 3 -or $damageResponse.status -cne 'failed' -or
                $damageResponse.transaction_id -cne $applyRequest.transaction_id -or
                $damageResponse.verify_response.status -cne 'ok' -or
                $damageResponse.verify_response.payload.status -cne 'fail' -or
                $damageResponse.verify_response.payload.install_id -cne $verifyRequest.install_id -or
                $damageResponse.verify_response.payload.report_id -cne $damageVerify.report_id -or
                $damageResponse.verify_response.payload.summary.modified_files -ne 1 -or
                $damageResponse.verify_response.payload.summary.missing_files -ne 0 -or
                $damageResponse.verify_response.payload.summary.unknown_paths -ne 0 -or
                $damagedFiles.Count -ne 1 -or $damagedFiles[0].status -cne 'modified' -or
                $damagedFiles[0].expected_sha256 -cne $damaged.before_sha256 -or
                $damagedFiles[0].actual_sha256 -cne $damaged.after_sha256) {
                throw ('Authenticated damaged-file verification did not report exact drift: '+
                    [IO.File]::ReadAllText($damageClient.error))
            }
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
            $damageRows=Invoke-IndependentMetadataReadback -DriveRoot $drive `
                -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
            $beforeFile=@($verifyRows.independent.rows|Where-Object path -ceq $damaged.path)
            $afterFile=@($damageRows.independent.rows|Where-Object path -ceq $damaged.path)
            $otherBefore=@($verifyRows.independent.rows|Where-Object path -cne $damaged.path)
            $otherAfter=@($damageRows.independent.rows|Where-Object path -cne $damaged.path)
            if($damageRows.independent.identity -cne 'S-1-5-18' -or
                -not $damageRows.observer_task_removed -or $beforeFile.Count -ne 1 -or
                $afterFile.Count -ne 1 -or $beforeFile[0].sha256 -cne $damaged.before_sha256 -or
                $afterFile[0].sha256 -cne $damaged.after_sha256 -or
                $afterFile[0].bytes -ne $beforeFile[0].bytes -or
                ($beforeFile[0].aces|ConvertTo-Json -Depth 8 -Compress) -cne
                    ($afterFile[0].aces|ConvertTo-Json -Depth 8 -Compress) -or
                $beforeFile[0].owner -cne $afterFile[0].owner -or
                $beforeFile[0].protected -ne $afterFile[0].protected -or
                ($otherBefore|ConvertTo-Json -Depth 32 -Compress) -cne
                    ($otherAfter|ConvertTo-Json -Depth 32 -Compress)) {
                throw 'Damaged verification changed protected metadata or another installed object'
            }
            $receipt.registered_installed_verify['damaged_owned_file']=[ordered]@{
                path=$damageEntries[0].relative_path;before_sha256=$damaged.before_sha256;
                after_sha256=$damaged.after_sha256;report_digest=$damageResponse.verify_response.payload.report_digest;
                status=$damageResponse.verify_response.payload.status;
                unchanged_other_rows=$otherAfter.Count;client_exit_code=$damageClient.process.ExitCode}
        }
    }
    if($HostileRights) {
        $attackOutput=Join-Path (Split-Path -Parent $vhd) 'unprivileged-attack.json'
        $attackIdentity=if($RegisteredService -and $NonAdminClient){
            @{ExistingCredential=$consumerCredential;ExistingSid=$consumerSid}
        }else{@{}}
        & (Join-Path $PSScriptRoot 'windows_publisher_unprivileged_runner.ps1') -VhdPath $vhd -VolumeRoot $VolumeRoot -ServiceSid $sid -OutputPath $attackOutput -Stage Postpublish -PayloadRelativePath $attackRelative @attackIdentity
        $attack=Get-Content -LiteralPath $attackOutput -Raw|ConvertFrom-Json
        $receipt['postpublish_hostile_rights']=$attack
        if($attack.status -ne 'unprivileged_access_denied_observed' -or $attack.payload_relative_path -cne $attackRelative){
            throw 'Selected postpublish attacker result differs'
        }
        if($RegisteredService -and ($attack.account_sid -cne $consumerSid -or
            $attack.account_origin -cne 'existing_owned_client')) {
            throw 'Registered postpublish attacker did not use the submitting client identity'
        }
        $afterAttack=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        $receipt['postpublish_after_attack']=$afterAttack.independent
        if($afterAttack.independent.identity -ne 'S-1-5-18' -or -not $afterAttack.observer_task_removed -or
            ($receipt.independent.rows|ConvertTo-Json -Depth 32 -Compress) -cne
            ($afterAttack.independent.rows|ConvertTo-Json -Depth 32 -Compress)) {
            throw 'Selected postpublish hostile attempts changed published state'
        }
    }
    if($recover -and -not $RegisteredService) {
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
            $repeatPath=Join-Path $root ('vm-recovery-reviewed-repeat-'+$id+'.json')
            $repeatCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$repeatPath+'" '+$VolumeRoot+
                ' --recover-reviewed --campaign-vm-id '+$vmId+$clientArguments
        }
        & sc.exe config $service binPath= $repeatCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned service repeat configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        if($ClientBinary){$requestClient=Start-RequestClient}
        $deadline=[DateTime]::UtcNow.AddSeconds(90)
        while(-not (Test-Path -LiteralPath $repeatPath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $repeatPath)){throw 'Repeated recovery receipt absent'}
        $repeat=Read-NativeReceipt $repeatPath
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
        if($ReviewedSource) {
            # Reissue the original source-derived service command after both
            # input files were removed. Its durable request must select the
            # same completed generation without reopening those paths.
            $reentryPath=Join-Path $root ('vm-selected-reconnect-'+$id+'.json')
            $reentryCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$reentryPath+'" '+$VolumeRoot+
                $selectedClientArguments+$clientArguments
            & sc.exe config $service binPath= $reentryCommand|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Reviewed source reentry configuration failed'}
            try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
            $nativePath=$reentryPath
            $requestClient=Start-RequestClient
            $receipt['reviewed_source_reentry_client']=Complete-RequestClient $requestClient $true
            $requestClient=$null
            $reentry=Read-NativeReceipt $reentryPath
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service}
            if($reentry.status -ne 'pass' -or
                $reentry.recovery_observation.decision -ne 'already_visible_bound' -or
                $reentry.recovery_installed_response.payload.transaction_id -ne $applyRequest.transaction_id) {
                throw 'Source-derived command did not reenter completed durable request'
            }
            $reentryReadback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
            if($after.independent.rows.Count -ne $reentryReadback.independent.rows.Count -or
                -not $reentryReadback.observer_task_removed) {
                throw 'Source-derived reentry changed completed record count or observer state'
            }
            foreach($row in $after.independent.rows) {
                $matching=@($reentryReadback.independent.rows|Where-Object path -ceq $row.path)
                if($matching.Count -ne 1 -or $matching[0].sha256 -ne $row.sha256 -or
                    $matching[0].bytes -ne $row.bytes -or
                    ($matching[0].aces|ConvertTo-Json -Depth 10 -Compress) -cne
                    ($row.aces|ConvertTo-Json -Depth 10 -Compress)) {
                    throw 'Source-derived reentry changed completed protected or public state'
                }
            }
            $receipt['reviewed_source_reentry']=[ordered]@{native=$reentry;unchanged_rows=$reentryReadback.independent.rows.Count;
                observer_task_removed=$reentryReadback.observer_task_removed}
        }
        $receipt['source_free_recovery']=[ordered]@{action=$recoveryDecision;repeat=$repeat;
            independent_repeat=$after.independent;repeat_observer_task_removed=$after.observer_task_removed;
            unchanged_row_count=$after.independent.rows.Count}
    }
    if($recover -and $ClientBinary -and -not $RegisteredService) {
        # A genuine authenticated peer cannot change the durable request merely
        # by reusing this endpoint after successful recovery.
        $tampered=$applyRequest|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json
        $tampered.transaction_id='install.'+[guid]::NewGuid().ToString('N')
        $stalePath=Join-Path $root ('vm-recovery-reviewed-stale-'+$id+'.json')
        $staleCommand='"'+$ServiceBinary+'" --service '+$service+' "'+$stalePath+'" '+$VolumeRoot+
            ' --recover-reviewed --campaign-vm-id '+$vmId+$clientArguments
        & sc.exe config $service binPath= $staleCommand|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Owned stale-client service configuration failed'}
        try{Start-Service $service}catch{if((Get-Service $service).Status -ne 'Stopped'){throw}}
        $requestClient=Start-RequestClient $tampered
        $nativePath=$stalePath
        $receipt['stale_authenticated_client']=Complete-RequestClient $requestClient $false $true
        $requestClient=$null
        $stale=Read-NativeReceipt $stalePath
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
        # The registered path has already damaged only the non-executable
        # addon and independently recorded that new state. Keep the neutral
        # executable intact for the non-admin execution check.
        $accessBaseline=if($RegisteredService){$damageRows.independent.rows}elseif($recover){$after.independent.rows}else{$receipt.independent.rows}
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
            $row=@($accessBaseline|Where-Object path -ceq $file.path)
            if($row.Count -ne 1 -or $row[0].sha256 -cne $file.sha256){throw 'Consumer-read bytes differ from independent SYSTEM readback'}
        }
        $receipt['consumer_access_observation']=$access
        $afterAccess=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot (Split-Path -Parent $vhd) -RunId ([guid]::NewGuid().ToString('N'))
        if(($accessBaseline|ConvertTo-Json -Depth 32 -Compress) -cne ($afterAccess.independent.rows|ConvertTo-Json -Depth 32 -Compress)){throw 'Consumer access attempts changed installed bytes/ACLs'}
        $receipt['consumer_attempts_unchanged_rows']=$afterAccess.independent.rows
        $receipt['consumer_attempts_observer_removed']=$afterAccess.observer_task_removed
    }
    if($ReviewedSource) {
        if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
        if((Get-Service $service).Status -ne 'Stopped') { throw 'Reviewed service remains active during root ACL observation' }
        $receipt['root_acl_after_service']=Get-OwnedVolumeRootSddl 'service-end'
        if($receipt.root_acl_at_service_start -cne $receipt.root_acl_after_service) {
            throw 'Reviewed-source service changed the preprotected volume root ACL'
        }
    }
    $receipt.status='protected_metadata_observed'
    }
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
    if($concurrentAttacker) {
        try {Stop-OwnedPublisherProcessTree $concurrentAttacker|Out-Null}
        catch {$clientCleanupConfirmed=$false;$failure='Concurrent attacker cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed'}
    }
    $receipt['client_cleanup_confirmed']=$clientCleanupConfirmed
    if($consumerCreated -and $clientCleanupConfirmed) {
        try {Remove-LocalUser -Name $consumerName -ErrorAction Stop;$receipt['consumer_account_removed']=$true}
        catch {$failure='Owned consumer account cleanup failed';$receipt.failure=$failure;$receipt.status='failed'}
    }
    if($consumerCreated -and -not $clientCleanupConfirmed){$receipt['consumer_account_retained']=$consumerName}
    $consumerCredential=$null
    if($registrationAttempted -and -not $created) {
        try {
            $pendingService=Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction Stop
            if($pendingService) {
                if($pendingService.PathName -cne $expectedRegisteredCommand) {
                    throw 'Failed registration left a service with an unexpected command; retain for inspection'
                }
                $created=$true
            }
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($created) {
        try {
            if((Get-Service $service).Status -ne 'Stopped'){Stop-Service $service -ErrorAction Stop}
            & sc.exe delete $service|Out-Null
            if($LASTEXITCODE -ne 0){throw 'Owned service deletion failed'}
            if(Get-Service $service -ErrorAction SilentlyContinue){throw 'Owned service remains after deletion'}
            $receipt.service_removed=$true
        } catch { $failure=$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    if($receipt.status -in @('protected_metadata_observed','preprotected_boundary_refusal_observed') -and $receipt.service_removed) {
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
    if(Test-Path -LiteralPath $observerRoot){
        try { Remove-Item -LiteralPath $observerRoot -ErrorAction Stop }
        catch { $failure='Owned root ACL observer directory cleanup failed: '+$_.Exception.Message;$receipt.failure=$failure;$receipt.status='failed' }
    }
    $receipt|ConvertTo-Json -Depth 32|Set-Content -LiteralPath $out -Encoding UTF8
    # The existing outer harness dismounts/deletes only its identified VHD.
    # This entire hosted VM is disposable; no workstation resources are used.
}
if($failure){throw $failure}
Write-Output "Protected selected metadata observed: $out"
