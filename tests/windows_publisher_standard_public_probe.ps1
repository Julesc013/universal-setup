# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$ServiceControlBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$PythonBinary
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_process.ps1')
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'Standard public qualification requires the owned hosted runner'
}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
    throw 'Standard fixture launcher requires the owned SYSTEM task context'
}
$lab=[IO.Path]::GetFullPath((Split-Path -Parent $VhdPath))
$runner=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
if(-not $lab.StartsWith($runner,[StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$') {throw 'Standard public lab differs'}
$image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
$disk=$image|Get-Disk -ErrorAction Stop
$parts=@($disk|Get-Partition|Where-Object DriveLetter)
if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $parts.Count -ne 1) {throw 'Standard target is not the owned disposable volume'}
$volume=$parts[0]|Get-Volume
if($volume.UniqueId -cne $VolumeRoot -or $volume.FileSystem -cne 'NTFS') {throw 'Standard target identity differs'}
$drive=[string]$volume.DriveLetter+':\'
$id=[guid]::NewGuid().ToString('N');$service='USK_PUB_'+$id;$accountName='USKCLI_'+$id.Substring(0,13)
$accountSid='';$accountCreated=$false;$clientsClosed=$true;$registered=$false;$secret=$null
$observersClosed=$true;$clientTokenLease=$null;$clientCaptureFile=Join-Path $lab 'public-client-token.json';$clientCaptureSha256=''
$ownerCreation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$publisherBuild=Split-Path -Parent (Split-Path -Parent ([IO.Path]::GetFullPath($ServiceBinary)))
$publisherProjectPath=Join-Path $publisherBuild 'usk_publisher_windows_static.vcxproj'
$publisherProject=[xml][IO.File]::ReadAllText($publisherProjectPath)
$publisherSdk=@($publisherProject.Project.PropertyGroup.WindowsTargetPlatformVersion|Where-Object {$_}|Select-Object -Unique)
if($publisherSdk.Count -ne 1 -or $publisherSdk[0] -cnotmatch '^10\.0\.[1-9][0-9]*\.0$'){throw 'Standard native publisher SDK is unavailable'}
$utf8=[Text.UTF8Encoding]::new($false)
$installedBinary=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$service+'.exe')
$receipt=[ordered]@{schema='usk.publisher_standard_public_probe.v1';status='not_run';service=$service;
    volume_root=$VolumeRoot;account_name=$accountName;client_cleanup_confirmed=$false;account_cleanup_confirmed=$false;
    profile_qualified=$false;launcher_identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    machine_sha256=(Get-FileHash -LiteralPath $MachineBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    service_sha256=(Get-FileHash -LiteralPath $ServiceBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    execution_build_context=@{windows_sdk=[string]$publisherSdk[0];
        publisher_project_sha256=(Get-FileHash -LiteralPath $publisherProjectPath -Algorithm SHA256).Hash.ToLowerInvariant()};
    client_captures=[Collections.Generic.List[object]]::new();readbacks=[Collections.Generic.List[object]]::new();
    native_observations=[Collections.Generic.List[object]]::new()}
function Write-Json([string]$Path,$Value) {[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 64 -Compress)+"`n",$utf8)}
function Read-ServicePolicy {
    $raw=[UskPublisherServiceSecurityReadback]::Read($service)
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($raw)
    if($descriptor.Owner.Value -cnotin @('S-1-5-18','S-1-5-32-544') -or $null -eq $descriptor.DiscretionaryAcl) {throw 'SCM policy owner/DACL differs'}
    $rows=@(foreach($ace in $descriptor.DiscretionaryAcl) {
        if($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or [int]$ace.AceFlags -ne 0 -or
            $ace.AceQualifier -notin @('AccessAllowed','AccessDenied')) {throw 'SCM policy ACE form differs'}
        $mask=[uint64]([long]$ace.AccessMask -band 0xffffffffL)
        $allowed=0x2018dL;if($ace.SecurityIdentifier.Value -ceq $accountSid){$allowed=$allowed -bor 0x10L}
        if($ace.AceQualifier -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -cnotin @('S-1-5-18','S-1-5-32-544') -and
            ($mask -band (-bnot $allowed)) -ne 0) {throw 'SCM policy grants outside mutation'}
        [ordered]@{sid=$ace.SecurityIdentifier.Value;mask=$mask;type=$ace.AceQualifier.ToString();flags=[int]$ace.AceFlags}
    })
    if(@($rows|Where-Object {$_.sid -ceq $accountSid -and $_.mask -eq 0x20015 -and $_.type -ceq 'AccessAllowed'}).Count -ne 1) {throw 'Configured standard start/query grant differs'}
    return [ordered]@{owner=$descriptor.Owner.Value;raw_security_diagnostic=$raw;aces=$rows}
}
function Assert-LeaseTransition($Before,$After,[bool]$Readonly=$false) {
    $leaseRequest=@{mode=$(if($Readonly){'readonly'}else{'append'});before=$Before.independent.rows;
        after=$After.independent.rows;drive=$drive;installed=$installed;volume_root_id=$After.independent.volume_boundary.root.file_id}
    $leaseRequest|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_installation_lease_evidence.py') --input -|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Standard installation lease/native row transition differs'}
}
function Read-InstalledSnapshot {
    $script:observersClosed=$false
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab -RunId ([guid]::NewGuid().ToString('N')) `
        -CallerProcessId $PID -CallerCreationFileTime $ownerCreation -CallerSid $accountSid -ServiceSid $sid `
        -ClientCaptureFile $clientCaptureFile -ClientCaptureSha256 $clientCaptureSha256 `
        -ExpectedVolumeRoot $VolumeRoot -ExpectedDiskNumber $disk.Number
    if(-not $readback.observer_task_removed -or $readback.independent.identity -cne 'S-1-5-18' -or
        $readback.independent.observer_token_handles_closed -ne $true){throw 'Standard independent reader cleanup differs'}
    $script:observersClosed=$true
    Assert-IndependentProtectedRows -Rows $readback.independent.rows -ServiceSid $sid -ConsumerSid $accountSid `
        -VisibleRoot ($drive+'publication\destination\visible')
    $prepared=@($readback.independent.rows|Where-Object path -ceq ($drive+'publication\journal\lab-prepared-evidence.json'))
    $visible=@($readback.independent.rows|Where-Object path -ceq ($drive+'publication\journal\lab-visible-evidence.json'))
    if($prepared.Count -ne 1 -or $visible.Count -ne 1){throw 'Standard native phase records are incomplete'}
    $input=Join-Path $lab ('standard-execution-'+[guid]::NewGuid().ToString('N')+'.json')
    Write-Json $input @{prepared_json=[string]$prepared[0].content_json;visible_json=[string]$visible[0].content_json;
        service_name=$service;service_sid=$sid;windows_build=[int][Environment]::OSVersion.Version.Build;sdk_version=[string]$publisherSdk[0]}
    $decoded=& $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_execution_evidence.py') --input $input
    if($LASTEXITCODE -ne 0){throw 'Standard native execution reconciliation failed'}
    $report=($decoded -join "`n")|ConvertFrom-Json
    if($report.schema -cne 'usk.publisher_execution_reconciliation.v4' -or $report.profile_qualified -ne $false -or
        $report.worker_security_phase_count -le 0 -or $report.creation_observation.worker_security_checked -ne $true) {
        throw 'Standard native creation/worker evidence is incomplete'
    }
    $readback|Add-Member -NotePropertyName execution_reconciliation -NotePropertyValue $report
    return $readback
}
function Invoke-StandardRequest([string]$Command,$Payload,[int]$ExpectedExit=0) {
    if((Get-Service $service).Status -ne 'Stopped') {throw 'Standard request did not begin at a stopped service'}
    $requestId='public.'+[guid]::NewGuid().ToString('N')
    if($Command -cin @('publisher.inspect','publisher.observe')){$Payload.request_id=$requestId}
    $request=Join-Path $lab ($requestId+'.json');$stdout=$request+'.stdout';$stderr=$request+'.stderr'
    $nativeOutput=Join-Path (Join-Path $lab 'native-observations') ($requestId+'.json')
    Write-Json $request @{schema='usk.oneshot_request.v1';request_id=$requestId;command=$Command;payload=$Payload;dry_run=($Command -ceq 'publisher.inspect')}
    if($clientTokenLease) {
        if(-not $observersClosed -or (Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $clientCaptureSha256) {
            throw 'Prior standard observer/capture is not closed and stable'
        }
        $clientTokenLease.Dispose();$script:clientTokenLease=$null
        [IO.File]::Move($clientCaptureFile,(Join-Path $lab ('retired-client-token-'+[guid]::NewGuid().ToString('N')+'.json')))
    }
    $launch=$null;$process=$null;$script:clientsClosed=$false
    try {
        $launch=[UskPublisherPausedClient]::CreateOwnedStandard($MachineBinary,('--machine --publisher '+$service+
            ' --request-file "'+$request+'" --publisher-observation-file "'+$nativeOutput+'"'),$stdout,$stderr,$accountName,$secret,$accountSid)
        $process=Get-Process -Id $launch.ProcessId;$null=$process.Handle
        $script:clientTokenLease=[UskPublisherEffectiveRights]::new($launch.ProcessId,$launch.CreationFileTime,$accountSid,$sid)
        $capture=$clientTokenLease.CaptureBinding($PID,[long]$ownerCreation,$MachineBinary)
        $capture['client_sha256']=$receipt.machine_sha256;$capture['request_id']=$requestId;$capture['command']=$Command
        if(Test-Path -LiteralPath $clientCaptureFile){throw 'Standard held-client capture already exists'}
        Write-Json $clientCaptureFile $capture
        $script:clientCaptureSha256=(Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $receipt.client_captures.Add([ordered]@{request_id=$requestId;command=$Command;process_id=$launch.ProcessId;
            creation_file_time=$launch.CreationFileTime.ToString();captured_before_primary_thread_resume=$true;
            primary_token=$launch.OwnedStandardPrimaryFacts;launcher_token=$launch.OwnedStandardLauncherFacts;image_sha256=$receipt.machine_sha256;
            capture_sha256=$clientCaptureSha256;initiating_token_id=$capture.initiating_token_id;filtered_token_id=$capture.filtered_token_id})
        $launch.Resume()
        if(-not $process.WaitForExit(120000)) {throw 'Standard public client exceeded its deadline'}
        $process.WaitForExit();$exit=$process.ExitCode
        $diagnostic=[IO.File]::ReadAllText($stderr)
        if((Get-Item -LiteralPath $stdout).Length -gt 4MB -or (Get-Item -LiteralPath $stderr).Length -gt 64KB -or
            ($ExpectedExit -eq 0 -and $diagnostic.Length) -or
            ($ExpectedExit -ne 0 -and $diagnostic -cnotmatch '^usk_machine: request refused\r?\n?$')) {throw 'Standard client output differs'}
        $responseText=[IO.File]::ReadAllText($stdout)
        $receipt['last_response_diagnostic']=[ordered]@{command=$Command;request_id=$requestId;exit_code=$exit;
            stdout_sha256=(Get-FileHash -LiteralPath $stdout -Algorithm SHA256).Hash.ToLowerInvariant();
            stdout_prefix=$responseText.Substring(0,[Math]::Min(8192,$responseText.Length))}
        $result=$responseText|ConvertFrom-Json
        $payloadMatches=if($Command -ceq 'publisher.observe') {
            $result.result.schema -ceq 'usk.publisher_capability.v3' -and
                $result.result.request_id -ceq $requestId -and
                $result.result.availability -eq $true -and $result.result.qualification -ceq 'qualified_for_scope' -and
                $result.result.support -ceq 'supported_for_scope' -and $result.result.execution_lease_held -eq $false
        } else {$result.result.status -ceq 'ok'}
        $responseMatches=$exit -eq $ExpectedExit -and $result.schema -ceq 'usk.oneshot_response.v1' -and
            $result.request_id -ceq $requestId -and
            ($ExpectedExit -ne 0 -or ($result.status -ceq 'ok' -and $payloadMatches))
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 50}
        if((Get-Service $service).Status -ne 'Stopped'){throw 'Standard public worker did not stop'}
        if(-not $responseMatches) {
            # Diagnose the measured failure using the same held client tokens.
            # Partial rows are retained evidence only, never a successful install.
            $script:observersClosed=$false
            $diagnostic=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab -RunId ([guid]::NewGuid().ToString('N')) `
                -CallerProcessId $PID -CallerCreationFileTime $ownerCreation -CallerSid $accountSid -ServiceSid $sid `
                -ClientCaptureFile $clientCaptureFile -ClientCaptureSha256 $clientCaptureSha256 `
                -ExpectedVolumeRoot $VolumeRoot -ExpectedDiskNumber $disk.Number
            $receipt['failed_request_readback']=$diagnostic
            if(-not $diagnostic.observer_task_removed -or $diagnostic.independent.observer_token_handles_closed -ne $true){
                throw 'Failed-request diagnostic observer closure is unconfirmed'
            }
            $script:observersClosed=$true
            throw ('Standard public response binding differs: command='+$Command+' exit='+$exit+' status='+$result.status)
        }
        if((Read-ServicePolicy|ConvertTo-Json -Depth 16 -Compress) -cne ($receipt.service_policy|ConvertTo-Json -Depth 16 -Compress)) {throw 'Service access policy changed across standard dispatch'}
        if($ExpectedExit -eq 0) {
            if(-not (Test-Path -LiteralPath $nativeOutput) -or (Get-Item -LiteralPath $nativeOutput).Length -gt 4MB) {
                throw 'Standard native response capture is missing or exceeds its bound'
            }
            $nativeText=[IO.File]::ReadAllText($nativeOutput)
            $native=$nativeText|ConvertFrom-Json
            $nativeSchema=if($Command -ceq 'publisher.observe'){'usk.publisher_service_capability_observation.v1'}else{'usk.publisher_lab_service_observation.v1'}
            $nativeStatus=if($Command -ceq 'publisher.observe'){'observed'}else{'pass'}
            if($native.schema -cne $nativeSchema -or $native.status -cne $nativeStatus -or
                $null -eq $native.registered_admission){throw 'Standard native admission capture is incomplete'}
            $receipt.native_observations.Add([ordered]@{command=$Command;request_id=$requestId;
                native_json=$nativeText;sha256=(Get-FileHash -LiteralPath $nativeOutput -Algorithm SHA256).Hash.ToLowerInvariant()})
        }
        return $result
    } finally {
        try {
            if($process -and -not $process.HasExited) {
                if($launch -and -not $launch.IsResumed){$launch.Dispose()}
                else {Stop-OwnedPublisherProcessTree $process|Out-Null}
            }
        } finally {
            if($process){$process.Dispose()}
            if($launch){$launch.Dispose();$script:clientsClosed=$true}
        }
    }
}
try {
    Initialize-PublisherMetadataNativeTypes
    if(Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue){throw 'Owned standard account name exists'}
    $secret=ConvertTo-SecureString ('Aa1!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $account=New-LocalUser -Name $accountName -Password $secret -PasswordNeverExpires -ErrorAction Stop
    $accountCreated=$true;$accountSid=$account.SID.Value;$receipt['account_sid']=$accountSid
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $account -ErrorAction Stop
    $labAcl=Get-Acl -LiteralPath $lab
    $labAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $lab -AclObject $labAcl
    $nativeDirectory=Join-Path $lab 'native-observations'
    New-Item -ItemType Directory -Path $nativeDirectory|Out-Null
    $nativeAcl=Get-Acl -LiteralPath $nativeDirectory
    $nativeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $nativeDirectory -AclObject $nativeAcl
    $machineAcl=Get-Acl -LiteralPath $MachineBinary
    $machineAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account.SID,'ReadAndExecute','Allow'))
    Set-Acl -LiteralPath $MachineBinary -AclObject $machineAcl
    $fixture=Join-Path $lab 'standard-authored-inputs';New-Item -ItemType Directory -Path $fixture|Out-Null
    $generated=& $PythonBinary -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') --output $fixture `
        --target ($drive+'publication\destination\visible') --request-id ('standard.'+$id)
    if($LASTEXITCODE -ne 0){throw 'Standard authored fixture failed'}
    $inputs=($generated -join "`n")|ConvertFrom-Json
    $context=Join-Path $lab 'context.json'
    Write-Json $context @{schema='usk.oneshot_context.v1';state_root=$drive+'setup-state';authorized_acceptance_root=$drive;target_policy_activation='operator_acceptance_candidate'}
    $output=& $MachineBinary --machine --request-file $inputs.request_file --context-file $context
    if($LASTEXITCODE -ne 0){throw 'Standard fixture planning failed'}
    $planned=($output -join "`n")|ConvertFrom-Json
    if($planned.result.payload.commit_authority_available -ne $false){throw 'Unqualified plan claimed availability'}
    $planResponse=Join-Path $lab 'plan-response.json';[IO.File]::WriteAllText($planResponse,($output -join "`n")+"`n",$utf8)
    $bound=& $PythonBinary -B (Join-Path $PSScriptRoot '..\tools\usk_bundle_apply_binding.py') --request-file $inputs.request_file `
        --response-file $planResponse --acceptance-root $drive --state-root ($drive+'setup-state') `
        --transaction-id ('install.'+$id) --applied-at ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) --output-dir (Join-Path $fixture 'binding')
    if($LASTEXITCODE -ne 0){throw 'Standard reviewed binding failed'}
    $binding=($bound -join "`n")|ConvertFrom-Json;$apply=Get-Content -LiteralPath $binding.apply_file -Raw|ConvertFrom-Json
    $receipt['plan_request']=Get-Content -LiteralPath $inputs.request_file -Raw|ConvertFrom-Json
    $receipt['plan']=$planned.result.payload;$receipt['apply_request']=$apply
    $registration=& $ServiceControlBinary --register $service $ServiceBinary $VolumeRoot $binding.envelope_file `
        $binding.envelope_sha256 $accountSid $receipt.service_sha256 --service-admitted-client
    if($LASTEXITCODE -ne 0 -or ($registration|ConvertFrom-Json).status -cne 'registered'){throw 'Standard registration failed'}
    $registered=$true
    $sid=[Security.Principal.NTAccount]::new('NT SERVICE\'+$service).Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt['service_sid']=$sid
    $inputAcl=Get-Acl -LiteralPath $fixture
    $inputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),
        'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $fixture -AclObject $inputAcl
    & $ServiceControlBinary --provision-target $service --confirm-empty-volume|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Standard target admission failed'}
    $receipt['service_policy']=Read-ServicePolicy
    $receipt['discovery']=Invoke-StandardRequest 'publisher.inspect' @{schema='usk.publisher_capability_request.v1';request_id='inspect.'+$id} 2
    if($receipt.discovery.status -cne 'refused' -or $receipt.discovery.error.code -cne 'publisher_capability_unavailable'){throw 'Unqualified standard discovery did not refuse explicitly'}
    $receipt['capability_protocol']='usk.publisher_capability.v3'
    $receipt['service_discovery']=Invoke-StandardRequest 'publisher.observe' @{schema='usk.publisher_capability_request.v3';request_id='observe.'+$id}
    if($receipt.service_discovery.result.schema -cne 'usk.publisher_capability.v3' -or
        $receipt.service_discovery.result.availability -ne $true -or
        $receipt.service_discovery.result.qualification -cne 'qualified_for_scope' -or
        $receipt.service_discovery.result.support -cne 'supported_for_scope' -or
        $receipt.service_discovery.result.execution_lease_held -ne $false) {throw 'Scoped service observation lost its qualified dimensions'}
    $receipt['apply']=Invoke-StandardRequest 'install_local.apply' $apply
    $installed=$receipt.apply.result.payload
    if($installed.install_id -cne $apply.plan_request.install_id -or $installed.transaction_id -cne $apply.transaction_id -or
        $installed.created_at -cne $apply.applied_at -or $installed.lifecycle_status -cne 'installed'){throw 'Standard installed state identity differs'}
    $before=Read-InstalledSnapshot;$receipt.readbacks.Add($before)
    $exactFixture=[IO.Path]::GetFullPath($fixture)
    if($exactFixture -cne [IO.Path]::GetFullPath((Join-Path $lab 'standard-authored-inputs')) -or
        (Get-Item -LiteralPath $exactFixture).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Owned standard source cleanup escaped'}
    Remove-Item -LiteralPath $exactFixture -Recurse -Force
    if(Test-Path -LiteralPath $binding.envelope_file){throw 'Standard original source remains'}
    $receipt['source_free']=$true
    $receipt['recovery']=Invoke-StandardRequest 'install_local.recover' @{schema='usk.publisher_recovery_request.v1';request_id='recover.'+$id;
        install_id=$installed.install_id;transaction_id=$installed.transaction_id}
    $recovered=Read-InstalledSnapshot;$receipt.readbacks.Add($recovered)
    Assert-LeaseTransition $before $recovered
    $receipt['replayed_apply']=Invoke-StandardRequest 'install_local.apply' $apply
    foreach($terminal in @($receipt.recovery,$receipt.replayed_apply)) {
        if(($terminal.result.payload|ConvertTo-Json -Depth 64 -Compress) -cne ($installed|ConvertTo-Json -Depth 64 -Compress)){throw 'Standard source-free state changed'}
    }
    $after=Read-InstalledSnapshot;$receipt.readbacks.Add($after)
    Assert-LeaseTransition $recovered $after
    $verify=@{schema='usk.publisher_installed_verify_request.v1';request_id='verify.'+$id;install_id=$installed.install_id;
        transaction_id=$installed.transaction_id;report_id='verify.'+$id;verified_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}
    $receipt['verification']=Invoke-StandardRequest 'installed.verify' $verify
    if($receipt.verification.result.payload.status -cne 'pass' -or $receipt.verification.result.payload.report_id -cne $verify.report_id){throw 'Standard verification failed'}
    $verified=Read-InstalledSnapshot;$receipt.readbacks.Add($verified)
    if(($after.independent.rows|ConvertTo-Json -Depth 64 -Compress) -cne ($verified.independent.rows|ConvertTo-Json -Depth 64 -Compress)){throw 'Standard verification changed target snapshot'}
    Assert-LeaseTransition $after $verified $true
    $receipt['source_free_service_discovery']=Invoke-StandardRequest 'publisher.observe' @{schema='usk.publisher_capability_request.v3';request_id='observe-source-free.'+$id}
    if(($receipt.service_discovery.result.binding|Select-Object service_name,service_sid,caller_sid,binary_sha256,registration_sha256,target_admitted_sha256,volume_guid_root,root_file_id,volume_serial|ConvertTo-Json -Compress) -cne
        ($receipt.source_free_service_discovery.result.binding|Select-Object service_name,service_sid,caller_sid,binary_sha256,registration_sha256,target_admitted_sha256,volume_guid_root,root_file_id,volume_serial|ConvertTo-Json -Compress)) {
        throw 'Source-free service observation changed retained admission bindings'
    }
    $receipt.status='standard_public_install_verified_recovered'
} catch {$receipt.status='failed';$receipt['failure']=$_.Exception.Message}
finally {
    if($secret){$secret.Dispose()}
    if($clientTokenLease -and $observersClosed) {
        try {$clientTokenLease.Dispose();$clientTokenLease=$null}
        catch {$clientsClosed=$false;$receipt.status='failed';$receipt['cleanup_failure']=$_.Exception.Message}
    }
    $receipt.client_cleanup_confirmed=$clientsClosed -and $observersClosed -and $null -eq $clientTokenLease
    if($accountCreated -and $receipt.client_cleanup_confirmed) {
        try {
            $remaining=Get-LocalUser -Name $accountName -ErrorAction Stop
            if($remaining.SID.Value -cne $accountSid){throw 'Owned standard cleanup SID differs'}
            Remove-LocalUser -SID $remaining.SID -ErrorAction Stop
            if(Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue){throw 'Owned standard account remains'}
            $receipt.account_cleanup_confirmed=$true
        } catch {$receipt.status='failed';$receipt['cleanup_failure']=$_.Exception.Message}
    }
    Write-Json $OutputPath $receipt
}
if($receipt.status -cne 'standard_public_install_verified_recovered' -or -not $receipt.client_cleanup_confirmed -or
    -not $receipt.account_cleanup_confirmed){throw ('Standard public qualification failed: '+$receipt.failure)}
