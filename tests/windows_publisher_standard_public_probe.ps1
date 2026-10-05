# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$ServiceControlBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$PythonBinary,
    [switch]$BootstrapProcessLoss,
    [switch]$BootstrapPreservationProcessLoss,
    [switch]$ActiveInstallContention,
    [switch]$StalePlanQualification
)
$ErrorActionPreference='Stop'
if($ActiveInstallContention -and ($BootstrapProcessLoss -or $BootstrapPreservationProcessLoss)) {
    throw 'Active holder contention requires the original uninterrupted installer'
}
. (Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_owned_process.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_production_boundary.ps1')
. (Join-Path $PSScriptRoot 'windows_publisher_active_worker.ps1')
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
$activeContenderClosed=$true;$activeWorkerRestored=$true;$activeRetainedTokenLease=$null;$activeRetainedOriginalTokenLease=$null
$ownerCreation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$publisherBuild=Split-Path -Parent (Split-Path -Parent ([IO.Path]::GetFullPath($ServiceBinary)))
$publisherProjectPath=Join-Path $publisherBuild 'usk_publisher_windows_static.vcxproj'
$publisherProject=[xml][IO.File]::ReadAllText($publisherProjectPath)
$publisherSdk=@($publisherProject.Project.PropertyGroup.WindowsTargetPlatformVersion|Where-Object {$_}|Select-Object -Unique)
if($publisherSdk.Count -ne 1 -or $publisherSdk[0] -cnotmatch '^10\.0\.[1-9][0-9]*\.0$'){throw 'Standard native publisher SDK is unavailable'}
$utf8=[Text.UTF8Encoding]::new($false)
$installedBinary=Join-Path $env:ProgramW6432 ('Universal Setup\Publisher\'+$service+'.exe')
$receipt=[ordered]@{schema='usk.publisher_standard_public_probe.v1';status='not_run';service=$service;
    installed_binary=$installedBinary;
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
function Read-NativeSnapshot([switch]$PublicationPreserved) {
    $script:observersClosed=$false
    $readback=Invoke-IndependentMetadataReadback -DriveRoot $drive -OutputRoot $lab -RunId ([guid]::NewGuid().ToString('N')) `
        -CallerProcessId $PID -CallerCreationFileTime $ownerCreation -CallerSid $accountSid -ServiceSid $sid `
        -ClientCaptureFile $clientCaptureFile -ClientCaptureSha256 $clientCaptureSha256 `
        -ExpectedVolumeRoot $VolumeRoot -ExpectedDiskNumber $disk.Number `
        -AbsentPublicationPreservationPrefix $(if($PublicationPreserved){$script:bootstrapOperationPrefix}else{''})
    if(-not $readback.observer_task_removed -or $readback.independent.identity -cne 'S-1-5-18' -or
        $readback.independent.observer_token_handles_closed -ne $true){throw 'Standard independent reader cleanup differs'}
    $script:observersClosed=$true
    Assert-IndependentProtectedRows -Rows $readback.independent.rows -ServiceSid $sid -ConsumerSid $accountSid `
        -VisibleRoot ($drive+'publication\destination\visible')
    return $readback
}
function Read-InstalledSnapshot {
    $readback=Read-NativeSnapshot
    # Missing coordination cannot select a historical compatibility path.
    $leaseRequest=@{mode='snapshot';rows=$readback.independent.rows;drive=$drive;installed=$installed;
        volume_root_id=$readback.independent.volume_boundary.root.file_id}
    $leaseRequest|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_installation_lease_evidence.py') --input -|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Current standard snapshot lacks valid installation coordination'}
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
function Close-StandardPublisherClient($Process,$Launch,[bool]$LaunchAttempted=$true) {
    $script:clientsClosed=$false;$closureConfirmed=$false;$processDisposed=$false
    try {
        if($LaunchAttempted -and -not $Launch){throw 'Standard launch attempted without returned custody; retain account'}
        if($Launch -and -not $Launch.IsResumed){$Launch.Dispose()}
        if($Process) {
            # A retained descendant set still needs checking after root exit.
            $closure=Stop-OwnedPublisherProcessTree $Process
            if($closure.confirmed -ne $true){throw 'Standard client process closure is unconfirmed'}
        } elseif($Launch -and $Launch.IsResumed) {
            throw 'Resumed standard client has no held process for closure'
        }
        $closureConfirmed=$true
    } finally {
        try {
            if($Process){$Process.Dispose()}
            $processDisposed=$true
        } finally {
            if($Launch){$Launch.Dispose()}
            $script:clientsClosed=$closureConfirmed -and $processDisposed
        }
    }
}
function Invoke-RegisteredEndpointContention([Diagnostics.Process]$HeldWorker=$null,$WorkerPause=$null) {
    $activeHolder=$null -ne $HeldWorker
    if($activeHolder) {
        if(-not $WorkerPause -or $HeldWorker.HasExited -or (Get-Service $service).Status -ne 'Running') {
            throw 'Active contention fixture lacks a held live worker'
        }
        $WorkerPause.RequirePaused()
    } elseif((Get-Service $service).Status -ne 'Stopped'){throw 'Contention fixture did not begin at a stopped service'}
    $probeBinary=Join-Path (Split-Path -Parent $MachineBinary) 'usk_publisher_registered_contention_probe.exe'
    if(-not (Test-Path -LiteralPath $probeBinary)){throw 'Registered contention producer is unavailable'}
    $probeHash=(Get-FileHash -LiteralPath $probeBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $requestId='contention.'+[guid]::NewGuid().ToString('N')
    $request=Join-Path $lab ($requestId+'.json');$stdout=$request+'.stdout';$stderr=$request+'.stderr'
    Write-Json $request @{schema='usk.oneshot_request.v1';request_id=$requestId;command='install_local.apply';payload=$apply;dry_run=$false}
    $record=[ordered]@{schema='usk.publisher_registered_contention_probe.v1';scope=$(if($activeHolder){
            'active_install_holder_endpoint_before_effect_request_bytes'
        }else{'registered_endpoint_before_effect_request_bytes'});
        profile_qualified=$false;producer_sha256=$probeHash;request_sha256=(Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant();
        client_capture=$null;native_observation=$null;before=$null;after=$null;worker_stopped=$false}
    $receipt[$(if($activeHolder){'active_install_contention'}else{'registered_contention'})]=$record
    if($activeHolder){$record['paused_worker']=$WorkerPause.Observation()}
    $launch=$null;$process=$null;$launchAttempted=$false;$script:clientsClosed=$false
    try {
        $probeAcl=Get-Acl -LiteralPath $probeBinary
        $probeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($accountSid),'ReadAndExecute','Allow'))
        Set-Acl -LiteralPath $probeBinary -AclObject $probeAcl
        if($clientTokenLease) {
            if(-not $observersClosed -or (Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $clientCaptureSha256){
                throw 'Prior standard observer/capture is not closed and stable'
            }
            $clientTokenLease.Dispose();$script:clientTokenLease=$null
            [IO.File]::Move($clientCaptureFile,(Join-Path $lab ('retired-client-token-'+[guid]::NewGuid().ToString('N')+'.json')))
        }
        $launchAttempted=$true
        $arguments=$service+' "'+$request+'" '+$receipt.service_sha256
        if($activeHolder){$arguments+=' '+$HeldWorker.Id+' '+$HeldWorker.StartTime.ToUniversalTime().ToFileTimeUtc()}
        $launch=[UskPublisherPausedClient]::CreateOwnedStandard($probeBinary,
            $arguments,$stdout,$stderr,$accountName,$secret,$accountSid)
        $process=Get-Process -Id $launch.ProcessId;$null=$process.Handle
        $script:clientTokenLease=[UskPublisherEffectiveRights]::new($launch.ProcessId,$launch.CreationFileTime,$accountSid,$sid)
        $capture=$clientTokenLease.CaptureBinding($PID,[long]$ownerCreation,$probeBinary)
        $capture['client_sha256']=$probeHash;$capture['request_id']=$requestId;$capture['command']='registered_contention'
        Write-Json $clientCaptureFile $capture
        $script:clientCaptureSha256=(Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $record.client_capture=[ordered]@{request_id=$requestId;command='registered_contention';process_id=$launch.ProcessId;
            creation_file_time=$launch.CreationFileTime.ToString();captured_before_primary_thread_resume=$true;
            primary_token=$launch.OwnedStandardPrimaryFacts;launcher_token=$launch.OwnedStandardLauncherFacts;image_sha256=$probeHash;
            capture_sha256=$clientCaptureSha256;initiating_token_id=$capture.initiating_token_id;filtered_token_id=$capture.filtered_token_id}
        $record.before=Read-NativeSnapshot
        if($activeHolder) {
            $leaseRequest=@{mode='snapshot';rows=$record.before.independent.rows;drive=$drive;
                installed=@{install_id=$apply.plan_request.install_id;transaction_id=$apply.transaction_id};
                allow_active=$true;allow_initial_empty_state=$true;
                volume_root_id=$record.before.independent.volume_boundary.root.file_id}
            $decoded=$leaseRequest|ConvertTo-Json -Depth 64 -Compress|
                & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_installation_lease_evidence.py') --input -
            if($LASTEXITCODE -ne 0){throw 'Active contention lacks independently reconciled native ownership'}
            $record['lease_before']=($decoded -join "`n")|ConvertFrom-Json
            $history=@($record.lease_before.coordination.history)
            if($history.Count -ne 1 -or $history[0].status -cne 'active' -or $history[0].generation -ne 1 -or
                $history[0].holder.process_id -ne $HeldWorker.Id -or
                $history[0].holder.process_creation_time -cne $HeldWorker.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16')) {
                throw 'Active contention native generation/holder differs'
            }
            $WorkerPause.RequirePaused()
        } else {
            Start-Service -Name $service -ErrorAction Stop
            (Get-Service $service).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        }
        $launch.Resume()
        if(-not $process.WaitForExit(60000)){throw 'Registered contention producer exceeded its deadline'}
        $process.WaitForExit()
        $stdoutLength=(Get-Item -LiteralPath $stdout).Length;$stderrLength=(Get-Item -LiteralPath $stderr).Length
        if($process.ExitCode -ne 0 -or $stdoutLength -gt 1MB -or $stderrLength -ne 0){
            $errorBytes=[byte[]]::new(4096);$errorStream=[IO.File]::OpenRead($stderr)
            try {$errorCount=$errorStream.Read($errorBytes,0,$errorBytes.Length)} finally {$errorStream.Dispose()}
            # Failed fixture diagnostics are retained privately; a successful
            # closed evidence record never contains this additional field.
            $record['producer_failure']=[ordered]@{exit_code=$process.ExitCode;stdout_bytes=$stdoutLength;
                stderr_bytes=$stderrLength;stderr_excerpt=[Text.Encoding]::UTF8.GetString($errorBytes,0,$errorCount)}
            throw 'Registered contention producer failed'
        }
        $record.native_observation=[IO.File]::ReadAllText($stdout)|ConvertFrom-Json
        $native=$record.native_observation
        if($native.schema -cne 'usk.publisher_registered_contention_observation.v1' -or $native.status -cne 'pass' -or
            $native.profile_qualified -ne $false -or $native.scope -cne $record.scope -or
            $native.request_sha256 -cne $record.request_sha256 -or $native.worker_expected_image_sha256 -cne $receipt.service_sha256 -or
            -not [string]::Equals($native.worker_process_image_path,$installedBinary,[StringComparison]::OrdinalIgnoreCase) -or
            $native.caller_process_id -ne $launch.ProcessId -or
            [string]$native.caller_process_creation_time -cne $launch.CreationFileTime.ToString()){
            throw 'Registered contention native source/client binding differs'
        }
        if($activeHolder) {
            $WorkerPause.RequirePaused()
            if($native.worker_process_id -ne $HeldWorker.Id -or
                [string]$native.worker_process_creation_time -cne $HeldWorker.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) {
                throw 'Active contention producer observed a different worker'
            }
        } else {
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 50}
            if((Get-Service $service).Status -ne 'Stopped'){throw 'Registered contention worker did not stop after endpoint release'}
            $record.worker_stopped=$true
        }
        $record.after=Read-NativeSnapshot
        if(($record.before.independent.rows|ConvertTo-Json -Depth 64 -Compress) -cne
            ($record.after.independent.rows|ConvertTo-Json -Depth 64 -Compress) -or
            ($record.before.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress) -cne
            ($record.after.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress)){
            throw 'Registered pre-dispatch contention changed the independently observed target'
        }
    } finally {Close-StandardPublisherClient $process $launch $launchAttempted}
}
function Invoke-ActiveInstallContention([Diagnostics.Process]$Installer) {
    $script:activeContenderClosed=$false;$script:activeWorkerRestored=$false
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    $candidate=$drive+'publication\staging\candidate'
    $worker=$null;$pause=$null;$pauseAttempted=$false
    $priorToken=$clientTokenLease;$priorCaptureFile=$clientCaptureFile;$priorCaptureSha256=$clientCaptureSha256
    $script:activeRetainedOriginalTokenLease=$priorToken
    $retainedCapture=Join-Path $lab ('active-retained-installer-'+[guid]::NewGuid().ToString('N')+'.json')
    $captureMoved=$false;$captureRestored=$false
    try {
        # Observe only this fixture's real installer. No production gate or
        # authority transfer is introduced; its held lease remains active.
        while([DateTime]::UtcNow -lt $deadline) {
            if($Installer.HasExited){throw 'Active installer observation window already passed'}
            if(Test-Path -LiteralPath $candidate) {
                $registration=Get-CimInstance Win32_Service -Filter ("Name='"+$service+"'") -ErrorAction Stop
                if($registration.State -ceq 'Running' -and $registration.ProcessId -gt 0) {
                    $worker=Get-Process -Id $registration.ProcessId -ErrorAction Stop;$null=$worker.Handle
                    break
                }
            }
            Start-Sleep -Milliseconds 1
        }
        if(-not $worker){throw 'Active installer native candidate was not observed before its deadline'}
        $pauseAttempted=$true
        $pause=Start-OwnedPublisherWorkerPause -Process $worker -Service $service -VhdPath $VhdPath `
            -VolumeRoot $VolumeRoot -ExpectedServiceCommand $registeredCommand `
            -ExpectedImagePath $installedBinary -ExpectedImageSha256 $receipt.service_sha256
        if(-not $observersClosed -or (Get-FileHash -LiteralPath $priorCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $priorCaptureSha256) {
            throw 'Original active installer capture is not stable and closed'
        }
        [IO.File]::Move($priorCaptureFile,$retainedCapture);$captureMoved=$true
        $script:clientTokenLease=$null
        $script:clientCaptureSha256=''
        Invoke-RegisteredEndpointContention -HeldWorker $worker -WorkerPause $pause
        if(-not $script:clientsClosed){throw 'Active contender cleanup remains unconfirmed'}
        $script:activeContenderClosed=$true
        $pause.RequirePaused()
        $receipt.active_install_contention['installer_live_before_resume']=-not $Installer.HasExited
        if($Installer.HasExited){throw 'First installer ended during active contention'}
    } finally {
        try {
            if($clientTokenLease -and $clientTokenLease -ne $priorToken) {
                $script:activeRetainedTokenLease=$clientTokenLease
                if($observersClosed) {$clientTokenLease.Dispose();$script:activeRetainedTokenLease=$null}
            }
            if($captureMoved) {
                if(-not $observersClosed){throw 'Active observer still borrows its capture; retain both token leases'}
                if(Test-Path -LiteralPath $priorCaptureFile) {
                    if((Get-FileHash -LiteralPath $priorCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $clientCaptureSha256) {
                        throw 'Active contender capture changed before checked retirement'
                    }
                    [IO.File]::Move($priorCaptureFile,(Join-Path $lab ('retired-active-contender-'+[guid]::NewGuid().ToString('N')+'.json')))
                }
                [IO.File]::Move($retainedCapture,$priorCaptureFile)
                if((Get-FileHash -LiteralPath $priorCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $priorCaptureSha256) {
                    throw 'Original active installer capture differs after restoration'
                }
            }
            $script:clientTokenLease=$priorToken;$script:clientCaptureFile=$priorCaptureFile
            $script:clientCaptureSha256=$priorCaptureSha256;$captureRestored=$true
            $script:activeRetainedOriginalTokenLease=$null
        } finally {
            $script:clientsClosed=$false # The first installer still needs checked closure.
            try {
                $pauseFailure=$null
                try {
                    if($pause){$pause.Dispose();$script:activeWorkerRestored=$true}
                    elseif($pauseAttempted){throw 'Worker pause attempted without returned custody'}
                } catch {$pauseFailure=$_.Exception}
                if($pauseFailure) {
                    # A failed constructor/restoration must not strand this
                    # owned worker. Recheck the same private registration and
                    # retained process before bounded failure-only termination.
                    if($worker -and -not $worker.HasExited) {
                        $current=Get-CimInstance Win32_Service -Filter ("Name='"+$service+"'") -ErrorAction Stop
                        if($current.ProcessId -ne $worker.Id -or $current.PathName -cne $registeredCommand -or
                            -not [string]::Equals($worker.Path,$installedBinary,[StringComparison]::OrdinalIgnoreCase) -or
                            (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.service_sha256) {
                            throw 'Failed pause worker ownership is unconfirmed; retain the lab'
                        }
                        $termination=Stop-OwnedPublisherProcessTree -Process $worker -RequireLiveKill
                        if(-not $termination.confirmed){throw 'Failed pause worker termination is unconfirmed'}
                        $receipt['failed_active_worker_termination']=$termination
                    }
                    throw $pauseFailure
                }
                if($receipt.Contains('active_install_contention')) {
                    $receipt.active_install_contention['worker_pause_restored']=$activeWorkerRestored -and $captureRestored
                    if(-not $captureRestored){$script:activeWorkerRestored=$false}
                }
            } finally {if($worker){$worker.Dispose()}}
        }
    }
}
function Invoke-StandardRequest([string]$Command,$Payload,[int]$ExpectedExit=0,[switch]$BootstrapLoss,[switch]$PreservationLoss,
    [switch]$StalePlanRefusal,[switch]$StateRevisionRefusal) {
    if((Get-Service $service).Status -ne 'Stopped') {throw 'Standard request did not begin at a stopped service'}
    $processLoss=$BootstrapLoss -or $PreservationLoss
    $structuredRefusal=$StalePlanRefusal -or $StateRevisionRefusal
    if(($StalePlanRefusal -and $StateRevisionRefusal) -or
        ($structuredRefusal -and ($Command -cne 'install_local.apply' -or $ExpectedExit -ne 4 -or $processLoss))) {
        throw 'Stale-plan case requires a completed authenticated refusal'
    }
    $lossKey=if($PreservationLoss){'bootstrap_preservation_loss'}else{'bootstrap_loss'}
    $lossPhase=if($PreservationLoss){'bootstrap_preserved'}else{'bootstrap'}
    if(($BootstrapLoss -and $PreservationLoss) -or ($processLoss -and
        ($Command -cne 'install_local.apply' -or $ExpectedExit -ne 5 -or -not $BootstrapProcessLoss -or
            $receipt.Contains($lossKey) -or ($PreservationLoss -and
                (-not $BootstrapPreservationProcessLoss -or -not $receipt.Contains('bootstrap_loss')))))) {
        throw 'Bootstrap interruption request differs'
    }
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
    $launch=$null;$process=$null;$bootstrapObserver=$null;$launchAttempted=$false;$script:clientsClosed=$false
    try {
        $launchAttempted=$true
        $launch=[UskPublisherPausedClient]::CreateOwnedStandard($MachineBinary,('--machine --publisher '+$service+
            ' --request-file "'+$request+'" --publisher-observation-file "'+$nativeOutput+'"'),$stdout,$stderr,$accountName,$secret,$accountSid)
        $process=Get-Process -Id $launch.ProcessId;$null=$process.Handle
        $script:clientTokenLease=[UskPublisherEffectiveRights]::new($launch.ProcessId,$launch.CreationFileTime,$accountSid,$sid)
        $capture=$clientTokenLease.CaptureBinding($PID,[long]$ownerCreation,$MachineBinary)
        $capture['client_sha256']=$receipt.machine_sha256;$capture['request_id']=$requestId;$capture['command']=$Command
        if(Test-Path -LiteralPath $clientCaptureFile){throw 'Standard held-client capture already exists'}
        Write-Json $clientCaptureFile $capture
        $script:clientCaptureSha256=(Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $clientCapture=[ordered]@{request_id=$requestId;command=$Command;process_id=$launch.ProcessId;
            creation_file_time=$launch.CreationFileTime.ToString();captured_before_primary_thread_resume=$true;
            primary_token=$launch.OwnedStandardPrimaryFacts;launcher_token=$launch.OwnedStandardLauncherFacts;image_sha256=$receipt.machine_sha256;
            capture_sha256=$clientCaptureSha256;initiating_token_id=$capture.initiating_token_id;filtered_token_id=$capture.filtered_token_id}
        if($processLoss) {
            $receipt[$lossKey]=[ordered]@{schema=$(if($PreservationLoss){
                    'usk.publisher_registered_bootstrap_preservation_loss.v1'
                }else{'usk.publisher_registered_bootstrap_loss.v1'});
                client_capture=$clientCapture;response=$null;boundary=$null;readback=$null;reconciliation=$null}
            # The production worker waits for authenticated RPC. Start only the
            # exact owned fixture service while this ordinary client is paused.
            Start-Service -Name $service -ErrorAction Stop
            (Get-Service $service).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
            $observerRoot=Join-Path $lab ($lossPhase+'-observer')
            New-Item -ItemType Directory -Path $observerRoot -ErrorAction Stop|Out-Null
            $script:observersClosed=$false
            $operationPrefix=if($PreservationLoss){$script:bootstrapOperationPrefix}else{''}
            $bootstrapObserver=Start-OwnedProductionBoundaryObserver -Phase $lossPhase -Service $service `
                -ObserverRoot $observerRoot -VhdPath $VhdPath -VolumeRoot $VolumeRoot -DriveRoot $drive `
                -VisibleRoot ($drive+'publication\destination\visible') -ServiceCommand $registeredCommand `
                -ServiceBinarySha256 $receipt.service_sha256 -BootstrapOperationPrefix $operationPrefix
        } elseif($StalePlanRefusal) {$script:stalePlanCase.client_capture=$clientCapture}
        elseif($StateRevisionRefusal) {$script:stateRevisionCase.client_capture=$clientCapture}
        else {$receipt.client_captures.Add($clientCapture)}
        $launch.Resume()
        if($ActiveInstallContention -and $Command -ceq 'install_local.apply' -and -not $processLoss -and
            -not $receipt.Contains('active_install_contention')) {
            Invoke-ActiveInstallContention $process
        }
        if(-not $process.WaitForExit(120000)) {throw 'Standard public client exceeded its deadline'}
        $process.WaitForExit();$exit=$process.ExitCode
        $diagnostic=[IO.File]::ReadAllText($stderr)
        if((Get-Item -LiteralPath $stdout).Length -gt 4MB -or (Get-Item -LiteralPath $stderr).Length -gt 64KB -or
            (($ExpectedExit -eq 0 -or $structuredRefusal) -and $diagnostic.Length) -or
            ($processLoss -and $diagnostic.Length) -or
            ($ExpectedExit -ne 0 -and -not $processLoss -and -not $structuredRefusal -and
                $diagnostic -cnotmatch '^usk_machine: request refused\r?\n?$')) {throw 'Standard client output differs'}
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
        if($processLoss) {
            $responseMatches=$responseMatches -and $result.status -ceq 'unknown' -and $null -eq $result.result -and
                $result.error.code -ceq 'publisher_outcome_unknown' -and -not (Test-Path -LiteralPath $nativeOutput)
            $receipt[$lossKey].response=$result
            $receipt[$lossKey].boundary=Complete-OwnedProductionBoundaryObserver $bootstrapObserver $lossPhase
            $script:observersClosed=$true
        }
        if($StalePlanRefusal) {
            $responseMatches=$responseMatches -and $result.status -ceq 'refused' -and $null -eq $result.result -and
                $result.error.code -ceq 'stale_plan'
            $script:stalePlanCase.response=$result
        }
        if($StateRevisionRefusal) {
            $responseMatches=$responseMatches -and $result.status -ceq 'refused' -and $null -eq $result.result -and
                $result.error.code -ceq 'state_revision_stale'
            $script:stateRevisionCase.response=$result
        }
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
        if($ExpectedExit -eq 0 -or $structuredRefusal) {
            if(-not (Test-Path -LiteralPath $nativeOutput) -or (Get-Item -LiteralPath $nativeOutput).Length -gt 4MB) {
                throw 'Standard native response capture is missing or exceeds its bound'
            }
            $nativeText=[IO.File]::ReadAllText($nativeOutput)
            $native=$nativeText|ConvertFrom-Json
            $nativeSchema=if($Command -ceq 'publisher.observe'){'usk.publisher_service_capability_observation.v1'}else{'usk.publisher_lab_service_observation.v1'}
            $nativeStatus=if($structuredRefusal){'failed'}elseif($Command -ceq 'publisher.observe'){'observed'}else{'pass'}
            if($native.schema -cne $nativeSchema -or $native.status -cne $nativeStatus -or
                $null -eq $native.registered_admission){throw 'Standard native admission capture is incomplete'}
            $nativeCapture=[ordered]@{command=$Command;request_id=$requestId;
                native_json=$nativeText;sha256=(Get-FileHash -LiteralPath $nativeOutput -Algorithm SHA256).Hash.ToLowerInvariant()}
            if($StalePlanRefusal) {
                if($native.error_code -cne 'stale_plan'){throw 'Native stale-plan reason was not preserved'}
                $script:stalePlanCase.native_observation=$nativeCapture
            } elseif($StateRevisionRefusal) {
                if($native.error_code -cne 'state_revision_stale' -or $null -eq $native.reviewed_operation_admission){
                    throw 'Native approved-operation revision refusal was not preserved'
                }
                $script:stateRevisionCase.native_observation=$nativeCapture
            } else {$receipt.native_observations.Add($nativeCapture)}
        }
        return $result
    } finally {
        try {
            if($bootstrapObserver -and -not $bootstrapObserver.removed) {
                Remove-OwnedProductionBoundaryObserver $bootstrapObserver
                $script:observersClosed=$true
            }
        } finally {
            Close-StandardPublisherClient $process $launch $launchAttempted
        }
    }
}
function Invoke-StalePlanCases([int]$BaselineIndex,[bool]$SourceFree) {
    $baseline=$receipt.readbacks[$BaselineIndex]
    $fields=if($SourceFree){@('transaction_id','applied_at')}else{@('reviewed_plan_digest','plan_request.request_id')}
    foreach($field in $fields) {
        $changed=$apply|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
        switch -CaseSensitive ($field) {
            'reviewed_plan_digest' {$changed.reviewed_plan_digest=$(if($changed.reviewed_plan_digest -ceq ('0'*64)){'1'*64}else{'0'*64})}
            'plan_request.request_id' {$changed.plan_request.request_id='stale.'+[guid]::NewGuid().ToString('N')}
            'transaction_id' {$changed.transaction_id='stale.'+[guid]::NewGuid().ToString('N')}
            'applied_at' {$changed.applied_at='2000-01-01T00:00:00Z'}
            default {throw 'Unknown finite stale-plan field'}
        }
        $script:stalePlanCase=[ordered]@{field=$field;source_free=$SourceFree;apply_request=$changed;
            client_capture=$null;response=$null;native_observation=$null;readback=$null}
        $receipt.stale_plan_refusals.cases.Add($script:stalePlanCase)
        $null=Invoke-StandardRequest 'install_local.apply' $changed 4 -StalePlanRefusal
        $readback=Read-InstalledSnapshot
        if(($readback.independent.rows|ConvertTo-Json -Depth 64 -Compress) -cne
            ($baseline.independent.rows|ConvertTo-Json -Depth 64 -Compress) -or
            ($readback.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress) -cne
            ($baseline.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress)) {
            throw 'Stale-plan refusal changed the independently observed native target'
        }
        # Share only exactly equal rows. Retain the fresh reader/token/closure
        # observation, with a canonical digest bound to the existing raw rows.
        $digest=$readback.independent.rows|ConvertTo-Json -Depth 64 -Compress|
            & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_stale_plan_evidence.py') --rows-digest
        if($LASTEXITCODE -ne 0 -or [string]$digest -cnotmatch '^[0-9a-f]{64}$'){throw 'Native stale-plan row digest failed'}
        $readback.independent.rows=[ordered]@{schema='usk.publisher_native_rows_reference.v1';
            baseline_readback_index=$BaselineIndex;sha256=[string]$digest}
        $script:stalePlanCase.readback=$readback
        $script:stalePlanCase=$null
    }
}
function Invoke-ChangedStateCase([int]$BaselineIndex,[bool]$SourceFree) {
    $baseline=$receipt.readbacks[$BaselineIndex]
    $script:stateRevisionCase=[ordered]@{source_free=$SourceFree;client_capture=$null;
        response=$null;native_observation=$null;readback=$null}
    $receipt.changed_state_revision.cases.Add($script:stateRevisionCase)
    $null=Invoke-StandardRequest 'install_local.apply' $applyA 4 -StateRevisionRefusal
    $readback=Read-InstalledSnapshot
    if(($readback.independent.rows|ConvertTo-Json -Depth 64 -Compress) -cne
        ($baseline.independent.rows|ConvertTo-Json -Depth 64 -Compress) -or
        ($readback.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress) -cne
        ($baseline.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress)) {
        throw 'Approved Plan A refusal changed committed Plan B native material'
    }
    $digest=$readback.independent.rows|ConvertTo-Json -Depth 64 -Compress|
        & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_stale_plan_evidence.py') --rows-digest
    if($LASTEXITCODE -ne 0 -or [string]$digest -cnotmatch '^[0-9a-f]{64}$'){throw 'Changed-state native row digest failed'}
    $readback.independent.rows=[ordered]@{schema='usk.publisher_native_rows_reference.v1';
        baseline_readback_index=$BaselineIndex;sha256=[string]$digest}
    $script:stateRevisionCase.readback=$readback
    $script:stateRevisionCase=$null
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
    $fixtureArguments=@('--output',$fixture,'--target',($drive+'publication\destination\visible'),'--request-id',('standard.'+$id))
    if($ActiveInstallContention){$fixtureArguments+=@('--core-bytes','33554432')}
    $generated=& $PythonBinary -B (Join-Path $PSScriptRoot 'windows_publisher_metadata_inputs.py') @fixtureArguments
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
    if($StalePlanQualification) {
        # Plan A is independently produced by the real machine planner while
        # the target is still empty. Only its authored request identity differs
        # from B; no apply digest or installed record is manufactured.
        $requestA=$receipt.plan_request|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
        $requestA.request_id='planA.'+$id;$requestA.payload.request_id=$requestA.request_id
        $requestAPath=Join-Path $fixture 'plan-a-request.json';Write-Json $requestAPath $requestA
        $planAOutput=& $MachineBinary --machine --request-file $requestAPath --context-file $context
        if($LASTEXITCODE -ne 0){throw 'Independent initial Plan A failed'}
        $planAResponsePath=Join-Path $fixture 'plan-a-response.json'
        [IO.File]::WriteAllText($planAResponsePath,($planAOutput -join "`n")+"`n",$utf8)
        $boundA=& $PythonBinary -B (Join-Path $PSScriptRoot '..\tools\usk_bundle_apply_binding.py') --request-file $requestAPath `
            --response-file $planAResponsePath --acceptance-root $drive --state-root ($drive+'setup-state') `
            --transaction-id ('installA.'+$id) --applied-at ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')) `
            --output-dir (Join-Path $fixture 'binding-a')
        if($LASTEXITCODE -ne 0){throw 'Real Plan A reviewed binding failed'}
        $bindingA=($boundA -join "`n")|ConvertFrom-Json
        $applyA=Get-Content -LiteralPath $bindingA.apply_file -Raw|ConvertFrom-Json
        $receipt['changed_state_revision']=[ordered]@{schema='usk.publisher_changed_state_revision_probe.v1';
            scope='approved_initial_plan_a_commit_b_apply_a_before_effects';profile_qualified=$false;
            publication_authority_granted=$false;plan_a_request=$requestA;
            plan_a_response=($planAOutput -join "`n")|ConvertFrom-Json;apply_a=$applyA;
            planned_at_file_time=[DateTime]::UtcNow.ToFileTimeUtc().ToString();enrolled_at_file_time=$null;
            envelope_a_json=[IO.File]::ReadAllText($bindingA.envelope_file);
            enrollments=[Collections.Generic.List[object]]::new();cases=[Collections.Generic.List[object]]::new()}
    }
    $registration=& $ServiceControlBinary --register $service $ServiceBinary $VolumeRoot $binding.envelope_file `
        $binding.envelope_sha256 $accountSid $receipt.service_sha256 --service-admitted-client
    if($LASTEXITCODE -ne 0 -or ($registration|ConvertFrom-Json).status -cne 'registered'){throw 'Standard registration failed'}
    $registered=$true
    $registeredCommand=(Get-CimInstance Win32_Service -Filter ("Name='"+$service+"'") -ErrorAction Stop).PathName
    $sid=[Security.Principal.NTAccount]::new('NT SERVICE\'+$service).Translate([Security.Principal.SecurityIdentifier]).Value
    $receipt['service_sid']=$sid
    $inputAcl=Get-Acl -LiteralPath $fixture
    $inputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),
        'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $fixture -AclObject $inputAcl
    & $ServiceControlBinary --provision-target $service --confirm-empty-volume|Out-Null
    if($LASTEXITCODE -ne 0){throw 'Standard target admission failed'}
    if($StalePlanQualification) {
        foreach($approved in @($bindingA,$binding)) {
            $enrollment=& $ServiceControlBinary --enroll-reviewed-operation $service $approved.envelope_file `
                $approved.envelope_sha256 $approved.apply_file
            if($LASTEXITCODE -ne 0){throw 'Administrative reviewed-operation enrollment failed'}
            $observedEnrollment=($enrollment -join "`n")|ConvertFrom-Json
            if($observedEnrollment.status -cne 'reviewed_operation_enrolled' -or $observedEnrollment.service -cne $service){
                throw 'Reviewed operation enrollment response differs'
            }
            $receipt.changed_state_revision.enrollments.Add($observedEnrollment)
        }
        $receipt.changed_state_revision.enrolled_at_file_time=[DateTime]::UtcNow.ToFileTimeUtc().ToString()
    }
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
    if($BootstrapProcessLoss) {
        $null=Invoke-StandardRequest 'install_local.apply' $apply 5 -BootstrapLoss
        $receipt.bootstrap_loss.readback=Read-NativeSnapshot
    }
    if($BootstrapPreservationProcessLoss) {
        if(-not $BootstrapProcessLoss){throw 'Preservation loss requires the original reserved bootstrap loss'}
        $suffix='-bootstrap-g00000000000000000001.json'
        $reservations=@($receipt.bootstrap_loss.readback.independent.rows|Where-Object {
            -not $_.directory -and $_.path.EndsWith($suffix,[StringComparison]::Ordinal)})
        if($reservations.Count -ne 1){throw 'Original native bootstrap reservation is ambiguous'}
        $script:bootstrapOperationPrefix=$reservations[0].path.Substring(0,$reservations[0].path.Length-$suffix.Length)
        $null=Invoke-StandardRequest 'install_local.apply' $apply 5 -PreservationLoss
        $receipt.bootstrap_preservation_loss.readback=Read-NativeSnapshot -PublicationPreserved
    }
    $receipt['apply']=Invoke-StandardRequest 'install_local.apply' $apply
    $installed=$receipt.apply.result.payload
    if($installed.install_id -cne $apply.plan_request.install_id -or $installed.transaction_id -cne $apply.transaction_id -or
        $installed.created_at -cne $apply.applied_at -or $installed.lifecycle_status -cne 'installed'){throw 'Standard installed state identity differs'}
    $before=Read-InstalledSnapshot;$receipt.readbacks.Add($before)
    if($BootstrapProcessLoss) {
        $loss=$receipt.bootstrap_loss
        $bootstrapRequest=@{mode='bootstrap_takeover';before=$loss.readback.independent.rows;after=$before.independent.rows;
            drive=$drive;installed=$installed;volume_root_id=$before.independent.volume_boundary.root.file_id;
            terminated_holder=@{process_id=[int]$loss.boundary.service_pid;process_creation_time=$loss.boundary.process_creation_file_time}}
        if($BootstrapPreservationProcessLoss) {
            $preserved=$receipt.bootstrap_preservation_loss
            $bootstrapRequest.mode='bootstrap_preservation_takeover'
            $bootstrapRequest.Remove('terminated_holder')
            $bootstrapRequest.preserved=$preserved.readback.independent.rows
            $bootstrapRequest.terminated_holders=@(
                @{process_id=[int]$loss.boundary.service_pid;process_creation_time=$loss.boundary.process_creation_file_time},
                @{process_id=[int]$preserved.boundary.service_pid;process_creation_time=$preserved.boundary.process_creation_file_time})
        }
        $decoded=$bootstrapRequest|ConvertTo-Json -Depth 64 -Compress|
            & $PythonBinary -B (Join-Path $PSScriptRoot 'publisher_installation_lease_evidence.py') --input -
        if($LASTEXITCODE -ne 0){throw 'Registered bootstrap takeover/native preservation differs'}
        $receipt.bootstrap_loss.reconciliation=($decoded -join "`n")|ConvertFrom-Json
        if($BootstrapPreservationProcessLoss) {$receipt.bootstrap_preservation_loss.reconciliation=$receipt.bootstrap_loss.reconciliation}
    }
    Invoke-RegisteredEndpointContention
    if($StalePlanQualification) {
        $receipt['stale_plan_refusals']=[ordered]@{schema='usk.publisher_stale_plan_probe.v1';
            scope='authenticated_immutable_apply_context_before_effects';profile_qualified=$false;
            publication_authority_granted=$false;cases=[Collections.Generic.List[object]]::new()}
        Invoke-StalePlanCases 0 $false
        Invoke-ChangedStateCase 0 $false
    }
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
    if($StalePlanQualification){Invoke-StalePlanCases 1 $true}
    if($StalePlanQualification){Invoke-ChangedStateCase 1 $true}
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
    $receipt.client_cleanup_confirmed=$clientsClosed -and $observersClosed -and $null -eq $clientTokenLease -and
        $activeContenderClosed -and $activeWorkerRestored -and $null -eq $activeRetainedTokenLease -and
        $null -eq $activeRetainedOriginalTokenLease
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
