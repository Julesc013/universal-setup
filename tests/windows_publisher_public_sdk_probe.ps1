# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Uses the existing fixture's account, native process custody, capture and
# independent readback. This does not install or register a separate service.
function Invoke-StandardSdkRequest([string]$Command,$Payload,
    [ValidateSet('ok','refused')][string]$ExpectedStatus='ok') {
    if($Command -cnotin @('install_local.apply','installed.verify','repair.apply','move.apply','uninstall.apply',
        'recovery.inspect','recovery.plan','recovery.apply')) {throw 'SDK fixture command differs'}
    $binary=Join-Path (Split-Path -Parent $MachineBinary) 'usk_publisher_sdk_consumer.exe'
    if(-not (Test-Path -LiteralPath $binary -PathType Leaf)) {throw 'Public SDK consumer was not built'}
    $imageSha=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $requestId='public.'+[guid]::NewGuid().ToString('N')
    $request=Join-Path $lab ($requestId+'.json');$stdout=$request+'.stdout';$stderr=$request+'.stderr'
    Write-Json $request $Payload
    if($clientTokenLease) {
        if(-not $observersClosed -or
            (Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $clientCaptureSha256) {
            throw 'Prior observer/capture is not closed and stable before SDK request'
        }
        $clientTokenLease.Dispose();$script:clientTokenLease=$null
        [IO.File]::Move($clientCaptureFile,(Join-Path $lab ('retired-client-token-'+[guid]::NewGuid().ToString('N')+'.json')))
    }
    $launch=$null;$process=$null;$attempted=$false;$requestFailure=$null
    $record=[ordered]@{request_id=$requestId;command=$Command;binary=$binary;image_sha256=$imageSha;
        request_sha256=(Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant();
        native_observation='not_exposed_by_public_sdk';status='prepared';response=$null;expected_status=$ExpectedStatus;
        client_resume_attempted=$false;client_cleanup_confirmed=$false}
    if(-not $receipt.Contains('sdk_requests')) {$receipt['sdk_requests']=[Collections.Generic.List[object]]::new()}
    $receipt.sdk_requests.Add($record)
    try {
        $attempted=$true;$script:clientsClosed=$false
        $launch=[UskPublisherPausedClient]::CreateOwnedStandard($binary,
            ($service+' '+$Command+' "'+$request+'"'),$stdout,$stderr,$accountName,$secret,$accountSid)
        $process=Get-Process -Id $launch.ProcessId;$nativeHandle=$process.Handle
        $script:clientTokenLease=[UskPublisherEffectiveRights]::new($launch.ProcessId,$launch.CreationFileTime,$accountSid,$sid)
        $capture=$clientTokenLease.CaptureBinding($PID,[long]$ownerCreation,$binary)
        $capture['client_sha256']=$imageSha;$capture['request_id']=$requestId;$capture['command']=$Command
        if(Test-Path -LiteralPath $clientCaptureFile) {throw 'SDK held-client capture already exists'}
        Write-Json $clientCaptureFile $capture
        $script:clientCaptureSha256=(Get-FileHash -LiteralPath $clientCaptureFile -Algorithm SHA256).Hash.ToLowerInvariant()
        $record['client_capture']=[ordered]@{process_id=$launch.ProcessId;
            creation_file_time=$launch.CreationFileTime.ToString();captured_before_primary_thread_resume=$true;
            primary_token=$launch.OwnedStandardPrimaryFacts;launcher_token=$launch.OwnedStandardLauncherFacts;
            capture_sha256=$clientCaptureSha256;image_sha256=$imageSha}
        $record.client_resume_attempted=$true
        $launch.Resume()
        if(-not $process.WaitForExit(120000)) {throw 'Public SDK request exceeded its unchanged deadline'}
        $process.WaitForExit()
        $record['exit_code']=[UskMetadataFacts]::ReadExitedProcessCode($nativeHandle)
        if((Get-Item -LiteralPath $stdout).Length -gt 4MB -or (Get-Item -LiteralPath $stderr).Length -gt 64KB) {
            throw 'Public SDK output exceeds fixture bound'
        }
        $record['stdout_sha256']=(Get-FileHash -LiteralPath $stdout -Algorithm SHA256).Hash.ToLowerInvariant()
        $text=[IO.File]::ReadAllText($stdout)
        $record['stdout_prefix']=$text.Substring(0,[Math]::Min(8192,$text.Length))
        $result=$text|ConvertFrom-Json
        $record.response=$result
        $expectedExit=if($ExpectedStatus -ceq 'ok'){0}else{1}
        if($record.exit_code -ne $expectedExit -or [IO.File]::ReadAllText($stderr).Length -ne 0 -or
            $result.schema -cne 'usk.command_response.v1' -or $result.status -cne $ExpectedStatus -or
            ($ExpectedStatus -ceq 'ok' -and $null -ne $result.error) -or
            ($ExpectedStatus -ceq 'refused' -and $result.error.code -cne 'stale_plan')) {
            throw 'Public SDK did not return a completed command result'
        }
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) {Start-Sleep -Milliseconds 50}
        if((Get-Service $service).Status -ne 'Stopped') {throw 'Public SDK service did not stop'}
        if((Read-ServicePolicy|ConvertTo-Json -Depth 16 -Compress) -cne
            ($receipt.service_policy|ConvertTo-Json -Depth 16 -Compress)) {throw 'Service policy changed across SDK request'}
        $record.status='completed'
        return $result
    } catch {
        $requestFailure=$_
        $record.status='failed'
        $message=[string]$_.Exception.Message
        $record['failure']=$message.Substring(0,[Math]::Min(4096,$message.Length))
        throw
    } finally {
        try {
            Close-StandardPublisherClient $process $launch $attempted
            $record.client_cleanup_confirmed=$script:clientsClosed
            if(-not $record.client_cleanup_confirmed){throw 'SDK client cleanup is unconfirmed'}
        } catch {
            $message=[string]$_.Exception.Message
            $record['cleanup_failure']=$message.Substring(0,[Math]::Min(4096,$message.Length))
            if(-not $requestFailure){throw}
        }
    }
}

# Ordinary lifecycle commands only; private recovery selectors keep their
# distinct existing harness route and are never projected as public SDK work.
function Invoke-StandardLifecycleRequest([string]$Command,$Payload) {
    if($Command -cnotin @('install_local.apply','installed.verify','repair.apply','move.apply','uninstall.apply')) {
        throw 'Ordinary lifecycle fixture command differs'
    }
    if($SdkLifecycleQualification) {return Invoke-StandardSdkRequest $Command $Payload}
    return Invoke-StandardRequest $Command $Payload
}
function Get-StandardLifecyclePayload($Response) {
    if($SdkLifecycleQualification) {
        if($Response.schema -cne 'usk.command_response.v1' -or $Response.status -cne 'ok' -or
            $null -ne $Response.error -or $null -eq $Response.payload) {
            throw 'SDK lifecycle requires its actual completed public response'
        }
        return $Response.payload
    }
    if($Response.schema -cne 'usk.oneshot_response.v1' -or $Response.status -cne 'ok' -or
        $Response.result.schema -cne 'usk.command_response.v1' -or $Response.result.status -cne 'ok') {
        throw 'CLI lifecycle requires its actual completed machine response'
    }
    return $Response.result.payload
}
