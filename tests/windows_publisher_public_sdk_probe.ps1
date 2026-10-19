# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Uses the existing fixture's account, native process custody, capture and
# independent readback. This does not install or register a separate service.
function Invoke-StandardSdkRequest([string]$Command,$Payload) {
    if($Command -cnotin @('install_local.apply','installed.verify')) {throw 'SDK fixture command differs'}
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
    $launch=$null;$process=$null;$attempted=$false
    $record=[ordered]@{request_id=$requestId;command=$Command;binary=$binary;image_sha256=$imageSha;
        request_sha256=(Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant();
        native_observation='not_exposed_by_public_sdk';status='not_run';response=$null}
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
        if($record.exit_code -ne 0 -or [IO.File]::ReadAllText($stderr).Length -ne 0 -or
            $result.schema -cne 'usk.command_response.v1' -or $result.status -cne 'ok' -or $null -ne $result.error) {
            throw 'Public SDK did not return a completed command result'
        }
        $deadline=[DateTime]::UtcNow.AddSeconds(30)
        while((Get-Service $service).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline) {Start-Sleep -Milliseconds 50}
        if((Get-Service $service).Status -ne 'Stopped') {throw 'Public SDK service did not stop'}
        if((Read-ServicePolicy|ConvertTo-Json -Depth 16 -Compress) -cne
            ($receipt.service_policy|ConvertTo-Json -Depth 16 -Compress)) {throw 'Service policy changed across SDK request'}
        $record.status='completed'
        return $result
    } finally {
        Close-StandardPublisherClient $process $launch $attempted
    }
}
