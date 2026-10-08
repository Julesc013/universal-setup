# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
#Requires -Version 7.0
param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$ServiceBinary,
    [Parameter(Mandatory=$true)][string]$ServiceControlBinary,
    [Parameter(Mandatory=$true)][string]$MachineBinary,
    [switch]$FreshQualification
)

$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'Thread creation tracing requires the existing administrative GitHub-hosted disposable lab'
}
$runnerTemp=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
$out=[IO.Path]::GetFullPath($OutputPath)
if((Split-Path -Parent $out) -cne $runnerTemp -or (Test-Path -LiteralPath $out)) {
    throw 'Thread trace requires a fresh original probe receipt inside runner temporary storage'
}
$journey=if($FreshQualification){'fresh'}else{'ended_recovery'}
$traceDirectory=if($FreshQualification){'usk-wu007-maintenance-fresh-trace'}else{'usk-wu007-maintenance-thread-trace'}
$traceRoot=Join-Path $runnerTemp $traceDirectory
if(Test-Path -LiteralPath $traceRoot) {throw 'Preserve the existing diagnostic trace directory'}
New-Item -ItemType Directory -Path $traceRoot -ErrorAction Stop | Out-Null
# Upload only bounded validated files, never the unchecked raw stop output.
$retainedRoot=Join-Path $traceRoot 'retained'
New-Item -ItemType Directory -Path $retainedRoot -ErrorAction Stop | Out-Null
$instance='USKMaintenanceCreator'+[Guid]::NewGuid().ToString('N')
$etl=Join-Path $traceRoot 'maintenance-thread-creator.etl'
$profileFile=if($FreshQualification){'windows_publisher_maintenance_fresh_cpu_trace.wprp'}else{'windows_publisher_maintenance_thread_trace.wprp'}
$profileName=if($FreshQualification){'USKFreshCPU'}else{'USKThreadCreator'}
$captureKind=if($FreshQualification){'cpu_stacks_scheduler_events_and_thread_creation'}else{'cpu_scheduler_and_thread_creation'}
$captureStacks=if($FreshQualification){@('ThreadCreate','SampledProfile')}else{@('ThreadCreate','SampledProfile','CSwitch','ReadyThread')}
$interpretation=if($FreshQualification){'Circular coverage remains unproved; join actual request/PID/birth/TID/module/ancestry and retained interval before interpreting CPU/thread stacks or scheduler events. Scheduler/wakeup stacks are omitted; this capture cannot attribute wait call stacks or establish a call cycle or thread creator'}else{'Circular coverage remains unproved; join actual request/PID/birth/TID/module/ancestry and retained interval before interpreting CPU or wait stacks. Wait stacks alone do not establish a call cycle or thread creator'}
$profile=Join-Path $PSScriptRoot $profileFile
# Pin the OS tool: hosted PATH can contain both System32 and WPT installations.
$wpr=[IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\wpr.exe'))
if(-not (Test-Path -LiteralPath $wpr -PathType Leaf)) {throw 'The pinned Windows WPR executable is absent'}
$sourceCommit=& git -C $env:GITHUB_WORKSPACE rev-parse HEAD
if($LASTEXITCODE -ne 0){throw 'Thread trace source commit is unavailable'}
$sourceTree=& git -C $env:GITHUB_WORKSPACE rev-parse 'HEAD^{tree}'
if($LASTEXITCODE -ne 0){throw 'Thread trace source tree is unavailable'}
$event=Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw|ConvertFrom-Json
$receipt=[ordered]@{
    schema='usk.publisher_maintenance_thread_trace.v1';scope='external_owned_diagnostic_no_authority';
    profile_qualified=$false;creator_attribution_proven=$false;status='running';
    journey=$journey;capture_kind=$captureKind;
    captured_keywords=@('ProcessThread','Loader','SampledProfile','CSwitch','ReadyThread');
    captured_stacks=$captureStacks;profile_file=$profileFile;profile_name=$profileName;
    scheduler_stacks_requested=(-not $FreshQualification);
    maximum_retained_etl_bytes=134217728;maximum_command_log_characters=32768;
    original_request_identity_source='Original probe receipt; join native process birth and ancestry with raw ETL';
    capture_start_precedes_probe=$false;capture_end_follows_probe=$false;
    instance_name=$instance;identity=$identity.Name;windows_build=[Environment]::OSVersion.Version.ToString();
    created_utc=[DateTime]::UtcNow.ToString('o');configured_buffer_bytes=67108864;
    logging_mode='Memory';profile_sha256=(Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant();
    wpr_path=$wpr;wpr_sha256=(Get-FileHash -LiteralPath $wpr -Algorithm SHA256).Hash.ToLowerInvariant();
    ci_run_id=$env:GITHUB_RUN_ID;ci_run_attempt=$env:GITHUB_RUN_ATTEMPT;
    source_commit=[string]$sourceCommit;source_tree=[string]$sourceTree;pull_request_head=[string]$event.pull_request.head.sha;
    trace_start_issued=$false;trace_started=$false;trace_stop_issued=$false;trace_closed=$false;
    probe_invoked=$false;probe_passed=$false;probe_failure=$null;probe_receipt=$null;
    commands=[Collections.Generic.List[object]]::new();diagnostic_failures=[Collections.Generic.List[string]]::new();
    etl=$null;events_lost=$null;capture_completeness='not_established';product_symbols=$null;
    # Circular retention and event/header/payload joins must be checked against
    # actual PID/birth/TID/birth and owner checkpoints before interpreting stacks.
    interpretation=$interpretation
}
$probeFailure=$null
$ownedInstance=$false

function Invoke-OwnedWpr([string]$Label,[string[]]$CommandArgs) {
    $commandOutput=@(& $wpr @CommandArgs -instancename $instance 2>&1)
    $exit=$LASTEXITCODE
    $body=($commandOutput|ForEach-Object {[string]$_}) -join "`n"
    $truncated=$body.Length -gt 32768
    if($truncated){$body=$body.Substring(0,32768)}
    $log=Join-Path $retainedRoot ($Label+'.log')
    [IO.File]::WriteAllText($log,$body+"`n",[Text.UTF8Encoding]::new($false))
    $entry=[ordered]@{label=$Label;arguments=@($CommandArgs)+@('-instancename',$instance);
        exit_code=$exit;utc=[DateTime]::UtcNow.ToString('o');output_truncated=$truncated;
        log_name=[IO.Path]::GetFileName($log);log_sha256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant()}
    $receipt.commands.Add($entry)
    if($truncated){$receipt.diagnostic_failures.Add('WPR output was truncated: '+$Label)}
    [pscustomobject]@{exit_code=$exit;text=$body;truncated=$truncated}
}
function Test-RecordingAbsent($Observation) {
    $Observation.exit_code -eq 0 -and -not $Observation.truncated -and
        $Observation.text -match '(?m)^WPR is not recording\s*$'
}

function Copy-BoundedProductFile([string]$Source,[string]$Name,[long]$MaximumBytes) {
    $full=[IO.Path]::GetFullPath($Source)
    $file=Get-Item -LiteralPath $full -ErrorAction Stop
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Product symbol input is not a regular build file'
    }
    $inputStream=$null;$outputStream=$null;$hash=$null
    try {
        # Deny concurrent write/delete while hashing and copying the same bytes.
        $inputStream=[IO.FileStream]::new($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $length=$inputStream.Length
        if($length -le 0 -or $length -gt $MaximumBytes) {throw 'Product symbol input exceeds its separate retention bound'}
        $hash=[Security.Cryptography.SHA256]::Create()
        $sha=[BitConverter]::ToString($hash.ComputeHash($inputStream)).Replace('-','').ToLowerInvariant()
        $inputStream.Position=0
        $destination=Join-Path $retainedRoot $Name
        $outputStream=[IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $inputStream.CopyTo($outputStream,65536)
        if($outputStream.Length -ne $length -or $inputStream.Length -ne $length) {throw 'Product symbol copy length changed'}
        [ordered]@{name=$Name;bytes=$length;sha256=$sha;source_path=$full;maximum_bytes=$MaximumBytes}
    } finally {
        if($outputStream){$outputStream.Dispose()}
        if($inputStream){$inputStream.Dispose()}
        if($hash){$hash.Dispose()}
    }
}

try {
    $preflight=Invoke-OwnedWpr 'preflight-status' @('-status')
    if(-not (Test-RecordingAbsent $preflight)) {throw 'Fresh named WPR instance absence is unconfirmed'}
    # Ownership follows a fresh named-instance absence and our own start issue.
    # A partially successful start is stopped only through this exact instance.
    $ownedInstance=$true
    $receipt.trace_start_issued=$true
    $started=Invoke-OwnedWpr 'start' @('-start',($profile+'!'+$profileName+'.Verbose'))
    if($started.exit_code -ne 0 -or $started.truncated) {throw 'Owned memory thread creation trace did not start'}
    $receipt.trace_started=$true
    $receipt['started_utc']=[DateTime]::UtcNow.ToString('o')
    $active=Invoke-OwnedWpr 'active-profiles' @('-status','profiles')
    if($active.exit_code -ne 0 -or $active.truncated -or
        $active.text -notmatch ([regex]::Escape($profileName+'.Verbose.Memory'))) {
        throw 'Owned thread creation memory profile is not positively observed'
    }
    $receipt.probe_invoked=$true
    $receipt['probe_started_utc']=[DateTime]::UtcNow.ToString('o')
    $receipt.capture_start_precedes_probe=$true
    $probeArguments=@{OutputPath=$out;ServiceBinary=$ServiceBinary;ServiceControlBinary=$ServiceControlBinary;
        MachineBinary=$MachineBinary;PublicInstallation=$true;PublicStandardClient=$true}
    if($FreshQualification){$probeArguments.PublicStandardMaintenanceQualification=$true}
    else{$probeArguments.PublicStandardMaintenanceRecoveryQualification=$true}
    & (Join-Path $PSScriptRoot 'windows_publisher_lab_probe.ps1') @probeArguments
    $receipt.probe_passed=$true
} catch {
    $probeFailure=$_
    $receipt.probe_failure=([string]$_.Exception.Message).Substring(0,[Math]::Min(4096,([string]$_.Exception.Message).Length))
} finally {
    $receipt['probe_returned_utc']=[DateTime]::UtcNow.ToString('o')
    if($ownedInstance) {
        try {
            $status=Invoke-OwnedWpr 'before-stop-status' @('-status','collectors','-details')
            $loss=[regex]::Matches($status.text,'(?im)(?:Dropped event|Events Lost)\s*:\s*(\d+)')
            if($status.exit_code -ne 0 -or $status.truncated -or $loss.Count -eq 0) {
                $receipt.diagnostic_failures.Add('Trace event-loss observation is unavailable')
            } else {
                $receipt.events_lost=@($loss|ForEach-Object {[uint64]$_.Groups[1].Value})
                if(@($receipt.events_lost|Where-Object {$_ -ne 0}).Count) {
                    $receipt.diagnostic_failures.Add('Trace reports lost events; actual creation coverage remains incomplete')
                }
            }
        } catch {$receipt.diagnostic_failures.Add('Trace status failed: '+[string]$_.Exception.Message)}
        # Stop remains independent of status failure; no default/global cancel.
        try {
            $receipt.trace_stop_issued=$true
            $receipt['stop_issued_utc']=[DateTime]::UtcNow.ToString('o')
            $receipt.capture_end_follows_probe=$receipt.probe_invoked
            $stopped=Invoke-OwnedWpr 'stop' @('-stop',$etl)
            if($stopped.exit_code -ne 0 -or $stopped.truncated) {
                $receipt.diagnostic_failures.Add('Owned trace stop did not confirm success')
            }
            $closed=Invoke-OwnedWpr 'closed-status' @('-status')
            $receipt.trace_closed=($stopped.exit_code -eq 0 -and (Test-RecordingAbsent $closed))
            if(-not $receipt.trace_closed){$receipt.diagnostic_failures.Add('Owned trace closure is unconfirmed')}
        } catch {$receipt.diagnostic_failures.Add('Owned trace stop/closure failed: '+[string]$_.Exception.Message)}
    }
    try {
        if(Test-Path -LiteralPath $etl -PathType Leaf) {
            $file=Get-Item -LiteralPath $etl
            if($file.Length -le 0 -or $file.Length -gt 134217728 -or
                ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Trace output does not satisfy the bounded regular-file retention limit'
            }
            $receipt.etl=[ordered]@{name=$file.Name;bytes=$file.Length;
                sha256=(Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash.ToLowerInvariant()}
            Move-Item -LiteralPath $etl -Destination (Join-Path $retainedRoot $file.Name) -ErrorAction Stop
        } else {throw 'Owned raw ETL is absent'}
    } catch {$receipt.diagnostic_failures.Add('ETL readback failed: '+[string]$_.Exception.Message)}
    try {
        if(-not (Test-Path -LiteralPath $out -PathType Leaf)) {throw 'Original probe receipt is absent'}
        $file=Get-Item -LiteralPath $out
        if($file.Length -le 0 -or $file.Length -gt 16777216 -or
            ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Original probe receipt is not bounded regular data'}
        $original=Get-Content -LiteralPath $out -Raw|ConvertFrom-Json
        if($original.build_profile.source_commit -cne $receipt.source_commit -or
            $original.build_profile.source_tree -cne $receipt.source_tree -or
            $original.build_profile.pull_request_head -cne $receipt.pull_request_head -or
            $original.build_profile.ci_run_id -cne $receipt.ci_run_id -or
            $original.build_profile.ci_run_attempt -cne $receipt.ci_run_attempt) {
            throw 'Original probe source/run/attempt does not match the actual trace producer'
        }
        $receipt.probe_receipt=[ordered]@{name=$file.Name;bytes=$file.Length;
            sha256=(Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLowerInvariant();
            status=$original.status;build_profile=$original.build_profile}
    } catch {$receipt.diagnostic_failures.Add('Original probe receipt readback failed: '+[string]$_.Exception.Message)}
    if($FreshQualification) {
        try {
            if(-not $receipt.probe_receipt -or -not $receipt.trace_closed) {throw 'Closed trace and joined original probe receipt are required for product symbol retention'}
            $installedHash=[string]$original.service_observation.service_sha256
            if($installedHash -cnotmatch '^[0-9a-f]{64}$') {throw 'Actual installed service image hash is unavailable'}
            $image=Copy-BoundedProductFile $ServiceBinary 'usk_publisher_service.exe' 16777216
            if($image.sha256 -cne $installedHash) {throw 'Build service image differs from the actual installed image'}
            $symbols=Copy-BoundedProductFile ([IO.Path]::ChangeExtension([IO.Path]::GetFullPath($ServiceBinary),'.pdb')) 'usk_publisher_service.pdb' 67108864
            $product=[ordered]@{
                schema='usk.publisher_service_symbols.v1';scope='external_owned_diagnostic_no_authority';
                source_commit=$receipt.source_commit;source_tree=$receipt.source_tree;pull_request_head=$receipt.pull_request_head;
                ci_run_id=$receipt.ci_run_id;ci_run_attempt=$receipt.ci_run_attempt;build_profile=$original.build_profile;
                image=$image;pdb=$symbols;installed_image_sha256=$installedHash;installed_image_hash_equal=$true;
                symbol_identity='not_established_require_PE_CodeView_GUID_age_and_PDB_validation';
                runtime_qualification=$false;publication_authority=$false;
                interpretation='Optimized Release symbols retain inlining and ICF; hash equality joins image bytes only, not process birth, request ancestry, PDB identity or runtime authority'
            }
            $manifest=Join-Path $retainedRoot 'publisher-service-symbols.json'
            $manifestBytes=[Text.UTF8Encoding]::new($false).GetBytes(($product|ConvertTo-Json -Depth 32 -Compress)+"`n")
            if($manifestBytes.Length -gt 65536) {throw 'Product symbol manifest exceeds its separate retention bound'}
            $manifestStream=$null
            try {
                $manifestStream=[IO.FileStream]::new($manifest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                $manifestStream.Write($manifestBytes,0,$manifestBytes.Length)
            } finally {if($manifestStream){$manifestStream.Dispose()}}
            $receipt.product_symbols=[ordered]@{name='publisher-service-symbols.json';bytes=$manifestBytes.Length;
                sha256=(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant();
                installed_image_hash_equal=$true;symbol_identity=$product.symbol_identity}
        } catch {$receipt.diagnostic_failures.Add('Product image/symbol retention failed: '+[string]$_.Exception.Message)}
    }
    $receipt['completed_utc']=[DateTime]::UtcNow.ToString('o')
    $receipt.status=if($probeFailure){'probe_failed'}elseif($receipt.diagnostic_failures.Count){'diagnostic_failed'}else{'diagnostic_retained'}
    try {
        [IO.File]::WriteAllText((Join-Path $retainedRoot 'maintenance-thread-creator.json'),
            ($receipt|ConvertTo-Json -Depth 32 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    } catch {
        if($probeFailure){throw $probeFailure}
        throw
    }
}
if($probeFailure){throw $probeFailure}
if($receipt.diagnostic_failures.Count){throw ($receipt.diagnostic_failures -join '; ')}
Write-Output 'Owned maintenance CPU scheduler and thread diagnostic retained; coverage attribution and runtime qualification remain unproved'
