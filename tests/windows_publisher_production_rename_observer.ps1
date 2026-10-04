# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param([Parameter(Mandatory=$true)][string]$ConfigPath)

$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'owned-process.ps1')
$config=Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop|ConvertFrom-Json
$result=[ordered]@{schema='usk.publisher.production_rename_observer.v1';status='not_run';
    identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    service_name=$config.service_name;service_pid=$config.process_id;
    service_binary_sha256=$null;volume_guid_root=$config.volume_guid_root;
    phase=$config.phase;boundary_seen_utc=$null;journal_before_kill=$null;
    journal_after_kill=$null;visible_after_kill=$null;
    prepared_exclusive_observed=$false;prepared_record_sha256=$null;
    termination=$null;failure=$null}
try {
    if($config.schema -cne 'usk.publisher.production_rename_observer_config.v1' -or
        $config.phase -cnotin @('prepublish','postrename') -or
        $result.identity -cne 'S-1-5-18' -or
        $config.service_name -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or
        $config.service_binary_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $config.process_id -le 0 -or
        $config.drive_letter -cnotmatch '^[A-Z]$' -or
        $config.visible_path -cne ($config.drive_letter+':\publication\destination\visible') -or
        $config.journal_path -cne ($config.drive_letter+':\publication\journal\lab-'+
            $(if($config.phase -ceq 'prepublish'){'prepared'}else{'visible'})+'-evidence.json') -or
        $config.volume_guid_root -cnotmatch '^\\\\\?\\Volume\{[0-9a-f-]{36}\}\\$' -or
        (Split-Path -Parent $config.ready_path) -cne $PSScriptRoot -or
        (Split-Path -Parent $config.output_path) -cne $PSScriptRoot -or
        (Test-Path -LiteralPath $config.ready_path) -or
        (Test-Path -LiteralPath $config.output_path)) {
        throw 'Production rename observer configuration or identity differs'
    }
    $volume=Get-Volume -DriveLetter $config.drive_letter -ErrorAction Stop
    if($volume.UniqueId -cne $config.volume_guid_root -or $volume.FileSystem -cne 'NTFS') {
        throw 'Production rename observer volume differs'
    }
    $service=Get-CimInstance Win32_Service -Filter ("Name='"+$config.service_name+"'") -ErrorAction Stop
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$config.process_id) -ErrorAction Stop
    if(-not $service -or $service.State -cne 'Running' -or
        $service.ProcessId -ne $config.process_id -or
        $service.PathName -cne $config.service_command -or
        -not $process -or $process.CommandLine -cne $config.process_command -or
        $process.ExecutablePath -cne $config.process_executable -or
        [math]::Abs(($process.CreationDate.ToUniversalTime().Ticks)-
            [long]$config.process_creation_ticks) -gt 10000) {
        throw 'Production rename observer service process differs'
    }
    $actualHash=(Get-FileHash -LiteralPath $process.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $result.service_binary_sha256=$actualHash
    if($actualHash -cne $config.service_binary_sha256 -or
        (Split-Path -Leaf $process.ExecutablePath) -cne ($config.service_name+'.exe')) {
        throw 'Production rename observer executable differs'
    }
    $held=Get-Process -Id $config.process_id -ErrorAction Stop
    if([math]::Abs(($held.StartTime.ToUniversalTime().Ticks)-
        [long]$config.process_creation_ticks) -gt 10000) {
        throw 'Production rename observer held process differs'
    }
    $owned=[Collections.Generic.List[object]]::new()
    $owned.Add($process)
    $held|Add-Member -NotePropertyName UskOwnedTree -NotePropertyValue $owned
    [IO.File]::WriteAllText($config.ready_path,
        "usk.publisher.production_rename_observer_ready.v1`n",[Text.UTF8Encoding]::new($false))
    $deadline=[DateTime]::UtcNow.AddSeconds(120)
    while([DateTime]::UtcNow -lt $deadline) {
        if($held.HasExited){throw 'Production service exited before visible rename'}
        $journalPresent=$false
        $visiblePresent=$false
        if($config.phase -ceq 'prepublish') {
            $journalPresent=Test-Path -LiteralPath $config.journal_path
            if($journalPresent){$visiblePresent=Test-Path -LiteralPath $config.visible_path}
        } else {
            $visiblePresent=Test-Path -LiteralPath $config.visible_path
            if($visiblePresent){$journalPresent=Test-Path -LiteralPath $config.journal_path}
        }
        if($config.phase -ceq 'prepublish' -and $journalPresent -and -not $visiblePresent) {
            # The create handle is shared, so mere directory visibility can
            # precede FlushFileBuffers. An exclusive read succeeds only after
            # the writer and its independent readback have closed their handles.
            $sealed=$null
            try {
                $sealed=[IO.FileStream]::new($config.journal_path,[IO.FileMode]::Open,
                    [IO.FileAccess]::Read,[IO.FileShare]::None)
            } catch [IO.IOException] { Start-Sleep -Milliseconds 1; continue }
            try {
                if($sealed.Length -le 0 -or $sealed.Length -gt 1MB) {
                    throw 'Prepared journal record exceeds observer bound'
                }
                $result.prepared_exclusive_observed=$true
            } finally {$sealed.Dispose()}
            $visiblePresent=Test-Path -LiteralPath $config.visible_path
        }
        if(($config.phase -ceq 'prepublish' -and $journalPresent) -or
            ($config.phase -ceq 'postrename' -and $visiblePresent)) {
            $result.boundary_seen_utc=[DateTime]::UtcNow.ToString('o')
            $result.journal_before_kill=$journalPresent
            if(($config.phase -ceq 'prepublish' -and $visiblePresent) -or
                ($config.phase -ceq 'postrename' -and $journalPresent)) {
                $result.status='window_missed_boundary_already_passed'
                break
            }
            # The held process handle is bound to the checked creation time.
            # Avoid CIM and volume queries inside the short rename window.
            $result.termination=Stop-OwnedPublisherProcessTree $held -RequireLiveKill
            $result.journal_after_kill=Test-Path -LiteralPath $config.journal_path
            $result.visible_after_kill=Test-Path -LiteralPath $config.visible_path
            if($config.phase -ceq 'prepublish' -and $result.journal_after_kill) {
                $record=[IO.File]::ReadAllText($config.journal_path,
                    [Text.UTF8Encoding]::new($false,$true))
                $parsed=$record|ConvertFrom-Json
                if($parsed.schema -cnotin @('usk.publisher.lab_phase_evidence.v2','usk.publisher.lab_phase_evidence.v3','usk.publisher.lab_phase_evidence.v4','usk.publisher.lab_phase_evidence.v5','usk.publisher.lab_phase_evidence.v6','usk.publisher.lab_phase_evidence.v7','usk.publisher.lab_phase_evidence.v8','usk.publisher.lab_phase_evidence.v9') -or
                    $parsed.phase -cne 'lab_prepared_evidence') {
                    throw 'Prepared journal phase differs from protected intent'
                }
                $result.prepared_record_sha256=[Convert]::ToHexString(
                    [Security.Cryptography.SHA256]::HashData(
                        [Text.Encoding]::UTF8.GetBytes($record))).ToLowerInvariant()
            }
            if((Get-Volume -DriveLetter $config.drive_letter -ErrorAction Stop).UniqueId -cne
                $config.volume_guid_root) {
                throw 'Production observer volume changed during termination'
            }
            $result.status=if($config.phase -ceq 'prepublish') {
                if($result.journal_after_kill -and -not $result.visible_after_kill) {
                    'terminated_prepared_prerename'
                }else{'window_missed_rename_raced_kill'}
            }elseif($result.journal_after_kill) {
                'window_missed_visible_journal_raced_kill'
            }else{'terminated_postrename_prejournal'}
            break
        }
        Start-Sleep -Milliseconds 1
    }
    if($result.status -eq 'not_run'){$result.status='window_missed_timeout'}
} catch {
    $result.status='failed'
    $result.failure=$_.Exception.Message
} finally {
    $result.observed_utc=[DateTime]::UtcNow.ToString('o')
    $outputTemp=$config.output_path+'.tmp'
    [IO.File]::WriteAllText($outputTemp,
        ($result|ConvertTo-Json -Depth 8 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($outputTemp,$config.output_path)
}
if($result.status -cnotin @('terminated_prepared_prerename',
    'terminated_postrename_prejournal')){exit 1}
