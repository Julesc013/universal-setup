param(
    [Parameter(Mandatory = $true)][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedUserSid,
    [Parameter(Mandatory = $true)][string]$ServiceSid,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateSet('Prepublish', 'Postpublish', 'Concurrent', 'ProductionConcurrent')][string]$Stage = 'Postpublish',
    [string]$ReleasePath = '',
    [ValidateSet('payload.bin', 'bin/core.bin', 'bin/core.exe')][string]$PayloadRelativePath = 'payload.bin'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
$root = $VolumeRoot.TrimEnd('\') + '\'
$receipt = [ordered]@{
    schema = 'usk.publisher.unprivileged_access_probe.v1'
    status = 'not_run'
    process_id = $PID
    user_sid = $identity.User.Value
    administrator = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    service_sid_present = @($identity.Groups | Where-Object {
        $_.Value -eq $ServiceSid
    }).Count -ne 0
    volume_root = $root
    stage = $Stage
    payload_relative_path = $PayloadRelativePath
    attempts = @()
    failure = $null
}

function Require-Denied {
    param([string]$Name, [scriptblock]$Action)
    try {
        & $Action
        $receipt.attempts += [ordered]@{ name = $Name; outcome = 'unexpected_success' }
        throw "unprivileged $Name unexpectedly succeeded"
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause.HResult -ne -2147024891) {
            $receipt.attempts += [ordered]@{
                name = $Name
                outcome = 'other_failure'
                hresult = $cause.HResult
                type = $cause.GetType().FullName
            }
            throw
        }
        $receipt.attempts += [ordered]@{
            name = $Name
            outcome = 'access_denied'
            hresult = $cause.HResult
        }
    }
}

function Observe-ConcurrentDenial {
    param([string]$Name, [scriptblock]$Action, [bool]$AllowMissing,
        [bool]$AfterCompletion, [bool]$AfterRelease)
    try {
        & $Action
        throw "concurrent $Name unexpectedly obtained mutation access"
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause.HResult -eq -2147024891) {
            $receipt.concurrent[$Name].denied++
            if ($AfterCompletion) { $receipt.concurrent[$Name].denied_after_completion++ }
            if ($AfterRelease -and -not $AfterCompletion) {
                if ($Stage -eq 'ProductionConcurrent') {
                    $receipt.concurrent[$Name].denied_after_start_before_observed_reply++
                } else {
                    $receipt.concurrent[$Name].denied_after_gate_before_observed_reply++
                }
            }
        } elseif ($AllowMissing -and $cause.HResult -in @(-2147024894, -2147024893)) {
            $receipt.concurrent[$Name].missing++
        } else { throw }
    }
}

try {
    if ($root -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$' -or
        $identity.User.Value -ne $ExpectedUserSid -or
        $receipt.administrator -or $receipt.service_sid_present -or
        $identity.User.Value -eq 'S-1-5-18') {
        throw 'unprivileged process or disposable volume identity mismatch'
    }
    $destination = $root + 'publication\destination'
    $payloadPath = $PayloadRelativePath.Replace('/', '\')
    if ($Stage -in @('Concurrent', 'ProductionConcurrent')) {
        $output = [IO.Path]::GetFullPath($OutputPath)
        $folder = [IO.Path]::GetDirectoryName($output)
        $releaseMarker = [IO.Path]::GetFullPath($ReleasePath)
        if ($env:GITHUB_ACTIONS -ne 'true' -or
            $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
            [IO.Path]::GetFileName($output) -cne 'concurrent-attack.json' -or
            [IO.Path]::GetFileName($folder) -cne 'consumer-output' -or
            [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($folder)) -cne 'C:\USK-Lab' -or
            [IO.Path]::GetDirectoryName($releaseMarker) -cne 'C:\USK-Lab' -or
            -not [IO.Path]::GetFileName($releaseMarker).EndsWith(
                $(if ($Stage -eq 'ProductionConcurrent') {'-production-start.txt'}
                  else {'-prepublish-release.txt'}), [StringComparison]::Ordinal)) {
            throw 'concurrent attacker requires the owned hosted consumer output'
        }
        $ready = Join-Path $folder 'concurrent-ready.txt'
        $completed = Join-Path $folder 'concurrent-completed.txt'
        if ((Test-Path -LiteralPath $ready) -or
            (Test-Path -LiteralPath $completed) -or
            (Test-Path -LiteralPath $output)) {
            throw 'concurrent attacker markers are not fresh'
        }
        $candidate = $root + 'publication\staging\candidate'
        $stagedFile = $candidate + '\' + $payloadPath
        $visibleFile = $destination + '\visible\' + $payloadPath
        $receipt['concurrent'] = [ordered]@{
            destination_create = [ordered]@{ denied = 0; missing = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0 }
            staged_write = [ordered]@{ denied = 0; missing = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0 }
            visible_write = [ordered]@{ denied = 0; missing = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0 }
            cycles = 0; cycles_after_gate_before_observed_reply = 0; cycles_after_start_before_observed_reply = 0; cycles_after_completion = 0; max_cycle_gap_ms = 0
            ready_utc = $null; release_seen_utc = $null; started_seen_utc = $null; completed_seen_utc = $null
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        $prior = [DateTime]::UtcNow
        while ([DateTime]::UtcNow -lt $deadline) {
            $now = [DateTime]::UtcNow
            $gap = ($now - $prior).TotalMilliseconds
            if ($gap -gt $receipt.concurrent.max_cycle_gap_ms) {
                $receipt.concurrent.max_cycle_gap_ms = [math]::Round($gap, 3)
            }
            $prior = $now
            $afterCompletion = Test-Path -LiteralPath $completed
            $afterRelease = Test-Path -LiteralPath $releaseMarker
            if ($afterRelease -and $Stage -eq 'ProductionConcurrent' -and
                -not $receipt.concurrent.started_seen_utc) {
                $receipt.concurrent.started_seen_utc = $now.ToString('o')
            }
            if ($afterRelease -and $Stage -eq 'Concurrent' -and
                -not $receipt.concurrent.release_seen_utc) {
                $receipt.concurrent.release_seen_utc = $now.ToString('o')
            }
            if ($afterCompletion -and -not $receipt.concurrent.completed_seen_utc) {
                $receipt.concurrent.completed_seen_utc = $now.ToString('o')
            }
            Observe-ConcurrentDenial 'destination_create' {
                [IO.Directory]::CreateDirectory($destination + '\hostile-child') | Out-Null
            } ($Stage -eq 'ProductionConcurrent') $afterCompletion $afterRelease
            Observe-ConcurrentDenial 'staged_write' {
                $handle = [IO.File]::Open($stagedFile, [IO.FileMode]::Open,
                    [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                $handle.Dispose()
            } $true $afterCompletion $afterRelease
            Observe-ConcurrentDenial 'visible_write' {
                $handle = [IO.File]::Open($visibleFile, [IO.FileMode]::Open,
                    [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                $handle.Dispose()
            } $true $afterCompletion $afterRelease
            $receipt.concurrent.cycles++
            if ($afterRelease -and -not $afterCompletion) {
                if ($Stage -eq 'ProductionConcurrent') {
                    $receipt.concurrent.cycles_after_start_before_observed_reply++
                } else {
                    $receipt.concurrent.cycles_after_gate_before_observed_reply++
                }
            }
            if ($afterCompletion) { $receipt.concurrent.cycles_after_completion++ }
            if (-not $receipt.concurrent.ready_utc -and
                ($Stage -eq 'ProductionConcurrent' -or
                 $receipt.concurrent.staged_write.denied -gt 0)) {
                $readyTemp = $ready + '.tmp'
                $readyBytes = [Text.Encoding]::ASCII.GetBytes("usk.publisher.concurrent_ready.v1`n")
                $stream = [IO.FileStream]::new($readyTemp, [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write, [IO.FileShare]::Read)
                try { $stream.Write($readyBytes, 0, $readyBytes.Length); $stream.Flush($true) }
                finally { $stream.Dispose() }
                [IO.File]::Move($readyTemp, $ready)
                $receipt.concurrent.ready_utc = [DateTime]::UtcNow.ToString('o')
            }
            if ($receipt.concurrent.cycles_after_completion -ge 3) { break }
            Start-Sleep -Milliseconds 1
        }
        if ($Stage -eq 'ProductionConcurrent') {
            if (-not $receipt.concurrent.ready_utc -or
                $receipt.concurrent.destination_create.denied -lt 4 -or
                $receipt.concurrent.destination_create.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.cycles_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.visible_write.denied_after_completion -lt 3 -or
                $receipt.concurrent.cycles_after_completion -lt 3) {
                throw 'production attacker did not cover request-to-reply and completed visibility'
            }
        } elseif (-not $receipt.concurrent.ready_utc -or
            $receipt.concurrent.destination_create.denied -lt 4 -or
            $receipt.concurrent.destination_create.denied_after_gate_before_observed_reply -lt 1 -or
            $receipt.concurrent.cycles_after_gate_before_observed_reply -lt 1 -or
            $receipt.concurrent.staged_write.denied -lt 1 -or
            $receipt.concurrent.visible_write.denied_after_completion -lt 3 -or
            $receipt.concurrent.cycles_after_completion -lt 3) {
            throw 'concurrent attacker did not cover prepublish, gate-to-reply, and completed visibility'
        }
    } elseif ($Stage -eq 'Prepublish') {
        $candidate = $root + 'publication\staging\candidate'
        $file = $candidate + '\' + $payloadPath
        Require-Denied 'staged_read' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'staged_write' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'staged_insert' {
            [IO.Directory]::CreateDirectory($candidate + '\hostile-child') | Out-Null
        }
        Require-Denied 'destination_precreate' {
            [IO.Directory]::CreateDirectory($destination + '\visible') | Out-Null
        }
    } else {
        $file = $destination + '\visible\' + $payloadPath
        Require-Denied 'visible_read' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'visible_write' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'destination_create' {
            [IO.Directory]::CreateDirectory($destination + '\hostile-child') | Out-Null
        }
        Require-Denied 'visible_delete' {
            [IO.File]::Delete($file)
        }
    }
    $receipt.status = 'access_denied_observed'
} catch {
    $receipt.status = 'failed'
    $receipt.failure = $_.Exception.Message
} finally {
    $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
if ($receipt.status -ne 'access_denied_observed') { exit 1 }
