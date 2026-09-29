param(
    [Parameter(Mandatory = $true)][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedUserSid,
    [Parameter(Mandatory = $true)][string]$ServiceSid,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateSet('Prepublish', 'Postpublish', 'Concurrent', 'ProductionConcurrent')][string]$Stage = 'Postpublish',
    [string]$ReleasePath = '',
    [string]$SameVolumeSource = '',
    [ValidateSet('payload.bin', 'bin/core.bin', 'bin/core.exe', 'bin/addon.bin')][string]$PayloadRelativePath = 'payload.bin',
    [ValidateSet('visible', 'selected-app')][string]$VisibleLeaf = 'visible'
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
    visible_leaf = $VisibleLeaf
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
        $attemptStart=[Diagnostics.Stopwatch]::GetTimestamp()
        & $Action
        throw "concurrent $Name unexpectedly obtained mutation access"
    } catch {
        $attemptEnd=[Diagnostics.Stopwatch]::GetTimestamp()
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause.HResult -eq -2147024891) {
            $receipt.concurrent[$Name].denied++
            if ($AfterCompletion) { $receipt.concurrent[$Name].denied_after_completion++ }
            if ($AfterRelease -and -not $AfterCompletion) {
                if ($Stage -eq 'ProductionConcurrent') {
                    $receipt.concurrent[$Name].denied_after_start_before_observed_reply++
                    if ($Name -in @('destination_create','staged_write','staged_replace',
                            'staged_insert','staged_ads_write',
                            'publication_rename','publication_write_dac')) {
                        $samples=$receipt.concurrent[$Name].denied_attempts
                        $sample=[ordered]@{start_tick=$attemptStart;end_tick=$attemptEnd}
                        $limit=if($Name -in @('staged_write','staged_replace')){1024}else{256}
                        if($samples.Count -lt $limit){
                            $receipt.concurrent[$Name].denied_attempts += $sample
                        }else{
                            $samples[$receipt.concurrent[$Name].denied_attempt_count % $limit]=$sample
                        }
                        $receipt.concurrent[$Name].denied_attempt_count++
                    }
                } else {
                    $receipt.concurrent[$Name].denied_after_gate_before_observed_reply++
                }
            }
        } elseif ($AllowMissing -and $cause.HResult -in @(-2147024894, -2147024893)) {
            $receipt.concurrent[$Name].missing++
            if ($Stage -eq 'ProductionConcurrent' -and -not $AfterRelease) {
                $receipt.concurrent[$Name].missing_before_start++
            }
            if ($Stage -eq 'ProductionConcurrent' -and $AfterCompletion) {
                $receipt.concurrent[$Name].missing_after_completion++
            }
        } else { throw }
    }
}

function Throw-NativeMutationError {
    param([string]$Name, [int]$Code)
    switch($Code) {
        5 { throw [UnauthorizedAccessException]::new("$Name was denied by Windows") }
        2 { throw [IO.FileNotFoundException]::new("$Name source is absent") }
        3 { throw [IO.DirectoryNotFoundException]::new("$Name parent is absent") }
        default { throw "$Name failed with unexpected Win32 error $Code" }
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
        $visibleFile = $destination + '\' + $VisibleLeaf + '\' + $payloadPath
        if($Stage -eq 'ProductionConcurrent') {
            if($SameVolumeSource -cne $root+'attacker-scratch\replacement.bin' -or
                $VisibleLeaf -cne 'selected-app' -or
                $PayloadRelativePath -notin @('bin/core.bin','bin/addon.bin')) {
                throw 'production attacker source is not on the exact owned volume'
            }
            # The protected volume-root ACL deliberately prevents this caller
            # from reopening even its own scratch file. SYSTEM independently
            # checks the source bytes before and after the attempted rename.
            Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
public static class USKPublisherAncestorAttack {
    [DllImport("kernel32.dll", EntryPoint="MoveFileExW", CharSet=CharSet.Unicode,
        ExactSpelling=true, SetLastError=true)]
    public static extern bool MoveFileExW(string source, string destination, uint flags);
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode,
        ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
public static class USKPublisherRenameRace {
    const int Capacity = 262144;
    static readonly long[] Starts = new long[Capacity];
    static readonly long[] Ends = new long[Capacity];
    static Thread worker;
    static volatile bool stopping;
    static long attempts;
    static long missingBeforeProtectedRoot;
    static string failure;
    static string source;
    static string destination;
    [DllImport("kernel32.dll", EntryPoint="MoveFileExW", CharSet=CharSet.Unicode,
        ExactSpelling=true, SetLastError=true)]
    static extern bool MoveFileExW(string source, string destination, uint flags);
    public static void Start(string sourcePath, string destinationPath) {
        if (worker != null) throw new InvalidOperationException("rename race already started");
        source = sourcePath;
        destination = destinationPath;
        stopping = false;
        worker = new Thread(Loop);
        worker.IsBackground = true;
        worker.Start();
    }
    static void Loop() {
        try {
            while (!stopping) {
                long start = Stopwatch.GetTimestamp();
                bool succeeded = MoveFileExW(source, destination, 0);
                int error = Marshal.GetLastWin32Error();
                long end = Stopwatch.GetTimestamp();
                if (!succeeded && (error == 2 || error == 3) && attempts == 0) {
                    missingBeforeProtectedRoot++;
                    Thread.Sleep(1);
                    continue;
                }
                if (succeeded || error != 5) {
                    failure = succeeded ? "unexpected_success" : "unexpected_win32_" + error;
                    break;
                }
                long index = attempts % Capacity;
                Starts[index] = start;
                Ends[index] = end;
                attempts++;
            }
        } catch (Exception error) { failure = error.GetType().FullName; }
    }
    public static Dictionary<string, object> Stop(long nativeStart, long nativeEnd) {
        if (worker == null) throw new InvalidOperationException("rename race did not start");
        stopping = true;
        if (!worker.Join(5000)) throw new TimeoutException("rename race worker did not stop");
        long first = Math.Max(0, attempts - Capacity);
        long overlapCount = 0;
        long[] overlap = null;
        for (long i = first; i < attempts; ++i) {
            int slot = (int)(i % Capacity);
            if (nativeStart > 0 && Starts[slot] <= nativeEnd && Ends[slot] >= nativeStart) {
                overlapCount++;
                if (overlap == null) overlap = new long[] { Starts[slot], Ends[slot] };
            }
        }
        return new Dictionary<string, object> {
            { "operation", "publication_rename" },
            { "clock", "qpc" },
            { "clock_frequency", Stopwatch.Frequency },
            { "attempt_count", attempts },
            { "missing_before_protected_root", missingBeforeProtectedRoot },
            { "retained_first_tick", first < attempts ? Starts[first % Capacity] : 0 },
            { "retained_last_tick", attempts > first ? Ends[(attempts - 1) % Capacity] : 0 },
            { "overlap_count", overlapCount },
            { "overlap_attempt", overlap },
            { "failure", failure }
        };
    }
}
'@
        }
        $receipt['concurrent'] = [ordered]@{
            destination_create = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            staged_write = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            staged_replace = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            staged_insert = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            staged_ads_write = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            publication_rename = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            publication_write_dac = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0; denied_attempt_count = 0; denied_attempts = @() }
            visible_write = [ordered]@{ denied = 0; missing = 0; missing_before_start = 0; missing_after_completion = 0; denied_after_completion = 0; denied_after_gate_before_observed_reply = 0; denied_after_start_before_observed_reply = 0 }
            cycles = 0; cycles_after_gate_before_observed_reply = 0; cycles_after_start_before_observed_reply = 0; cycles_after_completion = 0; max_cycle_gap_ms = 0
            clock = 'qpc'; clock_frequency = [Diagnostics.Stopwatch]::Frequency
            ready_utc = $null; release_seen_utc = $null; started_seen_utc = $null; completed_seen_utc = $null
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(120)
        $prior = [DateTime]::UtcNow
        $renameRaceStarted = $false
        $renameRaceSummary = $null
        while ([DateTime]::UtcNow -lt $deadline) {
            $now = [DateTime]::UtcNow
            $gap = ($now - $prior).TotalMilliseconds
            if ($gap -gt $receipt.concurrent.max_cycle_gap_ms) {
                $receipt.concurrent.max_cycle_gap_ms = [math]::Round($gap, 3)
            }
            $prior = $now
            $afterCompletion = Test-Path -LiteralPath $completed
            $afterRelease = Test-Path -LiteralPath $releaseMarker
            if ($Stage -eq 'ProductionConcurrent' -and $afterRelease -and
                -not $afterCompletion -and -not $renameRaceStarted) {
                [USKPublisherRenameRace]::Start($root+'publication',
                    $root+'hostile-publication')
                $renameRaceStarted = $true
            }
            if ($Stage -eq 'ProductionConcurrent' -and $afterCompletion -and
                $renameRaceStarted -and -not $renameRaceSummary) {
                $completedLines=[IO.File]::ReadAllLines($completed)
                if($completedLines.Count -ne 2 -or
                    $completedLines[0] -cne 'usk.publisher.concurrent_completed.v2') {
                    throw 'production rename race target is malformed'
                }
                $renameTarget=$completedLines[1]|ConvertFrom-Json
                if($renameTarget.schema -cne 'usk.publisher.rename_race_target.v1' -or
                    $renameTarget.clock -cne 'qpc' -or
                    [long]$renameTarget.frequency -ne [Diagnostics.Stopwatch]::Frequency -or
                    [long]$renameTarget.start_tick -le 0 -or
                    [long]$renameTarget.end_tick -lt [long]$renameTarget.start_tick) {
                    throw 'production rename race target clock is invalid'
                }
                $renameRaceSummary=[USKPublisherRenameRace]::Stop(
                    [long]$renameTarget.start_tick,[long]$renameTarget.end_tick)
                $receipt.concurrent['native_rename_overlap']=$renameRaceSummary
            }
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
            if($Stage -eq 'ProductionConcurrent') {
                Observe-ConcurrentDenial 'staged_replace' {
                    [IO.File]::Move($SameVolumeSource,$stagedFile,$true)
                } $true $afterCompletion $afterRelease
                Observe-ConcurrentDenial 'staged_insert' {
                    [IO.Directory]::CreateDirectory($candidate+'\hostile-child') | Out-Null
                } $true $afterCompletion $afterRelease
                Observe-ConcurrentDenial 'staged_ads_write' {
                    $handle=[IO.File]::Open($stagedFile+':usk-hostile',
                        [IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    $handle.Dispose()
                } $true $afterCompletion $afterRelease
                Observe-ConcurrentDenial 'publication_rename' {
                    if([USKPublisherAncestorAttack]::MoveFileExW(
                            $root+'publication',$root+'hostile-publication',0)) {
                        throw 'publication root was renamed by the non-admin attacker'
                    }
                    $nativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Throw-NativeMutationError 'publication rename' $nativeError
                } $true $afterCompletion $afterRelease
                Observe-ConcurrentDenial 'publication_write_dac' {
                    $handle=[USKPublisherAncestorAttack]::CreateFileW(
                        $root+'publication',0x40000,7,[IntPtr]::Zero,3,
                        0x02200000,[IntPtr]::Zero)
                    if($handle -ne [IntPtr]::new(-1)) {
                        [USKPublisherAncestorAttack]::CloseHandle($handle)|Out-Null
                        throw 'publication WRITE_DAC was acquired by the non-admin attacker'
                    }
                    $nativeError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Throw-NativeMutationError 'publication WRITE_DAC' $nativeError
                } $true $afterCompletion $afterRelease
            }
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
                (($Stage -eq 'ProductionConcurrent') -or
                 ($Stage -ne 'ProductionConcurrent' -and
                  $receipt.concurrent.staged_write.denied -gt 0))) {
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
            if (-not $renameRaceStarted -or -not $renameRaceSummary -or
                $renameRaceSummary.failure -or $renameRaceSummary.attempt_count -lt 1 -or
                $renameRaceSummary.overlap_count -lt 1 -or
                -not $receipt.concurrent.ready_utc -or
                $receipt.concurrent.destination_create.denied -lt 4 -or
                $receipt.concurrent.destination_create.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.staged_write.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.staged_replace.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.staged_insert.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.staged_ads_write.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.publication_rename.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.publication_write_dac.denied_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.cycles_after_start_before_observed_reply -lt 1 -or
                $receipt.concurrent.visible_write.denied_after_completion -lt 3 -or
                $receipt.concurrent.cycles_after_completion -lt 3) {
                throw 'production attacker did not observe live staging and completed visibility'
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
    if ($renameRaceStarted -and -not $renameRaceSummary) {
        try { [USKPublisherRenameRace]::Stop(0,0)|Out-Null } catch {}
    }
    $receipt | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
if ($receipt.status -ne 'access_denied_observed') { exit 1 }
