# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param([Parameter(Mandatory=$true)][string]$ConfigPath)

$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'owned-effect-child.ps1')
$effectPair=$null
$held=$null
$config=Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop|ConvertFrom-Json

function New-OriginalScmTermination($pair) {
    return @{confirmed=$true;terminated=1;kill_invoked=$true;method='TerminateProcess_owned_held_root';
        process_id=$pair.parent_process_id;process_creation_file_time=$pair.parent_process_birth;native_wait_result=$pair.parent_native_wait_result}
}
function Confirm-OriginalPairClosure($record) {
    $pair=$record.native_process_pair
    if(-not $pair -or $pair.parent_native_wait_result -ne 0 -or $pair.child_native_wait_result -ne 0 -or
        -not $pair.child_observer_close_confirmed -or $pair.child_termination_invoked -or
        $pair.parent_process_id -ne $record.service_pid -or
        $pair.parent_process_birth -cne $record.process_creation_file_time -or
        $pair.effect_process_id -ne $record.effect_holder.process_id -or
        $pair.effect_process_birth -cne $record.effect_holder.process_creation_time){throw 'Original native pair closure differs'}
    $census=@(Get-CimInstance Win32_Process -ErrorAction Stop)
    if($census.Count -gt 4096){throw 'Owned post-termination process census exceeds its bound'}
    $descendants=@($census|Where-Object {
        $_.ParentProcessId -in @($pair.parent_process_id,$pair.effect_process_id) -and
        (-not $_.CreationDate -or $_.CreationDate.ToUniversalTime().Ticks -ge [long]$config.process_creation_ticks)
    })
    if($descendants.Count){throw 'Original SCM/effect pair has unresolved descendants; retain lab material'}
    $record['original_pair_closure_confirmed']=$true
}
$result=[ordered]@{schema='usk.publisher.production_rename_observer.v2';status='not_run';
    identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
    service_name=$config.service_name;service_pid=$config.process_id;
    service_binary_sha256=$null;service_executable=$config.process_executable;volume_guid_root=$config.volume_guid_root;
    phase=$config.phase;boundary_seen_utc=$null;journal_before_kill=$null;
    journal_after_kill=$null;visible_after_kill=$null;
    prepared_exclusive_observed=$false;prepared_record_sha256=$null;
    termination=$null;failure=$null}
try {
    if($config.schema -cne 'usk.publisher.production_rename_observer_config.v2' -or
        $config.phase -cnotin @('bootstrap','bootstrap_preserved','prepublish','postrename','maintenance_published') -or
        $result.identity -cne 'S-1-5-18' -or
        $config.service_name -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or
        $config.service_binary_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $config.process_id -le 0 -or
        $config.drive_letter -cnotmatch '^[A-Z]$' -or
        $config.visible_path -cne ($config.drive_letter+':\publication\destination\visible') -or
        $config.journal_path -cne $(if($config.phase -ceq 'maintenance_published') {
            if($config.maintenance_transaction_id -cnotmatch '^maintenance\.repair\.[0-9a-f]{32}$' -or
                $config.maintenance_plan_digest -cnotmatch '^[0-9a-f]{64}$' -or
                $config.process_creation_file_time -cnotmatch '^[0-9a-f]{16}$'){throw 'Maintenance boundary binding differs'}
            $config.drive_letter+':\setup-state\state\transactions\'+$config.maintenance_transaction_id+
                '.native-maintenance-custody\00000000000000000000.json'
        } else {$config.drive_letter+':\publication\journal\lab-'+
            $(if($config.phase -cin @('bootstrap','bootstrap_preserved','prepublish')){'prepared'}else{'visible'})+'-evidence.json'}) -or
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
    $result['process_creation_file_time']=$held.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16')
    if($config.phase -ceq 'maintenance_published' -and
        $result.process_creation_file_time -cne $config.process_creation_file_time) {
        throw 'Maintenance observer current worker birth differs'
    }
    $publication=$config.drive_letter+':\publication'
    $candidate=$publication+'\staging\candidate'
    if($config.phase -cin @('bootstrap','bootstrap_preserved')) {
        if($config.phase -ceq 'bootstrap' -and (Test-Path -LiteralPath $publication)){
            throw 'Bootstrap observer did not precede publication creation'
        }
        $result['process_creation_file_time']=$held.StartTime.ToUniversalTime().ToFileTimeUtc().ToString('x16')
        $result['publication_before_kill']=$false;$result['publication_after_kill']=$false
        $result['candidate_before_kill']=$false;$result['candidate_after_kill']=$false
    }
    if($config.phase -ceq 'bootstrap_preserved') {
        if($config.bootstrap_operation_prefix -cnotmatch ('^'+[regex]::Escape($config.drive_letter+':\')+
            'installation-operations\\install-[0-9a-f]{64}\\operation-[0-9a-f]{64}$')) {
            throw 'Preservation observer prefix escaped the owned volume'
        }
        $retained=$config.bootstrap_operation_prefix+'-retained-g00000000000000000001'
        $preservation=$config.bootstrap_operation_prefix+'-preserve-g00000000000000000001.json'
        $replacement=$config.bootstrap_operation_prefix+'-bootstrap-g00000000000000000002.json'
        if(-not (Test-Path -LiteralPath $publication) -or (Test-Path -LiteralPath $retained) -or
            (Test-Path -LiteralPath $preservation) -or (Test-Path -LiteralPath $replacement) -or
            -not (Test-Path -LiteralPath ($config.bootstrap_operation_prefix+'-bootstrap-g00000000000000000001.json'))) {
            throw 'Preservation observer did not precede the original root disposition'
        }
        foreach($name in @('retained','preservation','replacement_reservation')) {
            $result[$name+'_before_kill']=$false;$result[$name+'_after_kill']=$false
        }
        $result['bootstrap_operation_prefix']=$config.bootstrap_operation_prefix
        $fastBoundary=$null
    }
    [IO.File]::WriteAllText($config.ready_path,
        "usk.publisher.production_rename_observer_ready.v1`n",[Text.UTF8Encoding]::new($false))
    $deadline=[DateTime]::UtcNow.AddSeconds(120)
    while([DateTime]::UtcNow -lt $deadline) {
        if($held.HasExited){throw 'Production service exited before visible rename'}
        if(-not $effectPair) {
            $children=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId='+$config.process_id) -ErrorAction Stop)
            if($children.Count -gt 1){throw 'Owned SCM has an ambiguous native effect-child population'}
            if(-not $children.Count){Start-Sleep -Milliseconds 1;continue}
            $child=$children[0]
            if(-not $child.CreationDate -or $child.ExecutablePath -cne $config.process_executable -or
                -not $child.CommandLine -or $child.ProcessId -le 0 -or $child.ProcessId -eq $held.Id) {
                throw 'Owned effect-child candidate image/command/birth differs'
            }
            $effectPair=[UskOwnedEffectChildObserver]::new($held,[uint32]$config.process_id,
                $held.StartTime.ToUniversalTime().ToFileTimeUtc(),[uint32]$child.ProcessId,
                $child.CreationDate.ToUniversalTime().Ticks,$config.process_executable,$child.CommandLine)
            $result['effect_holder']=@{process_id=[int]$effectPair.ChildProcessId;
                process_creation_time=$effectPair.ChildProcessBirth}
            if($config.phase -ceq 'bootstrap_preserved') {
                $fastBoundary=[UskOwnedPreservationBoundary]::new($held,$effectPair,[uint32]$config.process_id,
                    $held.StartTime.ToUniversalTime().ToFileTimeUtc(),$publication,$config.bootstrap_operation_prefix)
            }
        }
        $effectPair.RequireOriginalLivePair()
        if($config.phase -ceq 'maintenance_published') {
            if(-not (Test-Path -LiteralPath $config.journal_path)){Start-Sleep -Milliseconds 1;continue}
            if(((Get-Item -LiteralPath $config.journal_path).Attributes -band
                ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -ne 0) {
                throw 'Maintenance confirmation is not an ordinary owned record'
            }
            $sealed=$null
            try {
                # Deny writers: presence alone cannot select the kill boundary.
                $sealed=[IO.FileStream]::new($config.journal_path,[IO.FileMode]::Open,
                    [IO.FileAccess]::Read,[IO.FileShare]::Read)
            } catch [IO.IOException] {
                $errorCode=$_.Exception.HResult -band 0xffff
                if($errorCode -cin @(32,33)){Start-Sleep -Milliseconds 1;continue}
                throw
            }
            try {
                if($sealed.Length -le 0 -or $sealed.Length -gt 1MB){throw 'Maintenance confirmation exceeds its bound'}
                $reader=[IO.StreamReader]::new($sealed,[Text.UTF8Encoding]::new($false,$true),$false,4096,$true)
                try {$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
                $record=$text|ConvertFrom-Json
                $writer=$record.writer_lease_ownership
                if($record.schema -cne 'usk.publisher.maintenance_native_custody.v2' -or
                    $record.transaction_id -cne $config.maintenance_transaction_id -or
                    $record.plan_digest -cne $config.maintenance_plan_digest -or
                    $writer.schema -cne 'usk.installation_lease_ownership.v1' -or
                    $writer.status -cne 'active' -or $writer.operation -cne 'repair' -or
                    $writer.operation_id -cne $config.maintenance_transaction_id -or
                    $record.original_context_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                    $writer.operation_context_sha256 -cne $record.original_context_sha256 -or
                    $writer.holder.process_id -ne $effectPair.ChildProcessId -or
                    $writer.holder.process_creation_time -cne $effectPair.ChildProcessBirth -or
                    $record.sequence -ne 0 -or $record.kind -cne 'confirmed_publication' -or
                    $record.details.publication_transaction_snapshot_sha256 -cne $record.transaction_snapshot_sha256) {
                    throw 'Maintenance confirmation is outside the exact original publication'
                }
                $result.boundary_seen_utc=[DateTime]::UtcNow.ToString('o')
                $result.journal_before_kill=$true
                $result.native_process_pair=$effectPair.TerminateOriginalScmOwner()
                $result.termination=New-OriginalScmTermination $result.native_process_pair
                $result.journal_after_kill=Test-Path -LiteralPath $config.journal_path
                $result['maintenance_transaction_id']=$record.transaction_id
                $result['maintenance_plan_digest']=$record.plan_digest
                $result['maintenance_writer_lease_ownership']=$writer
                $result['maintenance_confirmation_sha256']=(Get-FileHash -LiteralPath $config.journal_path -Algorithm SHA256).Hash.ToLowerInvariant()
                $result.status='terminated_confirmed_maintenance_publication'
            } finally {$sealed.Dispose()}
            if((Get-Volume -DriveLetter $config.drive_letter -ErrorAction Stop).UniqueId -cne $config.volume_guid_root) {
                throw 'Maintenance observer volume changed during termination'
            }
            break
        }
        if($config.phase -ceq 'bootstrap_preserved') {
            $native=$fastBoundary.ObserveAndTerminate()
            foreach($key in $native.Keys){$result[$key]=$native[$key]}
            if($result.status -cne 'terminated_publication_preserved'){break}
            Confirm-OriginalPairClosure $result
            if((Get-Volume -DriveLetter $config.drive_letter -ErrorAction Stop).UniqueId -cne $config.volume_guid_root) {
                throw 'Preservation observer volume changed during termination'
            }
            break
        }
        if($config.phase -ceq 'bootstrap') {
            if(-not (Test-Path -LiteralPath $publication)){Start-Sleep -Milliseconds 1;continue}
            $result.boundary_seen_utc=[DateTime]::UtcNow.ToString('o')
            $result.publication_before_kill=$true
            $result.candidate_before_kill=Test-Path -LiteralPath $candidate
            $result.journal_before_kill=Test-Path -LiteralPath $config.journal_path
            if($result.candidate_before_kill -or $result.journal_before_kill) {
                $result.status='window_missed_bootstrap_already_passed';break
            }
            $result.native_process_pair=$effectPair.TerminateOriginalScmOwner()
                $result.termination=New-OriginalScmTermination $result.native_process_pair
            $result.publication_after_kill=Test-Path -LiteralPath $publication
            $result.candidate_after_kill=Test-Path -LiteralPath $candidate
            $result.journal_after_kill=Test-Path -LiteralPath $config.journal_path
            $result.visible_after_kill=Test-Path -LiteralPath $config.visible_path
            if((Get-Volume -DriveLetter $config.drive_letter -ErrorAction Stop).UniqueId -cne $config.volume_guid_root) {
                throw 'Bootstrap observer volume changed during termination'
            }
            $result.status=if($result.publication_after_kill -and -not $result.candidate_after_kill -and
                -not $result.journal_after_kill -and -not $result.visible_after_kill) {
                'terminated_publication_bootstrap'
            }else{'window_missed_bootstrap_raced_kill'}
            break
        }
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
            $result.native_process_pair=$effectPair.TerminateOriginalScmOwner()
                $result.termination=New-OriginalScmTermination $result.native_process_pair
            $result.journal_after_kill=Test-Path -LiteralPath $config.journal_path
            $result.visible_after_kill=Test-Path -LiteralPath $config.visible_path
            if($config.phase -ceq 'prepublish' -and $result.journal_after_kill) {
                $record=[IO.File]::ReadAllText($config.journal_path,
                    [Text.UTF8Encoding]::new($false,$true))
                $parsed=$record|ConvertFrom-Json
                if($parsed.schema -cnotin @('usk.publisher.lab_phase_evidence.v2','usk.publisher.lab_phase_evidence.v3','usk.publisher.lab_phase_evidence.v4','usk.publisher.lab_phase_evidence.v5','usk.publisher.lab_phase_evidence.v6','usk.publisher.lab_phase_evidence.v7','usk.publisher.lab_phase_evidence.v8','usk.publisher.lab_phase_evidence.v9','usk.publisher.lab_phase_evidence.v10') -or
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
    if($result.native_process_pair){Confirm-OriginalPairClosure $result}
} catch {
    $result.status='failed'
    $result.failure=$_.Exception.Message
} finally {
    try {if($effectPair){$effectPair.Dispose()}} catch {
        $result.status='failed';$result.failure='Original child observer close unconfirmed: '+$_.Exception.Message
    }
    if($held){$held.Dispose()}
    $result.observed_utc=[DateTime]::UtcNow.ToString('o')
    $outputTemp=$config.output_path+'.tmp'
    [IO.File]::WriteAllText($outputTemp,
        ($result|ConvertTo-Json -Depth 8 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($outputTemp,$config.output_path)
}
if($result.status -cnotin @('terminated_confirmed_maintenance_publication','terminated_publication_bootstrap','terminated_publication_preserved','terminated_prepared_prerename',
    'terminated_postrename_prejournal')){exit 1}
