# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

# Hosted observer for the held original SCM/effect-child pair. JSON selects a
# test window only; it supplies no native authority to the product.
function Get-PublisherInitialOperationPrefix([string]$DriveRoot,[string]$InstallId,[string]$TransactionId) {
    if($DriveRoot -cnotmatch '^[A-Z]:\\$' -or $InstallId -cnotmatch '^[A-Za-z0-9_.-]{1,128}$' -or
        $TransactionId -cnotmatch '^maintenance\.repair\.[0-9a-f]{32}$') {throw 'Initial operation namespace identity differs'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $hashes=@(foreach($value in @($InstallId,$TransactionId)) {
            $text=ConvertTo-Json -InputObject $value -Compress
            ([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false,$true).GetBytes($text)))).
                Replace('-','').ToLowerInvariant()
        })
    } finally {$sha.Dispose()}
    return $DriveRoot+'installation-operations\install-'+$hashes[0]+'\operation-'+$hashes[1]
}

function Invoke-OwnedInitialMaintenanceBoundary($Config,$EffectPair,$Result) {
    $tx=[string]$Config.maintenance_transaction_id
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        $Config.schema -cne 'usk.publisher.production_rename_observer_config.v2' -or
        $Config.observer_family -cne 'owned_effect_child_v1' -or
        $Config.phase -cne 'maintenance_initial' -or $tx -cnotmatch '^maintenance\.repair\.[0-9a-f]{32}$' -or
        $Config.maintenance_plan_digest -cnotmatch '^[0-9a-f]{64}$' -or
        $Config.drive_letter -cnotmatch '^[A-Z]$' -or
        $Config.journal_path -cne ($Config.drive_letter+':\setup-state\state\transactions\'+$tx+'.journal.json')) {
        throw 'Initial maintenance observer binding differs'
    }
    $originalPath=$Config.drive_letter+':\setup-state\state\transactions\'+$tx+'.native-maintenance-original.json'
    $stage=$Config.drive_letter+':\setup-state\staging\.usk-stage-'+$tx
    $target=$Config.drive_letter+':\publication\destination\.usk-repair-'+$tx
    if(-not (Test-Path -LiteralPath $Config.journal_path)){return $false}
    $contextPrefix=Get-PublisherInitialOperationPrefix ($Config.drive_letter+':\') $Config.maintenance_install_id $tx
    if($Config.maintenance_original_context_prefix -cne $contextPrefix){throw 'Initial original operation namespace differs'}
    $opened=[Collections.Generic.List[IDisposable]]::new()
    try {
        $documents=@{}
        $digests=@{}
        # Pin the initial snapshot first. Reading original context must not delay
        # acquisition of the actual window. Any concurrent stage creation fails.
        foreach($entry in @(@{key='initial';path=$Config.journal_path;bound=4MB},
                           @{key='original';path=$originalPath;bound=16MB},
                           @{key='context';path=($contextPrefix+'.json');bound=16MB},
                           @{key='roots';path=($contextPrefix+'-roots.json');bound=1MB})) {
            if(((Get-Item -LiteralPath $entry.path -ErrorAction Stop).Attributes -band
                ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) -ne 0) {
                throw 'Initial maintenance observer record is not an ordinary file'
            }
            try {
                # Deny writers/deletion throughout selection and native owner
                # termination. The observer is explicitly intrusive; effects
                # racing the checks must fail the case, never become a pass.
                $file=[IO.FileStream]::new($entry.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            } catch [IO.IOException] {
                if(($_.Exception.HResult -band 0xffff) -cin @(32,33)){return $false}
                throw
            }
            $opened.Add($file)
            if($file.Length -le 0 -or $file.Length -gt $entry.bound){throw 'Initial maintenance observer record exceeds its bound'}
            $sha=[Security.Cryptography.SHA256]::Create()
            try {$digests[$entry.key]=([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-','').ToLowerInvariant()}
            finally {$sha.Dispose()}
            $file.Position=0
            $reader=[IO.StreamReader]::new($file,[Text.UTF8Encoding]::new($false,$true),$false,4096,$true)
            try {$documents[$entry.key]=$reader.ReadToEnd()|ConvertFrom-Json}
            finally {$reader.Dispose()}
        }
        $original=$documents.original;$journal=$documents.initial
        $context=$documents.context;$roots=$documents.roots
        $snapshot=$context.reviewed_snapshot;$plan=$snapshot.reviewed_plan
        if($context.schema -cne 'usk.installation_operation_context.v2' -or $context.operation -cne 'repair' -or
            $context.operation_id -cne $tx -or $context.install_id -cne $Config.maintenance_install_id -or
            $context.context_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $roots.schema -cne 'usk.installation_operation_roots.v1' -or $roots.operation_id -cne $tx -or
            $roots.install_id -cne $context.install_id -or $roots.context_sha256 -cne $context.context_sha256 -or
            $roots.roots_sha256 -cne $original.original_context_sha256 -or
            $snapshot.schema -cne 'usk.publisher.maintenance_reviewed_snapshot.v2' -or
            $snapshot.operation -cne 'repair' -or $snapshot.operation_id -cne $tx -or
            $snapshot.install_id -cne $context.install_id -or
            $snapshot.apply_request.schema -cne 'usk.repair_apply_request.v1' -or
            $snapshot.apply_request.transaction_id -cne $tx -or
            $snapshot.apply_request.reviewed_plan_id -cne $Config.maintenance_plan_id -or
            $snapshot.apply_request.reviewed_plan_digest -cne $Config.maintenance_plan_digest -or
            $plan.plan_id -cne $Config.maintenance_plan_id -or
            [IO.Path]::GetFullPath([string]$plan.staging_parent) -cne ($Config.drive_letter+':\setup-state\staging') -or
            [IO.Path]::GetFullPath([string]$plan.state_root) -cne [string]$Config.maintenance_roots.setup_state -or
            [IO.Path]::GetFullPath([string]$plan.audit_root) -cne [string]$Config.maintenance_roots.audit -or
            [IO.Path]::GetFullPath([string]$snapshot.installed_state.target_root) -cne [string]$Config.visible_path) {
            throw 'Initial snapshot differs from its protected original context and root binding'
        }
        $writer=$original.original_lease_ownership
        if($original.schema -cne 'usk.publisher.maintenance_original_custody.v4' -or
            $original.transaction_id -cne $tx -or $original.operation -cne 'repair' -or
            $original.plan_digest -cne $Config.maintenance_plan_digest -or
            $original.original_context_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $writer.schema -cne 'usk.installation_lease_ownership.v1' -or $writer.status -cne 'active' -or
            $writer.operation -cne 'repair' -or $writer.operation_id -cne $tx -or
            $writer.operation_context_sha256 -cne $original.original_context_sha256 -or
            $writer.holder.process_id -ne $EffectPair.ChildProcessId -or
            $writer.holder.process_creation_time -cne $EffectPair.ChildProcessBirth -or
            $journal.schema -cne 'usk.transaction_journal.v1' -or $journal.operation -cne 'repair' -or
            $journal.transaction_id -cne $tx -or $journal.plan_id -cne $Config.maintenance_plan_id -or
            -not $Config.maintenance_plan_id -or $journal.plan_digest -cne $Config.maintenance_plan_digest) {
            throw 'Initial maintenance snapshot is outside the exact held original operation'
        }
        if(@($journal.roots).Count -ne 4){throw 'Initial maintenance snapshot root count differs'}
        foreach($role in @('target','staging','setup_state','audit')) {
            $rows=@($journal.roots|Where-Object role -ceq $role)
            $expected=[string]$Config.maintenance_roots.$role
            if($rows.Count -ne 1 -or -not [IO.Path]::IsPathFullyQualified($expected) -or
                [IO.Path]::GetFullPath([string]$rows[0].root) -cne [IO.Path]::GetFullPath($expected)) {
                throw 'Initial maintenance snapshot roots differ from its real reviewed plan'
            }
        }
        if([IO.Path]::GetFullPath([string]$Config.maintenance_roots.staging) -cne $stage -or
            [IO.Path]::GetFullPath([string]$Config.maintenance_roots.target) -cne $target) {
            throw 'Initial maintenance observer escaped the exact owned fixture layout'
        }
        $metadata=$journal.recovery_metadata;$stream=$metadata.stream_journal
        if($journal.current_state -cne 'staging' -or @($journal.transitions).Count -ne 4 -or
            $null -ne $metadata.staging_identity -or @($metadata.staged_files).Count -ne 0 -or
            $metadata.commit_cleanup_policy -cne 'retain_only' -or $metadata.stream_cleanup_policy -cne 'retain_only' -or
            $journal.recovery.required -ne $false -or @($journal.recovery.available_actions).Count -ne 1 -or
            $journal.recovery.available_actions[0] -cne 'retain_for_operator' -or -not $stream -or
            @($stream.entries).Count -ne 0 -or $stream.source_digest -cnotmatch '^[0-9a-f]{64}$' -or
            -not $stream.source_context -or $stream.publication_root_identity) {
            throw 'Initial maintenance shared snapshot window was missed or is malformed'
        }
        $phases=@('created','validated','planned','staging')
        $chain=[Text.StringBuilder]::new()
        for($i=0;$i -lt 4;$i++) {
            $transition=$journal.transitions[$i]
            if($transition.sequence -ne $i -or $transition.to -cne $phases[$i] -or
                $transition.transition_id -cne ($tx+'.'+$i) -or
                $transition.durable_before_external_visibility -ne $true -or -not $transition.recorded_at -or
                ($i -eq 0 -and $null -ne $transition.from) -or
                ($i -gt 0 -and $transition.from -cne $phases[$i-1])) {
                throw 'Initial maintenance shared snapshot chain differs'
            }
            $from=if($i -eq 0){''}else{$phases[$i-1]}
            [void]$chain.Append($i).Append([char]0).Append($from).Append([char]0).Append($phases[$i]).
                Append([char]0).Append([string]$transition.recorded_at).Append([char]10)
        }
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$chainSha=([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false,$true).
            GetBytes($chain.ToString())))).Replace('-','').ToLowerInvariant()}
        finally {$sha.Dispose()}
        if($journal.journal_digest -cne $chainSha -or $journal.updated_at -cne $journal.transitions[3].recorded_at) {
            throw 'Initial maintenance shared snapshot digest or final time differs'
        }
        if((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $target)) {
            throw 'Initial maintenance staging effect already began; required window missed'
        }
        $EffectPair.RequireOriginalLivePair()
        $Result.boundary_seen_utc=[DateTime]::UtcNow.ToString('o')
        $Result.journal_before_kill=$true
        $Result.native_process_pair=$EffectPair.TerminateOriginalScmOwner()
        $Result.termination=New-OriginalScmTermination $Result.native_process_pair
        $Result.journal_after_kill=Test-Path -LiteralPath $Config.journal_path
        if(-not $Result.journal_after_kill -or (Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $target)) {
            throw 'Initial maintenance record vanished or staging raced owner termination'
        }
        $Result['maintenance_transaction_id']=$tx
        $Result['maintenance_install_id']=$Config.maintenance_install_id
        $Result['maintenance_plan_id']=$Config.maintenance_plan_id
        $Result['maintenance_plan_digest']=$Config.maintenance_plan_digest
        $Result['maintenance_writer_lease_ownership']=$writer
        $Result['initial_snapshot_sha256']=$digests.initial
        $Result['original_custody_sha256']=$digests.original
        $Result['original_context_record_sha256']=$digests.context
        $Result['original_roots_record_sha256']=$digests.roots
        $Result['observer_interference']='write_delete_denial_for_held_initial_and_original_records'
        $Result['staging_before_kill']=$false;$Result['staging_after_kill']=$false
        $Result['target_before_kill']=$false;$Result['target_after_kill']=$false
        $Result.status='terminated_initial_maintenance_before_staging'
        return $true
    } finally {
        for($i=$opened.Count-1;$i -ge 0;$i--){$opened[$i].Dispose()}
    }
}
