# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Assert-IndependentMetadataProbe {
    param($Result)
    $drive=$Result.volume_drive_root
    if($drive -cnotmatch '^[A-Z]:\\$'){throw 'Exact observed volume drive root required'}
    if ($Result.native.status -ne 'pass' -or -not $Result.observer_task_removed -or
        $Result.independent.identity -ne 'S-1-5-18' -or
        $Result.independent.missing_roots) { throw 'Service, observer identity or confirmed task cleanup differs' }
    foreach ($row in $Result.independent.rows) {
        if ($row.owner -ne 'S-1-5-18' -or -not $row.protected -or $row.aces.Count -ne 2 -or
            @($row.aces|Where-Object sid -eq 'S-1-5-18').Count -ne 1 -or
            @($row.aces|Where-Object sid -eq $Result.service_sid).Count -ne 1 -or
            @($row.aces|Where-Object { $_.rights -ne 2032127 -or $_.type -ne 'Allow' -or
                $_.inherited -or $_.inheritance -ne 0 -or $_.propagation -ne 0 }).Count -ne 0) {
            throw ('Independent owner/DACL differs: ' + $row.path)
        }
    }
    function Get-ExactRecord([string]$Path) {
        $found=@($Result.independent.rows|Where-Object { $_.path -ceq $Path -and -not $_.directory })
        if ($found.Count -ne 1 -or -not $found[0].content_json) { throw ('Missing independent record: ' + $Path) }
        $found[0].content_json | ConvertFrom-Json
    }
    $snapshot=Get-ExactRecord ($drive + 'publication\journal\lab-reviewed-plan.json')
    $completion=Get-ExactRecord ($drive + 'publication\state\lab-installed-state.json')
    $completionRow=@($Result.independent.rows|Where-Object path -ceq ($drive + 'publication\state\lab-installed-state.json'))[0]
    if ($snapshot.plan_digest -ne $Result.plan.plan_digest -or $snapshot.archive_sha256 -ne $Result.archive_sha256 -or
        $completion.source_binding.reviewed_plan_digest -ne $snapshot.plan_digest) { throw 'Independent reviewed source binding differs' }
    if ($Result.apply_request -and ($snapshot.transaction_id -ne $Result.apply_request.transaction_id -or
        $snapshot.applied_at -ne $Result.apply_request.applied_at)) { throw 'Independent caller operation binding differs' }
    $transaction=$snapshot.transaction_id
    $installId=$Result.request.install_id
    $installedPath=($drive + 'setup-state\state\installed\') + $installId + '.' + $transaction + '.json'
    $installed=Get-ExactRecord $installedPath
    $ownershipPath=($drive + 'setup-state\state\') + $installed.ownership_manifest_ref.Replace('/','\')
    $ownership=Get-ExactRecord $ownershipPath
    $marker=Get-ExactRecord ($drive + 'setup-state\.usk-owned-root.v1.json')
    $auditRoot=($drive + 'setup-state\audit\chains\') + $installed.audit_chain_id + '\'
    $validatedPath=$auditRoot+'00000000000000000000.event.json'
    $completedPath=$auditRoot+'00000000000000000001.event.json'
    $validated=Get-ExactRecord $validatedPath
    $completed=Get-ExactRecord $completedPath
    $publicFiles=@($Result.independent.rows|Where-Object { -not $_.directory -and $_.path.StartsWith(($drive + 'setup-state\'),[StringComparison]::Ordinal) })
    $expected=@(($drive + 'setup-state\.usk-owned-root.v1.json'),$installedPath,$ownershipPath,$validatedPath,$completedPath)
    if ($publicFiles.Count -ne 5 -or @($publicFiles|Where-Object {$_.path -cnotin $expected}).Count -ne 0) { throw 'Independent public record closure differs' }
    $target=$Result.plan.target.root.Replace('/','\')
    if ($marker.schema -ne 'usk.setup_owned_root.v1' -or $marker.acceptance_root.Replace('/','\') -cne ($drive + '') -or
        $installed.schema -ne 'usk.installed_state.v1' -or $installed.install_id -ne $installId -or
        $installed.transaction_id -ne $transaction -or $installed.created_at -ne $snapshot.applied_at -or
        $installed.target_root.Replace('/','\') -cne $target -or $installed.source_archive_digest -ne $Result.archive_sha256 -or
        $installed.recipe_digest -ne $Result.request.recipe.recipe_digest -or $installed.product_id -ne $Result.request.recipe.product_id -or
        $installed.product_version -ne $Result.request.recipe.product_version -or $installed.lifecycle_status -ne 'installed' -or
        ($installed.component_selection|ConvertTo-Json -Compress) -cne ($Result.request.recipe.components|ConvertTo-Json -Compress) -or
        $ownership.schema -ne 'usk.ownership_manifest.v1' -or $ownership.install_id -ne $installId -or
        $ownership.created_by_transaction_id -ne $transaction -or $ownership.target_root.Replace('/','\') -cne $target -or
        $ownership.manifest_digest -ne $installed.ownership_manifest_digest -or
        $installed.ownership_manifest_ref -cne ('ownership/'+$ownership.manifest_id+'.json') -or
        $installed.last_verification.status -ne 'pass') { throw 'Independent installed/ownership/marker binding differs' }
    if ($validated.phase -ne 'validated' -or $validated.status -ne 'pass' -or $validated.sequence -ne 0 -or
        $validated.details_digest -ne $completionRow.sha256 -or $validated.subject.subject_id -ne $Result.plan.plan_id -or
        $validated.subject.subject_type -ne 'journal' -or $null -ne $validated.previous_event_digest -or
        $completed.phase -ne 'completed' -or $completed.status -ne 'pass' -or $completed.sequence -ne 1 -or
        $completed.previous_event_digest -ne $validated.event_digest -or $completed.subject.subject_id -ne $installId -or
        $completed.subject.subject_type -ne 'installation' -or
        $completed.details_digest -ne $installed.last_verification.report_digest) { throw 'Independent audit linkage differs' }
    foreach ($event in @($validated,$completed)) {
        if ($event.schema -ne 'usk.audit_event.v1' -or $event.operation -ne 'install_local' -or
            $event.transaction_id -ne $transaction -or $event.plan_id -ne $Result.plan.plan_id -or
            $event.created_at -ne $snapshot.applied_at -or $event.audit_chain_id -ne $installed.audit_chain_id) {
            throw 'Independent audit operation binding differs'
        }
    }
    $entries=@($Result.plan.planned_entries|Where-Object entry_type -eq file)
    if ($ownership.files.Count -ne $entries.Count) { throw 'Independent ownership file count differs' }
    $visibleRoot=$drive+'publication\destination\visible'
    $expectedPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedDirectories=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$expectedDirectories.Add($visibleRoot)
    foreach($entry in $entries) {
        $path=$visibleRoot+'\'+$entry.relative_path.Replace('/','\')
        if(-not $expectedPaths.Add($path)){throw 'Duplicate planned visible file'}
        $parent=[IO.Path]::GetDirectoryName($path)
        while($parent.StartsWith($visibleRoot+'\',[StringComparison]::Ordinal)) {
            [void]$expectedDirectories.Add($parent)
            $parent=[IO.Path]::GetDirectoryName($parent)
        }
    }
    $visibleRows=@($Result.independent.rows|Where-Object {
        $_.path -ceq $visibleRoot -or $_.path.StartsWith($visibleRoot+'\',[StringComparison]::Ordinal)
    })
    if(@($visibleRows|Where-Object { -not $_.directory }).Count -ne $entries.Count -or
        @($visibleRows|Where-Object { if($_.directory){-not $expectedDirectories.Contains($_.path)}else{-not $expectedPaths.Contains($_.path)} }).Count -ne 0) {
        throw 'Independent visible payload closure differs'
    }
    foreach ($entry in $entries) {
        $path=($drive + 'publication\destination\visible\')+$entry.relative_path.Replace('/','\')
        $found=@($Result.independent.rows|Where-Object path -ceq $path)
        $owned=@($ownership.files|Where-Object relative_path -ceq $entry.relative_path)
        if ($found.Count -ne 1 -or $owned.Count -ne 1 -or $found[0].sha256 -ne $entry.sha256 -or
            $found[0].bytes -ne $entry.size_bytes -or $owned[0].sha256 -ne $entry.sha256 -or $owned[0].size_bytes -ne $entry.size_bytes) {
            throw ('Independent selected payload/ownership differs: ' + $path)
        }
    }
}
function Invoke-IndependentMetadataReadback {
    param([string]$DriveRoot,[string]$OutputRoot,[string]$RunId,[switch]$AllowAbsentSetupRoot)
    if($DriveRoot -cnotmatch '^[A-Z]:\\$' -or $RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Exact observed volume alias and owned observer identity required'
    }
    $name='USK_METADATA_OBSERVER_'+$RunId
    $script=Join-Path $OutputRoot ('metadata-observer-'+$RunId+'.ps1')
    $output=Join-Path $OutputRoot ('metadata-observed-'+$RunId+'.json')
    if((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $script) -or (Test-Path -LiteralPath $output)) { throw 'Observer collision' }
    $observer=@'
param([string]$Output,[string]$DriveRoot,[switch]$AllowAbsentSetupRoot)
$ErrorActionPreference='Stop'
$rows=[Collections.Generic.List[object]]::new()
$missing=[Collections.Generic.List[string]]::new()
$pending=[Collections.Generic.Stack[object]]::new()
foreach($top in @(($DriveRoot+'setup-state'),($DriveRoot+'publication'))) {
 if($AllowAbsentSetupRoot -and $top -ceq ($DriveRoot+'setup-state') -and -not (Test-Path -LiteralPath $top)) {
  $missing.Add($top);continue
 }
 $pending.Push((Get-Item -LiteralPath $top -Force))
 while($pending.Count -gt 0) {
  $p=$pending.Pop()
  if(($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected readback link' }
  if($rows.Count -ge 10000 -or (-not $p.PSIsContainer -and $p.Extension -eq '.json' -and $p.Length -gt 16MB)) {throw 'Independent readback exceeds its record budget'}
  $a=Get-Acl -LiteralPath $p.FullName
  $aces=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
   [ordered]@{sid=$_.IdentityReference.Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}
  })
  $rows.Add([ordered]@{path=$p.FullName;directory=$p.PSIsContainer;owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;protected=$a.AreAccessRulesProtected;aces=$aces;
   bytes= $(if($p.PSIsContainer){0}else{$p.Length});sha256=$(if($p.PSIsContainer){$null}else{(Get-FileHash -LiteralPath $p.FullName -Algorithm SHA256).Hash.ToLowerInvariant()});
   content_json=$(if(-not $p.PSIsContainer -and $p.Extension -eq '.json'){[IO.File]::ReadAllText($p.FullName)}else{$null})})
  if($p.PSIsContainer){foreach($child in Get-ChildItem -LiteralPath $p.FullName -Force){$pending.Push($child)}}
 }
}
$result=[ordered]@{schema='usk.publisher.metadata_independent_readback.v1';identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rows=$rows;missing_roots=$missing.ToArray();observed_utc=[DateTime]::UtcNow.ToString('o')}
$temporary=$Output+'.pending'
$stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 10))
 $stream.Write($bytes,0,$bytes.Length)
 $stream.Flush($true)
} finally { $stream.Dispose() }
# Only the closed, complete result becomes visible to the caller. File.Move
# refuses an existing destination in the installed Windows PowerShell runtime.
[IO.File]::Move($temporary,$Output)
'@
    [IO.File]::WriteAllText($script,$observer,[Text.UTF8Encoding]::new($false))
    # Use the installed SYSTEM policy without changing execution policy. The
    # reviewed script is passed as data to a -Command script block.
    $command="& ([scriptblock]::Create([IO.File]::ReadAllText('"+$script.Replace("'","''")+"'))) -Output '"+
        $output.Replace("'","''")+"' -DriveRoot '"+$DriveRoot+"'"
    if($AllowAbsentSetupRoot){$command+=' -AllowAbsentSetupRoot'}
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $name -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $name
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
        while(-not (Test-Path -LiteralPath $output) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $output)){throw 'Independent observer receipt absent'}
        $observed=Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $name -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Owned observer cleanup failed'}
        }
    }
    [pscustomobject]@{independent=$observed;observer_task_removed=$true}
}
