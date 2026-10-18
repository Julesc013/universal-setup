# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
function Get-OwnedPublisherActorRoot {
    param([string]$OwnedHostedLabRoot)
    if(-not $OwnedHostedLabRoot){return 'C:\USK-Lab'}
    $owned=[IO.Path]::GetFullPath($OwnedHostedLabRoot).TrimEnd('\')
    $lab=Split-Path -Parent $owned
    $temporary=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or
        (Split-Path -Leaf $owned) -cne 'controller-inputs' -or
        (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or
        -not $lab.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Actor output requires the exact owned hosted lab root'
    }
    $trusted=@('S-1-5-18','S-1-5-32-544')
    $mutation=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach($path in @($lab,$owned)) {
        $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
        if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin $trusted) {
            throw 'Actor lab root type or owner differs'
        }
        foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -cnotin $trusted -and
                ($ace.FileSystemRights -band $mutation)) {throw 'Actor lab root permits an untrusted writer'}
        }
    }
    return $owned
}
function Stop-OwnedPublisherProcessTree {
    param([Parameter(Mandatory=$true)][Diagnostics.Process]$Process,
        [switch]$RequireLiveKill)
    $tracked=$Process.PSObject.Properties['UskOwnedTree']
    if($tracked){$owned=$tracked.Value} else {
    if($Process.HasExited){
        if($RequireLiveKill){throw 'Owned process exited before required termination'}
        return [pscustomobject]@{confirmed=$true;terminated=0;kill_invoked=$false}
    }
    $started=$Process.StartTime.ToUniversalTime()
    $rows=@(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine)
    if($rows.Count -gt 4096){throw 'Owned process observation exceeds bound'}
    $root=@($rows|Where-Object ProcessId -eq $Process.Id)
    if($root.Count -ne 1 -or -not $root[0].ExecutablePath -or -not $root[0].CommandLine -or
        [math]::Abs(($root[0].CreationDate.ToUniversalTime()-$started).Ticks) -gt 10000){
        throw 'Owned process identity changed before cancellation'
    }
    $owned=[Collections.Generic.List[object]]::new();$owned.Add($root[0])
    for($index=0;$index -lt $owned.Count;$index++) {
        $parent=$owned[$index]
        foreach($child in $rows|Where-Object ParentProcessId -eq $parent.ProcessId) {
            if($child.CreationDate -ge $parent.CreationDate -and
                -not @($owned|Where-Object ProcessId -eq $child.ProcessId).Count){$owned.Add($child)}
        }
        if($owned.Count -gt 1024){throw 'Owned process tree exceeds bound'}
    }
    # Keep these identities on the held process object even when cancellation
    # throws after the wrapper exits. A retry must still confirm its children.
    $Process|Add-Member -NotePropertyName UskOwnedTree -NotePropertyValue $owned
    }
    # The held root and these start-time-bound descendants are ours. Kill(true)
    # includes descendants created after the observation; confirm recorded
    # instances have gone before removing their account or owned resources.
    $killInvoked=$false
    if(-not $Process.HasExited){
        $Process.Kill($true)
        $killInvoked=$true
        if(-not $Process.WaitForExit(5000)){throw 'Owned process root did not terminate'}
    } elseif($RequireLiveKill){
        throw 'Owned process exited before required termination'
    }
    $until=[DateTime]::UtcNow.AddSeconds(5)
    do {
        $remaining=0
        foreach($record in $owned) {
            $live=Get-CimInstance Win32_Process -Filter ('ProcessId='+$record.ProcessId) -ErrorAction Stop
            if($live -and -not $live.CreationDate) {
                # An observed PID with unknown creation time is still live or
                # ambiguous. Never turn an incomplete CIM row into confirmed
                # process exit.
                $remaining++
                continue
            }
            if($live -and $live.CreationDate -eq $record.CreationDate) {
                # CIM can temporarily omit either field while a killed process
                # exits. Keep waiting for disappearance; still reject any
                # observed replacement identity or a descendant left alive.
                if(($live.ExecutablePath -and $live.ExecutablePath -cne $record.ExecutablePath) -or
                    ($live.CommandLine -and $live.CommandLine -cne $record.CommandLine)){
                    throw 'Owned process identity changed during cancellation'
                }
                $remaining++
            }
        }
        if(-not $remaining){return [pscustomobject]@{confirmed=$true;terminated=$owned.Count;kill_invoked=$killInvoked}}
        Start-Sleep -Milliseconds 50
    } while([DateTime]::UtcNow -lt $until)
    throw 'Owned process descendants remain; retain account and lab material'
}
