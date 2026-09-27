# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
function Stop-OwnedPublisherProcessTree {
    param([Parameter(Mandatory=$true)][Diagnostics.Process]$Process)
    $tracked=$Process.PSObject.Properties['UskOwnedTree']
    if($tracked){$owned=$tracked.Value} else {
    if($Process.HasExited){return [pscustomobject]@{confirmed=$true;terminated=0}}
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
    if(-not $Process.HasExited){
        $Process.Kill($true)
        if(-not $Process.WaitForExit(5000)){throw 'Owned process root did not terminate'}
    }
    $until=[DateTime]::UtcNow.AddSeconds(5)
    do {
        $remaining=0
        foreach($record in $owned) {
            $live=Get-CimInstance Win32_Process -Filter ('ProcessId='+$record.ProcessId) -ErrorAction Stop
            if($live -and $live.CreationDate -eq $record.CreationDate) {
                if($live.ExecutablePath -cne $record.ExecutablePath -or $live.CommandLine -cne $record.CommandLine){
                    throw 'Owned process identity changed during cancellation'
                }
                $remaining++
            }
        }
        if(-not $remaining){return [pscustomobject]@{confirmed=$true;terminated=$owned.Count}}
        Start-Sleep -Milliseconds 50
    } while([DateTime]::UtcNow -lt $until)
    throw 'Owned process descendants remain; retain account and lab material'
}
