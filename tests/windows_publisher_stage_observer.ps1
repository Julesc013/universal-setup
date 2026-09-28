# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$StagePath,
    [Parameter(Mandatory=$true)][string]$ReadyPath,
    [Parameter(Mandatory=$true)][string]$StopPath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$SourcePath = ''
)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') {
    throw 'Stage observer requires SYSTEM'
}
$runs=[Collections.Generic.List[object]]::new()
$sourceAtStart=if($SourcePath){
    (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
}else{$null}
$first=0L;$last=0L;$count=0;$maximumGap=0L
$deadline=[DateTime]::UtcNow.AddSeconds(120)
[IO.File]::WriteAllText($ReadyPath,"usk.publisher.stage_observer_ready.v1`n",[Text.UTF8Encoding]::new($false))
while(-not [IO.File]::Exists($StopPath) -and [DateTime]::UtcNow -lt $deadline) {
    $tick=[DateTime]::UtcNow.Ticks
    if([IO.File]::Exists($StagePath)) {
        if($count -eq 0){$first=$tick}else{
            $gap=$tick-$last;if($gap -gt $maximumGap){$maximumGap=$gap}
        }
        $last=$tick;$count++
    } elseif($count -gt 0) {
        if($runs.Count -ge 64){throw 'Stage observer interval bound exceeded'}
        $runs.Add([ordered]@{first_tick=$first;last_tick=$last;samples=$count;maximum_gap_ticks=$maximumGap})
        $first=0L;$last=0L;$count=0;$maximumGap=0L
    }
    Start-Sleep -Milliseconds 1
}
if($count -gt 0) {
    if($runs.Count -ge 64){throw 'Stage observer interval bound exceeded'}
    $runs.Add([ordered]@{first_tick=$first;last_tick=$last;samples=$count;maximum_gap_ticks=$maximumGap})
}
$sourceAtStop=if($SourcePath){
    (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
}else{$null}
@{schema='usk.publisher.stage_observer.v1';identity='S-1-5-18';
  stopped=[IO.File]::Exists($StopPath);runs=$runs.ToArray();
  source_sha256_at_start=$sourceAtStart;source_sha256_at_stop=$sourceAtStop} |
    ConvertTo-Json -Depth 6 -Compress |
    Set-Content -LiteralPath $OutputPath -Encoding UTF8
