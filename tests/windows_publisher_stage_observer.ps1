# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$StagePath,
    [Parameter(Mandatory=$true)][string]$VisiblePath,
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
$lastStagedOnlyStart=0L;$lastStagedOnlyEnd=0L
$firstVisibleStart=0L;$firstVisibleEnd=0L;$ambiguousSamples=0
$sawStage=$false;$visibleBeforeStage=$false;$stageAfterVisible=$false
$deadline=[DateTime]::UtcNow.AddSeconds(120)
[IO.File]::WriteAllText($ReadyPath,"usk.publisher.stage_observer_ready.v1`n",[Text.UTF8Encoding]::new($false))
while(-not [IO.File]::Exists($StopPath) -and [DateTime]::UtcNow -lt $deadline) {
    $tick=[Diagnostics.Stopwatch]::GetTimestamp()
    $staged=[IO.File]::Exists($StagePath)
    $visible=[IO.Directory]::Exists($VisiblePath)
    $sampleEnd=[Diagnostics.Stopwatch]::GetTimestamp()
    if($staged -and -not $visible) {
        $sawStage=$true
        $lastStagedOnlyStart=$tick
        $lastStagedOnlyEnd=$sampleEnd
        if($firstVisibleStart -gt 0){$stageAfterVisible=$true}
    } elseif(-not $staged -and $visible) {
        if(-not $sawStage){$visibleBeforeStage=$true}
        if($sawStage -and $firstVisibleStart -eq 0){
            $firstVisibleStart=$tick
            $firstVisibleEnd=$sampleEnd
        }
    } elseif($staged -and $visible) {
        $ambiguousSamples++
    }
    if($staged) {
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
  clock='qpc';clock_frequency=[Diagnostics.Stopwatch]::Frequency;
  stopped=[IO.File]::Exists($StopPath);runs=$runs.ToArray();
  transition=@{last_staged_only_start_tick=$lastStagedOnlyStart;
    last_staged_only_end_tick=$lastStagedOnlyEnd;
    first_visible_start_tick=$firstVisibleStart;
    first_visible_end_tick=$firstVisibleEnd;
    ambiguous_samples=$ambiguousSamples;
    visible_before_stage=$visibleBeforeStage;
    stage_after_visible=$stageAfterVisible};
  source_sha256_at_start=$sourceAtStart;source_sha256_at_stop=$sourceAtStop} |
    ConvertTo-Json -Depth 6 -Compress |
    Set-Content -LiteralPath $OutputPath -Encoding UTF8
