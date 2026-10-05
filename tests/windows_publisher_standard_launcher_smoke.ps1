# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Ordinary temporary files only: no tasks, services, accounts, worker pause or lab.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_standard_launcher.ps1')
$binding=[pscustomobject]@{schema='usk.publisher_standard_launcher.v1';process_id=123;
    creation_file_time='134356545325368891';identity='S-1-5-18';image='owned-test-image'}
$taskName='USK_STANDARD_PUBLIC_test';$sha256='a'*64
$ack=[ordered]@{schema='usk.publisher_standard_launcher_ack.v1';task_name=$taskName;
    process_id=$binding.process_id;creation_file_time=$binding.creation_file_time;binding_sha256=$sha256}
Assert-StandardLauncherAcknowledgment ([pscustomobject]$ack) $binding $taskName $sha256
foreach($prior in @('original child failure','')) {
    $result=Update-StandardLauncherUnconfirmed ([pscustomobject]@{status='passed';failure=$prior;
        client_cleanup_confirmed=$true;launcher_task_removed=$true}) 'unconfirmed launcher exit'
    $expected=if($prior){$prior}else{'unconfirmed launcher exit'}
    if($result.status -cne 'failed' -or $result.failure -cne $expected -or $result.client_cleanup_confirmed -or
        $result.launcher_task_removed -or $result.launcher_cleanup_failure -cne 'unconfirmed launcher exit') {
        throw 'Launcher cleanup lost the original failure or promoted unknown closure'
    }
}
foreach($case in @('schema','task','pid','fractional_pid','boolean_pid','birth','numeric_birth','hash','extra','missing')) {
    $changed=[ordered]@{};foreach($key in $ack.Keys){$changed[$key]=$ack[$key]}
    switch($case) {
        'schema' {$changed.schema='invented'}
        'task' {$changed.task_name='different-task'}
        'pid' {$changed.process_id=124}
        'fractional_pid' {$changed.process_id=123.0}
        'boolean_pid' {$changed.process_id=$true}
        'birth' {$changed.creation_file_time='134356545325368892'}
        'numeric_birth' {$changed.creation_file_time=134356545325368891L}
        'hash' {$changed.binding_sha256='b'*64}
        'extra' {$changed.authority=$true}
        'missing' {$changed.Remove('binding_sha256')}
    }
    $refused=$false
    try {Assert-StandardLauncherAcknowledgment ([pscustomobject]$changed) $binding $taskName $sha256}
    catch {$refused=$true}
    if(-not $refused){throw ('Contradictory launcher acknowledgment accepted: '+$case)}
}
$owned=Join-Path ([IO.Path]::GetTempPath()) ('usk-launcher-smoke-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($owned)|Out-Null
$path=Join-Path $owned 'ack.json'
try {
    [IO.File]::WriteAllText($path,([pscustomobject]$ack|ConvertTo-Json -Compress))
    Wait-StandardLauncherAcknowledgment $path $binding $taskName $sha256 100
    [IO.File]::WriteAllText($path,(' '*4097))
    $refused=$false;try {Wait-StandardLauncherAcknowledgment $path $binding $taskName $sha256 100}catch{$refused=$true}
    if(-not $refused){throw 'Oversize launcher acknowledgment accepted'}
    [IO.File]::Delete($path)
    $refused=$false;try {Wait-StandardLauncherAcknowledgment $path $binding $taskName $sha256 50}catch{$refused=$true}
    if(-not $refused){throw 'Missing launcher acknowledgment permitted probe execution'}
    foreach($budget in @(0,30001)) {
        $refused=$false;try {Wait-StandardLauncherAcknowledgment $path $binding $taskName $sha256 $budget}catch{$refused=$true}
        if(-not $refused){throw 'Invalid launcher wait budget accepted'}
    }
} finally {
    if([IO.File]::Exists($path)){[IO.File]::Delete($path)}
    [IO.Directory]::Delete($owned)
}
$retained=$null
try {throw [ComponentModel.Win32Exception]::new(2)} catch {$retained=$_}
$diagnostic=Get-StandardLauncherErrorDiagnostic $retained 'acquire_launcher_custody'
if($diagnostic.native_error_code -ne 2 -or $diagnostic.phase -cne 'acquire_launcher_custody' -or
    -not $diagnostic.exception_type -or -not $diagnostic.script_line -or -not $diagnostic.message_excerpt -or
    $diagnostic.message_excerpt.Length -gt 2048 -or $diagnostic.stack_excerpt.Length -gt 4096) {
    throw 'Original launcher diagnostic lost its finite native failure context'
}
'Launcher startup: matching acknowledgment accepted; ten contradictions, byte/deadline budgets and original Win32 diagnostic checked'
