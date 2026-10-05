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
function New-FixtureCimFailure([uint32]$Status) {
    $data=[Microsoft.Management.Infrastructure.CimInstance]::new('CIM_Error')
    try {
        $data.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create(
            'CIMStatusCode',$Status,[Microsoft.Management.Infrastructure.CimType]::UInt32,[Microsoft.Management.Infrastructure.CimFlags]::None))
        $data.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create(
            'Message','owned synthetic information read failure',[Microsoft.Management.Infrastructure.CimType]::String,[Microsoft.Management.Infrastructure.CimFlags]::None))
        return [Microsoft.Management.Infrastructure.CimException]::new($data)
    } finally {$data.Dispose()}
}
foreach($code in @(1,6)) {
    $attempts=[int[]]@(0,0)
    $failure=New-FixtureCimFailure $code
    $information=Read-StandardLauncherTaskInformation -RevalidateTask {$attempts[1]++} -ReadInformation {
        $attempts[0]++;if($attempts[0] -lt 3){throw $failure};[pscustomobject]@{actual_observation='returned'}
    }
    if($attempts[0] -ne 3 -or $attempts[1] -ne 3 -or $information.actual_observation -cne 'returned') {
        throw 'Finite task-info retries omitted actual observation or task revalidation'
    }
}
foreach($case in @('persistent','access_denied','task_changed','ordinary_error')) {
    $attempts=[int[]]@(0,0);$refused=$false
    $failure=New-FixtureCimFailure $(if($case -ceq 'access_denied'){2}else{1})
    try {
        $null=Read-StandardLauncherTaskInformation -RevalidateTask {
            $attempts[1]++;if($case -ceq 'task_changed' -and $attempts[1] -eq 2){throw 'changed owned task'}
        } -ReadInformation {
            $attempts[0]++;if($case -ceq 'ordinary_error'){throw 'ordinary failure'};throw $failure
        }
    } catch {$refused=$true}
    $expected=if($case -ceq 'persistent'){3}else{1}
    if(-not $refused -or $attempts[0] -ne $expected -or $attempts[1] -gt 3) {
        throw ('Task information failure was retried without a finite admitted observation: '+$case)
    }
}
try {throw (New-FixtureCimFailure 6)} catch {$cimDiagnostic=Get-StandardLauncherErrorDiagnostic $_ 'observe_launcher_exit'}
if($cimDiagnostic.cim_status_code -ne 6 -or $null -eq $cimDiagnostic.cim_native_error_code) {
    throw 'Original finite CIM status diagnostic was discarded'
}
'Launcher startup: acknowledgment/closure controls and finite revalidated CIM metadata reads checked; no tasks executed'
