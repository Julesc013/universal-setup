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
try {throw (New-FixtureCimFailure 6)} catch {$cimDiagnostic=Get-StandardLauncherErrorDiagnostic $_ 'observe_launcher_exit'}
if($cimDiagnostic.cim_status_code -ne 6 -or $null -eq $cimDiagnostic.cim_native_error_code) {
    throw 'Original finite CIM status diagnostic was discarded'
}
try {throw [Runtime.InteropServices.COMException]::new('owned metadata failure',-2147024894)}
catch {$comDiagnostic=Get-StandardLauncherErrorDiagnostic $_ 'observe_launcher_exit'}
if($comDiagnostic.com_hresult -ne -2147024894){throw 'Original COM HRESULT diagnostic was discarded'}

$registeredName='USK_STANDARD_PUBLIC_'+('a'*32)
function New-FixtureRegisteredTask {
    [pscustomobject]@{ReferenceKind='task';Name=$registeredName;Path=('\'+$registeredName);
        LastRunTime=[DateTime]::new(2026,10,5);LastTaskResult=0}
}
foreach($case in @('name','path','null_time','text_time','null_result','text_result','boolean_result','fractional_result','overflow_result')) {
    $task=New-FixtureRegisteredTask
    switch($case) {
        'name' {$task.Name='other'}
        'path' {$task.Path='\other\'+$registeredName}
        'null_time' {$task.LastRunTime=$null}
        'text_time' {$task.LastRunTime='2026-10-05'}
        'null_result' {$task.LastTaskResult=$null}
        'text_result' {$task.LastTaskResult='0'}
        'boolean_result' {$task.LastTaskResult=$false}
        'fractional_result' {$task.LastTaskResult=0.0}
        'overflow_result' {$task.LastTaskResult=4294967296L}
    }
    $refused=$false;try {$null=ConvertTo-StandardRegisteredTaskInformation $task $registeredName}catch{$refused=$true}
    if(-not $refused){throw ('Contradictory registered task metadata accepted: '+$case)}
}
foreach($result in @(0,1,-2147024894,[uint32]::MaxValue)) {
    $task=New-FixtureRegisteredTask;$task.LastTaskResult=$result
    $info=ConvertTo-StandardRegisteredTaskInformation $task $registeredName
    if($info.LastTaskResult -ne $result -or $info.LastRunTime -ne $task.LastRunTime -or
        $info.observation_source -cne 'TaskScheduler.IRegisteredTask') {
        throw 'Actual registered task result was replaced or its source lost'
    }
}
function New-FixtureScheduler([string]$Mode) {
    $state=[pscustomobject]@{Mode=$Mode;Calls=[Collections.Generic.List[string]]::new();
        Released=[Collections.Generic.List[string]]::new()}
    $task=New-FixtureRegisteredTask
    if($Mode -ceq 'wrong_identity'){$task.Path='\other'}
    $folder=[pscustomobject]@{ReferenceKind='folder';FixtureState=$state;RegisteredTask=$task}
    $folder|Add-Member -MemberType ScriptMethod -Name GetTask -Value {
        param($Name)
        $this.FixtureState.Calls.Add('task:'+$Name)
        if($this.FixtureState.Mode -in @('task','task_and_cleanup')){throw 'original task observation failure'}
        return $this.RegisteredTask
    }
    $scheduler=[pscustomobject]@{ReferenceKind='scheduler';FixtureState=$state;Folder=$folder}
    $scheduler|Add-Member -MemberType ScriptMethod -Name Connect -Value {
        $this.FixtureState.Calls.Add('connect')
        if($this.FixtureState.Mode -ceq 'connect'){throw 'original connect observation failure'}
    }
    $scheduler|Add-Member -MemberType ScriptMethod -Name GetFolder -Value {
        param($Path)
        $this.FixtureState.Calls.Add('folder:'+$Path)
        if($this.FixtureState.Mode -ceq 'folder'){throw 'original folder observation failure'}
        return $this.Folder
    }
    return [pscustomobject]@{State=$state;Scheduler=$scheduler}
}
foreach($case in @('positive','task_changed','connect','folder','task','wrong_identity','cleanup','task_and_cleanup','folder_cleanup')) {
    $fixture=New-FixtureScheduler $case;$state=$fixture.State;$failure=$null;$info=$null
    try {
        $info=Read-StandardRegisteredTaskInformation -TaskName $registeredName -RevalidateTask {
            $state.Calls.Add('revalidate');if($state.Mode -ceq 'task_changed'){throw 'changed owned task'}
        }.GetNewClosure() -CreateScheduler {
            $state.Calls.Add('create');return $fixture.Scheduler
        }.GetNewClosure() -ReleaseReference {
            param($Reference)
            $state.Released.Add($Reference.ReferenceKind)
            if(($state.Mode -in @('cleanup','task_and_cleanup') -and $Reference.ReferenceKind -ceq 'folder') -or
                ($state.Mode -ceq 'folder_cleanup' -and $Reference.ReferenceKind -ceq 'folder')) {
                throw 'reference cleanup failure'
            }
        }.GetNewClosure()
    } catch {$failure=$_}
    $expectedCalls=@('revalidate','create','connect','folder:\',('task:'+$registeredName))
    $expectedReleased=@('task','folder','scheduler')
    switch($case) {
        'task_changed' {$expectedCalls=@('revalidate');$expectedReleased=@()}
        'connect' {$expectedCalls=@('revalidate','create','connect');$expectedReleased=@('scheduler')}
        'folder' {$expectedCalls=@('revalidate','create','connect','folder:\');$expectedReleased=@('scheduler')}
        'task' {$expectedReleased=@('folder','scheduler')}
        'task_and_cleanup' {$expectedReleased=@('folder','scheduler')}
    }
    if(($state.Calls -join '|') -cne ($expectedCalls -join '|') -or
        ($state.Released -join '|') -cne ($expectedReleased -join '|')) {
        throw ('Registered task observation/reverse cleanup order differs: '+$case)
    }
    if($case -ceq 'positive') {
        if($failure -or $info.LastTaskResult -ne 0){throw 'Actual registered task observation was lost'}
    } else {
        $expectedFailure=switch($case) {
            'task_changed' {'changed owned task'}
            'connect' {'original connect observation failure'}
            'folder' {'original folder observation failure'}
            'wrong_identity' {'identity/type differs'}
            'cleanup' {'reference cleanup failure'}
            'folder_cleanup' {'reference cleanup failure'}
            default {'original task observation failure'}
        }
        if(-not $failure -or $failure.Exception.Message -notmatch [regex]::Escape($expectedFailure) -or $null -ne $info) {
            throw ('Registered task failure became a successful observation or lost its original error: '+$case)
        }
    }
}
$opened=[int[]]@(0);$refused=$false
try {$null=Read-StandardRegisteredTaskInformation -TaskName 'not-owned' -RevalidateTask {} -CreateScheduler {$opened[0]++}}
catch {$refused=$true}
if(-not $refused -or $opened[0] -ne 0){throw 'Unowned task name reached scheduler access'}
'Launcher startup: acknowledgment, metadata identity/types, original errors and reference cleanup checked; no tasks executed'
