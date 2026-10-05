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
    $action=[pscustomobject]@{ReferenceKind='action';Type=0;Path='owned-image';Arguments='owned-arguments';WorkingDirectory=''}
    $actions=[pscustomobject]@{ReferenceKind='actions';Count=1;Action=$action;FixtureState=$null}
    $actions|Add-Member -MemberType ScriptMethod -Name Item -Value {
        param($Index)
        if($Index -ne 1){throw 'COM action index differs'}
        if($this.FixtureState){
            $this.FixtureState.Calls.Add('action:1')
            if($this.FixtureState.Mode -ceq 'action'){throw 'original action observation failure'}
        }
        return $this.Action
    }
    $principal=[pscustomobject]@{ReferenceKind='principal';UserId='S-1-5-18';GroupId='';RunLevel=1;LogonType=5}
    $definition=[pscustomobject]@{ReferenceKind='definition';Principal=$principal;Actions=$actions}
    [pscustomobject]@{ReferenceKind='task';Name=$registeredName;Path=('\'+$registeredName);
        LastRunTime=[DateTime]::new(2026,10,5);LastTaskResult=0;State=3;Definition=$definition}
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
    $task.Definition.Actions.FixtureState=$state
    if($Mode -ceq 'wrong_identity'){$task.Path='\other'}
    if($Mode -ceq 'binding_user'){$task.Definition.Principal.UserId='S-1-5-19'}
    if($Mode -ceq 'binding_image'){$task.Definition.Actions.Action.Path='other-image'}
    if($Mode -ceq 'binding_arguments'){$task.Definition.Actions.Action.Arguments='other-arguments'}
    $folder=[pscustomobject]@{ReferenceKind='folder';FixtureState=$state;RegisteredTask=$task}
    $folder|Add-Member -MemberType ScriptMethod -Name GetTask -Value {
        param($Name)
        $this.FixtureState.Calls.Add('task:'+$Name)
        if($this.FixtureState.Mode -in @('task','task_and_cleanup')){throw 'original task observation failure'}
        if($this.FixtureState.Mode -ceq 'missing'){throw [Runtime.InteropServices.COMException]::new('exact task absent',-2147024894)}
        if($this.FixtureState.Mode -ceq 'access'){throw [Runtime.InteropServices.COMException]::new('task access denied',-2147024891)}
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
        if($this.FixtureState.Mode -ceq 'folder_missing'){throw [Runtime.InteropServices.COMException]::new('folder absent',-2147024894)}
        return $this.Folder
    }
    return [pscustomobject]@{State=$state;Scheduler=$scheduler}
}
foreach($case in @('positive','task_changed','connect','folder','task','action','wrong_identity','cleanup','task_and_cleanup','folder_cleanup',
    'binding_user','binding_image','binding_arguments')) {
    $fixture=New-FixtureScheduler $case;$state=$fixture.State;$failure=$null;$info=$null
    try {
        $info=Read-StandardRegisteredTaskInformation -TaskName $registeredName -RevalidateTask {
            param($Observed)
            $state.Calls.Add('revalidate');if($state.Mode -ceq 'task_changed'){throw 'changed owned task'}
            if($Observed.TaskName -cne $registeredName -or $Observed.TaskPath -cne '\' -or
                $Observed.Actions[0].Execute -cne 'owned-image' -or $Observed.Actions[0].Arguments -cne 'owned-arguments' -or
                $Observed.Principal.UserId -cne 'S-1-5-18') {
                throw 'Plain definition binding differs'
            }
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
    $expectedCalls=@('create','connect','folder:\',('task:'+$registeredName),'action:1','revalidate')
    $expectedReleased=@('action','actions','principal','definition','task','folder','scheduler')
    switch($case) {
        'connect' {$expectedCalls=@('create','connect');$expectedReleased=@('scheduler')}
        'folder' {$expectedCalls=@('create','connect','folder:\');$expectedReleased=@('scheduler')}
        'task' {$expectedCalls=$expectedCalls[0..3];$expectedReleased=@('folder','scheduler')}
        'task_and_cleanup' {$expectedCalls=$expectedCalls[0..3];$expectedReleased=@('folder','scheduler')}
        'wrong_identity' {$expectedCalls=$expectedCalls[0..3];$expectedReleased=@('task','folder','scheduler')}
        'action' {$expectedCalls=$expectedCalls[0..4];$expectedReleased=@('actions','principal','definition','task','folder','scheduler')}
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
            'action' {'original action observation failure'}
            'binding_user' {'Plain definition binding differs'}
            'binding_image' {'Plain definition binding differs'}
            'binding_arguments' {'Plain definition binding differs'}
            default {'original task observation failure'}
        }
        if(-not $failure -or $failure.Exception.Message -notmatch [regex]::Escape($expectedFailure) -or $null -ne $info) {
            throw ('Registered task failure became a successful observation or lost its original error: '+$case)
        }
    }
}
foreach($case in @('state_text','state_boolean','state_range','user_empty','group','group_boolean','runlevel_text','runlevel_boolean',
    'runlevel','logon_text','logon','count_boolean','count','action_type_text','action_type','path_null',
    'arguments_null','directory_null','directory','principal_null','actions_null','action_null')) {
    $fixture=New-FixtureScheduler 'positive';$task=$fixture.Scheduler.Folder.RegisteredTask
    $principal=$task.Definition.Principal;$actions=$task.Definition.Actions;$action=$actions.Action
    switch($case) {
        'state_text' {$task.State='3'}
        'state_boolean' {$task.State=$true}
        'state_range' {$task.State=5}
        'user_empty' {$principal.UserId=''}
        'group' {$principal.GroupId='S-1-5-32-544'}
        'group_boolean' {$principal.GroupId=$false}
        'runlevel_text' {$principal.RunLevel='1'}
        'runlevel_boolean' {$principal.RunLevel=$true}
        'runlevel' {$principal.RunLevel=0}
        'logon_text' {$principal.LogonType='5'}
        'logon' {$principal.LogonType=1}
        'count_boolean' {$actions.Count=$true}
        'count' {$actions.Count=2}
        'action_type_text' {$action.Type='0'}
        'action_type' {$action.Type=5}
        'path_null' {$action.Path=$null}
        'arguments_null' {$action.Arguments=$null}
        'directory_null' {$action.WorkingDirectory=$null}
        'directory' {$action.WorkingDirectory='other'}
        'principal_null' {$task.Definition.Principal=$null}
        'actions_null' {$task.Definition.Actions=$null}
        'action_null' {$actions.Action=$null}
    }
    $observed=[int[]]@(0);$refused=$false
    try {$null=Read-StandardRegisteredTaskInformation -TaskName $registeredName -RevalidateTask {$observed[0]++} `
        -CreateScheduler {return $fixture.Scheduler}.GetNewClosure() -ReleaseReference {}}
    catch {$refused=$true}
    if(-not $refused -or $observed[0] -ne 0){throw ('Contradictory COM definition reached binding validation: '+$case)}
}
foreach($value in 0..4) {
    $fixture=New-FixtureScheduler 'positive';$fixture.Scheduler.Folder.RegisteredTask.State=$value
    $info=Read-StandardRegisteredTaskInformation -TaskName $registeredName -RevalidateTask {} `
        -CreateScheduler {return $fixture.Scheduler}.GetNewClosure() -ReleaseReference {}
    if($info.State -cne @('Unknown','Disabled','Queued','Ready','Running')[$value]){throw 'Actual task state mapping differs'}
}
foreach($case in @('missing','positive','task','access','folder_missing','connect','cleanup')) {
    $mode=if($case -ceq 'cleanup'){'missing'}else{$case}
    $fixture=New-FixtureScheduler $mode;$state=$fixture.State;$failure=$null
    try {Assert-StandardRegisteredTaskAbsent -TaskName $registeredName `
        -CreateScheduler {return $fixture.Scheduler}.GetNewClosure() -ReleaseReference {
            param($Reference)
            $state.Released.Add($Reference.ReferenceKind)
            if($case -ceq 'cleanup' -and $Reference.ReferenceKind -ceq 'folder'){throw 'absence cleanup failed'}
        }.GetNewClosure()}
    catch {$failure=$_}
    if(($case -ceq 'missing') -ne ($null -eq $failure)){throw ('Unconfirmed task absence became successful: '+$case)}
    $released=if($case -ceq 'positive'){'task|folder|scheduler'}elseif($case -in @('connect','folder_missing')){'scheduler'}else{'folder|scheduler'}
    if(($state.Released -join '|') -cne $released){throw ('Absence reference cleanup order differs: '+$case)}
}
$opened=[int[]]@(0);$refused=$false
try {$null=Read-StandardRegisteredTaskInformation -TaskName 'not-owned' -RevalidateTask {} -CreateScheduler {$opened[0]++}}
catch {$refused=$true}
if(-not $refused -or $opened[0] -ne 0){throw 'Unowned task name reached scheduler access'}
$refused=$false
try {Assert-StandardRegisteredTaskAbsent -TaskName 'not-owned' -CreateScheduler {$opened[0]++}}
catch {$refused=$true}
if(-not $refused -or $opened[0] -ne 0){throw 'Unowned task absence reached scheduler access'}
'Launcher startup: acknowledgment, metadata identity/types, original errors and reference cleanup checked; no tasks executed'
