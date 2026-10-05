# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Definition-only helpers for the owned launcher's startup acknowledgment.
function Update-StandardLauncherUnconfirmed {
    param($Result,[string]$Reason)
    foreach($item in @{status='failed';client_cleanup_confirmed=$false;launcher_task_removed=$false;
        launcher_cleanup_failure=$Reason}.GetEnumerator()) {
        $Result|Add-Member -NotePropertyName $item.Key -NotePropertyValue $item.Value -Force
    }
    $priorFailure=$Result.PSObject.Properties['failure']
    if(-not $priorFailure -or [string]::IsNullOrWhiteSpace([string]$priorFailure.Value)) {
        $Result|Add-Member -NotePropertyName failure -NotePropertyValue $Reason -Force
    }
    return $Result
}

function Get-StandardLauncherErrorDiagnostic {
    param($ErrorRecord,[string]$Phase)
    $exception=$ErrorRecord.Exception;$nativeCode=$null;$cimNativeCode=$null;$cimStatusCode=$null;$comHresult=$null
    for($depth=0;$exception -and $depth -lt 8;$depth++) {
        if($exception -is [Microsoft.Management.Infrastructure.CimException]) {
            $cimNativeCode=[int]$exception.NativeErrorCode;$cimStatusCode=[uint32]$exception.StatusCode
        }
        if($exception -is [Runtime.InteropServices.COMException]){$comHresult=$exception.HResult}
        if($exception -is [ComponentModel.Win32Exception]){$nativeCode=$exception.NativeErrorCode;break}
        $exception=$exception.InnerException
    }
    $message=[string]$ErrorRecord.Exception.Message;$stack=[string]$ErrorRecord.ScriptStackTrace
    return [ordered]@{phase=$Phase;exception_type=$ErrorRecord.Exception.GetType().FullName;
        hresult=$ErrorRecord.Exception.HResult;native_error_code=$nativeCode;
        cim_native_error_code=$cimNativeCode;cim_status_code=$cimStatusCode;com_hresult=$comHresult;
        message_excerpt=$message.Substring(0,[Math]::Min(2048,$message.Length));
        script_name=$ErrorRecord.InvocationInfo.ScriptName;script_line=$ErrorRecord.InvocationInfo.ScriptLineNumber;
        stack_excerpt=$stack.Substring(0,[Math]::Min(4096,$stack.Length))}
}

function ConvertTo-StandardRegisteredTaskInformation {
    param($RegisteredTask,[string]$TaskName)
    $name=$RegisteredTask.Name;$path=$RegisteredTask.Path
    $time=$RegisteredTask.LastRunTime;$result=$RegisteredTask.LastTaskResult
    if(-not ($name -is [string]) -or $name -cne $TaskName -or
        -not ($path -is [string]) -or $path -cne ('\'+$TaskName) -or
        -not ($time -is [DateTime]) -or
        -not ($result -is [int] -or $result -is [long] -or $result -is [uint32]) -or
        [long]$result -lt [int]::MinValue -or [long]$result -gt [uint32]::MaxValue) {
        throw 'Exact registered task information identity/type differs'
    }
    return [pscustomobject]@{LastRunTime=$time;LastTaskResult=[long]$result;
        observation_source='TaskScheduler.IRegisteredTask'}
}

function Read-StandardRegisteredTaskInformation {
    param([Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][scriptblock]$RevalidateTask,
        [scriptblock]$CreateScheduler={New-Object -ComObject 'Schedule.Service'},
        [scriptblock]$ReleaseReference={param($Reference)
            if([Runtime.InteropServices.Marshal]::IsComObject($Reference)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Reference)
            }})
    if($TaskName -cnotmatch '^USK_STANDARD_PUBLIC_[0-9a-f]{32}$'){throw 'Owned registered task name differs'}
    $scheduler=$null;$folder=$null;$task=$null;$definition=$null;$principal=$null
    $actions=$null;$action=$null;$failure=$null;$information=$null
    try {
        $scheduler=& $CreateScheduler
        $scheduler.Connect()
        $folder=$scheduler.GetFolder('\')
        $task=$folder.GetTask($TaskName)
        $information=ConvertTo-StandardRegisteredTaskInformation $task $TaskName
        $state=$task.State
        $definition=$task.Definition
        $principal=$definition.Principal
        $actions=$definition.Actions
        $count=$actions.Count
        $userId=$principal.UserId;$groupId=$principal.GroupId
        $runLevel=$principal.RunLevel;$logonType=$principal.LogonType
        if(-not ($state -is [int]) -or $state -lt 0 -or $state -gt 4 -or
            -not ($userId -is [string]) -or [string]::IsNullOrWhiteSpace($userId) -or
            ($null -ne $groupId -and -not ($groupId -is [string])) -or $groupId -or
            -not ($runLevel -is [int]) -or $runLevel -ne 1 -or
            -not ($logonType -is [int]) -or $logonType -ne 5 -or
            -not ($count -is [int]) -or $count -ne 1) {
            throw 'Exact registered task principal/action/state identity/type differs'
        }
        # COM collections are one-based. Keep every acquired reference owned by
        # this observation; plain values leave the helper, never an RCW.
        $action=$actions.Item(1)
        $actionType=$action.Type;$image=$action.Path;$arguments=$action.Arguments;$directory=$action.WorkingDirectory
        # The launcher leaves this optional BSTR unset. Null and the empty
        # string both mean no working directory; other types remain invalid.
        if($null -eq $directory){$directory=''}
        if(-not ($actionType -is [int]) -or $actionType -ne 0 -or
            -not ($image -is [string]) -or -not ($arguments -is [string]) -or
            -not ($directory -is [string]) -or $directory.Length -ne 0) {
            throw 'Exact registered task executable action identity/type differs'
        }
        $information|Add-Member -NotePropertyName TaskName -NotePropertyValue $TaskName
        $information|Add-Member -NotePropertyName TaskPath -NotePropertyValue '\'
        $information|Add-Member -NotePropertyName State -NotePropertyValue (@('Unknown','Disabled','Queued','Ready','Running')[$state])
        $information|Add-Member -NotePropertyName Principal -NotePropertyValue ([pscustomobject]@{
            UserId=$userId;RunLevel='Highest';LogonType=$logonType})
        $information|Add-Member -NotePropertyName Actions -NotePropertyValue @([pscustomobject]@{
            Execute=$image;Arguments=$arguments;WorkingDirectory=$directory})
        & $RevalidateTask $information|Out-Null
    } catch {$failure=$_}
    finally {
        # All seven references belong to this read. Attempt every release,
        # retaining the first observation failure or cleanup failure.
        foreach($reference in @($action,$actions,$principal,$definition,$task,$folder,$scheduler)) {
            if($null -ne $reference) {
                try {& $ReleaseReference $reference|Out-Null}
                catch {if($null -eq $failure){$failure=$_}}
            }
        }
    }
    if($null -ne $failure){throw $failure}
    return $information
}

function Assert-StandardRegisteredTaskAbsent {
    param([Parameter(Mandatory=$true)][string]$TaskName,
        [scriptblock]$CreateScheduler={New-Object -ComObject 'Schedule.Service'},
        [scriptblock]$ReleaseReference={param($Reference)
            if([Runtime.InteropServices.Marshal]::IsComObject($Reference)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Reference)
            }})
    if($TaskName -cnotmatch '^USK_STANDARD_PUBLIC_[0-9a-f]{32}$'){throw 'Owned registered task name differs'}
    $scheduler=$null;$folder=$null;$task=$null;$failure=$null;$absent=$false
    try {
        $scheduler=& $CreateScheduler
        $scheduler.Connect()
        $folder=$scheduler.GetFolder('\')
        try {$task=$folder.GetTask($TaskName)}
        catch {
            $exception=$_.Exception
            for($depth=0;$exception -and $depth -lt 8;$depth++) {
                if($exception -is [Runtime.InteropServices.COMException] -and $exception.HResult -eq -2147024894) {
                    $absent=$true;break
                }
                $exception=$exception.InnerException
            }
            if(-not $absent){throw}
        }
        if(-not $absent){throw 'Owned standard task remains registered'}
    } catch {$failure=$_}
    finally {
        foreach($reference in @($task,$folder,$scheduler)) {
            if($null -ne $reference) {
                try {& $ReleaseReference $reference|Out-Null}
                catch {if($null -eq $failure){$failure=$_}}
            }
        }
    }
    if($null -ne $failure){throw $failure}
}

function Assert-StandardLauncherAcknowledgment {
    param($Acknowledgment,$Binding,[string]$TaskName,[string]$BindingSha256)
    $members=@('schema','task_name','process_id','creation_file_time','binding_sha256')
    $names=@($Acknowledgment.PSObject.Properties.Name)
    if($names.Count -ne $members.Count -or @($names|Where-Object {$members -cnotcontains $_}).Count -ne 0 -or
        $Acknowledgment.schema -cne 'usk.publisher_standard_launcher_ack.v1' -or
        $Acknowledgment.task_name -cne $TaskName -or
        -not ($Acknowledgment.process_id -is [int] -or $Acknowledgment.process_id -is [long]) -or
        $Acknowledgment.process_id -le 0 -or $Acknowledgment.process_id -ne $Binding.process_id -or
        -not ($Acknowledgment.creation_file_time -is [string]) -or
        $Acknowledgment.creation_file_time -cne $Binding.creation_file_time -or
        $BindingSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Acknowledgment.binding_sha256 -cne $BindingSha256) {
        throw 'Owned launcher acknowledgment differs from its published start binding'
    }
}

function Wait-StandardLauncherAcknowledgment {
    param([string]$Path,$Binding,[string]$TaskName,[string]$BindingSha256,
        [int]$WaitMilliseconds=30000)
    if($WaitMilliseconds -lt 1 -or $WaitMilliseconds -gt 30000){throw 'Owned launcher acknowledgment wait exceeds bound'}
    $elapsed=[Diagnostics.Stopwatch]::StartNew()
    do {
        if([IO.File]::Exists($Path)) {
            if(([IO.FileInfo]::new($Path)).Length -gt 4096){throw 'Owned launcher acknowledgment exceeds byte bound'}
            $ack=[IO.File]::ReadAllText($Path)|ConvertFrom-Json
            Assert-StandardLauncherAcknowledgment $ack $Binding $TaskName $BindingSha256
            return
        }
        if($elapsed.ElapsedMilliseconds -ge $WaitMilliseconds){break}
        Start-Sleep -Milliseconds ([Math]::Min(25,[Math]::Max(1,$WaitMilliseconds-$elapsed.ElapsedMilliseconds)))
    } while($elapsed.ElapsedMilliseconds -lt $WaitMilliseconds)
    throw 'Owned launcher parent acknowledgment did not arrive within its bound'
}
