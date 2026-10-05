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
    $exception=$ErrorRecord.Exception;$nativeCode=$null
    for($depth=0;$exception -and $depth -lt 8;$depth++) {
        if($exception -is [ComponentModel.Win32Exception]){$nativeCode=$exception.NativeErrorCode;break}
        $exception=$exception.InnerException
    }
    $message=[string]$ErrorRecord.Exception.Message;$stack=[string]$ErrorRecord.ScriptStackTrace
    return [ordered]@{phase=$Phase;exception_type=$ErrorRecord.Exception.GetType().FullName;
        hresult=$ErrorRecord.Exception.HResult;native_error_code=$nativeCode;
        message_excerpt=$message.Substring(0,[Math]::Min(2048,$message.Length));
        script_name=$ErrorRecord.InvocationInfo.ScriptName;script_line=$ErrorRecord.InvocationInfo.ScriptLineNumber;
        stack_excerpt=$stack.Substring(0,[Math]::Min(4096,$stack.Length))}
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
