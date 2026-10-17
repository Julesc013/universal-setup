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

function Test-StandardLauncherTerminalObservation {
    param($Information,[bool]$Acknowledged,[bool]$ProcessExitConfirmed)
    # COM properties are sequential reads. A ready state can be read after
    # the earlier result still reported SCHED_S_TASK_RUNNING (WinError.h).
    # Keep polling that observation; every successful terminal still needs 0.
    return $Acknowledged -and $ProcessExitConfirmed -and $Information.LastRunTime.Year -gt 2000 -and
        $Information.State -in @('Ready','Disabled') -and $Information.LastTaskResult -ne 0x00041301
}

function Get-StandardLauncherCompletionDiagnostic {
    param($Information,[bool]$Acknowledged,$ProcessExitConfirmed)
    return [ordered]@{schema='usk.publisher_standard_launcher_completion_observation.v1';
        observation_source=$(if($Information){$Information.observation_source}else{$null});
        state=$(if($Information){$Information.State}else{$null});
        last_task_result=$(if($Information){$Information.LastTaskResult}else{$null});
        last_run_time=$(if($Information){$Information.LastRunTime.ToString('o')}else{$null});
        start_acknowledged=$Acknowledged;process_exit_confirmed=$ProcessExitConfirmed;
        atomic_snapshot=$false;qualification_granted=$false}
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
            }},
        [ValidateSet('SystemStandard','NamedController')][string]$ActorProfile='SystemStandard')
    $pattern=if($ActorProfile -ceq 'NamedController'){'^USK_ADMITTED_CONTROLLER_[0-9a-f]{32}$'}else{'^USK_STANDARD_PUBLIC_[0-9a-f]{32}$'}
    $expectedLogonType=if($ActorProfile -ceq 'NamedController'){1}else{5}
    if($TaskName -cnotmatch $pattern){throw 'Owned registered task name differs'}
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
            -not ($logonType -is [int]) -or $logonType -ne $expectedLogonType -or
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
            }},
        [ValidateSet('SystemStandard','NamedController')][string]$ActorProfile='SystemStandard')
    $pattern=if($ActorProfile -ceq 'NamedController'){'^USK_ADMITTED_CONTROLLER_[0-9a-f]{32}$'}else{'^USK_STANDARD_PUBLIC_[0-9a-f]{32}$'}
    if($TaskName -cnotmatch $pattern){throw 'Owned registered task name differs'}
    $scheduler=$null;$folder=$null;$task=$null;$failure=$null;$absent=$false
    try {
        $scheduler=& $CreateScheduler
        $scheduler.Connect()
        $folder=$scheduler.GetFolder('\')
        try {$task=$folder.GetTask($TaskName)}
        catch {
            $exception=$_.Exception
            for($depth=0;$exception -and $depth -lt 8;$depth++) {
                # PowerShell's COM binder can map this exact HRESULT to a
                # managed FileNotFoundException instead of COMException.
                if(($exception -is [Runtime.InteropServices.COMException] -or $exception -is [IO.FileNotFoundException]) -and
                    $exception.HResult -eq -2147024894) {
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

function Invoke-OwnedPublisherFixtureTask {
    param([string]$VhdPath,[string]$VolumeRoot,[string]$ServiceBinary,[string]$ServiceControlBinary,
        [string]$MachineBinary,[string]$OutputPath,[string]$LabRoot,
        [string]$DeviceAclBinary,[string]$PublicApplyBinary,[string]$ClientBinary,
        [ValidateSet('SystemStandard','NamedController')][string]$ActorProfile='SystemStandard',
        [switch]$IdentityProbe,[switch]$BootstrapProcessLoss,
        [switch]$BootstrapPreservationProcessLoss,[switch]$ActiveInstallContention,[switch]$StalePlanQualification,[switch]$InstallationGuardConflict,
        [string]$ConstructedBootstrapPrefix='none',[string]$ConstructedBootstrapDurableState='none',
        [switch]$MaintenanceQualification,[switch]$MaintenanceRecoveryQualification,[switch]$MaintenanceInitialQualification)
    # Both profiles use the same acknowledged process custody. Only the named
    # controller needs a generated account; the standard profile remains SYSTEM.
    $named=$ActorProfile -ceq 'NamedController'
    if($IdentityProbe -and -not $named){throw 'Identity probe requires the named controller profile'}
    if($named) {
        $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
            -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
            [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
            throw 'Named controller requires an administrative hosted disposable VM'
        }
        $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if($computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine') {
            throw 'Named controller requires the actual hosted virtual machine'
        }
        $temporary=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
        $owned=[IO.Path]::GetFullPath($LabRoot)
        if(-not $owned.StartsWith($temporary,[StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $owned) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or
            -not (Test-Path -LiteralPath $owned -PathType Container)) {
            throw 'Named controller requires its existing owned lab directory'
        }
        $ancestor=$owned
        while($ancestor) {
            if((Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Named controller lab ancestry contains a link'
            }
            $ancestor=Split-Path -Parent $ancestor
        }
        $labAcl=[Security.AccessControl.DirectorySecurity]::new()
        $labAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $labAcl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
            $labAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        Set-Acl -LiteralPath $owned -AclObject $labAcl -ErrorAction Stop
    }
    $taskName=$(if($named){'USK_ADMITTED_CONTROLLER_'}else{'USK_STANDARD_PUBLIC_'})+[guid]::NewGuid().ToString('N')
    $account=$null;$accountName=$null;$accountSid=$null;$password=$null;$secure=$null;$accountAttempted=$false
    $actorClosed=$false;$expectedSid='S-1-5-18';$actorOriginalError=$null
    if($named) {
        $script:controllerLauncherClosed=$false
        $script:controllerActorObservation=[ordered]@{profile=$ActorProfile;identity_only=[bool]$IdentityProbe;
            task_name=$taskName;
            account_name=$null;account_sid=$null;process_exit_confirmed=$false;
            task_removed=$false;account_removed=$false;account_retained=$false}
    }
    try {
    if($named) {
        $accountName='USKCTL_'+[guid]::NewGuid().ToString('N').Substring(0,13)
        if(Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue){throw 'Owned controller account collision'}
        $password='Aa1!'+[guid]::NewGuid().ToString('N')
        $secure=ConvertTo-SecureString $password -AsPlainText -Force
        $accountAttempted=$true
        $account=New-LocalUser -Name $accountName -Password $secure -PasswordNeverExpires -Description $taskName -ErrorAction Stop
        $accountSid=$account.SID.Value;$expectedSid=$accountSid
        $script:controllerActorObservation.account_name=$accountName
        $script:controllerActorObservation.account_sid=$accountSid
        if($accountSid -cnotmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)$' -or
            [uint64]$Matches[1] -lt 1000){throw 'Generated controller account class differs'}
        Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')) -Member $account -ErrorAction Stop
    }
    $script=Join-Path $LabRoot ($taskName+'.ps1')
    $startBinding=Join-Path $LabRoot ($taskName+'.started.json')
    $acknowledgment=Join-Path $LabRoot ($taskName+'.acknowledged.json')
    $launcherHelpers=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_publisher_standard_launcher.ps1'))
    $quote={param([string]$value) "'"+$value.Replace("'","''")+"'"}
    $probe=Join-Path $PSScriptRoot $(if($named){'windows_publisher_metadata_hosted_probe.ps1'}else{'windows_publisher_standard_public_probe.ps1'})
    $probeSha256=(Get-FileHash -LiteralPath $probe -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    $python=(Get-Command python -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
    if(-not [IO.Path]::IsPathRooted($python) -or -not [IO.File]::Exists($python)){throw 'Owned standard Python interpreter is unavailable'}
    $body=@('$ErrorActionPreference=''Stop''',
        '$env:GITHUB_ACTIONS=''true''', '$env:RUNNER_ENVIRONMENT=''github-hosted''',
        ('$env:RUNNER_TEMP='+(& $quote $env:RUNNER_TEMP)),
        '$identity=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
        ('if($identity -cne '+(& $quote $expectedSid)+'){throw ''Owned launcher identity differs''}'),
        $launcherHelpers,
        ('$startBinding='+(& $quote $startBinding)),
        ('$acknowledgment='+(& $quote $acknowledgment)),
        ('$taskName='+(& $quote $taskName)),
        '$process=Get-Process -Id $PID',
        '$binding=@{schema=''usk.publisher_standard_launcher.v1'';process_id=$PID;creation_file_time=$process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();identity=$identity;image=$process.Path}',
        '$pendingBinding=$startBinding+''.pending''',
        '$stream=[IO.File]::Open($pendingBinding,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)',
        'try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($binding|ConvertTo-Json -Compress));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose();$process.Dispose()}',
        ('Set-Acl -LiteralPath $pendingBinding -AclObject (Get-Acl -LiteralPath '+(& $quote $script)+')'),
        '[IO.File]::Move($pendingBinding,$startBinding)',
        '$bindingSha256=(Get-FileHash -LiteralPath $startBinding -Algorithm SHA256).Hash.ToLowerInvariant()',
        'Wait-StandardLauncherAcknowledgment $acknowledgment ([pscustomobject]$binding) $taskName $bindingSha256')
    if($named) {
        $body=$body[0..2]+@(
            ('$env:RUNNER_TEMP='+(& $quote $env:RUNNER_TEMP)),
            ('$env:PATH='+(& $quote $env:PATH)),
            ('$env:ProgramW6432='+(& $quote $env:ProgramW6432)),
            ('if((Get-Command python -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source -cne '+(& $quote $python)+'){throw ''Controller Python interpreter differs''}'),
            '$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()',
            'if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw ''Controller token is not elevated''}',
            '$groups=@((& whoami.exe /groups /fo csv /nh)|ConvertFrom-Csv -Header name,type,sid,attributes)',
            '$integrity=@($groups|Where-Object {$_.sid -cmatch ''^S-1-16-([0-9]+)$''})',
            'if($integrity.Count -ne 1 -or [uint32]($integrity[0].sid.Split(''-'')[-1]) -lt 12288){throw ''Controller token lacks high integrity''}')+
            $body[3..($body.Count-1)]
        $invoke=if($IdentityProbe){
            '[ordered]@{schema=''usk.publisher_controller_actor_probe.v1'';status=''passed'';scope=''identity_only_no_product_dispatch'';identity=$identity;administrator=$true;integrity_sid=$integrity[0].sid;client_cleanup_confirmed=$true}|ConvertTo-Json|Set-Content -LiteralPath '+(& $quote $OutputPath)+' -Encoding utf8'
        }else{
            'if((Get-FileHash -LiteralPath '+(& $quote $probe)+' -Algorithm SHA256).Hash.ToLowerInvariant() -cne '+(& $quote $probeSha256)+'){throw ''Controller fixture source changed''}; & '+
                (& $quote $probe)+' -VhdPath '+(& $quote $VhdPath)+' -VolumeRoot '+(& $quote $VolumeRoot)+
                ' -ServiceBinary '+(& $quote $ServiceBinary)+' -ServiceControlBinary '+(& $quote $ServiceControlBinary)+
                ' -DeviceAclBinary '+(& $quote $DeviceAclBinary)+' -MachineBinary '+(& $quote $MachineBinary)+
                ' -PublicApplyBinary '+(& $quote $PublicApplyBinary)+' -ClientBinary '+(& $quote $ClientBinary)+
                ' -OutputPath '+(& $quote $OutputPath)+' -ReviewedSource -RegisteredService -ControllerApply -ReuseRegistration -AdmittedTarget'
        }
        $body+=$invoke
    } else {
        $body+=('& '+(& $quote $probe)+' -VhdPath '+(& $quote $VhdPath)+' -VolumeRoot '+(& $quote $VolumeRoot)+
            ' -ServiceBinary '+(& $quote $ServiceBinary)+' -ServiceControlBinary '+(& $quote $ServiceControlBinary)+
            ' -MachineBinary '+(& $quote $MachineBinary)+' -OutputPath '+(& $quote $OutputPath)+' -PythonBinary '+(& $quote $python)+
            $(if($BootstrapProcessLoss){' -BootstrapProcessLoss'}else{''})+
            $(if($BootstrapPreservationProcessLoss){' -BootstrapPreservationProcessLoss'}else{''})+
            $(if($ActiveInstallContention){' -ActiveInstallContention'}else{''})+
            $(if($StalePlanQualification){' -StalePlanQualification'}else{''})+
            $(if($InstallationGuardConflict){' -InstallationGuardConflict'}else{''})+
            $(if($MaintenanceQualification){' -MaintenanceQualification'}else{''})+
            $(if($MaintenanceRecoveryQualification){' -MaintenanceRecoveryQualification'}else{''})+
            $(if($MaintenanceInitialQualification){' -MaintenanceInitialQualification'}else{''})+
            ' -ConstructedBootstrapPrefix '+(& $quote $ConstructedBootstrapPrefix)+
            ' -ConstructedBootstrapDurableState '+(& $quote $ConstructedBootstrapDurableState))
    }
    $body=$body -join "`n"
    $stream=[IO.File]::Open($script,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes($body);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $acl=[Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
    foreach($principalSid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principalSid),'FullControl','Allow'))
    }
    Set-Acl -LiteralPath $script -AclObject $acl
    $command='& '+(& $quote $script)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $taskImage=if($named){(Get-Command pwsh -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source}else{Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'}
    $taskArguments='-NoProfile -NonInteractive -EncodedCommand '+$encoded
    $action=New-ScheduledTaskAction -Execute $taskImage -Argument $taskArguments
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit $(if($named){
        New-TimeSpan -Seconds $(if($IdentityProbe){90}else{420})
    }else{New-TimeSpan -Minutes 15})
    $created=$false;$finished=$false;$launcherProcess=$null;$launcherBinding=$null;$launcherAcknowledged=$false;$info=$null
    $launcherPhase='register_task'
    $script:standardLauncherClosed=$false
    if($named){$script:controllerLauncherClosed=$false}
    $scriptSha256=(Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant()
    $assertOwnedTask={param($task)
        $principal=[Security.Principal.SecurityIdentifier]::new($expectedSid)
        try {$principal=[Security.Principal.SecurityIdentifier]::new([string]$task.Principal.UserId)}
        catch {$principal=[Security.Principal.NTAccount]::new([string]$task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier])}
        if($task.TaskName -cne $taskName -or $task.TaskPath -cne '\' -or $principal.Value -cne $expectedSid -or
            $task.Principal.RunLevel -ne 'Highest' -or @($task.Actions).Count -ne 1 -or
            $task.Actions[0].Execute -cne $taskImage -or $task.Actions[0].Arguments -cne $taskArguments -or
            $task.Actions[0].WorkingDirectory -or
            (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -cne $scriptSha256) {
            throw 'Owned SYSTEM standard task definition or protected wrapper changed'
        }
    }
    $recordUnconfirmed={param([string]$reason)
        $result=if(Test-Path -LiteralPath $OutputPath -PathType Leaf){
            Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json
        }else{[pscustomobject]@{}}
        $result=Update-StandardLauncherUnconfirmed $result $reason
        [IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 64 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    }
    try {
        if($named) {
            Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Settings $settings `
                -User ($env:COMPUTERNAME+'\'+$accountName) -Password $password -RunLevel Highest -ErrorAction Stop|Out-Null
            $password=$null
        } else {
            Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Settings $settings -User SYSTEM -RunLevel Highest -ErrorAction Stop|Out-Null
        }
        $created=$true
        $launcherPhase='start_task'
        $null=Read-StandardRegisteredTaskInformation -ActorProfile $ActorProfile -TaskName $taskName -RevalidateTask $assertOwnedTask
        Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
        $launcherPhase='observe_task'
        $deadline=[DateTime]::UtcNow.AddMinutes(12)
        $elapsed=[Diagnostics.Stopwatch]::StartNew()
        $waitMilliseconds=if($IdentityProbe){90000}else{420000}
        do {
            $info=Read-StandardRegisteredTaskInformation -ActorProfile $ActorProfile -TaskName $taskName -RevalidateTask $assertOwnedTask
            if(-not $launcherProcess -and (Test-Path -LiteralPath $startBinding -PathType Leaf)) {
                $launcherPhase='read_start_binding'
                if((Get-Item -LiteralPath $startBinding).Length -gt 4096){throw 'Owned launcher start binding exceeds bound'}
                $launcherBinding=Get-Content -LiteralPath $startBinding -Raw|ConvertFrom-Json
                if($launcherBinding.schema -cne 'usk.publisher_standard_launcher.v1' -or
                    $launcherBinding.identity -cne $expectedSid -or $launcherBinding.image -cne $taskImage -or
                    $launcherBinding.process_id -le 0 -or $launcherBinding.creation_file_time -cnotmatch '^[1-9][0-9]{16,18}$') {
                    throw 'Owned launcher start identity differs'
                }
                $launcherPhase='acquire_launcher_custody'
                $launcherProcess=Get-Process -Id $launcherBinding.process_id -ErrorAction Stop;$null=$launcherProcess.Handle
                if($launcherProcess.Path -cne $taskImage -or
                    $launcherProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -cne $launcherBinding.creation_file_time -or
                    $launcherProcess.HasExited) {
                    throw 'Held owned launcher process identity differs'
                }
                if($named) {
                    $nativeProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$launcherBinding.process_id) -ErrorAction Stop
                    $nativeOwner=Invoke-CimMethod -InputObject $nativeProcess -MethodName GetOwnerSid -ErrorAction Stop
                    if($nativeOwner.ReturnValue -ne 0 -or $nativeOwner.Sid -cne $expectedSid -or $launcherProcess.HasExited) {
                        throw 'Held controller process native account differs'
                    }
                    $script:controllerActorObservation['native_process_sid']=$nativeOwner.Sid
                }
                $launcherPhase='acknowledge_launcher_custody'
                $null=Read-StandardRegisteredTaskInformation -ActorProfile $ActorProfile -TaskName $taskName -RevalidateTask $assertOwnedTask
                $ack=[ordered]@{schema='usk.publisher_standard_launcher_ack.v1';task_name=$taskName;
                    process_id=$launcherBinding.process_id;creation_file_time=$launcherBinding.creation_file_time;
                    binding_sha256=(Get-FileHash -LiteralPath $startBinding -Algorithm SHA256).Hash.ToLowerInvariant()}
                $pendingAcknowledgment=$acknowledgment+'.pending'
                $ackStream=[IO.File]::Open($pendingAcknowledgment,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try {$ackBytes=[Text.UTF8Encoding]::new($false).GetBytes(($ack|ConvertTo-Json -Compress));$ackStream.Write($ackBytes,0,$ackBytes.Length);$ackStream.Flush($true)}
                finally {$ackStream.Dispose()}
                Set-Acl -LiteralPath $pendingAcknowledgment -AclObject $acl
                [IO.File]::Move($pendingAcknowledgment,$acknowledgment)
                $launcherAcknowledged=$true
                $launcherPhase='observe_launcher_exit'
            }
            $processExited=$launcherProcess -and $launcherProcess.HasExited
            if(Test-StandardLauncherTerminalObservation $info $launcherAcknowledged $processExited) {$finished=$true;break}
            if($named -and -not $launcherAcknowledged -and $elapsed.ElapsedMilliseconds -ge 30000) {
                throw 'Controller startup was not acknowledged within30seconds'
            }
            Start-Sleep -Milliseconds 100
        } while($(if($named){$elapsed.ElapsedMilliseconds -lt $waitMilliseconds}else{[DateTime]::UtcNow -lt $deadline}))
        if(-not $finished -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
            # Keep ownership unconfirmed; outer cleanup must retain backing
            # storage until runner disposal if any client might still be live.
            & $recordUnconfirmed 'owned SYSTEM standard task completion is unconfirmed'
            throw 'Owned SYSTEM standard task did not complete with a receipt'
        }
        if($info.LastTaskResult -ne 0){throw 'Owned SYSTEM standard fixture failed; retained receipt contains its failure'}
    } catch {
        $originalLauncherError=$_
        if($named){$actorOriginalError=$originalLauncherError}
        & $recordUnconfirmed 'owned SYSTEM standard launcher failed; original diagnostic retained'
        $failedResult=Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json
        $diagnostic=Get-StandardLauncherErrorDiagnostic $originalLauncherError $launcherPhase
        $failedResult|Add-Member -NotePropertyName launcher_error -NotePropertyValue $diagnostic -Force
        $processExited=$null
        try {if($launcherProcess){$processExited=$launcherProcess.HasExited}} catch {}
        $completion=Get-StandardLauncherCompletionDiagnostic $info $launcherAcknowledged $processExited
        $failedResult|Add-Member -NotePropertyName launcher_completion_observation -NotePropertyValue $completion -Force
        [IO.File]::WriteAllText($OutputPath,($failedResult|ConvertTo-Json -Depth 64 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
        throw
    } finally {
        if($created -and $finished) {
            try {
                $launcherPhase='revalidate_task_before_removal'
                $null=Read-StandardRegisteredTaskInformation -ActorProfile $ActorProfile -TaskName $taskName -RevalidateTask $assertOwnedTask
                $launcherPhase='unregister_owned_task'
                Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
                $launcherPhase='confirm_owned_task_absence'
                Assert-StandardRegisteredTaskAbsent -ActorProfile $ActorProfile -TaskName $taskName
                if($named) {
                    $actorClosed=$true
                    $script:controllerActorObservation.process_exit_confirmed=$true
                    $script:controllerActorObservation.task_removed=$true
                }
            } catch {
                $originalRemovalError=$_
                & $recordUnconfirmed 'owned SYSTEM standard task removal is unconfirmed'
                $failedResult=Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json
                $diagnostic=Get-StandardLauncherErrorDiagnostic $originalRemovalError $launcherPhase
                $failedResult|Add-Member -NotePropertyName launcher_removal_error -NotePropertyValue $diagnostic -Force
                [IO.File]::WriteAllText($OutputPath,($failedResult|ConvertTo-Json -Depth 64 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
                if($named -and $actorOriginalError) {
                    $script:controllerActorObservation['launcher_cleanup_failure']=$originalRemovalError.Exception.Message
                } else {throw $originalRemovalError}
            }
        }
        if(-not $finished){& $recordUnconfirmed 'owned SYSTEM launcher termination is unconfirmed'}
        if($launcherProcess){$launcherProcess.Dispose()}
    }
    $result=Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json
    $result|Add-Member -NotePropertyName launcher_task_removed -NotePropertyValue $true
    $result|Add-Member -NotePropertyName launcher_task_result -NotePropertyValue ([uint32]$info.LastTaskResult)
    $result|Add-Member -NotePropertyName launcher_information_source -NotePropertyValue $info.observation_source
    $result|Add-Member -NotePropertyName launcher_task -NotePropertyValue $taskName
    $result|Add-Member -NotePropertyName launcher_process -NotePropertyValue $launcherBinding
    $result|Add-Member -NotePropertyName launcher_process_exit_confirmed -NotePropertyValue $true
    $result|Add-Member -NotePropertyName launcher_start_acknowledged -NotePropertyValue $launcherAcknowledged
    [IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 64 -Compress)+"`n",[Text.UTF8Encoding]::new($false))
    $script:standardLauncherClosed=$true
    } catch {
        if($named -and $actorOriginalError){throw $actorOriginalError}
        $actorOriginalError=$_;throw
    } finally {
        $password=$null
        if($null -ne $secure){$secure.Dispose();$secure=$null}
        if($named -and $accountAttempted) {
            $script:controllerLauncherClosed=$actorClosed
            try {
                $result=if(Test-Path -LiteralPath $OutputPath -PathType Leaf){Get-Content -LiteralPath $OutputPath -Raw|ConvertFrom-Json}else{$null}
                $retired=$actorClosed -and $result -and $(if($IdentityProbe){
                    $result.schema -ceq 'usk.publisher_controller_actor_probe.v1' -and
                        $result.scope -ceq 'identity_only_no_product_dispatch' -and $result.status -ceq 'passed'
                }else{
                    [object]::Equals($result.service_removed,$true) -and
                        [object]::Equals($result.protected_service_binary_removed,$true) -and
                        [object]::Equals($result.client_cleanup_confirmed,$true) -and -not $result.retirement_cleanup_failure
                })
                if($retired -and $accountSid) {
                    $current=Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($accountSid)) -ErrorAction Stop
                    if($current.Name -cne $accountName -or $current.Description -cne $taskName){throw 'Owned controller account identity changed'}
                    Remove-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($accountSid)) -ErrorAction Stop
                    if(Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($accountSid)) -ErrorAction SilentlyContinue){throw 'Owned controller account remains'}
                    $script:controllerActorObservation.account_removed=$true
                } else {$script:controllerActorObservation.account_retained=$true}
            } catch {
                $script:controllerActorObservation.account_retained=$true
                $script:controllerActorObservation['account_cleanup_failure']=$_.Exception.Message
                if(-not $actorOriginalError){throw}
            }
        }
    }
}
