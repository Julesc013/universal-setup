# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Inert flow controls for product-owned fault preparation; no SCM/ACL/VHD effects."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("USK_FAULT_PREPARATION_TEST_SOURCE",
                              ROOT / "tests/windows_publisher_metadata_hosted_probe.ps1"))
SHELLS = tuple(dict.fromkeys(filter(None, (shutil.which("powershell"), shutil.which("pwsh")))))
COMMON = r'''
param([string]$Source)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Actual fixture parse failed'}
'''
ROUTES = COMMON + r'''
$parts=@('$registeredFaultService','$deviceMode','$expectedDeviceAdmission')|ForEach-Object {
    $name=$_
    $found=@($ast.FindAll({param($n)
        $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -ceq $name},$true))
    if($found.Count -ne 1){throw ('Actual assignment differs: '+$name)}
    [scriptblock]::Create($found[0].Extent.Text)
}
$call=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.IfStatementAst] -and
    $n.Clauses[0].Item1.Extent.Text -ceq '$registeredFaultService' -and
    $n.Clauses[0].Item2.Extent.Text.Contains('Initialize-RegisteredFaultDeviceWithProduct')},$true))
if($call.Count -ne 1){throw 'Actual fault preparation call differs'}
$invoke=[scriptblock]::Create($call[0].Extent.Text)
function Initialize-RegisteredFaultDeviceWithProduct {$script:Calls++}
foreach($registered in @($false,$true)) {
 foreach($bits in 0..7) {
    $RegisteredService=$registered;$AdmittedTarget=$false
    $InterruptAfterStage=[bool]($bits-band 1)
    $HostileRights=[bool]($bits-band 2)
    $TerminateAtPostrename=[bool]($bits-band 4)
    $script:Calls=0
    . $parts[0];. $invoke;. $parts[1];. $parts[2]
    $fault=$registered -and $bits -ne 0
    if($registeredFaultService -ne $fault -or $script:Calls -ne [int]$fault){
        throw 'Fault predicate or preparation membership changed'
    }
    $mode=if($fault){'--observe-owned-hosted-vm-vhd-volume'}
        elseif($registered){'--observe-owned-hosted-vm-pre-admission-volume'}
        else{'--owned-hosted-vm-vhd-volume'}
    $admission=if($fault){'hosted_vm_read_only'}
        elseif($registered){'hosted_vm_pre_admission_read_only'}else{'hosted_vm'}
    if($deviceMode -cne $mode -or $expectedDeviceAdmission -cne $admission){
        throw 'Device helper route changed beyond registered fault preparation'
    }
 }
}
$RegisteredService=$true;$AdmittedTarget=$true
$InterruptAfterStage=$false;$HostileRights=$false;$TerminateAtPostrename=$false;$script:Calls=0
. $parts[0];. $invoke;. $parts[1];. $parts[2]
if($script:Calls -ne 0 -or $deviceMode -cne '--observe-owned-hosted-vm-vhd-volume' -or
    $expectedDeviceAdmission -cne 'hosted_vm_read_only'){throw 'Admitted mode changed'}
'actual fault routing matrix passed'
'''
FLOW = COMMON + r'''
$f=@($ast.FindAll({param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -ceq 'Initialize-RegisteredFaultDeviceWithProduct'},$true))
if($f.Count -ne 1){throw 'Actual preparation helper differs'}
. ([scriptblock]::Create($f[0].Extent.Text))
$service='USK_PUB_inert';$ServiceBinary='C:\inert\service.exe'
$expectedRegisteredCommand='"C:\inert\service.exe" --service USK_PUB_inert --no-receipt'
$drive='Z:\';$nativePath='C:\inert\never-created.json'
$registeredFaultService=$true;$AdmittedTarget=$false;$script:controllerPending=$false
$birth=[DateTime]::SpecifyKind([DateTime]'2026-01-01',[DateTimeKind]::Utc)
function Assert-OwnedVolume {
    $script:Events.Add('volume')
    if($script:Mode -ceq 'volume_after' -and $script:Phase -ceq 'stopped'){throw 'inert changed volume'}
}
function Test-Path {
    param([string]$LiteralPath)
    return (($script:Mode -ceq 'namespace_before' -and $script:Phase -ceq 'before') -or
        ($script:Mode -ceq 'namespace_after' -and $script:Phase -ceq 'stopped'))
}
function Start-RegisteredPublisher {
    $script:Events.Add('product_start')
    if($script:Mode -ceq 'admission_failure'){throw 'inert native admission refusal'}
    $script:Phase='running'
}
function Get-CimInstance {
    param([string]$ClassName,[string]$Filter)
    if($ClassName -ceq 'Win32_Process'){
        return [pscustomobject]@{ProcessId=$(if($script:Mode -ceq 'row_pid_changed'){9200}else{9100});CreationDate=$birth;CommandLine=$expectedRegisteredCommand;ExecutablePath=$ServiceBinary}
    }
    if($ClassName -cne 'Win32_Service'){throw 'Unexpected inert query'}
    $script:ServiceQueries++
    if($script:Phase -ceq 'before'){
        return [pscustomobject]@{State='Stopped';ProcessId=0;PathName=$expectedRegisteredCommand}
    }
    if($script:Phase -ceq 'running' -or $script:Mode -ceq 'scm_stop_unknown'){
        $command=if($script:Mode -ceq 'command_changed'){'changed'}else{$expectedRegisteredCommand}
        return [pscustomobject]@{State='Running';ProcessId=$(if($script:Mode -ceq 'scm_binding_changed' -and $script:ServiceQueries -eq 3){9200}else{9100});PathName=$command}
    }
    return [pscustomobject]@{State='Stopped';ProcessId=0;PathName=$expectedRegisteredCommand}
}
function Get-Process {
    param([int]$Id)
    $script:Events.Add('hold_instance')
    if($Id -ne 9100){throw 'Wrong inert PID'}
    $date=if($script:Mode -ceq 'birth_changed'){$birth.AddSeconds(3)}else{$birth}
    $image=if($script:Mode -ceq 'image_changed'){'C:\inert\other.exe'}else{$ServiceBinary}
    $fake=[pscustomobject]@{Id=$(if($script:Mode -ceq 'pid_changed'){9200}else{9100});Handle=[IntPtr]1;HasExited=($script:Mode -ceq 'already_exited');
        StartTime=$date;MainModule=[pscustomobject]@{FileName=$image}}
    $fake|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
        param([int]$Milliseconds)
        $script:Events.Add('wait_instance')
        if($Milliseconds -ne 30000){throw 'Stop wait contract changed'}
        return $script:Mode -cnotin @('wait_unknown','wait_and_dispose_failure')
    }
    $fake|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $script:Events.Add('dispose_instance')
        if($script:Mode -cin @('dispose_failure','wait_and_dispose_failure')){throw 'inert dispose uncertainty'}
    }
    return $fake
}
function Stop-Service {
    param([string]$Name)
    $script:Events.Add('stop_service')
    if($Name -cne $service){throw 'Wrong inert service'}
    if($script:Mode -ceq 'stop_failure'){throw 'inert stop refusal'}
    $script:Phase='stopped'
}
foreach($mode in @('success','namespace_before','admission_failure','command_changed',
    'already_exited','birth_changed','image_changed','stop_failure','wait_unknown',
    'scm_stop_unknown','namespace_after','volume_after','pid_changed','row_pid_changed',
    'scm_binding_changed','dispose_failure','wait_and_dispose_failure')) {
    $script:Mode=$mode;$script:Phase='before';$script:ServiceQueries=0
    $script:Events=[Collections.Generic.List[string]]::new()
    $receipt=[ordered]@{};$caught=$false
    try{Initialize-RegisteredFaultDeviceWithProduct}catch{$caught=$true}
    $p=$receipt.registered_fault_device_preparation
    if($null -eq $p -or $p.client_dispatched -ne $false -or
        @($script:Events|Where-Object {$_ -ceq 'product_start'}).Count -gt 1 -or
        @($script:Events|Where-Object {$_ -ceq 'stop_service'}).Count -gt 1){
        throw 'Preparation lost uncertainty or repeated a native action'
    }
    $held=@($script:Events|Where-Object {$_ -ceq 'hold_instance'}).Count
    $disposed=@($script:Events|Where-Object {$_ -ceq 'dispose_instance'}).Count
    if($held -ne $disposed){throw 'Inert held instance was not released'}
    if($mode -ceq 'success'){
        if($caught -or $p.status -cne 'admitted_stopped_without_request' -or
            -not $p.stop_requested -or -not $p.process_exit_confirmed -or
            -not $p.scm_stopped_confirmed -or -not $p.namespace_unchanged -or
            $p.service_process_id -ne 9100 -or
            $p.service_creation_file_time -cne $birth.ToFileTimeUtc().ToString()){
            throw 'Successful inert control lost its required closure facts'
        }
        if(($script:Events -join '|') -cne 'volume|product_start|hold_instance|stop_service|wait_instance|volume|dispose_instance'){
            throw 'Preparation order changed'
        }
    } elseif(-not $caught -or $p.status -cne 'failed' -or -not $p.failure -or ($p.namespace_unchanged -and $mode -cne 'dispose_failure')){
        throw ('Failed preparation became usable: '+$mode)
    }
    if($mode -in @('already_exited','birth_changed','image_changed','command_changed','pid_changed','row_pid_changed','scm_binding_changed') -and
        $script:Events.Contains('stop_service')){throw 'Changed identity reached cooperative stop'}
    if($mode -ceq 'wait_and_dispose_failure' -and
        ($p.failure -cne 'Product fault preparation process did not stop' -or -not $p.dispose_failure)){
        throw 'Dispose uncertainty suppressed the original failure'
    }
}
foreach($invalid in @('not_fault','admitted','controller_pending')){
    $registeredFaultService=$invalid -cne 'not_fault';$AdmittedTarget=$invalid -ceq 'admitted'
    $script:controllerPending=$invalid -ceq 'controller_pending'
    $receipt=[ordered]@{};$script:Events.Clear();$caught=$false
    try{Initialize-RegisteredFaultDeviceWithProduct}catch{$caught=$true}
    if(-not $caught -or $receipt.Count -ne 0 -or $script:Events.Count -ne 0){
        throw 'Ineligible preparation reached native activity'
    }
}
'actual preparation flow controls passed with inert facades only'
'''


@unittest.skipUnless(SHELLS, "PowerShell is unavailable")
class PublisherFaultProductPreparationTests(unittest.TestCase):
    def run_control(self, script, shell):
        with tempfile.TemporaryDirectory(prefix="usk-fault-preparation-") as temp:
            path = Path(temp) / "control.ps1"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(
                [shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                 "Bypass", "-File", str(path), "-Source", str(SOURCE)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout[-2000:] + result.stderr[-4000:])

    def test_actual_fault_device_routes_preserve_other_profiles(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                self.run_control(ROUTES, shell)

    def test_actual_product_preparation_keeps_failed_closure_sticky(self):
        for shell in SHELLS:
            with self.subTest(shell=shell):
                self.run_control(FLOW, shell)

