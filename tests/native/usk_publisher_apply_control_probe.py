# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Changed registered requests must refuse before starting an SCM service."""

from __future__ import annotations

import hashlib
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


def write_json(path: Path, value: dict) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def verify_fixture_retention(repository: Path, root: Path) -> None:
    # Execute the fixtures' actual catch/finally blocks. Replace only disk and
    # process effects: no VHD, mount, service or administrator token is needed.
    driver = root / "fixture-retention.ps1"
    driver.write_text(r'''
param([string]$Repository,[string]$Scratch)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
function Read-OuterTry([string]$Name) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Repository ('tests\'+$Name)),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Fixture parse failed'}
    $tries=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally})
    if(-not $tries.Count){throw 'Fixture outer cleanup is missing'}
    return $tries[-1]
}
function Read-Block($Block) {
    $source=$Block.Extent.Text
    return [scriptblock]::Create($source.Substring(1,$source.Length-2))
}
# Exercise the real observer ACL setup with Windows descriptors, without
# changing filesystem permissions. SYSTEM is also the runner in one profile.
& {
    $tokens=$null;$errors=$null
    $metadataAst=[Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Repository 'tests\windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Observer ACL fixture parse failed'}
    $statements=@($metadataAst.EndBlock.Statements)
    $runnerIndex=@(0..($statements.Count-1)|Where-Object {
        $statements[$_] -is [Management.Automation.Language.AssignmentStatementAst] -and
        $statements[$_].Left.Extent.Text -ceq '$runnerSid'})
    $receiptIndex=@(0..($statements.Count-1)|Where-Object {
        $statements[$_] -is [Management.Automation.Language.AssignmentStatementAst] -and
        $statements[$_].Left.Extent.Text -ceq '$receipt'})
    if($runnerIndex.Count -ne 1 -or $receiptIndex.Count -ne 1 -or
        $receiptIndex[0] -le $runnerIndex[0]+1){throw 'Observer ACL setup missing or ambiguous'}
    $setup=[scriptblock]::Create(($statements[($runnerIndex[0]+1)..($receiptIndex[0]-1)]|
        ForEach-Object {$_.Extent.Text}) -join "`n")
    $observerRoot='in-memory-observer-acl-only'
    $namedSid='S-1-5-21-101-102-103-1001';$unexpectedSid='S-1-5-32-545'
    function Set-Acl([string]$LiteralPath,[Security.AccessControl.DirectorySecurity]$AclObject) {
        if($LiteralPath -cne $observerRoot){throw 'Unexpected observer ACL write'}
        $script:observerAclWrites++
        $script:storedObserverAcl=[Security.AccessControl.DirectorySecurity]::new()
        $script:storedObserverAcl.SetSecurityDescriptorBinaryForm($AclObject.GetSecurityDescriptorBinaryForm())
    }
    function Get-Acl([string]$LiteralPath) {
        if($LiteralPath -cne $observerRoot){throw 'Unexpected observer ACL read'}
        $script:observerAclReads++
        $acl=$script:storedObserverAcl
        switch($case) {
            'missing_system' {$acl.PurgeAccessRules([Security.Principal.SecurityIdentifier]'S-1-5-18')}
            'missing_runner' {$acl.PurgeAccessRules([Security.Principal.SecurityIdentifier]$runnerSid)}
            'extra' {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]$unexpectedSid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
            'rights' {$acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]$runnerSid,'Read','ContainerInherit,ObjectInherit','None','Allow'))}
            'inheritance' {$acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]$runnerSid,'FullControl','ContainerInherit','None','Allow'))}
            'propagation' {$acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]$runnerSid,'FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow'))}
            'deny' {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]$runnerSid,'FullControl','ContainerInherit,ObjectInherit','None','Deny'))}
            'unprotected' {$acl.SetAccessRuleProtection($false,$true)}
            'owner' {$acl.SetOwner([Security.Principal.SecurityIdentifier]$unexpectedSid)}
            'inherited_extra' {$acl.SetSecurityDescriptorSddlForm(
                $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)+
                '(A;OICIID;FA;;;'+$unexpectedSid+')')}
            'inherited_runner' {$acl.SetSecurityDescriptorSddlForm(
                $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)+
                '(A;OICIID;FA;;;'+$runnerSid+')')}
        }
        if($case -in @('inherited_extra','inherited_runner') -and
            (-not $acl.AreAccessRulesProtected -or
                @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|
                    Where-Object {$_.IsInherited}).Count -ne 1)) {
            throw 'Inherited observer ACL fixture did not reach its intended boundary'
        }
        return $acl
    }
    foreach($case in @('system','named','missing_system','missing_runner','extra',
        'rights','inheritance','propagation','deny','unprotected','owner','inherited_extra','inherited_runner')) {
        $runnerSid=if($case -ceq 'system'){'S-1-5-18'}else{$namedSid}
        $script:observerAclWrites=0;$script:observerAclReads=0;$caught=$null
        try {. $setup} catch {$caught=$_}
        $accept=$case -in @('system','named')
        if($script:observerAclWrites -ne 1 -or $script:observerAclReads -ne 1 -or
            (($null -eq $caught) -ne $accept)) {
            throw ('Observer ACL protection differs: '+$case+'; '+$caught.Exception.Message)
        }
        if(-not $accept -and $caught.Exception.Message -cne
            'Owned SYSTEM observer output directory has an unexpected ACL') {
            throw ('Observer ACL control failed at the wrong boundary: '+$case)
        }
    }
}
function Get-DiskImage([string]$ImagePath,[object]$ErrorAction) {
    if($ImagePath -cne $vhd){throw 'Unexpected cleanup image'}
    $script:imageQueries++
    return [pscustomobject]@{Attached=$true}
}
function Dismount-DiskImage([string]$ImagePath,[object]$ErrorAction) {
    if($ImagePath -cne $vhd){throw 'Unexpected dismount image'}
    $script:dismountCalls++
}
function Remove-Item([string]$LiteralPath,[switch]$Force,[object]$ErrorAction) {
    if($LiteralPath -cne $vhd){throw 'Unexpected deletion target'}
    $script:deleteCalls++
    [IO.File]::Delete($LiteralPath)
}
$outer=Read-OuterTry 'windows_publisher_lab_probe.ps1'
$cleanup=Read-Block $outer.Finally
$vhd=Join-Path $Scratch 'cleanup-owned-vhd-sentinel.vhdx'
$out=Join-Path $Scratch 'cleanup-receipt.json'
$PublicStandardClient=$false;$standardLauncherClosed=$true;$mounted=$true
$cases=@(
    @{name='missing';observation=$null;retain=$true},
    @{name='service';observation=@{service_removed=$false};retain=$true},
    @{name='binary';observation=@{service_removed=$true;client_cleanup_confirmed=$true};retain=$true},
    @{name='client';observation=@{service_removed=$true;protected_service_binary_removed=$true};retain=$true},
    @{name='untyped';observation=@{service_removed='true';protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$true},
    @{name='refused';observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true;retirement_cleanup_failure='refused'};retain=$true},
    @{name='launcher';observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$true;launcher_closed=$false},
    @{name='packaged_launcher';packaged=$true;observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$true;launcher_closed=$false},
    @{name='packaged_confirmed';packaged=$true;observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$false},
    @{name='confirmed';observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$false},
    @{name='legacy';observation=$null;retain=$false})
foreach($case in $cases) {
    [IO.File]::WriteAllText($vhd,'owned cleanup sentinel')
    $script:imageQueries=0;$script:dismountCalls=0;$script:deleteCalls=0
    $AdmittedTarget=$case.name -cne 'legacy';$failure=$null
    $controllerLauncherClosed=-not $case.ContainsKey('launcher_closed') -or $case.launcher_closed
    $admittedPackagedProfile=$case.ContainsKey('packaged') -and $case.packaged
    $admittedControllerProfile=-not $admittedPackagedProfile
    $standardLauncherClosed=-not $case.ContainsKey('launcher_closed') -or $case.launcher_closed
    $receipt=[ordered]@{status='fixture_body_passed';service_observation=$case.observation}
    . $cleanup
    $retained=Test-Path -LiteralPath $vhd -PathType Leaf
    if($case.retain) {
        if(-not $retained -or $script:imageQueries -or $script:dismountCalls -or $script:deleteCalls -or
            -not $failure -or $receipt.status -cne 'failed') {
            throw ('Unconfirmed retirement reached VHD cleanup: '+$case.name)
        }
    } elseif($retained -or $script:imageQueries -ne 1 -or $script:dismountCalls -ne 1 -or
        $script:deleteCalls -ne 1 -or $failure) {
        throw ('Confirmed or legacy cleanup changed: '+$case.name)
    }
}
# The original failure must survive a second exception in real client cleanup.
function Stop-OwnedPublisherProcessTree($Process) {throw 'synthetic client cleanup failure'}
$inner=Read-OuterTry 'windows_publisher_metadata_hosted_probe.ps1'
$primaryCatch=Read-Block $inner.CatchClauses[0].Body
$innerCleanup=Read-Block $inner.Finally
$AdmittedTarget=$true;$RegisteredService=$false;$registrationAttempted=$false;$created=$false
$consumerCreated=$false;$unrelatedAccountCreated=$false;$clientCleanupConfirmed=$true
$requestClient=[pscustomobject]@{process='owned fixture process'}
$consumerProcess=$null;$concurrentAttacker=$null;$unrelatedAttacker=$null;$preopenedRootProcess=$null
$stageObserver=$null;$postrenameObserver=$null
$observerRoot=Join-Path $Scratch 'nonexistent-observer-root'
$receipt=[ordered]@{status='pending'};$failure=$null
try {throw 'synthetic primary request failure'} catch {. $primaryCatch}
. $innerCleanup
if($failure -cne 'synthetic primary request failure' -or
    $receipt.primary_failure -cne $failure -or $receipt.failure -cne $failure -or
    $receipt.cleanup_failure -cne 'Owned client cleanup failed: synthetic client cleanup failure' -or
    $receipt.client_cleanup_confirmed -ne $false -or $receipt.status -cne 'failed') {
    throw 'Client cleanup obscured the primary request failure'
}
# Execute the account finalizer itself, with inert account effects. A closed
# launcher alone cannot retire an account still bound to product authority.
$tokens=$null;$errors=$null
$helperAst=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Repository 'tests\windows_publisher_standard_launcher.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Launcher parse failed'}
$actorFunction=$helperAst.Find({param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -ceq 'Invoke-OwnedPublisherFixtureTask'},$false)
$actorTries=@($actorFunction.Body.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally})
if($actorTries.Count -ne 1){throw 'Owned account finalizer is missing or ambiguous'}
$accountCleanup=Read-Block $actorTries[0].Finally
function Get-LocalUser($SID,$ErrorAction) {
    if($script:accountReadFailure){throw 'synthetic account cleanup failure'}
    if($script:accountPresent){return [pscustomobject]@{Name=$accountName;Description=('USKCTL:'+('a'*32))}}
}
function Remove-LocalUser($SID,$ErrorAction) {$script:accountDeletes++;$script:accountPresent=$false}
$named=$true;$accountAttempted=$true;$accountSid='S-1-5-21-1-2-3-1001'
$accountName='USKCTL_fixture';$taskName='USK_ADMITTED_CONTROLLER_'+('a'*32)
$OutputPath=Join-Path $Scratch 'actor-child.json';$secure=$null
$cases=@(
    @{name='live';closed=$false;state=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};remove=$false},
    @{name='authority';closed=$true;state=@{service_removed=$false;client_cleanup_confirmed=$true};remove=$false},
    @{name='binary';closed=$true;state=@{service_removed=$true;client_cleanup_confirmed=$true};remove=$false},
    @{name='untyped';closed=$true;state=@{service_removed='true';protected_service_binary_removed=$true;client_cleanup_confirmed=$true};remove=$false},
    @{name='retired';closed=$true;state=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};remove=$true},
    @{name='probe';closed=$true;probe=$true;state=@{schema='usk.publisher_controller_actor_probe.v1';scope='identity_only_no_product_dispatch';status='passed'};remove=$true},
    @{name='wrong_scope';closed=$true;probe=$true;state=@{schema='usk.publisher_controller_actor_probe.v1';scope='product_dispatch';status='passed'};remove=$false})
foreach($case in $cases) {
    $case.state|ConvertTo-Json|Set-Content -LiteralPath $OutputPath -Encoding utf8
    $actorClosed=$case.closed;$IdentityProbe=[bool]$case.probe;$actorOriginalError=$null
    $script:accountReadFailure=$false;$script:accountPresent=$true;$script:accountDeletes=0
    $controllerActorObservation=[ordered]@{account_removed=$false;account_retained=$false}
    . $accountCleanup
    if(($script:accountDeletes -eq 1) -ne $case.remove -or
        $controllerActorObservation.account_removed -ne $case.remove -or
        $controllerActorObservation.account_retained -eq $case.remove) {
        throw ('Owned controller account retirement differs: '+$case.name)
    }
}
$IdentityProbe=$false;$actorClosed=$true
@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true}|
    ConvertTo-Json|Set-Content -LiteralPath $OutputPath -Encoding utf8
try {throw 'original actor failure'} catch {$actorOriginalError=$_}
$script:accountReadFailure=$true;$script:accountDeletes=0
$controllerActorObservation=[ordered]@{account_removed=$false;account_retained=$false}
. $accountCleanup
if($script:accountDeletes -or -not $controllerActorObservation.account_retained -or
    $controllerActorObservation.account_cleanup_failure -cne 'synthetic account cleanup failure' -or
    $actorOriginalError.Exception.Message -cne 'original actor failure') {
    throw 'Account cleanup erased original failure or removed an uncertain account'
}
# Execute the actual configured-caller cleanup statements. Account and usable
# credentials survive an uncertain owned retirement or incomplete client closure.
$inner=Read-OuterTry 'windows_publisher_metadata_hosted_probe.ps1'
$callerStatements=@($inner.Finally.Statements|Where-Object {
    $_.Extent.Text -match '^\$callerRetirementConfirmed=|^if\(\$consumerCreated|^if\(\$clientCleanupConfirmed -and \$callerRetirementConfirmed\)'
})
if($callerStatements.Count -ne 4){throw 'Configured caller cleanup statements missing'}
$callerCleanup=[scriptblock]::Create(($callerStatements|ForEach-Object {$_.Extent.Text}) -join "`n")
function Remove-LocalUser([string]$Name,[object]$ErrorAction) {
    if($Name -cne 'fixture-consumer'){throw 'Wrong configured caller deletion'}
    $script:consumerDeletes++
}
foreach($case in @(
    @{name='service_retained';service=$false;image=$true;closed=$true;refusal=$false;remove=$false},
    @{name='image_retained';service=$true;image=$false;closed=$true;refusal=$false;remove=$false},
    @{name='client_uncertain';service=$true;image=$true;closed=$false;refusal=$false;remove=$false},
    @{name='retirement_refused';service=$true;image=$true;closed=$true;refusal=$true;remove=$false},
    @{name='retired';service=$true;image=$true;closed=$true;refusal=$false;remove=$true}
)) {
    $AdmittedTarget=$true;$consumerCreated=$true;$clientCleanupConfirmed=$case.closed
    $consumerName='fixture-consumer';$consumerCredential='retained credential sentinel';$script:consumerDeletes=0
    $receipt=[ordered]@{service_removed=$case.service;protected_service_binary_removed=$case.image;
        retirement_cleanup_failure=$(if($case.refusal){'refused'}else{$null})}
    . $callerCleanup
    if(($script:consumerDeletes -eq 1) -ne $case.remove -or
        (($null -eq $consumerCredential) -ne $case.remove) -or
        (([bool]$receipt.consumer_account_retained) -eq $case.remove)) {
        throw ('Configured recovery caller cleanup differs: '+$case.name)
    }
}
# Exercise the actual closed admission guards without running either fixture.
# Exactly the original controller and complete packaged-consumer profiles enter;
# missing prerequisites and every selected fault/control variant remain refused.
foreach($fixtureName in @('windows_publisher_lab_probe.ps1','windows_publisher_metadata_hosted_probe.ps1')) {
    $tokens=$null;$errors=$null
    $fixtureAst=[Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Repository ('tests\'+$fixtureName)),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Closed admission fixture parse failed'}
    $profileAssignments=@($fixtureAst.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -in @('$admittedControllerProfile','$admittedPackagedProfile')})
    $firstGuard=@($fixtureAst.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.IfStatementAst]}|Select-Object -First 1)
    if($profileAssignments.Count -ne 2 -or $firstGuard.Count -ne 1){throw 'Closed admission guard missing'}
    $guard=[scriptblock]::Create((@($profileAssignments|ForEach-Object {$_.Extent.Text})+
        @($firstGuard[0].Extent.Text)) -join "`n")
    $parameterNames=@($fixtureAst.ParamBlock.Parameters|ForEach-Object {$_.Name.VariablePath.UserPath})
    $selected=@('ControllerApply','ConsumerAccess','MachineRequestClient','ProductionConcurrentRights','NonAdminClient')
    $required=@('RegisteredService','ReviewedSource','ReuseRegistration')
    $faults=@('PublicInstallation','InterruptDuringConsumerAccess','InterruptAfterVisibleRecord',
        'InterruptAfterRename','InterruptBeforePublish','InterruptAfterStage','TerminateAtPoststage',
        'TerminateAtPostrename','ProductionPostpublishRights','ProductionPostrenameTermination',
        'ProductionPreparedTermination','ExpectUnprotectedRefusal','ExpectPreexistingAnchorRefusal',
        'HostileRights','HostilePostrename')|Where-Object {$_ -in $parameterNames}
    $cases=[Collections.Generic.List[object]]::new()
    foreach($mask in 0..31) {
        foreach($omit in @('none')+$required) {
            $flags=@('AdmittedTarget')+@($required|Where-Object {$_ -cne $omit})
            foreach($bit in 0..4){if($mask -band (1 -shl $bit)){$flags+=@($selected[$bit])}}
            $cases.Add(@{flags=$flags;accepted=($mask -in @(1,14) -and $omit -ceq 'none')})
        }
    }
    foreach($mask in @(1,14)) {
        foreach($fault in $faults) {
            $flags=@('AdmittedTarget')+$required+@($fault)
            foreach($bit in 0..4){if($mask -band (1 -shl $bit)){$flags+=@($selected[$bit])}}
            $cases.Add(@{flags=$flags;accepted=$false})
        }
    }
    foreach($case in $cases) {
        $accepted=$true
        try {& {
            param($names,$flags,$guard)
            foreach($name in $names){Set-Variable -Name $name -Value $false -Scope Local}
            foreach($flag in $flags){Set-Variable -Name $flag -Value $true -Scope Local}
            & $guard
        } $parameterNames $case.flags $guard} catch {$accepted=$false}
        if($accepted -ne $case.accepted){throw ('Closed admission profile differs: '+$fixtureName+' '+($case.flags -join ','))}
    }
}
# Execute the real activation helper without native effects. Its success must
# bind the product reply to this service; a prior exit code cannot admit it.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Repository 'tests\windows_publisher_metadata_hosted_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Activation fixture parse failed'}
$aclHelpers=@($ast.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $_.Name -in @('Set-OwnedMetadataServiceInputAccess','Grant-OwnedMetadataActorParentRead','Grant-OwnedMetadataActorScriptRead')})
if($aclHelpers.Count -ne 3){throw 'Owned metadata ACL construction helpers missing'}
& {
    param($Helpers,$Repository,$Scratch)
    foreach($helper in $Helpers){. ([scriptblock]::Create($helper.Extent.Text))}
    . (Join-Path $Repository 'tests\windows_publisher_owned_process.ps1')
    $root=Join-Path (Join-Path $Scratch ('usk-wu006-'+[guid]::NewGuid().ToString('N'))) 'controller-inputs'
    $parent=Split-Path -Parent $root
    $AdmittedTarget=$true;$admittedPackagedProfile=$true
    $sid='S-1-5-80-1-2-3-4-5';$consumerSid='S-1-5-21-1-2-3-1001';$unrelatedSid='S-1-5-21-1-2-3-1002'
    $consumerScript=Join-Path $root 'consumer-client.ps1'
    $script:ownedActorSourceRoot=Join-Path $root 'owned-actor-sources'
    $actorScript=Join-Path $script:ownedActorSourceRoot 'windows_publisher_unprivileged_probe.ps1'
    $actorHelper=Join-Path $script:ownedActorSourceRoot 'windows_publisher_owned_process.ps1'
    $wrapper=Join-Path $root ('windows_publisher_unprivileged_probe.ps1.owned-'+('1'*32)+'.ps1')
    $base='O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    $script:inputAcl=[Security.AccessControl.DirectorySecurity]::new();$script:inputAcl.SetSecurityDescriptorSddlForm($base)
    $script:parentAcl=[Security.AccessControl.DirectorySecurity]::new();$script:parentAcl.SetSecurityDescriptorSddlForm($base)
    $script:actorAcls=@{}
    foreach($path in @($script:ownedActorSourceRoot,$actorScript,$actorHelper,$wrapper)) {
        $acl=if($path -ceq $script:ownedActorSourceRoot){[Security.AccessControl.DirectorySecurity]::new()}
            else{[Security.AccessControl.FileSecurity]::new()}
        $acl.SetSecurityDescriptorSddlForm($base);$script:actorAcls[$path]=$acl
    }
    $script:inputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($consumerSid),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    $script:linkedParent=$false
    function Get-Acl([string]$LiteralPath) {
        if($LiteralPath -ceq $root){return $script:inputAcl}
        if($LiteralPath -ceq $parent){return $script:parentAcl}
        if($script:actorAcls.ContainsKey($LiteralPath)){return $script:actorAcls[$LiteralPath]}
        throw 'Unexpected ACL path'
    }
    function Set-Acl([string]$LiteralPath,$AclObject) {
        if($LiteralPath -ceq $root){$script:inputAcl=$AclObject;return}
        if($LiteralPath -ceq $parent){$script:parentAcl=$AclObject;return}
        if($script:actorAcls.ContainsKey($LiteralPath)){$script:actorAcls[$LiteralPath]=$AclObject;return}
        throw 'Unexpected ACL write path'
    }
    function Get-Item([string]$LiteralPath,[switch]$Force,[object]$ErrorAction) {
        if($LiteralPath -cnotin @($root,$parent) -and -not $script:actorAcls.ContainsKey($LiteralPath)){throw 'Unexpected actor path'}
        [pscustomobject]@{PSIsContainer=($LiteralPath -cin @($root,$parent,$script:ownedActorSourceRoot));Attributes=$(if($script:linkedParent -and $LiteralPath -ceq $parent){
            [IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory})}
    }
    function Get-CimInstance([string]$ClassName,[object]$ErrorAction) {
        if($ClassName -cne 'Win32_ComputerSystem'){throw 'Unexpected actor native query'}
        [pscustomobject]@{Manufacturer='Microsoft Corporation';Model='Virtual Machine'}
    }
    $saved=@{};foreach($name in @('GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_TEMP')){
        $saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
    try {
        $env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted';$env:RUNNER_TEMP=$Scratch
        Set-OwnedMetadataServiceInputAccess
        Grant-OwnedMetadataActorParentRead $consumerSid
        Grant-OwnedMetadataActorParentRead $unrelatedSid
        Grant-OwnedMetadataActorScriptRead $unrelatedSid $actorScript $wrapper
        if((Get-OwnedPublisherActorRoot $root) -cne $root){throw 'Produced actor ACL was not admitted'}
        $parentRules=@($script:parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|
            Where-Object {$_.IdentityReference.Value -ceq $consumerSid})
        if($parentRules.Count -ne 1 -or $parentRules[0].InheritanceFlags -ne 'None' -or
            ($parentRules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]'ListDirectory,Write,Delete,ChangePermissions,TakeOwnership')) {
            throw 'Actor parent metadata grant escaped its noninheriting read scope'
        }
        foreach($acl in @($script:inputAcl,$script:parentAcl,$script:actorAcls[$script:ownedActorSourceRoot])) {
            $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|
                Where-Object {$_.IdentityReference.Value -ceq $unrelatedSid})
            if($rules.Count -ne 1 -or $rules[0].InheritanceFlags -ne 'None' -or
                ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]'ListDirectory,Write,Delete,ChangePermissions,TakeOwnership')) {
                throw 'Unrelated actor acquired listing, broad input access or inherited grants'
            }
        }
        foreach($file in @($actorScript,$actorHelper,$wrapper)) {
            $rules=@($script:actorAcls[$file].GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|
                Where-Object {$_.IdentityReference.Value -ceq $unrelatedSid})
            if($rules.Count -ne 1 -or $rules[0].InheritanceFlags -ne 'None' -or
                ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]'ReadAndExecute') -ne
                    [Security.AccessControl.FileSystemRights]'ReadAndExecute' -or
                ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]'Write,Delete,ChangePermissions,TakeOwnership')) {
                throw 'Unrelated actor fixed script/wrapper read grant differs'
            }
        }
        $caught=$null
        try {Grant-OwnedMetadataActorScriptRead $unrelatedSid (Join-Path $root 'archive.zip') $wrapper} catch {$caught=$_}
        if(-not $caught){throw 'Unrelated actor read grant accepted another input'}
        $valid=$script:inputAcl.Sddl
        foreach($writer in @($sid,$consumerSid,$unrelatedSid)) {
            $script:inputAcl.SetSecurityDescriptorSddlForm($valid)
            $script:inputAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($writer),'Modify','ContainerInherit,ObjectInherit','None','Allow'))
            $caught=$null;try {$null=Get-OwnedPublisherActorRoot $root} catch {$caught=$_}
            if(-not $caught){throw 'Actor source guard accepted a service/consumer writer'}
        }
        $script:inputAcl.SetSecurityDescriptorSddlForm($valid);$script:linkedParent=$true
        $caught=$null;try {$null=Get-OwnedPublisherActorRoot $root} catch {$caught=$_}
        if(-not $caught){throw 'Actor source guard accepted a linked parent'}
        $script:linkedParent=$false;$script:inputAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($consumerSid))
        $caught=$null;try {$null=Get-OwnedPublisherActorRoot $root} catch {$caught=$_}
        if(-not $caught){throw 'Actor source guard accepted an untrusted owner'}
    } finally {
        foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    }
} $aclHelpers $Repository $Scratch
$bodyFactory=@($ast.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'New-OwnedMetadataActorBody'})
if($bodyFactory.Count -ne 1){throw 'Owned actor body factory missing'}
. ([scriptblock]::Create($bodyFactory[0].Extent.Text))
$stubScript=Join-Path $Scratch "actor ' literal.ps1"
$stubOutput=Join-Path $Scratch 'owned-actor-roundtrip.json'
[IO.File]::WriteAllText($stubScript,@'
param([string]$Message,[string]$OutputPath,[switch]$Selected)
[ordered]@{message=$Message;selected=[bool]$Selected;github=$env:GITHUB_ACTIONS;
    runner=$env:RUNNER_ENVIRONMENT;temporary=$env:RUNNER_TEMP}|
    ConvertTo-Json|Set-Content -LiteralPath $OutputPath -Encoding utf8
'@)
$contextNames=@('GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_TEMP');$savedContext=@{}
foreach($name in $contextNames){$savedContext[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try {
    $env:GITHUB_ACTIONS='true';$env:RUNNER_ENVIRONMENT='github-hosted';$env:RUNNER_TEMP=$Scratch+"\literal ' root"
    $message="literal ' ; "+'$()'
    $digest=(Get-FileHash -LiteralPath $stubScript -Algorithm SHA256).Hash.ToLowerInvariant()
    $body=New-OwnedMetadataActorBody $stubScript @('-Message',$message,'-OutputPath',$stubOutput,'-Selected') $digest
    . ([scriptblock]::Create($body))
    $observed=Get-Content -LiteralPath $stubOutput -Raw|ConvertFrom-Json
    if($observed.message -cne $message -or -not $observed.selected -or $observed.github -cne 'true' -or
        $observed.runner -cne 'github-hosted' -or $observed.temporary -cne $env:RUNNER_TEMP) {
        throw 'Owned actor argument/context literals did not roundtrip'
    }
    [IO.File]::Delete($stubOutput);[IO.File]::AppendAllText($stubScript,"`n# changed")
    $caught=$null
    try {. ([scriptblock]::Create($body))} catch {$caught=$_}
    if(-not $caught -or (Test-Path -LiteralPath $stubOutput)) {
        throw 'Changed actor source executed despite the bound digest'
    }
} finally {
    foreach($name in $contextNames){[Environment]::SetEnvironmentVariable($name,$savedContext[$name],'Process')}
}
$activation=@($ast.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Start-RegisteredPublisher'})
if($activation.Count -ne 1){throw 'Activation fixture helper missing'}
. ([scriptblock]::Create($activation[0].Extent.Text))
$service='USK_PUB_0123456789abcdef0123456789abcdef';$ServiceBinary='owned-publisher.exe'
$VolumeRoot='owned-volume';$callerSid='S-1-5-21-1-2-3-1001';$AdmittedTarget=$true
$script:controllerPending=$false
function Invoke-ObservedPublisherControl([string]$Phase,[string[]]$Arguments) {
    $script:activationCalls++
    if($Phase -cne 'service_activation' -or ($Arguments -join '|') -cne
        (@('--start',$service,$ServiceBinary,$VolumeRoot,$callerSid,'--service-admitted-client') -join '|')) {
        throw 'Activation did not use the exact product command'
    }
    return [pscustomobject]@{native_exit_code=$script:activationExit;output=@($script:activationReply)}
}
$reply=@{schema='usk.publisher_service_control.v1';status='start_requested';service=$service}
foreach($case in @('valid','wrong_service','wrong_status','wrong_schema','unknown','missing_exit')) {
    $script:activationCalls=0;$script:activationExit=0;$current=$reply.Clone()
    switch($case) {
        'wrong_service' {$current.service=$service+'.different'}
        'wrong_status' {$current.status='registered'}
        'wrong_schema' {$current.schema='usk.other.v1'}
        'unknown' {$script:activationExit=5}
        'missing_exit' {$script:activationExit=$null}
    }
    $script:activationReply=$current|ConvertTo-Json -Compress
    $caught=$null
    try {Start-RegisteredPublisher} catch {$caught=$_}
    if($script:activationCalls -ne 1 -or (($null -eq $caught) -ne ($case -ceq 'valid'))) {
        throw ('Product activation reply validation differs: '+$case)
    }
}
$script:controllerPending=$true;$script:activationCalls=0
Start-RegisteredPublisher
if($script:activationCalls){throw 'Pending controller dispatch started a second worker'}
$ControllerApply=$true;$script:controllerMode='verify'
$script:activationExit=0;$script:activationReply=$reply|ConvertTo-Json -Compress
Start-RegisteredPublisher -ActivateBeforeControllerRequest
if($script:activationCalls -ne 1 -or -not $script:controllerPending) {
    throw 'Explicit admitted verification activation skipped start or changed the controller request'
}
foreach($invalidMode in @('apply','recover')) {
    $script:controllerMode=$invalidMode;$script:activationCalls=0;$caught=$null
    try {Start-RegisteredPublisher -ActivateBeforeControllerRequest} catch {$caught=$_}
    if(-not $caught -or $script:activationCalls){throw 'Explicit activation admitted an unintended controller operation'}
}
$script:controllerMode='verify';$ControllerApply=$false;$script:activationCalls=0;$caught=$null
try {Start-RegisteredPublisher -ActivateBeforeControllerRequest} catch {$caught=$_}
if(-not $caught -or $script:activationCalls){throw 'Explicit controller activation admitted a different profile'}
# A native refusal failure and an uncertain restore have separate receipts.
# Only an owned temporary file is changed; no registered service is present.
$mutation=@($ast.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Assert-ChangedAdmissionStartRefusal'})
if($mutation.Count -ne 1){throw 'Admission mutation fixture helper missing'}
. ([scriptblock]::Create($mutation[0].Extent.Text))
$ServiceBinary=Join-Path $Scratch 'owned-publisher.exe'
$ownedRecord=Join-Path $Scratch ($service+'.target-admitted.json')
$originalBytes=[Text.Encoding]::UTF8.GetBytes('{"identity":{"registration_sha256":"original"}}')
function Assert-AdmittedStartRefusal([string]$Phase,[string[]]$Arguments,[string]$Diagnostic) {
    if($Phase -cne 'start_changed_admission' -or
        ([IO.File]::ReadAllText($ownedRecord)|ConvertFrom-Json).identity.registration_sha256 -cne ('0'*64)) {
        throw 'Changed record did not reach the intended refusal'
    }
    if($script:failRestore){[IO.File]::SetAttributes($ownedRecord,[IO.FileAttributes]::ReadOnly)}
    if($script:failNative){throw 'synthetic native refusal failure'}
}
foreach($case in @('success','native_failure','native_and_restore_failure')) {
    [IO.File]::WriteAllBytes($ownedRecord,$originalBytes)
    $receipt=[ordered]@{};$script:failNative=$case -cne 'success'
    $script:failRestore=$case -ceq 'native_and_restore_failure';$caught=$null
    try {Assert-ChangedAdmissionStartRefusal} catch {$caught=$_}
    finally {[IO.File]::SetAttributes($ownedRecord,[IO.FileAttributes]::Normal)}
    $control=$receipt.changed_admission_start_control
    if($script:failNative) {
        if(-not $caught -or $caught.Exception.Message -cne 'synthetic native refusal failure' -or
            $control.primary_failure -cne 'synthetic native refusal failure') {
            throw 'Admission restore replaced the primary native failure'
        }
    } elseif($caught -or $control.primary_failure) {
        throw ('Successful refusal acquired a primary failure: '+$caught.Exception.Message+'; '+$control.primary_failure)
    }
    if($script:failRestore) {
        if($control.restoration_status -cne 'unconfirmed' -or -not $control.restoration_failure) {
            throw 'Failed admission restore was not separately retained'
        }
    } elseif($control.restoration_status -cne 'restored' -or $control.restoration_failure -or
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($ownedRecord)) -cne
        [Convert]::ToBase64String($originalBytes)) {throw 'Exact admission restoration differs'}
}
''', encoding="utf-8")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(driver), "-Repository", str(repository), "-Scratch", str(root)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"fixture cleanup containment failed: {result}")


def main() -> int:
    executable = Path(sys.argv[1]).resolve(strict=True)
    service = "USK_PUB_" + uuid.uuid4().hex
    volume = r"\\?\Volume{00000000-0000-0000-0000-000000000000}" + "\\"
    identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, timeout=10, check=True)
    caller = next(csv.reader(identity.stdout.splitlines()))[1]
    with tempfile.TemporaryDirectory(prefix="usk-reviewed-apply-") as directory:
        root = Path(directory)
        envelope_file = root / "envelope.json"
        apply_file = root / "apply.json"
        apply = {"schema": "usk.install_local_apply_request.v1",
                 "confirmation": "APPLY", "transaction_id": "original"}
        envelope = {"schema": "usk.publisher.lab_reviewed_plan_envelope.v2",
                    "activation": "operator_acceptance_candidate",
                    "apply_request": apply}
        digest = write_json(envelope_file, envelope)
        changed = dict(apply, transaction_id="substituted")
        write_json(apply_file, changed)
        args = [str(executable), "--apply-registered", service,
                str(executable), volume, str(envelope_file), digest,
                caller, "0" * 64, str(apply_file)]
        before = subprocess.run(["sc.exe", "query", service],
                                capture_output=True, timeout=10, check=False)
        if before.returncode != 1060:
            raise AssertionError("generated test service absence was not established")
        # Exercise the real controller parser and request checks in every mode,
        # including the admitted route. The distinct diagnostic proves these
        # refusals reached the request check rather than an unsupported option.
        for mode in ([], ["--admit-client-observer"], ["--grant-client-read"],
                     ["--service-admitted-client"]):
            result = subprocess.run(
                args + mode, capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 3 or "apply request differs" not in result.stderr:
                raise AssertionError(f"reviewed apply substitution was admitted in {mode}: {result}")
            for operation, expected_schema in (
                ("--recover-registered", "usk.publisher_recovery_request.v1"),
                ("--verify-registered", "usk.publisher_installed_verify_request.v1"),
            ):
                wrong_request = root / (operation[2:] + ".json")
                write_json(wrong_request, {"schema": "usk.install_local_apply_request.v1"})
                result = subprocess.run(
                    [str(executable), operation, service, str(executable), volume,
                     caller, "0" * 64, str(wrong_request)] + mode,
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if result.returncode != 3 or "request mode differs" not in result.stderr:
                    raise AssertionError(
                        f"{operation} accepted a request other than {expected_schema} in {mode}: {result}"
                    )
        # Admitted requests must bind the current caller before reading input.
        # A different canonical account SID is insufficient, even with this mode.
        wrong_caller_args = list(args)
        wrong_caller_args[7] = "S-1-5-18" if caller != "S-1-5-18" else "S-1-5-19"
        result = subprocess.run(
            wrong_caller_args + ["--service-admitted-client"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 3 or "caller differs from this process identity" not in result.stderr:
            raise AssertionError(f"admitted controller did not reject the actual caller mismatch: {result}")
        # Legacy reconfiguration remains unavailable for admitted registrations.
        for operation in ("--recover", "--verify"):
            result = subprocess.run(
                [str(executable), operation, service, str(executable), volume,
                 caller, "--service-admitted-client"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 3 or "caller access mode is invalid" not in result.stderr:
                raise AssertionError(f"admitted mode reached legacy {operation}: {result}")
        # Admitted activation is parsed, but an ordinary build executable is
        # still refused at the native protected-image fence before SCM access.
        result = subprocess.run(
            [str(executable), "--start", service, str(executable), volume,
             caller, "--service-admitted-client"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 3 or "outside the protected installation directory" not in result.stderr:
            raise AssertionError(f"admitted start bypassed protected-image custody: {result}")
        after = subprocess.run(["sc.exe", "query", service],
                               capture_output=True, timeout=10, check=False)
        if after.returncode != 1060:
            raise AssertionError("invalid apply left a service or unknown SCM state")
        # Run the real fixture entry points with rejected profile combinations.
        # Fake inputs must remain unopened and no output/VHD may be created.
        repository = Path(__file__).resolve().parents[2]
        verify_fixture_retention(repository, root)
        fixture_environment = dict(os.environ, GITHUB_ACTIONS="false", RUNNER_ENVIRONMENT="local")
        admitted = ["-AdmittedTarget", "-ControllerApply", "-RegisteredService",
                    "-ReviewedSource", "-ReuseRegistration"]
        output = root / "must-not-be-created.json"
        missing_vhd = root / "must-not-be-created.vhdx"
        for name in ("windows_publisher_lab_probe.ps1", "windows_publisher_metadata_hosted_probe.ps1"):
            fixture = repository / "tests" / name
            inputs = ["-OutputPath", str(output)]
            if "metadata" in name:
                inputs += ["-VhdPath", str(missing_vhd), "-VolumeRoot", volume,
                           "-ServiceBinary", str(executable), "-DeviceAclBinary", str(executable),
                           "-MachineBinary", str(executable), "-PublicApplyBinary", str(executable)]
            else:
                inputs += ["-ServiceControlBinary", str(executable)]
            combinations = [[flag for flag in admitted if flag != "-ControllerApply"]]
            combinations += [admitted + [flag] for flag in (
                "-ConsumerAccess", "-MachineRequestClient", "-InterruptAfterStage", "-NonAdminClient")]
            for flags in combinations:
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-File", str(fixture)] + inputs + flags,
                    capture_output=True, text=True, timeout=10, check=False, env=fixture_environment,
                )
                if result.returncode == 0 or "Admitted target currently requires" not in result.stderr:
                    raise AssertionError(f"unsafe admitted fixture profile reached setup: {name}: {result}")
                if output.exists() or missing_vhd.exists():
                    raise AssertionError("rejected fixture profile created output or storage")
        actor_probe = repository / "tests" / "windows_publisher_controller_actor_probe.ps1"
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(actor_probe), "-OutputPath", str(output)],
            capture_output=True, text=True, timeout=10, check=False, env=fixture_environment,
        )
        if result.returncode == 0 or "requires the hosted disposable VM" not in result.stderr or output.exists():
            raise AssertionError(f"controller actor probe bypassed hosted admission: {result}")
        if len(sys.argv) > 2:
            observer = Path(sys.argv[2]).resolve(strict=True)
            result = subprocess.run(
                [str(observer), "--observe-owned-hosted-vm-vhd-volume", volume, service,
                 "4294967295", str(missing_vhd), "00000000-0000-0000-0000-000000000000"],
                capture_output=True, text=True, timeout=10, check=False, env=fixture_environment,
            )
            if result.returncode != 2 or "requires a hosted disposable runner" not in result.stderr:
                raise AssertionError(f"read-only device observer bypassed native hosted admission: {result}")
            if missing_vhd.exists():
                raise AssertionError("non-hosted device observer created storage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
