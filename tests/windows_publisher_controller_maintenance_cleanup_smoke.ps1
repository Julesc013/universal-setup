# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Exercise the real request helper's finally with inert processes. No dispatch.
$ErrorActionPreference='Stop'
# CTest can inherit a PowerShell 7 module path while launching Windows PowerShell.
# Import this host's own built-in utility module without changing machine policy.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'windows_publisher_controller_maintenance_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Controller maintenance helper does not parse'}
$functions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-ControllerMaintenanceRequest'
},$true))
if($functions.Count -ne 1){throw 'Controller request helper is ambiguous'}
. ([scriptblock]::Create($functions[0].Extent.Text))
# Bind a real readable fixture image before the inert launch boundary. This
# script is hashed by the request helper and is never executed as a client.
$MachineBinary=$PSCommandPath;$service='inert-service'
$AdmittedTarget=$false;$admittedPackagedProfile=$false
function Start-OwnedMetadataProcess {
    param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
    if($FilePath -cne $MachineBinary -or
        $ArgumentList -cnotcontains '--publisher' -or $WindowStyle -cne 'Hidden') {
        throw 'Controller request lost the public registered path or hidden execution'
    }
    if($script:launchFails){throw 'Injected uncertain launch failure'}
    return $script:inertProcess
}
function Stop-OwnedPublisherProcessTree($Process) {
    if($Process -ne $script:inertProcess){throw 'Cleanup lost its held process'}
    $script:closureCalls++
    if($script:closureFails){throw 'Injected ambiguous descendant closure'}
    return [pscustomobject]@{confirmed=$script:closureConfirmed}
}
function Invoke-InertRequest {
    $script:requestClient=$null;$script:clientCleanupConfirmed=$true
    $script:closureCalls=0;$case=[ordered]@{response=$null};$caught=$null
    try {Invoke-ControllerMaintenanceRequest -RequestPath 'unused-input.json' -RequestId 'inert-request' -Case $case}
    catch {$caught=$_}
    if(-not $caught){throw 'Inert failed request escaped as success'}
    return [pscustomobject]@{message=$caught.Exception.Message;case=$case}
}
$script:waitExpires=$true;$script:disposeFails=$false
$script:inertProcess=[pscustomobject]@{ExitCode=5}
$script:inertProcess|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($Milliseconds) if($null -eq $Milliseconds){return}; return -not $script:waitExpires}
$script:inertProcess|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
    if($script:disposeFails){throw 'Injected process handle close failure'}
}
$script:launchFails=$false;$script:closureFails=$true;$script:closureConfirmed=$true
$result=Invoke-InertRequest
if($result.message -cne 'Owned public maintenance request timed out' -or
    $result.case.client_cleanup_failure -cne 'Injected ambiguous descendant closure' -or
    $script:clientCleanupConfirmed -or $script:requestClient.process -ne $script:inertProcess -or
    $script:closureCalls -ne 1) {throw 'Cleanup failure masked timeout or discarded shared ownership'}
$script:closureFails=$false
$result=Invoke-InertRequest
if($result.message -cne 'Owned public maintenance request timed out' -or
    -not $script:clientCleanupConfirmed -or $null -ne $script:requestClient -or
    $script:closureCalls -ne 1) {throw 'Confirmed cleanup lost the original request failure'}
$script:closureConfirmed=$false
$result=Invoke-InertRequest
if($result.message -cne 'Owned public maintenance request timed out' -or
    $script:clientCleanupConfirmed -or $script:requestClient.process -ne $script:inertProcess -or
    $result.case.client_cleanup_failure -cne 'Owned maintenance client closure is unconfirmed') {
    throw 'Nonconfirmed cleanup discarded shared ownership'
}
$script:launchFails=$true
$result=Invoke-InertRequest
if($result.message -cne 'Injected uncertain launch failure' -or
    $script:clientCleanupConfirmed -or $script:closureCalls -ne 0) {
    throw 'Uncertain launch manufactured a confirmed cleanup'
}
$script:launchFails=$false;$script:closureConfirmed=$true;$script:disposeFails=$true
$result=Invoke-InertRequest
if($result.message -cne 'Owned public maintenance request timed out' -or
    $script:clientCleanupConfirmed -or $script:requestClient.process -ne $script:inertProcess -or
    $result.case.client_cleanup_failure -notlike '*Injected process handle close failure*') {
    throw 'Process handle failure discarded primary error or shared ownership'
}
# An actual UNKNOWN response with no native completion must survive observation.
$script:disposeFails=$false;$script:waitExpires=$false
$temporary=[IO.Path]::Combine([IO.Path]::GetTempPath(),('usk-controller-client-'+[guid]::NewGuid().ToString('N')))
[IO.Directory]::CreateDirectory($temporary)|Out-Null
$requestPath=Join-Path $temporary 'request.json'
$responsePath=$requestPath+'.response'
try {
    [IO.File]::WriteAllText($responsePath,(@{schema='usk.oneshot_response.v1';request_id='inert-request';
        status='unknown';result=$null;error=@{code='publisher_outcome_unknown'}}|ConvertTo-Json -Compress))
    $case=[ordered]@{response=$null};$caught=$null
    try {Invoke-ControllerMaintenanceRequest -RequestPath $requestPath -RequestId 'inert-request' -Case $case}
    catch {$caught=$_}
    if(-not $caught -or $caught.Exception.Message -cne
        'Owned public maintenance request did not complete; retain its actual response and authority' -or
        $case.response.status -cne 'unknown' -or $null -ne $case.response.result -or
        $case.response.error.code -cne 'publisher_outcome_unknown' -or $case.response.request_id -cne 'inert-request' -or
        -not $script:clientCleanupConfirmed -or $case.Contains('native_response')) {
        throw ('Missing native capture erased UNKNOWN or manufactured another operation verdict: '+
            (@{caught=$caught.Exception.Message;response=$case.response;cleanup=$script:clientCleanupConfirmed;
                failure=$case.client_cleanup_failure}|ConvertTo-Json -Depth 6 -Compress))
    }
} finally {
    # Exact ordinary files created above; no recursive or product cleanup.
    [IO.File]::Delete($responsePath)
    [IO.Directory]::Delete($temporary)
}
# Exercise the actual retirement caller with inert control/readback adapters.
# The positive case is a fixture observation, never native retirement evidence.
$retirementFunctions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-ControllerOwnedRetirement'
},$true))
if($retirementFunctions.Count -ne 1){throw 'Controller retirement helper is ambiguous'}
. ([scriptblock]::Create($retirementFunctions[0].Extent.Text))
$AdmittedTarget=$true;$ControllerApply=$true;$service='inert-service'
$installedServiceBinary='inert-protected.exe'
$drive='inert-drive';$vhd='inert-volume.vhdx';$root=$temporary
function Invoke-ObservedPublisherControl {
    param([string]$Phase,[string[]]$Arguments,[string]$DiagnosticPath)
    if($Phase -cne 'owned_retirement' -or
        $DiagnosticPath -cne (Join-Path $root 'owned-retirement-error.txt') -or
        $Arguments.Count -ne 2 -or $Arguments[0] -cne '--retire-owned' -or $Arguments[1] -cne $service) {
        throw 'Retirement dispatch lost its fixed owner and service'
    }
    $script:retirementDispatchCount++
    [pscustomobject]@{native_exit_code=$script:retirementExitCode;
        output=(@{schema='usk.publisher_service_control.v1';status='owned_retired';service=$service}|ConvertTo-Json -Compress)}
}
function Get-Service {
    param($Name,$ErrorAction)
    if($script:retirementDispatchCount -eq 0 -or $script:serviceRetained){return [pscustomobject]@{Status='Stopped'}}
}
function Test-Path {param($LiteralPath) return $script:imageRetained}
function Assert-OwnedVolume {}
function Read-BoundedDiagnostic {param($Path,$Maximum) return 'inert incomplete native retirement'}
function Invoke-IndependentMetadataReadback {
    param($DriveRoot,$OutputRoot,$RunId)
    return @{independent=@{rows=@(@{path='retained-state';sha256=$script:readbackDigest})}}
}
function Reset-InertRetirement {
    $script:retirementDispatchCount=0;$script:retirementExitCode=0
    $script:serviceRetained=$false;$script:imageRetained=$false;$script:readbackDigest='unchanged'
    $script:clientCleanupConfirmed=$true
    $script:receipt=@{owned_uninstall=@{status='owned_uninstall_observed_retirement_pending';
        retirement_qualified=$false;cases=@(@{status='observed_completed'},@{status='observed_completed';
            after=@{independent=@{rows=@(@{path='retained-state';sha256='unchanged'})}}})}}
}
[IO.Directory]::CreateDirectory($root)|Out-Null
try {
foreach($kind in @('uncertain-client','incomplete-uninstall','native-failure','service-retained','image-retained','changed-evidence','completed')) {
    Reset-InertRetirement
    switch($kind) {
        'uncertain-client' {$script:clientCleanupConfirmed=$false}
        'incomplete-uninstall' {$receipt.owned_uninstall.cases[-1].status='unknown'}
        'native-failure' {$script:retirementExitCode=5}
        'service-retained' {$script:serviceRetained=$true}
        'image-retained' {$script:imageRetained=$true}
        'changed-evidence' {$script:readbackDigest='changed'}
    }
    $caught=$null
    try {Invoke-ControllerOwnedRetirement} catch {$caught=$_}
    if($kind -ceq 'native-failure' -and ($null -eq $caught -or
        $caught.Exception.Message -cne 'Owned publisher retirement incomplete; retain its actual state for revalidation' -or
        $receipt.product_retirement_failure -cne 'inert incomplete native retirement')) {
        throw 'Inert native failure lost its actual retirement diagnostic or failure boundary'
    }
    if($kind -ceq 'completed') {
        if($caught -or $script:retirementDispatchCount -ne 1 -or
            $receipt.owned_uninstall.status -cne 'owned_uninstall_and_retirement_observed' -or
            -not $receipt.owned_uninstall.retirement_observed -or $receipt.owned_uninstall.retirement_qualified) {
            throw ('Inert completed retirement lost its qualified distinction: '+$caught)
        }
    } else {
        $expectedDispatch=if($kind -in @('uncertain-client','incomplete-uninstall')){0}else{1}
        if(-not $caught -or $script:retirementDispatchCount -ne $expectedDispatch -or
            $receipt.owned_uninstall.retirement_observed -or $receipt.protected_service_binary_removed -or
            $receipt.owned_uninstall.status -cne 'owned_uninstall_observed_retirement_pending') {
            throw ('Inert incomplete retirement escaped or discarded evidence: '+$kind)
        }
    }
}
} finally {
    [IO.File]::Delete((Join-Path $root 'owned-retirement-error.txt'))
    [IO.Directory]::Delete($root)
}
Write-Output 'PASS controller maintenance primary-error, cleanup and retirement completion barriers'
