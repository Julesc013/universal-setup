# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Extract only cleanup control flow; use inert process and launch objects.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'windows_publisher_standard_public_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Standard fixture source does not parse'}
$functions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Close-StandardPublisherClient'
},$true))
if($functions.Count -ne 1){throw 'Standard client cleanup helper is ambiguous'}
. ([scriptblock]::Create($functions[0].Extent.Text))
function Stop-OwnedPublisherProcessTree($Process) {
    $Process.ClosureChecks++
    if($Process.ClosureFails){throw 'Synthetic indeterminate descendant closure after root exit'}
    return [pscustomobject]@{confirmed=$Process.ClosureConfirmed}
}
function New-InertProcess {
    $process=[pscustomobject]@{HasExited=$true;ClosureChecks=0;ClosureFails=$false;
        ClosureConfirmed=$true;DisposeFails=$false;Disposed=$false}
    $process|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        if($this.DisposeFails){throw 'Synthetic process-handle disposal failure'}
        $this.Disposed=$true
    }
    return $process
}
function New-InertLaunch {
    $launch=[pscustomobject]@{IsResumed=$true;DisposeFails=$false;Disposed=$false}
    $launch|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        if($this.DisposeFails){throw 'Synthetic launch disposal failure'}
        $this.Disposed=$true
    }
    return $launch
}
$process=New-InertProcess;$launch=New-InertLaunch
Close-StandardPublisherClient $process $launch
if(-not $clientsClosed -or $process.ClosureChecks -ne 1 -or -not $process.Disposed -or -not $launch.Disposed){
    throw 'Confirmed process and launch closure did not succeed'
}
foreach($failure in @('indeterminate_descendants','unconfirmed_tree','process_disposal','launch_disposal','missing_held_process','attempted_without_custody')) {
    $process=New-InertProcess;$launch=New-InertLaunch;$script:clientsClosed=$true
    switch($failure) {
        'indeterminate_descendants' {$process.ClosureFails=$true}
        'unconfirmed_tree' {$process.ClosureConfirmed=$false}
        'process_disposal' {$process.DisposeFails=$true}
        'launch_disposal' {$launch.DisposeFails=$true}
        'missing_held_process' {$process=$null}
        'attempted_without_custody' {$process=$null;$launch=$null}
    }
    $threw=$false
    try {Close-StandardPublisherClient $process $launch} catch {$threw=$true}
    if(-not $threw -or $clientsClosed){throw ('Failed closure promoted to confirmation: '+$failure)}
}
$launch=New-InertLaunch;$launch.IsResumed=$false
Close-StandardPublisherClient $null $launch
if(-not $clientsClosed -or -not $launch.Disposed){throw 'Confirmed never-resumed launch cleanup did not succeed'}
Close-StandardPublisherClient $null $null $false
if(-not $clientsClosed){throw 'Empty launch cleanup did not succeed'}
'Standard client cleanup: confirmed closure accepted; six ambiguous or failed closures refused'
