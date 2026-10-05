# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Inert failures only: no holder, native event, SCM or volume is created.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_install_guard_fixture.ps1')
function Assert-GuardCleanupControl([bool]$Condition,[string]$Message) {if(-not $Condition){throw $Message}}
$value=[IntPtr]42;$failed=$false
try {
    [UskPublisherInstallGuardEvents]::CloseTracked([ref]$value,[Func[IntPtr,bool]]{param($pointer)$false},[Func[int]]{6})
} catch {$failed=$true}
Assert-GuardCleanupControl ($failed -and $value -eq [IntPtr]42) 'Failed close relinquished the retained handle'
[UskPublisherInstallGuardEvents]::CloseTracked([ref]$value,[Func[IntPtr,bool]]{param($pointer)$true},[Func[int]]{0})
Assert-GuardCleanupControl ($value -eq [IntPtr]::Zero) 'Confirmed inert close did not clear its handle'
$script:controlCalls=[Collections.Generic.List[string]]::new();$failed=$false
try {
    [UskPublisherInstallGuardEvents]::RunAllCleanup([Action[]]@(
        [Action]{$script:controlCalls.Add('ready');throw 'controlled-ready-close'},
        [Action]{$script:controlCalls.Add('release');throw 'controlled-release-close'},
        [Action]{$script:controlCalls.Add('descriptor')}))
} catch {$failed=$true;Assert-GuardCleanupControl ($_.Exception.ToString().Contains('controlled-ready-close')) 'First close failure was replaced'}
Assert-GuardCleanupControl ($failed -and ($controlCalls -join ',') -ceq 'ready,release,descriptor') 'A failed close skipped later resources'
function New-InertGuardResource([string]$Name,[bool]$Fail) {
    $value=[pscustomobject]@{control_name=$Name;control_fail=$Fail}
    $value|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        $script:controlCalls.Add($this.control_name)
        if($this.control_fail){throw ('controlled-disposal-'+$this.control_name)}
    }
    $value|Add-Member -MemberType ScriptMethod -Name Release -Value {$script:controlCalls.Add('signal')}
    return $value
}
$holder=New-InertGuardResource 'process' $true
$events=New-InertGuardResource 'events' $true
$image=New-InertGuardResource 'image' $false
$script:controlCalls.Clear()
$result=Complete-InstallGuardFixtureCleanup $holder $events $image $true $true
Assert-GuardCleanupControl ($result.confirmed -eq $false -and
    ([string]$result.first_error).Contains('controlled-disposal-process') -and
    ($controlCalls -join ',') -ceq 'process,events,image' -and
    [object]::ReferenceEquals($script:installGuardRetainedProcess,$holder) -and
    [object]::ReferenceEquals($script:installGuardRetainedEvents,$events) -and
    $null -eq $script:installGuardRetainedImage) 'Disposal failure promoted cleanup or dropped a failed resource'
function Stop-OwnedPublisherProcessTree($Process) {return [pscustomobject]@{confirmed=$false}}
$holder=New-InertGuardResource 'process' $false
$events=New-InertGuardResource 'events' $false
$image=New-InertGuardResource 'image' $false
$script:controlCalls.Clear()
$result=Complete-InstallGuardFixtureCleanup $holder $events $image $true $false
Assert-GuardCleanupControl ($result.confirmed -eq $false -and
    ($controlCalls -join ',') -ceq 'signal,events,image' -and
    [object]::ReferenceEquals($script:installGuardRetainedProcess,$holder)) 'Unknown child closure dropped live custody'
$script:controlCalls.Clear()
$result=Complete-InstallGuardFixtureCleanup $null $events $image $true $false
Assert-GuardCleanupControl ($result.confirmed -eq $false -and
    ([string]$result.first_error).Contains('launch custody is unconfirmed') -and
    ($controlCalls -join ',') -ceq 'events,image') 'Missing launch custody was promoted'
$holder=New-InertGuardResource 'process' $false
$script:controlCalls.Clear()
$result=Complete-InstallGuardFixtureCleanup $holder $events $image $true $true
Assert-GuardCleanupControl ($result.confirmed -eq $true -and $null -eq $result.first_error -and
    $null -eq $script:installGuardRetainedProcess -and $null -eq $script:installGuardRetainedEvents -and
    $null -eq $script:installGuardRetainedImage -and ($controlCalls -join ',') -ceq 'process,events,image') 'Complete inert disposal did not close the barrier'
'Installation guard inert close/disposal/custody controls: PASS'
