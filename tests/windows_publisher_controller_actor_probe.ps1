# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'windows_publisher_standard_launcher.ps1')
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'Controller actor probe requires the hosted disposable VM'
}
$temporary=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
$lab=Join-Path $temporary ('usk-wu006-'+[guid]::NewGuid().ToString('N'))
$out=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $out){throw 'Controller actor receipt already exists'}
New-Item -ItemType Directory -Path $lab -ErrorAction Stop|Out-Null
$child=Join-Path $lab 'actor-child.json'
$failure=$null;$controllerActorObservation=$null;$controllerLauncherClosed=$false
$receipt=[ordered]@{schema='usk.publisher_controller_actor_qualification.v1';status='failed';
    scope='identity_only_no_product_dispatch';actor=$null;child=$null;failure=$null;owned_inputs_removed=$false}
try {
    Invoke-OwnedPublisherFixtureTask -ActorProfile NamedController -IdentityProbe -LabRoot $lab -OutputPath $child
    $observed=Get-Content -LiteralPath $child -Raw|ConvertFrom-Json
    if($observed.status -cne 'passed' -or -not $controllerLauncherClosed -or
        $controllerActorObservation.native_process_sid -cne $observed.identity -or
        -not [object]::Equals($controllerActorObservation.process_exit_confirmed,$true) -or
        -not [object]::Equals($controllerActorObservation.task_removed,$true) -or
        -not [object]::Equals($controllerActorObservation.account_removed,$true) -or
        $controllerActorObservation.account_retained) {
        throw 'Named controller identity or owned cleanup was not established'
    }
    $receipt.child=$observed
    # Delete only this successful probe's known ordinary files after the held
    # actor exited, its exact task disappeared and its generated account retired.
    if([IO.Path]::GetFullPath($lab) -cne (Join-Path $temporary (Split-Path -Leaf $lab)) -or
        (Get-Item -LiteralPath $lab -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Owned controller probe cleanup directory changed'
    }
    $name=$controllerActorObservation.task_name
    $expected=@(($name+'.ps1'),($name+'.started.json'),($name+'.acknowledged.json'),'actor-child.json')
    $files=@(Get-ChildItem -LiteralPath $lab -Force)
    if($files.Count -ne $expected.Count){throw 'Owned controller probe cleanup namespace differs'}
    foreach($file in $files) {
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $expected -cnotcontains $file.Name -or $file.DirectoryName -cne $lab) {
            throw 'Owned controller probe cleanup input differs'
        }
    }
    foreach($file in $files){Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop}
    Remove-Item -LiteralPath $lab -ErrorAction Stop
    $receipt.owned_inputs_removed=$true;$receipt.status='passed'
} catch {$failure=$_;$receipt.failure=$_.Exception.Message} finally {
    $receipt.actor=$controllerActorObservation
    $receipt|ConvertTo-Json -Depth 32|Set-Content -LiteralPath $out -Encoding utf8
}
if($failure){throw $failure}
