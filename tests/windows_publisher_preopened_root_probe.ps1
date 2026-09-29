# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$VolumeRoot,
    [Parameter(Mandatory=$true)][string]$ExpectedUserSid,
    [Parameter(Mandatory=$true)][string]$ServiceSid,
    [Parameter(Mandatory=$true)][string]$ReadyPath,
    [Parameter(Mandatory=$true)][string]$ReleasePath
)
$ErrorActionPreference='Stop'
$VolumeRoot=$VolumeRoot.TrimEnd('\')+'\'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]$identity
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $VolumeRoot -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$' -or
    $identity.User.Value -cne $ExpectedUserSid -or
    $identity.User.Value -ceq 'S-1-5-18' -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    @($identity.Groups|Where-Object Value -ceq $ServiceSid).Count -ne 0 -or
    [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($ReadyPath)) -cne
        'C:\USK-Lab\consumer-output' -or
    [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($ReleasePath)) -cne
        'C:\USK-Lab\consumer-output' -or
    [IO.Path]::GetFileName($ReadyPath) -cne 'preopened-root-ready.txt' -or
    [IO.Path]::GetFileName($ReleasePath) -cne 'preopened-root-release.txt' -or
    (Test-Path -LiteralPath $ReadyPath) -or (Test-Path -LiteralPath $ReleasePath)) {
    throw 'Preopened-root probe requires the exact owned non-admin hosted identity and paths'
}
$env:TEMP=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ReadyPath))
$env:TMP=$env:TEMP
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class UskPreopenedRoot {
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle Open(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
}
'@
# FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, all share modes, OPEN_EXISTING,
# FILE_FLAG_BACKUP_SEMANTICS. This handle is opened before root ACL hardening.
$held=[UskPreopenedRoot]::Open($VolumeRoot,0x81,7,[IntPtr]::Zero,3,0x02000000,[IntPtr]::Zero)
if($held.IsInvalid) {
    throw ('Non-admin pre-open of the new volume root failed; Win32 '+
        [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}
try {
    [IO.File]::WriteAllText($ReadyPath,
        ('usk.publisher.preopened_root.v1 '+$PID+' '+$identity.User.Value+"`n"),
        [Text.UTF8Encoding]::new($false))
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    while(-not (Test-Path -LiteralPath $ReleasePath) -and
        [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
    if(-not (Test-Path -LiteralPath $ReleasePath) -or
        [IO.File]::ReadAllText($ReleasePath) -cne "usk.publisher.release_preopened_root.v1`n") {
        throw 'Preopened-root probe release was absent or invalid'
    }
} finally { $held.Dispose() }
