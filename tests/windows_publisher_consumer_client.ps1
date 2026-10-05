# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param(
    [Parameter(Mandatory=$true)][string]$ExpectedUserSid,
    [Parameter(Mandatory=$true)][string]$IdentityPath,
    [string]$ClientBinary='', [string]$ServiceName='', [string]$RequestFile='',
    [ValidateSet('service','candidate-service','machine-one-shot')][string]$ClientMode='service',
    [string]$ExpectedClientSha256='',
    [string]$PayloadRoot='', [string]$AccessReceipt=''
)
$ErrorActionPreference='Stop'
$env:TEMP=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($IdentityPath))
$env:TMP=$env:TEMP
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]$identity
$observed=[ordered]@{user_sid=$identity.User.Value;administrator=$principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator);process_id=$PID;
    privileges=((& whoami.exe /priv /fo csv /nh) -join "`n")}
if($observed.user_sid -cne $ExpectedUserSid -or $observed.administrator -or
    $observed.user_sid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$') {
    throw 'Consumer process is not the admitted non-admin account'
}
$observed|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $IdentityPath -Encoding utf8
if($PayloadRoot) {
    if($PayloadRoot -cnotmatch '^[A-Z]:\\publication\\destination\\(?:visible|selected-app)$') {
        throw 'Exact admitted visible fixture path required'
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class USKConsumerAccessProbe {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr CreateFile(string path,uint access,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
'@
    $attempts=[Collections.Generic.List[object]]::new()
    function Require-Denied([string]$Name,[string]$Path,[uint32]$Access) {
        $handle=[USKConsumerAccessProbe]::CreateFile($Path,$Access,7,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero)
        $error=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if($handle -ne [IntPtr]::new(-1)) {
            [USKConsumerAccessProbe]::CloseHandle($handle)|Out-Null
            throw ('Consumer unexpectedly acquired '+$Name+' rights')
        }
        if($error -ne 5){throw ('Consumer denial did not establish access denied: '+$Name+'; '+$error)}
        $attempts.Add([ordered]@{name=$Name;win32_error=$error})
    }
    $files=@(Get-ChildItem -LiteralPath (Join-Path $PayloadRoot 'bin') -File)
    if($files.Count -ne 2){throw 'Consumer-visible fixture file closure differs'}
    $hashes=@($files|ForEach-Object {[ordered]@{path=$_.FullName;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    foreach($file in $files) {
        Require-Denied 'payload_write' $file.FullName 2
        Require-Denied 'payload_delete' $file.FullName 0x10000
        Require-Denied 'payload_write_dac' $file.FullName 0x40000
        Require-Denied 'payload_write_owner' $file.FullName 0x80000
    }
    Require-Denied 'visible_add_file' $PayloadRoot 2
    Require-Denied 'visible_delete_child' $PayloadRoot 0x40
    Require-Denied 'visible_write_dac' $PayloadRoot 0x40000
    $drive=[IO.Path]::GetPathRoot($PayloadRoot)
    foreach($private in @('publication\staging','publication\journal','publication\state','setup-state')) {
        Require-Denied 'private_list' ($drive+$private) 1
        Require-Denied 'private_write_dac' ($drive+$private) 0x40000
    }
    $payload=Join-Path $PayloadRoot 'bin\core.exe'
    $output=& $payload
    if($LASTEXITCODE -ne 0 -or ($output -join "`n") -cne 'hello from an independently built product') {
        throw 'Published neutral executable did not run as the admitted consumer'
    }
    [ordered]@{schema='usk.publisher.consumer_access_observation.v1';status='pass';identity=$observed;
        files=$hashes;execution_output=($output -join "`n");denied=$attempts.ToArray()}|
        ConvertTo-Json -Depth 6|Set-Content -LiteralPath $AccessReceipt -Encoding utf8
    exit 0
}
if(-not $ClientBinary -or -not $ServiceName -or -not $RequestFile){throw 'Client request inputs missing'}
if($ExpectedClientSha256 -cnotmatch '^[0-9a-f]{64}$'){
    throw 'Exact expected client binary digest is required'
}
$clientPath=[IO.Path]::GetFullPath($ClientBinary)
$clientDigest=(Get-FileHash -LiteralPath $clientPath -Algorithm SHA256).Hash.ToLowerInvariant()
if($clientDigest -cne $ExpectedClientSha256){throw 'Client binary differs from parent selection'}
$observed['client_binary_path']=$clientPath
$observed['client_binary_sha256']=$clientDigest
$observed['client_mode']=$ClientMode
$observed|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $IdentityPath -Encoding utf8
if($ClientMode -eq 'machine-one-shot') {
    & $clientPath --machine --candidate-service $ServiceName --request-file $RequestFile
} else {
    & $clientPath ('--'+$ClientMode) $ServiceName --request-file $RequestFile
}
exit $LASTEXITCODE
