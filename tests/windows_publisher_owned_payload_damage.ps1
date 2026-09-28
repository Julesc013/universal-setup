# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Invoke-IndependentOwnedPayloadDamage {
    param(
        [Parameter(Mandatory=$true)][string]$VhdPath,
        [Parameter(Mandatory=$true)][string]$VolumeRoot,
        [Parameter(Mandatory=$true)][string]$DriveRoot,
        [Parameter(Mandatory=$true)][string]$VisibleRoot,
        [Parameter(Mandatory=$true)][string]$PayloadRelativePath,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256
    )
    $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $runnerTemp=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
    $vhd=[IO.Path]::GetFullPath($VhdPath)
    if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
        -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        -not $vhd.StartsWith($runnerTemp+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $vhd -PathType Leaf) -or
        $DriveRoot -cnotmatch '^[A-Z]:\\$' -or
        $VisibleRoot -cnotmatch '^[A-Z]:\\publication\\destination\\[A-Za-z0-9_.-]+$' -or
        -not $VisibleRoot.StartsWith($DriveRoot+'publication\destination\',[StringComparison]::Ordinal) -or
        $PayloadRelativePath -cnotmatch '^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)*$' -or
        @($PayloadRelativePath.Split('/')|Where-Object {$_ -eq '.' -or $_ -eq '..'}).Count -ne 0 -or
        $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Owned payload damage requires an exact hosted disposable volume and selected file'
    }
    $image=Get-DiskImage -ImagePath $vhd -ErrorAction Stop
    $disk=@($image|Get-Disk -ErrorAction Stop)
    $partition=@($disk|Get-Partition -ErrorAction Stop|Where-Object DriveLetter)
    if(-not $image.Attached -or $disk.Count -ne 1 -or $disk[0].IsBoot -or $disk[0].IsSystem -or
        $partition.Count -ne 1 -or $partition[0].DriveLetter -cne $DriveRoot[0] -or
        (Get-Volume -Partition $partition[0] -ErrorAction Stop).UniqueId -ne $VolumeRoot) {
        throw 'Owned payload damage volume differs from the disposable VHD'
    }
    $target=$VisibleRoot+'\'+$PayloadRelativePath.Replace('/','\')
    $id=[guid]::NewGuid().ToString('N')
    $name='USK_PAYLOAD_DAMAGE_'+$id
    $outputRoot=Split-Path -Parent $vhd
    $output=Join-Path $outputRoot ('payload-damage-'+$id+'.json')
    if((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $output)) {
        throw 'Owned payload damage task or output collision'
    }
    $body=@'
param([string]$Target,[string]$ExpectedSha256,[string]$VhdPath,[string]$VolumeRoot,[string]$DriveRoot,[string]$VisibleRoot,[string]$Output)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {throw 'SYSTEM payload damage identity required'}
$image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
$disk=@($image|Get-Disk -ErrorAction Stop)
$partition=@($disk|Get-Partition -ErrorAction Stop|Where-Object DriveLetter)
if(-not $image.Attached -or $disk.Count -ne 1 -or $disk[0].IsBoot -or $disk[0].IsSystem -or
    $partition.Count -ne 1 -or $partition[0].DriveLetter -cne $DriveRoot[0] -or
    (Get-Volume -Partition $partition[0] -ErrorAction Stop).UniqueId -ne $VolumeRoot -or
    -not $VisibleRoot.StartsWith($DriveRoot+'publication\destination\',[StringComparison]::Ordinal) -or
    -not $Target.StartsWith($VisibleRoot+'\',[StringComparison]::Ordinal)) {
    throw 'SYSTEM payload damage volume or target changed'
}
$item=Get-Item -LiteralPath $Target -Force -ErrorAction Stop
if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $item.Length -lt 1 -or $item.Length -gt 16MB) {throw 'Selected damage target is not a bounded regular file'}
$before=(Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
if($before -cne $ExpectedSha256) {throw 'Selected damage target no longer has reviewed bytes'}
$stream=[IO.File]::Open($Target,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $first=$stream.ReadByte()
    if($first -lt 0){throw 'Selected damage target became empty'}
    $stream.Position=0
    $stream.WriteByte([byte]($first -bxor 1))
    $stream.Flush($true)
} finally {$stream.Dispose()}
$after=(Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
if($after -ceq $before){throw 'Selected payload damage did not change content'}
[ordered]@{schema='usk.publisher.owned_payload_damage.v1';identity='S-1-5-18';
    path=$Target;bytes=$item.Length;before_sha256=$before;after_sha256=$after}|
    ConvertTo-Json -Compress|Set-Content -LiteralPath $Output -Encoding utf8
'@
    $quote={param($value) "'"+$value.Replace("'","''")+"'"}
    # Keep executable text in the registered task action. A separate script
    # under runner temp could be replaced between registration and SYSTEM run.
    $command='& ([scriptblock]::Create('+(& $quote $body)+'))'+
        ' -Target '+(& $quote $target)+' -ExpectedSha256 '+(& $quote $ExpectedSha256)+
        ' -VhdPath '+(& $quote $vhd)+' -VolumeRoot '+(& $quote $VolumeRoot)+
        ' -DriveRoot '+(& $quote $DriveRoot)+' -VisibleRoot '+(& $quote $VisibleRoot)+
        ' -Output '+(& $quote $output)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $name -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $name
        $deadline=[DateTime]::UtcNow.AddSeconds(45)
        while(-not (Test-Path -LiteralPath $output) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 250}
        if(-not (Test-Path -LiteralPath $output)){throw 'Owned SYSTEM payload damage receipt absent'}
        $result=Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
        if($result.schema -cne 'usk.publisher.owned_payload_damage.v1' -or
            $result.identity -cne 'S-1-5-18' -or $result.path -cne $target -or
            $result.before_sha256 -cne $ExpectedSha256 -or
            $result.after_sha256 -ceq $ExpectedSha256) {
            throw 'Owned SYSTEM payload damage receipt differs'
        }
        return $result
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $name -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Owned damage task cleanup failed'}
        }
        if(Test-Path -LiteralPath $output){Remove-Item -LiteralPath $output -Force -ErrorAction Stop}
    }
}
