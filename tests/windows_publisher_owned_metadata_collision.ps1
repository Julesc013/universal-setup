# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

function Invoke-IndependentOwnedMetadataCollision {
    param([string]$VhdPath,[string]$VolumeRoot,[string]$DriveRoot,[string]$ServiceName,
        [string]$ServiceSid,[string]$TransactionId)
    if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
        $DriveRoot -cnotmatch '^[A-Z]:\\$' -or $ServiceName -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or
        $TransactionId -cne ('install.'+$ServiceName.Substring(8))) {
        throw 'Metadata collision requires the exact owned public hosted transaction'
    }
    $lab=[IO.Path]::GetFullPath((Split-Path -Parent $VhdPath))
    $runner=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
    if(-not $lab.StartsWith($runner,[StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $lab) -cnotmatch '^usk-wu006-[0-9a-f]{32}$' -or
        (Split-Path -Leaf $VhdPath) -cne 'publisher.vhdx') {
        throw 'Metadata collision backing file is outside its fresh hosted lab'
    }
    $expectedSid=[Security.Principal.NTAccount]::new('NT SERVICE',$ServiceName).Translate([Security.Principal.SecurityIdentifier]).Value
    if($ServiceSid -cne $expectedSid -or (Get-Service $ServiceName).Status -ne 'Stopped') {
        throw 'Metadata collision service identity or stopped boundary differs'
    }
    $id=[guid]::NewGuid().ToString('N')
    $name='USK_METADATA_COLLISION_'+$id
    $script=Join-Path $lab ('metadata-collision-'+$id+'.ps1')
    $output=Join-Path $lab ('metadata-collision-'+$id+'.json')
    if((Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $script) -or (Test-Path -LiteralPath $output) -or
        (Test-Path -LiteralPath ($output+'.pending'))) {throw 'Owned metadata collision resource already exists'}
    $observer=@'
param([string]$VhdPath,[string]$VolumeRoot,[string]$DriveRoot,[string]$ServiceName,
    [string]$ServiceSid,[string]$TransactionId,[string]$Output)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
    $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $ServiceName -cnotmatch '^USK_PUB_[0-9a-f]{32}$' -or $DriveRoot -cnotmatch '^[A-Z]:\\$' -or
    $TransactionId -cne ('install.'+$ServiceName.Substring(8))) {throw 'Owned SYSTEM metadata collision context differs'}
$expectedSid=[Security.Principal.NTAccount]::new('NT SERVICE',$ServiceName).Translate([Security.Principal.SecurityIdentifier]).Value
if($ServiceSid -cne $expectedSid -or (Get-Service $ServiceName).Status -ne 'Stopped') {throw 'Owned collision service changed'}
$image=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
$disk=$image|Get-Disk -ErrorAction Stop
$parts=@($disk|Get-Partition|Where-Object DriveLetter)
if(-not $image.Attached -or $disk.IsBoot -or $disk.IsSystem -or $parts.Count -ne 1) {throw 'Owned collision VHD differs'}
$volume=$parts[0]|Get-Volume
if($volume.UniqueId -cne $VolumeRoot -or $volume.FileSystem -cne 'NTFS' -or
    ([string]$volume.DriveLetter+':\') -cne $DriveRoot) {throw 'Owned collision volume alias differs'}
$root=$DriveRoot+'setup-state'
$marker=Join-Path $root '.usk-owned-root.v1.json'
if(-not (Test-Path -LiteralPath $marker -PathType Leaf) -or
    -not (Test-Path -LiteralPath ($DriveRoot+'publication\destination\visible') -PathType Container)) {
    throw 'Owned metadata collision has no retained public visible boundary'
}
$state=Join-Path $root 'state'
$installed=Join-Path $state 'installed'
$collision=Join-Path $installed ('org.example.metadata.probe.'+$TransactionId+'.json')
$paths=@($collision)
foreach($path in @($root,$state,$installed)) {
    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Owned metadata collision retained parent is absent or substituted'
    }
}
if(Test-Path -LiteralPath $collision){throw 'Owned metadata collision record path is preexisting'}
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$ServiceSid+')')
foreach($path in $paths) {
    # Create only fresh owned fixture directories. The final directory blocks
    # a regular installed-state record without supplying any fabricated JSON.
    [IO.Directory]::CreateDirectory($path,$security)|Out-Null
}
$result=[ordered]@{schema='usk.publisher.owned_metadata_collision.v1';identity='S-1-5-18';
    service=$ServiceName;service_sid=$ServiceSid;transaction_id=$TransactionId;
    volume_root=$VolumeRoot;path=$collision;created_paths=$paths;status='owned_directory_collision_created'}
$temporary=$Output+'.pending'
$stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}
finally {$stream.Dispose()}
[IO.File]::Move($temporary,$Output)
'@
    [IO.File]::WriteAllText($script,$observer,[Text.UTF8Encoding]::new($false))
    $command="& ([scriptblock]::Create([IO.File]::ReadAllText('"+$script.Replace("'","''")+"')))"
    foreach($pair in @(@('VhdPath',$VhdPath),@('VolumeRoot',$VolumeRoot),@('DriveRoot',$DriveRoot),
        @('ServiceName',$ServiceName),@('ServiceSid',$ServiceSid),@('TransactionId',$TransactionId),@('Output',$output))) {
        $command+=' -'+$pair[0]+" '"+$pair[1].Replace("'","''")+"'"
    }
    $arguments='-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $executable=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action=New-ScheduledTaskAction -Execute $executable -Argument $arguments
    $registered=$false
    try {
        Register-ScheduledTask -TaskName $name -Action $action -User SYSTEM -RunLevel Highest|Out-Null
        $registered=$true
        Start-ScheduledTask -TaskName $name
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
        while(-not (Test-Path -LiteralPath $output) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
        if(-not (Test-Path -LiteralPath $output) -or (Get-Item -LiteralPath $output).Length -gt 16KB) {
            $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
            $info=Get-ScheduledTaskInfo -TaskName $name -ErrorAction Stop
            throw ('Owned metadata collision receipt absent or unbounded; task_state='+$task.State+
                '; last_task_result='+$info.LastTaskResult)
        }
        $result=Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
        if($result.schema -cne 'usk.publisher.owned_metadata_collision.v1' -or $result.identity -cne 'S-1-5-18' -or
            $result.status -cne 'owned_directory_collision_created' -or $result.service -cne $ServiceName -or
            $result.service_sid -cne $ServiceSid -or $result.transaction_id -cne $TransactionId -or
            $result.volume_root -cne $VolumeRoot -or $result.path -cne
            ($DriveRoot+'setup-state\state\installed\org.example.metadata.probe.'+$TransactionId+'.json')) {
            throw 'Owned metadata collision receipt differs from the bound fixture'
        }
    } finally {
        if($registered) {
            $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
            $actions=@($task.Actions)
            $principal=if($task.Principal.UserId -ceq 'S-1-5-18'){'S-1-5-18'}else{
                [Security.Principal.NTAccount]::new($task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value
            }
            if($actions.Count -ne 1 -or $actions[0].Execute -cne $executable -or
                $actions[0].Arguments -cne $arguments -or $principal -cne 'S-1-5-18') {
                throw 'Owned collision task identity changed; task retained'
            }
            if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $name -ErrorAction Stop}
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Owned collision task cleanup unconfirmed'}
        }
    }
    return $result
}
