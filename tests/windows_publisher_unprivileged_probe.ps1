param(
    [Parameter(Mandatory = $true)][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedUserSid,
    [Parameter(Mandatory = $true)][string]$ServiceSid,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateSet('Prepublish', 'Postpublish')][string]$Stage = 'Postpublish'
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
$root = $VolumeRoot.TrimEnd('\') + '\'
$receipt = [ordered]@{
    schema = 'usk.publisher.unprivileged_access_probe.v1'
    status = 'not_run'
    process_id = $PID
    user_sid = $identity.User.Value
    administrator = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    service_sid_present = @($identity.Groups | Where-Object {
        $_.Value -eq $ServiceSid
    }).Count -ne 0
    volume_root = $root
    stage = $Stage
    attempts = @()
    failure = $null
}

function Require-Denied {
    param([string]$Name, [scriptblock]$Action)
    try {
        & $Action
        $receipt.attempts += [ordered]@{ name = $Name; outcome = 'unexpected_success' }
        throw "unprivileged $Name unexpectedly succeeded"
    } catch {
        $cause = $_.Exception
        while ($cause.InnerException) { $cause = $cause.InnerException }
        if ($cause.HResult -ne -2147024891) {
            $receipt.attempts += [ordered]@{
                name = $Name
                outcome = 'other_failure'
                hresult = $cause.HResult
                type = $cause.GetType().FullName
            }
            throw
        }
        $receipt.attempts += [ordered]@{
            name = $Name
            outcome = 'access_denied'
            hresult = $cause.HResult
        }
    }
}

try {
    if ($root -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$' -or
        $identity.User.Value -ne $ExpectedUserSid -or
        $receipt.administrator -or $receipt.service_sid_present -or
        $identity.User.Value -eq 'S-1-5-18') {
        throw 'unprivileged process or disposable volume identity mismatch'
    }
    $destination = $root + 'publication\destination'
    if ($Stage -eq 'Prepublish') {
        $candidate = $root + 'publication\staging\candidate'
        $file = $candidate + '\payload.bin'
        Require-Denied 'staged_read' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'staged_write' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'staged_insert' {
            [IO.Directory]::CreateDirectory($candidate + '\hostile-child') | Out-Null
        }
        Require-Denied 'destination_precreate' {
            [IO.Directory]::CreateDirectory($destination + '\visible') | Out-Null
        }
    } else {
        $file = $destination + '\visible\payload.bin'
        Require-Denied 'visible_read' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'visible_write' {
            $handle = [IO.File]::Open($file, [IO.FileMode]::Open,
                [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite -bor
                [IO.FileShare]::Delete)
            $handle.Dispose()
        }
        Require-Denied 'destination_create' {
            [IO.Directory]::CreateDirectory($destination + '\hostile-child') | Out-Null
        }
        Require-Denied 'visible_delete' {
            [IO.File]::Delete($file)
        }
    }
    $receipt.status = 'access_denied_observed'
} catch {
    $receipt.status = 'failed'
    $receipt.failure = $_.Exception.Message
} finally {
    $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
if ($receipt.status -ne 'access_denied_observed') { exit 1 }
