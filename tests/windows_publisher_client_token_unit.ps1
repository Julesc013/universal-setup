# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Owned process/temporary-file unit controls; no SCM, volume or account effects.
param([Parameter(Mandatory=$true)][string]$Root,[switch]$ReadHeld)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($env:USK_CAPTURE_NATIVE))
if($ReadHeld) {
$capture=Get-Content -LiteralPath (Join-Path $Root 'capture.json') -Raw|ConvertFrom-Json
function New-HeldBridge($c) {
 [UskPublisherEffectiveRights]::new([uint32]$c.owner_process_id,[long]$c.owner_creation_file_time,$c.caller_sid,$c.service_sid,
  [uint32]$c.client_process_id,[long]$c.client_creation_file_time,[long]$c.client_process_handle,
  [long]$c.initiating_handle,[long]$c.filtered_handle,$c.initiating_token_id,$c.filtered_token_id)
}
$bridge=New-HeldBridge $capture
try {
 if(-not $bridge.TokenFacts['captured_client']['exited_at_observation']){throw 'Held client is still live'}
 $closed=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$capture.service_sid+')')
 $bytes=[byte[]]::new($closed.BinaryLength);$closed.GetBinaryForm($bytes,0)
 $checks=$bridge.CheckDescriptor($bytes)
 foreach($actor in @('initiating','filtered')) {
  foreach($right in $checks[$actor].GetEnumerator()) {
   if($right.Value['allowed'] -or $right.Value['granted'] -ne 0){throw 'Closed descriptor admitted held client mutation'}
  }
 }
 $owned=[Security.AccessControl.RawSecurityDescriptor]::new('O:'+$capture.caller_sid+'G:SYD:P(A;;FA;;;'+$capture.caller_sid+')')
 $bytes=[byte[]]::new($owned.BinaryLength);$owned.GetBinaryForm($bytes,0)
 if(-not $bridge.CheckDescriptor($bytes)['filtered']['write_or_add_file']['allowed']){throw 'Positive held-token control failed'}
 $ownedLoginGuards=0
 $secret=[Security.SecureString]::new()
 foreach($character in 'OwnedUnitNoLogin123!'.ToCharArray()){$secret.AppendChar($character)}
 $secret.MakeReadOnly()
 try {
  foreach($variant in 0..2) {
   $account='USKOBS_0000000000000';$expectedSid='S-1-5-21-1-2-3-1001';$password=$secret
   switch($variant) {0 {$account='foreign-account'};1 {$expectedSid='S-1-5-18'};2 {$password=$null}}
   try {
    $bridge.HoldOwnedLocalLogin($account,$password,$expectedSid,$capture.service_sid)|Out-Null
    throw 'Invalid owned-login inputs were admitted'
   } catch {
    if($_.Exception.ToString() -notmatch 'Owned local-login binding is incomplete or already held'){throw}
    ++$ownedLoginGuards
   }
  }
 } finally {$secret.Dispose()}
} finally {$bridge.Dispose()}
$refused=0
foreach($change in @(
 {param($c) $c.owner_creation_file_time=([long]$c.owner_creation_file_time+1).ToString()},
 {param($c) $c.client_creation_file_time=([long]$c.client_creation_file_time+1).ToString()},
 {param($c) $c.client_process_id++},
 {param($c) $c.initiating_token_id='0000000000000000'},
 {param($c) $c.filtered_token_id='0000000000000000'},
 {param($c) $c.initiating_handle=$c.client_process_handle},
 {param($c) $c.caller_sid='S-1-5-21-1-2-3-1001'})) {
 $bad=$capture|ConvertTo-Json -Depth 8|ConvertFrom-Json;& $change $bad
 $unexpected=$null
 try {$unexpected=New-HeldBridge $bad;throw 'Contradictory held-token binding admitted'}
 catch {if($_.Exception.Message -ceq 'Contradictory held-token binding admitted'){throw};++$refused}
 finally {if($unexpected){$unexpected.Dispose()}}
}
[ordered]@{held_exited_client_observed=$true;positive_owned_control=$true;closed_actor_checks=18;contradictory_contexts_refused=$refused;invalid_owned_login_inputs_refused=$ownedLoginGuards}|ConvertTo-Json -Compress

return
}
$env:USK_PAUSED_MARKER=Join-Path $root 'executed'
$image=(Get-Command pwsh).Source
$body="[IO.File]::WriteAllText(`$env:USK_PAUSED_MARKER,'executed');[Console]::WriteLine('owned client executed')"
$arguments='-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
$launch=$null;$client=$null;$lease=$null
try {
 $launch=[UskPublisherPausedClient]::new($image,$arguments,(Join-Path $root 'stdout'),(Join-Path $root 'stderr'))
 $client=Get-Process -Id $launch.ProcessId
 $null=$client.Handle
 Start-Sleep -Milliseconds 150
 if(Test-Path -LiteralPath $env:USK_PAUSED_MARKER){throw 'Owned primary thread executed before capture'}
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $lease=[UskPublisherEffectiveRights]::new($launch.ProcessId,$launch.CreationFileTime,$sid,'S-1-5-80-1-2-3-4-5')
 $owner=Get-Process -Id $PID
 $capture=$lease.CaptureBinding($PID,$owner.StartTime.ToUniversalTime().ToFileTimeUtc(),$image)
 $capture['caller_sid']=$sid;$capture['service_sid']='S-1-5-80-1-2-3-4-5'
 $capture|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Root 'capture.json') -Encoding utf8
 $launch.Resume()
 if(-not $client.WaitForExit(10000)){throw 'Owned resumed primary thread did not exit'}
 if($client.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $env:USK_PAUSED_MARKER) -or
  [IO.File]::ReadAllText((Join-Path $root 'stdout')).Trim() -cne 'owned client executed' -or
  [IO.File]::ReadAllText((Join-Path $root 'stderr')).Length){throw 'Owned resumed client result differs'}
 $readerCommand="& ([scriptblock]::Create([IO.File]::ReadAllText(`$env:USK_CAPTURE_UNIT))) -Root '"+$Root.Replace("'","''")+"' -ReadHeld"
 & ((Get-Process -Id $PID).Path) -NoProfile -NonInteractive -Command $readerCommand
 if($LASTEXITCODE -ne 0){throw 'Cross-process held-token controls failed'}
 $secondResumeRefused=$false
 try {$launch.Resume()}catch {$secondResumeRefused=$true}
 if(-not $secondResumeRefused){throw 'Primary thread resumed twice'}
 [ordered]@{primary_thread_paused_during_capture=$true;client_token_captured=$true;resume_once_refused=$secondResumeRefused;stdout_observed=$true}|ConvertTo-Json -Compress
} finally {
 if($lease){$lease.Dispose()}
 try {
  if($client -and -not $client.HasExited) {
   if($launch -and -not $launch.IsResumed){$launch.Dispose()}
   else {$client.Kill()} # This benign unit client creates no child processes.
   if(-not $client.WaitForExit(5000)){throw 'Owned unit client termination unconfirmed'}
  }
 } finally {if($launch){$launch.Dispose()};if($client){$client.Dispose()}}
}
$env:USK_PAUSED_MARKER=Join-Path $root 'never-executed'
$never=[UskPublisherPausedClient]::new($image,$arguments,(Join-Path $root 'never-stdout'),(Join-Path $root 'never-stderr'))
$unused=$null
try {
 $unused=Get-Process -Id $never.ProcessId
 $null=$unused.Handle
 $never.Dispose()
 if(-not $unused.WaitForExit(5000)){throw 'Never-resumed owned client cleanup failed'}
 if(Test-Path -LiteralPath $env:USK_PAUSED_MARKER){throw 'Never-resumed owned client executed its entrypoint'}
} finally {
 try {$never.Dispose()}finally {if($unused){$unused.Dispose()}}
}
[ordered]@{never_resumed_client_termination_confirmed=$true}|ConvertTo-Json -Compress
