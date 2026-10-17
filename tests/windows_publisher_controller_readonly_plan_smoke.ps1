# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param([string]$MachineBinary='')
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1'))
$tokens=$null;$errors=$null
$outer=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors){throw 'Readback source does not parse'}
$strings=@($outer.FindAll({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and
 $n.Value.Contains('public static class UskMetadataFacts')},$true))
if($strings.Count -ne 1){throw 'Actual observer is ambiguous'}
$observer=$strings[0].Value
$native=[regex]::Match($observer,'(?s) Add-Type -TypeDefinition @"\r?\n(.*?)"@')
if(-not $native.Success){throw 'Actual native prefix reader is absent'}
Add-Type -TypeDefinition $native.Groups[1].Value
$ast=[Management.Automation.Language.Parser]::ParseInput($observer,[ref]$tokens,[ref]$errors)
if($errors){throw 'Actual observer does not parse'}
$blocks=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Extent.Text.StartsWith('if($MaintenancePlanningBinding)',[StringComparison]::Ordinal)},$true))
if($blocks.Count -ne 1){throw 'Actual planning block is ambiguous'}
$statements=$blocks[0].Clauses[0].Item2.Statements
$try=@($statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
$final=@($statements|Where-Object {$_.Extent.Text -ceq 'if($planningFailure){throw $planningFailure}'})
$start=@($try[0].Body.Statements|Where-Object {
 $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$stdout'})
if($try.Count -ne 1 -or $final.Count -ne 1 -or $start.Count -ne 1){throw 'Actual process/error tail differs'}
# Only the real process/catch/finally tail is exercised. No SYSTEM gate,
# scheduled task, installed ownership or native authority is manufactured.
$tail=[scriptblock]::Create('try {'+$observer.Substring($start[0].Extent.StartOffset,
 $final[0].Extent.EndOffset-$start[0].Extent.StartOffset))
$script:realStart=Get-Command Start-Process -CommandType Cmdlet
function Start-Process {
 param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
 if($WindowStyle -cne 'Hidden' -or $ArgumentList[0] -cne '--machine' -or
  $ArgumentList[1] -cne '--request-file' -or $ArgumentList[3] -cne '--context-file') {
  throw 'Readonly planner lost fixed arguments or hidden execution'
 }
 if($script:scenario -ceq 'real_refusal'){return & $script:realStart @PSBoundParameters}
 if($script:scenario -ceq 'empty'){$text=''}
 elseif($script:scenario -cin @('success','mismatch','cleanup_only_failure')) {
  $text=@{schema='usk.oneshot_response.v1';request_id=$(if($script:scenario -ceq 'mismatch'){'wrong'}else{'plan.test'});
   status='ok';result=@{status='ok';payload=@{plan_id='plan.test'}}}|ConvertTo-Json -Depth 8 -Compress
 } else {$text='actual-failure:'+([char]0x03c0).ToString()*5000}
 [IO.File]::WriteAllText($RedirectStandardOutput,$text,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText($RedirectStandardError,'actual-stderr-'+('e'*4000),[Text.UTF8Encoding]::new($false))
 if($script:scenario -ceq 'capture_failure') {
  New-Item -ItemType HardLink -Path ($RedirectStandardOutput+'.link') -Target $RedirectStandardOutput|Out-Null
 }
 return $script:inert
}
$script:inert=[pscustomobject]@{Id=7123;ExitCode=4}
$script:inert|Add-Member -MemberType ScriptProperty -Name Handle -Value {
 $script:handleObserved=$true;return [IntPtr]7123
}
$script:inert|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
 param($Milliseconds)
 if(-not $script:handleObserved){throw 'Planner waited before retaining its process handle'}
 if($null -eq $Milliseconds){return}
 return ($script:scenario -cne 'timeout' -or $Milliseconds -ne 30000)
}
$script:inert|Add-Member -MemberType ScriptMethod -Name Kill -Value {$script:killed=$true}
$script:inert|Add-Member -MemberType ScriptMethod -Name Dispose -Value {
 if($script:scenario -cin @('cleanup_failure','cleanup_only_failure')){throw 'Injected planner handle close failure'}
}
$root=[IO.Path]::Combine([IO.Path]::GetTempPath(),('usk-plan-diagnostic-'+[guid]::NewGuid().ToString('N')))
[IO.Directory]::CreateDirectory($root)|Out-Null
$scenarios=@('failure','empty','mismatch','timeout','capture_failure','cleanup_failure','cleanup_only_failure','success')
if($MachineBinary){$scenarios+=@('real_refusal')}
$directories=[Collections.Generic.List[string]]::new()
try {
 foreach($script:scenario in $scenarios) {
  $directory=Join-Path $root $script:scenario;$directories.Add($directory)
  [IO.Directory]::CreateDirectory($directory)|Out-Null
  $request=@{schema='usk.oneshot_request.v1';request_id='plan.test';command='uninstall.plan';dry_run=$true;
   payload=@{schema='usk.uninstall_plan_request.v1';request_id='inner.test';plan_id='plan.test';
    install_id='absent.install';created_at='2026-10-18T00:00:00Z'}}
  $binding=@{request=(Join-Path $directory 'request.json');context=(Join-Path $directory 'context.json');
   machine=$MachineBinary;request_sha256=('a'*64);context_sha256=('b'*64);machine_sha256=('c'*64)}
  [IO.File]::WriteAllText($binding.request,($request|ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText($binding.context,(@{schema='usk.oneshot_context.v1';state_root=(Join-Path $directory 'absent-setup');
   authorized_acceptance_root=$directory;target_policy_activation='operator_acceptance_candidate'}|ConvertTo-Json -Compress),
   [Text.UTF8Encoding]::new($false))
  $planner=$null;$plannerEnded=$false;$planningFailure=$null;$planningDiagnostic=$null
  $global:UskMetadataReadonlyPlanningFailure=$null;$script:killed=$false;$script:handleObserved=$false
  $script:inert.ExitCode=if($script:scenario -cin @('empty','mismatch','cleanup_only_failure','success')){0}else{4}
  $held=[Collections.Generic.List[object]]::new();$ownedStream=[IO.MemoryStream]::new();$held.Add($ownedStream)
  $result=@{};$caught=$null
  try {. $tail} catch {$caught=$_}
  if($ownedStream.CanRead){throw 'Planner forgot another held input'}
  $diagnostic=$global:UskMetadataReadonlyPlanningFailure
  if($script:scenario -ceq 'success') {
   if($caught -or $diagnostic -or -not $result.maintenance_plan){throw 'Successful plan changed'}
  } else {
   if(-not $caught -or -not $diagnostic -or $result.maintenance_plan -or
    $diagnostic.schema -cne 'usk.controller_readonly_plan_failure.v1' -or $diagnostic.qualification_granted -or
    $diagnostic.authority_granted -or $diagnostic.request_id -cne 'plan.test' -or
    $diagnostic.request_sha256 -cne $binding.request_sha256){throw 'Failed plan escaped or lost binding'}
   if($script:scenario -ceq 'timeout') {
    if($caught.Exception.Message -cne 'Readonly maintenance planner exceeded its bound' -or
     $diagnostic.planner_exited -or $null -ne $diagnostic.exit_code -or -not $script:killed) {
     throw 'Timeout manufactured exit or lost original failure'
    }
   } else {
    $expectedExit=if($script:scenario -cin @('empty','mismatch','cleanup_only_failure')){0}else{4}
    if(-not $diagnostic.planner_exited -or $diagnostic.exit_code -ne $expectedExit) {
     throw ('Actual exit observation changed: '+(@{case=$script:scenario;expected=$expectedExit;
       primary=$caught.Exception.Message;diagnostic=$diagnostic}|ConvertTo-Json -Depth 8 -Compress))
    }
   }
   if($script:scenario -ceq 'cleanup_failure' -and
    $caught.Exception.Message -cne 'Readonly maintenance planner did not return a bounded success') {
    throw 'Secondary cleanup error replaced the original planner refusal'
   }
   if($script:scenario -ceq 'cleanup_only_failure' -and
    $caught.Exception.Message -cnotlike '*Injected planner handle close failure*') {
    throw 'Cleanup-only failure lost its primary error'
   }
   if($script:scenario -ceq 'capture_failure') {
    if($diagnostic.stdout.capture_status -cne 'unavailable' -or $diagnostic.stdout.complete_file_claimed -or
     $caught.Exception.Message -cne 'Readonly maintenance planner did not return a bounded success') {
     throw 'Diagnostic read failure masked original refusal'
    }
   } else {
    foreach($role in @('stdout','stderr')) {
     $capture=$diagnostic[$role];$path=$binding.request+'.plan.'+$role
     $bytes=[IO.File]::ReadAllBytes($path);$prefix=[Convert]::FromBase64String($capture.captured_bytes_base64)
     $limit=if($role -ceq 'stdout'){4096}else{2048}
     if($capture.capture_status -cne 'captured_prefix' -or $capture.complete_file_claimed -or
      -not $capture.potentially_partial -or $capture.observed_bytes -ne $bytes.Length -or
      $capture.captured_bytes -ne [Math]::Min($bytes.Length,$limit)) {throw 'Bounded prefix length/claim differs'}
     for($i=0;$i -lt $prefix.Length;$i++){if($bytes[$i] -ne $prefix[$i]){throw 'Actual prefix bytes differ'}}
     $sha=[Security.Cryptography.SHA256]::Create()
     try {$hash=([BitConverter]::ToString($sha.ComputeHash($prefix))).Replace('-','').ToLowerInvariant()}
     finally {$sha.Dispose()}
     if($capture.captured_bytes_sha256 -cne $hash){throw 'Captured-prefix hash differs'}
    }
   }
   if($script:scenario -ceq 'real_refusal') {
    $reply=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($diagnostic.stdout.captured_bytes_base64))|ConvertFrom-Json
    if($reply.schema -cne 'usk.oneshot_response.v1' -or $reply.request_id -cne 'plan.test' -or
     $reply.status -cne 'refused' -or $diagnostic.exit_code -ne 4 -or
     (Test-Path -LiteralPath (Join-Path $directory 'absent-setup'))){throw 'Actual local machine refusal differs'}
   }
  }
 }
 foreach($limit in @(0,8193)) {
  $refused=$false
  try {[UskMetadataFacts]::ReadDiagnosticPrefix($binding.request+'.plan.stdout',$limit)|Out-Null}
  catch {$refused=$true}
  if(-not $refused){throw 'Prefix accepted an unbounded limit'}
 }
} finally {
 # Exact ordinary files created above. Never recursively retire unknown data.
 foreach($directory in $directories) {
  foreach($name in @('request.json','context.json','request.json.plan.stdout','request.json.plan.stderr','request.json.plan.stdout.link')) {
   [IO.File]::Delete((Join-Path $directory $name))
  }
  [IO.Directory]::Delete($directory)
 }
 [IO.Directory]::Delete($root)
}
Write-Output ('PASS readonly planner diagnostics: '+$scenarios.Count+' cases; actual native prefixes; no authority grant')
