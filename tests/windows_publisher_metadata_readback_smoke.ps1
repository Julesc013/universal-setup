# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
param([Parameter(Mandatory=$true)][string]$SourceRoot)
$ErrorActionPreference='Stop'
# Test the readback oracle without starting a VM, service, or scheduled task.
# These synthetic records are test inputs, never operating-system evidence.
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $SourceRoot 'tests/windows_publisher_metadata_readback.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Probe syntax is invalid'}
$functions=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('Assert-IndependentMetadataProbe','Assert-IndependentProtectedRows')
},$true))
if($functions.Count -ne 2){throw 'Exact independent validator and ACL helper functions required'}
foreach($function in $functions){Set-Item -LiteralPath ('Function:\'+$function.Name) -Value $function.Body.GetScriptBlock()}
$sid='S-1-5-80-1-2-3-4-5'
$digest='a'*64; $ownershipDigest='b'*64; $verificationDigest='c'*64
$completionDigest='d'*64; $eventDigest='e'*64
$time='2026-09-26T00:00:00Z'
$target='E:/publication/destination/visible'
$recipe=@{recipe_digest=$digest;product_id='org.example.synthetic';product_version='1.0.0';components=@('core')}
$rows=[Collections.Generic.List[object]]::new()
function Add-Record([string]$Path,$Record,[string]$Sha=$digest,[long]$Bytes=1) {
    $rows.Add(@{path=$Path;directory=$false;owner='S-1-5-18';protected=$true;bytes=$Bytes;sha256=$Sha;
        content_json=($Record|ConvertTo-Json -Depth 16 -Compress);aces=@(
            @{sid='S-1-5-18';rights=2032127;type='Allow';inherited=$false;inheritance=0;propagation=0},
            @{sid=$sid;rights=2032127;type='Allow';inherited=$false;inheritance=0;propagation=0})})
}
Add-Record 'E:\publication\journal\lab-reviewed-plan.json' @{
    plan_digest=$digest;archive_sha256=$digest;transaction_id='tx.synthetic';applied_at=$time}
Add-Record 'E:\publication\state\lab-installed-state.json' @{
    source_binding=@{reviewed_plan_digest=$digest}} $completionDigest
Add-Record 'E:\setup-state\.usk-owned-root.v1.json' @{
    schema='usk.setup_owned_root.v1';acceptance_root='E:/'}
Add-Record 'E:\setup-state\state\installed\org.example.synthetic.tx.synthetic.json' @{
    schema='usk.installed_state.v1';install_id='org.example.synthetic';transaction_id='tx.synthetic';created_at=$time;
    target_root=$target;source_archive_digest=$digest;recipe_digest=$digest;
    product_id=$recipe.product_id;product_version=$recipe.product_version;component_selection=@('core');
    lifecycle_status='installed';ownership_manifest_ref='ownership/ownership.synthetic.json';
    ownership_manifest_digest=$ownershipDigest;last_verification=@{status='pass';report_digest=$verificationDigest};audit_chain_id='chain.synthetic'}
Add-Record 'E:\setup-state\state\ownership\ownership.synthetic.json' @{
    schema='usk.ownership_manifest.v1';manifest_id='ownership.synthetic';manifest_digest=$ownershipDigest;
    install_id='org.example.synthetic';created_by_transaction_id='tx.synthetic';target_root=$target;
    files=@(@{relative_path='app.bin';size_bytes=5;sha256=$digest})}
$common=@{schema='usk.audit_event.v1';operation='install_local';transaction_id='tx.synthetic';
    plan_id='plan.synthetic';created_at=$time;audit_chain_id='chain.synthetic';status='pass'}
$validated=$common.Clone();$validated.phase='validated';$validated.sequence=0;
$validated.details_digest=$completionDigest;$validated.previous_event_digest=$null;
$validated.subject=@{subject_type='journal';subject_id='plan.synthetic'};$validated.event_digest=$eventDigest
$completed=$common.Clone();$completed.phase='completed';$completed.sequence=1;
$completed.details_digest=$verificationDigest;$completed.previous_event_digest=$eventDigest;
$completed.subject=@{subject_type='installation';subject_id='org.example.synthetic'}
Add-Record 'E:\setup-state\audit\chains\chain.synthetic\00000000000000000000.event.json' $validated
Add-Record 'E:\setup-state\audit\chains\chain.synthetic\00000000000000000001.event.json' $completed
Add-Record 'E:\publication\destination\visible' $null
$rows[$rows.Count-1].directory=$true
$rows[$rows.Count-1].bytes=0
$rows[$rows.Count-1].sha256=$null
Add-Record 'E:\publication\destination\visible\app.bin' $null $digest 5
$fixture=@{volume_drive_root='E:\';native=@{status='pass'};observer_task_removed=$true;service_sid=$sid;archive_sha256=$digest;
    independent=@{identity='S-1-5-18';rows=$rows.ToArray()};request=@{install_id='org.example.synthetic';recipe=$recipe};
    plan=@{plan_digest=$digest;plan_id='plan.synthetic';target=@{root=$target};
        planned_entries=@(@{entry_type='file';relative_path='app.bin';sha256=$digest;size_bytes=5})}}
$serialized=$fixture|ConvertTo-Json -Depth 32 -Compress
Assert-IndependentMetadataProbe ($serialized|ConvertFrom-Json)
$aliasFixture=$serialized.Replace('E:', 'R:')|ConvertFrom-Json
Assert-IndependentMetadataProbe $aliasFixture
function Edit-Record($Result,[string]$Path,[scriptblock]$Edit) {
    $row=@($Result.independent.rows|Where-Object path -ceq $Path)[0]
    $record=$row.content_json|ConvertFrom-Json
    & $Edit $record
    $row.content_json=$record|ConvertTo-Json -Depth 16 -Compress
}
$cases=[ordered]@{
    observer_not_removed={param($r) $r.observer_task_removed=$false}
    wrong_volume_alias={param($r) $r.volume_drive_root='R:\'}
    malformed_volume_alias={param($r) $r.volume_drive_root='E:\ordinary\'}
    non_system_observer={param($r) $r.independent.identity='S-1-5-32-544'}
    partial_installed_state={param($r) $r.independent.rows=@($r.independent.rows|Where-Object path -cne 'E:\setup-state\state\installed\org.example.synthetic.tx.synthetic.json')}
    missing_record={param($r) $r.independent.rows=@($r.independent.rows|Where-Object path -cne 'E:\setup-state\.usk-owned-root.v1.json')}
    unexpected_record={param($r) $extra=$r.independent.rows[2].PSObject.Copy();$extra.path='E:\setup-state\extra.json';$r.independent.rows+=@($extra)}
    unexpected_visible_file={param($r) $extra=$r.independent.rows[-1].PSObject.Copy();$extra.path='E:\publication\destination\visible\extra.bin';$r.independent.rows+=@($extra)}
    unexpected_visible_directory={param($r) $extra=$r.independent.rows[-1].PSObject.Copy();$extra.path='E:\publication\destination\visible\extra';$extra.directory=$true;$r.independent.rows+=@($extra)}
    unexpected_destination_sibling={param($r) $extra=@($r.independent.rows|Where-Object path -ceq 'E:\publication\destination\visible')[0].PSObject.Copy();$extra.path='E:\publication\destination\shadow';$r.independent.rows+=@($extra)}
    wrong_owner={param($r) $r.independent.rows[0].owner='S-1-5-32-544'}
    duplicate_system_ace={param($r) $r.independent.rows[0].aces[1].sid='S-1-5-18'}
    unprotected_acl={param($r) $r.independent.rows[0].protected=$false}
    wrong_payload={param($r) $r.independent.rows[-1].sha256='f'*64}
    wrong_operation_identity={param($r) Edit-Record $r 'E:\setup-state\audit\chains\chain.synthetic\00000000000000000001.event.json' {param($record) $record.transaction_id='another.tx'}}
    broken_audit_chain={param($r) Edit-Record $r 'E:\setup-state\audit\chains\chain.synthetic\00000000000000000001.event.json' {param($record) $record.previous_event_digest='f'*64}}
    substituted_installed_version={param($r) Edit-Record $r 'E:\setup-state\state\installed\org.example.synthetic.tx.synthetic.json' {param($record) $record.product_version='2.0.0'}}
    inconsistent_ownership={param($r) Edit-Record $r 'E:\setup-state\state\ownership\ownership.synthetic.json' {param($record) $record.manifest_digest='f'*64}}
}
foreach($case in $cases.GetEnumerator()) {
    $result=$serialized|ConvertFrom-Json
    & $case.Value $result
    $refused=$false
    try{Assert-IndependentMetadataProbe $result}catch{$refused=$true}
    if(-not $refused){throw ('Readback validator accepted: '+$case.Key)}
}
$consumer=$serialized|ConvertFrom-Json
$consumerSid='S-1-5-21-1-2-3-1001'
$consumer|Add-Member -NotePropertyName consumer_sid -NotePropertyValue $consumerSid
$consumer.native|Add-Member -NotePropertyName consumer_access -NotePropertyValue ([pscustomobject]@{status='read_execute_granted';consumer_sid=$consumerSid})
Edit-Record $consumer 'E:\publication\journal\lab-reviewed-plan.json' {param($r)
    $r|Add-Member -NotePropertyName schema -NotePropertyValue 'usk.publisher.lab_reviewed_plan_snapshot.v4'
    $r|Add-Member -NotePropertyName consumer_read_sid -NotePropertyValue $consumerSid
}
foreach($row in $consumer.independent.rows|Where-Object {$_.path -ceq 'E:\publication\destination\visible' -or $_.path.StartsWith('E:\publication\destination\visible\',[StringComparison]::Ordinal)}) {
    $row.aces+=@([pscustomobject]@{sid=$consumerSid;rights=1179817;type='Allow';inherited=$false;inheritance=0;propagation=0})
}
Assert-IndependentMetadataProbe $consumer
$reorderedConsumer=$consumer|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json
$reader=$reorderedConsumer.independent.rows[-1].aces[2]
$reorderedConsumer.independent.rows[-1].aces[2]=$reorderedConsumer.independent.rows[-1].aces[1]
$reorderedConsumer.independent.rows[-1].aces[1]=$reader
Assert-IndependentMetadataProbe $reorderedConsumer
$consumerBytes=$consumer|ConvertTo-Json -Depth 32 -Compress
$consumerCases=[ordered]@{
    wrong_reader={param($r)$r.independent.rows[-1].aces[-1].sid='S-1-5-21-1-2-3-1002'}
    consumer_write={param($r)$r.independent.rows[-1].aces[-1].rights=1179819}
    inherited_read={param($r)$r.independent.rows[-1].aces[-1].inherited=$true}
    private_grant={param($r)$r.independent.rows[0].aces+=@($r.independent.rows[-1].aces[-1])}
    unbound_policy={param($r)Edit-Record $r 'E:\publication\journal\lab-reviewed-plan.json' {param($record)$record.consumer_read_sid='S-1-5-21-1-2-3-1002'}}
}
foreach($case in $consumerCases.GetEnumerator()) {
    $changed=$consumerBytes|ConvertFrom-Json
    &$case.Value $changed
    $refused=$false
    try{Assert-IndependentMetadataProbe $changed}catch{$refused=$true}
    if(-not $refused){throw ('Consumer oracle accepted: '+$case.Key)}
}
$partial=$consumerBytes|ConvertFrom-Json
$partial.native.status='recovery_required'
$partial.native|Add-Member -NotePropertyName error -NotePropertyValue 'injected interruption after first consumer grant; recovery required'
Assert-IndependentMetadataProbe $partial -AllowPartialConsumerGrant
Edit-Record $partial 'E:\setup-state\audit\chains\chain.synthetic\00000000000000000001.event.json' {param($r)$r.phase='validated'}
$refused=$false
try{Assert-IndependentMetadataProbe $partial -AllowPartialConsumerGrant}catch{$refused=$true}
if(-not $refused){throw 'Partial consumer grant was accepted without completed audit'}
# Exercise the interpreter/root projection with an inert verifier. The real
# verifier's record semantics have their own tests; this grants no authority.
$lease=$serialized|ConvertFrom-Json
$nativeRootId='0123456789abcdef:'+('1'*32)
$lease.independent|Add-Member -NotePropertyName native_volume_root_file_id -NotePropertyValue $nativeRootId
$lease.native|Add-Member -NotePropertyName protected_anchors -NotePropertyValue @{boundary_file_id=$nativeRootId}
$context=$lease.independent.rows[0]|ConvertTo-Json -Depth 32 -Compress|ConvertFrom-Json
$context.path='E:\installation-operations\synthetic\context.json'
$lease.independent.rows+=@($context)
$script:leaseProjectionCalls=0
$script:expectedAllowActive=$false
function Invoke-SyntheticLeaseVerifier {
    if($args.Count -ne 4 -or $args[0] -cne '-B' -or
        (Split-Path -Leaf $args[1]) -cne 'publisher_installation_lease_evidence.py' -or
        $args[2] -cne '--input' -or $args[3] -cne '-') {throw 'Lease verifier invocation differs'}
    $request=($input -join "`n")|ConvertFrom-Json
    if($request.mode -cne 'snapshot' -or $request.volume_root_id -cne $nativeRootId -or
        $request.drive -cne 'E:\' -or $request.installed.install_id -cne $lease.request.install_id -or
        $request.rows.Count -ne $lease.independent.rows.Count -or
        $request.allow_active -ne $script:expectedAllowActive) {throw 'Independent lease inputs differ'}
    $script:leaseProjectionCalls++
    $global:LASTEXITCODE=0
    '{"coordination":{"files":[]}}'
}
Assert-IndependentMetadataProbe $lease -PythonBinary 'Invoke-SyntheticLeaseVerifier'
if($script:leaseProjectionCalls -ne 1){throw 'Explicit lease verifier was not entered'}
foreach($decision in @('already_visible_bound','installed_state_completed_forward','snapshot_only_completed_forward')) {
    $recoveryFixture=$lease|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
    $recoveryFixture.native.PSObject.Properties.Remove('protected_anchors')
    $observation=@{decision=$decision}
    if($decision -ceq 'snapshot_only_completed_forward'){$observation.protected_anchors=@{boundary_file_id=$nativeRootId}}
    $recoveryFixture.native|Add-Member -NotePropertyName recovery_observation -NotePropertyValue $observation
    $recoveryFixture.native|Add-Member -NotePropertyName recovery_installed_response -NotePropertyValue @{
        status='ok';payload=@{install_id=$lease.request.install_id;transaction_id='tx.synthetic'}}
    Assert-IndependentMetadataProbe $recoveryFixture -PythonBinary 'Invoke-SyntheticLeaseVerifier'
}
$partialLease=$consumerBytes|ConvertFrom-Json
$partialLease.native.status='recovery_required'
$partialLease.native|Add-Member -NotePropertyName error -NotePropertyValue 'injected interruption after first consumer grant; recovery required'
$partialLease.independent|Add-Member -NotePropertyName native_volume_root_file_id -NotePropertyValue $nativeRootId
$partialLease.independent.rows+=@($context)
$script:expectedAllowActive=$true
Assert-IndependentMetadataProbe $partialLease -AllowPartialConsumerGrant -PythonBinary 'Invoke-SyntheticLeaseVerifier'
$script:expectedAllowActive=$false
if($script:leaseProjectionCalls -ne 5){throw 'Admitted response shapes did not enter the lease verifier'}
foreach($case in @('interpreter','root','service_root','bound_root')) {
    $changed=$lease|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
    $interpreter='Invoke-SyntheticLeaseVerifier'
    switch($case) {
        interpreter {$interpreter=''}
        root {$changed.independent.native_volume_root_file_id=$null}
        service_root {$changed.native.protected_anchors.boundary_file_id='0123456789abcdef:'+('2'*32)}
        bound_root {$changed.independent|Add-Member -NotePropertyName volume_boundary -NotePropertyValue @{root=@{file_id='0123456789abcdef:'+('2'*32)}}}
    }
    $refused=$false
    try{Assert-IndependentMetadataProbe $changed -PythonBinary $interpreter}catch{$refused=$true}
    if(-not $refused -or $script:leaseProjectionCalls -ne 5){throw ('Unbound lease input reached the verifier: '+$case)}
}
$shapeCases=[ordered]@{
    missing_apply_anchor={param($r)$r.native.PSObject.Properties.Remove('protected_anchors')}
    unknown_recovery={param($r)$r.native.recovery_observation.decision='recovery_required'}
    missing_recovery_response={param($r)$r.native.PSObject.Properties.Remove('recovery_installed_response')}
    wrong_recovery_operation={param($r)$r.native.recovery_installed_response.payload.transaction_id='tx.foreign'}
    conflicting_modes={param($r)$r.native|Add-Member -NotePropertyName protected_anchors -NotePropertyValue @{boundary_file_id=$nativeRootId}}
    snapshot_root={param($r)$r.native.recovery_observation.protected_anchors.boundary_file_id='0123456789abcdef:'+('2'*32)}
}
foreach($case in $shapeCases.GetEnumerator()) {
    $changed=$(if($case.Key -ceq 'missing_apply_anchor'){$lease}else{$recoveryFixture})|ConvertTo-Json -Depth 64 -Compress|ConvertFrom-Json
    &$case.Value $changed
    $refused=$false
    try{Assert-IndependentMetadataProbe $changed -PythonBinary 'Invoke-SyntheticLeaseVerifier'}catch{$refused=$true}
    if(-not $refused -or $script:leaseProjectionCalls -ne 5){throw ('Unbound response shape reached the verifier: '+$case.Key)}
}
[ordered]@{status='pass';positive=10;refused=($cases.Count+$consumerCases.Count+5+$shapeCases.Count);scope='synthetic readback validation only; no VM/runtime qualification'}|ConvertTo-Json -Compress
