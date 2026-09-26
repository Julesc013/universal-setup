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
    $node.Name -eq 'Assert-IndependentMetadataProbe'
},$true))
if($functions.Count -ne 1){throw 'Exact independent validator function required'}
. ([scriptblock]::Create($functions[0].Extent.Text))
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
    missing_record={param($r) $r.independent.rows=@($r.independent.rows|Where-Object path -cne 'E:\setup-state\.usk-owned-root.v1.json')}
    unexpected_record={param($r) $extra=$r.independent.rows[2].PSObject.Copy();$extra.path='E:\setup-state\extra.json';$r.independent.rows+=@($extra)}
    unexpected_visible_file={param($r) $extra=$r.independent.rows[-1].PSObject.Copy();$extra.path='E:\publication\destination\visible\extra.bin';$r.independent.rows+=@($extra)}
    unexpected_visible_directory={param($r) $extra=$r.independent.rows[-1].PSObject.Copy();$extra.path='E:\publication\destination\visible\extra';$extra.directory=$true;$r.independent.rows+=@($extra)}
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
[ordered]@{status='pass';positive=2;refused=$cases.Count;scope='synthetic readback validation only; no VM/runtime qualification'}|ConvertTo-Json -Compress
