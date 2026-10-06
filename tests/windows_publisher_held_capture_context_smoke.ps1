# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Evaluate only the actual generated reader's pure context predicate.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$source=Join-Path $PSScriptRoot 'windows_publisher_metadata_readback.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Readback source does not parse'}
$assignments=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$observer'
},$true))
if($assignments.Count -ne 1){throw 'Generated reader assignment is ambiguous'}
$literals=@($assignments[0].Right.FindAll({param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $node.StringConstantType -eq [Management.Automation.Language.StringConstantType]::SingleQuotedHereString
},$true))
if($literals.Count -ne 1){throw 'Generated reader literal is ambiguous'}
$reader=[Management.Automation.Language.Parser]::ParseInput($literals[0].Value,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Generated reader does not parse'}
$functions=@($reader.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Test-PublisherHeldCaptureRequestContext'
},$true))
if($functions.Count -ne 1){throw 'Held capture context predicate is ambiguous'}
. ([scriptblock]::Create($functions[0].Extent.Text))
$public='public.'+('a'*32);$contention='contention.'+('b'*32)
foreach($command in @('install_local.apply','install_local.recover','installed.verify','publisher.observe',
    'repair.apply','repair.recover','move.apply','move.recover','uninstall.apply','uninstall.recover')) {
    if(-not (Test-PublisherHeldCaptureRequestContext $public $command)){throw 'Existing public capture pair refused'}
    if(Test-PublisherHeldCaptureRequestContext $contention $command){throw 'Cross-context public command admitted'}
}
if(-not (Test-PublisherHeldCaptureRequestContext $contention 'registered_contention')){throw 'Owned contention capture pair refused'}
foreach($pair in @(@($public,'registered_contention'),@($contention,'publisher.observe'),
    @($public,'repair.plan'),@($public,'REPAIR.RECOVER'),@($public,'REPAIR.APPLY'),
    @($public,'publisher.inspect'),@('public.'+('a'*31),'repair.apply'),
    @('public.'+('A'*32),'move.apply'),
    @('contention.'+('B'*32),'registered_contention'),@('contention.'+('b'*31),'registered_contention'),
    @($contention,'REGISTERED_CONTENTION'),@('other.'+('b'*32),'registered_contention'))) {
    if(Test-PublisherHeldCaptureRequestContext $pair[0] $pair[1]){throw 'Contradictory held capture context admitted'}
}
'Held capture context: eleven exact pairs accepted, twenty-two contradictory pairs refused'
