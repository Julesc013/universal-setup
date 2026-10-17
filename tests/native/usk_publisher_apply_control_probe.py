# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Changed registered requests must refuse before starting an SCM service."""

from __future__ import annotations

import hashlib
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


def write_json(path: Path, value: dict) -> str:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def verify_fixture_retention(repository: Path, root: Path) -> None:
    # Execute the fixtures' actual catch/finally blocks. Replace only disk and
    # process effects: no VHD, mount, service or administrator token is needed.
    driver = root / "fixture-retention.ps1"
    driver.write_text(r'''
param([string]$Repository,[string]$Scratch)
$ErrorActionPreference='Stop'
function Read-OuterTry([string]$Name) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Repository ('tests\'+$Name)),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Fixture parse failed'}
    $tries=@($ast.EndBlock.Statements|Where-Object {
        $_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally})
    if(-not $tries.Count){throw 'Fixture outer cleanup is missing'}
    return $tries[-1]
}
function Read-Block($Block) {
    $source=$Block.Extent.Text
    return [scriptblock]::Create($source.Substring(1,$source.Length-2))
}
function Get-DiskImage([string]$ImagePath,[object]$ErrorAction) {
    if($ImagePath -cne $vhd){throw 'Unexpected cleanup image'}
    $script:imageQueries++
    return [pscustomobject]@{Attached=$true}
}
function Dismount-DiskImage([string]$ImagePath,[object]$ErrorAction) {
    if($ImagePath -cne $vhd){throw 'Unexpected dismount image'}
    $script:dismountCalls++
}
function Remove-Item([string]$LiteralPath,[switch]$Force,[object]$ErrorAction) {
    if($LiteralPath -cne $vhd){throw 'Unexpected deletion target'}
    $script:deleteCalls++
    [IO.File]::Delete($LiteralPath)
}
$outer=Read-OuterTry 'windows_publisher_lab_probe.ps1'
$cleanup=Read-Block $outer.Finally
$vhd=Join-Path $Scratch 'cleanup-owned-vhd-sentinel.vhdx'
$out=Join-Path $Scratch 'cleanup-receipt.json'
$PublicStandardClient=$false;$standardLauncherClosed=$true;$mounted=$true
$cases=@(
    @{name='missing';observation=$null;retain=$true},
    @{name='service';observation=@{service_removed=$false};retain=$true},
    @{name='binary';observation=@{service_removed=$true;client_cleanup_confirmed=$true};retain=$true},
    @{name='client';observation=@{service_removed=$true;protected_service_binary_removed=$true};retain=$true},
    @{name='untyped';observation=@{service_removed='true';protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$true},
    @{name='refused';observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true;retirement_cleanup_failure='refused'};retain=$true},
    @{name='launcher';observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$true;launcher_closed=$false},
    @{name='confirmed';observation=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};retain=$false},
    @{name='legacy';observation=$null;retain=$false})
foreach($case in $cases) {
    [IO.File]::WriteAllText($vhd,'owned cleanup sentinel')
    $script:imageQueries=0;$script:dismountCalls=0;$script:deleteCalls=0
    $AdmittedTarget=$case.name -cne 'legacy';$failure=$null
    $controllerLauncherClosed=-not $case.ContainsKey('launcher_closed') -or $case.launcher_closed
    $receipt=[ordered]@{status='fixture_body_passed';service_observation=$case.observation}
    . $cleanup
    $retained=Test-Path -LiteralPath $vhd -PathType Leaf
    if($case.retain) {
        if(-not $retained -or $script:imageQueries -or $script:dismountCalls -or $script:deleteCalls -or
            -not $failure -or $receipt.status -cne 'failed') {
            throw ('Unconfirmed retirement reached VHD cleanup: '+$case.name)
        }
    } elseif($retained -or $script:imageQueries -ne 1 -or $script:dismountCalls -ne 1 -or
        $script:deleteCalls -ne 1 -or $failure) {
        throw ('Confirmed or legacy cleanup changed: '+$case.name)
    }
}
# The original failure must survive a second exception in real client cleanup.
function Stop-OwnedPublisherProcessTree($Process) {throw 'synthetic client cleanup failure'}
$inner=Read-OuterTry 'windows_publisher_metadata_hosted_probe.ps1'
$primaryCatch=Read-Block $inner.CatchClauses[0].Body
$innerCleanup=Read-Block $inner.Finally
$AdmittedTarget=$true;$RegisteredService=$false;$registrationAttempted=$false;$created=$false
$consumerCreated=$false;$unrelatedAccountCreated=$false;$clientCleanupConfirmed=$true
$requestClient=[pscustomobject]@{process='owned fixture process'}
$consumerProcess=$null;$concurrentAttacker=$null;$unrelatedAttacker=$null;$preopenedRootProcess=$null
$stageObserver=$null;$postrenameObserver=$null
$observerRoot=Join-Path $Scratch 'nonexistent-observer-root'
$receipt=[ordered]@{status='pending'};$failure=$null
try {throw 'synthetic primary request failure'} catch {. $primaryCatch}
. $innerCleanup
if($failure -cne 'synthetic primary request failure' -or
    $receipt.primary_failure -cne $failure -or $receipt.failure -cne $failure -or
    $receipt.cleanup_failure -cne 'Owned client cleanup failed: synthetic client cleanup failure' -or
    $receipt.client_cleanup_confirmed -ne $false -or $receipt.status -cne 'failed') {
    throw 'Client cleanup obscured the primary request failure'
}
# Execute the account finalizer itself, with inert account effects. A closed
# launcher alone cannot retire an account still bound to product authority.
$tokens=$null;$errors=$null
$helperAst=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Repository 'tests\windows_publisher_standard_launcher.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Launcher parse failed'}
$actorFunction=$helperAst.Find({param($Node)
    $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -ceq 'Invoke-OwnedPublisherFixtureTask'},$false)
$actorTries=@($actorFunction.Body.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally})
if($actorTries.Count -ne 1){throw 'Owned account finalizer is missing or ambiguous'}
$accountCleanup=Read-Block $actorTries[0].Finally
function Get-LocalUser($SID,$ErrorAction) {
    if($script:accountReadFailure){throw 'synthetic account cleanup failure'}
    if($script:accountPresent){return [pscustomobject]@{Name=$accountName;Description=$taskName}}
}
function Remove-LocalUser($SID,$ErrorAction) {$script:accountDeletes++;$script:accountPresent=$false}
$named=$true;$accountAttempted=$true;$accountSid='S-1-5-21-1-2-3-1001'
$accountName='USKCTL_fixture';$taskName='USK_ADMITTED_CONTROLLER_'+('a'*32)
$OutputPath=Join-Path $Scratch 'actor-child.json';$secure=$null
$cases=@(
    @{name='live';closed=$false;state=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};remove=$false},
    @{name='authority';closed=$true;state=@{service_removed=$false;client_cleanup_confirmed=$true};remove=$false},
    @{name='binary';closed=$true;state=@{service_removed=$true;client_cleanup_confirmed=$true};remove=$false},
    @{name='untyped';closed=$true;state=@{service_removed='true';protected_service_binary_removed=$true;client_cleanup_confirmed=$true};remove=$false},
    @{name='retired';closed=$true;state=@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true};remove=$true},
    @{name='probe';closed=$true;probe=$true;state=@{schema='usk.publisher_controller_actor_probe.v1';scope='identity_only_no_product_dispatch';status='passed'};remove=$true},
    @{name='wrong_scope';closed=$true;probe=$true;state=@{schema='usk.publisher_controller_actor_probe.v1';scope='product_dispatch';status='passed'};remove=$false})
foreach($case in $cases) {
    $case.state|ConvertTo-Json|Set-Content -LiteralPath $OutputPath -Encoding utf8
    $actorClosed=$case.closed;$IdentityProbe=[bool]$case.probe;$actorOriginalError=$null
    $script:accountReadFailure=$false;$script:accountPresent=$true;$script:accountDeletes=0
    $controllerActorObservation=[ordered]@{account_removed=$false;account_retained=$false}
    . $accountCleanup
    if(($script:accountDeletes -eq 1) -ne $case.remove -or
        $controllerActorObservation.account_removed -ne $case.remove -or
        $controllerActorObservation.account_retained -eq $case.remove) {
        throw ('Owned controller account retirement differs: '+$case.name)
    }
}
$IdentityProbe=$false;$actorClosed=$true
@{service_removed=$true;protected_service_binary_removed=$true;client_cleanup_confirmed=$true}|
    ConvertTo-Json|Set-Content -LiteralPath $OutputPath -Encoding utf8
try {throw 'original actor failure'} catch {$actorOriginalError=$_}
$script:accountReadFailure=$true;$script:accountDeletes=0
$controllerActorObservation=[ordered]@{account_removed=$false;account_retained=$false}
. $accountCleanup
if($script:accountDeletes -or -not $controllerActorObservation.account_retained -or
    $controllerActorObservation.account_cleanup_failure -cne 'synthetic account cleanup failure' -or
    $actorOriginalError.Exception.Message -cne 'original actor failure') {
    throw 'Account cleanup erased original failure or removed an uncertain account'
}
''', encoding="utf-8")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(driver), "-Repository", str(repository), "-Scratch", str(root)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"fixture cleanup containment failed: {result}")


def main() -> int:
    executable = Path(sys.argv[1]).resolve(strict=True)
    service = "USK_PUB_" + uuid.uuid4().hex
    volume = r"\\?\Volume{00000000-0000-0000-0000-000000000000}" + "\\"
    identity = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                              capture_output=True, text=True, timeout=10, check=True)
    caller = next(csv.reader(identity.stdout.splitlines()))[1]
    with tempfile.TemporaryDirectory(prefix="usk-reviewed-apply-") as directory:
        root = Path(directory)
        envelope_file = root / "envelope.json"
        apply_file = root / "apply.json"
        apply = {"schema": "usk.install_local_apply_request.v1",
                 "confirmation": "APPLY", "transaction_id": "original"}
        envelope = {"schema": "usk.publisher.lab_reviewed_plan_envelope.v2",
                    "activation": "operator_acceptance_candidate",
                    "apply_request": apply}
        digest = write_json(envelope_file, envelope)
        changed = dict(apply, transaction_id="substituted")
        write_json(apply_file, changed)
        args = [str(executable), "--apply-registered", service,
                str(executable), volume, str(envelope_file), digest,
                caller, "0" * 64, str(apply_file)]
        before = subprocess.run(["sc.exe", "query", service],
                                capture_output=True, timeout=10, check=False)
        if before.returncode != 1060:
            raise AssertionError("generated test service absence was not established")
        # Exercise the real controller parser and request checks in every mode,
        # including the admitted route. The distinct diagnostic proves these
        # refusals reached the request check rather than an unsupported option.
        for mode in ([], ["--admit-client-observer"], ["--grant-client-read"],
                     ["--service-admitted-client"]):
            result = subprocess.run(
                args + mode, capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 3 or "apply request differs" not in result.stderr:
                raise AssertionError(f"reviewed apply substitution was admitted in {mode}: {result}")
            for operation, expected_schema in (
                ("--recover-registered", "usk.publisher_recovery_request.v1"),
                ("--verify-registered", "usk.publisher_installed_verify_request.v1"),
            ):
                wrong_request = root / (operation[2:] + ".json")
                write_json(wrong_request, {"schema": "usk.install_local_apply_request.v1"})
                result = subprocess.run(
                    [str(executable), operation, service, str(executable), volume,
                     caller, "0" * 64, str(wrong_request)] + mode,
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if result.returncode != 3 or "request mode differs" not in result.stderr:
                    raise AssertionError(
                        f"{operation} accepted a request other than {expected_schema} in {mode}: {result}"
                    )
        # Admitted requests must bind the current caller before reading input.
        # A different canonical account SID is insufficient, even with this mode.
        wrong_caller_args = list(args)
        wrong_caller_args[7] = "S-1-5-18" if caller != "S-1-5-18" else "S-1-5-19"
        result = subprocess.run(
            wrong_caller_args + ["--service-admitted-client"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 3 or "caller differs from this process identity" not in result.stderr:
            raise AssertionError(f"admitted controller did not reject the actual caller mismatch: {result}")
        # The mode is deliberately unavailable on legacy configure/start verbs.
        # Opting in must never turn these into SCM mutations for an admitted target.
        for operation in ("--recover", "--verify", "--start"):
            result = subprocess.run(
                [str(executable), operation, service, str(executable), volume,
                 caller, "--service-admitted-client"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 3 or "caller access mode is invalid" not in result.stderr:
                raise AssertionError(f"admitted mode reached legacy {operation}: {result}")
        after = subprocess.run(["sc.exe", "query", service],
                               capture_output=True, timeout=10, check=False)
        if after.returncode != 1060:
            raise AssertionError("invalid apply left a service or unknown SCM state")
        # Run the real fixture entry points with rejected profile combinations.
        # Fake inputs must remain unopened and no output/VHD may be created.
        repository = Path(__file__).resolve().parents[2]
        verify_fixture_retention(repository, root)
        fixture_environment = dict(os.environ, GITHUB_ACTIONS="false", RUNNER_ENVIRONMENT="local")
        admitted = ["-AdmittedTarget", "-ControllerApply", "-RegisteredService",
                    "-ReviewedSource", "-ReuseRegistration"]
        output = root / "must-not-be-created.json"
        missing_vhd = root / "must-not-be-created.vhdx"
        for name in ("windows_publisher_lab_probe.ps1", "windows_publisher_metadata_hosted_probe.ps1"):
            fixture = repository / "tests" / name
            inputs = ["-OutputPath", str(output)]
            if "metadata" in name:
                inputs += ["-VhdPath", str(missing_vhd), "-VolumeRoot", volume,
                           "-ServiceBinary", str(executable), "-DeviceAclBinary", str(executable),
                           "-MachineBinary", str(executable), "-PublicApplyBinary", str(executable)]
            else:
                inputs += ["-ServiceControlBinary", str(executable)]
            combinations = [[flag for flag in admitted if flag != "-ControllerApply"]]
            combinations += [admitted + [flag] for flag in (
                "-ConsumerAccess", "-MachineRequestClient", "-InterruptAfterStage", "-NonAdminClient")]
            for flags in combinations:
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-File", str(fixture)] + inputs + flags,
                    capture_output=True, text=True, timeout=10, check=False, env=fixture_environment,
                )
                if result.returncode == 0 or "Admitted target currently requires" not in result.stderr:
                    raise AssertionError(f"unsafe admitted fixture profile reached setup: {name}: {result}")
                if output.exists() or missing_vhd.exists():
                    raise AssertionError("rejected fixture profile created output or storage")
        actor_probe = repository / "tests" / "windows_publisher_controller_actor_probe.ps1"
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(actor_probe), "-OutputPath", str(output)],
            capture_output=True, text=True, timeout=10, check=False, env=fixture_environment,
        )
        if result.returncode == 0 or "requires the hosted disposable VM" not in result.stderr or output.exists():
            raise AssertionError(f"controller actor probe bypassed hosted admission: {result}")
        if len(sys.argv) > 2:
            observer = Path(sys.argv[2]).resolve(strict=True)
            result = subprocess.run(
                [str(observer), "--observe-owned-hosted-vm-vhd-volume", volume, service,
                 "4294967295", str(missing_vhd), "00000000-0000-0000-0000-000000000000"],
                capture_output=True, text=True, timeout=10, check=False, env=fixture_environment,
            )
            if result.returncode != 2 or "requires a hosted disposable runner" not in result.stderr:
                raise AssertionError(f"read-only device observer bypassed native hosted admission: {result}")
            if missing_vhd.exists():
                raise AssertionError("non-hosted device observer created storage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
