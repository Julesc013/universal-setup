# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Exercise the real image policy validator and held-file observations."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which('pwsh')
SCRIPT = r'''
param([string]$Root)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'tests/windows_publisher_lab_probe.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Lab fixture parse failed'}
foreach($name in @('Initialize-OwnedVhdImageSecurity','Assert-OwnedVhdImageSecurity','Protect-NewOwnedVhdImage')) {
    $functions=@($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    },$true))
    if($functions.Count -ne 1){throw 'Owned image function is ambiguous'}
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
Initialize-OwnedVhdImageSecurity
Initialize-OwnedVhdImageSecurity
$valid='O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)'
$cases=[ordered]@{
    valid=$valid
    wrong_owner=$valid.Replace('O:BA','O:BU')
    missing_owner=$valid.Substring(4)
    null_dacl='O:BAD:NO_ACCESS_CONTROL'
    unprotected=$valid.Replace('D:P','D:')
    missing_ace=$valid.Replace('(A;;FA;;;SY)','')
    extra_ace=$valid+'(A;;0x1200a9;;;AU)'
    duplicate_ace=$valid+'(A;;0x1200a9;;;BA)'
    wrong_order='O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'
    denied=$valid.Replace('(A;;FA;;;BA)','(D;;FA;;;BA)')
    inherited=$valid.Replace('(A;;FA;;;BA)','(A;ID;FA;;;BA)')
    inheritable=$valid.Replace('(A;;FA;;;BA)','(A;OI;FA;;;BA)')
    user_modify=$valid.Replace('0x1200a9','0x1301bf')
    wrong_principal=$valid.Replace(';;;BU)',';;;AU)')
    admin_read=$valid.Replace('(A;;FA;;;BA)','(A;;0x1200a9;;;BA)')
    callback=$valid
}
$rows=@()
foreach($case in $cases.Keys) {
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($cases[$case])
    if($case -ceq 'callback') {
        $raw.DiscretionaryAcl[0]=[Security.AccessControl.CommonAce]::new(
            [Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,
            0x1f01ff,[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),$true,[byte[]]@())
    }
    $bytes=[byte[]]::new($raw.BinaryLength);$raw.GetBinaryForm($bytes,0)
    $accepted=$false;$message=$null
    try {$actual=Assert-OwnedVhdImageSecurity $bytes;$accepted=$true} catch {$message=$_.Exception.Message}
    $rows+=@{case=$case;accepted=$accepted;failure=$message}
}
# Only this test's new ordinary file is opened. Its caller-owned policy tests
# the raw native setter/readback; no BA-owner profile setter, VHD, disk, service,
# client or publisher constructor runs on the local workstation.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('usk-image-control-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp)|Out-Null
$path=Join-Path $temp 'publisher.vhdx';$stream=$null;$owner=$null;$sha=$null
try {
    # The resource guard's temporary parent may omit WRITE_OWNER for the
    # interactive token. Give only this new test file its caller's full rights
    # at CREATE_NEW; do not weaken the production opener or change parent ACLs.
    $caller=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $createdSecurity=[Security.AccessControl.FileSecurity]::new()
    $createdSecurity.SetSecurityDescriptorSddlForm('O:'+$caller+'D:P(A;;FA;;;'+$caller+')')
    $created=[IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($path),[IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$createdSecurity)
    try {$created.Write([byte[]](0..255),0,256)} finally {$created.Dispose()}
    $owner=[UskOwnedVhdImage]::Open($path);$stream=$owner.Stream;$held=$stream.SafeFileHandle
    $before=[UskOwnedVhdImage]::Observe($stream,$path)
    $sha=[Security.Cryptography.SHA256]::Create()
    $first=[Convert]::ToHexString($sha.ComputeHash($stream))
    $security=[Security.AccessControl.RawSecurityDescriptor]::new([UskOwnedVhdImage]::ReadOwnerDacl($stream),0)
    if($security.Owner.Value -cne $caller){throw 'Actual held caller-owner differs'}
    $sharingRefused=$false;$other=$null
    try {$other=[IO.File]::OpenRead($path)} catch {$sharingRefused=$true} finally {if($null -ne $other){$other.Dispose()}}
    $wrongPathRefused=$false
    try {[UskOwnedVhdImage]::Observe($stream,(Join-Path $temp 'replacement.vhdx'))|Out-Null} catch {$wrongPathRefused=$true}
    # Native SetSecurityInfo preserves the explicit BA/SY/BU order. Keep the
    # caller as owner and grant it full rights only on this new controlled file.
    $controlPolicy=[Security.AccessControl.RawSecurityDescriptor]::new(
        'O:'+$caller+'D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;FA;;;'+$caller+')')
    $planned=[byte[]]::new($controlPolicy.BinaryLength);$controlPolicy.GetBinaryForm($planned,0)
    [UskOwnedVhdImage]::SetOwnerDacl($stream,$planned)
    $rawReadback=[UskOwnedVhdImage]::ReadOwnerDacl($stream)
    $stored=[Security.AccessControl.RawSecurityDescriptor]::new($rawReadback,0)
    $expectedAcl=[byte[]]::new($controlPolicy.DiscretionaryAcl.BinaryLength)
    $controlPolicy.DiscretionaryAcl.GetBinaryForm($expectedAcl,0)
    $actualAcl=[byte[]]::new($stored.DiscretionaryAcl.BinaryLength)
    $stored.DiscretionaryAcl.GetBinaryForm($actualAcl,0)
    # FileSecurity canonicalizes the same input, demonstrating why an actual
    # stored descriptor must not pass through its managed ACL projection.
    $projection=[Security.AccessControl.FileSecurity]::new()
    $projection.SetSecurityDescriptorBinaryForm($rawReadback)
    $projected=[Security.AccessControl.RawSecurityDescriptor]::new($projection.GetSecurityDescriptorBinaryForm(),0)
    $projectedAcl=[byte[]]::new($projected.DiscretionaryAcl.BinaryLength)
    $projected.DiscretionaryAcl.GetBinaryForm($projectedAcl,0)
    $nativePolicy=@{owner=$stored.Owner.Value;caller=$caller;acl_bytes_exact=
        [Convert]::ToHexString($expectedAcl) -ceq [Convert]::ToHexString($actualAcl);
        protected=[bool]($stored.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected);
        first_sid=$stored.DiscretionaryAcl[0].SecurityIdentifier.Value;second_sid=$stored.DiscretionaryAcl[1].SecurityIdentifier.Value;
        managed_projection_differs=[Convert]::ToHexString($projectedAcl) -cne [Convert]::ToHexString($actualAcl)}
    # The original strict BA-owner contract still refuses this caller-owned
    # control. The real profile's setter remains a hosted-only future operation.
    $wrongOwnerRefused=$false
    try {Assert-OwnedVhdImageSecurity $rawReadback|Out-Null} catch {$wrongOwnerRefused=$true}
    $nativePolicy.profile_refused_wrong_owner=$wrongOwnerRefused
    $stream.Position=0;$second=[Convert]::ToHexString($sha.ComputeHash($stream))
    $after=[UskOwnedVhdImage]::Observe($stream,$path)
    if(-not $owner.Close()){throw 'Native ordinary control close unconfirmed'};$stream=$null
    $reopened=[IO.File]::ReadAllBytes($path)
    $ordinary=@{identity_unchanged=$before[0] -ceq $after[0];size_bytes=$after[1];
        hash_unchanged=$first -ceq $second;sharing_refused=$sharingRefused;wrong_path_refused=$wrongPathRefused;
        original_handle_closed=$held.IsClosed;native_close_confirmed=$owner.NativeCloseConfirmed;
        native_close_attempted=$owner.CloseAttempted;native_close_error=$owner.NativeCloseError;reopened_size=$reopened.Length}
    $empty=Join-Path $temp 'empty.vhdx'
    $created=[IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($empty),[IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$createdSecurity)
    $created.Dispose()
    $owner=[UskOwnedVhdImage]::Open($empty);$stream=$owner.Stream;$emptyRefused=$false
    try {[UskOwnedVhdImage]::Observe($stream,$empty)|Out-Null} catch {$emptyRefused=$true}
    if(-not $owner.Close()){throw 'Native empty control close unconfirmed'};$stream=$null
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class UskImageHardlinkControl {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CreateHardLinkW(string path,string existing,IntPtr security);
}
'@
    $link=Join-Path $temp 'alias.vhdx'
    if(-not [UskImageHardlinkControl]::CreateHardLinkW($link,$path,[IntPtr]::Zero)){throw 'Owned hardlink control could not be created'}
    $owner=[UskOwnedVhdImage]::Open($path);$stream=$owner.Stream;$hardlinkRefused=$false
    try {[UskOwnedVhdImage]::Observe($stream,$path)|Out-Null} catch {$hardlinkRefused=$true}
    if(-not $owner.Close()){throw 'Native hardlink control close unconfirmed'};$stream=$null
    $ordinary.empty_refused=$emptyRefused;$ordinary.hardlink_refused=$hardlinkRefused
} finally {
    if($null -ne $sha){$sha.Dispose()}
    if($null -ne $owner -and -not $owner.Close()) {throw 'Native control custody unknown; retain its new temporary directory'}
    $resolved=(Resolve-Path -LiteralPath $temp -ErrorAction Stop).ProviderPath
    if($resolved -cne [IO.Path]::GetFullPath($temp) -or
        [IO.Path]::GetFileName($resolved) -cnotmatch '^usk-image-control-[0-9a-f]{32}$' -or
        [IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -cne [IO.Path]::GetTempPath().TrimEnd('\')) {
        throw 'Owned image control cleanup target differs'
    }
    [IO.Directory]::Delete($temp,$true)
}
$try=@($ast.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally
})
if($try.Count -ne 1){throw 'Original lab creation control flow is ambiguous'}
$flow=$try[0].Body.Extent.Text
$created=$flow.IndexOf("throw 'file-backed VHD was not created'")
$protected=$flow.IndexOf("if(`$PublicInstallation){`$receipt['backing_image_provisioning']=Protect-NewOwnedVhdImage `$vhd `$receipt}")
$attached=$flow.IndexOf('Mount-DiskImage -ImagePath $vhd -NoDriveLetter')
if($created -lt 0 -or $protected -le $created -or $attached -le $protected){throw 'New image policy does not precede first attachment'}
# Exercise the ACTUAL one-attempt C# method with inert private-constructor
# closers. These synthetic values are never passed to an OS close/open call.
$constructors=@([UskOwnedVhdImage].GetConstructors([Reflection.BindingFlags]'Instance,NonPublic'))
if($constructors.Count -ne 1){throw 'Original image owner constructor is ambiguous'}
$closeRows=@()
foreach($mode in @('success','failure','throw')) {
    $script:closeCalls=0
    $closer=[Func[IntPtr,Tuple[bool,int]]]{param($original)
        if($original -ne [IntPtr]12345){throw 'Synthetic original changed'}
        $script:closeCalls++
        if($mode -ceq 'throw'){throw 'Synthetic close failure'}
        [Tuple]::Create([bool]($mode -ceq 'success'),[int]$(if($mode -ceq 'success'){0}else{5}))
    }
    $owned=$constructors[0].Invoke([object[]]@([IntPtr]12345,$closer))
    $threw=$false
    try {[void]$owned.Close()} catch {$threw=$true}
    $again=$owned.Close()
    $closeRows+=@{mode=$mode;calls=$script:closeCalls;attempted=$owned.CloseAttempted;
        confirmed=$owned.NativeCloseConfirmed;error=$owned.NativeCloseError;threw=$threw;second_result=$again}
}
# Replace only the effectful try body. Actual initialization/catch/finally,
# original-failure preservation, close facts and admission refusal remain.
$protect=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Protect-NewOwnedVhdImage'
},$true))[0]
$mainTry=@($protect.Body.EndBlock.Statements|Where-Object {
    $_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally
})
if($mainTry.Count -ne 1){throw 'Original image provision try is ambiguous'}
$text=$protect.Body.Extent.Text
$offset=$mainTry[0].Body.Extent.StartOffset-$protect.Body.Extent.StartOffset
$text=$text.Remove($offset,$mainTry[0].Body.Extent.Text.Length).Insert($offset,
    '{ $owner=$syntheticOwner; if($primaryFails){throw "Synthetic original provisioning failure"} }')
$provisionFlow=[scriptblock]::Create($text.Substring(1,$text.Length-2))
$flowRows=@()
foreach($primaryFails in @($false,$true)) {
  foreach($nativeConfirmed in @($false,$true)) {
    foreach($closeThrows in @($false,$true)) {
      $Receipt=[ordered]@{};$ImagePath='synthetic';$syntheticOwner=[pscustomobject]@{
        CloseAttempted=$false;NativeCloseConfirmed=$false;NativeCloseError=0;Calls=0}
      $syntheticOwner|Add-Member -MemberType ScriptMethod -Name Close -Value {
        $this.Calls++;$this.CloseAttempted=$true;$this.NativeCloseConfirmed=$nativeConfirmed
        $this.NativeCloseError=if($nativeConfirmed){0}else{5}
        if($closeThrows){throw 'Synthetic cleanup exception'}
        return $nativeConfirmed
      }
      $failure=$null
      try {& $provisionFlow|Out-Null} catch {$failure=$_.Exception.Message}
      $flowRows+=@{primary=$primaryFails;confirmed=$nativeConfirmed;close_throws=$closeThrows;
        error=$failure;calls=$syntheticOwner.Calls;observation=$Receipt.backing_image_provisioning}
    }
  }
}
$retention=@($try[0].Finally.Statements[0].Body.FindAll({param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Extent.Text.Contains("throw 'Owned VHD image closure unconfirmed; retain backing file until runner VM disposal'")
},$true))
if($retention.Count -ne 1){throw 'Unknown image custody retention is ambiguous'}
$retentionFlow=[scriptblock]::Create($retention[0].Extent.Text)
$retentionRows=@()
foreach($custody in @('unknown','released','not_acquired')) {
    $receipt=@{backing_image_provisioning=@{custody=$custody}};$refused=$false
    try {& $retentionFlow} catch {$refused=$true}
    $retentionRows+=@{custody=$custody;refused=$refused}
}
@{policy_cases=$rows;ordinary=$ordinary;native_policy=$nativePolicy;close_controls=$closeRows;flow_controls=$flowRows;
    retention_controls=$retentionRows;before_attachment=$true;profile_ba_setter_executed=$false}|ConvertTo-Json -Depth 8 -Compress
'''


@unittest.skipUnless(os.name == 'nt' and POWERSHELL, 'Windows PowerShell Core is required')
class PublisherVhdImageSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'image-controls.ps1'
            script.write_text(SCRIPT, encoding='utf-8')
            result = subprocess.run(
                [POWERSHELL, '-NoProfile', '-File', str(script), '-Root', str(ROOT)],
                capture_output=True, text=True, timeout=45, check=False,
            )
        if result.returncode:
            raise AssertionError(result.stderr[-4096:] + result.stdout[-4096:])
        cls.observation = json.loads(result.stdout)

    def test_exact_policy_and_mutation_refusals(self):
        rows = self.observation['policy_cases']
        self.assertEqual(len(rows), 16)
        for row in rows:
            self.assertEqual(row['accepted'], row['case'] == 'valid', row)
            if row['case'] != 'valid':
                self.assertIn('Owned VHD image', row['failure'])

    def test_original_held_file_and_attachment_order(self):
        row = self.observation['ordinary']
        for key in ('identity_unchanged', 'hash_unchanged', 'sharing_refused', 'wrong_path_refused',
                    'original_handle_closed', 'native_close_attempted', 'native_close_confirmed',
                    'empty_refused', 'hardlink_refused'):
            self.assertTrue(row[key], key)
        self.assertEqual(row['native_close_error'], 0)
        self.assertEqual(row['size_bytes'], 256)
        self.assertEqual(row['reopened_size'], 256)
        self.assertTrue(self.observation['before_attachment'])
        self.assertFalse(self.observation['profile_ba_setter_executed'])

    def test_raw_native_policy_preserves_actual_order(self):
        row = self.observation['native_policy']
        self.assertEqual(row['owner'], row['caller'])
        for key in ('acl_bytes_exact', 'protected', 'managed_projection_differs', 'profile_refused_wrong_owner'):
            self.assertTrue(row[key], key)
        self.assertEqual(row['first_sid'], 'S-1-5-32-544')
        self.assertEqual(row['second_sid'], 'S-1-5-18')

    def test_one_attempt_unknown_close_and_original_failure(self):
        rows = self.observation['close_controls']
        self.assertEqual(len(rows), 3)
        for row in rows:
            self.assertEqual(row['calls'], 1, row)
            self.assertTrue(row['attempted'])
            self.assertEqual(row['confirmed'], row['mode'] == 'success', row)
            self.assertEqual(row['second_result'], row['confirmed'], row)
            self.assertEqual(row['threw'], row['mode'] == 'throw', row)
            self.assertEqual(row['error'], 5 if row['mode'] == 'failure' else 0)
        rows = self.observation['flow_controls']
        self.assertEqual(len(rows), 8)
        for row in rows:
            self.assertEqual(row['calls'], 1, row)
            observation = row['observation']
            self.assertEqual(observation['custody'], 'released' if row['confirmed'] else 'unknown')
            self.assertEqual(observation['observations_closed'], row['confirmed'])
            self.assertFalse(observation['volume_admission_granted'])
            if row['primary']:
                self.assertEqual(row['error'], 'Synthetic original provisioning failure', row)
            elif row['close_throws']:
                self.assertIn('Synthetic cleanup exception', row['error'], row)
            elif not row['confirmed']:
                self.assertIn('native close unconfirmed', row['error'], row)
            else:
                self.assertIsNone(row['error'])
        for row in self.observation['retention_controls']:
            self.assertEqual(row['refused'], row['custody'] == 'unknown', row)
