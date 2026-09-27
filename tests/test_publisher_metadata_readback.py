# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

import json
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == "nt", "Windows PowerShell readback oracle")
class PublisherMetadataReadbackTests(unittest.TestCase):
    def test_owned_wrapper_and_child_termination_is_confirmed(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh")
        self.assertIsNotNone(shell, "PowerShell 7 is required for process-tree cancellation")
        encode = lambda value: base64.b64encode(value.encode("utf-16-le")).decode("ascii")
        child = encode("Start-Sleep -Seconds 30")
        wrapper = encode("$c=Start-Process (Get-Command pwsh).Source -ArgumentList "
                         "@('-NoProfile','-NonInteractive','-EncodedCommand','" + child + "') "
                         "-PassThru -WindowStyle Hidden; "
                         "[IO.File]::WriteAllText($env:USK_CHILD_ID,[string]$c.Id); $c.WaitForExit()")
        with tempfile.TemporaryDirectory() as temporary:
            environment = dict(os.environ, USK_CHILD_ID=str(Path(temporary) / "child-id"),
                               USK_WRAPPER=wrapper,
                               USK_PROCESS_HELPER=str(root / "tests/windows_publisher_owned_process.ps1"))
            code = """$ErrorActionPreference='Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_PROCESS_HELPER)))
$p=Start-Process (Get-Command pwsh).Source -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$env:USK_WRAPPER) -PassThru -WindowStyle Hidden
try {
 $until=[DateTime]::UtcNow.AddSeconds(10)
 while(-not (Test-Path -LiteralPath $env:USK_CHILD_ID)) {
  if([DateTime]::UtcNow -ge $until){throw 'Owned child did not start'}
  Start-Sleep -Milliseconds 50
 }
 $result=Stop-OwnedPublisherProcessTree $p
 if(-not $result.confirmed -or $result.terminated -lt 2){throw 'Owned descendant termination was not established'}
 $result|ConvertTo-Json -Compress
} finally {if(-not $p.HasExited){Stop-OwnedPublisherProcessTree $p|Out-Null}}
"""
            result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", code],
                                    env=environment, capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["confirmed"])

    def test_exited_wrapper_does_not_forget_a_live_recorded_child(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh")
        self.assertIsNotNone(shell)
        encode = lambda value: base64.b64encode(value.encode("utf-16-le")).decode("ascii")
        child = encode("Start-Sleep -Seconds 30")
        wrapper = encode("$c=Start-Process (Get-Command pwsh).Source -ArgumentList "
                         "@('-NoProfile','-NonInteractive','-EncodedCommand','" + child + "') "
                         "-PassThru -WindowStyle Hidden; "
                         "[IO.File]::WriteAllText($env:USK_CHILD_ID,[string]$c.Id)")
        with tempfile.TemporaryDirectory() as temporary:
            environment = dict(os.environ, USK_CHILD_ID=str(Path(temporary) / "child-id"),
                               USK_WRAPPER=wrapper,
                               USK_PROCESS_HELPER=str(root / "tests/windows_publisher_owned_process.ps1"))
            code = """$ErrorActionPreference='Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_PROCESS_HELPER)))
$p=Start-Process (Get-Command pwsh).Source -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$env:USK_WRAPPER) -PassThru -WindowStyle Hidden
$child=$null
try {
 if(-not $p.WaitForExit(10000)){throw 'Owned wrapper did not exit'}
 $child=Get-Process -Id ([int][IO.File]::ReadAllText($env:USK_CHILD_ID))
 $record=Get-CimInstance Win32_Process -Filter ('ProcessId='+$child.Id)
 $p|Add-Member -NotePropertyName UskOwnedTree -NotePropertyValue @($record)
 $refused=$false
 try {Stop-OwnedPublisherProcessTree $p|Out-Null} catch {
  if($_.Exception.Message -notmatch 'Owned process descendants remain'){throw}
  $refused=$true
 }
 if(-not $refused -or $child.HasExited){throw 'Exited wrapper erased a live owned child'}
 $child.Kill();$child.WaitForExit()
 $result=Stop-OwnedPublisherProcessTree $p
 if(-not $result.confirmed){throw 'Final child exit was not confirmed'}
 $result|ConvertTo-Json -Compress
} finally {
 if($child -and -not $child.HasExited){$child.Kill();$child.WaitForExit()}
 if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()}
}
"""
            result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", code],
                                    env=environment, capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["confirmed"])

    def test_record_substitution_and_failed_cleanup_are_refused(self):
        root = Path(__file__).resolve().parents[1]
        shell = shutil.which("pwsh") or shutil.which("powershell.exe")
        self.assertIsNotNone(shell, "Installed Windows PowerShell is required")
        environment = dict(os.environ, USK_METADATA_SOURCE=str(root),
                           USK_METADATA_TEST=str(root / "tests/windows_publisher_metadata_readback_smoke.ps1"))
        # Read this repository test as trusted command input. No execution
        # policy override or machine-wide configuration change is used.
        result = subprocess.run(
            [shell, "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference='Stop'; & ([scriptblock]::Create([IO.File]::ReadAllText($env:USK_METADATA_TEST))) -SourceRoot $env:USK_METADATA_SOURCE"],
            env=environment, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual((observed["positive"], observed["refused"]), (5, 23))
        self.assertIn("no VM/runtime qualification", observed["scope"])


if __name__ == "__main__":
    unittest.main()
