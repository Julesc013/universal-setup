# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Data-only observer controls; no native interruption or restoration authority."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-10-17T05:38:02Z"
TX = "maintenance.repair." + "1" * 32


def journal(timestamp=STAMP):
    phases = ("created", "validated", "planned", "staging")
    transitions = [
        {"sequence": i, "from": phases[i - 1] if i else None, "to": phase,
         "transition_id": TX + "." + str(i), "recorded_at": timestamp,
         "durable_before_external_visibility": True}
        for i, phase in enumerate(phases)
    ]
    # The published journal protocol uses decoded timestamp text, with NUL
    # separators and LF terminators; it does not hash localized DateTime text.
    chain = b"".join(
        (str(i) + "\0" + (row["from"] or "") + "\0" + row["to"] + "\0" +
         timestamp + "\n").encode("utf-8") for i, row in enumerate(transitions)
    )
    return {"schema": "usk.transaction_journal.v1", "transaction_id": TX,
            "current_state": "staging", "transitions": transitions,
            "updated_at": timestamp, "journal_digest": hashlib.sha256(chain).hexdigest()}


SCRIPT = r"""
$ErrorActionPreference='Stop'
. $env:USK_INITIAL_BOUNDARY_HELPER
$vectors=ConvertFrom-PublisherInitialMaintenanceJson ([IO.File]::ReadAllText($env:USK_INITIAL_JSON_VECTORS))
$results=@()
foreach($culture in @('en-US','fr-FR')) {
    [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo($culture)
    foreach($vector in $vectors) {
        $document=ConvertFrom-PublisherInitialMaintenanceJson ([string]$vector.text)
        $refused=$false
        try { Assert-PublisherInitialMaintenanceJournalChain $document $env:USK_INITIAL_TRANSACTION }
        catch { $refused=$true }
        if($refused -ne [bool]$vector.refuse) {throw ('Journal vector disposition differs: '+$vector.name)}
        if(-not $vector.refuse) {
            if($document.updated_at -isnot [string] -or $document.updated_at -cne '2026-10-17T05:38:02Z' -or
                @($document.transitions|Where-Object {$_.recorded_at -isnot [string] -or
                    $_.recorded_at -cne '2026-10-17T05:38:02Z'}).Count -ne 0) {
                throw 'The real observer parser changed digest-bearing timestamp text'
            }
        }
        $results+=@{culture=$culture;name=$vector.name;refused=$refused}
    }
    $coerced=ConvertFrom-PublisherInitialMaintenanceJson ([string]$vectors[0].text)
    $coerced.transitions[0].recorded_at=[DateTime]::Parse('2026-10-17T05:38:02Z')
    $refused=$false
    try { Assert-PublisherInitialMaintenanceJournalChain $coerced $env:USK_INITIAL_TRANSACTION }
    catch { $refused=$true }
    if(-not $refused){throw 'A coerced DateTime was accepted as original timestamp text'}
    $results+=@{culture=$culture;name='coerced_datetime';refused=$refused}
}
@{version=$PSVersionTable.PSVersion.ToString();results=$results;native_effects=$false}|ConvertTo-Json -Depth 8 -Compress
"""


@unittest.skipUnless(os.name == "nt", "Windows observer host controls")
class InitialTimestampTextTests(unittest.TestCase):
    def test_actual_observer_parser_and_chain_in_available_windows_hosts(self):
        hosts = [path for name in ("pwsh", "powershell.exe") if (path := shutil.which(name))]
        self.assertTrue(hosts, "no Windows observer host is available")
        vectors = [{"name": "original", "document": journal(), "refuse": False}]
        mutations = {
            "digest": lambda value: value.update(journal_digest="0" * 64),
            "final_time": lambda value: value.update(updated_at="2026-10-17T05:38:03Z"),
            "timestamp": lambda value: value["transitions"][1].update(recorded_at="2026-10-17T05:38:03Z"),
            "offset_spelling": lambda value: value["transitions"][1].update(recorded_at="2026-10-17T05:38:02+00:00"),
            "phase": lambda value: value["transitions"][1].update(to="planned"),
            "origin": lambda value: value["transitions"][0].update({"from": "created"}),
            "sequence": lambda value: value["transitions"][1].update(sequence=2),
            "durability": lambda value: value["transitions"][1].update(durable_before_external_visibility=False),
            "count": lambda value: value["transitions"].pop(),
        }
        for name, mutate in mutations.items():
            value = copy.deepcopy(vectors[0]["document"])
            mutate(value)
            vectors.append({"name": name, "document": value, "refuse": True})
        # These have internally matching digests and times. The observer still
        # requires the journal protocol's exact timestamp grammar.
        vectors.extend([
            {"name": "newline_with_matching_digest", "document": journal(STAMP + "\n"), "refuse": True},
            {"name": "offset_with_matching_digest", "document": journal("2026-10-17T05:38:02+00:00"), "refuse": True},
        ])
        encoded = [{"name": value["name"], "refuse": value["refuse"],
                    "text": json.dumps(value["document"], separators=(",", ":"))} for value in vectors]
        with tempfile.TemporaryDirectory(prefix="usk-initial-json-") as directory:
            path = Path(directory) / "vectors.json"
            path.write_text(json.dumps(encoded), encoding="utf-8")
            environment = dict(os.environ, USK_INITIAL_JSON_VECTORS=str(path),
                               USK_INITIAL_BOUNDARY_HELPER=str(ROOT / "tests/windows_publisher_initial_maintenance_boundary.ps1"),
                               USK_INITIAL_TRANSACTION=TX)
            command = base64.b64encode(SCRIPT.encode("utf-16-le")).decode("ascii")
            for host in hosts:
                with self.subTest(host=host):
                    result = subprocess.run([host, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                             "-EncodedCommand", command],
                                            env=environment, capture_output=True, text=True,
                                            encoding="utf-8", errors="replace", timeout=45, check=False)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = json.loads(result.stdout.lstrip("\ufeff"))
                    self.assertFalse(report["native_effects"])
                    self.assertEqual(len(report["results"]), 2 * (len(vectors) + 1))
                    self.assertEqual(sum(not row["refused"] for row in report["results"]), 2)


if __name__ == "__main__":
    unittest.main()
