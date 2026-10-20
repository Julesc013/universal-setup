# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Hosted WPR's Profiles schema orders collectors, providers, then profiles."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent


class PublisherWprProfileCompatibilityTests(unittest.TestCase):
    def test_definition_groups_follow_hosted_wpr_schema_order(self):
        # Hosted WPR 2022 actually rejected a collector after SystemProvider
        # (0xc00ce014). Newer WPR -profiledetails did not detect that ordering.
        # Check the schema groups independently of any specific profile layout.
        groups = {
            "SystemCollector": 0, "EventCollector": 0,
            "SystemProvider": 1, "MicroArchitecturalConfig": 1,
            "HardwareCounter": 1, "EventProvider": 1, "HeapEventProvider": 1,
            "Profile": 2,
        }
        paths = list(ROOT.glob("windows_publisher_*trace.wprp"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(profile=path.name):
                definitions = ET.parse(path).getroot().find("Profiles")
                self.assertIsNotNone(definitions)
                order = [groups[node.tag] for node in definitions]
                self.assertEqual(order, sorted(order),
                                 "Collectors must precede providers and profile references")


    def test_recovery_cpu_route_has_bounded_identity_and_phase_capture(self):
        definitions = ET.parse(ROOT / "windows_publisher_maintenance_fresh_cpu_trace.wprp").getroot().find("Profiles")
        nodes = {node.attrib["Id"]: node for node in definitions}
        profiles = [node for node in definitions.findall("Profile")
                    if node.attrib["Name"] == "USKRecoveryCPU"]
        self.assertEqual({node.attrib["LoggingMode"] for node in profiles}, {"Memory", "File"})
        self.assertEqual(len(profiles), 2)
        for profile in profiles:
            collector_ref = profile.find("Collectors/SystemCollectorId")
            provider = nodes[collector_ref.find("SystemProviderId").attrib["Value"]]
            self.assertEqual({node.attrib["Value"] for node in provider.findall("Keywords/Keyword")},
                             {"ProcessThread", "Loader", "SampledProfile"})
            self.assertEqual({node.attrib["Value"] for node in provider.findall("Stacks/Stack")},
                             {"ThreadCreate", "SampledProfile"})
            collector = nodes[collector_ref.attrib["Value"]]
            self.assertEqual(int(collector.find("BufferSize").attrib["Value"]) *
                             int(collector.find("Buffers").attrib["Value"]), 512 * 128)
            event_ref = profile.find("Collectors/EventCollectorId")
            events = event_ref.findall("EventProviders/EventProviderId")
            self.assertEqual(len(events), 1)
            self.assertEqual(nodes[events[0].attrib["Value"]].attrib["Name"],
                             "7e4a4d0e-4d53-4c2d-93a3-6ba61cf46711")
            event_collector = nodes[event_ref.attrib["Value"]]
            self.assertEqual(int(event_collector.find("BufferSize").attrib["Value"]) *
                             int(event_collector.find("Buffers").attrib["Value"]), 64 * 128)
        # Existing fresh capture keeps scheduler observations for its distinct task.
        fresh = next(node for node in definitions.findall("Profile")
                     if node.attrib["Name"] == "USKFreshCPU" and node.attrib["LoggingMode"] == "Memory")
        provider_ref = fresh.find("Collectors/SystemCollectorId/SystemProviderId")
        self.assertEqual({node.attrib["Value"] for node in nodes[provider_ref.attrib["Value"]].findall("Keywords/Keyword")},
                         {"ProcessThread", "Loader", "SampledProfile", "CSwitch", "ReadyThread"})


if __name__ == "__main__":
    unittest.main()
