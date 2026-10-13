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


if __name__ == "__main__":
    unittest.main()
