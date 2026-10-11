# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
from copy import deepcopy
import unittest

from publisher_process_boundary import ProcessBoundaryError, QUERY_RIGHTS, validate_process_boundary


class ProcessBoundaryTests(unittest.TestCase):
    service_sid = "S-1-5-80-1-2-3-4-5"
    consumer_sid = "S-1-5-21-1-2-3-1000"
    logon_sid = "S-1-5-5-0-900"
    groups = [{"sid": service_sid, "attributes": 4}, {"sid": logon_sid, "attributes": 0xC0000005}]

    def boundary(self):
        return {"schema": "usk.publisher_process_boundary.v1", "scope": "stored_current_process_owner_dacl",
                "process_id": 500, "owner_sid": "S-1-5-18", "dacl_present": True, "dacl_protected": False,
                "dacl_aces": [{"type": 0, "flags": 0, "access_mask": 0x1FFFFF, "sid": "S-1-5-18"},
                              {"type": 0, "flags": 0, "access_mask": 0x1FFFFF, "sid": self.service_sid},
                              {"type": 0, "flags": 0, "access_mask": QUERY_RIGHTS, "sid": self.consumer_sid}]}

    def validate(self, value, groups=None):
        return validate_process_boundary(value, 500, self.service_sid, self.groups if groups is None else groups)

    def test_service_logon_and_consumer_query_boundaries(self):
        for owner in ("S-1-5-18", "S-1-5-32-544", self.service_sid, self.logon_sid):
            value = self.boundary()
            value["owner_sid"] = owner
            self.assertEqual(self.validate(value), value)
        value = self.boundary()
        value["dacl_aces"].append({"type": 1, "flags": 0, "access_mask": 0xFFFFFFFF, "sid": self.consumer_sid})
        self.assertEqual(self.validate(value), value)

    def test_each_non_query_process_or_security_right_is_refused(self):
        # These are record-only policy controls, not access attempts against a process.
        for bit in range(32):
            if QUERY_RIGHTS & (1 << bit):
                continue
            value = self.boundary()
            value["dacl_aces"][-1]["access_mask"] |= 1 << bit
            with self.subTest(bit=bit), self.assertRaises(ProcessBoundaryError):
                self.validate(value)

    def test_contradictory_owner_process_ace_and_logon_context_are_refused(self):
        for field, replacement in (("process_id", True), ("process_id", 501), ("owner_sid", self.consumer_sid),
                                   ("dacl_present", False), ("dacl_protected", 1), ("dacl_aces", None),
                                   ("scope", "all_external_handles_excluded")):
            value = self.boundary()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ProcessBoundaryError):
                self.validate(value)
        for field, replacement in (("type", True), ("type", 2), ("flags", 16),
                                   ("access_mask", True), ("access_mask", 1 << 32), ("sid", "S-1-5-021-1"),
                                   ("sid", "S-1-0")):
            value = self.boundary()
            value["dacl_aces"][-1][field] = replacement
            with self.subTest(ace_field=field), self.assertRaises(ProcessBoundaryError):
                self.validate(value)
        for groups in ([self.groups[-1], self.groups[-1]],
                       [{"sid": self.logon_sid, "attributes": 0xC0000015}],
                       [{"sid": "S-1-5-5-900", "attributes": 0xC0000005}],
                       [{"sid": "S-1-0", "attributes": 4}], self.groups * 2049):
            with self.subTest(groups=groups), self.assertRaises(ProcessBoundaryError):
                self.validate(self.boundary(), deepcopy(groups))


if __name__ == "__main__":
    unittest.main()
