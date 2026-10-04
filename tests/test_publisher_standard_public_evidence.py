# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic policy contradictions; these records are never OS qualification."""
import copy
import unittest
from publisher_standard_public_evidence import StandardEvidenceError, client_token, service_policy, deny_mutation, native_boundary, MUTATION_RIGHTS

CLIENT = "S-1-5-21-1-2-3-1001"
UNRELATED = "S-1-5-21-1-2-3-1002"


def token():
    return {"user_sid": CLIENT, "groups": [{"sid": "S-1-5-32-545", "attributes": 7}],
        "privileges": [{"name": "SeChangeNotifyPrivilege", "attributes": 3},
            {"name": "SeTimeZonePrivilege", "attributes": 0}], "token_id": "0000000000001234",
        "authentication_id": "0000000000001235", "token_type": 1, "impersonation_level": None}


def policy():
    return {"owner": "S-1-5-18", "raw_security_diagnostic": "O:SYD:(A;;CCLCRPRC;;;" + CLIENT + ")",
        "aces": [{"sid": "S-1-5-32-544", "mask": 0xf01ff, "flags": 0, "type": "AccessAllowed"},
            {"sid": CLIENT, "mask": 0x20015, "flags": 0, "type": "AccessAllowed"},
            {"sid": UNRELATED, "mask": 0x2018d, "flags": 0, "type": "AccessAllowed"}]}


class StandardPublicPolicyTests(unittest.TestCase):
    def test_native_denial_controls(self):
        checks = {name: {"requested": mask, "allowed": False, "granted": 0} for name, mask in MUTATION_RIGHTS.items()}
        checks["maximum_allowed"] = {"requested": 0x2000000, "allowed": True, "granted": 1179817}
        deny_mutation(checks)
        boundary = {"root": {"effective_rights": {actor: copy.deepcopy(checks) for actor in ("initiating", "filtered")}},
            "device": {"checks": {actor: copy.deepcopy(checks) for actor in ("initiating", "filtered")}}}
        native_boundary(boundary)
        for value in ({}, {"root": boundary["root"]}, {"device": boundary["device"]}):
            with self.subTest(boundary=value), self.assertRaises(StandardEvidenceError):
                native_boundary(value)
        for key, value in (("allowed", 0), ("granted", False), ("requested", True)):
            item = copy.deepcopy(checks); item["delete"][key] = value
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                deny_mutation(item)
        for name, mask in MUTATION_RIGHTS.items():
            item = copy.deepcopy(checks); item[name].update(allowed=True, granted=mask)
            with self.subTest(name=name), self.assertRaises(StandardEvidenceError):
                deny_mutation(item)
            item = copy.deepcopy(checks); item["maximum_allowed"]["granted"] |= mask
            with self.subTest(maximum=name), self.assertRaises(StandardEvidenceError):
                deny_mutation(item)
    def test_standard_primary_positive(self):
        client_token(token(), CLIENT)
        service_policy(policy(), CLIENT)

    def test_primary_contradictions(self):
        variants = []
        for key, value in (("user_sid", UNRELATED), ("token_type", 2), ("token_type", True),
                           ("impersonation_level", 2), ("token_id", "0000000000000000"), ("claimed_standard", True)):
            item = token(); item[key] = value; variants.append(item)
        for principal in ("S-1-5-18", "S-1-5-32-544", "S-1-5-80-1-2-3-4-5", "S-1-5-32-0544"):
            item = token(); item["groups"].append({"sid": principal, "attributes": 16}); variants.append(item)
        item = token(); item["privileges"][1]["attributes"] = 2; variants.append(item)
        item = token(); item["privileges"][1]["name"] = "SeBackupPrivilege"; variants.append(item)
        for item in variants:
            with self.subTest(item=item), self.assertRaises(StandardEvidenceError):
                client_token(item, CLIENT)

    def test_every_outside_nonquery_service_right(self):
        for target in (1, 2):
            allowed = 0x2018d | (0x10 if target == 1 else 0)
            for bit in range(32):
                if allowed & (1 << bit):
                    continue
                item = policy(); item["aces"][target]["mask"] |= 1 << bit
                with self.subTest(target=target, bit=bit), self.assertRaises(StandardEvidenceError):
                    service_policy(item, CLIENT)

    def test_service_owner_closed_ace_and_binding(self):
        variants = []
        item = policy(); item["owner"] = CLIENT; variants.append(item)
        item = policy(); item["aces"][1]["sid"] = UNRELATED; variants.append(item)
        for key, value in (("flags", 16), ("type", "ObjectAllowed"), ("mask", True), ("sid", "S-1-5-21-01-2-3-1002")):
            item = policy(); item["aces"][2][key] = value; variants.append(item)
        item = policy(); item["uninterrupted"] = True; variants.append(item)
        for item in variants:
            with self.subTest(item=item), self.assertRaises(StandardEvidenceError):
                service_policy(item, CLIENT)
        item = copy.deepcopy(policy()); item["aces"][2]["type"] = "AccessDenied"; item["aces"][2]["mask"] = 0xffffffff
        service_policy(item, CLIENT)
