# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Synthetic policy contradictions; these records are never OS qualification."""
import copy
import hashlib
import unittest
from publisher_standard_public_evidence import StandardEvidenceError, client_token, service_policy, deny_mutation, native_boundary, MUTATION_RIGHTS, registered_admission, canonical, require_native_capture_set

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
    def test_current_capture_set_requires_every_bound_public_request(self):
        commands = ['publisher.inspect', 'install_local.apply', 'install_local.recover', 'install_local.apply', 'installed.verify']
        captures = [{'request_id': str(index)} for index in range(5)]
        native = [{'command': command, 'request_id': str(index)} for index, command in enumerate(commands[1:], 1)]
        require_native_capture_set(native, captures, commands)
        for changed in (None, [], native[:-1], list(reversed(native)), native + native[:1]):
            with self.subTest(captures=changed), self.assertRaises(StandardEvidenceError):
                require_native_capture_set(changed, captures, commands)
        changed = copy.deepcopy(native)
        changed[-1]['request_id'] = 'other'
        with self.assertRaises(StandardEvidenceError):
            require_native_capture_set(changed, captures, commands)

    def test_registered_admission_binds_image_process_and_native_boundary(self):
        boundary = '0000000000001234:' + '0' * 31 + '1'
        service = 'USK_PUB_' + 'a' * 32
        service_sid = 'S-1-5-80-1-2-3-4-5'
        target = {'registration_sha256': 'b' * 64, 'metadata': [], 'disk_identity': {},
            'volume_identity': {'volume_root': 'E:/', 'root_file_id': boundary, 'volume_serial': str(0x1234)}}
        admitted = {'schema': 'usk.publisher_target_admitted.v1', 'identity': target}
        value = {'schema': 'usk.publisher_registered_admission_observation.v1',
            'scope': 'held_registered_service_image_and_controller_target_admission',
            'service_name': service, 'service_sid': service_sid, 'process_id': 123,
            'configured_caller_sid': CLIENT, 'registration_sha256': 'b' * 64,
            'target_identity': target, 'target_admitted_sha256': hashlib.sha256(canonical(admitted).encode()).hexdigest(),
            'publisher_image': {'path': 'fixture.exe', 'volume_id': 'fixture-volume', 'file_id': 'fixture-file',
                'size_bytes': 1234, 'sha256': 'a' * 64}}
        native = {'process_id': 123, 'registered_admission': value}
        def check(record):
            return registered_admission(record, service, service_sid, CLIENT, 'a' * 64, 'E:/', boundary)
        self.assertEqual(check(native), value)
        for key, other in [('process_id', True), ('configured_caller_sid', UNRELATED),
                           ('service_sid', 'S-1-5-18'), ('registration_sha256', 'c' * 64),
                           ('target_admitted_sha256', 'c' * 64)]:
            changed = copy.deepcopy(native)
            changed['registered_admission'][key] = other
            with self.subTest(key=key), self.assertRaises(StandardEvidenceError):
                check(changed)
        changed = copy.deepcopy(native)
        changed['registered_admission']['publisher_image']['sha256'] = 'c' * 64
        with self.assertRaises(StandardEvidenceError):
            check(changed)
        changed = copy.deepcopy(native)
        changed['registered_admission']['target_identity']['volume_identity']['root_file_id'] = 'wrong'
        with self.assertRaises(StandardEvidenceError):
            check(changed)

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
