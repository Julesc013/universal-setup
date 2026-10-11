# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_bundle_apply_binding import BindingError, compose_binding


class BundleApplyBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = {
            "schema": "usk.oneshot_request.v1", "command": "install_local.plan",
            "request_id": "plan.1", "dry_run": True,
            "payload": {
                "schema": "usk.install_local_plan_request.v1", "request_id": "plan.1",
                "required_commit_authority": "staged_child_bound_v1",
                "archive": {"path": "Q:/authored/payload.zip", "expected_sha256": "a" * 64},
                "target": {"root": "Q:/publication/destination/visible"},
                "recipe": {"components": ["core", "addon"],
                           "provider_revision": "b" * 64,
                           "recipe_digest": "c" * 64},
            },
        }
        self.response = {
            "schema": "usk.oneshot_response.v1", "status": "ok",
            "result": {"status": "ok", "payload": {
                "schema": "usk.install_plan.v1", "operation": "install_local",
                "plan_id": "plan.1", "plan_digest": "d" * 64,
                "required_commit_authority": "staged_child_bound_v1",
                "commit_authority_available": False,
                "target": {"root": "Q:/publication/destination/visible"},
                "source": {"path": "Q:/authored/payload.zip", "sha256": "a" * 64},
                "component_selection": ["core", "addon"],
                "input_identity": {"provider_revision": "b" * 64,
                                   "recipe_digest": "c" * 64},
            }},
        }

    def bind(self, request=None, response=None):
        return compose_binding(request or self.request, response or self.response,
                               acceptance_root="Q:\\", state_root="Q:/setup-state",
                               transaction_id="install.1",
                               applied_at="2026-09-28T00:00:00Z")

    def test_exact_native_plan_binds_apply_and_service_envelope(self) -> None:
        apply, envelope = self.bind()
        self.assertEqual(apply["plan_request"], self.request["payload"])
        self.assertEqual(envelope["apply_request"], apply)
        self.assertEqual(envelope["reviewed_plan_digest"], "d" * 64)
        self.assertEqual(envelope["activation"], "operator_acceptance_candidate")

    def test_reviewed_child_may_vary_only_beneath_protected_parent(self) -> None:
        request = copy.deepcopy(self.request)
        response = copy.deepcopy(self.response)
        target = "Q:/publication/destination/selected-app"
        request["payload"]["target"]["root"] = target.replace("/", "\\")
        response["result"]["payload"]["target"]["root"] = target
        apply, envelope = self.bind(request, response)
        self.assertEqual(apply["plan_request"]["target"]["root"], target.replace("/", "\\"))
        self.assertEqual(envelope["plan_request"]["target"]["root"], target.replace("/", "\\"))
        for invalid in (
            "Q:/publication/other/selected-app",
            "Q:/publication/destination/nested/selected-app",
            "Q:/publication/destination/CON.txt",
            "Q:/publication/destination/trailing.",
            "Q:/publication/destination/../selected-app",
            "Q:/publication//destination/selected-app",
            "R:/publication/destination/selected-app",
        ):
            with self.subTest(target=invalid):
                changed = copy.deepcopy(response)
                changed["result"]["payload"]["target"]["root"] = invalid
                request["payload"]["target"]["root"] = invalid
                with self.assertRaises(BindingError):
                    self.bind(request, changed)

    def test_source_target_selection_and_authority_substitution_refuse(self) -> None:
        for location, key, replacement in (
            ("source", "sha256", "0" * 64),
            ("target", "root", "Q:/other/visible"),
            ("input_identity", "recipe_digest", "0" * 64),
        ):
            with self.subTest(location=location, key=key):
                altered = copy.deepcopy(self.response)
                altered["result"]["payload"][location][key] = replacement
                with self.assertRaises(BindingError):
                    self.bind(response=altered)
        altered = copy.deepcopy(self.response)
        altered["result"]["payload"]["component_selection"] = ["core"]
        with self.assertRaises(BindingError):
            self.bind(response=altered)
        altered = copy.deepcopy(self.response)
        altered["result"]["payload"]["commit_authority_available"] = True
        with self.assertRaises(BindingError):
            self.bind(response=altered)

    def test_failed_plan_and_other_volume_refuse(self) -> None:
        altered = copy.deepcopy(self.response)
        altered["status"] = "refused"
        with self.assertRaises(BindingError):
            self.bind(response=altered)
        with self.assertRaises(BindingError):
            compose_binding(self.request, self.response, acceptance_root="R:\\",
                            state_root="R:/setup-state", transaction_id="install.1",
                            applied_at="2026-09-28T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
