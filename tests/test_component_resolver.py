# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

from __future__ import annotations

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from usk_component_resolver import ResolutionError, resolve_component_ids


def component(name: str, *, requires: tuple[str, ...] = (),
              conflicts: tuple[str, ...] = (), required: bool = False,
              default_selected: bool = False) -> dict:
    return {"id": name, "requires": list(requires), "conflicts": list(conflicts),
            "required": required, "default_selected": default_selected}


class ComponentResolverTests(unittest.TestCase):
    def test_dependency_closure_and_order_are_input_order_independent(self) -> None:
        graph = [component("ui", requires=("core",), default_selected=True),
                 component("addon", requires=("core",)),
                 component("core", required=True)]
        expected = ("core", "addon", "ui")
        self.assertEqual(resolve_component_ids(graph, ["addon"]), expected)
        self.assertEqual(resolve_component_ids(list(reversed(graph)), ["addon"]), expected)
        self.assertEqual(resolve_component_ids(graph), ("core", "ui"))

    def test_cycle_witness_is_stable_and_unselected_cycle_refuses(self) -> None:
        graph = [component("z", requires=("y",)),
                 component("y", requires=("z",)), component("a", required=True)]
        for variant in (graph, list(reversed(graph))):
            with self.assertRaises(ResolutionError) as caught:
                resolve_component_ids(variant)
            self.assertEqual(caught.exception.code, "cycle")
            self.assertEqual(caught.exception.witness, ("y", "z", "y"))

    def test_selected_conflict_refuses_with_same_witness_after_reordering(self) -> None:
        graph = [component("beta", required=True),
                 component("alpha", conflicts=("beta",), default_selected=True)]
        for variant in (graph, list(reversed(graph))):
            with self.assertRaises(ResolutionError) as caught:
                resolve_component_ids(variant)
            self.assertEqual(caught.exception.code, "conflict")
            self.assertEqual(caught.exception.witness, ("alpha", "beta"))

    def test_unknown_reference_and_duplicate_id_refuse(self) -> None:
        for graph, code in (
            ([component("a", requires=("missing",))], "unknown_reference"),
            ([component("a"), component("a")], "duplicate_component"),
            ([component("a", conflicts=("a",))], "self_conflict"),
        ):
            with self.assertRaises(ResolutionError) as caught:
                resolve_component_ids(graph)
            self.assertEqual(caught.exception.code, code)

    def test_deep_graph_is_iterative_and_budget_is_enforced(self) -> None:
        graph = [component(f"c{i:04}", requires=(f"c{i-1:04}",) if i else (),
                           required=i == 1199) for i in range(1200)]
        result = resolve_component_ids(list(reversed(graph)))
        self.assertEqual(len(result), 1200)
        self.assertEqual((result[0], result[-1]), ("c0000", "c1199"))
        for kwargs, witness in (({"component_limit": 1199}, "components"),
                                ({"edge_limit": 1198}, "edges")):
            with self.assertRaises(ResolutionError) as caught:
                resolve_component_ids(graph, **kwargs)
            self.assertEqual((caught.exception.code, caught.exception.witness),
                             ("resource_limit", (witness,)))

    def test_invalid_budget_and_unbounded_request_input_refuse(self) -> None:
        graph = [component("core", required=True)]
        with self.assertRaisesRegex(ResolutionError, "invalid_budget"):
            resolve_component_ids(graph, component_limit=4097)
        with self.assertRaisesRegex(ResolutionError, "invalid_requests"):
            resolve_component_ids(graph, (name for name in ["core"]))
        with self.assertRaises(ResolutionError) as caught:
            resolve_component_ids([component(f"c{i}") for i in range(4097)])
        self.assertEqual((caught.exception.code, caught.exception.witness),
                         ("resource_limit", ("components",)))


if __name__ == "__main__":
    unittest.main()
