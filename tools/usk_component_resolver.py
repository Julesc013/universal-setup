# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Bounded, deterministic component closure for declarative setup authoring.

This is a graph resolver, not a machine plan or execution authority. The
caller must validate the complete bundle contract and target variants before
using the selected IDs to build a carrier.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any


MAX_COMPONENTS = 4096
MAX_EDGES = 65536
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")


class ResolutionError(ValueError):
    def __init__(self, code: str, *witness: str) -> None:
        self.code = code
        self.witness = witness
        super().__init__(code + (": " + " -> ".join(witness) if witness else ""))


def _references(value: Any, owner: str, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_EDGES:
        raise ResolutionError("invalid_references", owner, field)
    if any(not isinstance(item, str) or not IDENTIFIER.fullmatch(item)
           for item in value) or len(value) != len(set(value)):
        raise ResolutionError("invalid_references", owner, field)
    return tuple(sorted(value))


def resolve_component_ids(
    components: Any,
    requested: Sequence[str] = (),
    *,
    component_limit: int = MAX_COMPONENTS,
    edge_limit: int = MAX_EDGES,
) -> tuple[str, ...]:
    """Return selected IDs in stable dependency-first order.

    Required and default-selected components seed the selection, along with
    explicit requests. Every declared dependency graph is checked, including
    unselected components, so latent cycles cannot enter a compiled bundle.
    Conflict declarations are directional; either side rejects a selected pair.
    """
    if (type(component_limit) is not int or not 1 <= component_limit <= MAX_COMPONENTS or
            type(edge_limit) is not int or not 0 <= edge_limit <= MAX_EDGES):
        raise ResolutionError("invalid_budget")
    if not isinstance(components, list) or not components:
        raise ResolutionError("invalid_components")
    if len(components) > component_limit:
        raise ResolutionError("resource_limit", "components")
    if not isinstance(requested, (list, tuple)) or len(requested) > component_limit:
        raise ResolutionError("invalid_requests")

    graph: dict[str, tuple[bool, bool, tuple[str, ...], tuple[str, ...]]] = {}
    edges = 0
    for entry in components:
        if not isinstance(entry, dict):
            raise ResolutionError("invalid_component")
        name = entry.get("id")
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name):
            raise ResolutionError("invalid_component")
        if name in graph:
            raise ResolutionError("duplicate_component", name)
        required = entry.get("required")
        default_selected = entry.get("default_selected")
        if type(required) is not bool or type(default_selected) is not bool:
            raise ResolutionError("invalid_component", name)
        requires = _references(entry.get("requires"), name, "requires")
        conflicts = _references(entry.get("conflicts"), name, "conflicts")
        edges += len(requires) + len(conflicts)
        if edges > edge_limit:
            raise ResolutionError("resource_limit", "edges")
        graph[name] = (required, default_selected, requires, conflicts)

    for name in sorted(graph):
        if name in graph[name][3]:
            raise ResolutionError("self_conflict", name)
        for reference in graph[name][2] + graph[name][3]:
            if reference not in graph:
                raise ResolutionError("unknown_reference", name, reference)

    # Iterative DFS avoids recursion depth and yields a stable topological order.
    state: dict[str, int] = {}
    order: list[str] = []
    for start in sorted(graph):
        if state.get(start) == 2:
            continue
        state[start] = 1
        active = [start]
        positions = {start: 0}
        stack = [(start, 0)]
        while stack:
            name, index = stack[-1]
            dependencies = graph[name][2]
            if index == len(dependencies):
                stack.pop()
                active.pop()
                del positions[name]
                state[name] = 2
                order.append(name)
                continue
            stack[-1] = (name, index + 1)
            dependency = dependencies[index]
            if state.get(dependency) == 1:
                raise ResolutionError("cycle", *active[positions[dependency]:], dependency)
            if state.get(dependency) != 2:
                state[dependency] = 1
                positions[dependency] = len(active)
                active.append(dependency)
                stack.append((dependency, 0))

    seeds = {name for name, (required, default_selected, _, _) in graph.items()
             if required or default_selected}
    for name in requested:
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name not in graph:
            raise ResolutionError("unknown_requested", str(name))
        seeds.add(name)
    selected: set[str] = set()
    pending = sorted(seeds, reverse=True)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        selected.add(name)
        pending.extend(graph[name][2])

    for name in sorted(selected):
        for conflicting in graph[name][3]:
            if conflicting in selected:
                raise ResolutionError("conflict", name, conflicting)
    return tuple(name for name in order if name in selected)
