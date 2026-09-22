# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Deterministic candidate-publication oracle; it performs no filesystem work."""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping


class Phase(str, Enum):
    INITIAL = "initial"
    VERIFIED = "verified"
    PUBLISH_PREPARED = "publish_prepared"
    RENAMED = "renamed"
    VISIBLE_BOUND = "visible_bound"
    RECOVERY_REQUIRED = "recovery_required"
    COMPLETED = "completed"


DISPOSITIONS = frozenset({
    "advanced", "no_effect_refusal", "retained_refusal", "recovery_required",
    "completed", "invalid_trace",
})


@dataclass(frozen=True)
class ModelState:
    phase: Phase = Phase.INITIAL
    generation: str = "generation-1"
    available: bool = False
    eligible: bool = False
    verified_identity: str = "file:verified"
    verified_closure: tuple[str, ...] = ("payload.bin",)
    visible_identity: str | None = None
    visible_closure: tuple[str, ...] | None = None
    renamed: bool = False
    metadata_written: bool = False
    retained: bool = False
    completed_generations: frozenset[str] = frozenset()


@dataclass(frozen=True)
class StepResult:
    state: ModelState
    disposition: str
    reason: str

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise ValueError("unknown disposition: " + self.disposition)


def initial_state(**overrides: Any) -> ModelState:
    """Return an immutable candidate state. Defaults deliberately remain unavailable."""
    if "verified_closure" in overrides:
        overrides["verified_closure"] = tuple(overrides["verified_closure"])
    if "completed_generations" in overrides:
        overrides["completed_generations"] = frozenset(overrides["completed_generations"])
    return ModelState(**overrides)


def _result(state: ModelState, disposition: str, reason: str) -> StepResult:
    return StepResult(state, disposition, reason)


def _recovery(state: ModelState, reason: str) -> StepResult:
    return _result(replace(state, phase=Phase.RECOVERY_REQUIRED, retained=True), "recovery_required", reason)


def transition(state: ModelState, step: Mapping[str, Any] | str) -> StepResult:
    """Apply one abstract protocol step without observing a host or filesystem."""
    if isinstance(step, str):
        step = {"action": step}
    if not isinstance(step, Mapping) or not isinstance(step.get("action"), str):
        return _result(state, "invalid_trace", "step must contain a string action")
    action = step["action"]
    if state.phase in (Phase.RECOVERY_REQUIRED, Phase.COMPLETED):
        return _result(state, "invalid_trace", "terminal phase cannot advance")
    if action == "preflight":
        if not state.available:
            return _result(state, "no_effect_refusal", "candidate unavailable")
        if not state.eligible:
            return _result(state, "no_effect_refusal", "target is ineligible")
        return _result(replace(state, phase=Phase.VERIFIED), "advanced", "bound preflight accepted")
    if action == "publish_prepared":
        if state.phase != Phase.VERIFIED:
            return _result(state, "invalid_trace", "publish_prepared requires verified")
        return _result(replace(state, phase=Phase.PUBLISH_PREPARED), "advanced", "prepared journal durable")
    if action == "rename":
        if state.phase != Phase.PUBLISH_PREPARED:
            return _result(state, "invalid_trace", "rename requires publish_prepared")
        if step.get("destination_exists"):
            return _result(replace(state, retained=True), "retained_refusal", "no-replace destination exists")
        return _result(replace(state, phase=Phase.RENAMED, renamed=True), "advanced", "rename attempted")
    if action == "confirm_visible":
        if state.phase != Phase.RENAMED:
            return _result(state, "invalid_trace", "visible confirmation requires rename")
        identity = str(step.get("identity", state.verified_identity))
        closure = tuple(step.get("closure", state.verified_closure))
        if identity != state.verified_identity or closure != state.verified_closure:
            return _recovery(replace(state, visible_identity=identity, visible_closure=closure), "visible identity or closure mismatch")
        return _result(replace(state, phase=Phase.VISIBLE_BOUND, visible_identity=identity,
                               visible_closure=closure), "advanced", "visible identity and closure bound")
    if action == "metadata":
        if state.phase != Phase.VISIBLE_BOUND:
            return _result(state, "invalid_trace", "metadata requires visible_bound")
        if step.get("fail"):
            return _recovery(state, "metadata failed after visibility")
        if state.generation in state.completed_generations:
            return _result(state, "invalid_trace", "generation already completed")
        completed = state.completed_generations | frozenset({state.generation})
        return _result(replace(state, phase=Phase.COMPLETED, metadata_written=True,
                               completed_generations=completed), "completed", "completion recorded")
    if action == "crash":
        if state.phase in (Phase.VERIFIED, Phase.PUBLISH_PREPARED, Phase.RENAMED, Phase.VISIBLE_BOUND):
            return _recovery(state, "crash leaves retained recovery")
        return _result(state, "invalid_trace", "crash prefix has no prepared operation")
    if action == "privileged_attacker":
        return _result(state, "no_effect_refusal", "outside candidate adversary claim")
    return _result(state, "invalid_trace", "unknown action: " + action)


def replay(state: ModelState, steps: Iterable[Mapping[str, Any] | str]) -> StepResult:
    result = _result(state, "advanced", "empty trace")
    for step in steps:
        result = transition(result.state, step)
        if result.disposition in {"invalid_trace", "recovery_required", "completed"}:
            break
    return result


def invariant_errors(state: ModelState) -> tuple[str, ...]:
    errors: list[str] = []
    if state.phase == Phase.COMPLETED:
        if not state.renamed or not state.metadata_written:
            errors.append("completed requires rename and metadata")
        if state.visible_identity != state.verified_identity:
            errors.append("completed visible identity differs from verified identity")
        if state.visible_closure != state.verified_closure:
            errors.append("completed visible closure differs from verified closure")
        if state.generation not in state.completed_generations:
            errors.append("completed generation is not recorded")
    if state.phase == Phase.VISIBLE_BOUND and (state.visible_identity != state.verified_identity or
                                                state.visible_closure != state.verified_closure):
        errors.append("visible_bound requires exact identity and closure")
    if state.phase == Phase.RECOVERY_REQUIRED and not state.retained:
        errors.append("recovery_required retains ambiguous material")
    if not state.available and state.phase != Phase.INITIAL:
        errors.append("unavailable candidate cannot advance")
    return tuple(errors)
