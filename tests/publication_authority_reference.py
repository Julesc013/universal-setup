# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Closed deterministic model for the unavailable WU-004 publication profile.

This module performs no filesystem work and proves no Windows behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import json
import re
from typing import Any, Iterable, Mapping


MAX_CLOSURE_ENTRIES = 200_000
MAX_CLOSURE_DEPTH = 128
MAX_COMPONENT_UTF16_UNITS = 255
MAX_EVIDENCE_BYTES = 268_435_456
MAX_CONTENT_BYTES = 17_592_186_044_416
PROFILE_ID = "windows_nt_x64_local_ntfs_service_sid_noreplace_v1"
SERVICE_SID = "S-1-5-80-3180180915-1861177297-4117424284-3321057921-2519428456"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FILE_ID_RE = re.compile(r"^[0-9a-f]{16}:[0-9a-f]{32}$")


class Phase(str, Enum):
    UNAVAILABLE = "unavailable"
    PROTECTED_EMPTY = "protected_empty"
    MATERIALIZING = "materializing"
    SEALED = "sealed"
    PUBLISH_PREPARED = "publish_prepared"
    RENAMED_UNCONFIRMED = "renamed_unconfirmed"
    VISIBLE_BOUND = "visible_bound"
    METADATA_PENDING = "metadata_pending"
    COMPLETED = "completed"
    REFUSED_RETAINED = "refused_retained"
    RECOVERY_REQUIRED = "recovery_required"


class RenameState(str, Enum):
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"
    UNKNOWN = "unknown"


class EffectState(str, Enum):
    NO_EFFECT = "no_effect"
    RENAMED = "renamed"
    AMBIGUOUS = "ambiguous"


class EntryType(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"


DISPOSITIONS = frozenset({"advanced", "no_effect_refusal", "retained_refusal",
                          "recovery_required", "completed", "invalid_trace"})
TERMINAL_DISPOSITIONS = DISPOSITIONS - {"advanced"}


class EvidenceError(ValueError):
    """Missing, unknown, ill-typed, or inconsistent evidence."""


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise EvidenceError(f"{label} keys missing={sorted(expected - actual)} unknown={sorted(actual - expected)}")


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{label} must be an integer >= {minimum}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{label} must be a non-empty string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{label} must be a boolean")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise EvidenceError(f"{label} must be a list of non-empty strings")
    return tuple(value)


@dataclass(frozen=True, order=True)
class Ace:
    principal: str
    ace_type: str
    rights: tuple[str, ...]

    @classmethod
    def parse(cls, value: Any) -> "Ace":
        if not isinstance(value, Mapping):
            raise EvidenceError("ace must be an object")
        _exact_keys(value, frozenset({"principal", "type", "rights"}), "ace")
        return cls(_string(value["principal"], "ace.principal"),
                   _string(value["type"], "ace.type"), _strings(value["rights"], "ace.rights"))


FULL_CONTROL = ("DELETE", "FILE_ADD_FILE", "FILE_ADD_SUBDIRECTORY", "FILE_APPEND_DATA",
                "FILE_DELETE_CHILD", "FILE_EXECUTE", "FILE_LIST_DIRECTORY", "FILE_READ_ATTRIBUTES",
                "FILE_READ_DATA", "FILE_READ_EA", "FILE_TRAVERSE", "FILE_WRITE_ATTRIBUTES",
                "FILE_WRITE_DATA", "FILE_WRITE_EA", "READ_CONTROL", "SYNCHRONIZE", "WRITE_DAC",
                "WRITE_OWNER")
EXPECTED_ACES = (Ace("S-1-5-18", "allow", FULL_CONTROL), Ace(SERVICE_SID, "allow", FULL_CONTROL))
EXPECTED_COVERED_OBJECTS = ("staging_root", "destination_parent", "state_anchor", "journal_anchor",
                            "all_ancestors", "all_descendants")
EXPECTED_APIS = ("GetSecurityInfo", "GetFileInformationByHandleEx:FileIdInfo",
                 "GetFileInformationByHandleEx:FileAttributeTagInfo",
                 "GetFileInformationByHandleEx:FileStandardInfo",
                 "GetFileInformationByHandleEx:FileStreamInfo",
                 "GetFileInformationByHandleEx:FileCaseSensitiveInfo")


@dataclass(frozen=True, order=True)
class AncestorEvidence:
    file_id: str
    security_descriptor_sha256: str
    reparse: bool
    case_sensitive: bool

    @classmethod
    def parse(cls, value: Any) -> "AncestorEvidence":
        if not isinstance(value, Mapping):
            raise EvidenceError("ancestor must be an object")
        _exact_keys(value, frozenset({"file_id", "security_descriptor_sha256", "reparse", "case_sensitive"}), "ancestor")
        result = cls(_string(value["file_id"], "ancestor.file_id"),
                     _string(value["security_descriptor_sha256"], "ancestor.security_descriptor_sha256"),
                     _boolean(value["reparse"], "ancestor.reparse"),
                     _boolean(value["case_sensitive"], "ancestor.case_sensitive"))
        if not FILE_ID_RE.fullmatch(result.file_id) or not SHA256_RE.fullmatch(result.security_descriptor_sha256):
            raise EvidenceError("ancestor identity or digest format is invalid")
        return result


PROFILE_KEYS = frozenset({"profile_id", "os_family", "os_arch", "windows_build", "sdk_version",
    "publisher_service_sid", "service_sid_type", "anchor_creation", "owner_sid", "dacl_protected",
    "inherited_aces", "dacl_aces", "consumer_grants", "untrusted_mutating_rights", "covered_objects",
    "handle_provenance", "anchor_preexisting", "handles_inheritable", "handles_duplicated_outside_service",
    "filesystem", "local_volume", "same_volume", "volume_serial", "staging_parent_id",
    "destination_parent_id", "state_anchor_id", "journal_anchor_id", "ancestor_chain",
    "ancestors_revalidated", "destination_absent", "single_final_component", "replace_if_exists",
    "observation_apis", "closure_entry_count", "closure_max_depth", "max_component_utf16_units",
    "serialized_evidence_bytes", "total_content_bytes"})


@dataclass(frozen=True)
class ProfileEvidence:
    profile_id: str
    os_family: str
    os_arch: str
    windows_build: int
    sdk_version: str
    publisher_service_sid: str
    service_sid_type: str
    anchor_creation: str
    owner_sid: str
    dacl_protected: bool
    inherited_aces: tuple[str, ...]
    dacl_aces: tuple[Ace, ...]
    consumer_grants: tuple[str, ...]
    untrusted_mutating_rights: tuple[str, ...]
    covered_objects: tuple[str, ...]
    handle_provenance: str
    anchor_preexisting: bool
    handles_inheritable: bool
    handles_duplicated_outside_service: bool
    filesystem: str
    local_volume: bool
    same_volume: bool
    volume_serial: str
    staging_parent_id: str
    destination_parent_id: str
    state_anchor_id: str
    journal_anchor_id: str
    ancestor_chain: tuple[AncestorEvidence, ...]
    ancestors_revalidated: bool
    destination_absent: bool
    single_final_component: bool
    replace_if_exists: bool
    observation_apis: tuple[str, ...]
    closure_entry_count: int
    closure_max_depth: int
    max_component_utf16_units: int
    serialized_evidence_bytes: int
    total_content_bytes: int

    @classmethod
    def parse(cls, value: Any) -> "ProfileEvidence":
        if not isinstance(value, Mapping):
            raise EvidenceError("profile evidence must be an object")
        _exact_keys(value, PROFILE_KEYS, "profile evidence")
        if not isinstance(value["dacl_aces"], list) or not isinstance(value["ancestor_chain"], list):
            raise EvidenceError("dacl_aces and ancestor_chain must be lists")
        result = cls(
            _string(value["profile_id"], "profile_id"), _string(value["os_family"], "os_family"),
            _string(value["os_arch"], "os_arch"), _integer(value["windows_build"], "windows_build"),
            _string(value["sdk_version"], "sdk_version"), _string(value["publisher_service_sid"], "publisher_service_sid"),
            _string(value["service_sid_type"], "service_sid_type"), _string(value["anchor_creation"], "anchor_creation"),
            _string(value["owner_sid"], "owner_sid"), _boolean(value["dacl_protected"], "dacl_protected"),
            _strings(value["inherited_aces"], "inherited_aces"), tuple(Ace.parse(x) for x in value["dacl_aces"]),
            _strings(value["consumer_grants"], "consumer_grants"),
            _strings(value["untrusted_mutating_rights"], "untrusted_mutating_rights"),
            _strings(value["covered_objects"], "covered_objects"), _string(value["handle_provenance"], "handle_provenance"),
            _boolean(value["anchor_preexisting"], "anchor_preexisting"),
            _boolean(value["handles_inheritable"], "handles_inheritable"),
            _boolean(value["handles_duplicated_outside_service"], "handles_duplicated_outside_service"),
            _string(value["filesystem"], "filesystem"), _boolean(value["local_volume"], "local_volume"),
            _boolean(value["same_volume"], "same_volume"), _string(value["volume_serial"], "volume_serial"),
            _string(value["staging_parent_id"], "staging_parent_id"),
            _string(value["destination_parent_id"], "destination_parent_id"),
            _string(value["state_anchor_id"], "state_anchor_id"), _string(value["journal_anchor_id"], "journal_anchor_id"),
            tuple(AncestorEvidence.parse(x) for x in value["ancestor_chain"]),
            _boolean(value["ancestors_revalidated"], "ancestors_revalidated"),
            _boolean(value["destination_absent"], "destination_absent"),
            _boolean(value["single_final_component"], "single_final_component"),
            _boolean(value["replace_if_exists"], "replace_if_exists"),
            _strings(value["observation_apis"], "observation_apis"),
            _integer(value["closure_entry_count"], "closure_entry_count"),
            _integer(value["closure_max_depth"], "closure_max_depth"),
            _integer(value["max_component_utf16_units"], "max_component_utf16_units", 1),
            _integer(value["serialized_evidence_bytes"], "serialized_evidence_bytes"),
            _integer(value["total_content_bytes"], "total_content_bytes"))
        result.validate()
        return result

    def validate(self) -> None:
        identities = (self.volume_serial, self.staging_parent_id, self.destination_parent_id,
                      self.state_anchor_id, self.journal_anchor_id)
        rejected = (self.profile_id != PROFILE_ID or self.os_family != "Windows NT" or self.os_arch != "x64" or
            self.windows_build < 17763 or self.sdk_version != "10.0.17763.0" or
            self.publisher_service_sid != SERVICE_SID or self.service_sid_type != "SERVICE_SID_TYPE_RESTRICTED" or
            self.anchor_creation != "atomic_protected_from_inception" or self.owner_sid != "S-1-5-18" or
            not self.dacl_protected or bool(self.inherited_aces) or self.dacl_aces != EXPECTED_ACES or
            bool(self.consumer_grants) or bool(self.untrusted_mutating_rights) or
            self.covered_objects != EXPECTED_COVERED_OBJECTS or
            self.handle_provenance != "service_created_from_inception" or self.anchor_preexisting or
            self.handles_inheritable or self.handles_duplicated_outside_service or self.filesystem != "NTFS" or
            not self.local_volume or not self.same_volume or any(not FILE_ID_RE.fullmatch(x) for x in identities) or
            not self.ancestor_chain or any(x.reparse or x.case_sensitive for x in self.ancestor_chain) or
            not self.ancestors_revalidated or not self.destination_absent or not self.single_final_component or
            self.replace_if_exists or self.observation_apis != EXPECTED_APIS or
            self.closure_entry_count > MAX_CLOSURE_ENTRIES or self.closure_max_depth > MAX_CLOSURE_DEPTH or
            self.max_component_utf16_units > MAX_COMPONENT_UTF16_UNITS or
            self.serialized_evidence_bytes > MAX_EVIDENCE_BYTES or self.total_content_bytes > MAX_CONTENT_BYTES)
        if rejected:
            raise EvidenceError("profile evidence does not satisfy the closed profile")


ENTRY_KEYS = frozenset({"relative_path", "type", "file_id", "content_sha256", "size", "attributes",
                        "security_descriptor_sha256", "link_count", "streams", "reparse", "reparse_tag"})


@dataclass(frozen=True, order=True)
class ClosureEntry:
    relative_path: str
    entry_type: EntryType
    file_id: str
    content_sha256: str | None
    size: int
    attributes: tuple[str, ...]
    security_descriptor_sha256: str
    link_count: int
    streams: tuple[str, ...]
    reparse: bool
    reparse_tag: int | None

    @classmethod
    def parse(cls, value: Any) -> "ClosureEntry":
        if not isinstance(value, Mapping):
            raise EvidenceError("closure entry must be an object")
        _exact_keys(value, ENTRY_KEYS, "closure entry")
        try:
            entry_type = EntryType(value["type"])
        except (TypeError, ValueError) as exc:
            raise EvidenceError("closure entry type is invalid") from exc
        digest = value["content_sha256"]
        if digest is not None and not isinstance(digest, str):
            raise EvidenceError("content_sha256 must be a string or null")
        tag = value["reparse_tag"]
        if tag is not None and (isinstance(tag, bool) or not isinstance(tag, int)):
            raise EvidenceError("reparse_tag must be an integer or null")
        result = cls(_string(value["relative_path"], "relative_path"), entry_type,
                     _string(value["file_id"], "file_id"), digest, _integer(value["size"], "size"),
                     _strings(value["attributes"], "attributes"),
                     _string(value["security_descriptor_sha256"], "security_descriptor_sha256"),
                     _integer(value["link_count"], "link_count", 1), _strings(value["streams"], "streams"),
                     _boolean(value["reparse"], "reparse"), tag)
        result.validate()
        return result

    def validate(self) -> None:
        if not FILE_ID_RE.fullmatch(self.file_id) or not SHA256_RE.fullmatch(self.security_descriptor_sha256):
            raise EvidenceError("closure identity or security descriptor digest is invalid")
        if self.reparse or self.reparse_tag is not None or self.link_count != 1:
            raise EvidenceError("reparse or multiply-linked entries are not admitted")
        if self.entry_type == EntryType.FILE:
            if self.content_sha256 is None or not SHA256_RE.fullmatch(self.content_sha256):
                raise EvidenceError("file content digest is required")
            if self.streams != ("::$DATA",):
                raise EvidenceError("file must have only the unnamed data stream")
        elif self.content_sha256 is not None or self.streams:
            raise EvidenceError("directory cannot carry content digest or streams")
        if self.relative_path == ".":
            if self.entry_type != EntryType.DIRECTORY:
                raise EvidenceError("root must be a directory")
            return
        if self.relative_path.startswith(("/", "\\")) or "\\" in self.relative_path:
            raise EvidenceError("relative path must use canonical slash separators")
        parts = self.relative_path.split("/")
        if any(part in ("", ".", "..") for part in parts) or len(parts) > MAX_CLOSURE_DEPTH:
            raise EvidenceError("relative path is invalid or too deep")
        if any(len(part.encode("utf-16-le")) // 2 > MAX_COMPONENT_UTF16_UNITS for part in parts):
            raise EvidenceError("component length exceeds profile limit")


def _parse_closure(root_value: Any, entries_value: Any) -> tuple[ClosureEntry, tuple[ClosureEntry, ...]]:
    root = ClosureEntry.parse(root_value)
    if root.relative_path != "." or not isinstance(entries_value, list):
        raise EvidenceError("root/closure shape invalid")
    entries = tuple(ClosureEntry.parse(item) for item in entries_value)
    if len(entries) > MAX_CLOSURE_ENTRIES:
        raise EvidenceError("closure count exceeds profile limit")
    paths = tuple(item.relative_path for item in entries)
    if paths != tuple(sorted(paths, key=str.casefold)) or len({x.casefold() for x in paths}) != len(paths):
        raise EvidenceError("closure paths must be unique and case-insensitively sorted")
    return root, entries


@dataclass(frozen=True)
class ModelState:
    phase: Phase = Phase.UNAVAILABLE
    generation: str = "generation-1"
    profile: ProfileEvidence | None = None
    verified_root: ClosureEntry | None = None
    verified_closure: tuple[ClosureEntry, ...] | None = None
    visible_root: ClosureEntry | None = None
    visible_closure: tuple[ClosureEntry, ...] | None = None
    rename_state: RenameState = RenameState.NOT_APPLIED
    effect_state: EffectState = EffectState.NO_EFFECT
    retained: bool = False
    durable_milestones: tuple[str, ...] = ()
    completed_generations: frozenset[str] = frozenset()


@dataclass(frozen=True)
class StepResult:
    state: ModelState
    disposition: str
    reason_code: str

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise ValueError("unknown disposition: " + self.disposition)


def initial_state(generation: str = "generation-1") -> ModelState:
    if not isinstance(generation, str) or not generation:
        raise EvidenceError("generation must be a non-empty string")
    return ModelState(generation=generation)


def _result(state: ModelState, disposition: str, reason: str) -> StepResult:
    return StepResult(state, disposition, reason)


def _recovery(state: ModelState, reason: str, rename_state: RenameState | None = None) -> StepResult:
    renamed = state.rename_state if rename_state is None else rename_state
    effect = (EffectState.RENAMED if renamed == RenameState.APPLIED else
              EffectState.AMBIGUOUS if renamed == RenameState.UNKNOWN else state.effect_state)
    return _result(replace(state, phase=Phase.RECOVERY_REQUIRED, retained=True,
                           rename_state=renamed, effect_state=effect), "recovery_required", reason)


def _retained(state: ModelState, reason: str) -> StepResult:
    return _result(replace(state, phase=Phase.REFUSED_RETAINED, retained=True), "retained_refusal", reason)


EVENT_KEYS = {
    "admit_profile": frozenset({"action", "evidence"}),
    "begin_materialization": frozenset({"action"}),
    "seal": frozenset({"action", "root", "closure"}),
    "prepare_publish": frozenset({"action"}),
    "rename": frozenset({"action", "outcome", "replace_if_exists", "destination_exists"}),
    "confirm_visible": frozenset({"action", "root", "closure"}),
    "begin_metadata": frozenset({"action"}),
    "complete_metadata": frozenset({"action", "success"}),
    "crash": frozenset({"action", "rename_outcome"}),
    "privileged_attacker": frozenset({"action"}),
}


def transition(state: ModelState, event: Mapping[str, Any]) -> StepResult:
    """Apply one closed-schema event without host or filesystem observation."""
    if not isinstance(event, Mapping) or not isinstance(event.get("action"), str):
        return _result(state, "invalid_trace", "invalid_event_shape")
    action = event["action"]
    expected = EVENT_KEYS.get(action)
    if expected is None:
        return _result(state, "invalid_trace", "unknown_event")
    try:
        _exact_keys(event, expected, f"event {action}")
    except EvidenceError:
        if action == "confirm_visible" and state.phase == Phase.RENAMED_UNCONFIRMED and \
                frozenset(event).issubset(expected):
            return _recovery(state, "visible_evidence_missing_or_invalid")
        return _result(state, "invalid_trace", "invalid_event_shape")
    if state.phase in {Phase.COMPLETED, Phase.REFUSED_RETAINED, Phase.RECOVERY_REQUIRED}:
        return _result(state, "invalid_trace", "terminal_state")

    if action == "admit_profile":
        if state.phase != Phase.UNAVAILABLE:
            return _result(state, "invalid_trace", "preflight_wrong_phase")
        try:
            profile = ProfileEvidence.parse(event["evidence"])
        except EvidenceError:
            return _result(state, "no_effect_refusal", "profile_evidence_refused")
        return _result(replace(state, phase=Phase.PROTECTED_EMPTY, profile=profile), "advanced", "profile_admitted")
    if action == "begin_materialization":
        if state.phase != Phase.PROTECTED_EMPTY:
            return _result(state, "invalid_trace", "materialize_wrong_phase")
        return _result(replace(state, phase=Phase.MATERIALIZING), "advanced", "materialization_started")
    if action == "seal":
        if state.phase != Phase.MATERIALIZING:
            return _result(state, "invalid_trace", "seal_wrong_phase")
        try:
            root, closure = _parse_closure(event["root"], event["closure"])
        except EvidenceError:
            return _retained(state, "sealed_evidence_refused")
        assert state.profile is not None
        serialized = len(json.dumps({"root": event["root"], "closure": event["closure"]},
                                    sort_keys=True, separators=(",", ":")).encode())
        depth = max((len(item.relative_path.split("/")) for item in closure), default=0)
        component_width = max((len(part.encode("utf-16-le")) // 2 for item in closure
                               for part in item.relative_path.split("/")), default=0)
        total = root.size + sum(item.size for item in closure)
        if (len(closure) != state.profile.closure_entry_count or depth != state.profile.closure_max_depth or
                component_width > state.profile.max_component_utf16_units or
                serialized > state.profile.serialized_evidence_bytes or total > state.profile.total_content_bytes):
            return _retained(state, "closure_bounds_mismatch")
        return _result(replace(state, phase=Phase.SEALED, verified_root=root, verified_closure=closure),
                       "advanced", "closure_sealed")
    if action == "prepare_publish":
        if state.phase != Phase.SEALED:
            return _result(state, "invalid_trace", "prepare_wrong_phase")
        return _result(replace(state, phase=Phase.PUBLISH_PREPARED,
                               durable_milestones=state.durable_milestones + ("publish_prepared",)),
                       "advanced", "publish_prepared_durable")
    if action == "rename":
        if state.phase != Phase.PUBLISH_PREPARED:
            return _result(state, "invalid_trace", "rename_wrong_phase")
        if not isinstance(event["replace_if_exists"], bool) or not isinstance(event["destination_exists"], bool):
            return _result(state, "invalid_trace", "invalid_event_shape")
        try:
            outcome = RenameState(event["outcome"])
        except (TypeError, ValueError):
            return _result(state, "invalid_trace", "invalid_rename_outcome")
        if event["replace_if_exists"]:
            return _retained(state, "replace_if_exists_forbidden")
        if event["destination_exists"]:
            if outcome != RenameState.NOT_APPLIED:
                return _recovery(state, "destination_collision_ambiguous", RenameState.UNKNOWN)
            return _retained(state, "destination_exists")
        if outcome == RenameState.NOT_APPLIED:
            return _retained(state, "rename_not_applied")
        if outcome == RenameState.UNKNOWN:
            return _recovery(state, "rename_outcome_unknown", RenameState.UNKNOWN)
        return _result(replace(state, phase=Phase.RENAMED_UNCONFIRMED, rename_state=RenameState.APPLIED,
                               effect_state=EffectState.RENAMED), "advanced", "rename_applied_unconfirmed")
    if action == "confirm_visible":
        if state.phase != Phase.RENAMED_UNCONFIRMED:
            return _result(state, "invalid_trace", "confirm_wrong_phase")
        try:
            root, closure = _parse_closure(event["root"], event["closure"])
        except EvidenceError:
            return _recovery(state, "visible_evidence_missing_or_invalid")
        observed = replace(state, visible_root=root, visible_closure=closure)
        if root != state.verified_root or closure != state.verified_closure:
            return _recovery(observed, "visible_binding_mismatch")
        return _result(replace(observed, phase=Phase.VISIBLE_BOUND,
                               durable_milestones=state.durable_milestones + ("visible_bound",)),
                       "advanced", "visible_binding_exact")
    if action == "begin_metadata":
        if state.phase != Phase.VISIBLE_BOUND:
            return _result(state, "invalid_trace", "metadata_wrong_phase")
        return _result(replace(state, phase=Phase.METADATA_PENDING), "advanced", "metadata_pending")
    if action == "complete_metadata":
        if state.phase != Phase.METADATA_PENDING or not isinstance(event["success"], bool):
            return _result(state, "invalid_trace", "metadata_completion_invalid")
        if not event["success"]:
            return _recovery(state, "metadata_failed")
        if state.generation in state.completed_generations:
            return _result(state, "invalid_trace", "duplicate_generation_completion")
        return _result(replace(state, phase=Phase.COMPLETED,
                               durable_milestones=state.durable_milestones + ("metadata_completed",),
                               completed_generations=state.completed_generations | {state.generation}),
                       "completed", "completion_recorded")
    if action == "crash":
        try:
            reported = RenameState(event["rename_outcome"])
        except (TypeError, ValueError):
            return _result(state, "invalid_trace", "invalid_rename_outcome")
        if state.phase in {Phase.PUBLISH_PREPARED, Phase.RENAMED_UNCONFIRMED, Phase.VISIBLE_BOUND, Phase.METADATA_PENDING}:
            effective = state.rename_state if state.rename_state != RenameState.NOT_APPLIED else reported
            return _recovery(state, "crash_requires_recovery", effective)
        if state.phase in {Phase.PROTECTED_EMPTY, Phase.MATERIALIZING, Phase.SEALED}:
            return _recovery(state, "crash_retains_protected_material", RenameState.NOT_APPLIED)
        return _result(state, "invalid_trace", "crash_wrong_phase")
    if state.rename_state in {RenameState.APPLIED, RenameState.UNKNOWN}:
        return _recovery(state, "excluded_actor_after_rename")
    return _result(state, "no_effect_refusal", "excluded_actor_outside_claim")


def replay(state: ModelState, events: Iterable[Mapping[str, Any]]) -> StepResult:
    result = _result(state, "advanced", "empty_trace")
    for event in events:
        result = transition(result.state, event)
        if result.disposition in TERMINAL_DISPOSITIONS:
            break
    return result


def _entry_projection(entry: ClosureEntry) -> dict[str, Any]:
    return {"relative_path": entry.relative_path, "type": entry.entry_type.value, "file_id": entry.file_id,
            "content_sha256": entry.content_sha256, "size": entry.size, "attributes": list(entry.attributes),
            "security_descriptor_sha256": entry.security_descriptor_sha256, "link_count": entry.link_count,
            "streams": list(entry.streams), "reparse": entry.reparse, "reparse_tag": entry.reparse_tag}


def projection(result: StepResult) -> dict[str, Any]:
    state = result.state
    visible = None
    if state.visible_root is not None and state.visible_closure is not None:
        visible = {"root": _entry_projection(state.visible_root),
                   "closure": [_entry_projection(item) for item in state.visible_closure]}
    return {"disposition": result.disposition, "phase": state.phase.value,
            "effect_state": state.effect_state.value, "rename_state": state.rename_state.value,
            "retained": state.retained, "durable_milestones": list(state.durable_milestones),
            "visible_binding": visible, "completed_generation_count": len(state.completed_generations),
            "reason_code": result.reason_code}


def invariant_errors(state: ModelState) -> tuple[str, ...]:
    errors: list[str] = []
    if state.phase == Phase.COMPLETED:
        if state.rename_state != RenameState.APPLIED or state.effect_state != EffectState.RENAMED:
            errors.append("completed requires an applied rename")
        if state.visible_root is None or state.visible_closure is None:
            errors.append("completed requires explicit visible evidence")
        if state.visible_root != state.verified_root or state.visible_closure != state.verified_closure:
            errors.append("completed requires exact root and closure binding")
        if state.durable_milestones != ("publish_prepared", "visible_bound", "metadata_completed"):
            errors.append("completed durable milestone order is invalid")
        if state.generation not in state.completed_generations or len(state.completed_generations) != 1:
            errors.append("generation must complete exactly once")
    if state.phase in {Phase.RENAMED_UNCONFIRMED, Phase.VISIBLE_BOUND, Phase.METADATA_PENDING, Phase.COMPLETED} and \
            "publish_prepared" not in state.durable_milestones:
        errors.append("rename requires durable prepare")
    if state.phase == Phase.VISIBLE_BOUND and (state.visible_root != state.verified_root or
                                                state.visible_closure != state.verified_closure):
        errors.append("visible_bound requires exact visible evidence")
    if state.phase == Phase.UNAVAILABLE and state.effect_state != EffectState.NO_EFFECT:
        errors.append("unavailable state cannot have an effect")
    if state.phase == Phase.RECOVERY_REQUIRED and not state.retained:
        errors.append("recovery must retain ambiguous material")
    if state.rename_state == RenameState.UNKNOWN and state.effect_state != EffectState.AMBIGUOUS:
        errors.append("unknown rename must have ambiguous effect")
    return tuple(errors)
