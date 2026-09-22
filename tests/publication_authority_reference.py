# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Closed deterministic model for the unavailable WU-004 publication profile.

This module performs no filesystem work and proves no Windows behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import re
import unicodedata
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
VOLUME_SERIAL_RE = re.compile(r"^[0-9a-f]{16}$")
VOLUME_NAME_RE = re.compile(r"^\\\\\?\\Volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\$")
FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*')
RESERVED_DEVICE_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                                   "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
                                   "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                                   "LPT9", "LPT¹", "LPT²", "LPT³"})


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


def _file_id_parts(value: str, label: str) -> tuple[str, str]:
    if not FILE_ID_RE.fullmatch(value):
        raise EvidenceError(f"{label} must be a FILE_ID_INFO volume:file-id composite")
    volume_serial, file_id = value.split(":", 1)
    return volume_serial, file_id


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
                 "GetFileInformationByHandleEx:FileCaseSensitiveInfo",
                 "GetVolumeInformationByHandleW",
                 "GetFileInformationByHandleEx:FileRemoteProtocolInfo",
                 "GetFileInformationByHandleEx:FileNameInfo")
EXPECTED_FILESYSTEM_FLAGS = ("FILE_CASE_PRESERVED_NAMES", "FILE_CASE_SENSITIVE_SEARCH",
                             "FILE_PERSISTENT_ACLS", "FILE_SUPPORTS_REPARSE_POINTS",
                             "FILE_SUPPORTS_USN_JOURNAL")


@dataclass(frozen=True, order=True)
class EffectiveAccess:
    principal: str
    rights: tuple[str, ...]

    @classmethod
    def parse(cls, value: Any) -> "EffectiveAccess":
        if not isinstance(value, Mapping):
            raise EvidenceError("effective access must be an object")
        _exact_keys(value, frozenset({"principal", "rights"}), "effective access")
        return cls(_string(value["principal"], "effective_access.principal"),
                   _strings(value["rights"], "effective_access.rights"))


EXPECTED_EFFECTIVE_ACCESS = (EffectiveAccess("initiating_user", ()), EffectiveAccess("untrusted_users", ()))
SECURITY_KEYS = frozenset({"owner_sid", "dacl_protected", "inherited_aces", "dacl_aces",
                           "other_aces", "effective_access", "canonical_descriptor_sha256"})


def _security_canonical_payload(value: Mapping[str, Any]) -> bytes:
    payload = {key: value[key] for key in SECURITY_KEYS if key != "canonical_descriptor_sha256"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, order=True)
class SecurityEvidence:
    owner_sid: str
    dacl_protected: bool
    inherited_aces: tuple[str, ...]
    dacl_aces: tuple[Ace, ...]
    other_aces: tuple[str, ...]
    effective_access: tuple[EffectiveAccess, ...]
    canonical_descriptor_sha256: str

    @classmethod
    def parse(cls, value: Any) -> "SecurityEvidence":
        if not isinstance(value, Mapping):
            raise EvidenceError("security evidence must be an object")
        _exact_keys(value, SECURITY_KEYS, "security evidence")
        if not isinstance(value["dacl_aces"], list) or not isinstance(value["effective_access"], list):
            raise EvidenceError("security ACE and effective access evidence must be lists")
        digest = _string(value["canonical_descriptor_sha256"], "canonical_descriptor_sha256")
        expected_digest = hashlib.sha256(_security_canonical_payload(value)).hexdigest()
        result = cls(_string(value["owner_sid"], "security.owner_sid"),
                     _boolean(value["dacl_protected"], "security.dacl_protected"),
                     _strings(value["inherited_aces"], "security.inherited_aces"),
                     tuple(Ace.parse(item) for item in value["dacl_aces"]),
                     _strings(value["other_aces"], "security.other_aces"),
                     tuple(EffectiveAccess.parse(item) for item in value["effective_access"]), digest)
        if (result.owner_sid != "S-1-5-18" or not result.dacl_protected or result.inherited_aces or
                result.dacl_aces != EXPECTED_ACES or result.other_aces or
                result.effective_access != EXPECTED_EFFECTIVE_ACCESS or
                not SHA256_RE.fullmatch(digest) or digest != expected_digest):
            raise EvidenceError("security evidence does not match the exact protected descriptor")
        return result


@dataclass(frozen=True, order=True)
class ProtectedObjectEvidence:
    role: str
    observed_path: str
    file_id: str
    reparse: bool
    case_sensitive: bool
    security: SecurityEvidence

    @classmethod
    def parse(cls, value: Any) -> "ProtectedObjectEvidence":
        if not isinstance(value, Mapping):
            raise EvidenceError("protected object must be an object")
        _exact_keys(value, frozenset({"role", "observed_path", "file_id", "reparse", "case_sensitive", "security"}),
                    "protected object")
        result = cls(_string(value["role"], "protected_object.role"),
                     _string(value["observed_path"], "protected_object.observed_path"),
                     _string(value["file_id"], "protected_object.file_id"),
                     _boolean(value["reparse"], "protected_object.reparse"),
                     _boolean(value["case_sensitive"], "protected_object.case_sensitive"),
                     SecurityEvidence.parse(value["security"]))
        _file_id_parts(result.file_id, "protected_object.file_id")
        if result.reparse or result.case_sensitive:
            raise EvidenceError("protected object identity/reparse/case evidence is invalid")
        return result


PROFILE_KEYS = frozenset({"profile_id", "os_family", "os_arch", "windows_build", "sdk_version",
    "publisher_service_sid", "service_sid_type", "anchor_creation", "consumer_grants",
    "untrusted_mutating_rights", "covered_objects", "observer_provenance",
    "handle_provenance", "anchor_preexisting", "handles_inheritable", "handles_duplicated_outside_service",
    "volume_name", "volume_serial", "volume_information_serial", "filesystem_name",
    "maximum_component_length", "filesystem_flags", "remote_protocol", "remote_protocol_major",
    "remote_protocol_minor", "remote_protocol_revision", "remote_protocol_flags", "protected_objects",
    "ancestors_revalidated", "destination_name", "destination_open_result", "replace_if_exists",
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
    consumer_grants: tuple[str, ...]
    untrusted_mutating_rights: tuple[str, ...]
    covered_objects: tuple[str, ...]
    observer_provenance: str
    handle_provenance: str
    anchor_preexisting: bool
    handles_inheritable: bool
    handles_duplicated_outside_service: bool
    volume_name: str
    volume_serial: str
    volume_information_serial: str
    filesystem_name: str
    maximum_component_length: int
    filesystem_flags: tuple[str, ...]
    remote_protocol: int
    remote_protocol_major: int
    remote_protocol_minor: int
    remote_protocol_revision: int
    remote_protocol_flags: int
    protected_objects: tuple[ProtectedObjectEvidence, ...]
    ancestors_revalidated: bool
    destination_name: str
    destination_open_result: str
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
        if not isinstance(value["protected_objects"], list):
            raise EvidenceError("protected_objects must be a list")
        result = cls(
            _string(value["profile_id"], "profile_id"), _string(value["os_family"], "os_family"),
            _string(value["os_arch"], "os_arch"), _integer(value["windows_build"], "windows_build"),
            _string(value["sdk_version"], "sdk_version"), _string(value["publisher_service_sid"], "publisher_service_sid"),
            _string(value["service_sid_type"], "service_sid_type"), _string(value["anchor_creation"], "anchor_creation"),
            _strings(value["consumer_grants"], "consumer_grants"),
            _strings(value["untrusted_mutating_rights"], "untrusted_mutating_rights"),
            _strings(value["covered_objects"], "covered_objects"),
            _string(value["observer_provenance"], "observer_provenance"),
            _string(value["handle_provenance"], "handle_provenance"),
            _boolean(value["anchor_preexisting"], "anchor_preexisting"),
            _boolean(value["handles_inheritable"], "handles_inheritable"),
            _boolean(value["handles_duplicated_outside_service"], "handles_duplicated_outside_service"),
            _string(value["volume_name"], "volume_name"), _string(value["volume_serial"], "volume_serial"),
            _string(value["volume_information_serial"], "volume_information_serial"),
            _string(value["filesystem_name"], "filesystem_name"),
            _integer(value["maximum_component_length"], "maximum_component_length", 1),
            _strings(value["filesystem_flags"], "filesystem_flags"),
            _integer(value["remote_protocol"], "remote_protocol"),
            _integer(value["remote_protocol_major"], "remote_protocol_major"),
            _integer(value["remote_protocol_minor"], "remote_protocol_minor"),
            _integer(value["remote_protocol_revision"], "remote_protocol_revision"),
            _integer(value["remote_protocol_flags"], "remote_protocol_flags"),
            tuple(ProtectedObjectEvidence.parse(x) for x in value["protected_objects"]),
            _boolean(value["ancestors_revalidated"], "ancestors_revalidated"),
            _string(value["destination_name"], "destination_name"),
            _string(value["destination_open_result"], "destination_open_result"),
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
        anchor_roles = ("staging_root", "destination_parent", "state_anchor", "journal_anchor")
        roles = tuple(item.role for item in self.protected_objects)
        expected_ancestor_roles = tuple(f"ancestor:{index}" for index in range(max(0, len(roles) - len(anchor_roles))))
        object_ids = tuple(item.file_id for item in self.protected_objects)
        rejected = (self.profile_id != PROFILE_ID or self.os_family != "Windows NT" or self.os_arch != "x64" or
            self.windows_build < 17763 or self.sdk_version != "10.0.17763.0" or
            self.publisher_service_sid != SERVICE_SID or self.service_sid_type != "SERVICE_SID_TYPE_RESTRICTED" or
            self.anchor_creation != "atomic_protected_from_inception" or
            bool(self.consumer_grants) or bool(self.untrusted_mutating_rights) or
            self.covered_objects != EXPECTED_COVERED_OBJECTS or
            self.observer_provenance != "independent_observer_same_handle" or
            self.handle_provenance != "service_created_from_inception" or self.anchor_preexisting or
            self.handles_inheritable or self.handles_duplicated_outside_service or
            not VOLUME_NAME_RE.fullmatch(self.volume_name) or not VOLUME_SERIAL_RE.fullmatch(self.volume_serial) or
            not re.fullmatch(r"[0-9a-f]{8}", self.volume_information_serial) or
            self.volume_serial != "00000000" + self.volume_information_serial or self.filesystem_name != "NTFS" or
            self.maximum_component_length != MAX_COMPONENT_UTF16_UNITS or self.filesystem_flags != EXPECTED_FILESYSTEM_FLAGS or
            any((self.remote_protocol, self.remote_protocol_major, self.remote_protocol_minor,
                 self.remote_protocol_revision, self.remote_protocol_flags)) or
            len(roles) <= len(anchor_roles) or roles[:len(anchor_roles)] != anchor_roles or
            roles[len(anchor_roles):] != expected_ancestor_roles or
            any(_file_id_parts(file_id, "protected object file_id")[0] != self.volume_serial
                                                 for file_id in object_ids) or
            not self.ancestors_revalidated or self.destination_open_result != "ERROR_FILE_NOT_FOUND" or
            self.replace_if_exists or self.observation_apis != EXPECTED_APIS or
            self.closure_entry_count > MAX_CLOSURE_ENTRIES or self.closure_max_depth > MAX_CLOSURE_DEPTH or
            self.max_component_utf16_units != self.maximum_component_length or
            self.serialized_evidence_bytes > MAX_EVIDENCE_BYTES or self.total_content_bytes > MAX_CONTENT_BYTES)
        try:
            _validate_component(self.destination_name)
        except EvidenceError:
            rejected = True
        if rejected:
            raise EvidenceError("profile evidence does not satisfy the closed profile")


def _validate_component(component: str) -> None:
    if not component or component in {".", ".."} or component[-1] in {".", " "}:
        raise EvidenceError("Windows path component is empty, relative, or has a forbidden suffix")
    if unicodedata.normalize("NFC", component) != component:
        raise EvidenceError("Windows path component is not canonically normalized")
    if any(character in FORBIDDEN_COMPONENT_CHARACTERS or ord(character) < 32 for character in component):
        raise EvidenceError("Windows path component contains a forbidden character")
    if component.split(".", 1)[0].upper() in RESERVED_DEVICE_NAMES:
        raise EvidenceError("Windows path component is a reserved DOS device name")
    try:
        units = len(component.encode("utf-16-le")) // 2
    except UnicodeEncodeError as exc:
        raise EvidenceError("Windows path component is not valid Unicode") from exc
    if units > MAX_COMPONENT_UTF16_UNITS:
        raise EvidenceError("Windows path component exceeds the NTFS limit")


def _validate_relative_path(path: str) -> tuple[str, ...]:
    if (path.startswith(("/", "\\")) or "\\" in path or re.match(r"^[A-Za-z]:", path) or
            path.startswith(("//", "\\\\", "\\?\\", "\\.\\"))):
        raise EvidenceError("path must be an unambiguous canonical relative path")
    parts = tuple(path.split("/"))
    if len(parts) > MAX_CLOSURE_DEPTH:
        raise EvidenceError("closure depth exceeds profile limit")
    for part in parts:
        _validate_component(part)
    return parts


ENTRY_KEYS = frozenset({"relative_path", "type", "file_id", "content_sha256", "size", "attributes",
                        "security", "link_count", "streams", "reparse", "reparse_tag"})


@dataclass(frozen=True, order=True)
class ClosureEntry:
    relative_path: str
    entry_type: EntryType
    file_id: str
    content_sha256: str | None
    size: int
    attributes: tuple[str, ...]
    security: SecurityEvidence
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
                     SecurityEvidence.parse(value["security"]),
                     _integer(value["link_count"], "link_count", 1), _strings(value["streams"], "streams"),
                     _boolean(value["reparse"], "reparse"), tag)
        result.validate()
        return result

    def validate(self) -> None:
        _file_id_parts(self.file_id, "closure file_id")
        attribute_reparse = "REPARSE_POINT" in self.attributes
        if attribute_reparse != self.reparse or ((self.reparse_tag is not None) != self.reparse):
            raise EvidenceError("reparse attribute, flag, and tag are inconsistent")
        if self.reparse and (self.reparse_tag is None or self.reparse_tag <= 0):
            raise EvidenceError("reparse tag must be nonzero when present")
        if self.reparse or self.link_count != 1:
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
        _validate_relative_path(self.relative_path)


def _parse_closure(root_value: Any, entries_value: Any,
                   volume_serial: str) -> tuple[ClosureEntry, tuple[ClosureEntry, ...]]:
    root = ClosureEntry.parse(root_value)
    if root.relative_path != "." or not isinstance(entries_value, list):
        raise EvidenceError("root/closure shape invalid")
    entries = tuple(ClosureEntry.parse(item) for item in entries_value)
    if len(entries) > MAX_CLOSURE_ENTRIES:
        raise EvidenceError("closure count exceeds profile limit")
    paths = tuple(item.relative_path for item in entries)
    if paths != tuple(sorted(paths, key=str.casefold)) or len({x.casefold() for x in paths}) != len(paths):
        raise EvidenceError("closure paths must be unique and case-insensitively sorted")
    if _file_id_parts(root.file_id, "root file_id")[0] != volume_serial or any(
            _file_id_parts(item.file_id, "closure file_id")[0] != volume_serial for item in entries):
        raise EvidenceError("root or descendant is on a different volume")
    by_path = {item.relative_path.casefold(): item for item in entries}
    for entry in entries:
        parts = entry.relative_path.split("/")
        for end in range(1, len(parts)):
            parent = by_path.get("/".join(parts[:end]).casefold())
            if parent is None or parent.entry_type != EntryType.DIRECTORY:
                raise EvidenceError("every intermediate parent must be a closure directory")
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
    "confirm_visible": frozenset({"action", "destination_name", "root", "closure"}),
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
        assert state.profile is not None
        try:
            root, closure = _parse_closure(event["root"], event["closure"], state.profile.volume_serial)
        except EvidenceError:
            return _retained(state, "sealed_evidence_refused")
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
        assert state.profile is not None
        try:
            destination_name = _string(event["destination_name"], "visible destination_name")
            _validate_component(destination_name)
            if destination_name != state.profile.destination_name:
                raise EvidenceError("visible destination component differs from prepared component")
            root, closure = _parse_closure(event["root"], event["closure"], state.profile.volume_serial)
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


def _security_projection(security: SecurityEvidence) -> dict[str, Any]:
    return {"owner_sid": security.owner_sid, "dacl_protected": security.dacl_protected,
            "inherited_aces": list(security.inherited_aces),
            "dacl_aces": [{"principal": ace.principal, "type": ace.ace_type, "rights": list(ace.rights)}
                          for ace in security.dacl_aces],
            "other_aces": list(security.other_aces),
            "effective_access": [{"principal": access.principal, "rights": list(access.rights)}
                                 for access in security.effective_access],
            "canonical_descriptor_sha256": security.canonical_descriptor_sha256}


def _entry_projection(entry: ClosureEntry) -> dict[str, Any]:
    return {"relative_path": entry.relative_path, "type": entry.entry_type.value, "file_id": entry.file_id,
            "content_sha256": entry.content_sha256, "size": entry.size, "attributes": list(entry.attributes),
            "security": _security_projection(entry.security), "link_count": entry.link_count,
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
