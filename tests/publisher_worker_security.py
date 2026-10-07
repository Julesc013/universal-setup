# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent closed-record checks of observed primary-token/thread policies.

The caller binds SCM and token identity first. Population snapshots are not an
atomic census, nor evidence of absence of previously exported handles.
"""
import re
from publisher_process_boundary import sid


class WorkerSecurityError(ValueError):
    pass


TOKEN_QUERY_RIGHTS = 0x00020000 | 0x8 | 0x10
THREAD_QUERY_RIGHTS = 0x00100000 | 0x00020000 | 0x40 | 0x800
DEFAULT_QUERY_RIGHTS = 0x00020000
OBJECT_KEYS = {"owner_sid", "dacl_present", "dacl_protected", "dacl_aces"}


def require(condition, diagnostic):
    if not condition:
        raise WorkerSecurityError(diagnostic)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 0xFFFFFFFF


def validate_acl(aces, trusted, query_rights):
    require(isinstance(aces, list) and len(aces) <= 4096, "worker security ACE bound differs")
    for ace in aces:
        require(isinstance(ace, dict) and set(ace) == {"type", "flags", "access_mask", "sid"} and
                type(ace["type"]) is int and ace["type"] in (0, 1) and
                type(ace["flags"]) is int and ace["flags"] == 0 and sid(ace["sid"]) and
                integer(ace["access_mask"]) and (ace["type"] == 1 or ace["sid"] in trusted or
                ace["access_mask"] & ~query_rights == 0), "worker DACL grants an outside capability")


def validate_object(value, trusted, query_rights):
    require(sid(value["owner_sid"]) and value["owner_sid"] in trusted and
            value["dacl_present"] is True and type(value["dacl_protected"]) is bool,
            "worker security owner/DACL differs")
    validate_acl(value["dacl_aces"], trusted, query_rights)


def validate_worker_security(value, service):
    if isinstance(value, dict) and value.get("schema") == "usk.publisher_worker_security.v2":
        return validate_retirement_security(value, service)
    require(isinstance(value, dict) and set(value) == {"schema", "scope", "process_id", "current_thread_id",
            "primary_token", "threads"} and value["schema"] == "usk.publisher_worker_security.v1" and
            value["scope"] == "stored_primary_token_defaults_and_process_thread_owner_dacls" and
            isinstance(service, dict) and integer(service["process_id"], 1) and
            integer(value["process_id"], 1) and value["process_id"] == service["process_id"] and
            sid(service["service_sid"]) and service["token_type"] == 1 and type(service["token_type"]) is int,
            "worker security schema or independent context differs")
    trusted = {"S-1-5-18", "S-1-5-32-544", service["service_sid"]}
    groups = service["process_groups"]
    require(isinstance(groups, list) and len(groups) <= 4096, "worker token group bound differs")
    logons = []
    for group in groups:
        require(isinstance(group, dict) and set(group) == {"sid", "attributes"} and
                sid(group["sid"]) and integer(group["attributes"]), "worker token group differs")
        if group["attributes"] & 0xC0000000 == 0xC0000000:
            require(group["sid"].startswith("S-1-5-5-") and len(group["sid"].split("-")) == 6 and
                    group["attributes"] & 4 and not group["attributes"] & 16,
                    "worker logon identity differs")
            logons.append(group["sid"])
    require(len(logons) <= 1, "worker has multiple logon identities")
    trusted.update(logons)
    primary = value["primary_token"]
    require(isinstance(primary, dict) and set(primary) == OBJECT_KEYS |
            {"token_id", "authentication_id", "modified_id", "default_owner_sid", "default_dacl_aces"},
            "primary-token security keys differ")
    for key in ("token_id", "authentication_id", "modified_id"):
        require(isinstance(service[key], str) and re.fullmatch(r"[0-9a-f]{16}", service[key]) is not None and
                service[key] != "0000000000000000" and primary[key] == service[key],
                "primary-token security identity differs")
    validate_object(primary, trusted, TOKEN_QUERY_RIGHTS)
    require(sid(primary["default_owner_sid"]) and primary["default_owner_sid"] in trusted,
            "token default owner can grant an outside capability")
    validate_acl(primary["default_dacl_aces"], trusted, DEFAULT_QUERY_RIGHTS)
    require(integer(value["current_thread_id"], 1) and isinstance(value["threads"], list) and
            0 < len(value["threads"]) <= 4096, "worker thread closure bound differs")
    previous, found = 0, False
    for thread in value["threads"]:
        require(isinstance(thread, dict) and set(thread) == OBJECT_KEYS | {"thread_id", "creation_time", "thread_impersonating"} and
                thread["thread_impersonating"] is False and
                integer(thread["thread_id"], 1) and thread["thread_id"] > previous and
                isinstance(thread["creation_time"], str) and re.fullmatch(r"[0-9a-f]{16}", thread["creation_time"]) is not None and
                thread["creation_time"] != "0000000000000000", "worker thread identity or order differs")
        validate_object(thread, trusted, THREAD_QUERY_RIGHTS)
        previous = thread["thread_id"]
        found |= previous == value["current_thread_id"]
    require(found, "current worker thread missing from closure")
    return value


def validate_retirement_security(value, service):
    require(set(value) == {"schema", "scope", "process_id", "current_thread_id", "primary_token",
            "threads", "original_baseline", "retired_threads"} and
            value["scope"] == "original_pinned_token_defaults_and_native_thread_retirement_partition",
            "native retirement closed schema differs")
    baseline = value["original_baseline"]
    require(isinstance(baseline, dict) and baseline.get("schema") == "usk.publisher_worker_security.v1",
            "retirement baseline is not the original closed snapshot")
    validate_worker_security(baseline, service)
    live = {key: value[key] for key in ("process_id", "current_thread_id", "primary_token", "threads")}
    live.update(schema=baseline["schema"], scope=baseline["scope"])
    validate_worker_security(live, service)
    require(all(live[key] == baseline[key] for key in ("process_id", "current_thread_id", "primary_token")),
            "retirement changed original non-thread security")
    originals = {thread["thread_id"]: thread for thread in baseline["threads"]}
    partition = set()
    for thread in live["threads"]:
        identity = thread["thread_id"]
        require(identity in originals and identity not in partition and thread == originals[identity],
                "live partition added or changed an original thread")
        partition.add(identity)
    retired = value["retired_threads"]
    require(isinstance(retired, list) and len(retired) <= len(originals), "retirement evidence exceeds original population")
    previous = 0
    for thread in retired:
        require(isinstance(thread, dict) and set(thread) == {"thread_id", "creation_time", "exit_time"},
                "retirement evidence closed keys differ")
        identity, birth, exit_time = thread["thread_id"], thread["creation_time"], thread["exit_time"]
        require(integer(identity, 1) and identity > previous and identity in originals and identity not in partition and
                identity != live["current_thread_id"] and birth == originals[identity]["creation_time"] and
                isinstance(exit_time, str) and re.fullmatch(r"[0-9a-f]{16}", exit_time) is not None and
                exit_time != "0000000000000000" and exit_time >= birth,
                "original retirement identity, native exit or partition differs")
        partition.add(identity)
        previous = identity
    require(partition == set(originals), "original thread partition is incomplete")
    return value


def validate_worker_continuity(earlier, later):
    """Both records must first pass independently bound native-policy checks."""
    if earlier["schema"] != "usk.publisher_worker_security.v2":
        require(earlier == later, "legacy token/default/thread security changed")
        return
    require(later["schema"] == "usk.publisher_worker_security.v2" and
            all(earlier[key] == later[key] for key in
                ("schema", "scope", "process_id", "current_thread_id", "primary_token", "original_baseline")),
            "frozen original security binding changed")
    retired = {thread["thread_id"]: thread for thread in later["retired_threads"]}
    require(len(retired) == len(later["retired_threads"]) and
            all(retired.get(thread["thread_id"]) == thread for thread in earlier["retired_threads"]),
            "original retirement disappeared, revived or changed exit")
