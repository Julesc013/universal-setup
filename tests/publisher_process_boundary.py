# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Read-only validation of a publisher worker's retained process owner/DACL.

The SCM identity and token groups must already have been independently bound.
This checks process access policy; it does not enumerate existing capabilities
or establish that arbitrary processes have never received a handle.
"""
import re


class ProcessBoundaryError(ValueError):
    pass


QUERY_RIGHTS = 0x00100000 | 0x00020000 | 0x00000400 | 0x00001000
KEYS = frozenset({"schema", "scope", "process_id", "owner_sid", "dacl_present",
                  "dacl_protected", "dacl_aces"})


def require(condition, message):
    if not condition:
        raise ProcessBoundaryError(message)


def sid(value):
    if not isinstance(value, str) or not 5 <= len(value) <= 184:
        return False
    if re.fullmatch(r"S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}", value) is None:
        return False
    parts = value.split("-")
    return int(parts[2]) <= 0xFFFFFFFFFFFF and all(int(part) <= 0xFFFFFFFF for part in parts[3:])


def validate_process_boundary(value, process_id, service_sid, process_groups):
    require(isinstance(value, dict) and set(value) == KEYS and
            value["schema"] == "usk.publisher_process_boundary.v1" and
            value["scope"] == "stored_current_process_owner_dacl" and
            type(process_id) is int and 0 < process_id <= 0xFFFFFFFF and
            type(value["process_id"]) is int and value["process_id"] == process_id and
            value["dacl_present"] is True and type(value["dacl_protected"]) is bool and
            sid(service_sid) and isinstance(process_groups, list) and len(process_groups) <= 4096,
            "process boundary schema or independent process context differs")
    trusted = {"S-1-5-18", "S-1-5-32-544", service_sid}
    logons = []
    for group in process_groups:
        require(isinstance(group, dict) and set(group) == {"sid", "attributes"} and sid(group["sid"]) and
                type(group["attributes"]) is int and 0 <= group["attributes"] <= 0xFFFFFFFF,
                "process boundary token group context differs")
        attributes = group["attributes"]
        if attributes & 0xC0000000 != 0xC0000000:
            continue
        require(group["sid"].startswith("S-1-5-5-") and len(group["sid"].split("-")) == 6 and
                attributes & 4 and not attributes & 16, "process boundary publisher logon SID differs")
        logons.append(group["sid"])
    require(len(logons) <= 1, "process boundary has multiple publisher logon identities")
    trusted.update(logons)
    require(sid(value["owner_sid"]) and value["owner_sid"] in trusted,
            "process owner can grant an untrusted process capability")
    aces = value["dacl_aces"]
    require(isinstance(aces, list) and len(aces) <= 4096, "process boundary DACL bound differs")
    for ace in aces:
        require(isinstance(ace, dict) and set(ace) == {"type", "flags", "access_mask", "sid"} and
                type(ace["type"]) is int and ace["type"] in (0, 1) and
                type(ace["flags"]) is int and ace["flags"] == 0 and sid(ace["sid"]) and
                type(ace["access_mask"]) is int and 0 <= ace["access_mask"] <= 0xFFFFFFFF and
                (ace["type"] == 1 or ace["sid"] in trusted or ace["access_mask"] & ~QUERY_RIGHTS == 0),
                "process DACL grants an outside capability or has unsupported ACE facts")
    return value
