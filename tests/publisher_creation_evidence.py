# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent read-only bindings for the native candidate's creation graph.

This checks a retained successful-create observation, not global capability
exclusion, an atomic snapshot, historical events absent from the record or
publication-profile qualification. No Windows endpoint effects are performed.
"""
import hashlib
import json
import re
import struct

from publication_authority_reference import _validate_relative_path


class CreationEvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CreationEvidenceError(message)


def closed(value, keys, message):
    require(isinstance(value, dict) and set(value) == set(keys), message)


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def creation_graph(anchors, tree):
    chain = anchors["chain"]
    require(isinstance(chain, list) and len(chain) == 1 and chain[0]["component"] == "publication",
            "creation graph publication chain differs")
    boundary = anchors["boundary"]["file_id"]
    publication = chain[0]["object"]["file_id"]
    root = tree["root"]["file_id"]
    rows = {}

    def add(identity, parent, name, directory):
        require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{16}:[0-9a-f]{32}", value)
                    for value in (identity, parent)) and identity != parent and
                identity != boundary and identity[:16] == parent[:16] and identity not in rows,
                "creation graph object/parent identity differs")
        try:
            require(len(_validate_relative_path(name)) == 1, "creation graph name is not one component")
        except ValueError as error:
            raise CreationEvidenceError("creation graph component differs") from error
        rows[identity] = {"file_id": identity, "parent_file_id": parent, "name": name,
                          "kind": "directory" if directory else "file"}

    add(publication, boundary, "publication", True)
    for key, name in (("staging", "staging"), ("destination_parent", "destination"),
                      ("state", "state"), ("journal", "journal")):
        add(anchors[key]["file_id"], publication, name, True)
    add(root, anchors["staging"]["file_id"], "candidate", True)
    descendants = tree["descendants"]
    require(isinstance(descendants, list) and len(descendants) <= 200000, "creation graph count differs")
    paths, folded = {}, set()
    for entry in descendants:
        require(isinstance(entry["relative_path"], str), "creation graph path is not text")
        path = entry["relative_path"].replace("\\", "/")
        try:
            _validate_relative_path(path)
        except ValueError as error:
            raise CreationEvidenceError("creation graph descendant path differs") from error
        require(path.casefold() not in folded, "creation graph repeats a canonical path")
        attributes = entry["object"]["attributes"]
        require(type(attributes) is int and 0 <= attributes <= 0xFFFFFFFF, "creation graph attributes differ")
        paths[path] = (entry["object"]["file_id"], bool(attributes & 0x10))
        folded.add(path.casefold())
    for path, (identity, directory) in paths.items():
        parts = path.rsplit("/", 1)
        parent = root
        if len(parts) == 2:
            require(parts[0] in paths and paths[parts[0]][1], "creation graph intermediate directory absent")
            parent = paths[parts[0]][0]
        add(identity, parent, parts[-1], directory)
    return [rows[key] for key in sorted(rows)]


def descriptor_binding(hex_bytes, expected_sid):
    require(isinstance(hex_bytes, str) and re.fullmatch(r"(?:[0-9a-f]{2}){20,65536}", hex_bytes),
            "creation descriptor is not bounded canonical bytes")
    raw = bytes.fromhex(hex_bytes)
    revision, reserved, control, owner, group, sacl, dacl = struct.unpack_from("<BBHLLLL", raw)
    require((revision, reserved, control, group, sacl) == (1, 0, 0x9004, 0, 0) and owner >= 20 and dacl >= 20,
            "creation descriptor header is not exact protected owner/DACL")

    def read_sid(offset, end):
        require(20 <= offset <= end - 8, "creation descriptor SID offset differs")
        sid_revision, count = raw[offset:offset + 2]
        length = 8 + 4 * count
        require(sid_revision == 1 and 1 <= count <= 15 and offset + length <= end,
                "creation descriptor SID shape differs")
        authority = int.from_bytes(raw[offset + 2:offset + 8], "big")
        subauthorities = struct.unpack_from("<" + "L" * count, raw, offset + 8)
        return "S-1-" + str(authority) + "-" + "-".join(map(str, subauthorities)), length

    owner_sid, owner_size = read_sid(owner, len(raw))
    require(owner_sid == "S-1-5-18" and dacl <= len(raw) - 8, "creation descriptor owner/ACL differs")
    acl_revision, acl_reserved, acl_size, ace_count, acl_reserved2 = struct.unpack_from("<BBHHH", raw, dacl)
    acl_end = dacl + acl_size
    require((acl_revision, acl_reserved, ace_count, acl_reserved2) == (2, 0, 2, 0) and
            acl_size >= 8 and acl_end <= len(raw), "creation descriptor ACL header differs")
    cursor = dacl + 8
    for expected in ("S-1-5-18", expected_sid):
        require(cursor <= acl_end - 8, "creation descriptor ACE is truncated")
        ace_type, flags, size, mask = struct.unpack_from("<BBHL", raw, cursor)
        require(ace_type == 0 and flags == 0 and size >= 16 and cursor + size <= acl_end and mask == 0x1F01FF,
                "creation descriptor ACE differs")
        actual_sid, sid_size = read_sid(cursor + 8, cursor + size)
        require(actual_sid == expected and size == 8 + sid_size, "creation descriptor ACE SID differs")
        cursor += size
    require(cursor == acl_end, "creation descriptor ACL has extra bytes")
    segments = sorted(((owner, owner + owner_size), (dacl, acl_end)))
    require(segments[0][0] == 20 and segments[0][1] == segments[1][0] and segments[1][1] == len(raw),
            "creation descriptor offsets overlap, omit or append bytes")
    return hashlib.sha256(raw).hexdigest()


CALL_PROFILE = {"api": "NtCreateFile", "create_disposition": 2, "creation_result": 2,
    "ntstatus": 0, "object_attribute_flags": 0x40, "share_access": 7,
    "directory_create_options": 0x00200021, "file_create_options": 0x00200062,
    "directory_file_attributes": 0x10, "file_file_attributes": 0x80,
    "directory_access_mask": 0x1300A7, "file_access_mask": 0x130183}
CREATOR_KEYS = frozenset({"service_name", "service_sid", "process_id", "token_id",
                          "authentication_id", "modified_id", "token_type"})
CERTIFICATE_KEYS = frozenset({"schema", "scope", "creator", "native_call", "handle_flags",
    "volume_boundary_file_id", "creation_descriptor_sha256", "creation_descriptor_hex",
    "created_object_count", "created_graph_sha256"})


def reconcile_creation(certificate, anchors, tree, execution):
    closed(certificate, CERTIFICATE_KEYS, "creation certificate keys differ")
    require(certificate["schema"] == "usk.publisher.creation_observation.v1" and
            certificate["scope"] == "successful_service_file_create_calls_to_bound_graph",
            "creation certificate schema/scope differs")
    closed(certificate["creator"], CREATOR_KEYS, "creation creator keys differ")
    require(certificate["creator"] == {key: execution["service"][key] for key in CREATOR_KEYS},
            "creation creator differs from original prepared worker")
    require(type(certificate["creator"]["process_id"]) is int and
            type(certificate["creator"]["token_type"]) is int, "creation creator integer types differ")
    closed(certificate["native_call"], CALL_PROFILE, "creation call profile keys differ")
    require(all(type(certificate["native_call"][key]) is type(expected) and
                certificate["native_call"][key] == expected for key, expected in CALL_PROFILE.items()),
            "creation native call arguments or result differ")
    require(type(certificate["handle_flags"]) is int and certificate["handle_flags"] == 0 and
            certificate["volume_boundary_file_id"] == anchors["boundary"]["file_id"],
            "creation flags or boundary differ")
    digest = descriptor_binding(certificate["creation_descriptor_hex"], execution["service"]["service_sid"])
    require(certificate["creation_descriptor_sha256"] == digest, "creation requested descriptor digest differs")
    graph = creation_graph(anchors, tree)
    graph_sha = canonical_sha(graph)
    require(type(certificate["created_object_count"]) is int and certificate["created_object_count"] == len(graph) and
            certificate["created_graph_sha256"] == graph_sha, "creation certificate differs from sealed graph")
    return {"schema": "usk.publisher_creation_reconciliation.v1", "status": "bindings_consistent",
            "created_object_count": len(graph), "created_graph_sha256": graph_sha,
            "creator_process_id": certificate["creator"]["process_id"],
            "scope": "retained_successful_create_graph_binding", "profile_qualified": False}
