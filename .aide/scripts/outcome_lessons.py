"""Source-linked lesson selection over outcome metadata; no IO or authority."""
import hashlib
import json
import re
from collections import Counter

SCHEMA = "aide.outcome-lesson.v1"
FEATURES = {"revision_chain", "source_sha256", "advisory_only"}
MAX_LEDGER = 1048576
MAX_EVIDENCE = 131072


def relative_path(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 512
            or any(ord(c) < 32 for c in value) or "\\" in value
            or any(c in value for c in ":*?[]")
            or any(p in ("", ".", "..") or p.endswith((".", " "))
                   for p in value.split("/"))):
        raise ValueError("lesson path must be an exact canonical relative path")
    return value


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def validate(lesson):
    if not isinstance(lesson, dict) or lesson.get("schema_version") != SCHEMA:
        raise ValueError("unsupported lesson schema")
    features = lesson.get("required_features")
    if (not isinstance(features, list) or not all(isinstance(x, str) for x in features)
            or len(features) != len(FEATURES) or set(features) != FEATURES):
        raise ValueError("unsupported required lesson semantics")
    if not isinstance(lesson.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", lesson["id"]):
        raise ValueError("invalid lesson id")
    if type(lesson.get("revision")) is not int or not 1 <= lesson["revision"] <= 256:
        raise ValueError("invalid lesson revision")
    if lesson.get("state") not in ("active", "retired"):
        raise ValueError("invalid lesson state")
    summary = lesson.get("summary")
    if (not isinstance(summary, str) or not summary.strip() or len(summary) > 2048
            or any(ord(c) < 32 for c in summary)):
        raise ValueError("invalid lesson summary")
    paths = lesson.get("applies_to")
    if not isinstance(paths, list) or not 1 <= len(paths) <= 16:
        raise ValueError("lesson requires bounded applicability paths")
    paths = [relative_path(p) for p in paths]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate lesson applicability path")
    evidence = lesson.get("evidence")
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 8:
        raise ValueError("lesson requires bounded source evidence")
    seen = set()
    for item in evidence:
        if (not isinstance(item, dict) or not isinstance(item.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("invalid lesson evidence digest")
        path = relative_path(item.get("path"))
        if path in seen:
            raise ValueError("duplicate lesson evidence path")
        seen.add(path)
    previous = lesson.get("supersedes")
    if ("supersedes" not in lesson or (lesson["revision"] == 1 and previous is not None)
            or (lesson["revision"] > 1 and (not isinstance(previous, str)
                or not re.fullmatch(r"[0-9a-f]{64}", previous)))):
        raise ValueError("invalid lesson predecessor")
    canonical_digest(lesson)  # Optional metadata participates in revision identity.


def latest_revisions(records):
    groups, count = {}, 0
    identities = Counter(tuple(record[k] for k in ("run_id", "phase", "source"))
                         for record in records)
    for record in records:
        if "lesson" not in record:
            continue
        count += 1
        if count > 256:
            raise ValueError("lesson revision limit exceeded")
        identity = tuple(record[k] for k in ("run_id", "phase", "source"))
        if identities[identity] != 1:
            raise ValueError("ambiguous lesson outcome identity")
        lesson = record["lesson"]
        validate(lesson)
        versions = groups.setdefault(lesson["id"], {})
        if lesson["revision"] in versions:
            raise ValueError("duplicate lesson revision")
        versions[lesson["revision"]] = (lesson, identity)
    latest = []
    for name in sorted(groups):
        versions = groups[name]
        if sorted(versions) != list(range(1, len(versions) + 1)):
            raise ValueError("incomplete lesson revision chain")
        previous = None
        for revision in sorted(versions):
            lesson, identity = versions[revision]
            if lesson["supersedes"] != previous:
                raise ValueError("lesson predecessor digest mismatch")
            previous = canonical_digest(lesson)
        latest.append((lesson, identity, previous))
    return latest


def select(records, path, observe):
    """Observe only latest active exact matches; never fall back to older advice."""
    relative_path(path)
    selected, excluded = [], []
    for lesson, identity, digest in latest_revisions(records):
        item = {"id": lesson["id"], "revision": lesson["revision"],
                "lesson_sha256": digest, "outcome_identity": list(identity)}
        if lesson["state"] == "retired":
            item["reason"] = "retired"
        elif path not in lesson["applies_to"]:
            item["reason"] = "out_of_scope"
        else:
            observations = []
            for evidence in lesson["evidence"]:
                state, actual = observe(evidence["path"])
                observations.append({"path": evidence["path"], "expected_sha256": evidence["sha256"],
                                     "observed_sha256": actual,
                                     "state": ("matching" if actual == evidence["sha256"] else "stale")
                                     if state == "observed" else state})
            item["evidence"] = observations
            if all(o["state"] == "matching" for o in observations):
                selected.append({**item, "lesson": lesson, "selection_reason": "exact_path_and_matching_evidence"})
                continue
            item["reason"] = "evidence_not_current"
        excluded.append(item)
    return {"schema_version": "aide.outcome-lessons-view.v1", "path": path,
            "selected": selected, "excluded": excluded, "advisory_only": True,
            "authorship_verified": False, "semantic_correctness_verified": False,
            "execution_admitted": False, "writes": False}
