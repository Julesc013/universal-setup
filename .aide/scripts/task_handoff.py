"""Finite task-record interchange. Pure data codec; no IO or execution authority."""
import hashlib
import json
import math
import re
import unicodedata

SCHEMA = "aide.task-handoff.v1"
MAX_BUNDLE = 1048576
MAX_RECORD = 131072
REQUIRED = {"record_sha256", "observational_only"}
NAMES = ("task.yaml", "status.yaml", "ExecPlan.md")
REQUEST_SCHEMA = "aide.task-handoff.v2"
RESULT_SCHEMA = "aide.task-handoff-result.v1"
REQUEST_REQUIRED = REQUIRED | {"selected_input_sha256"}
RESULT_REQUIRED = REQUIRED | {"request_binding", "candidate_only"}
MAX_INPUTS = 8


def record_paths(task_id):
    if (not isinstance(task_id, str) or len(task_id) > 160
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", task_id)
            or task_id.endswith(".")):
        raise ValueError("invalid_task_id")
    return [f".aide/queue/{task_id}/{name}" for name in NAMES]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(data):
    if data is None:
        return {"state": "missing", "text": None, "sha256": None}
    if not isinstance(data, bytes) or len(data) > MAX_RECORD:
        raise ValueError("record_too_large_or_invalid")
    return {"state": "captured", "text": data.decode("utf-8"), "sha256": sha(data)}


def _finite(value, depth=0):
    if depth > 16:
        raise ValueError("bundle_too_deep")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("invalid_json_key")
            _finite(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _finite(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite_json")


def validate(bundle):
    _finite(bundle)
    if isinstance(bundle, dict) and bundle.get("schema_version") == REQUEST_SCHEMA:
        if not features_match(bundle.get("required_features"), REQUEST_REQUIRED):
            raise ValueError("unsupported_required_features")
        validate({**bundle, "schema_version": SCHEMA, "required_features": sorted(REQUIRED)})
        inputs = bundle.get("inputs")
        if not isinstance(inputs, dict):
            raise ValueError("invalid_selected_inputs")
        input_paths(list(inputs))
        for item in inputs.values():
            captured_record(item)
        return bundle
    if isinstance(bundle, dict) and bundle.get("schema_version") == RESULT_SCHEMA:
        return validate_result(bundle)
    if not isinstance(bundle, dict) or bundle.get("schema_version") != SCHEMA:
        raise ValueError("unsupported_handoff_schema")
    features = bundle.get("required_features")
    if (not isinstance(features, list) or not all(isinstance(x, str) for x in features)
            or len(features) != len(set(features)) or set(features) != REQUIRED):
        raise ValueError("unsupported_required_features")
    if bundle.get("read_only") is not True or bundle.get("execution_admitted") is not False:
        raise ValueError("invalid_handoff_boundary")
    paths = record_paths(bundle.get("task_id"))
    records = bundle.get("records")
    if not isinstance(records, dict) or set(records) != set(paths):
        raise ValueError("invalid_record_set")
    for path, item in records.items():
        if not isinstance(item, dict) or not {"state", "text", "sha256"} <= set(item):
            raise ValueError("invalid_record")
        if item.get("state") == "missing":
            if path == paths[0] or item.get("text") is not None or item.get("sha256") is not None:
                raise ValueError("invalid_missing_record")
        elif item.get("state") == "captured":
            text = item.get("text")
            if not isinstance(text, str):
                raise ValueError("invalid_record_text")
            raw = text.encode("utf-8")
            if len(raw) > MAX_RECORD or item.get("sha256") != sha(raw):
                raise ValueError("record_digest_or_size_mismatch")
        else:
            raise ValueError("invalid_record_state")
    source = bundle.get("source")
    if not isinstance(source, dict) or not isinstance(bundle.get("continuation"), dict):
        raise ValueError("invalid_provenance_or_observation")
    commit = source.get("git_head")
    if commit is not None and (not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit)):
        raise ValueError("invalid_source_commit")
    return bundle


def input_paths(paths):
    """Portable names identify inputs; they are never extraction destinations."""
    if (not isinstance(paths, list) or not 1 <= len(paths) <= MAX_INPUTS
            or not all(isinstance(path, str) for path in paths)):
        raise ValueError("invalid_selected_inputs")
    if len({path.casefold() for path in paths}) != len(paths):
        raise ValueError("ambiguous_selected_inputs")
    for path in paths:
        if (len(path.encode("utf-8")) > 256 or unicodedata.normalize("NFC", path) != path
                or re.search(r'[\x00-\x1f\x7f<>:"\\|?*]', path)):
            raise ValueError("nonportable_input_path")
        for part in path.split("/"):
            if (part in ("", ".", "..") or part.endswith((".", " "))
                    or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", part.split(".")[0])):
                raise ValueError("nonportable_input_path")
    return paths


def captured_record(item):
    if (not isinstance(item, dict) or item.get("state") != "captured"
            or not isinstance(item.get("text"), str)):
        raise ValueError("invalid_captured_record")
    raw = item["text"].encode("utf-8")
    if len(raw) > MAX_RECORD or item.get("sha256") != sha(raw):
        raise ValueError("record_digest_or_size_mismatch")


def features_match(value, expected):
    return (isinstance(value, list) and all(isinstance(item, str) for item in value)
            and len(value) == len(set(value)) and set(value) == expected)


def validate_result(bundle):
    if (not features_match(bundle.get("required_features"), RESULT_REQUIRED)
            or bundle.get("read_only") is not True
            or bundle.get("execution_admitted") is not False
            or bundle.get("accepted") is not False):
        raise ValueError("invalid_result_boundary")
    record_paths(bundle.get("task_id"))
    record_paths(bundle.get("attempt_id"))
    if (not isinstance(bundle.get("request_sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", bundle["request_sha256"])
            or not isinstance(bundle.get("source"), dict)
            or bundle.get("outcome") not in ("submitted", "failed", "interrupted")):
        raise ValueError("invalid_result_identity_or_outcome")
    artifacts = bundle.get("artifacts")
    if (not isinstance(artifacts, dict) or "report" not in artifacts
            or not set(artifacts) <= {"report", "patch", "checks"}):
        raise ValueError("invalid_result_artifacts")
    for item in artifacts.values():
        captured_record(item)
    if not artifacts["report"]["text"].strip():
        raise ValueError("result_report_empty")
    return bundle


def bind_result(result, request, request_sha256):
    validate(result)
    validate(request)
    if (request["schema_version"] != REQUEST_SCHEMA or result["schema_version"] != RESULT_SCHEMA
            or result["request_sha256"] != request_sha256
            or result["task_id"] != request["task_id"] or result["source"] != request["source"]):
        raise ValueError("result_request_mismatch")
    return result


def encode(bundle):
    validate(bundle)
    data = (json.dumps(bundle, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("ascii")
    if len(data) > MAX_BUNDLE:
        raise ValueError("bundle_too_large")
    return data


def decode(data, expected_sha256):
    if not isinstance(data, bytes) or len(data) > MAX_BUNDLE:
        raise ValueError("bundle_too_large_or_invalid")
    if (not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            or sha(data) != expected_sha256):
        raise ValueError("bundle_digest_mismatch")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    try:
        bundle = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
        return validate(bundle)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid_handoff_encoding_or_depth") from exc


def compare(bundle, local):
    """Local observations are bytes, None (missing), or an unavailable reason."""
    validate(bundle)
    return compare_records(bundle["records"], local, record_paths(bundle["task_id"]))


def compare_records(records, local, paths=None):
    result = []
    for path in paths if paths is not None else sorted(records):
        captured, observed = records[path], local[path]
        if isinstance(observed, str):
            state = "unsafe_or_unreadable"
        elif observed is None:
            state = "missing" if captured["state"] == "captured" else "missing_in_both"
        elif captured["state"] == "missing":
            state = "not_captured"
        else:
            state = "matching" if sha(observed) == captured["sha256"] else "changed"
        result.append({"path": path, "comparison": state,
                       "captured_sha256": captured["sha256"],
                       "local_sha256": sha(observed) if isinstance(observed, bytes) else None,
                       "reason": observed if isinstance(observed, str) else None})
    return result
