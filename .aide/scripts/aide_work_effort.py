"""Pure observations of supplied managed attempts; never an acceptance authority."""
import hashlib
import json
import re

PHASES = ("preparation", "context", "execution", "tests", "review", "repair",
          "integration", "recovery", "cleanup")


def identity(value, pattern, label):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("invalid " + label)
    return value


def validate_work_set(value):
    if (set(value) != {"schema", "work_id", "receipts", "usage_roster"}
            or value["schema"] != "aide.work-effort-set.v1"):
        raise ValueError("invalid work-set schema")
    identity(value["work_id"], r"[A-Za-z0-9._-]{1,64}", "work identity")
    if not isinstance(value["receipts"], list) or len(value["receipts"]) > 16:
        raise ValueError("work set permits at most sixteen receipts")
    for entry in value["receipts"]:
        if (not isinstance(entry, dict) or set(entry) != {"path", "sha256", "phase"}
                or entry["phase"] not in PHASES):
            raise ValueError("invalid receipt entry or declared phase")
        identity(entry["sha256"], r"[0-9a-f]{64}", "receipt digest")
    roster = value["usage_roster"]
    if roster is not None:
        if not isinstance(roster, dict) or set(roster) != {"path", "sha256"}:
            raise ValueError("invalid usage roster reference")
        identity(roster["sha256"], r"[0-9a-f]{64}", "roster digest")


def _flag(value):
    if value is not None and type(value) is not bool:
        raise ValueError("invalid reconciliation observation")
    return value


def _peak(value):
    if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
        raise ValueError("invalid resource observation")
    return value


def normalize_receipt(receipt, work_id, digest, phase):
    job = receipt.get("job")
    job_id = identity(receipt.get("job_id"), r"[0-9a-f]{32}", "job identity")
    if (not isinstance(job, dict) or job.get("schema") != "aide.maintainer-job.v1"
            or job.get("workunit") != work_id):
        raise ValueError("receipt schema or work identity mismatch")
    manifest = hashlib.sha256(json.dumps(job, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False).encode()).hexdigest()
    if receipt.get("manifest_digest") != manifest:
        raise ValueError("receipt manifest digest mismatch")
    source = {name: identity(job.get(name), r"(?:[0-9a-f]{40}|[0-9a-f]{64})", name)
              for name in ("source_commit", "source_tree")}
    result = receipt.get("result", {})
    peaks = receipt.get("peaks", {})
    if not isinstance(result, dict) or not isinstance(peaks, dict):
        raise ValueError("invalid receipt result or peaks")
    if "job_id" in result and result["job_id"] != job_id:
        raise ValueError("result job identity mismatch")
    exit_code = result.get("exit_code")
    if exit_code is not None and (type(exit_code) is not int or not -(2**63) <= exit_code < 2**63):
        raise ValueError("invalid exit code")
    reason = result.get("reason")
    # A zero exit alone does not establish task acceptance or successful cleanup.
    outcome = "UNKNOWN"
    if reason == "exited" and exit_code is not None:
        outcome = "SUCCEEDED" if exit_code == 0 else "FAILED"
    elif reason == "cancelled":
        outcome = "CANCELLED"
    elif reason in ("timeout", "output_limit_or_io_error"):
        outcome = "FAILED"
    recovered = receipt.get("reconciliation", {})
    if not isinstance(recovered, dict):
        raise ValueError("invalid reconciliation record")
    original_quiescent = _flag(result.get("quiescent"))
    recovered_quiescent = _flag(recovered.get("quiescent"))
    # Owner recovery is a later observation, retained alongside the original.
    reconciliation = {"quiescent": recovered_quiescent if recovered_quiescent is not None else original_quiescent,
                      "result_quiescent": original_quiescent,
                      "recovery_quiescent": recovered_quiescent,
                      "scratch_absent": _flag(receipt.get("scratch_absent")),
                      "reservation_released": _flag(receipt.get("reservation_released"))}
    retired = receipt.get("phase") == "retired" and all(reconciliation[key] is True for key in
                                                      ("quiescent", "scratch_absent", "reservation_released"))
    collected = receipt.get("collected_manifest", {})
    if not isinstance(collected, dict) or len(collected) > 16:
        raise ValueError("invalid collected manifest")
    hashes = {}
    for name, sha in collected.items():
        identity(name, r"[A-Za-z0-9._-]{1,64}", "collection label")
        hashes[name] = identity(sha, r"[0-9a-f]{64}", "collection digest")
    return {"job_id": job_id, "receipt_sha256": digest, "manifest_digest": manifest,
            **source, "declared_phase": phase, "execution_outcome": outcome,
            "termination_reason": reason if reason in ("exited", "cancelled", "timeout", "output_limit_or_io_error") else "unknown",
            "exit_code": exit_code, "retired_observed": retired,
            "reconciliation": reconciliation,
            "memory_peak_bytes": _peak(peaks.get("memory_bytes")),
            "scratch_peak_bytes": _peak(peaks.get("scratch_bytes")),
            "collected_hashes_observed": hashes}


def summarize(work_id, observations, work_set_sha256, usage=None):
    """observations: (parsed receipt, raw byte SHA256, declared phase)."""
    attempts = {}
    duplicates = 0
    for receipt, digest, phase in observations:
        item = normalize_receipt(receipt, work_id, digest, phase)
        previous = attempts.get(item["job_id"])
        if previous is not None:
            if previous != item:
                raise ValueError("conflicting snapshots or phases for one job")
            duplicates += 1
        else:
            attempts[item["job_id"]] = item
    rows = sorted(attempts.values(), key=lambda item: item["job_id"])
    phases = {phase: {"observed_attempts": sum(row["declared_phase"] == phase for row in rows),
                      "accounting_coverage": "unknown"} for phase in PHASES}
    return {"schema": "aide.work-effort.v1", "status": "PARTIAL", "work_id": work_id,
            "work_set_sha256": work_set_sha256, "attempt_count": len(rows),
            "duplicate_observations_excluded": duplicates, "attempts": rows,
            "execution_outcomes": {outcome: sum(row["execution_outcome"] == outcome for row in rows)
                                   for outcome in ("SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN")},
            "retired_attempts_observed": sum(row["retired_observed"] for row in rows),
            "phases": phases,
            "max_observed_individual_job_peaks": {
                metric: max((row[metric] for row in rows if row[metric] is not None), default=None)
                for metric in ("memory_peak_bytes", "scratch_peak_bytes")},
            "model_usage": usage, "whole_work_cost": None, "human_effort_seconds": None,
            "accepted_outcome_elapsed_seconds": None, "work_outcome": "unknown",
            "limitations": ["supplied_receipts_only", "phase_assignment_is_declarative",
                            "whole_work_accounting_unknown", "peaks_are_not_additive_or_host_peaks",
                            "collection_hashes_not_revalidated", "no_acceptance_or_execution_effect"]}


def human_report(report):
    if report["status"] == "REFUSED":
        return "AIDE work effort: REFUSED\n" + report["reason"]
    counts = report["execution_outcomes"]
    lines = ["AIDE work effort: " + report["work_id"] + " (PARTIAL)",
             f"Attempts: {report['attempt_count']} unique; "
             + ", ".join(f"{count} {name.lower()}" for name, count in counts.items()),
             f"Retired observed: {report['retired_attempts_observed']}; "
             f"duplicates excluded: {report['duplicate_observations_excluded']}"]
    for phase, value in report["phases"].items():
        lines.append(f"{phase}: {value['observed_attempts']} declared attempts; accounting unknown")
    peaks = report["max_observed_individual_job_peaks"]
    lines.append("Largest observed individual-job peaks (bytes): " + ", ".join(
        f"{name}={value if value is not None else 'unknown'}" for name, value in peaks.items()))
    lines.append("Model usage: supplied partial roster" if report["model_usage"] else "Model usage: unknown")
    lines.append("Whole-work cost, human effort, accepted-outcome time and outcome: unknown.")
    lines.append("Next: supply missing receipts/usage; inspect --json for identities and limitations.")
    return "\n".join(lines)
