#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Offline USK specification workbench. No model calls, network, shell or runtime effects.

Python 3.9+; stdlib for core commands. Optional `jsonschema` for full schema checks.
This validates the bundle's JSON-valued-YAML producer profile, not arbitrary YAML/OKF.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any
from urllib.parse import unquote, urlsplit
import zipfile

VERSION = '0.2.0'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
IGNORE = {'__pycache__', '.git', '.pytest_cache'}
RESERVED = {'index.md', 'log.md'}
ID_RE = re.compile(r'^USK-S-[A-Z0-9-]+$')
REQ_RE = re.compile(r'^### (USK-R-[A-Z0-9-]+) — (.+)$', re.M)
LINK_RE = re.compile(r'(?<!!)\[[^\]\n]*\]\(([^)\n]+)\)')
AUTHORITY_IDS = ['USK-S-AUTH', 'USK-S-OKF', 'USK-S-WORK']
SCOPE_FIELDS = ('context_paths', 'allowed_paths', 'read_only_paths', 'forbidden_paths')
RELEASE_SELECTION_IDS = {'OD-002', 'OD-003', 'OD-008'}
RELEASE_SELECTION_FIELDS = {'schema', 'recorded_at', 'source', 'status', 'decisions', 'authority'}
RELEASE_AUTHORITY_FIELDS = {
    'implementation_grant', 'endpoint_mutation_grant', 'protected_ref_write',
    'signing', 'tagging', 'publication', 'queue_changed'
}
RELEASE_SELECTED_STRING_FIELDS = {
    'OD-002': {
        'os_family', 'architecture', 'mutation_filesystem', 'deployment_scope',
        'setup_implementation', 'first_graphical_adapter', 'appearance_default'
    },
    'OD-003': {
        'policy', 'existing_c_abi', 'new_capabilities', 'contract_identity',
        'breaking_change_rule'
    },
    'OD-008': {
        'development_train', 'target_release', 'product_name', 'current_release_readiness'
    },
}
RELEASE_SELECTED_LIST_FIELDS = {
    'OD-002': {'terminal_interfaces'},
    'OD-003': set(),
    'OD-008': {'stages'},
}
RELEASE_SELECTION_LIST_FIELDS = {
    'OD-002': {'outstanding', 'non_claims'},
    'OD-003': {'required_analysis', 'outstanding'},
    'OD-008': {'required_families', 'scheduled_later', 'outstanding'},
}
RELEASE_DECISION_FIELDS = {
    decision_id: {'parent_status', 'selected'} | RELEASE_SELECTION_LIST_FIELDS[decision_id]
    for decision_id in RELEASE_SELECTION_IDS
}
RELEASE_DECISION_FIELDS['OD-008'].add('product_objective')
PROGRAMME_STATUS_FIELDS = {
    'schema', 'recorded_at', 'release_selection_snapshot', 'campaign_authority',
    'authority_granted_by_this_projection', 'decisions', 'release_1_1',
    'full_spec_baseline'
}
RELEASE_PREDICATES = {
    'implementation_complete', 'machine_qualified', 'experience_assessed',
    'integrated', 'published'
}
RELEASE_READINESS = {'not_established', 'alpha', 'beta', 'rc', 'supported'}
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')

class SpecError(Exception):
    pass


def pairs_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SpecError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def json_loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=pairs_unique,
                          parse_constant=lambda x: (_ for _ in ()).throw(SpecError('non-finite JSON: ' + x)))
    except (ValueError, RecursionError) as exc:
        raise SpecError('invalid JSON: ' + str(exc)) from exc


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_text(path: Path) -> str:
    if path.is_symlink():
        raise SpecError('symlink input refused: ' + str(path))
    if path.stat().st_size > MAX_FILE:
        raise SpecError('file budget exceeded: ' + str(path))
    try:
        value = path.read_text(encoding='utf-8')
        if '\x00' in value or '\ufeff' in value[:1]:
            raise SpecError('NUL/BOM input refused: ' + str(path))
        return value
    except UnicodeError as exc:
        raise SpecError('invalid UTF-8: ' + str(path)) from exc


def load_json(path: Path) -> Any:
    return json_loads(read_text(path))


def safe_files(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise SpecError('spec root must be a real directory')
    result = []
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in list(dirs):
            if (base / name).is_symlink():
                raise SpecError('symlink directory refused: ' + str(base / name))
            if name in IGNORE:
                dirs.remove(name)
        for name in files:
            path = base / name
            if path.is_symlink():
                raise SpecError('symlink file refused: ' + str(path))
            if path.suffix == '.pyc':
                continue
            size = path.stat().st_size
            if size > MAX_FILE:
                raise SpecError('file budget exceeded: ' + str(path))
            total += size
            if total > MAX_TOTAL:
                raise SpecError('bundle byte budget exceeded')
            result.append(path)
    return sorted(result, key=lambda p: p.relative_to(root).as_posix())


def parse_concept(text: str, path: str = '<text>') -> tuple[dict, str]:
    if not text.startswith('---\n'):
        raise SpecError(path + ': missing producer frontmatter')
    if '\n---\n' not in text[4:]:
        raise SpecError(path + ': missing closing frontmatter')
    head, body = text[4:].split('\n---\n', 1)
    meta = {}
    for line in head.splitlines():
        if not line or ':' not in line:
            raise SpecError(path + ': expected key: JSON-value producer syntax')
        key, value = line.split(':', 1)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', key):
            raise SpecError(path + ': invalid metadata key')
        if key in meta:
            raise SpecError(path + ': duplicate frontmatter key: ' + key)
        meta[key] = json_loads(value)
    if not isinstance(meta.get('type'), str) or not meta['type']:
        raise SpecError(path + ': missing concept type')
    return meta, body.lstrip('\n')


def ensure_timestamp(value: Any) -> bool:
    try:
        stamp = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return stamp.tzinfo is not None and 'T' in str(value)
    except ValueError:
        return False


def extract_requirements(body: str, sid: str, path: str) -> list[dict]:
    found = list(REQ_RE.finditer(body))
    rows = []
    for i, match in enumerate(found):
        end = found[i+1].start() if i+1 < len(found) else len(body)
        section = body[match.end():end]
        statement = re.search(r'\*\*Requirement\.\*\* (.+?)(?=\n\n)', section, re.S)
        case = re.search(r'\*\*Acceptance\.\*\* `(USK-AT-[A-Z0-9-]+)`', section)
        if not statement or not case:
            raise SpecError(path + ': incomplete requirement ' + match[1])
        rows.append({'id':match[1], 'title':match[2], 'statement':statement[1].strip(),
                     'spec_id':sid, 'path':path, 'acceptance_ids':[case[1]]})
    return rows


def graph_errors(graph: dict[str, list[str]], label: str) -> list[str]:
    errors = []
    active, done = set(), set()
    def visit(node: str, trail: list[str]) -> None:
        if node in active:
            errors.append(label + ' cycle: ' + ' -> '.join(trail + [node]))
            return
        if node in done:
            return
        active.add(node)
        for dep in graph.get(node, []):
            if dep not in graph:
                errors.append(label + ' missing dependency: ' + node + ' -> ' + dep)
            else:
                visit(dep, trail + [node])
        active.remove(node)
        done.add(node)
    for node in sorted(graph):
        visit(node, [])
    return errors


def scope_pattern_parts(pattern: str) -> tuple[str, bool]:
    """Return a normalized literal prefix and whether it represents a subtree."""
    if not isinstance(pattern, str) or not pattern:
        raise SpecError('scope path pattern must be a non-empty string')
    path = PurePosixPath(pattern)
    if path.is_absolute() or '..' in path.parts or '\\' in pattern:
        raise SpecError('scope path pattern must be repository-relative POSIX: ' + pattern)
    subtree = pattern.endswith('/**')
    literal = pattern[:-3] if subtree else pattern
    if not literal or any(char in literal for char in '*?['):
        raise SpecError('scope path pattern supports only literal paths or a final /**: ' + pattern)
    return literal.rstrip('/'), subtree


def scope_patterns_overlap(left: str, right: str) -> bool:
    """Conservatively detect intersections in the supported scope-pattern subset."""
    left_path, left_tree = scope_pattern_parts(left)
    right_path, right_tree = scope_pattern_parts(right)
    if left_path == right_path:
        return True
    if left_tree and (right_path.startswith(left_path + '/')):
        return True
    if right_tree and (left_path.startswith(right_path + '/')):
        return True
    return False


def task_scope_errors(task_id: str, task: dict) -> list[str]:
    errors = []
    for field in SCOPE_FIELDS:
        values = task.get(field)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            errors.append(task_id + ': ' + field + ' must be a string list')
            continue
        if len(values) != len(set(values)):
            errors.append(task_id + ': duplicate ' + field + ' entry')
        for value in values:
            try:
                scope_pattern_parts(value)
            except SpecError as exc:
                errors.append(task_id + ': ' + field + ': ' + str(exc))
    operations = task.get('forbidden_operations')
    if not isinstance(operations, list) or any(not isinstance(value, str) or not value for value in operations):
        errors.append(task_id + ': forbidden_operations must be a non-empty string list')
    elif not operations:
        errors.append(task_id + ': forbidden_operations must not be empty')
    allowed = task.get('allowed_paths') if isinstance(task.get('allowed_paths'), list) else []
    for deny_field in ('read_only_paths', 'forbidden_paths'):
        denied = task.get(deny_field) if isinstance(task.get(deny_field), list) else []
        for writable in allowed:
            for deny in denied:
                try:
                    overlaps = scope_patterns_overlap(writable, deny)
                except SpecError:
                    continue
                if overlaps:
                    errors.append(
                        task_id + ': contradictory writable scope ' + writable +
                        ' overlaps ' + deny_field + ' entry ' + deny
                    )
    return errors


def release_selection_snapshot_errors(release_selection: Any) -> list[str]:
    """Validate the immutable selection-time snapshot, not current programme state."""
    prefix = 'plan/release-selection.json: '
    if not isinstance(release_selection, dict):
        return [prefix + 'root must be an object']
    errors = []
    if set(release_selection) != RELEASE_SELECTION_FIELDS:
        errors.append(prefix + 'top-level fields are incomplete or unknown')
    if release_selection.get('schema') != 'usk.spec.release-selection/1':
        errors.append(prefix + 'unsupported schema')
    if not ensure_timestamp(release_selection.get('recorded_at')):
        errors.append(prefix + 'timezone-aware recorded_at required')
    if release_selection.get('status') != 'development_direction_selected_qualification_outstanding':
        errors.append(prefix + 'invalid development-direction status')
    source = release_selection.get('source')
    if not isinstance(source, dict) or set(source) != {'id', 'resource', 'title'} or any(
            not isinstance(source.get(field), str) or not source[field]
            for field in ('id', 'resource', 'title')):
        errors.append(prefix + 'source must bind non-empty id, resource and title')

    selected_decisions = release_selection.get('decisions')
    if not isinstance(selected_decisions, dict) or set(selected_decisions) != RELEASE_SELECTION_IDS:
        errors.append(prefix + 'expected OD-002, OD-003 and OD-008 selections')
        selected_decisions = {}
    for decision_id, selection in selected_decisions.items():
        if not isinstance(selection, dict) or selection.get('parent_status') != 'open':
            errors.append(decision_id + ': selection-time snapshot must declare its then-open parent status')
            continue
        if set(selection) != RELEASE_DECISION_FIELDS[decision_id]:
            errors.append(decision_id + ': selection fields are incomplete or unknown')
        selected = selection.get('selected')
        if not isinstance(selected, dict):
            errors.append(decision_id + ': selected direction must be an object')
        else:
            expected_selected = (RELEASE_SELECTED_STRING_FIELDS[decision_id] |
                                 RELEASE_SELECTED_LIST_FIELDS[decision_id])
            if set(selected) != expected_selected:
                errors.append(decision_id + ': selected fields are incomplete or unknown')
            for field in sorted(RELEASE_SELECTED_STRING_FIELDS[decision_id]):
                if not isinstance(selected.get(field), str) or not selected[field]:
                    errors.append(decision_id + ': missing selected.' + field)
            for field in sorted(RELEASE_SELECTED_LIST_FIELDS[decision_id]):
                value = selected.get(field)
                if (not isinstance(value, list) or not value or
                        any(not isinstance(item, str) or not item for item in value)):
                    errors.append(decision_id + ': selected.' + field + ' must be a non-empty string list')
        for field in sorted(RELEASE_SELECTION_LIST_FIELDS[decision_id]):
            value = selection.get(field)
            if (not isinstance(value, list) or not value or
                    any(not isinstance(item, str) or not item for item in value)):
                errors.append(decision_id + ': ' + field + ' must be a non-empty string list')
        if decision_id == 'OD-008':
            if not isinstance(selection.get('product_objective'), str) or not selection['product_objective']:
                errors.append(decision_id + ': product_objective must be a non-empty string')
            if isinstance(selected, dict) and selected.get('current_release_readiness') != 'not established':
                errors.append(decision_id + ': release readiness must remain not established')

    selection_authority = release_selection.get('authority')
    if not isinstance(selection_authority, dict) or set(selection_authority) != RELEASE_AUTHORITY_FIELDS:
        errors.append(prefix + 'authority ceiling fields are incomplete or unknown')
    elif any(value is not False for value in selection_authority.values()):
        errors.append(prefix + 'direction selection must not grant operational authority')
    return errors


def evidence_ref_errors(reference: Any, prefix: str) -> list[str]:
    if not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}:
        return [prefix + ' evidence reference must contain only path and sha256']
    path = reference.get('path')
    if (not isinstance(path, str) or not path or '\\' in path or
            PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts):
        return [prefix + ' evidence path must be repository-relative POSIX']
    if not SHA256_RE.fullmatch(str(reference.get('sha256', ''))):
        return [prefix + ' evidence sha256 is invalid']
    return []


def evidence_file_errors(root: Path, reference: Any, prefix: str) -> list[str]:
    errors = evidence_ref_errors(reference, prefix)
    if errors:
        return errors
    relative = PurePosixPath(reference['path'])
    repository = root.parent
    path = repository.joinpath(*relative.parts)
    must_exist_here = reference['path'].startswith('spec/') or (repository / '.git').exists()
    if must_exist_here:
        if not path.is_file() or path.is_symlink():
            errors.append(prefix + ' evidence file is missing or unsafe')
        elif digest(path.read_bytes()) != reference['sha256']:
            errors.append(prefix + ' evidence file digest is stale')
    return errors


def git_source_bytes(repository: Path, commit: str, path: str) -> bytes:
    """Read an exact repository path from a commit, never from the worktree."""
    result = subprocess.run(
        ['git', 'show', commit + ':' + path], cwd=repository, check=False,
        capture_output=True, timeout=30,
    )
    if result.returncode:
        raise SpecError('source commit does not contain ' + path)
    return result.stdout


def source_binding_errors(root: Path, source: Any, aggregate: Any,
                          evidence_path: str, prefix: str) -> list[str]:
    """Bind a receipt, its source identity, and its specification inventory together."""
    if (not isinstance(source, dict) or set(source) != {'commit', 'tree'} or
            any(not re.fullmatch(r'[0-9a-f]{40}', str(source.get(field, '')))
                for field in ('commit', 'tree'))):
        return [prefix + ' programme evidence source identity is invalid']
    if not SHA256_RE.fullmatch(str(aggregate)):
        return [prefix + ' programme evidence specification digest is invalid']
    repository = root.parent
    try:
        observed_commit = subprocess.run(
            ['git', 'rev-parse', '--verify', source['commit'] + '^{commit}'], cwd=repository,
            check=False, capture_output=True, text=True, timeout=30,
        )
        observed_tree = subprocess.run(
            ['git', 'rev-parse', '--verify', source['commit'] + '^{tree}'], cwd=repository,
            check=False, capture_output=True, text=True, timeout=30,
        )
        if observed_commit.returncode or observed_tree.returncode:
            raise SpecError('referenced source commit is unavailable')
        if observed_commit.stdout.strip() != source['commit']:
            raise SpecError('referenced source commit is not canonical')
        if observed_tree.stdout.strip() != source['tree']:
            raise SpecError('referenced source tree does not belong to source commit')
        integrity = json_loads(git_source_bytes(repository, source['commit'], 'spec/integrity.json').decode('utf-8'))
        if (not isinstance(integrity, dict) or integrity.get('schema') != 'usk.spec.integrity/1' or
                integrity.get('algorithm') != 'sha256' or integrity.get('self_excluded') != 'integrity.json' or
                not isinstance(integrity.get('files'), list) or
                integrity.get('aggregate_sha256') != aggregate):
            raise SpecError('source specification aggregate is invalid')
        rows = integrity['files']
        if digest(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()) != aggregate:
            raise SpecError('source specification aggregate does not match its inventory')
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256'} or
                    not isinstance(row['path'], str) or not isinstance(row['bytes'], int) or
                    row['bytes'] < 0 or not SHA256_RE.fullmatch(str(row['sha256']))):
                raise SpecError('source specification inventory is malformed')
    except (OSError, UnicodeError, SpecError) as exc:
        return [prefix + ' ' + str(exc)]
    return []


def git_commit_errors(root: Path, commit: Any, tree: Any | None, prefix: str,
                      require_main_reachability: bool = False) -> list[str]:
    """Require a real commit (and optionally its exact tree) in the local Git graph."""
    if not re.fullmatch(r'[0-9a-f]{40}', str(commit)):
        return [prefix + ' commit is invalid']
    if tree is not None and not re.fullmatch(r'[0-9a-f]{40}', str(tree)):
        return [prefix + ' tree is invalid']
    repository = root.parent
    try:
        observed_commit = subprocess.run(
            ['git', 'rev-parse', '--verify', str(commit) + '^{commit}'], cwd=repository,
            check=False, capture_output=True, text=True, timeout=30,
        )
        if observed_commit.returncode or observed_commit.stdout.strip() != commit:
            return [prefix + ' commit is unavailable or non-canonical']
        if tree is not None:
            observed_tree = subprocess.run(
                ['git', 'rev-parse', '--verify', str(commit) + '^{tree}'], cwd=repository,
                check=False, capture_output=True, text=True, timeout=30,
            )
            if observed_tree.returncode or observed_tree.stdout.strip() != tree:
                return [prefix + ' tree does not belong to its commit']
        if require_main_reachability:
            main = subprocess.run(
                ['git', 'rev-parse', '--verify', 'refs/remotes/origin/main^{commit}'], cwd=repository,
                check=False, capture_output=True, text=True, timeout=30,
            )
            main_oid = main.stdout.strip() if not main.returncode else ''
            if not main_oid:
                return [prefix + ' cannot verify reachability from authoritative origin/main']
            reachable = subprocess.run(
                ['git', 'merge-base', '--is-ancestor', str(commit), main_oid], cwd=repository,
                check=False, capture_output=True, timeout=30,
            )
            if reachable.returncode:
                return [prefix + ' commit is not reachable from main']
    except OSError as exc:
        return [prefix + ' Git validation failed: ' + str(exc)]
    return []


def remote_tag_errors(root: Path, tag: str, tag_commit: str, tag_object: Any,
                      tag_kind: Any) -> list[str]:
    """Read the authoritative remote tag namespace and bind its exact target."""
    if tag_kind not in {'lightweight', 'annotated'} or not re.fullmatch(r'[0-9a-f]{40}', str(tag_object)):
        return ['publication evidence remote tag identity is invalid']
    try:
        result = subprocess.run(
            ['git', 'ls-remote', '--tags', 'origin', 'refs/tags/' + tag, 'refs/tags/' + tag + '^{}'],
            cwd=root.parent, check=False, capture_output=True, text=True, timeout=30,
        )
    except OSError as exc:
        return ['publication evidence authoritative remote tag readback failed: ' + str(exc)]
    if result.returncode:
        return ['publication evidence authoritative remote tag readback is unavailable']
    tag_ref = 'refs/tags/' + tag
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 2 or not re.fullmatch(r'[0-9a-f]{40}', fields[0]) or fields[1] not in {tag_ref, tag_ref + '^{}'}:
            return ['publication evidence authoritative remote tag readback is malformed']
        if fields[1] in observed:
            return ['publication evidence authoritative remote tag readback is ambiguous']
        observed[fields[1]] = fields[0]
    if observed.get(tag_ref) != tag_object:
        return ['publication evidence named tag is absent or has moved in authoritative origin']
    peeled = observed.get(tag_ref + '^{}')
    if tag_kind == 'annotated':
        if peeled != tag_commit:
            return ['publication evidence annotated tag does not peel to tag_commit']
    elif peeled is not None or tag_object != tag_commit:
        return ['publication evidence lightweight tag does not resolve exactly to tag_commit']
    return []


def typed_receipt_record(root: Path, reference: Any, expected_schema: str,
                         expected_claim: str, prefix: str) -> tuple[dict, list[str]]:
    """Load an accepted, source-bound evidence receipt from the governed ledger."""
    errors = evidence_file_errors(root, reference, prefix)
    if errors:
        return {}, errors
    path_text = reference['path']
    if not path_text.startswith('release/evidence/') or not path_text.endswith('.json'):
        return {}, [prefix + ' must be a JSON receipt under release/evidence/']
    try:
        record = load_json(root.parent.joinpath(*PurePosixPath(path_text).parts))
    except (SpecError, OSError) as exc:
        return {}, [prefix + ' is unreadable: ' + str(exc)]
    expected_fields = {
        'schema', 'campaign', 'claim', 'status', 'recorded_at', 'source',
        'spec_aggregate_sha256', 'details'
    }
    if not isinstance(record, dict) or set(record) != expected_fields:
        return {}, [prefix + ' fields are incomplete or unknown']
    if record.get('schema') != expected_schema:
        errors.append(prefix + ' schema is invalid')
    if record.get('campaign') != 'USK-SPEC-TO-RELEASE-01' or record.get('status') != 'accepted':
        errors.append(prefix + ' is not accepted for the active campaign')
    if record.get('claim') != expected_claim:
        errors.append(prefix + ' claim mismatch')
    if not ensure_timestamp(record.get('recorded_at')):
        errors.append(prefix + ' timestamp is invalid')
    errors.extend(source_binding_errors(
        root, record.get('source'), record.get('spec_aggregate_sha256'), path_text, prefix
    ))
    if not isinstance(record.get('details'), dict):
        errors.append(prefix + ' details must be an object')
    return record, errors


def programme_evidence_record(root: Path, reference: Any, expected_claim: str,
                              prefix: str) -> tuple[dict, list[str]]:
    record, errors = typed_receipt_record(
        root, reference, 'universal.programme_evidence/1', expected_claim,
        prefix + ' programme evidence'
    )
    if not record:
        return {}, errors
    details = record.get('details')
    if not isinstance(details, dict):
        errors.append(prefix + ' programme evidence details must be an object')
        return record, errors

    candidate_claims = {
        'release_1_1.readiness', 'release_1_1.implementation_complete',
        'release_1_1.machine_qualified', 'release_1_1.experience_assessed',
        'release_1_1.integrated', 'release_1_1.published'
    }
    if expected_claim in candidate_claims and not SHA256_RE.fullmatch(str(details.get('candidate_sha256', ''))):
        errors.append(prefix + ' release evidence requires an exact candidate digest')
    if expected_claim == 'release_1_1.readiness':
        if set(details) != {'candidate_sha256', 'readiness'} or details.get('readiness') not in RELEASE_READINESS - {'not_established'}:
            errors.append(prefix + ' readiness evidence details are invalid')
    elif expected_claim == 'release_1_1.implementation_complete':
        workunits = details.get('completed_workunits')
        if (set(details) != {'candidate_sha256', 'completed_workunits'} or
                not isinstance(workunits, list) or not workunits or
                any(not isinstance(item, str) or not re.fullmatch(r'USK-WU-\d{3}', item) for item in workunits) or
                len(workunits) != len(set(workunits))):
            errors.append(prefix + ' implementation evidence needs unique completed WorkUnits')
    elif expected_claim == 'release_1_1.machine_qualified':
        profiles = details.get('profiles')
        receipts = details.get('qualification_receipts')
        if set(details) != {'candidate_sha256', 'profiles', 'qualification_receipts'} or not isinstance(profiles, list) or not profiles or any(not isinstance(item, str) or not item for item in profiles) or not isinstance(receipts, list) or not receipts:
            errors.append(prefix + ' machine qualification evidence details are invalid')
        elif isinstance(receipts, list):
            for index, nested in enumerate(receipts):
                qualification, qualification_errors = typed_receipt_record(
                    root, nested, 'universal.machine_qualification_receipt/1',
                    'release_1_1.machine_qualified',
                    prefix + f' qualification receipt[{index}]'
                )
                errors.extend(qualification_errors)
                detail = qualification.get('details', {})
                if (set(detail) != {'candidate_sha256', 'profile', 'result'} or
                        detail.get('candidate_sha256') != details.get('candidate_sha256') or
                        detail.get('profile') not in profiles or detail.get('result') != 'pass'):
                    errors.append(prefix + f' qualification receipt[{index}] is not a passing receipt for an admitted profile')
    elif expected_claim == 'release_1_1.experience_assessed':
        kind = details.get('assessment_kind')
        principals = details.get('observer_principals')
        if set(details) != {'candidate_sha256', 'assessment_kind', 'observer_principals'} or kind not in {'automated', 'human', 'mixed'} or not isinstance(principals, list):
            errors.append(prefix + ' experience evidence details are invalid')
        elif kind in {'human', 'mixed'} and (not principals or any(not isinstance(item, str) or not item for item in principals)):
            errors.append(prefix + ' human experience evidence requires actual observer principals')
    elif expected_claim == 'release_1_1.integrated':
        if (set(details) != {'candidate_sha256', 'branch', 'commit', 'tree'} or
                details.get('branch') != 'main' or
                any(not re.fullmatch(r'[0-9a-f]{40}', str(details.get(field, ''))) for field in ('commit', 'tree'))):
            errors.append(prefix + ' integration evidence must bind exact main commit/tree')
        else:
            errors.extend(git_commit_errors(
                root, details.get('commit'), details.get('tree'),
                prefix + ' integration evidence', require_main_reachability=True
            ))
    elif expected_claim == 'release_1_1.published':
        assets = details.get('remote_assets')
        expected = {'candidate_sha256', 'tag', 'tag_commit', 'remote_tag_object', 'tag_kind',
                    'remote_assets', 'remote_readback_at', 'immutable', 'signing'}
        if (set(details) != expected or not re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?', str(details.get('tag', ''))) or
                not re.fullmatch(r'[0-9a-f]{40}', str(details.get('tag_commit', ''))) or
                details.get('immutable') is not True or
                details.get('signing') not in {'not_required_by_release_profile', 'configured_signer_verified'} or
                not ensure_timestamp(details.get('remote_readback_at')) or not isinstance(assets, list) or not assets):
            errors.append(prefix + ' publication evidence details are invalid')
        elif any(not isinstance(item, dict) or set(item) != {'name', 'sha256', 'url'} or
                 not item.get('name') or not SHA256_RE.fullmatch(str(item.get('sha256', ''))) or
                 not str(item.get('url', '')).startswith('https://') for item in assets):
            errors.append(prefix + ' publication assets require name, digest and HTTPS readback URL')
        else:
            commit_errors = git_commit_errors(
                root, details.get('tag_commit'), None, prefix + ' publication evidence'
            )
            errors.extend(commit_errors)
            if not commit_errors:
                errors.extend(remote_tag_errors(
                    root, details['tag'], details['tag_commit'], details.get('remote_tag_object'), details.get('tag_kind')
                ))
    elif expected_claim == 'full_spec_baseline.complete':
        workunits = details.get('completed_workunits')
        expected_workunits = {f'USK-WU-{index:03d}' for index in range(1, 34)}
        profiles = details.get('admitted_profiles')
        if (set(details) != {'completed_workunits', 'admitted_profiles'} or
                not isinstance(workunits, list) or
                any(not isinstance(item, str) for item in workunits) or
                set(workunits) != expected_workunits or
                not isinstance(profiles, list) or not profiles):
            errors.append(prefix + ' full-spec evidence must cover all baseline WorkUnits and admitted profiles')
    elif expected_claim == 'full_spec_baseline.continuing_maintenance_operational':
        channels = details.get('channels')
        if (set(details) != {'workunit', 'operational_since', 'channels'} or
                details.get('workunit') != 'USK-WU-033' or
                not ensure_timestamp(details.get('operational_since')) or
                not isinstance(channels, list) or not channels):
            errors.append(prefix + ' continuing-maintenance evidence details are invalid')
    return record, errors


DECISION_EVIDENCE_KINDS = {
    'OD-001': ('platform_publication_security', {
        'enforcement', 'adversary_model_sha256', 'attack_evidence_sha256'
    }),
    'OD-002': ('machine_qualification', {'candidate_sha256', 'profile', 'qualification_receipt'}),
    'OD-003': ('c_abi_analysis', {'analysis_sha256', 'contract_identity'}),
    'OD-004': ('trust_provider_expiry', {
        'trust_provider', 'offline_expiry_seconds', 'test_vectors_sha256'
    }),
    'OD-008': ('release_plan', {'plan_sha256', 'target_release'}),
    'OD-005': ('campaign_authority_binding', {'authority_sha256', 'binding_policy'}),
    'OD-006': ('lab_experience_assessment', {
        'lab_target_identity', 'assessment_kind', 'observer_principals', 'assessment_sha256'
    }),
    'OD-007': ('performance_budget_measurement', {
        'corpus_sha256', 'budget_p95_ms', 'measured_p95_ms'
    }),
}


def decision_evidence_errors(root: Path, decision_id: str, reference: Any,
                             prefix: str) -> list[str]:
    expected = DECISION_EVIDENCE_KINDS.get(decision_id)
    if expected is None:
        return [prefix + ' has no registered typed evidence contract']
    record, errors = typed_receipt_record(
        root, reference, 'universal.decision_evidence/1', decision_id, prefix
    )
    details = record.get('details', {})
    kind, expected_fields = expected
    if (not isinstance(details, dict) or set(details) != expected_fields | {'evidence_kind'} or
            details.get('evidence_kind') != kind):
        errors.append(prefix + ' is not suitable typed evidence for ' + decision_id)
        return errors
    def required_sha256(field: str) -> bool:
        return SHA256_RE.fullmatch(str(details.get(field, ''))) is not None
    selection_path = root / 'plan/release-selection.json'
    selection = load_json(selection_path) if selection_path.is_file() else {}
    selected = selection.get('decisions', {}).get(decision_id, {}).get('selected', {}) if isinstance(selection, dict) else {}
    if decision_id == 'OD-001':
        if details.get('enforcement') != 'platform_enforced' or not all(
                required_sha256(field) for field in ('adversary_model_sha256', 'attack_evidence_sha256')):
            errors.append(prefix + ' must bind platform enforcement and exact adversary/attack evidence')
    if decision_id == 'OD-002' and isinstance(details, dict):
        expected_profile = 'windows-nt-x86_64'
        if (selected.get('os_family') != 'Windows NT' or selected.get('architecture') != 'x86_64' or
                details.get('profile') != expected_profile):
            errors.append(prefix + ' profile differs from the canonical OD-002 selection')
        nested = details.get('qualification_receipt')
        qualification, nested_errors = typed_receipt_record(
            root, nested, 'universal.machine_qualification_receipt/1',
            'release_1_1.machine_qualified', prefix + ' qualification receipt'
        )
        errors.extend(nested_errors)
        qualified = qualification.get('details', {})
        if (not isinstance(qualified, dict) or qualified.get('candidate_sha256') != details.get('candidate_sha256') or
                qualified.get('profile') != details.get('profile') or qualified.get('result') != 'pass'):
            errors.append(prefix + ' qualification receipt does not support the decision evidence')
    elif decision_id == 'OD-003':
        if not required_sha256('analysis_sha256') or details.get('contract_identity') != selected.get('contract_identity'):
            errors.append(prefix + ' must bind exact analysis to the canonical OD-003 contract identity')
    elif decision_id == 'OD-004':
        if (not isinstance(details.get('trust_provider'), str) or not details['trust_provider'] or
                type(details.get('offline_expiry_seconds')) is not int or details['offline_expiry_seconds'] <= 0 or
                not required_sha256('test_vectors_sha256')):
            errors.append(prefix + ' must bind a trust provider, positive offline expiry and exact test vectors')
    elif decision_id == 'OD-005':
        authority_path = root.parent / 'release/index/campaign_authority.v1.toml'
        if (not authority_path.is_file() or details.get('authority_sha256') != digest(authority_path.read_bytes()) or
                details.get('binding_policy') != 'exact_non_widening_task_binding'):
            errors.append(prefix + ' must bind the canonical campaign authority digest and non-widening policy')
    elif decision_id == 'OD-006':
        principals = details.get('observer_principals')
        if (not isinstance(details.get('lab_target_identity'), str) or not details['lab_target_identity'].startswith('lab:') or
                details.get('assessment_kind') not in {'automated', 'human', 'mixed'} or
                not isinstance(principals, list) or not principals or
                any(not isinstance(item, str) or not item for item in principals) or
                not required_sha256('assessment_sha256')):
            errors.append(prefix + ' must bind a lab target, attributed assessment and exact assessment evidence')
    elif decision_id == 'OD-007':
        if (not required_sha256('corpus_sha256') or type(details.get('budget_p95_ms')) is not int or
                type(details.get('measured_p95_ms')) is not int or details['budget_p95_ms'] <= 0 or
                details['measured_p95_ms'] < 0 or details['measured_p95_ms'] > details['budget_p95_ms']):
            errors.append(prefix + ' must bind an exact corpus and a measurement within its p95 budget')
    elif decision_id == 'OD-008':
        if not required_sha256('plan_sha256') or details.get('target_release') != selected.get('target_release'):
            errors.append(prefix + ' must bind an exact plan to the canonical OD-008 target release')
    return errors


def decision_state_errors(root: Path, decisions: Any) -> list[str]:
    prefix = 'plan/open-decisions.json: '
    if not isinstance(decisions, list) or not decisions:
        return [prefix + 'decisions must be a non-empty list']
    errors = []
    ids = []
    for decision in decisions:
        if not isinstance(decision, dict) or not isinstance(decision.get('id'), str):
            errors.append(prefix + 'decision entry is malformed')
            continue
        decision_id = decision['id']
        ids.append(decision_id)
        status = decision.get('status')
        if status not in ('open', 'resolved'):
            errors.append(decision_id + ': status must be open or resolved')
        if status == 'open':
            if not isinstance(decision.get('resolution_required'), str) or not decision['resolution_required']:
                errors.append(decision_id + ': open decision requires resolution_required')
        else:
            if not isinstance(decision.get('resolution'), str) or not decision['resolution']:
                errors.append(decision_id + ': resolved decision requires resolution')
            evidence = decision.get('resolution_evidence')
            if not isinstance(evidence, list) or not evidence:
                errors.append(decision_id + ': resolved decision requires evidence')
            else:
                for index, reference in enumerate(evidence):
                    errors.extend(decision_evidence_errors(
                        root, decision_id, reference, decision_id + f' evidence[{index}]'
                    ))
            if 'resolution_required' in decision:
                errors.append(decision_id + ': resolved decision must not retain resolution_required')
            if decision.get('outstanding_obligations'):
                errors.append(decision_id + ': resolved decision must not retain outstanding obligations')
    if len(ids) != len(set(ids)):
        errors.append(prefix + 'duplicate decision ID')
    return errors


def programme_status_errors(root: Path, status: Any, decisions: list[dict]) -> list[str]:
    prefix = 'plan/programme-status.json: '
    if not isinstance(status, dict):
        return [prefix + 'root must be an object']
    errors = []
    if set(status) != PROGRAMME_STATUS_FIELDS:
        errors.append(prefix + 'top-level fields are incomplete or unknown')
    if status.get('schema') != 'usk.spec.programme-status/1':
        errors.append(prefix + 'unsupported schema')
    if not ensure_timestamp(status.get('recorded_at')):
        errors.append(prefix + 'timezone-aware recorded_at required')
    if status.get('authority_granted_by_this_projection') is not False:
        errors.append(prefix + 'status projection must not mint execution authority')

    snapshot = status.get('release_selection_snapshot')
    errors.extend(evidence_file_errors(root, snapshot, prefix + 'release selection'))
    expected_snapshot = {
        'path': 'spec/plan/release-selection.json',
        'sha256': digest((root / 'plan/release-selection.json').read_bytes()),
    }
    if snapshot != expected_snapshot:
        errors.append(prefix + 'release-selection snapshot binding is stale')

    campaign = status.get('campaign_authority')
    if not isinstance(campaign, dict) or set(campaign) != {'campaign', 'path', 'sha256', 'status'}:
        errors.append(prefix + 'campaign authority binding is malformed')
    else:
        errors.extend(evidence_file_errors(root,
            {'path': campaign.get('path'), 'sha256': campaign.get('sha256')},
            prefix + 'campaign authority'))
        if campaign.get('campaign') != 'USK-SPEC-TO-RELEASE-01' or campaign.get('status') != 'active':
            errors.append(prefix + 'campaign authority must identify the active campaign')
        if campaign.get('path') != 'release/index/campaign_authority.v1.toml':
            errors.append(prefix + 'campaign authority path is not canonical')
        if (root.parent / '.git').exists():
            authority_path = root.parent.joinpath(*PurePosixPath(campaign['path']).parts)
            if not authority_path.is_file() or digest(authority_path.read_bytes()) != campaign.get('sha256'):
                errors.append(prefix + 'campaign authority file binding is stale')

    current_decisions = status.get('decisions')
    decision_map = {item.get('id'): item for item in decisions if isinstance(item, dict)}
    if not isinstance(current_decisions, dict) or set(current_decisions) != set(decision_map):
        errors.append(prefix + 'decision projection must cover the exact decision set')
    else:
        for decision_id, projection in current_decisions.items():
            if (not isinstance(projection, dict) or set(projection) != {'status', 'evidence'} or
                    projection.get('status') not in ('open', 'resolved')):
                errors.append(decision_id + ': current decision projection is malformed')
                continue
            if projection['status'] != decision_map[decision_id].get('status'):
                errors.append(decision_id + ': projected decision status differs from decision register')
            evidence = projection.get('evidence')
            if not isinstance(evidence, list):
                errors.append(decision_id + ': decision evidence must be a list')
                continue
            if projection['status'] == 'resolved' and not evidence:
                errors.append(decision_id + ': resolved projection requires evidence')
            if (projection['status'] == 'resolved' and
                    evidence != decision_map[decision_id].get('resolution_evidence')):
                errors.append(decision_id + ': projected resolution evidence differs from decision register')
            for index, reference in enumerate(evidence):
                errors.extend(decision_evidence_errors(
                    root, decision_id, reference, decision_id + f' projection evidence[{index}]'
                ))

    release = status.get('release_1_1')
    release_fields = {'readiness', *RELEASE_PREDICATES, 'evidence'}
    if not isinstance(release, dict) or set(release) != release_fields:
        errors.append(prefix + 'release_1_1 fields are incomplete or unknown')
    else:
        if release.get('readiness') not in RELEASE_READINESS:
            errors.append(prefix + 'release readiness is invalid')
        if any(type(release.get(field)) is not bool for field in RELEASE_PREDICATES):
            errors.append(prefix + 'release predicates must be booleans')
        evidence = release.get('evidence')
        if not isinstance(evidence, dict) or not set(evidence) <= (RELEASE_PREDICATES | {'readiness'}):
            errors.append(prefix + 'release evidence map has unknown predicates')
            evidence = {}
        readiness_refs = evidence.get('readiness', []) if isinstance(evidence, dict) else []
        if release.get('readiness') != 'not_established' and (
                not isinstance(readiness_refs, list) or not readiness_refs):
            errors.append(prefix + 'readiness requires evidence before advancement')
        if release.get('readiness') == 'not_established' and readiness_refs:
            errors.append(prefix + 'not-established readiness must not cite acceptance evidence')
        candidate_digests = set()
        integrated_commits = set()
        published_commits = set()
        if not isinstance(readiness_refs, list):
            errors.append(prefix + 'readiness evidence must be a list')
        else:
            for index, reference in enumerate(readiness_refs):
                record, record_errors = programme_evidence_record(
                    root, reference, 'release_1_1.readiness',
                    prefix + f'readiness evidence[{index}]')
                errors.extend(record_errors)
                details = record.get('details', {})
                if details.get('readiness') != release.get('readiness'):
                    errors.append(prefix + f'readiness evidence[{index}] does not match current readiness')
                if details.get('candidate_sha256'):
                    candidate_digests.add(details['candidate_sha256'])
        for field in RELEASE_PREDICATES:
            refs = evidence.get(field, []) if isinstance(evidence, dict) else []
            if release.get(field) is True and (not isinstance(refs, list) or not refs):
                errors.append(prefix + field + ' requires evidence before becoming true')
            if release.get(field) is False and refs:
                errors.append(prefix + field + ' is false but cites acceptance evidence')
            if not isinstance(refs, list):
                errors.append(prefix + field + ' evidence must be a list')
            else:
                for index, reference in enumerate(refs):
                    record, record_errors = programme_evidence_record(
                        root, reference, 'release_1_1.' + field,
                        prefix + field + f' evidence[{index}]')
                    errors.extend(record_errors)
                    details = record.get('details', {})
                    if details.get('candidate_sha256'):
                        candidate_digests.add(details['candidate_sha256'])
                    if field == 'integrated' and not record_errors and details.get('commit'):
                        integrated_commits.add(details['commit'])
                    if field == 'published' and not record_errors and details.get('tag_commit'):
                        published_commits.add(details['tag_commit'])
        if len(candidate_digests) > 1:
            errors.append(prefix + 'release evidence refers to different candidate bytes')
        if published_commits and integrated_commits != published_commits:
            errors.append(prefix + 'published tag commit differs from a genuinely validated integrated main commit')
        if release.get('published') is True and not all(release.get(field) is True for field in (
                'implementation_complete', 'machine_qualified', 'experience_assessed', 'integrated')):
            errors.append(prefix + 'published requires every prior 1.1 predicate')
        if release.get('readiness') == 'supported' and release.get('published') is not True:
            errors.append(prefix + 'supported readiness requires published=true')

    full = status.get('full_spec_baseline')
    if not isinstance(full, dict) or set(full) != {'complete', 'continuing_maintenance_operational', 'evidence'}:
        errors.append(prefix + 'full_spec_baseline fields are incomplete or unknown')
    else:
        evidence = full.get('evidence')
        if not isinstance(evidence, dict) or not set(evidence) <= {'complete', 'continuing_maintenance_operational'}:
            errors.append(prefix + 'full-spec evidence map is malformed')
            evidence = {}
        for field in ('complete', 'continuing_maintenance_operational'):
            if type(full.get(field)) is not bool:
                errors.append(prefix + 'full-spec predicates must be booleans')
            refs = evidence.get(field, []) if isinstance(evidence, dict) else []
            if full.get(field) is True and (not isinstance(refs, list) or not refs):
                errors.append(prefix + 'full-spec ' + field + ' requires evidence')
            if full.get(field) is False and refs:
                errors.append(prefix + 'full-spec ' + field + ' is false but cites acceptance evidence')
            if not isinstance(refs, list):
                errors.append(prefix + 'full-spec ' + field + ' evidence must be a list')
            else:
                for index, reference in enumerate(refs):
                    _, record_errors = programme_evidence_record(
                        root, reference, 'full_spec_baseline.' + field,
                        prefix + field + f' evidence[{index}]')
                    errors.extend(record_errors)
        if full.get('complete') is True and full.get('continuing_maintenance_operational') is not True:
            errors.append(prefix + 'full-spec completion requires operational continuing maintenance')
    return errors


def local_link_errors(root: Path, page: Path, body: str) -> list[str]:
    errors = []
    for match in LINK_RE.finditer(body):
        raw = match[1].strip().strip('<>')
        if raw.startswith('#') or urlsplit(raw).scheme:
            continue
        target = unquote(raw.split('#', 1)[0].split('?', 1)[0])
        if not target:
            continue
        if '\\' in target:
            errors.append('nonportable link: ' + raw); continue
        dest = (page.parent / target).resolve()
        try:
            dest.relative_to(root.resolve())
        except ValueError:
            errors.append('link escapes bundle: ' + raw); continue
        if not dest.exists():
            errors.append('missing local link: ' + str(page.relative_to(root)) + ' -> ' + raw)
    return errors


def load_bundle(root: Path) -> dict:
    files = safe_files(root)
    manifest = load_json(root / 'manifest.json')
    docs, reqs, tasks, errors = {}, {}, {}, []
    for path in files:
        rel = path.relative_to(root).as_posix()
        if path.suffix == '.json':
            load_json(path)  # Duplicate keys/non-finite values are forbidden in all JSON artifacts.
        if path.suffix != '.md' or path.name in RESERVED:
            continue
        meta, body = parse_concept(read_text(path), rel)
        us = meta.get('usk_spec')
        if not isinstance(us, dict) or not ID_RE.fullmatch(str(us.get('id', ''))):
            errors.append(rel + ': invalid/missing usk_spec.id'); continue
        sid = us['id']
        if sid in docs:
            errors.append('duplicate spec ID: ' + sid)
        for key in ('title','description'):
            if not isinstance(meta.get(key), str) or not meta[key]:
                errors.append(rel + ': missing ' + key)
        if not ensure_timestamp(meta.get('generated', {}).get('at')):
            errors.append(rel + ': timezone-aware generated.at required')
        if us.get('profile') != 'usk-engineering/0.1.0-draft.1':
            errors.append(rel + ': unknown producer profile')
        if us.get('status') not in ('proposed','accepted','superseded','retired'):
            errors.append(rel + ': invalid proposal status')
        if not isinstance(us.get('depends_on'), list) or any(not isinstance(x,str) for x in us.get('depends_on',[])):
            errors.append(rel + ': invalid dependency list')
        sources = meta.get('sources', [])
        keys = [s.get('id') for s in sources if isinstance(s,dict)]
        if len(keys) != len(sources) or len(set(keys)) != len(keys) or any(not s.get('resource') for s in sources):
            errors.append(rel + ': malformed source references')
        for foot in set(re.findall(r'\[\^([^\]]+)\]', body)):
            if foot not in keys:
                errors.append(rel + ': footnote lacks source ID: ' + foot)
        docs[sid] = {'id':sid,'path':rel,'meta':meta,'body':body,'text':read_text(path),'sha256':digest(path.read_bytes())}
        for req in extract_requirements(body,sid,rel):
            if req['id'] in reqs:
                errors.append('duplicate requirement: '+req['id'])
            reqs[req['id']] = req
        if 'usk_task' in meta:
            task = meta['usk_task']
            tid = task.get('id','')
            if not re.fullmatch(r'USK-WU-\d{3}',tid):
                errors.append(rel + ': bad task ID')
            if tid in tasks:
                errors.append('duplicate task ID: ' + tid)
            tasks[tid] = {**task,'definition_path':rel,'definition_spec_id':sid}
        errors.extend(local_link_errors(root,path,body))
    cases_list=load_json(root / 'verification/acceptance-cases.json')['cases']
    cases={}
    for case in cases_list:
        cid=case.get('id','')
        if cid in cases: errors.append('duplicate acceptance ID: '+cid)
        cases[cid]=case
        if case.get('status') != 'not_run' or case.get('result_refs'):
            errors.append(cid + ': design catalogue must not carry execution claims')
        if case.get('spec_id') not in docs: errors.append(cid + ': missing spec')
        for field in ('fixture','procedure','expected','negative_control','oracle'):
            if not case.get(field): errors.append(cid + ': missing '+field)
        for rid in case.get('requirements',[]):
            if rid not in reqs: errors.append(cid + ': missing requirement '+rid)
    for rid, req in reqs.items():
        for cid in req['acceptance_ids']:
            if cid not in cases or rid not in cases[cid].get('requirements',[]):
                errors.append(rid + ': inconsistent acceptance trace '+cid)
    for tid, task in tasks.items():
        if task.get('status') != 'proposed' or task.get('authorizes_implementation') is not False:
            errors.append(tid + ': template must remain inactive/proposed')
        for field in ('steps','deliverables','allowed_paths','context_paths','stop_conditions','required_binding'):
            if not task.get(field): errors.append(tid + ': missing '+field)
        errors.extend(task_scope_errors(tid, task))
        for sid in task.get('spec_ids',[]):
            if sid not in docs: errors.append(tid + ': missing spec '+sid)
        for rid in task.get('requirement_ids',[]):
            if rid not in reqs: errors.append(tid + ': missing requirement '+rid)
        for cid in task.get('acceptance_ids',[]):
            if cid not in cases: errors.append(tid + ': missing acceptance '+cid)
    covered={rid for task in tasks.values() for rid in task.get('requirement_ids',[])}
    for rid in sorted(set(reqs)-covered): errors.append('requirement has no planned work: '+rid)
    errors.extend(graph_errors({k:v['meta']['usk_spec']['depends_on'] for k,v in docs.items()},'spec'))
    errors.extend(graph_errors({k:v.get('depends_on',[]) for k,v in tasks.items()},'task'))
    decisions = load_json(root/'plan/open-decisions.json')['decisions']
    errors.extend(decision_state_errors(root, decisions))
    for decision in decisions:
        for tid in decision.get('blocks',[]):
            if tid not in tasks: errors.append(decision['id']+': missing blocked task '+tid)
    release_selection = load_json(root/'plan/release-selection.json')
    errors.extend(release_selection_snapshot_errors(release_selection))
    programme_status = load_json(root/'plan/programme-status.json')
    errors.extend(programme_status_errors(root, programme_status, decisions))
    if errors:
        raise SpecError('\n'.join(errors))
    repository_status = load_json(root/'integration/repository-status.json')
    if repository_status.get('schema') != 'usk.spec.repository-status/1':
        raise SpecError('integration/repository-status.json: unsupported schema')
    adoption = repository_status.get('adoption')
    if not isinstance(adoption, dict) or adoption.get('status') not in ('adopted', 'not_adopted'):
        raise SpecError('integration/repository-status.json: invalid adoption projection')
    for field in ('scope', 'record', 'workunit_id'):
        if not isinstance(adoption.get(field), str) or not adoption[field]:
            raise SpecError('integration/repository-status.json: missing adoption.' + field)
    if repository_status.get('import_manifest_adoption') != manifest.get('adoption'):
        raise SpecError('integration/repository-status.json: import adoption provenance mismatch')
    if repository_status.get('authority_granted') is not False:
        raise SpecError('integration/repository-status.json must not grant execution authority')
    record = PurePosixPath(adoption['record'])
    if record.is_absolute() or '..' in record.parts or '\\' in adoption['record']:
        raise SpecError('integration/repository-status.json: adoption record must be repository-relative POSIX')
    if (root.parent/'.git').exists():
        record_path = root.parent/record
        if not record_path.is_file():
            raise SpecError('integration/repository-status.json: adoption record is missing')
        if digest(record_path.read_bytes()) != adoption.get('record_sha256'):
            raise SpecError('integration/repository-status.json: adoption record digest mismatch')
    return {'root':root,'files':files,'manifest':manifest,'repository_status':repository_status,
            'release_selection':release_selection,'programme_status':programme_status,
            'docs':docs,'requirements':reqs,'tasks':tasks,'cases':cases,'decisions':decisions}


def make_index(bundle: dict) -> dict:
    return {'schema':'usk.spec.derived-index/1','generator':'specctl/'+VERSION,'authority':'derived-not-normative',
        'spec_version':bundle['manifest']['spec_version'],
        'documents':[{'id':d['id'],'path':d['path'],'title':d['meta']['title'],'description':d['meta']['description'],
                     'sha256':d['sha256'],'depends_on':d['meta']['usk_spec']['depends_on']} for d in sorted(bundle['docs'].values(),key=lambda x:x['id'])],
        'requirements':[bundle['requirements'][k] for k in sorted(bundle['requirements'])],
        'tasks':[bundle['tasks'][k] for k in sorted(bundle['tasks'])],
        'acceptance':[{'id':c['id'],'spec_id':c['spec_id'],'requirements':c['requirements'],'status':'not_run'} for c in sorted(bundle['cases'].values(),key=lambda x:x['id'])]}


def write_file(path: Path, text: str) -> None:
    if path.is_symlink(): raise SpecError('symlink output refused: '+str(path))
    for parent in path.parents:
        if parent.exists() and parent.is_symlink(): raise SpecError('symlink output parent refused')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8',newline='\n') as stream:
        stream.write(text)


def index_outputs(bundle: dict) -> dict[str,str]:
    outputs={'derived/catalogue.json':json_text(make_index(bundle))}
    root=bundle['root']
    directories={Path('.'),Path('derived')}
    for p in safe_files(root):
        for parent in p.relative_to(root).parents:
            directories.add(parent)
    directories.discard(Path('tools/tests'))  # no knowledge listing needed inside executable-test package
    for directory in sorted(directories,key=str):
        depth=0 if directory==Path('.') else len(directory.parts)
        intro='---\nokf_version: "0.2"\n---\n\n' if depth==0 else ''
        title='Universal Setup specification' if depth==0 else directory.as_posix().replace('-',' ').title()
        text=intro+'# '+title+'\n\n'
        if depth==0:
            text+='**Proposed engineering baseline. No runtime or release authority is granted.**\n\n'
            text+='[Start here](start-here.md) · [Adoption](integration/adoption.md) · [Authority](governance/authority.md) · [Source scope](provenance/baseline.md) · [Task programme](execution/implementation-plan.md)\n\n'
            text+=f"{len(bundle['docs'])} concepts; {len(bundle['requirements'])} requirements; {len(bundle['cases'])} acceptance designs (not run); {len(bundle['tasks'])} inactive WorkUnits.\n\n"
        else:
            text+='[Bundle index]('+('../'*depth)+'index.md)\n\n'
        direct=sorted((d for d in bundle['docs'].values() if Path(d['path']).parent==directory),key=lambda d:d['path'])
        for d in direct:
            text+=f"- [{d['meta']['title']}]({Path(d['path']).name}) — `{d['id']}`. {d['meta']['description']}\n"
        children=sorted({p.relative_to(directory).parts[0] for p in directories if p!=directory and p.parent==directory})
        if children:
            text+='\n## Sections\n\n'
            for child in children:text+='- ['+child.replace('-',' ')+']('+child+'/index.md)\n'
        data_files=[p for p in safe_files(root) if p.relative_to(root).parent==directory and p.suffix!='.md' and p.name!='integrity.json']
        if directory == Path('derived') and not any(p.name == 'catalogue.json' for p in data_files):
            data_files.append(root/'derived/catalogue.json')
        if data_files:
            text+='\n## Data and tools\n\n'
            for p in data_files:text+='- ['+p.name+']('+p.name+')\n'
        outputs[(directory/'index.md').as_posix()]=text
    return outputs


def generate_index(bundle: dict, check: bool=False) -> dict:
    outputs=index_outputs(bundle)
    mismatches=[]
    for rel,text in outputs.items():
        path=bundle['root']/rel
        if check:
            if not path.exists() or read_text(path)!=text: mismatches.append(rel)
        else: write_file(path,text)
    if mismatches: raise SpecError('stale/missing derived views: '+', '.join(mismatches))
    return {'generated_files':len(outputs),'check_only':check,'status':'PASS'}


def resolve_id(bundle: dict, identifier: str) -> dict:
    if identifier in bundle['docs']: return bundle['docs'][identifier]
    if identifier in bundle['requirements']: return bundle['requirements'][identifier]
    if identifier in bundle['cases']: return bundle['cases'][identifier]
    if identifier in bundle['tasks']: return bundle['tasks'][identifier]
    raise SpecError('unknown ID: '+identifier)


def search(bundle: dict, query: str) -> list[dict]:
    terms=query.lower().split()
    if not terms: raise SpecError('empty query')
    result=[]
    for d in bundle['docs'].values():
        hay=(d['id']+' '+d['meta']['title']+' '+d['meta']['description']+' '+d['body']).lower()
        if all(t in hay for t in terms):
            result.append({'id':d['id'],'path':d['path'],'title':d['meta']['title'],'sha256':d['sha256'],
                           'score':sum(hay.count(t) for t in terms)})
    return sorted(result,key=lambda d:(-d['score'],d['id']))[:50]


def next_tasks(bundle:dict, completed:list[str]) -> dict:
    unknown=set(completed)-set(bundle['tasks'])
    if unknown:raise SpecError('unknown completed IDs: '+', '.join(sorted(unknown)))
    ready=[]
    for tid,t in sorted(bundle['tasks'].items()):
        if tid not in completed and set(t['depends_on'])<=set(completed):
            blockers=[d['id'] for d in bundle['decisions'] if d['status']=='open' and tid in d.get('blocks',[])]
            ready.append({'id':tid,'title':t['title'],'open_decisions':blockers,
                          'execution_authorized_by_template':False,
                          'campaign_binding_available':True,
                          'classification':'dependency-ready definition; derive exact campaign binding before work'})
    return {'status':'binding-required','assumed_completed':completed,'actual_completion_verified':False,
            'campaign':'USK-SPEC-TO-RELEASE-01','candidates':ready}


def status_report(bundle: dict) -> dict:
    adoption = bundle['repository_status']['adoption']
    release = bundle['release_selection']['decisions']['OD-008']['selected']
    profile = bundle['release_selection']['decisions']['OD-002']['selected']
    programme = bundle['programme_status']
    return {'spec_version':bundle['manifest']['spec_version'],
            'adoption':adoption['status'],
            'adoption_scope':adoption['scope'],
            'adoption_record':adoption['record'],
            'adoption_workunit':adoption['workunit_id'],
            'import_manifest_adoption':bundle['manifest']['adoption'],
            'development_train':release['development_train'],
            'target_release':release['target_release'],
            'release_product_name':release['product_name'],
            'selected_release_readiness':release['current_release_readiness'],
            'release_readiness':programme['release_1_1']['readiness'],
            'release_1_1_predicates':{
                key:programme['release_1_1'][key] for key in sorted(RELEASE_PREDICATES)},
            'full_spec_baseline':programme['full_spec_baseline'],
            'initial_profile':{'os_family':profile['os_family'],'architecture':profile['architecture'],
                               'filesystem':profile['mutation_filesystem'],
                               'graphical_adapter':profile['first_graphical_adapter']},
            'authority_granted_by_spec_projection':False,
            'campaign_authority':programme['campaign_authority'],
            'concepts':len(bundle['docs']),
            'requirements':len(bundle['requirements']),
            'product_acceptance_designs':len(bundle['cases']),
            'product_acceptance_executed':0,
            'proposed_workunits':len(bundle['tasks']),
            'open_decisions':len([x for x in bundle['decisions'] if x['status']=='open']),
            'current_runtime_readiness':'not_assessed_by_spec_tool'}


def context_pack(bundle:dict, task_id:str, max_bytes:int, full_closure:bool=False) -> tuple[dict,str]:
    if max_bytes<=0:raise SpecError('byte budget must be positive')
    task=bundle['tasks'].get(task_id)
    if not task:raise SpecError('unknown task: '+task_id)
    selected=set(AUTHORITY_IDS+task['spec_ids']+[task['definition_spec_id']])
    required=set(selected)
    pending=list(selected)
    while pending:
        sid=pending.pop()
        for dep in bundle['docs'][sid]['meta']['usk_spec']['depends_on']:
            if dep not in selected: selected.add(dep);pending.append(dep)
    transitive=selected-required
    reference_only=[] if full_closure else [{'id':sid,'path':bundle['docs'][sid]['path'],'sha256':bundle['docs'][sid]['sha256'],'title':bundle['docs'][sid]['meta']['title'],'role':'reference-only; retrieve before editing this contract'} for sid in sorted(transitive)]
    if not full_closure: selected=required
    refs=[];sections=[]
    for sid in sorted(selected):
        d=bundle['docs'][sid]
        refs.append({'id':sid,'path':d['path'],'sha256':d['sha256']})
        sections.append({'id':sid,'path':d['path'],'text':d['text']})
    cases=[bundle['cases'][cid] for cid in task['acceptance_ids']]
    pack={'schema':'usk.spec.context/1','generator':'specctl/'+VERSION,'purpose':task['title'],'task_id':task_id,
          'source_refs':refs,'task':task,'sections':sections,'acceptance_designs':cases,
          'scope':{'context_paths':task['context_paths'],'allowed_paths':task['allowed_paths'],
                   'read_only_paths':task['read_only_paths'],'forbidden_paths':task['forbidden_paths'],
                   'forbidden_operations':task['forbidden_operations']},
          'open_decisions':[x for x in bundle['decisions'] if x['status']=='open'],
          'execution_authorized_by_packet':False,
          'required_binding':task['required_binding'],
          'runtime_tests_executed':False,'byte_budget':max_bytes,'full_closure':full_closure,
          'dependency_refs':reference_only,'omissions':[{'id':r['id'],'reason':'transitive reference; not task-declared full-reading input; fetch before changing its semantics'} for r in reference_only],
          'source_commit_observed':bundle['manifest']['source_commit_observed'],
          'source_commit_must_be_rebound_at_admission':True}
    raw=json_text(pack).encode('utf-8')
    if len(raw)>max_bytes:
        raise SpecError(f'required context is {len(raw)} UTF-8 bytes; budget is {max_bytes}; refusing silent truncation; split the task or raise the explicit budget')
    markdown='# '+task_id+' — '+task['title']+'\n\n'
    markdown+='Proposed context only. Revalidate source and spec hashes, then pair it with an exact campaign task binding. This packet alone authorizes no execution, endpoint effect, integration, signing or publication.\n\n'
    for section in sections:
        markdown+='\n---\n\n## Context: '+section['id']+' (`'+section['path']+'`)\n\n'+section['text']
    markdown+='\n---\n\n## Dependency references not embedded\n\nDo not treat these as read. Retrieve before modifying their contracts; use --full-closure for complete transitive content.\n\n'+''.join('- `'+r['id']+'` — `'+r['path']+'`, SHA-256 `'+r['sha256']+'`\n' for r in reference_only)
    markdown+='\n---\n\n## Acceptance designs (not run)\n\n```json\n'+json_text(cases)+'```\n'
    # Both individual files are bounded; budget includes the actual complete JSON packet.
    if len(markdown.encode('utf-8'))>max_bytes:
        raise SpecError('rendered context exceeds byte budget; refusing silent truncation')
    return pack,markdown


def verify_context(bundle:dict, pack:dict) -> dict:
    mismatches=[]
    for ref in pack.get('source_refs',[]):
        d=bundle['docs'].get(ref.get('id'))
        if not d or d['path']!=ref.get('path') or d['sha256']!=ref.get('sha256'):
            mismatches.append(ref.get('id','<missing>'))
    if mismatches:raise SpecError('stale context: '+', '.join(mismatches))
    if pack.get('execution_authorized_by_packet') is not False: raise SpecError('context cannot grant execution')
    expected,_=context_pack(bundle,pack.get('task_id',''),pack.get('byte_budget',0),pack.get('full_closure',False))
    if pack != expected: raise SpecError('context content/metadata differs from bound canonical inputs')
    return {'status':'PASS','source_files_checked':len(pack.get('source_refs',[])),'runtime_authority':False}


def output_directory(root:Path, output:Path) -> Path:
    output=output.absolute()
    for p in [output]+list(output.parents):
        if p.exists() and p.is_symlink():raise SpecError('symlink output refused: '+str(p))
    try:
        output.resolve().relative_to(root.resolve())
        raise SpecError('output directory must be outside spec/')
    except ValueError:
        pass
    repository=root.resolve().parent
    if (repository/'.git').exists():
        try:
            output.resolve().relative_to(repository)
            raise SpecError('output must be outside the repository checkout')
        except ValueError:
            pass
    if output.exists() and any(output.iterdir()):raise SpecError('output directory must be new or empty: '+str(output))
    output.mkdir(parents=True,exist_ok=True)
    return output


def impact(bundle:dict, paths:list[str]) -> dict:
    matched=set();unmapped=[]
    for path in paths:
        if PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or '\\' in path:
            raise SpecError('changed paths must be repository-relative POSIX paths')
        hits={tid for tid,t in bundle['tasks'].items() if any(fnmatch.fnmatchcase(path,p) for p in t['allowed_paths'])}
        if path.startswith('spec/'):
            rel=path[5:]
            changed_docs={sid for sid,d in bundle['docs'].items() if d['path']==rel}
            hits|={tid for tid,t in bundle['tasks'].items() if changed_docs.intersection(t['spec_ids'])}
        if not hits:unmapped.append(path)
        matched|=hits
    # Conservative dependency propagation.
    while True:
        new={tid for tid,t in bundle['tasks'].items() if set(t['depends_on']) & matched}
        if new<=matched:break
        matched|=new
    selected=sorted(matched)
    return {'classification':'broad-review-required' if unmapped else 'conservative-candidates-only',
            'unmapped_paths':unmapped,'task_ids':selected,
            'acceptance_ids':sorted({c for t in selected for c in bundle['tasks'][t]['acceptance_ids']}),
            'runtime_tests_executed':False,'can_omit_other_tests':False}


def aide_workunit(bundle:dict, task_id:str) -> dict:
    t=bundle['tasks'].get(task_id)
    if not t:raise SpecError('unknown task: '+task_id)
    return {'apiVersion':'aide/v1','kind':'WorkUnit',
      'metadata':{'id':task_id,'createdAt':bundle['manifest']['created_at'],'sourcePath':'spec/'+t['definition_path'],
        'producer':{'name':'usk-specctl','version':VERSION},
        'compatibility':{'schemaVersion':'1','protocolVersion':'1','minReaderVersion':'1','minWriterVersion':'1','featureFlags':[]},
        'usk_spec_export':{'status':'proposed','schema_validation':'not_run','pinned_aide':load_json(bundle['root']/'provenance/pins.json')['aide']['commit']}},
      'spec':{'task_id':task_id,'title':t['title'],'work_type':'check' if t['phase']=='M0' else 'build',
        'authorizes_implementation':False,'check_only':True,'acceptance_review':False,
        'implementation_scope':'; '.join(t['deliverables']),
        'stop_state':'proposed definition; pair with exact campaign binding or external queue authority',
        'predecessors':t['depends_on'],'dependencies':t['depends_on'],
        'scope':{'context_input_paths':t['context_paths'],'allowed_paths':t['allowed_paths'],
                 'forbidden_paths':t['forbidden_paths'],'read_only_review_paths':t['read_only_paths'],
                 'forbidden_operations':t['forbidden_operations']},
        'validation':{'commands':[{'command':' '.join(c['argv']),'status':'NOT_RUN','notes':c['scope']+'; display only, never executed by exporter'} for c in t['checks']]},
        'evidence_requirements':t['acceptance_ids'],
        'explicit_non_capabilities':['template grants no authority','no native execution by exporter','no queue admission by exporter','no direct protected Git write','no unqualified signing or publication']},
      'status':{'phase':'planned','result':'NOT_RUN','validated':False,'validation_errors':[],
                'validation_warnings':['Exported design; validate against pinned AIDE schema and admit separately.']}}


def aide_context(bundle:dict, pack:dict) -> dict:
    return {'apiVersion':'aide/v2','kind':'ContextPack',
      'metadata':{'id':'USK-CONTEXT-'+pack['task_id'],'createdAt':bundle['manifest']['created_at'],
       'sourcePath':'spec/'+pack['task']['definition_path'],'producer':{'name':'usk-specctl','version':VERSION},
       'compatibility':{'schemaVersion':'2','protocolVersion':'2','minReaderVersion':'2','minWriterVersion':'2','featureFlags':[]}},
      'spec':{'context_pack_ref':'urn:usk:context:'+digest(json_text(pack).encode()),'purpose':pack['purpose'],
       'source_refs':pack['source_refs'],'sections':pack['sections'],
       'context_input_paths':pack['scope']['context_paths'],
       'allowed_paths':pack['scope']['allowed_paths'],'read_only_paths':pack['scope']['read_only_paths'],
       'forbidden_paths':pack['scope']['forbidden_paths'],
       'forbidden_operations':pack['scope']['forbidden_operations'],'required_capability_refs':[],
       'required_evidence_refs':[], 'required_acceptance_definition_ids':pack['task']['acceptance_ids'],
       'reference_only_dependencies':pack.get('dependency_refs',[]),
       'explicit_non_capabilities':['no queue admission','no worker execution','no model call','no mutation grant','no proof of runtime qualification']},
      'status':{'validation_performed':False,'validation_status':'NOT_RUN','model_call_performed':False,
       'network_call_performed':False,'embedding_performed':False,'agent_started':False,'worker_started':False,
       'command_executed':False,'patch_applied':False,'repository_mutated':False,'trusted':False}}


def validate_aide_external(bundle:dict, exported:dict, checkout:Path, kind:str) -> dict:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise SpecError('jsonschema unavailable; cannot claim AIDE schema validation') from exc
    pin=load_json(bundle['root']/'provenance/pins.json')['aide']
    name='workunit' if kind=='WorkUnit' else 'context'
    path=checkout/pin[name+'_schema']
    if not path.is_file():raise SpecError('pinned AIDE schema missing: '+str(path))
    data=path.read_bytes()
    blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if blob!=pin[name+'_git_blob']:raise SpecError('AIDE schema Git blob mismatch; review a new pin before export validation')
    schema=json_loads(data.decode('utf-8'))
    require_local_schema(schema)
    validator=Draft202012Validator(schema)
    errors=list(validator.iter_errors(exported))
    if errors:raise SpecError('AIDE schema validation failed: '+'; '.join(e.message for e in errors))
    return {'status':'PASS','kind':kind,'schema_path':pin[name+'_schema'],'git_blob':blob,
            'scope':'schema shape only; not AIDE runtime/queue/grant admission'}


def require_local_schema(schema:Any) -> None:
    """Reject external references: schema validation must not acquire network capability."""
    todo=[schema]
    while todo:
        value=todo.pop()
        if isinstance(value,dict):
            for key,item in value.items():
                if key in ('$ref','$dynamicRef') and (not isinstance(item,str) or not item.startswith('#')):
                    raise SpecError('external schema reference refused in offline validator')
                todo.append(item)
        elif isinstance(value,list):todo.extend(value)


def schema_check(bundle:dict) -> dict:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise SpecError('jsonschema unavailable: schema-check NOT_RUN') from exc
    checks=0
    for item in load_json(bundle['root']/'prototypes/catalogue.json')['items']:
        schema=load_json(bundle['root']/item['schema'])
        require_local_schema(schema)
        Draft202012Validator.check_schema(schema)
        errors=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(load_json(bundle['root']/item['example'])))
        if errors:raise SpecError(item['example']+': '+'; '.join(e.message for e in errors))
        checks+=1
    schema=load_json(bundle['root']/'schema/concept-metadata.schema.json')
    require_local_schema(schema)
    for doc in bundle['docs'].values():
        errors=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(doc['meta']))
        if errors:raise SpecError(doc['path']+': '+'; '.join(e.message for e in errors))
        checks+=1
    schema=load_json(bundle['root']/'schema/acceptance-catalogue.schema.json')
    require_local_schema(schema)
    errors=list(Draft202012Validator(schema).iter_errors(load_json(bundle['root']/'verification/acceptance-cases.json')))
    if errors:raise SpecError('acceptance schema: '+'; '.join(e.message for e in errors))
    checks+=1
    schema=load_json(bundle['root']/'schema/programme-status.schema.json')
    require_local_schema(schema)
    Draft202012Validator.check_schema(schema)
    errors=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(bundle['programme_status']))
    if errors:raise SpecError('programme status schema: '+'; '.join(e.message for e in errors))
    return {'status':'PASS','instances_checked':checks+1,'scope':'spec/prototype syntax and shape only; no runtime conformance'}


def seal(root:Path,check:bool=False) -> dict:
    files=[p for p in safe_files(root) if p.relative_to(root).as_posix()!='integrity.json']
    rows=[{'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())} for p in files]
    result={'schema':'usk.spec.integrity/1','algorithm':'sha256','self_excluded':'integrity.json',
            'aggregate_sha256':digest(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()),'files':rows}
    if check:
        if not (root/'integrity.json').exists() or load_json(root/'integrity.json')!=result:
            raise SpecError('integrity inventory mismatch; modifications require deliberate re-sealing after review')
    else:write_file(root/'integrity.json',json_text(result))
    return {'status':'PASS','files':len(rows),'aggregate_sha256':result['aggregate_sha256'],'check_only':check}


def package(root:Path,output:Path) -> dict:
    seal(root,True)
    if output.is_symlink():raise SpecError('symlink archive output refused')
    if output.exists():raise SpecError('archive output already exists; refusing overwrite')
    try:
        output.resolve().relative_to(root.resolve())
        raise SpecError('archive must be outside spec/')
    except ValueError:pass
    for p in output.absolute().parents:
        if p.exists() and p.is_symlink():raise SpecError('symlink output parent refused')
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as zf:
        for path in safe_files(root):
            name='spec/'+path.relative_to(root).as_posix()
            info=zipfile.ZipInfo(name,date_time=(2026,9,20,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.create_system=3
            info.external_attr=(0o100644<<16)
            zf.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    return {'archive':str(output),'bytes':output.stat().st_size,'sha256':digest(output.read_bytes())}


def render_docs(bundle:dict,out:Path) -> dict:
    output_directory(bundle['root'],out)
    count=0
    # Keep task and source-control detail in spec; publish architecture/user/developer reference views.
    selected=[d for d in bundle['docs'].values() if not d['path'].startswith('plan/tasks/') and d['id']!='USK-S-SCOPE']
    for d in selected:
        banner='> Proposed Universal Setup design reference. Not a current capability/support claim.\n> Generated from `spec/'+d['path']+'`, `'+d['id']+'`, SHA-256 `'+d['sha256']+'`.\n\n'
        write_file(out/d['path'],banner+d['body']);count+=1
    listing='# Universal Setup — proposed design reference\n\nGenerated publication view. The OKF specification remains the engineering source; runtime contracts remain separately governed.\n\n'
    for d in sorted(selected,key=lambda d:d['path']):listing+='- ['+d['meta']['title']+']('+d['path']+')\n'
    write_file(out/'index.md',listing)
    for relative in ('provenance/sources.json','provenance/pins.json','provenance/inputs.json'):
        write_file(out/relative,read_text(bundle['root']/relative))
    return {'status':'PASS','pages':count+1,'output':str(out),'authority':'derived proposed documentation'}


def main(argv:list[str]|None=None) -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    sub=ap.add_subparsers(dest='cmd',required=True)
    sub.add_parser('validate');sub.add_parser('status');sub.add_parser('schema-check')
    p=sub.add_parser('index');p.add_argument('--check',action='store_true')
    p=sub.add_parser('search');p.add_argument('query')
    p=sub.add_parser('show');p.add_argument('id')
    p=sub.add_parser('next');p.add_argument('--completed',nargs='*',default=[])
    p=sub.add_parser('context');p.add_argument('task');p.add_argument('--max-bytes',type=int,default=64000);p.add_argument('--full-closure',action='store_true');p.add_argument('--output-dir',type=Path,required=True)
    p=sub.add_parser('context-check');p.add_argument('packet',type=Path)
    p=sub.add_parser('impact');p.add_argument('--path',action='append',required=True)
    p=sub.add_parser('aide-export');p.add_argument('task');p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--aide-checkout',type=Path);p.add_argument('--max-bytes',type=int,default=64000);p.add_argument('--full-closure',action='store_true')
    p=sub.add_parser('render-docs');p.add_argument('--output-dir',type=Path,required=True)
    p=sub.add_parser('seal');p.add_argument('--check',action='store_true')
    p=sub.add_parser('package');p.add_argument('--output',type=Path,required=True)
    args=ap.parse_args(argv)
    try:
        root=args.root.absolute()
        b=load_bundle(root)
        if args.cmd=='validate':result={'status':'PASS','concepts':len(b['docs']),'requirements':len(b['requirements']),'acceptance_designs':len(b['cases']),'inactive_workunits':len(b['tasks']),'runtime_tests_run':0}
        elif args.cmd=='status':result=status_report(b)
        elif args.cmd=='index':result=generate_index(b,args.check)
        elif args.cmd=='schema-check':result=schema_check(b)
        elif args.cmd=='search':result=search(b,args.query)
        elif args.cmd=='show':
            found=resolve_id(b,args.id)
            if 'text' in found:print(found['text'],end='');return 0
            result=found
        elif args.cmd=='next':result=next_tasks(b,args.completed)
        elif args.cmd=='context':
            packet,md=context_pack(b,args.task,args.max_bytes,args.full_closure);out=output_directory(root,args.output_dir)
            write_file(out/'context.json',json_text(packet));write_file(out/'context.md',md)
            result={'status':'PASS','output':str(out),'packet_sha256':digest((out/'context.json').read_bytes()),'bytes':(out/'context.json').stat().st_size,'execution_authorized_by_packet':False}
        elif args.cmd=='context-check':result=verify_context(b,load_json(args.packet))
        elif args.cmd=='impact':result=impact(b,args.path)
        elif args.cmd=='aide-export':
            packet,_=context_pack(b,args.task,args.max_bytes,args.full_closure);wu=aide_workunit(b,args.task);cp=aide_context(b,packet)
            checks=[]
            if args.aide_checkout:
                checks=[validate_aide_external(b,wu,args.aide_checkout,'WorkUnit'),validate_aide_external(b,cp,args.aide_checkout,'ContextPack')]
            out=output_directory(root,args.output_dir)
            write_file(out/'workunit.json',json_text(wu));write_file(out/'context-pack.json',json_text(cp))
            result={'status':'PASS' if checks else 'EXPORTED_SCHEMA_VALIDATION_NOT_RUN','schema_checks':checks,'output':str(out),'admitted':False,'live_queue_changed':False,'authority_granted':False}
            write_file(out/'export-report.json',json_text(result))
        elif args.cmd=='render-docs':result=render_docs(b,args.output_dir)
        elif args.cmd=='seal':result=seal(root,args.check)
        elif args.cmd=='package':result=package(root,args.output)
        else:raise SpecError('unknown command')
        print(json_text(result),end='');return 0
    except (SpecError,OSError,KeyError,TypeError,ValueError,RecursionError) as exc:
        print('specctl: '+str(exc),file=sys.stderr);return 2

if __name__=='__main__':
    sys.exit(main())
