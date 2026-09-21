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
        for field in ('steps','deliverables','allowed_paths','context_paths','stop_conditions','required_grant'):
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
    for decision in decisions:
        for tid in decision.get('blocks',[]):
            if tid not in tasks: errors.append(decision['id']+': missing blocked task '+tid)
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
            ready.append({'id':tid,'title':t['title'],'open_decisions':blockers,'execution_authorized':False,
                          'classification':'dependency-ready proposal only; verify real queue and grants'})
    return {'status':'proposal-only','assumed_completed':completed,'actual_completion_verified':False,'candidates':ready}


def status_report(bundle: dict) -> dict:
    adoption = bundle['repository_status']['adoption']
    return {'spec_version':bundle['manifest']['spec_version'],
            'adoption':adoption['status'],
            'adoption_scope':adoption['scope'],
            'adoption_record':adoption['record'],
            'adoption_workunit':adoption['workunit_id'],
            'import_manifest_adoption':bundle['manifest']['adoption'],
            'authority_granted':False,
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
          'execution_authorized':False,'runtime_tests_executed':False,'byte_budget':max_bytes,'full_closure':full_closure,
          'dependency_refs':reference_only,'omissions':[{'id':r['id'],'reason':'transitive reference; not task-declared full-reading input; fetch before changing its semantics'} for r in reference_only],
          'source_commit_observed':bundle['manifest']['source_commit_observed'],
          'source_commit_must_be_rebound_at_admission':True}
    raw=json_text(pack).encode('utf-8')
    if len(raw)>max_bytes:
        raise SpecError(f'required context is {len(raw)} UTF-8 bytes; budget is {max_bytes}; refusing silent truncation; split the task or raise the explicit budget')
    markdown='# '+task_id+' — '+task['title']+'\n\n'
    markdown+='Proposed context only. Revalidate source, grants and spec hashes. No installation, execution, protected integration or publication is authorized.\n\n'
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
    if pack.get('execution_authorized') is not False: raise SpecError('context cannot grant execution')
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
        'implementation_scope':'; '.join(t['deliverables']),'stop_state':'proposed; awaiting actual queue/grant admission',
        'predecessors':t['depends_on'],'dependencies':t['depends_on'],
        'scope':{'context_input_paths':t['context_paths'],'allowed_paths':t['allowed_paths'],
                 'forbidden_paths':t['forbidden_paths'],'read_only_review_paths':t['read_only_paths'],
                 'forbidden_operations':t['forbidden_operations']},
        'validation':{'commands':[{'command':' '.join(c['argv']),'status':'NOT_RUN','notes':c['scope']+'; display only, never executed by exporter'} for c in t['checks']]},
        'evidence_requirements':t['acceptance_ids'],
        'explicit_non_capabilities':['no grant','no native execution','no queue admission','no protected Git write','no signing or publication']},
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
            result={'status':'PASS','output':str(out),'packet_sha256':digest((out/'context.json').read_bytes()),'bytes':(out/'context.json').stat().st_size,'execution_authorized':False}
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
