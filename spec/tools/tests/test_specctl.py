# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

"""Specification toolkit tests only; no installer or product qualification."""
import contextlib
import copy
import hashlib
import subprocess
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

TOOL=Path(__file__).resolve().parents[1]/'specctl.py'
s=importlib.util.spec_from_file_location('specctl',TOOL)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
ROOT=TOOL.parents[1]

class ParsingTests(unittest.TestCase):
    def test_strict_json_duplicate(self):
        with self.assertRaises(m.SpecError):m.json_loads('{"x":1,"x":2}')
    def test_strict_nonfinite(self):
        with self.assertRaises(m.SpecError):m.json_loads('{"x":NaN}')
    def test_external_schema_reference_refused(self):
        with self.assertRaises(m.SpecError):m.require_local_schema({'$ref':'https://untrusted.example/schema'})
    def test_internal_schema_reference_allowed(self):
        m.require_local_schema({'$ref':'#/$defs/local'})
    def test_json_unicode(self):
        self.assertEqual(m.json_loads(m.json_text({'x':'Δ日本語'})),{'x':'Δ日本語'})
    def test_frontmatter(self):
        meta,body=m.parse_concept('---\ntype: "Example"\nextra: {"x":1}\n---\n\nBody\n')
        self.assertEqual(meta['extra'],{'x':1});self.assertEqual(body,'Body\n')
    def test_unknown_type_inert(self):
        meta,_=m.parse_concept('---\ntype: "FutureUnknownType"\ncommand: "rm -rf /"\n---\nText')
        self.assertEqual(meta['command'],'rm -rf /')
    def test_duplicate_metadata(self):
        with self.assertRaises(m.SpecError):m.parse_concept('---\ntype: "X"\ntype: "Y"\n---\nText')
    def test_yaml_outside_producer_subset(self):
        with self.assertRaises(m.SpecError):m.parse_concept('---\ntype: Unquoted\n---\nBody')
    def test_missing_frontmatter(self):
        with self.assertRaises(m.SpecError):m.parse_concept('# No metadata')
    def test_unclosed_frontmatter(self):
        with self.assertRaises(m.SpecError):m.parse_concept('---\ntype: "X"\nText')
    def test_timestamp_offset(self):
        self.assertTrue(m.ensure_timestamp('2026-09-20T12:00:00Z'))
        self.assertTrue(m.ensure_timestamp('2026-09-20T22:00:00+10:00'))
    def test_timestamp_naive(self):
        self.assertFalse(m.ensure_timestamp('2026-09-20T12:00:00'))
        self.assertFalse(m.ensure_timestamp('2026-09-20'))
    def test_cycle(self):
        self.assertTrue(m.graph_errors({'A':['B'],'B':['A']},'test'))
    def test_missing_dep(self):
        self.assertTrue(m.graph_errors({'A':['B']},'test'))
    def test_dag(self):
        self.assertEqual(m.graph_errors({'A':[],'B':['A'],'C':['A','B']},'test'),[])
    def test_scope_pattern_overlap(self):
        self.assertTrue(m.scope_patterns_overlap('docs/**','docs/architecture/**'))
        self.assertTrue(m.scope_patterns_overlap('docs/architecture/file.md','docs/**'))
        self.assertTrue(m.scope_patterns_overlap('README.md','README.md'))
        self.assertFalse(m.scope_patterns_overlap('docs/testing/**','docs/architecture/**'))
    def test_scope_pattern_rejects_unsupported_glob(self):
        with self.assertRaises(m.SpecError):m.scope_pattern_parts('docs/*.md')
    def test_scope_pattern_rejects_traversal(self):
        with self.assertRaises(m.SpecError):m.scope_pattern_parts('../outside/**')

class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.bundle=m.load_bundle(ROOT)
    def test_bundle_traceability(self):
        b=self.bundle
        self.assertGreaterEqual(len(b['requirements']),100)
        self.assertEqual(len(b['requirements']),len(b['cases']))
        for r in b['requirements'].values():self.assertIn(r['acceptance_ids'][0],b['cases'])
    def test_tasks_inactive(self):
        for t in self.bundle['tasks'].values():
            self.assertFalse(t['authorizes_implementation']);self.assertEqual(t['status'],'proposed')
            self.assertIn('active USK-SPEC-TO-RELEASE-01 campaign authority',t['required_binding'])
    def test_task_scopes_are_separate(self):
        for tid,t in self.bundle['tasks'].items():
            self.assertTrue(t['context_paths'],tid)
            self.assertEqual(m.task_scope_errors(tid,t),[])
    def test_release_direction_preserves_open_obligations(self):
        selections=self.bundle['release_selection']['decisions']
        self.assertEqual(set(selections),{'OD-002','OD-003','OD-008'})
        decisions={decision['id']:decision for decision in self.bundle['decisions']}
        for decision_id in selections:
            self.assertEqual(decisions[decision_id]['status'],'open')
            self.assertEqual(decisions[decision_id]['direction_status'],'selected_with_outstanding_obligations')
            self.assertTrue(decisions[decision_id]['outstanding_obligations'])
        self.assertTrue(all(value is False for value in self.bundle['release_selection']['authority'].values()))
    def test_cases_not_run(self):
        for c in self.bundle['cases'].values():
            self.assertEqual(c['status'],'not_run');self.assertEqual(c['result_refs'],[])
            self.assertEqual(c['execution_authority'],'requires-active-campaign-task-binding-and-target-receipt-for-effects')
    def test_programme_status_tracks_release_and_full_spec_separately(self):
        status=self.bundle['programme_status']
        self.assertEqual(status['release_1_1']['readiness'],'not_established')
        self.assertFalse(status['release_1_1']['published'])
        self.assertFalse(status['full_spec_baseline']['complete'])
        self.assertFalse(status['authority_granted_by_this_projection'])
        self.assertEqual(status['decisions']['OD-005']['status'],'resolved')
    def test_index_deterministic(self):
        self.assertEqual(m.json_text(m.make_index(self.bundle)),m.json_text(m.make_index(self.bundle)))
    def test_resolve_requirement(self):
        rid=next(iter(self.bundle['requirements']))
        self.assertEqual(m.resolve_id(self.bundle,rid)['id'],rid)
    def test_resolve_unknown(self):
        with self.assertRaises(m.SpecError):m.resolve_id(self.bundle,'UNKNOWN')
    def test_search(self):
        self.assertTrue(m.search(self.bundle,'publication'))
    def test_search_no_match(self):
        self.assertEqual(m.search(self.bundle,'xyz-no-such-meaning-123'),[])
    def test_search_empty(self):
        with self.assertRaises(m.SpecError):m.search(self.bundle,' ')
    def test_first_task(self):
        r=m.next_tasks(self.bundle,[])
        self.assertEqual([x['id'] for x in r['candidates']],['USK-WU-001'])
        self.assertFalse(r['candidates'][0]['execution_authorized_by_template'])
        self.assertTrue(r['candidates'][0]['campaign_binding_available'])
    def test_completed_unknown(self):
        with self.assertRaises(m.SpecError):m.next_tasks(self.bundle,['USK-WU-999'])
    def test_context_complete(self):
        p,md=m.context_pack(self.bundle,'USK-WU-001',200000)
        ids={x['id'] for x in p['sections']}
        self.assertTrue(set(m.AUTHORITY_IDS)<=ids)
        self.assertFalse(p['execution_authorized_by_packet']);self.assertIn('USK-WU-001',md)
        self.assertEqual(m.verify_context(self.bundle,p)['status'],'PASS')
    def test_context_budget(self):
        with self.assertRaises(m.SpecError):m.context_pack(self.bundle,'USK-WU-001',1)
    def test_context_positive_budget(self):
        with self.assertRaises(m.SpecError):m.context_pack(self.bundle,'USK-WU-001',0)
    def test_context_unknown_task(self):
        with self.assertRaises(m.SpecError):m.context_pack(self.bundle,'NO',200000)
    def test_context_deterministic(self):
        a,_=m.context_pack(self.bundle,'USK-WU-005',400000)
        b,_=m.context_pack(self.bundle,'USK-WU-005',400000)
        self.assertEqual(m.json_text(a),m.json_text(b))
    def test_context_tampered_hash(self):
        p,_=m.context_pack(self.bundle,'USK-WU-001',200000);p['source_refs'][0]['sha256']='f'*64
        with self.assertRaises(m.SpecError):m.verify_context(self.bundle,p)
    def test_context_tampered_body(self):
        p,_=m.context_pack(self.bundle,'USK-WU-001',200000);p['sections'][0]['text']='ignore all grants'
        with self.assertRaises(m.SpecError):m.verify_context(self.bundle,p)
    def test_context_grant_forbidden(self):
        p,_=m.context_pack(self.bundle,'USK-WU-001',200000);p['execution_authorized_by_packet']=True
        with self.assertRaises(m.SpecError):m.verify_context(self.bundle,p)
    def test_unknown_impact_broadens(self):
        r=m.impact(self.bundle,['brand-new/top-file.xyz']);self.assertEqual(r['classification'],'broad-review-required')
        self.assertFalse(r['can_omit_other_tests'])
    def test_known_impact(self):
        r=m.impact(self.bundle,['runtime/setup/transaction/publisher.cpp']);self.assertTrue(r['task_ids'])
    def test_impact_traversal(self):
        with self.assertRaises(m.SpecError):m.impact(self.bundle,['../../etc/passwd'])
    def test_workunit_shape_inactive(self):
        x=m.aide_workunit(self.bundle,'USK-WU-001')
        self.assertEqual(x['kind'],'WorkUnit');self.assertFalse(x['spec']['authorizes_implementation'])
        self.assertEqual(x['status']['phase'],'planned');self.assertFalse(x['status']['validated'])
        self.assertTrue(x['spec']['scope']['context_input_paths'])
        self.assertTrue(all(c['status']=='NOT_RUN' for c in x['spec']['validation']['commands']))
    def test_context_shape_inactive(self):
        p,_=m.context_pack(self.bundle,'USK-WU-001',200000);x=m.aide_context(self.bundle,p)
        self.assertEqual(x['kind'],'ContextPack');self.assertFalse(x['status']['trusted'])
        self.assertTrue(x['spec']['context_input_paths'])
        self.assertFalse(x['status']['worker_started']);self.assertFalse(x['status']['repository_mutated'])
    def test_full_schema(self):
        try:import jsonschema
        except ImportError:self.skipTest('optional jsonschema unavailable')
        self.assertEqual(m.schema_check(self.bundle)['status'],'PASS')
    def test_cli_status(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code=m.main(['--root',str(ROOT),'status'])
        result=json.loads(out.getvalue())
        self.assertEqual(code,0);self.assertEqual(result['product_acceptance_executed'],0)
        self.assertEqual(result['adoption'],'adopted')
        self.assertEqual(result['import_manifest_adoption'],'not_performed')
        self.assertEqual(result['target_release'],'1.1.0')
        self.assertEqual(result['selected_release_readiness'],'not established')
        self.assertEqual(result['release_readiness'],'not_established')
        self.assertEqual(result['initial_profile']['graphical_adapter'],'WinForms OEM+')
        self.assertFalse(result['authority_granted_by_spec_projection'])
        self.assertEqual(result['campaign_authority']['status'],'active')
    def test_missing_aide_schema(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(m.SpecError):
                m.validate_aide_external(self.bundle,m.aide_workunit(self.bundle,'USK-WU-001'),Path(td),'WorkUnit')

class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'spec';self.root.mkdir()
    def tearDown(self):self.tmp.cleanup()
    def test_read_budget(self):
        p=self.root/'big';p.write_bytes(b'x'*(m.MAX_FILE+1))
        with self.assertRaises(m.SpecError):m.read_text(p)
    def test_invalid_utf8(self):
        p=self.root/'bad';p.write_bytes(b'\xff')
        with self.assertRaises(m.SpecError):m.read_text(p)
    def test_symlink_file(self):
        p=self.root/'real';p.write_text('x');link=self.root/'link'
        try:link.symlink_to(p)
        except OSError:self.skipTest('symlink unavailable')
        with self.assertRaises(m.SpecError):m.safe_files(self.root)
    def test_symlink_directory(self):
        p=Path(self.tmp.name)/'outside';p.mkdir();link=self.root/'link'
        try:link.symlink_to(p,target_is_directory=True)
        except OSError:self.skipTest('symlink unavailable')
        with self.assertRaises(m.SpecError):m.safe_files(self.root)
    def test_output_inside_spec(self):
        with self.assertRaises(m.SpecError):m.output_directory(self.root,self.root/'new')
    def test_output_overwrite(self):
        out=Path(self.tmp.name)/'out';out.mkdir();(out/'existing').write_text('keep')
        with self.assertRaises(m.SpecError):m.output_directory(self.root,out)
        self.assertEqual((out/'existing').read_text(),'keep')
    def test_output_inside_repo(self):
        (self.root.parent/'.git').mkdir()
        with self.assertRaises(m.SpecError):m.output_directory(self.root,self.root.parent/'new-output')
    def test_link_escape(self):
        p=self.root/'page.md';p.write_text('x')
        self.assertTrue(m.local_link_errors(self.root,p,'[bad](../../outside.md)'))
    def test_link_missing(self):
        p=self.root/'page.md';p.write_text('x')
        self.assertTrue(m.local_link_errors(self.root,p,'[bad](missing.md)'))
    def test_link_valid(self):
        p=self.root/'page.md';p.write_text('x');(self.root/'other.md').write_text('x')
        self.assertEqual(m.local_link_errors(self.root,p,'[ok](other.md)'),[])
    def test_seal_tamper(self):
        (self.root/'a.txt').write_text('A');m.seal(self.root)
        self.assertEqual(m.seal(self.root,True)['status'],'PASS')
        (self.root/'a.txt').write_text('B')
        with self.assertRaises(m.SpecError):m.seal(self.root,True)
    def test_zip_deterministic(self):
        (self.root/'Δ.txt').write_text('hello');m.seal(self.root)
        a=Path(self.tmp.name)/'a.zip';b=Path(self.tmp.name)/'b.zip'
        m.package(self.root,a);m.package(self.root,b)
        self.assertEqual(a.read_bytes(),b.read_bytes())
        with zipfile.ZipFile(a) as z:self.assertTrue(all(n.startswith('spec/') for n in z.namelist()))
    def test_zip_no_overwrite(self):
        (self.root/'a').write_text('A');m.seal(self.root)
        z=Path(self.tmp.name)/'archive.zip';z.write_text('keep')
        with self.assertRaises(m.SpecError):m.package(self.root,z)
        self.assertEqual(z.read_text(),'keep')
    def test_nul_input(self):
        p=self.root/'contains-nul.bin';p.write_bytes(b'hello\0world')
        with self.assertRaises(m.SpecError):m.read_text(p)


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)/'Unicode Δ space'/ 'spec'
        shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('__pycache__'))
        receipt_source=ROOT.parent/'release/evidence/od-005-campaign-authority.json'
        receipt_target=self.root.parent/'release/evidence/od-005-campaign-authority.json'
        receipt_target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(receipt_source,receipt_target)
        authority_target=self.root.parent/'release/index/campaign_authority.v1.toml'
        authority_target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT.parent/'release/index/campaign_authority.v1.toml',authority_target)
        adoption_target=self.root.parent/'docs/architecture/specification_authority.md'
        adoption_target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT.parent/'docs/architecture/specification_authority.md',adoption_target)
        m.seal(self.root)
        repository=self.root.parent
        for command in (
            ['git','init'], ['git','config','user.email','tests@example.invalid'],
            ['git','config','user.name','specctl tests'], ['git','add','.'],
            ['git','commit','-m','baseline'],
        ):
            subprocess.run(command,cwd=repository,check=True,capture_output=True)
        self.source_commit=subprocess.run(['git','rev-parse','HEAD'],cwd=repository,check=True,capture_output=True,text=True).stdout.strip()
        self.source_tree=subprocess.run(['git','rev-parse','HEAD^{tree}'],cwd=repository,check=True,capture_output=True,text=True).stdout.strip()
        self.source_aggregate=m.load_json(self.root/'integrity.json')['aggregate_sha256']
        receipt=self.root.parent/'release/evidence/od-005-campaign-authority.json'
        record=m.load_json(receipt);record['source']={'commit':self.source_commit,'tree':self.source_tree};record['spec_aggregate_sha256']=self.source_aggregate
        receipt.write_text(m.json_text(record))
        reference={'path':'release/evidence/od-005-campaign-authority.json','sha256':hashlib.sha256(receipt.read_bytes()).hexdigest()}
        for path in (self.root/'plan/open-decisions.json',self.root/'plan/programme-status.json'):
            value=m.load_json(path)
            if 'decisions' in value and isinstance(value['decisions'],list):
                next(item for item in value['decisions'] if item['id']=='OD-005')['resolution_evidence']=[reference]
            else:value['decisions']['OD-005']['evidence']=[reference]
            path.write_text(m.json_text(value))
    def tearDown(self):self.tmp.cleanup()
    def programme_receipt(self,claim,details):
        path=self.root.parent/'release/evidence/test-programme-evidence.json'
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(m.json_text({
            'schema':'universal.programme_evidence/1',
            'campaign':'USK-SPEC-TO-RELEASE-01',
            'claim':claim,
            'status':'accepted',
            'recorded_at':'2026-09-22T00:00:00Z',
            'source':{'commit':self.source_commit,'tree':self.source_tree},
            'spec_aggregate_sha256':self.source_aggregate,
            'details':details,
        }))
        return {'path':'release/evidence/test-programme-evidence.json','sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def typed_receipt(self,name,schema,claim,details):
        path=self.root.parent/'release/evidence'/name
        path.write_text(m.json_text({
            'schema':schema,'campaign':'USK-SPEC-TO-RELEASE-01','claim':claim,
            'status':'accepted','recorded_at':'2026-09-22T00:00:00Z',
            'source':{'commit':self.source_commit,'tree':self.source_tree},
            'spec_aggregate_sha256':self.source_aggregate,'details':details,
        }))
        return {'path':'release/evidence/'+name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def test_clean_index_single_pass(self):
        shutil.rmtree(self.root/'derived',ignore_errors=True)
        for p in self.root.rglob('index.md'):p.unlink()
        b=m.load_bundle(self.root);m.generate_index(b)
        self.assertEqual(m.generate_index(m.load_bundle(self.root),True)['status'],'PASS')
    def test_execution_claim_rejected(self):
        path=self.root/'verification/acceptance-cases.json';x=m.load_json(path);x['cases'][0]['status']='PASS'
        path.write_text(m.json_text(x))
        with self.assertRaises(m.SpecError):m.load_bundle(self.root)
    def test_authorized_template_rejected(self):
        path=self.root/'plan/tasks/usk-wu-001.md';s=path.read_text();s=s.replace('"authorizes_implementation": false','"authorizes_implementation": true');path.write_text(s)
        with self.assertRaises(m.SpecError):m.load_bundle(self.root)
    def test_task_cycle_rejected(self):
        path=self.root/'plan/tasks/usk-wu-001.md';s=path.read_text();s=s.replace('"depends_on": []','"depends_on": ["USK-WU-002"]');path.write_text(s)
        with self.assertRaises(m.SpecError):m.load_bundle(self.root)
    def test_contradictory_task_scope_rejected(self):
        path=self.root/'plan/tasks/usk-wu-001.md';s=path.read_text();s=s.replace('"read_only_paths": ["contracts/**","release/**"]','"read_only_paths": ["contracts/**","release/**","spec/**"]');path.write_text(s)
        with self.assertRaisesRegex(m.SpecError,'contradictory writable scope'):m.load_bundle(self.root)
    def test_repository_projection_cannot_grant_authority(self):
        path=self.root/'integration/repository-status.json';x=m.load_json(path);x['authority_granted']=True;path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'must not grant execution authority'):m.load_bundle(self.root)
    def test_programme_status_projection_cannot_mint_authority(self):
        path=self.root/'plan/programme-status.json';x=m.load_json(path);x['authority_granted_by_this_projection']=True;path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'must not mint execution authority'):m.load_bundle(self.root)
    def test_release_selection_cannot_grant_authority(self):
        path=self.root/'plan/release-selection.json';x=m.load_json(path);x['authority']['signing']=True;path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'must not grant operational authority'):m.load_bundle(self.root)
    def test_release_selection_requires_complete_authority_ceiling(self):
        path=self.root/'plan/release-selection.json';x=m.load_json(path);del x['authority']['publication'];path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'authority ceiling fields are incomplete'):m.load_bundle(self.root)
    def test_release_selection_requires_status_report_fields(self):
        path=self.root/'plan/release-selection.json';x=m.load_json(path);del x['decisions']['OD-008']['selected']['current_release_readiness'];path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'missing selected.current_release_readiness'):m.load_bundle(self.root)
    def test_release_selection_rejects_unknown_selected_fields(self):
        path=self.root/'plan/release-selection.json';x=m.load_json(path);x['decisions']['OD-002']['selected']['ready']=True;path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'selected fields are incomplete or unknown'):m.load_bundle(self.root)
    def test_release_selection_rejects_readiness_overclaim(self):
        path=self.root/'plan/release-selection.json';x=m.load_json(path);x['decisions']['OD-008']['selected']['current_release_readiness']='ready';path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'release readiness must remain not established'):m.load_bundle(self.root)
    def test_release_selection_requires_nonempty_obligations(self):
        path=self.root/'plan/release-selection.json';x=m.load_json(path);x['decisions']['OD-003']['outstanding']=[];path.write_text(m.json_text(x))
        with self.assertRaisesRegex(m.SpecError,'outstanding must be a non-empty string list'):m.load_bundle(self.root)
    def test_qualified_current_decision_can_close_without_rewriting_snapshot(self):
        qualification=self.typed_receipt(
            'test-machine-qualification.json','universal.machine_qualification_receipt/1',
            'release_1_1.machine_qualified',
            {'candidate_sha256':'4'*64,'profile':'windows-nt-x64','result':'pass'},
        )
        evidence=self.typed_receipt(
            'test-od-002-decision.json','universal.decision_evidence/1','OD-002',
            {'evidence_kind':'machine_qualification','candidate_sha256':'4'*64,
             'profile':'windows-nt-x64','qualification_receipt':qualification},
        )
        decisions_path=self.root/'plan/open-decisions.json';decisions=m.load_json(decisions_path)
        decision=next(item for item in decisions['decisions'] if item['id']=='OD-002')
        decision['status']='resolved';decision.pop('resolution_required')
        decision['outstanding_obligations']=[]
        decision['resolution']='Exact target profile qualified by bound evidence.'
        decision['resolution_evidence']=[evidence]
        decisions_path.write_text(m.json_text(decisions))
        status_path=self.root/'plan/programme-status.json';status=m.load_json(status_path)
        status['decisions']['OD-002']={'status':'resolved','evidence':decision['resolution_evidence']}
        status_path.write_text(m.json_text(status))
        bundle=m.load_bundle(self.root)
        self.assertEqual(bundle['release_selection']['decisions']['OD-002']['parent_status'],'open')
        self.assertEqual(bundle['programme_status']['decisions']['OD-002']['status'],'resolved')
    def test_current_release_readiness_can_advance_with_evidence(self):
        path=self.root/'plan/programme-status.json';status=m.load_json(path)
        status['release_1_1']['readiness']='alpha'
        status['release_1_1']['evidence']['readiness']=[self.programme_receipt(
            'release_1_1.readiness',{'candidate_sha256':'4'*64,'readiness':'alpha'})]
        path.write_text(m.json_text(status))
        bundle=m.load_bundle(self.root)
        self.assertEqual(bundle['programme_status']['release_1_1']['readiness'],'alpha')
        self.assertEqual(bundle['release_selection']['decisions']['OD-008']['selected']['current_release_readiness'],'not established')
    def test_current_release_readiness_cannot_advance_without_evidence(self):
        path=self.root/'plan/programme-status.json';status=m.load_json(path)
        status['release_1_1']['readiness']='alpha';path.write_text(m.json_text(status))
        with self.assertRaisesRegex(m.SpecError,'readiness requires evidence'):m.load_bundle(self.root)
    def test_irrelevant_file_cannot_advance_release_readiness(self):
        path=self.root/'plan/programme-status.json';status=m.load_json(path)
        status['release_1_1']['readiness']='alpha'
        status['release_1_1']['evidence']['readiness']=[{
            'path':'spec/plan/release-selection.json',
            'sha256':hashlib.sha256((self.root/'plan/release-selection.json').read_bytes()).hexdigest()}]
        path.write_text(m.json_text(status))
        with self.assertRaisesRegex(m.SpecError,'programme evidence must be a JSON receipt under release/evidence'):m.load_bundle(self.root)
    def test_evidence_claim_cannot_be_reused_for_another_predicate(self):
        path=self.root/'plan/programme-status.json';status=m.load_json(path)
        status['release_1_1']['implementation_complete']=True
        status['release_1_1']['evidence']['implementation_complete']=[self.programme_receipt(
            'release_1_1.readiness',{'candidate_sha256':'4'*64,'readiness':'alpha'})]
        path.write_text(m.json_text(status))
        with self.assertRaisesRegex(m.SpecError,'programme evidence claim mismatch'):m.load_bundle(self.root)
    def test_programme_evidence_rejects_fabricated_source_commit(self):
        path=self.root/'plan/programme-status.json';status=m.load_json(path)
        status['release_1_1']['readiness']='alpha'
        reference=self.programme_receipt('release_1_1.readiness',{'candidate_sha256':'4'*64,'readiness':'alpha'})
        receipt=self.root.parent/reference['path'];record=m.load_json(receipt)
        record['source']['commit']='f'*40;receipt.write_text(m.json_text(record))
        reference['sha256']=hashlib.sha256(receipt.read_bytes()).hexdigest()
        status['release_1_1']['evidence']['readiness']=[reference];path.write_text(m.json_text(status))
        with self.assertRaisesRegex(m.SpecError,'referenced source commit is unavailable'):m.load_bundle(self.root)
    def test_machine_qualification_rejects_generic_file_reference(self):
        path=self.root/'plan/programme-status.json';status=m.load_json(path)
        status['release_1_1']['machine_qualified']=True
        status['release_1_1']['evidence']['machine_qualified']=[self.programme_receipt(
            'release_1_1.machine_qualified',{
                'candidate_sha256':'4'*64,'profiles':['windows-nt-x64'],
                'qualification_receipts':[{'path':'spec/manifest.json','sha256':hashlib.sha256((self.root/'manifest.json').read_bytes()).hexdigest()}],
            })]
        path.write_text(m.json_text(status))
        with self.assertRaisesRegex(m.SpecError,'qualification receipt.*release/evidence'):m.load_bundle(self.root)
    def test_resolved_decision_rejects_generic_evidence(self):
        decisions_path=self.root/'plan/open-decisions.json';decisions=m.load_json(decisions_path)
        decision=next(item for item in decisions['decisions'] if item['id']=='OD-003')
        decision['status']='resolved';decision.pop('resolution_required');decision['outstanding_obligations']=[]
        decision['resolution']='Compatibility analysis complete.'
        decision['resolution_evidence']=[{'path':'spec/plan/release-selection.json','sha256':hashlib.sha256((self.root/'plan/release-selection.json').read_bytes()).hexdigest()}]
        decisions_path.write_text(m.json_text(decisions))
        status_path=self.root/'plan/programme-status.json';status=m.load_json(status_path)
        status['decisions']['OD-003']={'status':'resolved','evidence':decision['resolution_evidence']};status_path.write_text(m.json_text(status))
        with self.assertRaisesRegex(m.SpecError,'OD-003 evidence.*release/evidence'):m.load_bundle(self.root)
    def test_duplicate_id_rejected(self):
        source=self.root/'model/identity.md';target=self.root/'model/copied.md';target.write_bytes(source.read_bytes())
        with self.assertRaises(m.SpecError):m.load_bundle(self.root)
    def test_prototype_extra_field_rejected(self):
        try:import jsonschema
        except ImportError:self.skipTest('optional jsonschema unavailable')
        p=self.root/'prototypes/examples/product-bundle.json';x=m.load_json(p);x['run_shell']='unrestricted';p.write_text(m.json_text(x))
        with self.assertRaises(m.SpecError):m.schema_check(m.load_bundle(self.root))
    def test_reference_only_context_explicit(self):
        b=m.load_bundle(self.root);p,_=m.context_pack(b,'USK-WU-005',100000)
        self.assertTrue(p['dependency_refs']);self.assertTrue(p['omissions']);self.assertFalse(p['full_closure'])
        full,_=m.context_pack(b,'USK-WU-005',400000,True)
        self.assertFalse(full['dependency_refs']);self.assertGreater(len(full['sections']),len(p['sections']))
    def test_stale_reference_dependency(self):
        b=m.load_bundle(self.root);p,_=m.context_pack(b,'USK-WU-005',100000)
        rel=p['dependency_refs'][0]['path'];path=self.root/rel;path.write_text(path.read_text()+'\nExtra changed intent.\n')
        with self.assertRaises(m.SpecError):m.verify_context(m.load_bundle(self.root),p)
    def test_zip_output_dangling_symlink(self):
        m.seal(self.root)
        path=Path(self.tmp.name)/'out.zip'
        try:path.symlink_to(Path(self.tmp.name)/'never-created.zip')
        except OSError:self.skipTest('symlink unavailable')
        with self.assertRaises(m.SpecError):m.package(self.root,path)

if __name__=='__main__':unittest.main()
