"""Observable portable protection choices; no remote effects or policy installation."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('aide_git_defaults', ROOT / '.aide/scripts/aide_lite.py')
aide = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aide
SPEC.loader.exec_module(aide)


class GitDefaults(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.policy = self.root / aide.BRANCH_PROTECTION_POLICY_PATH
        self.policy.parent.mkdir(parents=True)
        self.policy.write_bytes((ROOT / aide.BRANCH_PROTECTION_POLICY_PATH).read_bytes())
        self.state = {'local_branches': ['main', 'dev', 'task/active'],
                      'remote_branches': ['origin/main', 'origin/dev'],
                      'current_branch': 'task/active', 'current_role': 'task'}

    def plan(self):
        return aide.make_github_protection_plan(self.root, self.state)

    def change(self, before, after):
        text = self.policy.read_text(encoding='utf8')
        self.assertIn(before, text)
        self.policy.write_bytes(text.replace(before, after, 1).encode())

    def test_new_project_defaults_leave_hosting_protection_opt_in(self):
        plan = self.plan()
        targets = {t['branch']: t for t in plan['branch_targets']}
        self.assertFalse(targets['main']['recommended'])
        self.assertFalse(targets['dev']['recommended'])
        self.assertEqual(targets['main']['protection_choice'], 'project_optional')
        self.assertEqual(plan['policy_issues'], [])
        self.assertNotIn('integration', plan['protected_branch_roles'])
        self.assertTrue(plan['preserve_existing_remote_settings'])
        self.assertFalse(plan['remote_protection_observed'])
        self.assertFalse(plan['branch_protection_applied'])

    def test_project_opt_in_is_respected_without_mutating_the_policy(self):
        self.change('    protect: false', '    protect: true # project choice')
        before = self.policy.read_bytes()
        plan = self.plan()
        self.assertTrue(plan['branch_targets'][0]['recommended'])
        self.assertFalse(plan['branch_targets'][1]['recommended'])
        self.assertIn('canonical', plan['protected_branch_roles'])
        self.assertEqual(self.policy.read_bytes(), before)

    def test_dev_override_preserves_its_configured_review_choice(self):
        text = self.policy.read_text(encoding='utf8')
        start = text.index('  dev:')
        self.policy.write_bytes((text[:start] + text[start:].replace('protect: false', 'protect: true', 1)
                                 .replace('require_reviews: false', 'require_reviews: true', 1)).encode())
        dev = self.plan()['branch_targets'][1]
        self.assertTrue(dev['recommended'])
        self.assertEqual(dev['required_reviews'], 1)
        self.assertFalse(dev['allow_force_pushes'])
        self.assertFalse(dev['allow_deletions'])

    def test_duplicate_or_unsupported_boolean_does_not_guess_protection(self):
        original = self.policy.read_bytes()
        for value in ['true\n    protect: false', 'maybe', '# undecided', '"false"']:
            with self.subTest(value=value):
                self.policy.write_bytes(original)
                self.change('    protect: false', '    protect: ' + value)
                plan = self.plan()
                self.assertIsNone(plan['branch_targets'][0]['recommended'])
                self.assertTrue(plan['policy_issues'])

    def test_duplicate_rule_or_missing_file_is_explicit(self):
        self.change('  main:', '  main:\n    protect: true\n  main:')
        self.assertIsNone(self.plan()['branch_targets'][0]['recommended'])
        self.assertTrue(self.plan()['policy_issues'])
        self.policy.unlink()
        self.assertTrue(all(t['recommended'] is None for t in self.plan()['branch_targets']))

    def test_human_view_explains_same_choices_and_unknowns(self):
        plan = self.plan()
        human = aide.render_github_protection_plan_md(plan)
        self.assertIn('main: role=canonical; present=true; protection=false', human)
        self.assertIn('dev: role=integration; present=true; protection=false', human)
        self.assertIn('remote_protection_observed: false', human)
        self.change('    protect: false', '    protect: ambiguous')
        self.assertIn('protection=unknown', aide.render_github_protection_plan_md(self.plan()))

    def test_inline_duplicate_and_unsupported_headers_remain_unknown(self):
        original = self.policy.read_bytes()
        for before, after in [
            ('  main:', '  main: {protect: true}\n  main:'),
            ('  dev:', '  main: {protect: true}\n  dev:'),
            ('  main:', '  main: {protect: true}'),
            ('rules:', 'rules: {main: {protect: true}}\nrules:'),
            ('application_policy:', 'rules: {main: {protect: true}}\napplication_policy:'),
            ('rules:', 'rules: {main: {protect: true}}'),
        ]:
            with self.subTest(after=after):
                self.policy.write_bytes(original)
                self.change(before, after)
                plan = self.plan()
                self.assertIsNone(plan['branch_targets'][0]['recommended'])
                self.assertTrue(plan['policy_issues'])

    def test_parent_advisory_uses_target_identity_and_never_calls_network(self):
        seen = []
        def observe(_root, args):
            seen.append(args)
            self.assertEqual(args, ['remote', '-v'])
            return True, 'origin https://github.com/example/project.git (fetch)\n', ''
        with patch.object(aide, 'collect_git_helper_state', return_value=self.state):
            with patch.object(aide, 'run_git_capture', side_effect=observe):
                data = aide.make_github_advisory(self.root)
        self.assertEqual(data['repo_id'], data['branch_protection']['repo_id'])
        self.assertEqual(data['repo_id'], data['ci']['repo_id'])
        self.assertNotEqual(data['repo_id'].lower(), 'julesc013/aide')
        self.assertEqual(seen, [['remote', '-v']])
        self.assertFalse(data['network_calls'])
        self.assertFalse(data['github_api_mutation'])

    def test_observation_changes_no_fixture_bytes_or_mtimes(self):
        before = (self.policy.read_bytes(), self.policy.stat().st_mtime_ns)
        first = json.dumps(self.plan(), sort_keys=True)
        self.assertEqual(first, json.dumps(self.plan(), sort_keys=True))
        self.assertEqual(before, (self.policy.read_bytes(), self.policy.stat().st_mtime_ns))


if __name__ == '__main__':
    unittest.main()
