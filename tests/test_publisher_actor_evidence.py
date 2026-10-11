# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Independent actor contradictions cannot acquire an unrelated-login label."""
import copy
import unittest

from publisher_actor_evidence import LOGIN_BASIS, reconcile_unrelated_login
from publisher_standard_public_evidence import MUTATION_RIGHTS


SERVICE = 'S-1-5-80-1-2-3-4-5'
CALLER = 'S-1-5-21-1-2-3-500'
UNRELATED = 'S-1-5-21-1-2-3-1003'


def fixture():
    tokens = {}
    for actor, user, identity, session in (('initiating', CALLER, 1, 1),
            ('filtered', CALLER, 2, 1), ('unrelated', UNRELATED, 3, 2)):
        tokens[actor] = {'user_sid': user, 'token_id': f'{identity:016x}',
            'authentication_id': f'{session:016x}', 'token_type': 2, 'impersonation_level': 2,
            'groups': [{'sid': 'S-1-5-32-545', 'attributes': 7}],
            'privileges': [{'name': 'SeChangeNotifyPrivilege', 'attributes': 3}]}
    tokens['unrelated_logon_context'] = dict(account_name='USKOBS_0123456789abc', logon_type=2,
        contradictory_bindings_refused=7, basis=LOGIN_BASIS,
        **{key: tokens['unrelated'][key] for key in ('user_sid', 'token_id', 'authentication_id')})
    rights = {name: {'requested': mask, 'allowed': False, 'granted': 0}
        for name, mask in dict(MUTATION_RIGHTS, maximum_allowed=0x2000000).items()}
    def row(identity):
        return {'file_id': identity, 'effective_rights': {actor: copy.deepcopy(rights)
            for actor in ('initiating', 'filtered', 'unrelated')}}
    return {'schema': 'usk.publisher.metadata_independent_readback.v1', 'identity': 'S-1-5-18',
        'observer_token_handles_closed': True, 'effective_right_tokens': tokens,
        'rows': [row('payload')], 'volume_boundary': {'root': row('root')}}


class ActorEvidenceTests(unittest.TestCase):
    def test_distinct_login_and_privileged_initiator_keep_separate_scope(self):
        value = fixture()
        value['effective_right_tokens']['initiating']['groups'].append({'sid': 'S-1-5-32-544', 'attributes': 7})
        report = reconcile_unrelated_login(value, SERVICE)
        self.assertEqual(report['objects_checked'], 2)
        self.assertFalse(report['profile_qualified'])
        self.assertEqual(report['actor_profile'], 'initiating_and_unrelated_login')

    def test_context_and_token_contradictions_refuse(self):
        for key, bad in (('user_sid', CALLER), ('token_id', '0000000000000004'),
                ('authentication_id', '0000000000000001'), ('logon_type', True),
                ('contradictory_bindings_refused', 6), ('basis', 'reconstructed')):
            value = fixture()
            value['effective_right_tokens']['unrelated_logon_context'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                reconcile_unrelated_login(value, SERVICE)
        value = fixture()
        del value['effective_right_tokens']['unrelated_logon_context']
        with self.assertRaises(KeyError):
            reconcile_unrelated_login(value, SERVICE)

    def test_foreign_authority_and_ambiguous_population_refuse(self):
        for population, bad in (('groups', {'sid': 'S-1-5-32-544', 'attributes': 7}),
                ('groups', {'sid': SERVICE, 'attributes': 7}),
                ('privileges', {'name': 'SeRestorePrivilege', 'attributes': 2})):
            value = fixture()
            value['effective_right_tokens']['unrelated'][population].append(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                reconcile_unrelated_login(value, SERVICE)
        value = fixture()
        value['effective_right_tokens']['unrelated']['groups'] *= 2
        with self.assertRaises(ValueError):
            reconcile_unrelated_login(value, SERVICE)

    def test_missing_actor_and_row_mutation_refuse(self):
        for case in ('missing_actor', 'mutation', 'maximum', 'alias', 'open_handle'):
            value = fixture()
            rights = value['rows'][0]['effective_rights']
            if case == 'missing_actor': del rights['unrelated']
            elif case == 'mutation': rights['unrelated']['delete'].update(allowed=True, granted=65536)
            elif case == 'maximum': rights['unrelated']['maximum_allowed'].update(allowed=True, granted=2)
            elif case == 'alias': value['volume_boundary']['root']['file_id'] = 'payload'
            else: value['observer_token_handles_closed'] = False
            with self.subTest(case=case), self.assertRaises(ValueError):
                reconcile_unrelated_login(value, SERVICE)


if __name__ == '__main__':
    unittest.main()
