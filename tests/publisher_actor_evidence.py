# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Bind independently observed login actors; never grant publication authority.

The unrelated actor is the held, read-only local-login token reported by the
owned launcher and SYSTEM observer. Recorded phase-descriptor checks remain
retrospective. The initiating actor may be privileged; it is not relabelled as
a standard account or as the unrelated actor.
"""
from __future__ import annotations

import re

from publisher_execution_evidence import closed, integer, require, sid
from publisher_standard_public_evidence import deny_mutation


TOKEN_KEYS = frozenset({'user_sid', 'groups', 'privileges', 'token_id',
    'authentication_id', 'token_type', 'impersonation_level'})
LOGIN_KEYS = frozenset({'account_name', 'user_sid', 'token_id', 'authentication_id',
    'logon_type', 'contradictory_bindings_refused', 'basis'})
LOGIN_BASIS = 'actual owned local interactive logon token retained by launcher; SYSTEM DuplicateHandle readback'


def token(facts):
    closed(facts, TOKEN_KEYS, 'observed actor token keys differ')
    require(sid(facts['user_sid']) and integer(facts['token_type'], 2, 2) and
        integer(facts['impersonation_level'], 2, 2), 'observed actor token identity/type differs')
    for key in ('token_id', 'authentication_id'):
        require(isinstance(facts[key], str) and re.fullmatch('[0-9a-f]{16}', facts[key]) and
            int(facts[key], 16) != 0, 'observed actor token/session identity differs')
    for key, identity, limit in (('groups', 'sid', 1024), ('privileges', 'name', 256)):
        values, seen = facts[key], set()
        require(isinstance(values, list) and len(values) <= limit, 'observed actor population exceeds bound')
        for value in values:
            closed(value, {identity, 'attributes'}, 'observed actor population keys differ')
            principal = value[identity]
            valid = sid(principal) if identity == 'sid' else (
                isinstance(principal, str) and re.fullmatch('Se[A-Za-z]+Privilege', principal))
            require(valid and principal not in seen and integer(value['attributes']),
                'observed actor population identity/attributes differ')
            seen.add(principal)


def reconcile_unrelated_login(snapshot, service_sid):
    """Bind the independent snapshot's row checks, without a live phase claim."""
    require(snapshot['schema'] == 'usk.publisher.metadata_independent_readback.v1' and
        snapshot['identity'] == 'S-1-5-18' and snapshot['observer_token_handles_closed'] is True and
        sid(service_sid) and service_sid.startswith('S-1-5-80-'), 'unrelated observer/service scope differs')
    tokens = snapshot['effective_right_tokens']
    actors = ('initiating', 'filtered', 'unrelated')
    for actor in actors:
        token(tokens[actor])
    initiating, filtered, unrelated = (tokens[actor] for actor in actors)
    require(initiating['user_sid'] == filtered['user_sid'] and
        initiating['authentication_id'] == filtered['authentication_id'] and
        len({facts['token_id'] for facts in (initiating, filtered, unrelated)}) == 3,
        'same-account filtered token/session binding differs')
    login = tokens['unrelated_logon_context']
    closed(login, LOGIN_KEYS, 'unrelated local-login context keys differ')
    require(isinstance(login['account_name'], str) and re.fullmatch('USKOBS_[0-9a-f]{13}', login['account_name']) and
        integer(login['logon_type'], 2, 2) and integer(login['contradictory_bindings_refused'], 7, 7) and
        login['basis'] == LOGIN_BASIS and
        all(login[key] == unrelated[key] for key in ('user_sid', 'token_id', 'authentication_id')) and
        unrelated['user_sid'] not in (initiating['user_sid'], service_sid, 'S-1-5-18', 'S-1-5-32-544') and
        re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', unrelated['user_sid']) and
        unrelated['authentication_id'] != initiating['authentication_id'], 'unrelated login actor binding differs')
    require(not any(group['attributes'] & 4 and not group['attributes'] & 16 and
        (group['sid'] in ('S-1-5-18', 'S-1-5-32-544') or group['sid'].startswith('S-1-5-80-'))
        for group in unrelated['groups']) and not any(privilege['attributes'] & 2 and
        privilege['name'] != 'SeChangeNotifyPrivilege' for privilege in unrelated['privileges']),
        'unrelated actor has enabled privileged authority')
    require(isinstance(snapshot['rows'], list) and len(snapshot['rows']) <= 10000,
        'unrelated access rows exceed bound')
    rows = snapshot['rows'] + [snapshot['volume_boundary']['root']]
    require(1 <= len(rows) <= 10001 and
        len({row['file_id'] for row in rows}) == len(rows), 'unrelated access rows alias or exceed bound')
    for row in rows:
        closed(row['effective_rights'], set(actors), 'unrelated row actor set differs')
        deny_mutation(row['effective_rights']['unrelated'])
    return {'actor_profile': 'initiating_and_unrelated_login',
        'initiating_user_sid': initiating['user_sid'], 'unrelated_user_sid': unrelated['user_sid'],
        'unrelated_authentication_id': unrelated['authentication_id'],
        'objects_checked': len(rows), 'contradictory_bindings_refused': login['contradictory_bindings_refused'],
        'scope': 'independent_snapshot_held_login_token_access_checks', 'profile_qualified': False}
