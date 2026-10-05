# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Constructed bootstrap-prefix evidence; neither crash coverage nor authority."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import sys

from publisher_installation_lease_evidence import canonical, digest, document, require

ANCHORS = ('staging', 'destination', 'state', 'journal')
CASES = tuple('anchors_' + str(n) for n in range(1, 5)) + (
    'snapshot_empty', 'snapshot_first', 'snapshot_middle', 'snapshot_last', 'snapshot_full')
SCOPE = 'system_constructed_ordered_prefix_after_observed_empty_root_process_loss'


def prefix(case, context_row):
    require(case in CASES, 'constructed bootstrap prefix case differs')
    context = document(context_row)
    require(context.get('schema') == 'usk.installation_operation_context.v1' and
            'reviewed_snapshot' in context, 'constructed prefix lacks original native context')
    raw = (canonical(context['reviewed_snapshot']) + '\n').encode('utf-8')
    require(2 <= len(raw) <= 4 * 1024 * 1024, 'constructed snapshot byte budget differs')
    if case.startswith('anchors_'):
        return int(case[-1]), None
    length = {'snapshot_empty': 0, 'snapshot_first': 1, 'snapshot_middle': len(raw) // 2,
              'snapshot_last': len(raw) - 1, 'snapshot_full': len(raw)}[case]
    # The native byte predicate accepts every offset. This readback fixture uses
    # UTF-8 boundaries so its diagnostic text remains an exact byte projection.
    while True:
        try:
            raw[:length].decode('utf-8')
            break
        except UnicodeDecodeError:
            length -= 1
    return 4, raw[:length]


def constructed_rows(record, original_rows, drive, installed, observation, capture, volume_boundary):
    from publisher_standard_public_evidence import reader_rows, native_rows, native_boundary
    require(isinstance(record, dict) and record.keys() == {
        'schema', 'scope', 'case', 'fixture_actor', 'anchor_count', 'snapshot_size_bytes',
        'created_at_file_time', 'readback'} and record['schema'] == 'usk.publisher_constructed_bootstrap_prefix.v1' and
        record['scope'] == SCOPE, 'constructed prefix receipt is not closed/scoped')
    actor = record['fixture_actor']
    require(isinstance(actor, dict) and actor.keys() == {
        'identity', 'process_id', 'creation_file_time', 'service', 'service_stopped', 'publication_root_file_id'} and
        actor['identity'] == 'S-1-5-18' and type(actor['process_id']) is int and actor['process_id'] > 0 and
        isinstance(actor['creation_file_time'], str) and re.fullmatch('[1-9][0-9]{16,18}', actor['creation_file_time']) and
        actor['service'] == observation['service'] and actor['service_stopped'] is True,
        'constructed prefix actor/stopped service differs')
    require(isinstance(record['created_at_file_time'], str) and
        re.fullmatch('[1-9][0-9]{16,18}', record['created_at_file_time']) and
        int(record['created_at_file_time']) > int(actor['creation_file_time']),
        'constructed prefix timestamp differs')
    old = {row['path']: row for row in original_rows}
    publication = drive + 'publication'
    require(publication in old and old[publication]['directory'] is True and
        actor['publication_root_file_id'] == old[publication]['file_id'] and
        not any(path.startswith(publication + '\\') for path in old),
        'constructed prefix did not start from the independently observed empty root')
    context_path = (drive + 'installation-operations\\install-' + digest(installed['install_id']) +
                    '\\operation-' + digest(installed['transaction_id']) + '.json')
    require(context_path in old, 'constructed prefix original context absent')
    count, raw = prefix(record['case'], old[context_path])
    require(type(record['anchor_count']) is int and record['anchor_count'] == count and
        record['snapshot_size_bytes'] == (None if raw is None else len(raw)) and
        (raw is None or type(record['snapshot_size_bytes']) is int), 'constructed prefix shape/length differs')
    readback = record['readback']
    rows = reader_rows(readback, capture, observation['account_sid'])
    native_rows(rows, drive, installed['target_root'].replace('/', '\\'), observation['service_sid'], observation['account_sid'])
    native_boundary(readback['independent']['volume_boundary'])
    require(readback['independent']['volume_boundary'] == volume_boundary and
            'publication_absence' not in readback['independent'], 'constructed prefix volume boundary differs')
    new = {row['path']: row for row in rows}
    added = {publication + '\\' + anchor for anchor in ANCHORS[:count]}
    snapshot_path = publication + '\\journal\\lab-reviewed-plan.json'
    if raw is not None:
        added.add(snapshot_path)
    require(len(new) == len(rows) and set(new) == set(old) | added and
        all(new[path] == row for path, row in old.items()),
        'constructed prefix changed original native custody or added unexpected objects')
    require(all(new[path]['directory'] is True for path in added if path != snapshot_path),
        'constructed prefix anchor is not an ordinary native directory')
    if raw is not None:
        row = new[snapshot_path]
        require(row['directory'] is False and row['bytes'] == len(raw) and
            row['sha256'] == hashlib.sha256(raw).hexdigest() and
            row['content_json'].encode('utf-8') == raw, 'constructed snapshot bytes differ from exact original prefix')
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare', action='store_true', required=True)
    parser.parse_args()
    sys.stdin.reconfigure(encoding='utf-8-sig')
    value = json.load(sys.stdin)
    require(isinstance(value, dict) and value.keys() == {'case', 'context_row'}, 'prefix preparation input differs')
    count, raw = prefix(value['case'], value['context_row'])
    print(json.dumps({'anchor_count': count, 'snapshot_size_bytes': None if raw is None else len(raw),
        'snapshot_base64': None if raw is None else base64.b64encode(raw).decode('ascii')}, separators=(',', ':')))


if __name__ == '__main__':
    main()
