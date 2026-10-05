# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Bounded exact-byte transport for the six distinct durable fixture receipts."""
import argparse
from pathlib import Path
from publisher_bootstrap_durable_state_fixture import CASES
from publisher_prefix_archive import encode_receipts as _encode, decode_receipts as _decode, pack_directory as _pack

MAGIC = b'USK_DURABLE_RECEIPTS_V1\x00'
MEMBER_NAME = 'usk-wu007-durable-receipts.xz'


def encode_receipts(records):
    return _encode(records, cases=CASES, magic=MAGIC)


def decode_receipts(encoded):
    return _decode(encoded, cases=CASES, magic=MAGIC)


def pack_directory(directory, output):
    return _pack(directory, output, cases=CASES, magic=MAGIC, filename_prefix='usk-wu007-durable-')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('output', type=Path)
    arguments = parser.parse_args()
    count, size = pack_directory(arguments.directory, arguments.output)
    print(f'Packed {count} byte-preserved durable receipts into {size} bytes; qualification not granted')
