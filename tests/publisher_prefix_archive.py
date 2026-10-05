# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Bounded, byte-preserving transport for prefix receipts; never acceptance."""
from __future__ import annotations

import argparse
import lzma
from pathlib import Path
import struct

from publisher_bootstrap_prefix_evidence import CASES

MAGIC = b'USK_PREFIX_RECEIPTS_V1\x00'
MEMBER_NAME = 'usk-wu007-prefix-receipts.xz'
RAW_MAX = 4 * 1024 * 1024
# Leave room for the single-member GitHub ZIP, whose actual 1 MiB cap is
# independently enforced by the collector before and after download.
XZ_MAX = 1024 * 1024 - 4096
DECODED_MAX = len(MAGIC) + 1 + len(CASES) * (5 + RAW_MAX)
MEMORY_MAX = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def format_budget(cases, magic):
    require(isinstance(cases, tuple) and 1 <= len(cases) <= len(CASES) and len(set(cases)) == len(cases) and
        all(isinstance(case, str) and case for case in cases) and isinstance(magic, bytes) and 0 < len(magic) <= 64,
        'receipt format bound differs')
    return len(magic) + 1 + len(cases) * (5 + RAW_MAX)


def encode_receipts(records, *, cases=CASES, magic=MAGIC):
    format_budget(cases, magic)
    require(1 <= len(records) <= len(cases), 'receipt count differs')
    require(set(records) <= set(cases), 'receipt case differs')
    framed = bytearray(magic)
    framed.append(len(records))
    for case in cases:
        if case not in records:
            continue
        raw = records[case]
        require(isinstance(raw, bytes) and 0 < len(raw) <= RAW_MAX, 'raw receipt bound differs')
        framed.extend(struct.pack('<BI', cases.index(case), len(raw)))
        framed.extend(raw)
    encoded = lzma.compress(framed, format=lzma.FORMAT_XZ, preset=6)
    require(0 < len(encoded) <= XZ_MAX, 'encoded receipt bound differs')
    return encoded


def decode_receipts(encoded, *, cases=CASES, magic=MAGIC):
    decoded_max = format_budget(cases, magic)
    require(isinstance(encoded, bytes) and 0 < len(encoded) <= XZ_MAX, 'encoded receipt bound differs')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MEMORY_MAX)
    framed = decoder.decompress(encoded, max_length=decoded_max + 1)
    require(len(framed) <= decoded_max and decoder.eof and not decoder.unused_data,
            'decoded receipt budget, termination or trailing bytes differ')
    require(framed.startswith(magic) and len(framed) > len(magic), 'receipt frame identity differs')
    count = framed[len(magic)]
    require(1 <= count <= len(cases), 'receipt count differs')
    offset = len(magic) + 1
    records = {}
    for _ in range(count):
        require(offset + 5 <= len(framed), 'receipt header truncated')
        index, length = struct.unpack_from('<BI', framed, offset)
        offset += 5
        require(index < len(cases), 'receipt case differs')
        case = cases[index]
        require(case not in records, 'duplicate receipt case')
        require(0 < length <= RAW_MAX and offset + length <= len(framed), 'raw receipt bound differs')
        records[case] = framed[offset:offset + length]
        offset += length
    require(offset == len(framed), 'receipt frame has trailing bytes')
    return records


def pack_directory(directory, output, *, cases=CASES, magic=MAGIC, filename_prefix='usk-wu007-prefix-'):
    format_budget(cases, magic)
    require(filename_prefix in ('usk-wu007-prefix-', 'usk-wu007-durable-'), 'receipt filename prefix differs')
    paths = tuple(directory.glob(filename_prefix + '*.json'))
    require(1 <= len(paths) <= len(cases), 'receipt file count differs')
    records = {}
    for path in paths:
        case = path.name.removeprefix(filename_prefix).removesuffix('.json')
        require(case in cases and path.name == filename_prefix + case + '.json', 'receipt filename differs')
        require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= RAW_MAX,
                'raw receipt file bound differs')
        with path.open('rb') as stream:
            records[case] = stream.read(RAW_MAX + 1)
    encoded = encode_receipts(records, cases=cases, magic=magic)
    # Partial failed cohorts remain retainable, with their missing cases
    # reported by the collector. This transport cannot qualify them.
    with output.open('xb') as stream:
        stream.write(encoded)
    return len(records), len(encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('output', type=Path)
    arguments = parser.parse_args()
    count, size = pack_directory(arguments.directory, arguments.output)
    print(f'Packed {count} byte-preserved receipts into {size} bytes; qualification not granted')


if __name__ == '__main__':
    main()
