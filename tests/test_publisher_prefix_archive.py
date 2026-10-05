# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Receipt transport contradictions; no native fixture effects or acceptance."""
import hashlib
import lzma
from pathlib import Path
import struct
import tempfile
import unittest

from publisher_prefix_archive import (
    CASES, DECODED_MAX, MAGIC, MEMBER_NAME, MEMORY_MAX, RAW_MAX, XZ_MAX,
    decode_receipts, encode_receipts, pack_directory,
)


class ReceiptArchiveTests(unittest.TestCase):
    def assert_frame_refused(self, frame):
        with self.assertRaises((ValueError, lzma.LZMAError)):
            decode_receipts(lzma.compress(frame, preset=6))

    def test_original_bytes_and_hashes_survive_all_nine_cases(self):
        # Includes BOM, indentation, nested escaped JSON and non-ASCII bytes.
        raw = b'\xef\xbb\xbf{\r\n  "nested": "{\\\"typed\\\":1}", "value": "\xe2\x82\xac"\r\n}\r\n'
        records = {case: raw + str(n).encode() for n, case in enumerate(CASES)}
        actual = decode_receipts(encode_receipts(records))
        self.assertEqual(actual, records)
        self.assertEqual({k: hashlib.sha256(v).hexdigest() for k, v in actual.items()},
                         {k: hashlib.sha256(v).hexdigest() for k, v in records.items()})

    def test_partial_failed_cohort_stays_partial(self):
        records = {CASES[0]: b'{"status":"failed"}'}
        self.assertEqual(decode_receipts(encode_receipts(records)), records)

    def test_encoder_refuses_unknown_empty_and_oversized_records(self):
        for records in ({}, {'invented': b'{}'}, {CASES[0]: b''},
                        {CASES[0]: 'text'}, {CASES[0]: b'x' * (RAW_MAX + 1)}):
            with self.subTest(records=tuple(records)):
                with self.assertRaises(ValueError):
                    encode_receipts(records)

    def test_frame_identity_and_counts_are_closed(self):
        for frame in (b'other', MAGIC, MAGIC + b'\x00', MAGIC + b'\x0a'):
            self.assert_frame_refused(frame)

    def test_case_indices_and_duplicates_are_closed(self):
        for frame in (MAGIC + b'\x01' + struct.pack('<BI', 9, 2) + b'{}',
                      MAGIC + b'\x02' + (struct.pack('<BI', 0, 2) + b'{}') * 2):
            self.assert_frame_refused(frame)

    def test_raw_lengths_truncation_and_trailing_bytes_refuse(self):
        for frame in (MAGIC + b'\x01', MAGIC + b'\x01' + b'\x00',
                      MAGIC + b'\x01' + struct.pack('<BI', 0, 0),
                      MAGIC + b'\x01' + struct.pack('<BI', 0, RAW_MAX + 1),
                      MAGIC + b'\x01' + struct.pack('<BI', 0, 3) + b'{}',
                      MAGIC + b'\x01' + struct.pack('<BI', 0, 2) + b'{}extra'):
            self.assert_frame_refused(frame)

    def test_corrupt_truncated_concatenated_and_trailing_xz_refuse(self):
        valid = encode_receipts({CASES[0]: b'{}'})
        for encoded in (valid[:-1], b'corrupt', valid + b'extra', valid + valid):
            with self.assertRaises((ValueError, lzma.LZMAError)):
                decode_receipts(encoded)

    def test_encoded_and_decoded_budgets_refuse(self):
        for encoded in (b'', b'x' * (XZ_MAX + 1)):
            with self.assertRaises(ValueError):
                decode_receipts(encoded)
        self.assert_frame_refused(b'x' * (DECODED_MAX + 1))

    def test_decoder_memory_budget_refuses_large_dictionary(self):
        encoded = lzma.compress(MAGIC + b'\x01' + struct.pack('<BI', 0, 2) + b'{}', filters=[{
            'id': lzma.FILTER_LZMA2, 'dict_size': MEMORY_MAX, 'mode': lzma.MODE_FAST,
            'mf': lzma.MF_HC3, 'nice_len': 16,
        }])
        with self.assertRaises(lzma.LZMAError):
            decode_receipts(encoded)

    def test_file_packer_retains_exact_bytes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = b'{\r\n "status": "failed"\r\n}\r\n'
            (directory / ('usk-wu007-prefix-' + CASES[0] + '.json')).write_bytes(raw)
            output = directory / MEMBER_NAME
            count, size = pack_directory(directory, output)
            self.assertEqual((count, size), (1, output.stat().st_size))
            self.assertEqual(decode_receipts(output.read_bytes()), {CASES[0]: raw})
            with self.assertRaises(FileExistsError):
                pack_directory(directory, output)

    def test_file_packer_refuses_extra_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'usk-wu007-prefix-invented.json').write_bytes(b'{}')
            with self.assertRaises(ValueError):
                pack_directory(directory, directory / MEMBER_NAME)


if __name__ == '__main__':
    unittest.main()
