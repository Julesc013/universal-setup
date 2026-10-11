# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
"""Transport scope contradictions; no native effects or acceptance."""
from pathlib import Path
import tempfile
import unittest
import publisher_prefix_archive as prefix
import publisher_durable_archive as durable


class DurableArchiveTests(unittest.TestCase):
    def test_all_six_raw_receipts_survive_exactly(self):
        records = {case: b'{\r\n  "typed":1, "nested":"{\\\"value\\\":true}"\r\n}\r\n' for case in durable.CASES}
        self.assertEqual(durable.decode_receipts(durable.encode_receipts(records)), records)

    def test_artifact_scopes_cannot_be_interchanged(self):
        for decoder, encoded in (
            (prefix.decode_receipts, durable.encode_receipts({durable.CASES[0]: b'{}'})),
            (durable.decode_receipts, prefix.encode_receipts({prefix.CASES[0]: b'{}'})),
        ):
            with self.assertRaises(ValueError):
                decoder(encoded)

    def test_partial_failure_does_not_gain_cases(self):
        raw = {durable.CASES[0]: b'{"status":"failed"}'}
        self.assertEqual(durable.decode_receipts(durable.encode_receipts(raw)), raw)

    def test_unknown_cases_and_unbounded_formats_refuse(self):
        with self.assertRaises(ValueError):
            durable.encode_receipts({prefix.CASES[0]: b'{}'})
        for cases, magic in ((tuple(str(n) for n in range(10)), b'format'), (('same', 'same'), b'format'),
                             (durable.CASES, b'x' * 65)):
            with self.assertRaises(ValueError):
                prefix.decode_receipts(b'bad', cases=cases, magic=magic)

    def test_packer_preserves_raw_bytes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b'\xef\xbb\xbf{\r\n "status": "failed"\r\n}\r\n'
            (root / ('usk-wu007-durable-' + durable.CASES[0] + '.json')).write_bytes(raw)
            output = root / durable.MEMBER_NAME
            durable.pack_directory(root, output)
            self.assertEqual(durable.decode_receipts(output.read_bytes()), {durable.CASES[0]: raw})
            with self.assertRaises(FileExistsError):
                durable.pack_directory(root, output)


if __name__ == '__main__':
    unittest.main()
