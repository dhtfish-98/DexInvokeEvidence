"""DEX string and resource boundaries independent of the Android toolchain."""

from __future__ import annotations

import unittest

from dex_invoke_evidence.parser import DexError, _decode_mutf8


class ModifiedUtf8Tests(unittest.TestCase):
    def test_ascii_and_encoded_null(self) -> None:
        self.assertEqual(_decode_mutf8(b"call", 4), "call")
        self.assertEqual(_decode_mutf8(b"A\xc0\x80B", 3), "A\x00B")

    def test_surrogate_pair_and_isolated_surrogate(self) -> None:
        self.assertEqual(_decode_mutf8(b"\xed\xa0\xbd\xed\xb8\x80", 2), "\U0001f600")
        self.assertEqual(_decode_mutf8(b"\xed\xa0\xbd", 1), "\ud83d")

    def test_standard_four_byte_utf8_is_rejected(self) -> None:
        with self.assertRaisesRegex(DexError, "four-byte"):
            _decode_mutf8("\U0001f600".encode("utf-8"), 2)

    def test_overlong_and_wrong_utf16_length_are_rejected(self) -> None:
        with self.assertRaises(DexError):
            _decode_mutf8(b"\xc0\xaf", 1)
        with self.assertRaisesRegex(DexError, "length mismatch"):
            _decode_mutf8(b"A", 2)


if __name__ == "__main__":
    unittest.main()
