"""DEX string and resource boundaries independent of the Android toolchain."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from dex_invoke_evidence import parser as parser_module
from dex_invoke_evidence.parser import DexError, DexInvokeParser, _decode_mutf8


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


class PrototypeBudgetTests(unittest.TestCase):
    def test_distinct_prototype_indices_share_one_total_budget(self) -> None:
        parser = object.__new__(DexInvokeParser)
        parser.proto_ids_size = 2
        parser.proto_ids_off = 0
        parser._protos = {}
        parser._proto_text_bytes = 0
        parser._u32 = lambda _off: 0
        parser._string = lambda _index: "V"
        parser._type = lambda _index: "Lx;"
        with patch.object(parser_module, "MAX_PROTO_TEXT_BYTES_TOTAL", 9):
            self.assertEqual(parser._proto(0), "()Lx;")
            with self.assertRaisesRegex(DexError, "prototype text budget"):
                parser._proto(1)
        self.assertEqual(list(parser._protos), [0])

    def test_return_type_alone_cannot_exceed_symbol_budget(self) -> None:
        parser = object.__new__(DexInvokeParser)
        parser.proto_ids_size = 1
        parser.proto_ids_off = 0
        parser._protos = {}
        parser._proto_text_bytes = 0
        parser._u32 = lambda _off: 0
        parser._string = lambda _index: "V"
        parser._type = lambda _index: "L" * 8192
        with self.assertRaisesRegex(DexError, "prototype text budget"):
            parser._proto(0)


class CatchBudgetTests(unittest.TestCase):
    def test_typed_handlers_are_charged_before_decode_loop(self) -> None:
        parser = object.__new__(DexInvokeParser)
        parser._catch_handlers_total = 0
        parser._catch_items_total = 0
        parser._data_span = lambda *_args: None
        parser._u16 = lambda off: 1 if off == 24 else 0
        parser._u32 = lambda _off: 0
        parser._uleb = lambda _off: (1, 29)
        parser._sleb = lambda _off: (2, 30)
        with patch.object(parser_module, "MAX_CATCH_ITEMS_TOTAL", 1):
            with self.assertRaisesRegex(DexError, "catch item budget"):
                parser._validate_tries(0, 2, 1, {0, 1})


if __name__ == "__main__":
    unittest.main()
