"""Independent DEX invocation locator based on the Android format specification.

This module deliberately parses only standard DEX 035–040. Unsupported or
malformed structures fail closed. It does not execute Dalvik instructions.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import asdict, dataclass


MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CODE_UNITS_TOTAL = 2_000_000
MAX_INVOKE_SITES = 100_000
MAX_STRING_ENCODED_BYTES = 16 * 1024
MAX_STRING_UTF16_UNITS = 8 * 1024
MAX_DECODED_STRING_BYTES_TOTAL = 8 * 1024 * 1024
MAX_PROTO_PARAMETERS = 1024
MAX_SYMBOL_TEXT_BYTES = 8 * 1024
MAX_PROTO_TEXT_BYTES_TOTAL = 8 * 1024 * 1024
MAX_METHOD_TEXT_BYTES_TOTAL = 8 * 1024 * 1024
MAX_REPORT_ESTIMATED_BYTES = 32 * 1024 * 1024
MAX_CLASS_MEMBERS_TOTAL = 1_000_000
MAX_CATCH_HANDLERS_TOTAL = 100_000
MAX_CATCH_ITEMS_TOTAL = 100_000


class DexError(ValueError):
    """A malformed, unsupported, or over-budget DEX input."""


@dataclass(frozen=True)
class InvokeSite:
    caller: str
    caller_method_index: int
    code_unit_offset: int
    file_offset: int
    opcode: str
    target: str
    target_method_index: int

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


_INVOKES = {
    0x6E: "invoke-virtual",
    0x6F: "invoke-super",
    0x70: "invoke-direct",
    0x71: "invoke-static",
    0x72: "invoke-interface",
    0x74: "invoke-virtual/range",
    0x75: "invoke-super/range",
    0x76: "invoke-direct/range",
    0x77: "invoke-static/range",
    0x78: "invoke-interface/range",
    0xFA: "invoke-polymorphic",
    0xFB: "invoke-polymorphic/range",
}

_WIDTH_2 = frozenset(
    {
        0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C,
        0x1F, 0x20, 0x22, 0x23, 0x29, 0xFE, 0xFF,
    }
)
_WIDTH_3 = frozenset(
    {
        0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25,
        0x26, 0x2A, 0x2B, 0x2C,
    }
)


def _decode_mutf8(raw: bytes, utf16_length: int) -> str:
    """Decode DEX MUTF-8 without accepting standard UTF-8 four-byte forms."""
    if any(byte >= 0xF0 for byte in raw):
        raise DexError("DEX string uses unsupported four-byte UTF-8")
    try:
        units = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
        if len(units) != utf16_length:
            raise DexError("DEX string UTF-16 length mismatch")
        return units.encode("utf-16-le", "surrogatepass").decode(
            "utf-16-le", "surrogatepass"
        )
    except UnicodeError as exc:
        raise DexError("invalid modified UTF-8 string") from exc


class DexInvokeParser:
    """Validate a bounded DEX file and locate method-reference invocations."""

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not 112 <= len(data) <= MAX_FILE_BYTES:
            raise DexError("DEX input length outside supported bounds")
        self.data = data
        self.size = len(data)
        self.version = ""
        self.data_off = 0
        self.data_size = 0
        self.string_ids_size = 0
        self.string_ids_off = 0
        self.type_ids_size = 0
        self.type_ids_off = 0
        self.proto_ids_size = 0
        self.proto_ids_off = 0
        self.field_ids_size = 0
        self.field_ids_off = 0
        self.method_ids_size = 0
        self.method_ids_off = 0
        self.class_defs_size = 0
        self.class_defs_off = 0
        self._strings: dict[int, str] = {}
        self._types: dict[int, str] = {}
        self._protos: dict[int, str] = {}
        self._methods: dict[int, str] = {}
        self._decoded_string_bytes = 0
        self._proto_text_bytes = 0
        self._method_text_bytes = 0
        self._report_estimated_bytes = 0
        self._class_members_total = 0
        self._catch_handlers_total = 0
        self._catch_items_total = 0
        self.validated_try_items = 0
        self._total_code_units = 0
        self._used_code_offsets: set[int] = set()
        self._sites: list[InvokeSite] = []
        self._scanned = False
        self._read_header()

    def _span(self, off: int, length: int, label: str) -> None:
        if off < 0 or length < 0 or off > self.size or length > self.size - off:
            raise DexError(f"{label} extends beyond DEX input")

    def _data_span(self, off: int, length: int, label: str) -> None:
        self._span(off, length, label)
        if off < self.data_off:
            raise DexError(f"{label} is outside data section")

    def _u16(self, off: int) -> int:
        self._span(off, 2, "u16")
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        self._span(off, 4, "u32")
        return struct.unpack_from("<I", self.data, off)[0]

    def _i32(self, off: int) -> int:
        self._span(off, 4, "i32")
        return struct.unpack_from("<i", self.data, off)[0]

    def _uleb(self, off: int) -> tuple[int, int]:
        value = 0
        for i in range(5):
            self._data_span(off + i, 1, "ULEB128")
            byte = self.data[off + i]
            if i == 4 and byte > 0x0F:
                raise DexError("ULEB128 exceeds 32 bits")
            value |= (byte & 0x7F) << (7 * i)
            if byte < 0x80:
                return value, off + i + 1
        raise DexError("unterminated ULEB128")

    def _sleb(self, off: int) -> tuple[int, int]:
        value = 0
        for i in range(5):
            self._data_span(off + i, 1, "SLEB128")
            byte = self.data[off + i]
            value |= (byte & 0x7F) << (7 * i)
            if byte < 0x80:
                if byte & 0x40:
                    value -= 1 << (7 * (i + 1))
                if not -(1 << 31) <= value < (1 << 31):
                    raise DexError("SLEB128 exceeds 32 bits")
                return value, off + i + 1
        raise DexError("unterminated SLEB128")

    def _read_header(self) -> None:
        magic = self.data[:8]
        if magic[:4] != b"dex\n" or magic[7] != 0:
            raise DexError("unsupported DEX magic")
        self.version = magic[4:7].decode("ascii", errors="ignore")
        if self.version not in {"035", "036", "037", "038", "039", "040"}:
            raise DexError("unsupported DEX version")
        if self._u32(32) != self.size:
            raise DexError("header file_size does not match input")
        if self._u32(36) != 112:
            raise DexError("unsupported DEX header_size")
        if self._u32(40) != 0x12345678:
            raise DexError("unsupported DEX endianness")
        if self.data[12:32] != hashlib.sha1(self.data[32:]).digest():
            raise DexError("DEX SHA-1 signature mismatch")
        if self._u32(8) != zlib.adler32(self.data[12:]) & 0xFFFFFFFF:
            raise DexError("DEX Adler-32 checksum mismatch")

        map_off = self._u32(52)
        self.string_ids_size, self.string_ids_off = self._u32(56), self._u32(60)
        self.type_ids_size, self.type_ids_off = self._u32(64), self._u32(68)
        self.proto_ids_size, self.proto_ids_off = self._u32(72), self._u32(76)
        self.field_ids_size, self.field_ids_off = self._u32(80), self._u32(84)
        self.method_ids_size, self.method_ids_off = self._u32(88), self._u32(92)
        self.class_defs_size, self.class_defs_off = self._u32(96), self._u32(100)
        self.data_size, self.data_off = self._u32(104), self._u32(108)
        if self.data_off < 112 or self.data_off % 4 or self.data_size == 0:
            raise DexError("invalid data section")
        if self.data_off + self.data_size != self.size:
            raise DexError("data section does not end at file_size")
        self._data_span(map_off, 4, "map_list")
        if map_off % 4:
            raise DexError("unaligned map_list")

        tables = [
            ("string_ids", self.string_ids_size, self.string_ids_off, 4),
            ("type_ids", self.type_ids_size, self.type_ids_off, 4),
            ("proto_ids", self.proto_ids_size, self.proto_ids_off, 12),
            ("field_ids", self.field_ids_size, self.field_ids_off, 8),
            ("method_ids", self.method_ids_size, self.method_ids_off, 8),
            ("class_defs", self.class_defs_size, self.class_defs_off, 32),
        ]
        occupied: list[tuple[int, int, str]] = []
        for name, count, off, width in tables:
            if count == 0:
                if off != 0:
                    raise DexError(f"empty {name} has a nonzero offset")
                continue
            if off < 112 or off % 4 or off >= self.data_off:
                raise DexError(f"invalid {name} offset")
            length = count * width
            self._span(off, length, name)
            if off + length > self.data_off:
                raise DexError(f"{name} overlaps data section")
            occupied.append((off, off + length, name))
        occupied.sort()
        for previous, current in zip(occupied, occupied[1:]):
            if previous[1] > current[0]:
                raise DexError(f"{previous[2]} overlaps {current[2]}")

    def _string(self, index: int) -> str:
        if not 0 <= index < self.string_ids_size:
            raise DexError("string index out of bounds")
        if index in self._strings:
            return self._strings[index]
        off = self._u32(self.string_ids_off + index * 4)
        self._data_span(off, 1, "string_data_item")
        utf16_length, at = self._uleb(off)
        if utf16_length > MAX_STRING_UTF16_UNITS:
            raise DexError("DEX string exceeds UTF-16 unit budget")
        end = self.data.find(b"\x00", at, min(self.size, at + MAX_STRING_ENCODED_BYTES + 1))
        if end < 0:
            raise DexError("unterminated or over-budget DEX string")
        raw = self.data[at:end]
        self._decoded_string_bytes += len(raw)
        if self._decoded_string_bytes > MAX_DECODED_STRING_BYTES_TOTAL:
            raise DexError("DEX decoded string budget exceeded")
        value = _decode_mutf8(raw, utf16_length)
        self._strings[index] = value
        return value

    def _type(self, index: int) -> str:
        if not 0 <= index < self.type_ids_size:
            raise DexError("type index out of bounds")
        if index not in self._types:
            descriptor_index = self._u32(self.type_ids_off + index * 4)
            self._types[index] = self._string(descriptor_index)
        return self._types[index]

    def _proto(self, index: int) -> str:
        if not 0 <= index < self.proto_ids_size:
            raise DexError("prototype index out of bounds")
        if index in self._protos:
            return self._protos[index]
        off = self.proto_ids_off + index * 12
        self._string(self._u32(off))  # shorty index must resolve even if unused
        return_type = self._type(self._u32(off + 4))
        parameters_off = self._u32(off + 8)
        params: list[str] = []
        text_bytes = 2 + len(return_type.encode("utf-8", "surrogatepass"))
        if text_bytes > MAX_SYMBOL_TEXT_BYTES:
            raise DexError("prototype text budget exceeded")
        if parameters_off:
            if parameters_off % 4:
                raise DexError("unaligned type_list")
            self._data_span(parameters_off, 4, "type_list")
            count = self._u32(parameters_off)
            if count > MAX_PROTO_PARAMETERS:
                raise DexError("type_list exceeds supported parameter budget")
            self._data_span(parameters_off, 4 + 2 * count, "type_list")
            for i in range(count):
                param = self._type(self._u16(parameters_off + 4 + i * 2))
                text_bytes += len(param.encode("utf-8", "surrogatepass"))
                if text_bytes > MAX_SYMBOL_TEXT_BYTES:
                    raise DexError("prototype text budget exceeded")
                params.append(param)
        value = "(" + "".join(params) + ")" + return_type
        self._proto_text_bytes += text_bytes
        if self._proto_text_bytes > MAX_PROTO_TEXT_BYTES_TOTAL:
            raise DexError("DEX prototype text budget exceeded")
        self._protos[index] = value
        return value

    def _method(self, index: int) -> str:
        if not 0 <= index < self.method_ids_size:
            raise DexError("method index out of bounds")
        if index not in self._methods:
            off = self.method_ids_off + index * 8
            class_type = self._type(self._u16(off))
            proto = self._proto(self._u16(off + 2))
            name = self._string(self._u32(off + 4))
            value = f"{class_type}->{name}{proto}"
            text_bytes = len(value.encode("utf-8", "surrogatepass"))
            if text_bytes > MAX_SYMBOL_TEXT_BYTES:
                raise DexError("method text budget exceeded")
            self._method_text_bytes += text_bytes
            if self._method_text_bytes > MAX_METHOD_TEXT_BYTES_TOTAL:
                raise DexError("DEX method text budget exceeded")
            self._methods[index] = value
        return self._methods[index]

    @staticmethod
    def _instruction_width(units: list[int], pc: int) -> int:
        unit = units[pc]
        opcode = unit & 0xFF
        if opcode == 0:
            if unit == 0:
                return 1
            if pc + 1 >= len(units):
                raise DexError("truncated payload header")
            count = units[pc + 1]
            if unit == 0x0100:
                return 4 + 2 * count
            if unit == 0x0200:
                return 2 + 4 * count
            if unit == 0x0300:
                if pc + 3 >= len(units):
                    raise DexError("truncated array-data payload")
                if count not in {1, 2, 4, 8}:
                    raise DexError("unsupported array-data element width")
                elements = units[pc + 2] | (units[pc + 3] << 16)
                return 4 + (count * elements + 1) // 2
            raise DexError("unknown payload identifier")
        if opcode in _WIDTH_2 or 0x2D <= opcode <= 0x3D or 0x44 <= opcode <= 0x6D:
            return 2
        if opcode in _WIDTH_3 or 0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78:
            return 3
        if 0x90 <= opcode <= 0xAF or 0xD0 <= opcode <= 0xE2:
            return 2
        if opcode in {0xFA, 0xFB}:
            return 4
        if opcode in {0xFC, 0xFD}:
            return 3
        if opcode == 0x18:
            return 5
        if (
            opcode in {0x01, 0x04, 0x07, 0x1D, 0x1E, 0x21, 0x27, 0x28}
            or 0x0A <= opcode <= 0x12
            or 0x7B <= opcode <= 0x8F
            or 0xB0 <= opcode <= 0xCF
        ):
            return 1
        raise DexError(f"unsupported DEX opcode 0x{opcode:02x}")

    def _scan_code(self, caller_index: int, code_off: int) -> None:
        if code_off % 4:
            raise DexError("unaligned code_item")
        if code_off in self._used_code_offsets:
            raise DexError("two methods share one code_item offset")
        self._used_code_offsets.add(code_off)
        self._data_span(code_off, 16, "code_item")
        tries_size = self._u16(code_off + 6)
        debug_info_off = self._u32(code_off + 8)
        if debug_info_off:
            self._data_span(debug_info_off, 1, "debug_info_item")
        count = self._u32(code_off + 12)
        self._total_code_units += count
        if count == 0 or self._total_code_units > MAX_CODE_UNITS_TOTAL:
            raise DexError("code unit budget exceeded or empty code_item")
        insns_off = code_off + 16
        self._data_span(insns_off, count * 2, "code instructions")
        units = list(struct.unpack_from(f"<{count}H", self.data, insns_off))
        starts: set[int] = set()
        payload_refs: list[tuple[int, int]] = []
        pc = 0
        while pc < count:
            starts.add(pc)
            if units[pc] in {0x0100, 0x0200, 0x0300} and pc & 1:
                raise DexError("unaligned DEX payload pseudo-instruction")
            width = self._instruction_width(units, pc)
            if pc + width > count:
                raise DexError("truncated DEX instruction or payload")
            opcode = units[pc] & 0xFF
            if (opcode in {0xFA, 0xFB, 0xFC, 0xFD} and self.version < "038") or (
                opcode in {0xFE, 0xFF} and self.version < "039"
            ):
                raise DexError("instruction not defined for this DEX version")
            if opcode in _INVOKES:
                target_index = units[pc + 1]
                target = self._method(target_index)
                caller = self._method(caller_index)
                if opcode in {0xFA, 0xFB}:
                    self._proto(units[pc + 3])
                self._report_estimated_bytes += 256 + 6 * (
                    len(caller.encode("utf-8", "surrogatepass"))
                    + len(target.encode("utf-8", "surrogatepass"))
                )
                if self._report_estimated_bytes > MAX_REPORT_ESTIMATED_BYTES:
                    raise DexError("DEX report budget exceeded")
                self._sites.append(
                    InvokeSite(
                        caller=caller,
                        caller_method_index=caller_index,
                        code_unit_offset=pc,
                        file_offset=insns_off + 2 * pc,
                        opcode=_INVOKES[opcode],
                        target=target,
                        target_method_index=target_index,
                    )
                )
                if len(self._sites) > MAX_INVOKE_SITES:
                    raise DexError("invocation site budget exceeded")
            elif opcode in {0xFC, 0xFD}:
                raise DexError("invoke-custom call-site references are unsupported")
            elif opcode in {0x26, 0x2B, 0x2C}:
                relative = units[pc + 1] | (units[pc + 2] << 16)
                if relative & 0x80000000:
                    relative -= 1 << 32
                expected = {0x26: 0x0300, 0x2B: 0x0100, 0x2C: 0x0200}[opcode]
                payload_refs.append((pc + relative, expected))
            pc += width
        for target_pc, expected in payload_refs:
            if target_pc not in starts or units[target_pc] != expected:
                raise DexError("invalid switch or array-data payload offset")
        self._validate_tries(code_off, count, tries_size, starts)
        self.validated_try_items += tries_size

    def _validate_tries(
        self, code_off: int, insns_size: int, tries_size: int, starts: set[int]
    ) -> None:
        if tries_size == 0:
            return
        after_insns = code_off + 16 + 2 * insns_size
        if insns_size & 1 and self._u16(after_insns) != 0:
            raise DexError("nonzero code_item padding")
        tries_off = after_insns + (2 if insns_size & 1 else 0)
        self._data_span(tries_off, 8 * tries_size, "try_item list")
        handler_offsets = [self._u16(tries_off + i * 8 + 6) for i in range(tries_size)]
        previous_end = 0
        for i in range(tries_size):
            start = self._u32(tries_off + 8 * i)
            length = self._u16(tries_off + 8 * i + 4)
            if length == 0 or start >= insns_size or length > insns_size - start:
                raise DexError("try_item range outside code")
            end = start + length
            if start < previous_end or start not in starts or (
                end != insns_size and end not in starts
            ):
                raise DexError("try_item range is unaligned or overlaps")
            previous_end = end
        handlers_off = tries_off + 8 * tries_size
        count, at = self._uleb(handlers_off)
        if count == 0 or count > 65535:
            raise DexError("invalid encoded_catch_handler_list size")
        self._catch_handlers_total += count
        if self._catch_handlers_total > MAX_CATCH_HANDLERS_TOTAL:
            raise DexError("DEX catch handler list budget exceeded")
        seen: set[int] = set()
        for _ in range(count):
            seen.add(at - handlers_off)
            signed_count, at = self._sleb(at)
            if abs(signed_count) > 65535:
                raise DexError("catch handler count exceeds supported budget")
            self._catch_items_total += abs(signed_count) + int(signed_count <= 0)
            if self._catch_items_total > MAX_CATCH_ITEMS_TOTAL:
                raise DexError("DEX catch item budget exceeded")
            for _ in range(abs(signed_count)):
                type_index, at = self._uleb(at)
                address, at = self._uleb(at)
                self._type(type_index)
                if address not in starts:
                    raise DexError("catch handler target outside instruction boundaries")
            if signed_count <= 0:
                address, at = self._uleb(at)
                if address not in starts:
                    raise DexError("catch-all target outside instruction boundaries")
        if any(offset not in seen for offset in handler_offsets):
            raise DexError("try_item references missing catch handler")

    def _scan_class_data(self, class_index: int, off: int) -> None:
        self._data_span(off, 1, "class_data_item")
        static_count, off = self._uleb(off)
        instance_count, off = self._uleb(off)
        direct_count, off = self._uleb(off)
        virtual_count, off = self._uleb(off)
        if static_count + instance_count > self.field_ids_size:
            raise DexError("class_data field count exceeds field table")
        if direct_count + virtual_count > self.method_ids_size:
            raise DexError("class_data method count exceeds method table")
        self._class_members_total += static_count + instance_count + direct_count + virtual_count
        if self._class_members_total > MAX_CLASS_MEMBERS_TOTAL:
            raise DexError("class_data member budget exceeded")
        for count in (static_count, instance_count):
            field_index = 0
            for _ in range(count):
                delta, off = self._uleb(off)
                _, off = self._uleb(off)  # access_flags
                field_index += delta
                if field_index >= self.field_ids_size:
                    raise DexError("encoded field index out of bounds")
        for count in (direct_count, virtual_count):
            method_index = 0
            for _ in range(count):
                delta, off = self._uleb(off)
                _, off = self._uleb(off)  # access_flags
                code_off, off = self._uleb(off)
                method_index += delta
                if method_index >= self.method_ids_size:
                    raise DexError("encoded method index out of bounds")
                method_class = self._u16(self.method_ids_off + method_index * 8)
                if method_class != class_index:
                    raise DexError("encoded method belongs to a different class")
                if code_off:
                    self._scan_code(method_index, code_off)

    def scan(self) -> list[InvokeSite]:
        """Return every supported method-reference invocation in class methods."""
        if self._scanned:
            raise RuntimeError("scan() can only be called once")
        self._scanned = True
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            class_index = self._u32(off)
            self._type(class_index)
            class_data_off = self._u32(off + 24)
            if class_data_off:
                self._scan_class_data(class_index, class_data_off)
        return sorted(self._sites, key=lambda site: site.file_offset)


def scan_dex_file(path: str) -> tuple[DexInvokeParser, list[InvokeSite]]:
    with open(path, "rb") as source:
        data = source.read(MAX_FILE_BYTES + 1)
    parser = DexInvokeParser(data)
    return parser, parser.scan()
