"""Additional tests for small helper modules without mocks."""

from __future__ import annotations

import struct

from yaraast.ast.modifiers import StringModifier
from yaraast.codegen.generator_helpers import (
    escape_plain_string_value,
    format_integer_literal,
    format_modifiers,
)
from yaraast.dialects import YaraDialect, detect_dialect
from yaraast.evaluation.evaluation_helpers import (
    BUILTIN_READERS,
    LITTLE_ENDIAN_ALIASES,
    _read_int8,
    _read_int16,
    _read_int16_be,
    _read_int32,
    _read_int32_be,
    _read_uint8,
    _read_uint16,
    _read_uint16_be,
    _read_uint32,
    _read_uint32_be,
    read_struct,
)
from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_helpers import (
    _skip_block_comment,
    _skip_line_comment,
    _skip_line_continuation,
    skip_whitespace_and_comments,
)


def test_lexer_helpers_skip_whitespace_comments_and_line_continuation() -> None:
    lex = Lexer("  \t\r\n// line comment\n/* block */rule")
    skip_whitespace_and_comments(lex)
    assert lex._current_char() == "r"

    combined = Lexer("\\  \n// c\n/* b */x")
    skip_whitespace_and_comments(combined)
    assert combined._current_char() == "x"

    cont = Lexer("\\  \r\nx")
    _skip_line_continuation(cont)
    assert cont._current_char() == "x"

    cont_cr = Lexer("\\\rx")
    _skip_line_continuation(cont_cr)
    assert cont_cr._current_char() == "x"

    cont_lf = Lexer("\\\nx")
    _skip_line_continuation(cont_lf)
    assert cont_lf._current_char() == "x"

    line = Lexer("// comment only\nx")
    _skip_line_comment(line)
    assert line._current_char() == "\n"

    block = Lexer("/* comment */x")
    _skip_block_comment(block)
    assert block._current_char() == "x"

    unterminated = Lexer("/* unterminated")
    _skip_block_comment(unterminated)
    assert unterminated.position == len(unterminated.text)  # Consumes entire unterminated comment


def test_evaluation_helpers_read_struct_and_builtin_readers() -> None:
    data = bytes([0x7F]) + struct.pack("<H", 0x1234) + struct.pack("<I", 0x12345678)
    data += struct.pack("b", -2) + struct.pack("<h", -1234) + struct.pack("<i", -56789)
    data += struct.pack(">H", 0xBEEF) + struct.pack(">I", 0xA1B2C3D4)
    data += struct.pack(">h", -2222) + struct.pack(">i", -333333)

    assert read_struct(data, "B", -1, 1) == 0
    assert read_struct(data, "I", len(data), 4) == 0

    assert _read_uint8(data, 0) == 0x7F
    assert _read_uint16(data, 1) == 0x1234
    assert _read_uint32(data, 3) == 0x12345678
    assert _read_int8(data, 7) == -2
    assert _read_int16(data, 8) == -1234
    assert _read_int32(data, 10) == -56789
    assert _read_uint16_be(data, 14) == 0xBEEF
    assert _read_uint32_be(data, 16) == 0xA1B2C3D4
    assert _read_int16_be(data, 20) == -2222
    assert _read_int32_be(data, 22) == -333333

    assert BUILTIN_READERS["uint16"](data, 1) == 0x1234
    assert BUILTIN_READERS[LITTLE_ENDIAN_ALIASES["uint16le"]](data, 1) == 0x1234
    assert LITTLE_ENDIAN_ALIASES["int32le"] == "int32"


def test_generator_helpers_escape_integer_and_modifiers() -> None:
    escaped = escape_plain_string_value('a\\b"c\n\r\t\x00\x01')
    assert escaped == 'a\\\\b\\"c\\n\\r\\t\\x00\\x01'

    assert format_integer_literal("not-a-number") == "not-a-number"
    assert format_integer_literal("1024") == "0x400"
    assert format_integer_literal(0x4D5A) == "0x4D5A"
    assert format_integer_literal(0x30) == "48"
    assert format_integer_literal(0x200) == "0x200"
    assert format_integer_literal(255) == "255"

    mod = StringModifier.from_name_value("ascii")
    assert format_modifiers(["wide", mod, 7], lambda node: f"<{node.name}>") == " wide <ascii> 7"
    assert format_modifiers(("nocase",), lambda node: "") == " nocase"
    assert format_modifiers("private", lambda node: "") == " private"
    assert format_modifiers({"x"}, lambda node: "") == ""
    assert format_modifiers(123, lambda node: "") == ""


def test_detect_dialect_yaral_signals_and_default_yara() -> None:
    structural = """
rule login_event {
  events:
    $e.metadata.event_type = "LOGIN"
  condition:
    $e
}
"""
    assert detect_dialect(structural) == YaraDialect.YARA_L

    udm = 'rule x { condition: $e.principal.hostname == "host" }'
    assert detect_dialect(udm) == YaraDialect.YARA_L

    agg = 'rule x { condition: count_distinct("src") > 2 }'
    assert detect_dialect(agg) == YaraDialect.YARA_L

    plain_yara = 'rule classic { strings: $a = "events:" condition: $a }'
    assert detect_dialect(plain_yara) == YaraDialect.YARA


def test_detect_dialect_yarax_signals() -> None:
    yarax_lambda = "rule x { condition: lambda x, y: x + y }"
    assert detect_dialect(yarax_lambda) == YaraDialect.YARA_X

    yarax_match = "rule x { condition: match x { 1 => 2, _ => 3 } }"
    assert detect_dialect(yarax_match) == YaraDialect.YARA_X

    yarax_array_comp = "rule x { condition: [x for x in items if x] }"
    assert detect_dialect(yarax_array_comp) == YaraDialect.YARA_X

    yarax_with = 'rule x { condition: with $a = "test", $b = 2: true }'
    assert detect_dialect(yarax_with) == YaraDialect.YARA_X
