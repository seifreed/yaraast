"""Regression: high-byte plain strings survive a parse -> generate round trip.

Before raw_bytes tracking, ``$a = "\\xe9"`` (libyara byte 0xE9) regenerated as
``$a = "é"`` which libyara re-reads as the UTF-8 bytes 0xC3 0xA9 -- the round
trip silently changed the matched bytes. The lexer now records the exact bytes,
so codegen re-escapes high bytes faithfully.
"""

from __future__ import annotations

import pytest

from yaraast import Parser
from yaraast.ast.strings import PlainString
from yaraast.codegen.advanced_generator_helpers2 import render_advanced_plain_string
from yaraast.codegen.formatting import FormattingConfig
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.options import GeneratorOptions
from yaraast.codegen.pretty_printer import PrettyPrintOptions, pretty_print

yara = pytest.importorskip("yara")

_CASES = [
    (r'rule t { strings: $a = "\xe9" condition: $a }', b"\xe9"),
    (r'rule t { strings: $a = "caf\xe9bar" condition: $a }', b"caf\xe9bar"),
    ('rule t { strings: $a = "café" condition: $a }', b"caf\xc3\xa9"),
    (r'rule t { strings: $a = "x\x00y\x80\xff" condition: $a }', b"x\x00y\x80\xff"),
]


@pytest.mark.parametrize(("source", "expected_bytes"), _CASES)
def test_lexer_records_exact_plain_string_bytes(source: str, expected_bytes: bytes) -> None:
    ast = Parser(source).parse()
    plain = ast.rules[0].strings[0]
    assert isinstance(plain, PlainString)
    assert plain.raw_bytes == expected_bytes


@pytest.mark.parametrize(("source", "expected_bytes"), _CASES)
def test_regenerated_rule_matches_same_bytes_as_original(
    source: str, expected_bytes: bytes
) -> None:
    ast = Parser(source).parse()
    regenerated = CodeGenerator().generate(ast)

    original_match = bool(yara.compile(source=source).match(data=expected_bytes))
    regenerated_match = bool(yara.compile(source=regenerated).match(data=expected_bytes))
    assert original_match
    assert regenerated_match == original_match


def test_high_byte_escape_is_not_reencoded_as_utf8() -> None:
    ast = Parser(r'rule t { strings: $a = "\xe9" condition: $a }').parse()
    regenerated = CodeGenerator().generate(ast)
    # The single byte 0xE9 must round-trip, not the UTF-8 pair 0xC3 0xA9.
    assert '"\\xe9"' in regenerated
    assert not yara.compile(source=regenerated).match(data=b"\xc3\xa9")


def test_advanced_and_pretty_engines_are_byte_faithful() -> None:
    source = r'rule t { strings: $a = "caf\xe9" condition: $a }'
    ast = Parser(source).parse()

    advanced = CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig())).generate(ast)
    pretty = pretty_print(ast, PrettyPrintOptions())

    for rendered in (advanced, pretty):
        assert bool(yara.compile(source=rendered).match(data=b"caf\xe9"))
        assert not yara.compile(source=rendered).match(data=b"caf\xc3\xa9")


def test_render_advanced_plain_string_uses_raw_bytes_directly() -> None:
    ast = Parser(r'rule t { strings: $a = "\xff" condition: $a }').parse()
    plain = ast.rules[0].strings[0]

    generator = CodeGenerator(options=GeneratorOptions(advanced=FormattingConfig()))
    render_advanced_plain_string(generator, plain)
    assert generator.buffer.getvalue() == '$a = "\\xff"'
