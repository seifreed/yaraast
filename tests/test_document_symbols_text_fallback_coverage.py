"""Coverage for the text-based document symbol builders.

When a document fails to parse, symbols are recovered from raw text. These tests
drive that fallback over imports, includes, rules, sections, meta entries (int,
bool, string, float values) and string definitions.
"""

from __future__ import annotations

from typing import Any

import pytest

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_symbols import (
    _iter_text_rules,
    _parse_text_meta_value,
    _quoted_text_range,
    build_text_symbols,
)

TRUNCATED_SOURCE = """import "pe"
include "./other.yar"
rule alpha {
    meta:
        author = "alice"
        score = 5
        active = true
        ratio = 1.5
    strings:
        $a = "plain"
        $b = { 4D 5A }
        $c = /re/
    condition:
}
"""


def test_build_text_symbols_recovers_all_kinds() -> None:
    doc = DocumentContext(uri="file://x.yar", text=TRUNCATED_SOURCE)
    symbols = build_text_symbols(doc, doc.lines)
    kinds = {symbol.kind for symbol in symbols}

    assert {"import", "include", "rule", "section", "meta", "string"} <= kinds
    names = {(symbol.kind, symbol.name) for symbol in symbols}
    assert ("import", "pe") in names
    assert ("include", "./other.yar") in names
    assert ("rule", "alpha") in names
    assert ("string", "$a") in names


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("5", 5),
        ("true", True),
        ("false", False),
        ('"hello"', "hello"),
        ("1.5", 1.5),
        ("null", None),
        ("none", None),
        ("unquoted_word", None),
    ],
)
def test_parse_text_meta_value(raw: str, expected: Any | None) -> None:
    assert _parse_text_meta_value(raw) == expected


def test_iter_text_rules_finds_rule() -> None:
    doc = DocumentContext(uri="file://x.yar", text=TRUNCATED_SOURCE)
    rules = _iter_text_rules(doc.lines)
    assert any(name == "alpha" for name, _start, _col in rules)


def test_quoted_text_range_found_and_missing() -> None:
    assert _quoted_text_range('author = "alice"', 0, "alice") is not None
    assert _quoted_text_range("no quotes here", 0, "absent") is None
