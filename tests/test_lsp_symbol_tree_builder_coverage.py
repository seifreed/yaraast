"""Coverage for the LSP document-symbol text-fallback path and brace helpers.

The text-based symbol builder and its brace-counting helpers are used when a
document does not parse. These tests drive that path (including imports) and the
pure helpers directly with string-literal, comment and escape edge cases.
"""

from __future__ import annotations

import pytest

from yaraast.lsp.symbol_tree_builder import (
    _count_braces_outside_literals,
    find_closing_brace,
    find_line_containing,
)
from yaraast.lsp.symbols import SymbolsProvider


def test_find_line_containing_found_and_missing() -> None:
    lines = ["nothing", "here is rule x", "tail"]
    assert find_line_containing(lines, "rule") == 1
    assert find_line_containing(lines, "rule", start=2) == -1
    assert find_line_containing(lines, "absent") == -1


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("rule x { body }", (1, 1)),
        ('$a = "a{b}c" {', (1, 0)),
        ("} // } trailing comment", (0, 1)),
        (r'"escaped \" quote" }', (0, 1)),
        ("plain text", (0, 0)),
    ],
)
def test_count_braces_outside_literals(line: str, expected: tuple[int, int]) -> None:
    assert _count_braces_outside_literals(line) == expected


def test_find_closing_brace_spans_lines() -> None:
    lines = ["rule x {", "  condition: true", "}", "trailing"]
    assert find_closing_brace(lines, 0) == 2


def test_find_closing_brace_unterminated_returns_last_line() -> None:
    lines = ["rule x {", "  condition: true"]
    assert find_closing_brace(lines, 0) == len(lines) - 1


def test_text_fallback_includes_imports_and_rule() -> None:
    # Unparseable (truncated) source still yields text-based symbols.
    truncated = (
        'import "pe"\n'
        'import "math"\n'
        "rule broken {\n"
        "  strings:\n"
        '    $a = "x"\n'
        "  condition:\n"
    )
    symbols = SymbolsProvider().get_symbols(truncated)
    names = [symbol.name for symbol in symbols]
    assert 'import "pe"' in names
    assert 'import "math"' in names
    assert "broken" in names
