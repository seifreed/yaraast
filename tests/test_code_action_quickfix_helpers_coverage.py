"""Coverage for semantic quickfix argument-parsing helpers."""

from __future__ import annotations

from lsprotocol.types import Diagnostic, Position, Range
import pytest

from yaraast.lsp.code_action_semantic_quickfixes import (
    _find_diagnostic_occurrence,
    _scan_quoted_end,
    _split_top_level_arguments,
)


@pytest.mark.parametrize(
    ("args_text", "expected"),
    [
        ("a, b, c", ["a", "b", "c"]),
        ("f(a, b), c", ["f(a, b)", "c"]),
        ("arr[1, 2], x", ["arr[1, 2]", "x"]),
        ("{a, b}, c", ["{a, b}", "c"]),
        ('"a,b", c', ['"a,b"', "c"]),
        ("x matches /a,b/, y", ["x matches /a,b/", "y"]),
        ("a // comment\n, b", ["a // comment", "b"]),
        ("a /* x, y */, b", ["a /* x, y */", "b"]),
        ("", []),
    ],
)
def test_split_top_level_arguments(args_text: str, expected: list[str]) -> None:
    assert _split_top_level_arguments(args_text) == expected


@pytest.mark.parametrize(
    ("text", "start", "delimiter", "expected"),
    [
        ('"hello" rest', 0, '"', 6),
        ('"no end', 0, '"', 6),
        (r'"a\"b" x', 0, '"', 5),
    ],
)
def test_scan_quoted_end(text: str, start: int, delimiter: str, expected: int) -> None:
    assert _scan_quoted_end(text, start, delimiter) == expected


def test_find_diagnostic_occurrence() -> None:
    line = "condition: pe.imports(x) and pe.imports(y)"
    diagnostic = Diagnostic(
        range=Range(start=Position(line=0, character=29), end=Position(line=0, character=39)),
        message="x",
    )
    assert _find_diagnostic_occurrence(line, "pe.imports", diagnostic) == 29
    assert _find_diagnostic_occurrence(line, "absent", diagnostic) == -1
    assert _find_diagnostic_occurrence(line, "", diagnostic) == -1
