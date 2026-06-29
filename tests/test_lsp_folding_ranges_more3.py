"""More tests for LSP folding ranges provider (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.lsp.folding_ranges import FoldingRangesProvider
from yaraast.lsp.structure import (
    find_rule_end,
    find_rule_line,
    find_section_header_position,
    find_section_line,
    find_string_line,
)
from yaraast.parser.parser import Parser


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_folding_ranges_rejects_non_string_text(text: Any) -> None:
    provider = FoldingRangesProvider()

    with pytest.raises(TypeError, match="Folding ranges text must be a string"):
        provider.get_folding_ranges(cast(str, text))


def test_folding_ranges_imports_and_sections() -> None:
    text = """
import "pe"
import "math"

rule a {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    provider = FoldingRangesProvider()
    ranges = provider.get_folding_ranges(text)
    assert any(r.kind is not None for r in ranges)
    assert any(r.start_line == 0 for r in ranges)


def test_folding_ranges_ignore_section_names_inside_literals() -> None:
    text = """
rule a {
  strings:
    $a = "condition: decoy"
  condition:
    $a
}
""".lstrip()
    provider = FoldingRangesProvider()
    ranges = provider.get_folding_ranges(text)

    assert any(range_.start_line == 3 for range_ in ranges)
    assert all(range_.start_line != 2 for range_ in ranges)


def test_structure_scanners_ignore_section_names_inside_matches_regex() -> None:
    text = """
rule sample {
  condition:
    "abc" matches /strings:/
}
""".lstrip()
    lines = text.split("\n")

    assert find_section_header_position(lines, "strings", 0, 3) is None
    assert find_rule_end(lines, 0) == 3


@pytest.mark.parametrize("section_name", [None, 1, b"strings", object()])
def test_structure_find_section_header_position_rejects_non_string_names(
    section_name: Any,
) -> None:
    lines = ["rule a {", "strings:", '  $a = "x"', "condition:", "  $a", "}"]

    with pytest.raises(TypeError, match="Section name must be a string"):
        find_section_header_position(lines, cast(str, section_name), 0, len(lines) - 1)


def test_folding_ranges_match_exact_rule_names() -> None:
    text = """
rule foobar {
  condition:
    true
}
rule foo {
  condition:
    true
}
""".lstrip()
    lines = text.split("\n")
    provider = FoldingRangesProvider()
    ranges = provider.get_folding_ranges(text)

    assert find_rule_line(lines, "foo") == 4
    assert any(range_.start_line == 4 and range_.end_line == 7 for range_ in ranges)


def test_structure_find_string_line_rejects_empty_identifier() -> None:
    lines = ['rule a { strings: $a = "x" condition: $a }']

    assert find_string_line(lines, "") == -1


@pytest.mark.parametrize("section_header", [None, 1, b"strings:", object()])
def test_structure_find_section_line_rejects_non_string_headers(
    section_header: Any,
) -> None:
    lines = ["rule a {", "strings:", '  $a = "x"', "condition:", "  $a", "}"]

    with pytest.raises(TypeError, match="Section header must be a string"):
        find_section_line(lines, cast(str, section_header), 0)


@pytest.mark.parametrize("string_id", [None, 1, b"$a", object()])
def test_structure_find_string_line_rejects_non_string_identifiers(
    string_id: Any,
) -> None:
    lines = ["rule a {", "strings:", '  $a = "x"', "condition:", "  $a", "}"]

    with pytest.raises(TypeError, match="String identifier must be a string"):
        find_string_line(lines, cast(str, string_id), 0)


def test_folding_ranges_fallback_on_invalid() -> None:
    text = "rule a { \n  condition: true \n  "
    provider = FoldingRangesProvider()
    ranges = provider.get_folding_ranges(text)
    # fallback should still return something when braces mismatch
    assert isinstance(ranges, list)


def test_folding_ranges_helper_edges() -> None:
    provider = FoldingRangesProvider()

    assert provider._get_import_block_lines("rule a { condition: true }", []) is None
    assert (
        provider._get_import_block_lines('import "pe"\nrule a { condition: true }', [object()])
        is None
    )

    parsed = Parser(
        """
rule a {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()
    ).parse()
    rule = parsed.rules[0]
    rule.name = "missing"
    assert provider._get_rule_folding_range("rule a {\n  condition:\n    true\n}\n", rule) is None
    assert provider._get_section_folding_ranges("rule a {\n  condition:\n    true\n}\n", rule) == []

    actual_rule = Parser("rule a {\n  condition:\n    true\n}\n").parse().rules[0]
    assert (
        provider._get_rule_folding_range("rule a {\n  condition:\n    true\n", actual_rule) is None
    )

    lines = ["rule a {", "  meta:", "}"]
    assert provider._find_section_range(lines, 0, "strings:") is None
    assert provider._find_section_range(lines, 0, "meta:") is None

    fallback = provider._fallback_folding_ranges("rule a {\n}\n")
    assert len(fallback) == 1

    fallback_nested = provider._fallback_folding_ranges('rule a {\n  strings:\n    $a = "x"\n}\n')
    assert len(fallback_nested) == 1

    fallback_comment = provider._fallback_folding_ranges("rule a {\n  // }\n  condition: true\n}\n")
    assert len(fallback_comment) == 1
    assert fallback_comment[0].start_line == 0
    assert fallback_comment[0].end_line == 3
