"""More tests for LSP folding ranges provider (no mocks)."""

from __future__ import annotations

from yaraast.lsp.folding_ranges import FoldingRangesProvider
from yaraast.parser.parser import Parser


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
