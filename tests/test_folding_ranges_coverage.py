"""Coverage for the LSP folding ranges brace/comment/string scanner."""

from __future__ import annotations

from yaraast.lsp.folding_ranges import FoldingRangesProvider

SCANNER_RULE = (
    "rule alpha {\n"
    "    strings:\n"
    '        $a = "with \\" escaped"\n'
    "        $r = /a\\/b/\n"
    "    condition:\n"
    "        $a /* inline\n"
    "           block */ and  // line comment\n"
    "        $r\n"
    "}\n"
)


def test_folding_ranges_handles_strings_regex_and_comments() -> None:
    ranges = FoldingRangesProvider().get_folding_ranges(SCANNER_RULE)
    assert any(r.start_line == 0 for r in ranges)


def test_folding_ranges_empty_and_single_line() -> None:
    provider = FoldingRangesProvider()
    assert provider.get_folding_ranges("") == []
    assert provider.get_folding_ranges("rule r { condition: true }") == []
