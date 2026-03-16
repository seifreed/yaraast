"""More tests for LSP symbols provider (no mocks)."""

from __future__ import annotations

from yaraast.lsp.symbols import SymbolsProvider


def test_symbols_includes_meta_strings_condition() -> None:
    text = """
import "pe"

rule alpha {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
    $a
}
""".lstrip()

    provider = SymbolsProvider()
    symbols = provider.get_symbols(text)

    names = [sym.name for sym in symbols]
    assert 'import "pe"' in names
    assert "alpha" in names

    rule_sym = next(sym for sym in symbols if sym.name == "alpha")
    child_names = [child.name for child in (rule_sym.children or [])]
    assert "meta" in child_names
    assert "strings" in child_names
    assert "condition" in child_names


def test_symbols_helper_and_fallback_edges() -> None:
    provider = SymbolsProvider()

    assert provider._find_line_containing(["a", "b"], "z") == -1
    assert provider._find_closing_brace(["rule a {", "  condition: true"], 0) == 1
    rng = provider._make_range(1, 2, 3, 4)
    assert rng.start.line == 1 and rng.end.character == 4

    assert provider.get_symbols("rule bad { condition: ") == []
