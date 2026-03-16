"""Real tests for LSP symbols provider (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.lsp.symbols import SymbolsProvider


def test_symbols_for_rules_and_sections() -> None:
    text = dedent(
        """
        import "pe"

        rule alpha : t1 {
            meta:
                author = "unit"
            strings:
                $a = "abc"
            condition:
                $a and pe.is_pe
        }
        """,
    ).lstrip()

    provider = SymbolsProvider()
    symbols = provider.get_symbols(text)

    names = [s.name for s in symbols]
    assert any(name == 'import "pe"' for name in names)
    assert "alpha" in names

    alpha = next(s for s in symbols if s.name == "alpha")
    child_names = [c.name for c in (alpha.children or [])]
    assert "meta" in child_names
    assert "strings" in child_names
    assert "condition" in child_names
