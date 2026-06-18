"""More tests for LSP symbols provider (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.lsp.symbols import SymbolsProvider


@pytest.mark.parametrize("text", [None, 1, b"rule a", object()])
def test_symbols_rejects_non_string_text(text: Any) -> None:
    provider = SymbolsProvider()

    with pytest.raises(TypeError, match="Symbols text must be a string"):
        provider.get_symbols(cast(str, text), "file://test.yar")


def test_symbols_rejects_invalid_uri() -> None:
    provider = SymbolsProvider()

    with pytest.raises(TypeError, match="Symbols URI must be a string or None"):
        provider.get_symbols("rule a { condition: true }", cast(str, object()))


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

    broken = provider.get_symbols("""
rule bad {
  meta:
    author = "me"
  strings:
    $a = "x"
  condition:
""")
    assert [symbol.name for symbol in broken] == ["bad"]
    assert [child.name for child in (broken[0].children or [])] == ["meta", "strings", "condition"]


def test_symbols_provider_handles_context_creation_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaraast.lsp.symbols as symbols_module

    def fail_document_context(
        _runtime: object,
        _uri: str | None,
        _text: str,
        *,
        fallback_uri: str = "",
    ) -> object:
        raise RuntimeError("context failed")

    monkeypatch.setattr(symbols_module, "get_document_context", fail_document_context)

    assert SymbolsProvider().get_symbols("rule ok { condition: true }") == []
