"""Real tests for LSP symbols provider (no mocks)."""

from __future__ import annotations

from textwrap import dedent
from typing import NoReturn

import pytest

from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.symbol_tree_builder import build_document_symbols as real_build_document_symbols
import yaraast.lsp.symbols as symbols_module
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


def test_symbols_provider_does_not_cache_empty_result_after_internal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "rule sample { condition: true }\n"
    uri = "file:///sample.yar"
    provider = SymbolsProvider(LspRuntime())

    def fail_build_symbols(*_args: object, **_kwargs: object) -> NoReturn:
        raise RuntimeError("transient symbol failure")

    monkeypatch.setattr(symbols_module, "build_document_symbols", fail_build_symbols)
    failed = provider.get_symbols(text, uri)
    assert failed == []

    monkeypatch.setattr(symbols_module, "build_document_symbols", real_build_document_symbols)
    recovered = provider.get_symbols(text, uri)

    assert [symbol.name for symbol in recovered] == ["sample"]
