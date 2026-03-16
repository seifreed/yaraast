"""Real tests for LSP server initialization (no mocks)."""

from __future__ import annotations

from yaraast.lsp.server import YaraLanguageServer


def test_lsp_server_initializes_providers() -> None:
    server = YaraLanguageServer("yaraast", "0.1")

    assert server.diagnostics_provider is not None
    assert server.completion_provider is not None
    assert server.hover_provider is not None
    assert server.definition_provider is not None
    assert server.references_provider is not None
    assert server.symbols_provider is not None
    assert server.formatting_provider is not None
    assert server.code_actions_provider is not None
    assert server.rename_provider is not None
    assert server.semantic_tokens_provider is not None
    assert server.selection_range_provider is not None
    assert server.signature_help_provider is not None
    assert server.document_highlight_provider is not None
    assert server.folding_ranges_provider is not None
    assert server.document_links_provider is not None
    assert server.workspace_symbols_provider is not None
    assert server.runtime is not None
