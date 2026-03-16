"""Factory helpers for constructing the YARA language server."""

from __future__ import annotations

from yaraast.lsp.code_actions import CodeActionsProvider
from yaraast.lsp.completion import CompletionProvider
from yaraast.lsp.definition import DefinitionProvider
from yaraast.lsp.diagnostics import DiagnosticsProvider
from yaraast.lsp.document_highlight import DocumentHighlightProvider
from yaraast.lsp.document_links import DocumentLinksProvider
from yaraast.lsp.folding_ranges import FoldingRangesProvider
from yaraast.lsp.formatting import FormattingProvider
from yaraast.lsp.hover import HoverProvider
from yaraast.lsp.references import ReferencesProvider
from yaraast.lsp.rename import RenameProvider
from yaraast.lsp.runtime import LspRuntime
from yaraast.lsp.selection_range import SelectionRangeProvider
from yaraast.lsp.semantic_tokens import SemanticTokensProvider
from yaraast.lsp.signature_help import SignatureHelpProvider
from yaraast.lsp.symbols import SymbolsProvider
from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider


def create_runtime() -> LspRuntime:
    """Create the runtime used by the language server."""
    return LspRuntime()


def configure_providers(server, runtime: LspRuntime) -> None:
    """Attach all LSP providers to a server instance."""
    server.diagnostics_provider = DiagnosticsProvider(runtime)
    server.completion_provider = CompletionProvider(runtime)
    server.hover_provider = HoverProvider(runtime)
    server.definition_provider = DefinitionProvider(runtime)
    server.references_provider = ReferencesProvider(runtime)
    server.symbols_provider = SymbolsProvider(runtime)
    server.formatting_provider = FormattingProvider(runtime)
    server.code_actions_provider = CodeActionsProvider()
    server.rename_provider = RenameProvider(runtime)
    server.semantic_tokens_provider = SemanticTokensProvider(runtime)
    server.selection_range_provider = SelectionRangeProvider(runtime)
    server.signature_help_provider = SignatureHelpProvider()
    server.document_highlight_provider = DocumentHighlightProvider()
    server.folding_ranges_provider = FoldingRangesProvider()
    server.document_links_provider = DocumentLinksProvider(runtime)
    server.workspace_symbols_provider = WorkspaceSymbolsProvider(runtime)
