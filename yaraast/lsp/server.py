"""YARA Language Server implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pygls.lsp.server import LanguageServer  # pygls >= 2.0
else:
    try:
        from pygls.lsp.server import LanguageServer  # pygls >= 2.0
    except ImportError:
        from pygls.server import LanguageServer  # pygls < 2.0

from yaraast.lsp.server_factory import configure_providers, create_runtime
from yaraast.lsp.server_features import register_initialize, register_server_features

if TYPE_CHECKING:
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


class YaraLanguageServer(LanguageServer):
    """YARA Language Server."""

    runtime: LspRuntime
    diagnostics_provider: DiagnosticsProvider
    completion_provider: CompletionProvider
    hover_provider: HoverProvider
    definition_provider: DefinitionProvider
    references_provider: ReferencesProvider
    symbols_provider: SymbolsProvider
    formatting_provider: FormattingProvider
    code_actions_provider: CodeActionsProvider
    rename_provider: RenameProvider
    semantic_tokens_provider: SemanticTokensProvider
    selection_range_provider: SelectionRangeProvider
    signature_help_provider: SignatureHelpProvider
    document_highlight_provider: DocumentHighlightProvider
    folding_ranges_provider: FoldingRangesProvider
    document_links_provider: DocumentLinksProvider
    workspace_symbols_provider: WorkspaceSymbolsProvider
    protocol: Any
    lsp: Any

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self.runtime = create_runtime()
        configure_providers(self, self.runtime)

        # Register features
        register_server_features(self)

    # Compatibility shims for pygls 1.x API used throughout the codebase.
    # pygls 2.0 renamed these methods.

    if not hasattr(LanguageServer, "show_message_log"):

        def show_message_log(self, message: str, msg_type: Any = None) -> None:
            from lsprotocol.types import LogMessageParams, MessageType

            self.window_log_message(LogMessageParams(type=MessageType.Log, message=message))

    if not hasattr(LanguageServer, "publish_diagnostics"):

        def publish_diagnostics(self, uri: str, diagnostics: Any = None) -> None:
            from lsprotocol.types import PublishDiagnosticsParams

            self.text_document_publish_diagnostics(
                PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics or [])
            )


def create_server() -> YaraLanguageServer:
    """Create and configure the YARA Language Server."""
    server = YaraLanguageServer("yaraast-lsp", "v0.1.0")
    register_initialize(server)

    return server


def main() -> None:
    """Main entry point for the language server."""
    server = create_server()
    server.start_io()


if __name__ == "__main__":
    main()
