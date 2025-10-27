"""YARA Language Server implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lsprotocol.types import (
    TEXT_DOCUMENT_CODE_ACTION,
    TEXT_DOCUMENT_COMPLETION,
    TEXT_DOCUMENT_DEFINITION,
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
    TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT,
    TEXT_DOCUMENT_DOCUMENT_LINK,
    TEXT_DOCUMENT_DOCUMENT_SYMBOL,
    TEXT_DOCUMENT_FOLDING_RANGE,
    TEXT_DOCUMENT_FORMATTING,
    TEXT_DOCUMENT_HOVER,
    TEXT_DOCUMENT_PREPARE_RENAME,
    TEXT_DOCUMENT_RANGE_FORMATTING,
    TEXT_DOCUMENT_REFERENCES,
    TEXT_DOCUMENT_RENAME,
    TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
    TEXT_DOCUMENT_SIGNATURE_HELP,
    WORKSPACE_SYMBOL,
    CodeActionOptions,
    CodeActionParams,
    CompletionOptions,
    CompletionParams,
    DefinitionParams,
    DidChangeTextDocumentParams,
    DidCloseTextDocumentParams,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
    DocumentFormattingParams,
    DocumentHighlightParams,
    DocumentLinkParams,
    DocumentRangeFormattingParams,
    DocumentSymbolParams,
    FoldingRangeParams,
    HoverParams,
    PrepareRenameParams,
    ReferenceParams,
    RenameParams,
    SemanticTokensLegend,
    SemanticTokensParams,
    SemanticTokensRegistrationOptions,
    SignatureHelpOptions,
    SignatureHelpParams,
    TextDocumentSyncKind,
    WorkspaceSymbolParams,
)
from pygls.server import LanguageServer

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
from yaraast.lsp.semantic_tokens import SemanticTokensProvider
from yaraast.lsp.signature_help import SignatureHelpProvider
from yaraast.lsp.symbols import SymbolsProvider
from yaraast.lsp.workspace_symbols import WorkspaceSymbolsProvider

if TYPE_CHECKING:
    pass


class YaraLanguageServer(LanguageServer):
    """YARA Language Server."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Initialize providers
        self.diagnostics_provider = DiagnosticsProvider()
        self.completion_provider = CompletionProvider()
        self.hover_provider = HoverProvider()
        self.definition_provider = DefinitionProvider()
        self.references_provider = ReferencesProvider()
        self.symbols_provider = SymbolsProvider()
        self.formatting_provider = FormattingProvider()
        self.code_actions_provider = CodeActionsProvider()
        self.rename_provider = RenameProvider()
        self.semantic_tokens_provider = SemanticTokensProvider()

        # New advanced providers
        self.signature_help_provider = SignatureHelpProvider()
        self.document_highlight_provider = DocumentHighlightProvider()
        self.folding_ranges_provider = FoldingRangesProvider()
        self.document_links_provider = DocumentLinksProvider()
        self.workspace_symbols_provider = WorkspaceSymbolsProvider()

        # Register features
        self._register_features()

    def _register_features(self) -> None:
        """Register LSP features."""

        # Text document synchronization
        @self.feature(TEXT_DOCUMENT_DID_OPEN)
        async def did_open(ls: YaraLanguageServer, params: DidOpenTextDocumentParams):
            """Handle document open event."""
            ls.show_message_log("Document opened")
            document = ls.workspace.get_text_document(params.text_document.uri)
            diagnostics = ls.diagnostics_provider.get_diagnostics(document.source)
            ls.publish_diagnostics(document.uri, diagnostics)

        @self.feature(TEXT_DOCUMENT_DID_CHANGE)
        async def did_change(ls: YaraLanguageServer, params: DidChangeTextDocumentParams):
            """Handle document change event."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            diagnostics = ls.diagnostics_provider.get_diagnostics(document.source)
            ls.publish_diagnostics(document.uri, diagnostics)

        @self.feature(TEXT_DOCUMENT_DID_SAVE)
        async def did_save(ls: YaraLanguageServer, params: DidSaveTextDocumentParams):
            """Handle document save event."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            diagnostics = ls.diagnostics_provider.get_diagnostics(document.source)
            ls.publish_diagnostics(document.uri, diagnostics)

        @self.feature(TEXT_DOCUMENT_DID_CLOSE)
        async def did_close(ls: YaraLanguageServer, params: DidCloseTextDocumentParams):
            """Handle document close event."""
            ls.show_message_log("Document closed")

        # Completion
        @self.feature(
            TEXT_DOCUMENT_COMPLETION,
            CompletionOptions(trigger_characters=[".", "$", '"']),
        )
        async def completions(ls: YaraLanguageServer, params: CompletionParams):
            """Provide completions."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.completion_provider.get_completions(
                document.source,
                params.position,
            )

        # Hover
        @self.feature(TEXT_DOCUMENT_HOVER)
        async def hover(ls: YaraLanguageServer, params: HoverParams):
            """Provide hover information."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.hover_provider.get_hover(document.source, params.position)

        # Definition
        @self.feature(TEXT_DOCUMENT_DEFINITION)
        async def definition(ls: YaraLanguageServer, params: DefinitionParams):
            """Provide go-to-definition."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.definition_provider.get_definition(
                document.source,
                params.position,
                document.uri,
            )

        # References
        @self.feature(TEXT_DOCUMENT_REFERENCES)
        async def references(ls: YaraLanguageServer, params: ReferenceParams):
            """Provide find-all-references."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.references_provider.get_references(
                document.source,
                params.position,
                document.uri,
                params.context.include_declaration,
            )

        # Document symbols
        @self.feature(TEXT_DOCUMENT_DOCUMENT_SYMBOL)
        async def document_symbol(ls: YaraLanguageServer, params: DocumentSymbolParams):
            """Provide document symbols."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.symbols_provider.get_symbols(document.source)

        # Formatting
        @self.feature(TEXT_DOCUMENT_FORMATTING)
        async def formatting(ls: YaraLanguageServer, params: DocumentFormattingParams):
            """Provide document formatting."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.formatting_provider.format_document(document.source)

        @self.feature(TEXT_DOCUMENT_RANGE_FORMATTING)
        async def range_formatting(ls: YaraLanguageServer, params: DocumentRangeFormattingParams):
            """Provide range formatting."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.formatting_provider.format_range(
                document.source,
                params.range.start,
                params.range.end,
            )

        # Code actions
        @self.feature(
            TEXT_DOCUMENT_CODE_ACTION,
            CodeActionOptions(code_action_kinds=["quickfix", "refactor"]),
        )
        async def code_action(ls: YaraLanguageServer, params: CodeActionParams):
            """Provide code actions."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.code_actions_provider.get_code_actions(
                document.source,
                params.range,
                params.context.diagnostics,
                document.uri,
            )

        # Rename
        @self.feature(TEXT_DOCUMENT_PREPARE_RENAME)
        async def prepare_rename(ls: YaraLanguageServer, params: PrepareRenameParams):
            """Prepare for rename."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.rename_provider.prepare_rename(document.source, params.position)

        @self.feature(TEXT_DOCUMENT_RENAME)
        async def rename(ls: YaraLanguageServer, params: RenameParams):
            """Perform rename."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.rename_provider.rename(
                document.source,
                params.position,
                params.new_name,
                document.uri,
            )

        # Semantic tokens
        @self.feature(
            TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
            SemanticTokensRegistrationOptions(
                legend=SemanticTokensProvider.get_legend(),
                full=True,
            ),
        )
        async def semantic_tokens_full(ls: YaraLanguageServer, params: SemanticTokensParams):
            """Provide semantic tokens."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.semantic_tokens_provider.get_semantic_tokens(document.source)

        # Signature help
        @self.feature(
            TEXT_DOCUMENT_SIGNATURE_HELP,
            SignatureHelpOptions(trigger_characters=["(", ","]),
        )
        async def signature_help(ls: YaraLanguageServer, params: SignatureHelpParams):
            """Provide signature help."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.signature_help_provider.get_signature_help(
                document.source,
                params.position,
            )

        # Document highlight
        @self.feature(TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT)
        async def document_highlight(ls: YaraLanguageServer, params: DocumentHighlightParams):
            """Provide document highlights."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.document_highlight_provider.get_highlights(
                document.source,
                params.position,
            )

        # Folding ranges
        @self.feature(TEXT_DOCUMENT_FOLDING_RANGE)
        async def folding_range(ls: YaraLanguageServer, params: FoldingRangeParams):
            """Provide folding ranges."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.folding_ranges_provider.get_folding_ranges(document.source)

        # Document links
        @self.feature(TEXT_DOCUMENT_DOCUMENT_LINK)
        async def document_link(ls: YaraLanguageServer, params: DocumentLinkParams):
            """Provide document links."""
            document = ls.workspace.get_text_document(params.text_document.uri)
            return ls.document_links_provider.get_document_links(
                document.source,
                document.uri,
            )

        # Workspace symbols
        @self.feature(WORKSPACE_SYMBOL)
        async def workspace_symbol(ls: YaraLanguageServer, params: WorkspaceSymbolParams):
            """Provide workspace symbols."""
            return ls.workspace_symbols_provider.get_workspace_symbols(params.query)


def create_server() -> YaraLanguageServer:
    """Create and configure the YARA Language Server."""
    server = YaraLanguageServer("yaraast-lsp", "v0.1.0")

    @server.feature("initialize")
    def initialize(params):
        """Initialize the server."""
        server.show_message_log("YARAAST Language Server initialized")

        # Set workspace root for workspace symbols
        if hasattr(params, "root_uri") and params.root_uri:
            root_path = params.root_uri.replace("file://", "")
            server.workspace_symbols_provider.set_workspace_root(root_path)
        elif hasattr(params, "root_path") and params.root_path:
            server.workspace_symbols_provider.set_workspace_root(params.root_path)

    return server


def main():
    """Main entry point for the language server."""
    server = create_server()
    server.start_io()


if __name__ == "__main__":
    main()
