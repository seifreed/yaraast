# Copyright (c) 2026 Marc Rivero López
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for the public exports in yaraast.lsp.lsp_types."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Normal-path symbol exports
# ---------------------------------------------------------------------------


class TestNormalPathExports:
    """Verify every name in __all__ is accessible after a normal import."""

    def test_yaraast_runtime_status_constant(self) -> None:
        """YARAAST_RUNTIME_STATUS must equal the protocol method string."""
        from yaraast.lsp.lsp_types import YARAAST_RUNTIME_STATUS

        assert YARAAST_RUNTIME_STATUS == "yaraast/status"

    def test_text_document_method_constants_are_strings(self) -> None:
        """TEXT_DOCUMENT_* constants must be non-empty strings."""
        from yaraast.lsp.lsp_types import (
            TEXT_DOCUMENT_CODE_ACTION,
            TEXT_DOCUMENT_COMPLETION,
            TEXT_DOCUMENT_DEFINITION,
            TEXT_DOCUMENT_DIAGNOSTIC,
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
            TEXT_DOCUMENT_SELECTION_RANGE,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
            TEXT_DOCUMENT_SIGNATURE_HELP,
        )

        constants = [
            TEXT_DOCUMENT_CODE_ACTION,
            TEXT_DOCUMENT_COMPLETION,
            TEXT_DOCUMENT_DEFINITION,
            TEXT_DOCUMENT_DIAGNOSTIC,
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
            TEXT_DOCUMENT_SELECTION_RANGE,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
            TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
            TEXT_DOCUMENT_SIGNATURE_HELP,
        ]
        for constant in constants:
            message = f"Expected non-empty string, got {constant!r}"
            assert isinstance(constant, str) and constant, message

    def test_workspace_constants_are_strings(self) -> None:
        """WORKSPACE_* constants must be non-empty strings."""
        from yaraast.lsp.lsp_types import (
            WORKSPACE_DID_CHANGE_CONFIGURATION,
            WORKSPACE_DID_CHANGE_WATCHED_FILES,
            WORKSPACE_SYMBOL,
        )

        assert isinstance(WORKSPACE_DID_CHANGE_CONFIGURATION, str)
        assert isinstance(WORKSPACE_DID_CHANGE_WATCHED_FILES, str)
        assert isinstance(WORKSPACE_SYMBOL, str)

    def test_lsprotocol_types_are_classes(self) -> None:
        """All re-exported lsprotocol classes must be importable as real types."""
        from yaraast.lsp.lsp_types import (
            CodeAction,
            CodeActionOptions,
            CodeActionParams,
            CompletionList,
            CompletionOptions,
            CompletionParams,
            DefinitionParams,
            DiagnosticOptions,
            DidChangeConfigurationParams,
            DidChangeTextDocumentParams,
            DidChangeWatchedFilesParams,
            DidCloseTextDocumentParams,
            DidOpenTextDocumentParams,
            DidSaveTextDocumentParams,
            DocumentDiagnosticParams,
            DocumentDiagnosticReportKind,
            DocumentFormattingParams,
            DocumentHighlight,
            DocumentHighlightParams,
            DocumentLink,
            DocumentLinkParams,
            DocumentRangeFormattingParams,
            DocumentSymbol,
            DocumentSymbolParams,
            FoldingRange,
            FoldingRangeParams,
            FullDocumentDiagnosticReport,
            Hover,
            HoverParams,
            InitializeParams,
            Location,
            PrepareRenameParams,
            Range,
            ReferenceParams,
            RelatedFullDocumentDiagnosticReport,
            RenameParams,
            SelectionRange,
            SelectionRangeParams,
            SemanticTokens,
            SemanticTokensParams,
            SemanticTokensRangeParams,
            SemanticTokensRegistrationOptions,
            SignatureHelp,
            SignatureHelpOptions,
            SignatureHelpParams,
            SymbolInformation,
            TextEdit,
            WorkspaceEdit,
            WorkspaceFoldersServerCapabilities,
            WorkspaceSymbolParams,
        )

        exported_types = [
            CodeAction,
            CodeActionOptions,
            CodeActionParams,
            CompletionList,
            CompletionOptions,
            CompletionParams,
            DefinitionParams,
            DiagnosticOptions,
            DidChangeConfigurationParams,
            DidChangeTextDocumentParams,
            DidChangeWatchedFilesParams,
            DidCloseTextDocumentParams,
            DidOpenTextDocumentParams,
            DidSaveTextDocumentParams,
            DocumentDiagnosticParams,
            DocumentDiagnosticReportKind,
            DocumentFormattingParams,
            DocumentHighlight,
            DocumentHighlightParams,
            DocumentLink,
            DocumentLinkParams,
            DocumentRangeFormattingParams,
            DocumentSymbol,
            DocumentSymbolParams,
            FoldingRange,
            FoldingRangeParams,
            FullDocumentDiagnosticReport,
            Hover,
            HoverParams,
            InitializeParams,
            Location,
            PrepareRenameParams,
            Range,
            ReferenceParams,
            RelatedFullDocumentDiagnosticReport,
            RenameParams,
            SelectionRange,
            SelectionRangeParams,
            SemanticTokens,
            SemanticTokensParams,
            SemanticTokensRangeParams,
            SemanticTokensRegistrationOptions,
            SignatureHelp,
            SignatureHelpOptions,
            SignatureHelpParams,
            SymbolInformation,
            TextEdit,
            WorkspaceEdit,
            WorkspaceFoldersServerCapabilities,
            WorkspaceSymbolParams,
        ]
        for t in exported_types:
            assert isinstance(t, type) or callable(t), f"{t!r} is not a type or callable"

    def test_all_list_completeness(self) -> None:
        """Every name in __all__ must be resolvable as a real attribute."""
        import yaraast.lsp.lsp_types as lsp_types_mod

        for name in lsp_types_mod.__all__:
            assert hasattr(lsp_types_mod, name), f"__all__ member {name!r} not found on module"

    def test_did_open_method_string_value(self) -> None:
        """TEXT_DOCUMENT_DID_OPEN must carry the canonical LSP method name."""
        from yaraast.lsp.lsp_types import TEXT_DOCUMENT_DID_OPEN

        assert TEXT_DOCUMENT_DID_OPEN == "textDocument/didOpen"

    def test_hover_method_string_value(self) -> None:
        """TEXT_DOCUMENT_HOVER must carry the canonical LSP method name."""
        from yaraast.lsp.lsp_types import TEXT_DOCUMENT_HOVER

        assert TEXT_DOCUMENT_HOVER == "textDocument/hover"
