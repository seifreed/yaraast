"""Language feature handler registration for the language server."""

from __future__ import annotations

from yaraast.lsp.lsp_types import (
    TEXT_DOCUMENT_CODE_ACTION,
    TEXT_DOCUMENT_COMPLETION,
    TEXT_DOCUMENT_DEFINITION,
    TEXT_DOCUMENT_DIAGNOSTIC,
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
    WORKSPACE_SYMBOL,
    CodeAction,
    CodeActionOptions,
    CodeActionParams,
    CompletionList,
    CompletionOptions,
    CompletionParams,
    DefinitionParams,
    DiagnosticOptions,
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
    Hover,
    HoverParams,
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
    WorkspaceSymbolParams,
)
from yaraast.lsp.server_feature_helpers import (
    get_diagnostics,
    get_document_source,
    get_semantic_tokens,
    get_semantic_tokens_range,
)

# ── Top-level handler functions ──────────────────────────────────────────


async def _completions(ls, params: CompletionParams) -> CompletionList:
    doc = get_document_source(ls, params.text_document.uri)
    return ls.completion_provider.get_completions(doc, params.position, params.text_document.uri)


async def _hover(ls, params: HoverParams) -> Hover | None:
    uri = params.text_document.uri
    return ls.hover_provider.get_hover(get_document_source(ls, uri), params.position, uri)


async def _definition(ls, params: DefinitionParams) -> Location | list[Location] | None:
    uri = params.text_document.uri
    return ls.definition_provider.get_definition(get_document_source(ls, uri), params.position, uri)


async def _references(ls, params: ReferenceParams) -> list[Location]:
    uri = params.text_document.uri
    doc = get_document_source(ls, uri)
    return ls.references_provider.get_references(
        doc, params.position, uri, params.context.include_declaration
    )


async def _document_symbol(ls, params: DocumentSymbolParams) -> list[DocumentSymbol]:
    uri = params.text_document.uri
    return ls.symbols_provider.get_symbols(get_document_source(ls, uri), uri)


async def _formatting(ls, params: DocumentFormattingParams) -> list[TextEdit]:
    uri = params.text_document.uri
    return ls.formatting_provider.format_document(get_document_source(ls, uri), uri)


async def _range_formatting(ls, params: DocumentRangeFormattingParams) -> list[TextEdit]:
    uri = params.text_document.uri
    doc = get_document_source(ls, uri)
    return ls.formatting_provider.format_range(doc, params.range.start, params.range.end, uri)


async def _code_action(ls, params: CodeActionParams) -> list[CodeAction]:
    uri = params.text_document.uri
    doc = get_document_source(ls, uri)
    return ls.code_actions_provider.get_code_actions(
        doc, params.range, params.context.diagnostics, uri
    )


async def _prepare_rename(ls, params: PrepareRenameParams) -> Range | None:
    uri = params.text_document.uri
    return ls.rename_provider.prepare_rename(get_document_source(ls, uri), params.position, uri)


async def _rename(ls, params: RenameParams) -> WorkspaceEdit | None:
    uri = params.text_document.uri
    doc = get_document_source(ls, uri)
    return ls.rename_provider.rename(doc, params.position, params.new_name, uri)


async def _semantic_tokens_full(ls, params: SemanticTokensParams) -> SemanticTokens:
    doc = get_document_source(ls, params.text_document.uri)
    return get_semantic_tokens(ls, doc, params.text_document.uri)


async def _semantic_tokens_range(ls, params: SemanticTokensRangeParams) -> SemanticTokens:
    doc = get_document_source(ls, params.text_document.uri)
    return get_semantic_tokens_range(ls, doc, params.text_document.uri, params.range)


async def _selection_range(ls, params: SelectionRangeParams) -> list[SelectionRange]:
    uri = params.text_document.uri
    return ls.selection_range_provider.get_selection_ranges(
        get_document_source(ls, uri), params.positions, uri
    )


async def _document_diagnostic(
    ls, params: DocumentDiagnosticParams
) -> RelatedFullDocumentDiagnosticReport:
    uri = params.text_document.uri
    diagnostics = get_diagnostics(ls, get_document_source(ls, uri), uri)
    runtime = getattr(ls, "runtime", None)
    result_id = None
    if runtime is not None:
        doc = runtime.get_document(uri, load_workspace=False)
        result_id = doc.revision_key() if doc is not None else None
    return RelatedFullDocumentDiagnosticReport(
        items=diagnostics,
        related_documents=None,
        kind=DocumentDiagnosticReportKind.Full,
        result_id=result_id,
    )


async def _signature_help(ls, params: SignatureHelpParams) -> SignatureHelp | None:
    doc = get_document_source(ls, params.text_document.uri)
    return ls.signature_help_provider.get_signature_help(doc, params.position)


async def _document_highlight(ls, params: DocumentHighlightParams) -> list[DocumentHighlight]:
    doc = get_document_source(ls, params.text_document.uri)
    return ls.document_highlight_provider.get_highlights(doc, params.position)


async def _folding_range(ls, params: FoldingRangeParams) -> list[FoldingRange]:
    return ls.folding_ranges_provider.get_folding_ranges(
        get_document_source(ls, params.text_document.uri)
    )


async def _document_link(ls, params: DocumentLinkParams) -> list[DocumentLink]:
    uri = params.text_document.uri
    return ls.document_links_provider.get_document_links(get_document_source(ls, uri), uri)


async def _workspace_symbol(ls, params: WorkspaceSymbolParams) -> list[SymbolInformation]:
    return ls.workspace_symbols_provider.get_workspace_symbols(params.query)


# ── Declarative registration ─────────────────────────────────────────────

# Simple handlers: (protocol_constant, handler_function)
_SIMPLE_HANDLERS = [
    (TEXT_DOCUMENT_HOVER, _hover),
    (TEXT_DOCUMENT_DEFINITION, _definition),
    (TEXT_DOCUMENT_REFERENCES, _references),
    (TEXT_DOCUMENT_DOCUMENT_SYMBOL, _document_symbol),
    (TEXT_DOCUMENT_FORMATTING, _formatting),
    (TEXT_DOCUMENT_RANGE_FORMATTING, _range_formatting),
    (TEXT_DOCUMENT_PREPARE_RENAME, _prepare_rename),
    (TEXT_DOCUMENT_RENAME, _rename),
    (TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE, _semantic_tokens_range),
    (TEXT_DOCUMENT_SELECTION_RANGE, _selection_range),
    (TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT, _document_highlight),
    (TEXT_DOCUMENT_FOLDING_RANGE, _folding_range),
    (TEXT_DOCUMENT_DOCUMENT_LINK, _document_link),
    (WORKSPACE_SYMBOL, _workspace_symbol),
]


def register_language_handlers(server) -> None:
    """Register all language feature handlers on the server."""
    # Simple handlers (no options)
    for protocol_const, handler in _SIMPLE_HANDLERS:
        server.feature(protocol_const)(handler)

    # Handlers with options
    server.feature(
        TEXT_DOCUMENT_COMPLETION,
        CompletionOptions(trigger_characters=[".", "$", '"', "!", "@", "#"]),
    )(_completions)

    server.feature(
        TEXT_DOCUMENT_CODE_ACTION,
        CodeActionOptions(code_action_kinds=["quickfix", "refactor"]),
    )(_code_action)

    server.feature(
        TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
        SemanticTokensRegistrationOptions(
            legend=server.semantic_tokens_provider.get_legend(), full=True, range=True
        ),
    )(_semantic_tokens_full)

    server.feature(
        TEXT_DOCUMENT_DIAGNOSTIC,
        DiagnosticOptions(inter_file_dependencies=True, workspace_diagnostics=False),
    )(_document_diagnostic)

    server.feature(
        TEXT_DOCUMENT_SIGNATURE_HELP,
        SignatureHelpOptions(trigger_characters=["(", ","]),
    )(_signature_help)
