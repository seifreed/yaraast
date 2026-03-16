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


def register_language_handlers(server) -> None:
    @server.feature(
        TEXT_DOCUMENT_COMPLETION,
        CompletionOptions(trigger_characters=[".", "$", '"', "!", "@", "#"]),
    )
    async def completions(ls, params: CompletionParams) -> CompletionList:
        document = get_document_source(ls, params.text_document.uri)
        return ls.completion_provider.get_completions(
            document, params.position, params.text_document.uri
        )

    @server.feature(TEXT_DOCUMENT_HOVER)
    async def hover(ls, params: HoverParams) -> Hover | None:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.hover_provider.get_hover(document, params.position, uri)

    @server.feature(TEXT_DOCUMENT_DEFINITION)
    async def definition(ls, params: DefinitionParams) -> Location | list[Location] | None:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.definition_provider.get_definition(document, params.position, uri)

    @server.feature(TEXT_DOCUMENT_REFERENCES)
    async def references(ls, params: ReferenceParams) -> list[Location]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.references_provider.get_references(
            document, params.position, uri, params.context.include_declaration
        )

    @server.feature(TEXT_DOCUMENT_DOCUMENT_SYMBOL)
    async def document_symbol(ls, params: DocumentSymbolParams) -> list[DocumentSymbol]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.symbols_provider.get_symbols(document, uri)

    @server.feature(TEXT_DOCUMENT_FORMATTING)
    async def formatting(ls, params: DocumentFormattingParams) -> list[TextEdit]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.formatting_provider.format_document(document, uri)

    @server.feature(TEXT_DOCUMENT_RANGE_FORMATTING)
    async def range_formatting(ls, params: DocumentRangeFormattingParams) -> list[TextEdit]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.formatting_provider.format_range(
            document, params.range.start, params.range.end, uri
        )

    @server.feature(
        TEXT_DOCUMENT_CODE_ACTION, CodeActionOptions(code_action_kinds=["quickfix", "refactor"])
    )
    async def code_action(ls, params: CodeActionParams) -> list[CodeAction]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.code_actions_provider.get_code_actions(
            document, params.range, params.context.diagnostics, uri
        )

    @server.feature(TEXT_DOCUMENT_PREPARE_RENAME)
    async def prepare_rename(ls, params: PrepareRenameParams) -> Range | None:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.rename_provider.prepare_rename(document, params.position, uri)

    @server.feature(TEXT_DOCUMENT_RENAME)
    async def rename(ls, params: RenameParams) -> WorkspaceEdit | None:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.rename_provider.rename(document, params.position, params.new_name, uri)

    @server.feature(
        TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL,
        SemanticTokensRegistrationOptions(
            legend=server.semantic_tokens_provider.get_legend(), full=True, range=True
        ),
    )
    async def semantic_tokens_full(ls, params: SemanticTokensParams) -> SemanticTokens:
        document = get_document_source(ls, params.text_document.uri)
        return get_semantic_tokens(ls, document, params.text_document.uri)

    @server.feature(TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE)
    async def semantic_tokens_range(ls, params: SemanticTokensRangeParams) -> SemanticTokens:
        document = get_document_source(ls, params.text_document.uri)
        return get_semantic_tokens_range(ls, document, params.text_document.uri, params.range)

    @server.feature(TEXT_DOCUMENT_SELECTION_RANGE)
    async def selection_range(ls, params: SelectionRangeParams) -> list[SelectionRange]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.selection_range_provider.get_selection_ranges(document, params.positions, uri)

    @server.feature(
        TEXT_DOCUMENT_DIAGNOSTIC,
        DiagnosticOptions(inter_file_dependencies=True, workspace_diagnostics=False),
    )
    async def document_diagnostic(
        ls, params: DocumentDiagnosticParams
    ) -> RelatedFullDocumentDiagnosticReport:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        diagnostics = get_diagnostics(ls, document, uri)
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

    @server.feature(
        TEXT_DOCUMENT_SIGNATURE_HELP, SignatureHelpOptions(trigger_characters=["(", ","])
    )
    async def signature_help(ls, params: SignatureHelpParams) -> SignatureHelp | None:
        document = get_document_source(ls, params.text_document.uri)
        return ls.signature_help_provider.get_signature_help(document, params.position)

    @server.feature(TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT)
    async def document_highlight(ls, params: DocumentHighlightParams) -> list[DocumentHighlight]:
        document = get_document_source(ls, params.text_document.uri)
        return ls.document_highlight_provider.get_highlights(document, params.position)

    @server.feature(TEXT_DOCUMENT_FOLDING_RANGE)
    async def folding_range(ls, params: FoldingRangeParams) -> list[FoldingRange]:
        document = get_document_source(ls, params.text_document.uri)
        return ls.folding_ranges_provider.get_folding_ranges(document)

    @server.feature(TEXT_DOCUMENT_DOCUMENT_LINK)
    async def document_link(ls, params: DocumentLinkParams) -> list[DocumentLink]:
        uri = params.text_document.uri
        document = get_document_source(ls, uri)
        return ls.document_links_provider.get_document_links(document, uri)

    @server.feature(WORKSPACE_SYMBOL)
    async def workspace_symbol(ls, params: WorkspaceSymbolParams) -> list[SymbolInformation]:
        return ls.workspace_symbols_provider.get_workspace_symbols(params.query)
