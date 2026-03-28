"""Document lifecycle and runtime handler registration for the language server."""

from __future__ import annotations

import logging

from yaraast.lsp.lsp_types import (
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
    WORKSPACE_DID_CHANGE_CONFIGURATION,
    WORKSPACE_DID_CHANGE_WATCHED_FILES,
    YARAAST_RUNTIME_STATUS,
    DidChangeConfigurationParams,
    DidChangeTextDocumentParams,
    DidChangeWatchedFilesParams,
    DidCloseTextDocumentParams,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
)
from yaraast.lsp.server_feature_helpers import get_diagnostics, get_document_source

logger = logging.getLogger(__name__)


def register_document_handlers(server) -> None:
    # Length is due to 7 short handler registrations; splitting would reduce locality.
    @server.feature(TEXT_DOCUMENT_DID_OPEN)
    async def did_open(ls, params: DidOpenTextDocumentParams) -> None:
        ls.show_message_log("Document opened")
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.open_document(
                params.text_document.uri,
                params.text_document.text,
                getattr(params.text_document, "version", None),
            )
        diagnostics = get_diagnostics(ls, params.text_document.text, params.text_document.uri)
        ls.publish_diagnostics(params.text_document.uri, diagnostics)

    @server.feature(TEXT_DOCUMENT_DID_CHANGE)
    async def did_change(ls, params: DidChangeTextDocumentParams) -> None:
        uri = params.text_document.uri
        changes = getattr(params, "content_changes", None)
        if changes:
            text = changes[-1].text
        else:
            try:
                text = ls.workspace.get_text_document(uri).source
            except Exception:
                logger.debug("Operation failed in %s", __name__, exc_info=True)
                text = ""
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.update_document(uri, text, getattr(params.text_document, "version", None))
            if hasattr(runtime, "should_debounce") and runtime.should_debounce(
                uri, "push_diagnostics"
            ):
                return
        diagnostics = get_diagnostics(ls, text, uri)
        ls.publish_diagnostics(uri, diagnostics)

    @server.feature(TEXT_DOCUMENT_DID_SAVE)
    async def did_save(ls, params: DidSaveTextDocumentParams) -> None:
        uri = params.text_document.uri
        text = getattr(params, "text", None)
        if text is None:
            text = get_document_source(ls, uri)
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.save_document(uri, text)
        diagnostics = get_diagnostics(ls, text, uri)
        ls.publish_diagnostics(uri, diagnostics)

    @server.feature(TEXT_DOCUMENT_DID_CLOSE)
    async def did_close(ls, params: DidCloseTextDocumentParams) -> None:
        ls.show_message_log("Document closed")
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.close_document(params.text_document.uri)

    @server.feature(WORKSPACE_DID_CHANGE_CONFIGURATION)
    async def did_change_configuration(ls, params: DidChangeConfigurationParams) -> None:
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.update_config(getattr(params, "settings", {}))

    @server.feature(WORKSPACE_DID_CHANGE_WATCHED_FILES)
    async def did_change_watched_files(ls, params: DidChangeWatchedFilesParams) -> None:
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.handle_watched_files(getattr(params, "changes", []))

    @server.feature(YARAAST_RUNTIME_STATUS)
    async def runtime_status(ls, _params: object | None = None) -> dict[str, object]:
        runtime = getattr(ls, "runtime", None)
        if runtime is None:
            return {"available": False}
        return {"available": True, **runtime.get_status()}
