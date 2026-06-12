"""Document lifecycle and runtime handler registration for the language server."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

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
from yaraast.lsp.server_protocol import FeatureRegistrationServer

logger = logging.getLogger(__name__)


def _latest_change_text(changes: Any) -> str | None:
    if not changes:
        return None
    try:
        latest = changes[-1]
    except (IndexError, KeyError, TypeError):
        return None
    value = latest.get("text") if isinstance(latest, Mapping) else getattr(latest, "text", None)
    return value if isinstance(value, str) else None


def _changed_document_text(ls: Any, uri: str, changes: Any) -> str:
    try:
        source = ls.workspace.get_text_document(uri).source
        if isinstance(source, str):
            return source
    except Exception:
        logger.debug("Operation failed in %s", __name__, exc_info=True)
    return _latest_change_text(changes) or ""


def register_document_handlers(server: FeatureRegistrationServer) -> None:
    # Length is due to 7 short handler registrations; splitting would reduce locality.
    @server.feature(TEXT_DOCUMENT_DID_OPEN)
    async def did_open(ls: Any, params: DidOpenTextDocumentParams) -> None:
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
    async def did_change(ls: Any, params: DidChangeTextDocumentParams) -> None:
        uri = params.text_document.uri
        changes = getattr(params, "content_changes", None)
        text = _changed_document_text(ls, uri, changes)
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
    async def did_save(ls: Any, params: DidSaveTextDocumentParams) -> None:
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
    async def did_close(ls: Any, params: DidCloseTextDocumentParams) -> None:
        ls.show_message_log("Document closed")
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.close_document(params.text_document.uri)

    @server.feature(WORKSPACE_DID_CHANGE_CONFIGURATION)
    async def did_change_configuration(ls: Any, params: DidChangeConfigurationParams) -> None:
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.update_config(getattr(params, "settings", {}))

    @server.feature(WORKSPACE_DID_CHANGE_WATCHED_FILES)
    async def did_change_watched_files(ls: Any, params: DidChangeWatchedFilesParams) -> None:
        runtime = getattr(ls, "runtime", None)
        if runtime is not None:
            runtime.handle_watched_files(getattr(params, "changes", []))

    @server.feature(YARAAST_RUNTIME_STATUS)
    async def runtime_status(ls: Any, _params: object | None = None) -> dict[str, object]:
        runtime = getattr(ls, "runtime", None)
        if runtime is None:
            return {"available": False}
        return {"available": True, **runtime.get_status()}
