"""Shared helpers for LSP feature registration."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from lsprotocol.types import Diagnostic, SemanticTokens

from yaraast.lsp.document_types import uri_to_path
from yaraast.lsp.lsp_types import InitializeParams, Range
from yaraast.lsp.provider_call_helpers import call_range_with_optional_uri, call_with_optional_uri

if TYPE_CHECKING:
    from yaraast.lsp.server import YaraLanguageServer


def get_document_source(ls: YaraLanguageServer, uri: str, fallback_text: str | None = None) -> str:
    runtime = getattr(ls, "runtime", None)
    if runtime is not None:
        document = runtime.get_document(uri, load_workspace=False)
        if document is not None and isinstance(document.text, str):
            return document.text
    if fallback_text is not None:
        return fallback_text
    document = ls.workspace.get_text_document(uri)
    source = document.source
    return source if isinstance(source, str) else ""


def get_diagnostics(ls: YaraLanguageServer, text: str, uri: str) -> list[Diagnostic]:
    provider = ls.diagnostics_provider
    return cast(list[Diagnostic], call_with_optional_uri(provider.get_diagnostics, text, uri))


def get_semantic_tokens(ls: YaraLanguageServer, text: str, uri: str) -> SemanticTokens:
    provider = ls.semantic_tokens_provider
    return cast(SemanticTokens, call_with_optional_uri(provider.get_semantic_tokens, text, uri))


def get_semantic_tokens_range(
    ls: YaraLanguageServer, text: str, uri: str, range_: Range
) -> SemanticTokens:
    provider = ls.semantic_tokens_provider
    return cast(
        SemanticTokens,
        call_range_with_optional_uri(provider.get_semantic_tokens_range, text, range_, uri),
    )


def get_workspace_folders(params: InitializeParams) -> list[str]:
    folders: list[str] = []
    workspace_folders = getattr(params, "workspace_folders", None) or []
    for folder in workspace_folders:
        uri = getattr(folder, "uri", None)
        if isinstance(uri, str) and uri.lower().startswith("file:"):
            path = uri_to_path(uri)
            if path is not None:
                folders.append(str(path))
    root_uri = getattr(params, "root_uri", None)
    if isinstance(root_uri, str) and root_uri.lower().startswith("file:"):
        path = uri_to_path(root_uri)
        if path is not None:
            folders.append(str(path))
    root_path = getattr(params, "root_path", None)
    if isinstance(root_path, str) and root_path.strip():
        folders.append(root_path)
    return [folder for idx, folder in enumerate(folders) if folder and folder not in folders[:idx]]
