"""Real LSP server tests using pygls + external lsprotocol (no mocks)."""

from __future__ import annotations

import asyncio
import site
import sys

import pytest


def _prefer_site_packages() -> None:
    for path in reversed(site.getsitepackages()):
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)


def test_lsp_server_handlers_basic() -> None:
    _prefer_site_packages()

    try:
        import lsprotocol.types as lsp
    except Exception as exc:
        pytest.skip(f"pygls/lsprotocol not available: {exc}")

    try:
        from yaraast.lsp.server import YaraLanguageServer
    except ImportError as exc:
        pytest.skip(f"real lsprotocol not available: {exc}")

    ls = YaraLanguageServer("yaraast", "1.0")
    # pygls 2.0 uses ls.protocol, pygls 1.x uses ls.lsp
    proto = getattr(ls, "protocol", None) or ls.lsp

    params = lsp.InitializeParams(
        capabilities=lsp.ClientCapabilities(),
        process_id=1,
        root_uri="file:///tmp",
    )
    proto.lsp_initialize(params)

    # pygls 2.0 requires explicit workspace setup after initialize
    if not hasattr(proto, "_workspace") or proto._workspace is None:
        from pygls.workspace import Workspace

        proto._workspace = Workspace(root_uri="file:///tmp")

    doc_item = lsp.TextDocumentItem(
        uri="file:///tmp/test.yar",
        language_id="yara",
        version=1,
        text="rule test { condition: true }",
    )
    ls.workspace.put_text_document(doc_item)

    features = proto.fm._features

    async def _run() -> None:
        await features[lsp.TEXT_DOCUMENT_DID_OPEN](
            lsp.DidOpenTextDocumentParams(text_document=doc_item),
        )
        await features[lsp.TEXT_DOCUMENT_COMPLETION](
            lsp.CompletionParams(
                text_document=lsp.TextDocumentIdentifier(uri=doc_item.uri),
                position=lsp.Position(line=0, character=1),
            ),
        )
        await features[lsp.TEXT_DOCUMENT_HOVER](
            lsp.HoverParams(
                text_document=lsp.TextDocumentIdentifier(uri=doc_item.uri),
                position=lsp.Position(line=0, character=5),
            ),
        )

    asyncio.run(_run())
