"""Real tests for LSP server initialization (no mocks)."""

from __future__ import annotations

import asyncio
import inspect
import logging
from unittest.mock import patch

import pytest

from yaraast.lsp.server import YaraLanguageServer


def test_lsp_uses_supported_coroutine_inspection() -> None:
    assert asyncio.iscoroutinefunction is inspect.iscoroutinefunction


def test_lsp_server_initializes_providers() -> None:
    server = YaraLanguageServer("yaraast", "0.1")

    assert server.diagnostics_provider is not None
    assert server.completion_provider is not None
    assert server.hover_provider is not None
    assert server.definition_provider is not None
    assert server.references_provider is not None
    assert server.symbols_provider is not None
    assert server.formatting_provider is not None
    assert server.code_actions_provider is not None
    assert server.rename_provider is not None
    assert server.semantic_tokens_provider is not None
    assert server.selection_range_provider is not None
    assert server.signature_help_provider is not None
    assert server.document_highlight_provider is not None
    assert server.folding_ranges_provider is not None
    assert server.document_links_provider is not None
    assert server.workspace_symbols_provider is not None
    assert server.runtime is not None


def test_lsp_feature_context_uses_protocol_request_id() -> None:
    server = YaraLanguageServer("yaraast", "0.1")
    request_token = server.protocol._ctx_msg_id.set("req-42")

    def handler(_params: object) -> None:
        return None

    try:
        with patch("yaraast.lsp.server.log_context") as bind_context:
            registered = server.feature("textDocument/example")(handler)
            registered(None)

        bind_context.assert_called_once_with(operation="textDocument/example", request_id="req-42")
    finally:
        server.protocol._ctx_msg_id.reset(request_token)


def test_pygls_logs_are_sanitized_without_cli_configuration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    framework_logger = logging.getLogger("pygls.protocol.json_rpc")

    with caplog.at_level(logging.ERROR, logger="pygls.protocol.json_rpc"):
        framework_logger.error("Failed to handle request %s", {"text": "private rule body"})

    record = next(item for item in caplog.records if item.name == "pygls.protocol.json_rpc")
    assert record.getMessage() == "LSP framework event"
    assert getattr(record, "event_name", None) == "lsp.framework.failed"
    assert "private rule body" not in caplog.text
