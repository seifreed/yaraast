# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-loop tests for yaraast.lsp.server_feature_document_handlers.

Targets every branch and line that the existing suite does not reach.
All tests drive real production code through the public module API —
no mocking framework is used anywhere in this file.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from yaraast.lsp.lsp_types import (
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
    WORKSPACE_DID_CHANGE_CONFIGURATION,
    WORKSPACE_DID_CHANGE_WATCHED_FILES,
    YARAAST_RUNTIME_STATUS,
)
from yaraast.lsp.server_feature_document_handlers import (
    _changed_document_text,
    _latest_change_text,
    register_document_handlers,
)

# ---------------------------------------------------------------------------
# Minimal real infrastructure — no mocks, no stubs
# ---------------------------------------------------------------------------


class _Workspace:
    """In-memory workspace that maps URIs to text documents."""

    def __init__(self, docs: dict[str, SimpleNamespace] | None = None) -> None:
        self._docs: dict[str, SimpleNamespace] = docs or {}

    def get_text_document(self, uri: str) -> SimpleNamespace:
        if uri not in self._docs:
            raise KeyError(uri)
        return self._docs[uri]


class _FakeServer:
    """Minimal server that satisfies FeatureRegistrationServer protocol."""

    def __init__(
        self,
        workspace: _Workspace | None = None,
        runtime: Any = None,
    ) -> None:
        self.handlers: dict[str, Callable[..., Any]] = {}
        self.logs: list[str] = []
        self.published: list[tuple[str, Any]] = []
        self.workspace = workspace or _Workspace()
        self.runtime = runtime
        self.diagnostics_provider = SimpleNamespace(
            get_diagnostics=lambda source: [f"diag:{len(source)}"]
        )
        # Required by FeatureRegistrationServer protocol
        self.semantic_tokens_provider: Any = SimpleNamespace()
        self.workspace_symbols_provider: Any = SimpleNamespace()

    def feature(self, name: str, *_opts: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def _register(func: Callable[..., Any]) -> Callable[..., Any]:
            self.handlers[name] = func
            return func

        return _register

    def show_message_log(self, msg: str) -> None:
        self.logs.append(msg)

    def publish_diagnostics(self, uri: str, diagnostics: Any) -> None:
        self.published.append((uri, diagnostics))


class _FullRuntime:
    """Real runtime that records calls and exercises all handler branches."""

    def __init__(self, debounce: bool = False) -> None:
        self.opened: list[tuple[str, str, Any]] = []
        self.updated: list[tuple[str, str, Any]] = []
        self.saved: list[tuple[str, Any]] = []
        self.closed: list[str] = []
        self.configs: list[Any] = []
        self.watched: list[Any] = []
        self._debounce = debounce

    def open_document(self, uri: str, text: str, version: Any) -> None:
        self.opened.append((uri, text, version))

    def update_document(self, uri: str, text: str, version: Any) -> None:
        self.updated.append((uri, text, version))

    def save_document(self, uri: str, text: Any) -> None:
        self.saved.append((uri, text))

    def close_document(self, uri: str) -> None:
        self.closed.append(uri)

    def update_config(self, settings: Any) -> None:
        self.configs.append(settings)

    def handle_watched_files(self, changes: Any) -> None:
        self.watched.append(changes)

    def get_document(self, uri: str, load_workspace: bool = True) -> None:
        # Returns None so that get_document_source falls back to the workspace
        _ = load_workspace

    def get_status(self) -> dict[str, object]:
        return {"open_documents": len(self.opened), "language_mode": "auto"}

    def should_debounce(self, uri: str, _operation: str) -> bool:
        return self._debounce


def _make_server(
    runtime: Any = None,
    workspace: _Workspace | None = None,
) -> _FakeServer:
    server = _FakeServer(workspace=workspace, runtime=runtime)
    register_document_handlers(server)
    return server


async def _call(server: _FakeServer, name: str, params: Any) -> Any:
    return await server.handlers[name](server, params)


# ---------------------------------------------------------------------------
# _latest_change_text — unit-level tests for the helper
# ---------------------------------------------------------------------------


def test_latest_change_text_returns_none_for_empty_list() -> None:
    """Line 32: empty list triggers the early-return None branch."""
    result = _latest_change_text([])
    assert result is None


def test_latest_change_text_returns_none_for_none_input() -> None:
    """Line 32: None input triggers the early-return None branch."""
    result = _latest_change_text(None)
    assert result is None


def test_latest_change_text_returns_none_on_subscript_exception() -> None:
    """Lines 35-36: objects that raise TypeError on [-1] hit the except branch."""

    class _Unindexable:
        def __getitem__(self, _key: Any) -> Any:
            raise TypeError("not subscriptable")

        def __bool__(self) -> bool:
            return True

    result = _latest_change_text(_Unindexable())
    assert result is None


def test_latest_change_text_extracts_text_from_mapping() -> None:
    """Positive path: Mapping items supply text via .get('text')."""
    result = _latest_change_text([{"text": "rule x { condition: true }"}])
    assert result == "rule x { condition: true }"


def test_latest_change_text_extracts_text_from_namespace() -> None:
    """Positive path: non-Mapping items supply text via attribute access."""
    result = _latest_change_text([SimpleNamespace(text="rule y { condition: false }")])
    assert result == "rule y { condition: false }"


def test_latest_change_text_returns_none_for_non_string_text() -> None:
    """Non-string text attribute yields None."""
    result = _latest_change_text([SimpleNamespace(text=42)])
    assert result is None


# ---------------------------------------------------------------------------
# _changed_document_text — unit-level tests for the helper
# ---------------------------------------------------------------------------


def test_changed_document_text_returns_workspace_source_when_string() -> None:
    """Positive path: workspace source is returned as-is when it is a str."""
    uri = "file:///a.yar"
    ws = _Workspace({uri: SimpleNamespace(uri=uri, source="rule a { condition: true }")})
    server = _FakeServer(workspace=ws)
    result = _changed_document_text(server, uri, [])
    assert result == "rule a { condition: true }"


def test_changed_document_text_falls_back_to_latest_change_when_source_not_str() -> None:
    """workspace.source is not a str: falls back to _latest_change_text."""
    uri = "file:///a.yar"
    ws = _Workspace({uri: SimpleNamespace(uri=uri, source=object())})
    server = _FakeServer(workspace=ws)
    latest = "rule b { condition: false }"
    result = _changed_document_text(server, uri, [SimpleNamespace(text=latest)])
    assert result == latest


def test_changed_document_text_falls_back_to_empty_when_no_changes() -> None:
    """Both workspace and changes are empty: result is empty string."""
    uri = "file:///missing.yar"
    server = _FakeServer(workspace=_Workspace())
    result = _changed_document_text(server, uri, [])
    assert result == ""


# ---------------------------------------------------------------------------
# did_open — runtime is None branch (branch 57->63)
# ---------------------------------------------------------------------------


def test_did_open_without_runtime_still_publishes_diagnostics() -> None:
    """Branch 57->63: when runtime is None the open_document call is skipped
    but diagnostics are still published."""
    server = _make_server(runtime=None)
    uri = "file:///x.yar"
    text = "rule x { condition: true }"
    params = SimpleNamespace(text_document=SimpleNamespace(uri=uri, text=text, version=1))

    asyncio.run(_call(server, TEXT_DOCUMENT_DID_OPEN, params))

    assert "Document opened" in server.logs
    assert len(server.published) == 1
    published_uri, published_diags = server.published[0]
    assert published_uri == uri
    assert published_diags == [f"diag:{len(text)}"]


# ---------------------------------------------------------------------------
# did_change — runtime is None branch (branch 72->78)
# ---------------------------------------------------------------------------


def test_did_change_without_runtime_publishes_diagnostics() -> None:
    """Branch 72->78: when runtime is None the update_document call is skipped
    but diagnostics are still published using content_changes text."""
    uri = "file:///x.yar"
    text = "rule x { condition: false }"
    server = _make_server(
        runtime=None,
        workspace=_Workspace({uri: SimpleNamespace(uri=uri, source=text)}),
    )
    params = SimpleNamespace(
        text_document=SimpleNamespace(uri=uri, version=2),
        content_changes=[SimpleNamespace(text=text)],
    )

    asyncio.run(_call(server, TEXT_DOCUMENT_DID_CHANGE, params))

    assert len(server.published) == 1
    published_uri, published_diags = server.published[0]
    assert published_uri == uri
    assert published_diags == [f"diag:{len(text)}"]


# ---------------------------------------------------------------------------
# did_change — debounce early-exit branch (line 77)
# ---------------------------------------------------------------------------


def test_did_change_returns_early_when_debounce_is_true() -> None:
    """Line 77: when should_debounce returns True the handler returns without
    publishing diagnostics."""
    uri = "file:///x.yar"
    text = "rule x { condition: false }"
    runtime = _FullRuntime(debounce=True)
    server = _make_server(
        runtime=runtime,
        workspace=_Workspace({uri: SimpleNamespace(uri=uri, source=text)}),
    )
    params = SimpleNamespace(
        text_document=SimpleNamespace(uri=uri, version=3),
        content_changes=[SimpleNamespace(text=text)],
    )

    asyncio.run(_call(server, TEXT_DOCUMENT_DID_CHANGE, params))

    # update_document was still called, but publish_diagnostics was not
    assert runtime.updated == [(uri, text, 3)]
    assert server.published == []


# ---------------------------------------------------------------------------
# did_save — text is None branch (branch 85->87)
# ---------------------------------------------------------------------------


def test_did_save_fetches_workspace_source_when_text_param_is_none() -> None:
    """Branch 85->87: when params.text is None the handler calls get_document_source
    to resolve the document text from the workspace."""
    uri = "file:///a.yar"
    ws_text = "rule a { condition: true }"
    runtime = _FullRuntime()
    server = _make_server(
        runtime=runtime,
        workspace=_Workspace({uri: SimpleNamespace(uri=uri, source=ws_text)}),
    )
    # params.text is None — triggers the 85->87 branch
    params = SimpleNamespace(
        text_document=SimpleNamespace(uri=uri, version=1),
        text=None,
    )

    asyncio.run(_call(server, TEXT_DOCUMENT_DID_SAVE, params))

    assert runtime.saved == [(uri, ws_text)]
    assert len(server.published) == 1
    assert server.published[0] == (uri, [f"diag:{len(ws_text)}"])


# ---------------------------------------------------------------------------
# did_save — runtime is None branch (branch 88->90)
# ---------------------------------------------------------------------------


def test_did_save_without_runtime_still_publishes_diagnostics() -> None:
    """Branch 88->90: when runtime is None save_document is skipped but
    diagnostics are still published from the inline text."""
    uri = "file:///b.yar"
    text = "rule b { condition: false }"
    server = _make_server(runtime=None)
    params = SimpleNamespace(
        text_document=SimpleNamespace(uri=uri, version=1),
        text=text,
    )

    asyncio.run(_call(server, TEXT_DOCUMENT_DID_SAVE, params))

    assert len(server.published) == 1
    assert server.published[0] == (uri, [f"diag:{len(text)}"])


# ---------------------------------------------------------------------------
# did_close — runtime is None branch (branch 97->exit)
# ---------------------------------------------------------------------------


def test_did_close_without_runtime_logs_and_returns() -> None:
    """Branch 97->exit: when runtime is None close_document is not called."""
    uri = "file:///c.yar"
    server = _make_server(runtime=None)
    params = SimpleNamespace(text_document=SimpleNamespace(uri=uri))

    asyncio.run(_call(server, TEXT_DOCUMENT_DID_CLOSE, params))

    assert "Document closed" in server.logs
    # No runtime was attached so no further side effects occurred
    assert server.published == []


# ---------------------------------------------------------------------------
# did_change_configuration — runtime is None branch (branch 103->exit)
# ---------------------------------------------------------------------------


def test_did_change_configuration_without_runtime_returns_silently() -> None:
    """Branch 103->exit: when runtime is None update_config is not called."""
    server = _make_server(runtime=None)
    params = SimpleNamespace(settings={"YARA": {"cacheWorkspace": True}})

    asyncio.run(_call(server, WORKSPACE_DID_CHANGE_CONFIGURATION, params))

    # Nothing must have been published or logged as a side effect
    assert server.published == []
    assert server.logs == []


def test_did_change_configuration_with_runtime_calls_update_config() -> None:
    """Positive runtime path: update_config receives the settings dict."""
    runtime = _FullRuntime()
    server = _make_server(runtime=runtime)
    settings = {"YARA": {"cacheWorkspace": False}}
    params = SimpleNamespace(settings=settings)

    asyncio.run(_call(server, WORKSPACE_DID_CHANGE_CONFIGURATION, params))

    assert runtime.configs == [settings]


# ---------------------------------------------------------------------------
# did_change_watched_files — runtime is None branch (branch 109->exit)
# ---------------------------------------------------------------------------


def test_did_change_watched_files_without_runtime_returns_silently() -> None:
    """Branch 109->exit: when runtime is None handle_watched_files is not called."""
    server = _make_server(runtime=None)
    params = SimpleNamespace(changes=[SimpleNamespace(uri="file:///rule.yar", type=1)])

    asyncio.run(_call(server, WORKSPACE_DID_CHANGE_WATCHED_FILES, params))

    assert server.published == []
    assert server.logs == []


def test_did_change_watched_files_with_runtime_calls_handle_watched_files() -> None:
    """Positive runtime path: handle_watched_files receives the change list."""
    runtime = _FullRuntime()
    server = _make_server(runtime=runtime)
    changes = [SimpleNamespace(uri="file:///rule.yar", type=2)]
    params = SimpleNamespace(changes=changes)

    asyncio.run(_call(server, WORKSPACE_DID_CHANGE_WATCHED_FILES, params))

    assert runtime.watched == [changes]


# ---------------------------------------------------------------------------
# runtime_status — runtime is None branch (line 116)
# ---------------------------------------------------------------------------


def test_runtime_status_returns_available_false_when_runtime_is_none() -> None:
    """Line 116: when runtime is None the handler returns {"available": False}."""
    server = _make_server(runtime=None)

    result: dict[str, object] = asyncio.run(_call(server, YARAAST_RUNTIME_STATUS, None))

    assert result == {"available": False}


def test_runtime_status_returns_available_true_and_status_when_runtime_present() -> None:
    """Positive path: runtime is present and get_status() dict is merged."""
    runtime = SimpleNamespace(get_status=lambda: {"open_documents": 3, "language_mode": "yara"})
    server = _make_server(runtime=runtime)

    result: dict[str, object] = asyncio.run(_call(server, YARAAST_RUNTIME_STATUS, None))

    assert result["available"] is True
    assert result["open_documents"] == 3
    assert result["language_mode"] == "yara"


# ---------------------------------------------------------------------------
# Integration smoke: all handlers registered and reachable with full runtime
# ---------------------------------------------------------------------------


def test_all_handlers_registered_and_callable_with_full_runtime() -> None:
    """End-to-end smoke: every handler in the module fires without error."""
    uri = "file:///smoke.yar"
    text = "rule smoke { condition: true }"
    runtime = _FullRuntime()
    server = _make_server(
        runtime=runtime,
        workspace=_Workspace({uri: SimpleNamespace(uri=uri, source=text)}),
    )

    asyncio.run(
        _call(
            server,
            TEXT_DOCUMENT_DID_OPEN,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri, text=text, version=1)),
        )
    )
    asyncio.run(
        _call(
            server,
            TEXT_DOCUMENT_DID_CHANGE,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri, version=2),
                content_changes=[SimpleNamespace(text=text)],
            ),
        )
    )
    asyncio.run(
        _call(
            server,
            TEXT_DOCUMENT_DID_SAVE,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri, version=2), text=text),
        )
    )
    asyncio.run(
        _call(
            server,
            TEXT_DOCUMENT_DID_CLOSE,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri)),
        )
    )
    asyncio.run(
        _call(
            server,
            WORKSPACE_DID_CHANGE_CONFIGURATION,
            SimpleNamespace(settings={}),
        )
    )
    asyncio.run(
        _call(
            server,
            WORKSPACE_DID_CHANGE_WATCHED_FILES,
            SimpleNamespace(changes=[]),
        )
    )
    status: dict[str, object] = asyncio.run(_call(server, YARAAST_RUNTIME_STATUS, None))

    assert "Document opened" in server.logs
    assert "Document closed" in server.logs
    # open + change + save = 3 diagnostic publications
    assert len(server.published) == 3
    assert all(uri == pub_uri for pub_uri, _ in server.published)
    assert runtime.opened == [(uri, text, 1)]
    assert runtime.updated == [(uri, text, 2)]
    assert runtime.saved == [(uri, text)]
    assert runtime.closed == [uri]
    assert runtime.configs == [{}]
    assert runtime.watched == [[]]
    assert status["available"] is True
