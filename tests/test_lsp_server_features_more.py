"""Extra tests for LSP server feature registration and handlers (no mocks)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from yaraast.lsp import server_features as sf
from yaraast.lsp.document_types import uri_to_path
from yaraast.lsp.server_feature_helpers import get_workspace_folders


class _Workspace:
    def __init__(self) -> None:
        self._docs = {
            "file:///a.yar": SimpleNamespace(
                uri="file:///a.yar", source="rule a { condition: true }"
            )
        }

    def get_text_document(self, uri: str) -> SimpleNamespace:
        return self._docs[uri]


class _Provider:
    def __init__(self, value: Any) -> None:
        self.value = value

    def get_completions(self, *_args: Any) -> Any:
        return self.value

    def get_hover(self, *_args: Any) -> Any:
        return self.value

    def get_definition(self, *_args: Any) -> Any:
        return self.value

    def get_references(self, *_args: Any) -> Any:
        return self.value

    def get_symbols(self, *_args: Any) -> Any:
        return self.value

    def format_document(self, *_args: Any) -> Any:
        return self.value

    def format_range(self, *_args: Any) -> Any:
        return self.value

    def get_code_actions(self, *_args: Any) -> Any:
        return self.value

    def prepare_rename(self, *_args: Any) -> Any:
        return self.value

    def rename(self, *_args: Any) -> Any:
        return self.value

    def get_semantic_tokens(self, *_args: Any) -> Any:
        return self.value

    def get_semantic_tokens_range(self, *_args: Any) -> Any:
        return self.value

    def get_signature_help(self, *_args: Any) -> Any:
        return self.value

    def get_highlights(self, *_args: Any) -> Any:
        return self.value

    def get_folding_ranges(self, *_args: Any) -> Any:
        return self.value

    def get_document_links(self, *_args: Any) -> Any:
        return self.value

    def get_selection_ranges(self, *_args: Any) -> Any:
        return self.value


class _WorkspaceSymbolsProvider:
    def __init__(self) -> None:
        self.roots: list[str] = []

    def get_workspace_symbols(self, query: str) -> list[dict[str, str]]:
        return [{"query": query}]

    def set_workspace_root(self, root: str) -> None:
        self.roots.append(root)


class FakeServer:
    def __init__(self) -> None:
        self.handlers: dict[str, Callable[..., Any]] = {}
        self.logs: list[str] = []
        self.published: list[tuple[str, Any]] = []

        self.workspace = _Workspace()
        self.runtime: Any = SimpleNamespace(
            open_document=lambda *args, **kwargs: None,
            update_document=lambda *args, **kwargs: None,
            save_document=lambda *args, **kwargs: None,
            close_document=lambda *args, **kwargs: None,
            update_config=lambda *args, **kwargs: None,
            handle_watched_files=lambda *args, **kwargs: None,
            set_workspace_folders=lambda *args, **kwargs: None,
            get_document=lambda *args, **kwargs: None,
            should_debounce=lambda *args, **kwargs: False,
            get_status=lambda *args, **kwargs: {"open_documents": 1, "language_mode": "auto"},
        )
        self.diagnostics_provider = SimpleNamespace(
            get_diagnostics=lambda source: [f"diag:{len(source)}"]
        )
        self.completion_provider = _Provider(["c"])
        self.hover_provider = _Provider({"hover": True})
        self.definition_provider = _Provider([{"loc": 1}])
        self.references_provider = _Provider([{"ref": 1}])
        self.symbols_provider = _Provider([{"sym": 1}])
        self.formatting_provider = _Provider([{"edit": 1}])
        self.code_actions_provider = _Provider([{"act": 1}])
        self.rename_provider = _Provider({"rename": True})
        self.semantic_tokens_provider = SimpleNamespace(
            get_legend=lambda: {"tokenTypes": ["keyword"], "tokenModifiers": []},
            get_semantic_tokens=lambda source: {"data": [len(source)]},
            get_semantic_tokens_range=lambda source, range_: {
                "data": [len(source), range_.start.line]
            },
        )
        self.selection_range_provider = _Provider([{"sel": 1}])
        self.signature_help_provider = _Provider({"sig": 1})
        self.document_highlight_provider = _Provider([{"h": 1}])
        self.folding_ranges_provider = _Provider([{"f": 1}])
        self.document_links_provider = _Provider([{"l": 1}])
        self.workspace_symbols_provider = _WorkspaceSymbolsProvider()

    def feature(self, name: str, *_opts: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def _decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            self.handlers[name] = func
            return func

        return _decorator

    def show_message_log(self, msg: str) -> None:
        self.logs.append(msg)

    def publish_diagnostics(self, uri: str, diagnostics: Any) -> None:
        self.published.append((uri, diagnostics))


class _RecordingRuntime:
    def __init__(self) -> None:
        self.updated: list[tuple[str, str, int | None]] = []

    def update_document(self, uri: str, text: str, version: int | None = None) -> None:
        self.updated.append((uri, text, version))

    def should_debounce(self, *_args: Any, **_kwargs: Any) -> bool:
        return False


async def _call(server: FakeServer, name: str, params: Any) -> Any:
    return await server.handlers[name](server, params)


def _text_params(uri: str = "file:///a.yar") -> SimpleNamespace:
    return SimpleNamespace(
        text_document=SimpleNamespace(uri=uri, text="rule a { condition: true }", version=1)
    )


def test_register_server_features_and_initialize_handlers() -> None:
    server = FakeServer()
    sf.register_server_features(server)

    uri = "file:///a.yar"
    pos = SimpleNamespace(line=0, character=0)

    asyncio.run(_call(server, sf.TEXT_DOCUMENT_DID_OPEN, _text_params(uri)))
    asyncio.run(_call(server, sf.TEXT_DOCUMENT_DID_CHANGE, _text_params(uri)))
    asyncio.run(_call(server, sf.TEXT_DOCUMENT_DID_SAVE, _text_params(uri)))
    asyncio.run(_call(server, sf.TEXT_DOCUMENT_DID_CLOSE, _text_params(uri)))
    asyncio.run(
        _call(
            server,
            sf.WORKSPACE_DID_CHANGE_CONFIGURATION,
            SimpleNamespace(settings={"YARA": {"cacheWorkspace": True}}),
        )
    )
    asyncio.run(
        _call(
            server,
            sf.WORKSPACE_DID_CHANGE_WATCHED_FILES,
            SimpleNamespace(changes=[]),
        )
    )

    comp = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_COMPLETION,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos),
        ),
    )
    hov = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_HOVER,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos),
        ),
    )
    defi = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_DEFINITION,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos),
        ),
    )
    refs = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_REFERENCES,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri),
                position=pos,
                context=SimpleNamespace(include_declaration=True),
            ),
        ),
    )
    syms = asyncio.run(_call(server, sf.TEXT_DOCUMENT_DOCUMENT_SYMBOL, _text_params(uri)))
    fmtd = asyncio.run(_call(server, sf.TEXT_DOCUMENT_FORMATTING, _text_params(uri)))
    fmtr = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_RANGE_FORMATTING,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri),
                range=SimpleNamespace(start=pos, end=pos),
            ),
        ),
    )
    acts = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_CODE_ACTION,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri),
                range=SimpleNamespace(start=pos, end=pos),
                context=SimpleNamespace(diagnostics=[]),
            ),
        ),
    )
    prep = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_PREPARE_RENAME,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos),
        ),
    )
    ren = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_RENAME,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos, new_name="n"),
        ),
    )
    toks = asyncio.run(_call(server, sf.TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL, _text_params(uri)))
    tok_range = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri), range=SimpleNamespace(start=pos, end=pos)
            ),
        ),
    )
    selections = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_SELECTION_RANGE,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), positions=[pos]),
        ),
    )
    diagnostics = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_DIAGNOSTIC,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri)),
        ),
    )
    status = asyncio.run(_call(server, sf.YARAAST_RUNTIME_STATUS, None))
    sig = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_SIGNATURE_HELP,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos),
        ),
    )
    highs = asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT,
            SimpleNamespace(text_document=SimpleNamespace(uri=uri), position=pos),
        ),
    )
    folds = asyncio.run(_call(server, sf.TEXT_DOCUMENT_FOLDING_RANGE, _text_params(uri)))
    links = asyncio.run(_call(server, sf.TEXT_DOCUMENT_DOCUMENT_LINK, _text_params(uri)))
    ws_syms = asyncio.run(
        _call(server, sf.WORKSPACE_SYMBOL, SimpleNamespace(query="a")),
    )

    assert "Document opened" in server.logs
    assert "Document closed" in server.logs
    assert len(server.published) == 3
    assert comp == ["c"]
    assert hov == {"hover": True}
    assert defi == [{"loc": 1}]
    assert refs == [{"ref": 1}]
    assert syms == [{"sym": 1}]
    assert fmtd == [{"edit": 1}] and fmtr == [{"edit": 1}]
    assert acts == [{"act": 1}]
    assert prep == {"rename": True} and ren == {"rename": True}
    assert toks == {"data": [26]}
    assert tok_range == {"data": [26, 0]}
    assert selections == [{"sel": 1}]
    assert diagnostics.items == ["diag:26"]
    assert status["available"] is True
    assert status["open_documents"] == 1
    assert sig == {"sig": 1}
    assert highs == [{"h": 1}] and folds == [{"f": 1}] and links == [{"l": 1}]
    assert ws_syms == [{"query": "a"}]

    sf.register_initialize(server)
    server.handlers["initialize"](
        SimpleNamespace(
            root_uri="file:///tmp/ws",
            root_path=None,
            workspace_folders=[SimpleNamespace(uri="file:///tmp/ws3")],
            initialization_options={"YARA": {"cacheWorkspace": False}},
        )
    )
    server.handlers["initialize"](
        SimpleNamespace(
            root_uri=None, root_path="/tmp/ws2", workspace_folders=[], initialization_options={}
        )
    )

    assert "YARAAST Language Server initialized" in server.logs
    assert "/tmp/ws3" in server.workspace_symbols_provider.roots
    assert "/tmp/ws2" in server.workspace_symbols_provider.roots


def test_lsp_path_helpers_reject_empty_workspace_paths() -> None:
    assert uri_to_path(cast(Any, 123)) is None
    assert uri_to_path(cast(Any, object())) is None
    assert uri_to_path("") is None
    assert uri_to_path("   ") is None
    assert uri_to_path("\t") is None
    assert uri_to_path("file://") is None
    assert uri_to_path("file://example.com/tmp/ws") is None
    assert str(uri_to_path("file://localhost/tmp/ws")) == "/tmp/ws"
    assert str(uri_to_path("file://LOCALHOST/tmp/ws")) == "/tmp/ws"
    assert str(uri_to_path("FILE:///tmp/ws")) == "/tmp/ws"
    assert str(uri_to_path("File://LOCALHOST/tmp/ws")) == "/tmp/ws"
    assert str(uri_to_path("file:/tmp/ws")) == "/tmp/ws"
    assert uri_to_path("file:relative/ws") is None
    assert str(uri_to_path("relative/ws")) == "relative/ws"
    params = SimpleNamespace(
        root_uri="file:relative/ws",
        root_path="   ",
        workspace_folders=[SimpleNamespace(uri="file:/tmp/ws")],
    )
    assert get_workspace_folders(cast(Any, params)) == ["/tmp/ws"]


def test_did_change_uses_workspace_source_for_incremental_updates() -> None:
    server = FakeServer()
    sf.register_server_features(server)
    runtime = _RecordingRuntime()
    server.runtime = runtime
    uri = "file:///a.yar"
    full_text = "rule a { condition: false }"
    server.workspace._docs[uri] = SimpleNamespace(uri=uri, source=full_text)

    asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_DID_CHANGE,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri, version=2),
                content_changes=[
                    SimpleNamespace(
                        range=SimpleNamespace(
                            start=SimpleNamespace(line=0, character=20),
                            end=SimpleNamespace(line=0, character=24),
                        ),
                        text="false",
                    )
                ],
            ),
        )
    )

    assert runtime.updated == [(uri, full_text, 2)]
    assert server.published == [(uri, [f"diag:{len(full_text)}"])]


def test_did_change_ignores_malformed_change_without_workspace_source() -> None:
    server = FakeServer()
    sf.register_server_features(server)
    runtime = _RecordingRuntime()
    server.runtime = runtime
    uri = "file:///missing.yar"

    asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_DID_CHANGE,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri, version=2),
                content_changes=[object()],
            ),
        )
    )

    assert runtime.updated == [(uri, "", 2)]
    assert server.published == [(uri, ["diag:0"])]


def test_did_change_ignores_malformed_workspace_source_uses_latest_change_text() -> None:
    server = FakeServer()
    sf.register_server_features(server)
    runtime = _RecordingRuntime()
    server.runtime = runtime
    uri = "file:///a.yar"
    latest_text = "rule a { condition: false }"
    server.workspace._docs[uri] = SimpleNamespace(uri=uri, source=object())

    asyncio.run(
        _call(
            server,
            sf.TEXT_DOCUMENT_DID_CHANGE,
            SimpleNamespace(
                text_document=SimpleNamespace(uri=uri, version=3),
                content_changes=[SimpleNamespace(text=latest_text)],
            ),
        )
    )

    assert runtime.updated == [(uri, latest_text, 3)]
    assert server.published == [(uri, [f"diag:{len(latest_text)}"])]


def test_initialize_decodes_workspace_folder_file_uris(tmp_path: Path) -> None:
    server = FakeServer()
    sf.register_initialize(server)

    workspace_root = tmp_path / "rules with spaces"
    workspace_root.mkdir()
    server.handlers["initialize"](
        SimpleNamespace(
            root_uri=workspace_root.as_uri(),
            root_path=None,
            workspace_folders=[SimpleNamespace(uri=workspace_root.as_uri())],
            initialization_options={},
        )
    )

    assert server.workspace_symbols_provider.roots == [str(workspace_root)]
