# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage regression tests for yaraast.lsp.server_features.register_initialize.

Targets three uncovered paths identified by pytest-cov (75.76 % -> 100 %):

  1. Branch 87->90 (False): runtime is None  — server has no runtime attribute.
  2. Branch 90->94 (False): folders is empty — no workspace root is set.
  3. Lines 95-97: server_capabilities.completion_provider exists and trigger
     characters are populated.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaraast.lsp.server_features as sf

# ---------------------------------------------------------------------------
# Minimal real server implementations (no mocks)
# ---------------------------------------------------------------------------


class _WorkspaceSymbolsProvider:
    """Records set_workspace_root calls."""

    def __init__(self) -> None:
        self.roots: list[str] = []

    def set_workspace_root(self, root: str) -> None:
        self.roots.append(root)


class _MinimalServer:
    """Bare-minimum server satisfying FeatureRegistrationServer protocol.

    Includes semantic_tokens_provider (required by the Protocol) but does not
    expose runtime or server_capabilities, which are optional at initialization.
    """

    semantic_tokens_provider: Any = None

    def __init__(self) -> None:
        self.handlers: dict[str, Callable[..., Any]] = {}
        self.logs: list[str] = []
        self.workspace_symbols_provider = _WorkspaceSymbolsProvider()

    def feature(self, name: str, *_opts: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.handlers[name] = fn
            return fn

        return _decorator

    def show_message_log(self, msg: str) -> None:
        self.logs.append(msg)


class _ServerWithRuntime(_MinimalServer):
    """Server that exposes a real runtime attribute."""

    def __init__(self) -> None:
        super().__init__()
        self.runtime = SimpleNamespace(
            set_workspace_folders=lambda folders: None,
            update_config=lambda opts: None,
        )


class _ServerWithCapabilities(_MinimalServer):
    """Server that exposes server_capabilities with a live completion_provider."""

    def __init__(self) -> None:
        super().__init__()
        self.runtime = SimpleNamespace(
            set_workspace_folders=lambda _f: None,
            update_config=lambda _o: None,
        )
        # completion_provider starts with trigger_characters unset
        self.server_capabilities = SimpleNamespace(
            completion_provider=SimpleNamespace(trigger_characters=None)
        )


class _ServerWithNullCompletionProvider(_MinimalServer):
    """Server whose completion_provider is None inside server_capabilities."""

    def __init__(self) -> None:
        super().__init__()
        self.runtime = SimpleNamespace(
            set_workspace_folders=lambda _f: None,
            update_config=lambda _o: None,
        )
        self.server_capabilities = SimpleNamespace(completion_provider=None)


# ---------------------------------------------------------------------------
# Helper: build InitializeParams-like objects with controlled folder lists
# ---------------------------------------------------------------------------


def _params_with_folder_uri(folder_uri: str) -> Any:
    """Build a real SimpleNamespace that get_workspace_folders can process."""
    return SimpleNamespace(
        root_uri=None,
        root_path=None,
        workspace_folders=[SimpleNamespace(uri=folder_uri)],
        initialization_options={},
    )


def _params_no_folders() -> Any:
    """Params that produce an empty folder list."""
    return SimpleNamespace(
        root_uri=None,
        root_path=None,
        workspace_folders=[],
        initialization_options={},
    )


# ---------------------------------------------------------------------------
# Test 1: runtime is None — branch 87->90 False arm
# ---------------------------------------------------------------------------


def test_initialize_with_no_runtime_skips_runtime_calls(tmp_path: Path) -> None:
    """register_initialize must not call runtime methods when server has no runtime.

    Arrange: _MinimalServer has no 'runtime' attribute at all, so
             getattr(server, 'runtime', None) returns None.
    Act:     call the registered 'initialize' handler with a valid workspace URI.
    Assert:  the log confirms the handler ran; no AttributeError is raised;
             workspace_symbols_provider still records the folder root.
    """
    workspace = tmp_path / "ws_no_runtime"
    workspace.mkdir()

    server = _MinimalServer()
    sf.register_initialize(server)

    server.handlers["initialize"](_params_with_folder_uri(workspace.as_uri()))

    assert "YARAAST Language Server initialized" in server.logs
    # Workspace root must still be set even though runtime is absent
    assert str(workspace) in server.workspace_symbols_provider.roots


# ---------------------------------------------------------------------------
# Test 2: folders is empty — branch 90->94 False arm
# ---------------------------------------------------------------------------


def test_initialize_with_empty_folders_skips_set_workspace_root() -> None:
    """register_initialize must not call set_workspace_root when folders list is empty.

    Arrange: params produce an empty folder list.
    Act:     call 'initialize' handler.
    Assert:  workspace_symbols_provider.roots remains empty; handler still logs.
    """
    server = _ServerWithRuntime()
    sf.register_initialize(server)

    server.handlers["initialize"](_params_no_folders())

    assert "YARAAST Language Server initialized" in server.logs
    # With no folders the branch at line 90 is False: roots must stay empty
    assert server.workspace_symbols_provider.roots == []


# ---------------------------------------------------------------------------
# Test 3: server_capabilities.completion_provider present — lines 95-97
# ---------------------------------------------------------------------------


def test_initialize_sets_completion_trigger_characters_when_capabilities_present(
    tmp_path: Path,
) -> None:
    """register_initialize must write trigger_characters onto completion_provider.

    Arrange: server has server_capabilities with a truthy completion_provider.
    Act:     call 'initialize' handler with a valid workspace folder.
    Assert:  completion_provider.trigger_characters equals the expected list.
    """
    workspace = tmp_path / "ws_caps"
    workspace.mkdir()

    server = _ServerWithCapabilities()
    sf.register_initialize(server)

    server.handlers["initialize"](_params_with_folder_uri(workspace.as_uri()))

    assert "YARAAST Language Server initialized" in server.logs
    expected = [".", "!", "$", "@", "#"]
    assert server.server_capabilities.completion_provider.trigger_characters == expected


# ---------------------------------------------------------------------------
# Test 4: server_capabilities absent — guard at line 94 is False (regression)
# ---------------------------------------------------------------------------


def test_initialize_does_not_set_trigger_characters_when_no_capabilities(
    tmp_path: Path,
) -> None:
    """register_initialize must not fail when server_capabilities is absent.

    This guards the hasattr check at line 94.  The server has a runtime and
    folders so lines 88-89 and 91 execute; only line 94's False branch fires.
    """
    workspace = tmp_path / "ws_no_caps"
    workspace.mkdir()

    server = _ServerWithRuntime()
    # No server_capabilities attribute — hasattr returns False
    sf.register_initialize(server)

    server.handlers["initialize"](_params_with_folder_uri(workspace.as_uri()))

    assert "YARAAST Language Server initialized" in server.logs
    assert str(workspace) in server.workspace_symbols_provider.roots


# ---------------------------------------------------------------------------
# Test 5: server_capabilities present but completion_provider is None — line 96
# ---------------------------------------------------------------------------


def test_initialize_skips_trigger_chars_when_completion_provider_is_none(
    tmp_path: Path,
) -> None:
    """register_initialize must not fail when completion_provider is falsy.

    Guards the inner hasattr / truthiness check at line 96.
    """
    workspace = tmp_path / "ws_null_provider"
    workspace.mkdir()

    server = _ServerWithNullCompletionProvider()
    sf.register_initialize(server)

    server.handlers["initialize"](_params_with_folder_uri(workspace.as_uri()))

    assert "YARAAST Language Server initialized" in server.logs
    # No error; trigger_characters never set on a None provider
    assert server.server_capabilities.completion_provider is None
