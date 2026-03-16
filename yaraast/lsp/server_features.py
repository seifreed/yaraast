"""LSP feature registration for the YARA language server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.lsp.lsp_types import InitializeParams
from yaraast.lsp.server_feature_handlers import (
    register_server_features as _register_server_features,
)
from yaraast.lsp.server_feature_helpers import get_workspace_folders

if TYPE_CHECKING:
    from yaraast.lsp.server import YaraLanguageServer


def register_server_features(server: YaraLanguageServer) -> None:
    """Register LSP features on the server."""
    _register_server_features(server)


def register_initialize(server: YaraLanguageServer) -> None:
    """Register initialize handler."""

    @server.feature("initialize")
    def initialize(params: InitializeParams) -> None:
        """Initialize the server with completion triggers and capabilities."""
        server.show_message_log("YARAAST Language Server initialized")
        runtime = getattr(server, "runtime", None)
        folders = get_workspace_folders(params)
        if runtime is not None:
            runtime.set_workspace_folders(folders)
            runtime.update_config(getattr(params, "initialization_options", {}))
        if folders:
            server.workspace_symbols_provider.set_workspace_root(folders[0])

        # Set completion trigger characters for auto-invocation
        if hasattr(server, "server_capabilities") and server.server_capabilities:
            cap = server.server_capabilities
            if hasattr(cap, "completion_provider") and cap.completion_provider:
                cap.completion_provider.trigger_characters = [".", "!", "$", "@", "#"]
