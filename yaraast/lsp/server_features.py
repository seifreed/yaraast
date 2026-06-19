"""LSP feature registration for the YARA language server."""

from __future__ import annotations

from yaraast.lsp.lsp_types import (
    TEXT_DOCUMENT_CODE_ACTION,
    TEXT_DOCUMENT_COMPLETION,
    TEXT_DOCUMENT_DEFINITION,
    TEXT_DOCUMENT_DIAGNOSTIC,
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
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
    WORKSPACE_DID_CHANGE_CONFIGURATION,
    WORKSPACE_DID_CHANGE_WATCHED_FILES,
    WORKSPACE_SYMBOL,
    YARAAST_RUNTIME_STATUS,
    InitializeParams,
)
from yaraast.lsp.server_feature_document_handlers import register_document_handlers
from yaraast.lsp.server_feature_helpers import get_workspace_folders
from yaraast.lsp.server_feature_language_handlers import register_language_handlers
from yaraast.lsp.server_protocol import FeatureRegistrationServer

__all__ = [
    "TEXT_DOCUMENT_CODE_ACTION",
    "TEXT_DOCUMENT_COMPLETION",
    "TEXT_DOCUMENT_DEFINITION",
    "TEXT_DOCUMENT_DIAGNOSTIC",
    "TEXT_DOCUMENT_DID_CHANGE",
    "TEXT_DOCUMENT_DID_CLOSE",
    "TEXT_DOCUMENT_DID_OPEN",
    "TEXT_DOCUMENT_DID_SAVE",
    "TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT",
    "TEXT_DOCUMENT_DOCUMENT_LINK",
    "TEXT_DOCUMENT_DOCUMENT_SYMBOL",
    "TEXT_DOCUMENT_FOLDING_RANGE",
    "TEXT_DOCUMENT_FORMATTING",
    "TEXT_DOCUMENT_HOVER",
    "TEXT_DOCUMENT_PREPARE_RENAME",
    "TEXT_DOCUMENT_RANGE_FORMATTING",
    "TEXT_DOCUMENT_REFERENCES",
    "TEXT_DOCUMENT_RENAME",
    "TEXT_DOCUMENT_SELECTION_RANGE",
    "TEXT_DOCUMENT_SEMANTIC_TOKENS_FULL",
    "TEXT_DOCUMENT_SEMANTIC_TOKENS_RANGE",
    "TEXT_DOCUMENT_SIGNATURE_HELP",
    "WORKSPACE_DID_CHANGE_CONFIGURATION",
    "WORKSPACE_DID_CHANGE_WATCHED_FILES",
    "WORKSPACE_SYMBOL",
    "YARAAST_RUNTIME_STATUS",
    "InitializeParams",
    "register_initialize",
    "register_server_features",
]


def register_server_features(server: FeatureRegistrationServer) -> None:
    """Register LSP features on the server."""
    register_document_handlers(server)
    register_language_handlers(server)


def register_initialize(server: FeatureRegistrationServer) -> None:
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
