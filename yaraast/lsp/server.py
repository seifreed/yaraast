"""YARA Language Server implementation."""

from __future__ import annotations

from typing import Any

try:
    from pygls.lsp.server import LanguageServer  # pygls >= 2.0
except ImportError:
    from pygls.server import LanguageServer  # pygls < 2.0

from yaraast.lsp.server_factory import configure_providers, create_runtime
from yaraast.lsp.server_features import register_initialize, register_server_features


class YaraLanguageServer(LanguageServer):
    """YARA Language Server."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self.runtime = create_runtime()
        configure_providers(self, self.runtime)

        # Register features
        register_server_features(self)

    # Compatibility shims for pygls 1.x API used throughout the codebase.
    # pygls 2.0 renamed these methods.

    if not hasattr(LanguageServer, "show_message_log"):

        def show_message_log(self, message: str, msg_type: Any = None) -> None:
            self.window_log_message({"type": 4, "message": message})

    if not hasattr(LanguageServer, "publish_diagnostics"):

        def publish_diagnostics(self, uri: str, diagnostics: Any = None) -> None:
            self.text_document_publish_diagnostics({"uri": uri, "diagnostics": diagnostics or []})


def create_server() -> YaraLanguageServer:
    """Create and configure the YARA Language Server."""
    server = YaraLanguageServer("yaraast-lsp", "v0.1.0")
    register_initialize(server)

    return server


def main() -> None:
    """Main entry point for the language server."""
    server = create_server()
    server.start_io()


if __name__ == "__main__":
    main()
