"""YARA Language Server implementation."""

from __future__ import annotations

from typing import Any

from pygls.server import LanguageServer

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
