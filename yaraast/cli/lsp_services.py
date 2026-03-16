"""Services for LSP CLI (logic without IO)."""

from __future__ import annotations

from typing import Protocol

from yaraast.lsp.server import YaraLanguageServer, create_server


class LspServer(Protocol):
    def start_tcp(self, host: str, port: int) -> None: ...

    def start_io(self) -> None: ...


def create_lsp_server() -> YaraLanguageServer:
    return create_server()


def start_lsp_server(server: LspServer, tcp: int | None, host: str) -> None:
    if tcp:
        server.start_tcp(host, tcp)
    else:
        server.start_io()
