"""Extra tests for LSP CLI services without mocks."""

from __future__ import annotations

from yaraast.cli.lsp_services import create_lsp_server, start_lsp_server


def test_create_lsp_server_real() -> None:
    try:
        server = create_lsp_server()
    except ImportError:
        # Accept environments without optional LSP dependencies.
        return
    assert server is not None


def test_start_lsp_server_routes_tcp_vs_stdio() -> None:
    class DummyServer:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, int] | tuple[str]] = []

        def start_tcp(self, host: str, port: int) -> None:
            self.calls.append(("tcp", host, port))

        def start_io(self) -> None:
            self.calls.append(("io",))

    server = DummyServer()
    start_lsp_server(server, tcp=5007, host="0.0.0.0")
    start_lsp_server(server, tcp=None, host="127.0.0.1")

    assert server.calls == [("tcp", "0.0.0.0", 5007), ("io",)]
