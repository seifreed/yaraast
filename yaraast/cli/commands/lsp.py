"""LSP server command for CLI."""

from __future__ import annotations

import click
from rich.console import Console

from yaraast.cli.lsp_reporting import (
    display_listening_stdio,
    display_listening_tcp,
    display_missing_dependency,
    display_start_error,
    display_starting,
)
from yaraast.lsp.optional_dependencies import is_missing_lsp_dependency


@click.command()
@click.option(
    "--stdio",
    is_flag=True,
    default=True,
    expose_value=False,
    help="Use stdio for communication (default)",
)
@click.option("--tcp", type=click.IntRange(min=1, max=65535), help="Use TCP on specified port")
@click.option("--host", default="127.0.0.1", help="Host for TCP mode")
def lsp(tcp: int | None, host: str) -> None:
    """Start the YARA Language Server.

    The language server provides IDE features like autocomplete, diagnostics,
    hover information, go-to-definition, and more for YARA files.

    Examples:
        yaraast lsp --stdio           # Start with stdio (default)
        yaraast lsp --tcp 5007        # Start on TCP port 5007
    """
    console = Console()
    try:
        from yaraast.cli.lsp_services import start_lsp_server
        from yaraast.lsp.server import create_server

        display_starting(console)
        server = create_server()

        if tcp is not None:
            display_listening_tcp(console, host, tcp)
        else:
            display_listening_stdio(console)

        start_lsp_server(server, tcp, host)
    except ImportError as exc:
        if not is_missing_lsp_dependency(exc):
            raise
        display_missing_dependency(console, exc)
        raise click.Abort from exc
    except Exception as exc:
        display_start_error(console, exc)
        raise click.Abort from exc
