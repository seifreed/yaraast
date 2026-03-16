"""LSP server command for CLI."""

from __future__ import annotations

import click

from yaraast.cli.lsp_reporting import (
    display_listening_stdio,
    display_listening_tcp,
    display_missing_dependency,
    display_start_error,
    display_starting,
    get_console,
)
from yaraast.cli.lsp_services import create_lsp_server, start_lsp_server


@click.command()
@click.option(
    "--stdio",
    is_flag=True,
    default=True,
    help="Use stdio for communication (default)",
)
@click.option("--tcp", type=int, help="Use TCP on specified port")
@click.option("--host", default="127.0.0.1", help="Host for TCP mode")
def lsp(stdio: bool, tcp: int | None, host: str) -> None:
    """Start the YARA Language Server.

    The language server provides IDE features like autocomplete, diagnostics,
    hover information, go-to-definition, and more for YARA files.

    Examples:
        yaraast lsp --stdio           # Start with stdio (default)
        yaraast lsp --tcp 5007        # Start on TCP port 5007
    """
    console = get_console()
    try:
        display_starting(console)
        server = create_lsp_server()

        if tcp:
            display_listening_tcp(console, host, tcp)
        else:
            display_listening_stdio(console)

        start_lsp_server(server, tcp, host)
    except ImportError as exc:
        display_missing_dependency(console, exc)
        raise click.Abort from None
    except Exception as exc:
        display_start_error(console, exc)
        raise click.Abort from None
