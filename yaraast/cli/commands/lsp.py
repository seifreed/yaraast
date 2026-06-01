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

_OPTIONAL_LSP_DEPENDENCY_ROOTS = ("pygls", "lsprotocol")


def _is_optional_lsp_dependency_error(exc: ImportError) -> bool:
    missing_name = exc.name or ""
    return any(
        missing_name == dependency or missing_name.startswith(f"{dependency}.")
        for dependency in _OPTIONAL_LSP_DEPENDENCY_ROOTS
    )


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
    console = get_console()
    try:
        from yaraast.cli.lsp_services import create_lsp_server, start_lsp_server

        display_starting(console)
        server = create_lsp_server()

        if tcp is not None:
            display_listening_tcp(console, host, tcp)
        else:
            display_listening_stdio(console)

        start_lsp_server(server, tcp, host)
    except ImportError as exc:
        if not _is_optional_lsp_dependency_error(exc):
            raise
        display_missing_dependency(console, exc)
        raise click.Abort from None
    except Exception as exc:
        display_start_error(console, exc)
        raise click.Abort from None
