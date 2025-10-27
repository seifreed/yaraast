"""LSP server command for CLI."""

import click
from rich.console import Console

console = Console()


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
    try:
        from yaraast.lsp.server import create_server

        console.print("[green]🚀 Starting YARAAST Language Server...[/green]")

        server = create_server()

        if tcp:
            console.print(f"[blue]📡 Listening on {host}:{tcp}[/blue]")
            server.start_tcp(host, tcp)
        else:
            console.print("[blue]📡 Using stdio for communication[/blue]")
            server.start_io()

    except ImportError as e:
        console.print(f"[red]❌ Missing dependency: {e}[/red]")
        console.print("\nInstall LSP dependencies with:")
        console.print("  pip install 'yaraast[lsp]'")
        console.print("\nOr install pygls manually:")
        console.print("  pip install pygls lsprotocol")
        raise click.Abort from None

    except Exception as e:
        console.print(f"[red]❌ Error starting LSP server: {e}[/red]")
        raise click.Abort from None
