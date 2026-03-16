"""Reporting helpers for LSP CLI."""

from __future__ import annotations

from rich.console import Console


def get_console() -> Console:
    return Console()


def display_starting(console: Console) -> None:
    console.print("[green]🚀 Starting YARAAST Language Server...[/green]")


def display_listening_tcp(console: Console, host: str, port: int) -> None:
    console.print(f"[blue]📡 Listening on {host}:{port}[/blue]")


def display_listening_stdio(console: Console) -> None:
    console.print("[blue]📡 Using stdio for communication[/blue]")


def display_missing_dependency(console: Console, error: ImportError) -> None:
    console.print(f"[red]❌ Missing dependency: {error}[/red]")
    console.print("\nInstall LSP dependencies with:")
    console.print("  pip install 'yaraast[lsp]'")
    console.print("\nOr install pygls manually:")
    console.print("  pip install pygls lsprotocol")


def display_start_error(console: Console, error: Exception) -> None:
    console.print(f"[red]❌ Error starting LSP server: {error}[/red]")
