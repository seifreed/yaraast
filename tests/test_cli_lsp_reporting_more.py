"""Tests for LSP CLI reporting helpers."""

from __future__ import annotations

from rich.console import Console

from yaraast.cli.lsp_reporting import (
    display_listening_stdio,
    display_listening_tcp,
    display_missing_dependency,
    display_start_error,
    display_starting,
)


def test_reporting_helpers_render_expected_messages() -> None:
    console = Console(record=True, width=120)

    display_starting(console)
    display_listening_tcp(console, "127.0.0.1", 9000)
    display_listening_stdio(console)
    display_missing_dependency(console, ImportError("pygls"))
    display_start_error(console, RuntimeError("boom"))

    output = console.export_text()
    assert "Starting YARAAST Language Server" in output
    assert "Listening on 127.0.0.1:9000" in output
    assert "Using stdio for communication" in output
    assert "Missing dependency: pygls" in output
    assert "pip install 'yaraast'" in output
    assert "pip install pygls lsprotocol" in output
    assert "Error starting LSP server: boom" in output


def test_reporting_helpers_escape_markup_in_dynamic_values() -> None:
    console = Console(record=True, width=120)

    display_listening_tcp(console, "bad[/blue][broken", 9000)
    display_missing_dependency(console, ImportError("bad[/red][broken"))
    display_start_error(console, RuntimeError("bad[/red][broken"))

    output = console.export_text()
    assert "bad[/blue][broken" in output
    assert "bad[/red][broken" in output
