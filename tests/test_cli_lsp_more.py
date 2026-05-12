"""Real tests for CLI lsp command (no mocks)."""

from __future__ import annotations

from click.testing import CliRunner

from yaraast.cli.commands.lsp import lsp


def test_cli_lsp_help_real() -> None:
    runner = CliRunner()
    result = runner.invoke(lsp, ["--help"])
    assert result.exit_code == 0
    assert "--stdio" in result.output
    assert "--tcp" in result.output


def test_cli_lsp_rejects_invalid_tcp_port() -> None:
    runner = CliRunner()

    result = runner.invoke(lsp, ["--tcp", "0"])

    assert result.exit_code == 2
    assert "Invalid value for '--tcp'" in result.output
