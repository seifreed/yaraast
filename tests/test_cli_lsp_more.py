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
