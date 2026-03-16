"""CLI tests for LSP command (no mocks)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from yaraast.cli.commands.lsp import lsp


def test_lsp_reports_missing_dependency() -> None:
    try:
        from yaraast.lsp import server as _server  # noqa: F401
    except Exception:
        runner = CliRunner()
        result = runner.invoke(lsp, [])
        assert result.exit_code != 0
        assert "Missing dependency" in result.output
        return

    pytest.skip("LSP dependencies available; skipping to avoid starting server.")
