"""CLI tests for LSP command (no mocks)."""

from __future__ import annotations

import importlib

from click.testing import CliRunner
import pytest

from yaraast.cli.commands.lsp import lsp


def test_lsp_reports_missing_dependency() -> None:
    try:
        importlib.import_module("yaraast.lsp.server")
    except Exception:
        runner = CliRunner()
        result = runner.invoke(lsp, [])
        assert result.exit_code != 0
        assert "Missing dependency" in result.output
        return

    pytest.skip("LSP dependencies available; skipping to avoid starting server.")
