"""More tests for LSP CLI command (no mocks)."""

from __future__ import annotations

import sys

from click.testing import CliRunner

from yaraast.cli.commands.lsp import lsp


def test_lsp_command_missing_dependency_path() -> None:
    runner = CliRunner()

    import yaraast.lsp as lsp_pkg

    original_path = list(getattr(lsp_pkg, "__path__", []))
    original_server = sys.modules.pop("yaraast.lsp.server", None)
    original_lsp_services = sys.modules.pop("yaraast.cli.lsp_services", None)

    try:
        # Make submodule discovery fail to force ImportError in command body.
        lsp_pkg.__path__ = []
        result = runner.invoke(lsp, ["--stdio"])
        assert result.exit_code != 0
        assert "Missing dependency" in result.output
    finally:
        lsp_pkg.__path__ = original_path
        if original_server is not None:
            sys.modules["yaraast.lsp.server"] = original_server
        if original_lsp_services is not None:
            sys.modules["yaraast.cli.lsp_services"] = original_lsp_services
