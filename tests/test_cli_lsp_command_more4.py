"""More tests for LSP CLI command (no mocks)."""

from __future__ import annotations

import sys

from click.testing import CliRunner

from yaraast.cli.commands.lsp import lsp


def test_lsp_command_propagates_internal_lsp_module_import_error() -> None:
    runner = CliRunner()

    import yaraast.lsp as lsp_pkg

    original_path = list(getattr(lsp_pkg, "__path__", []))
    original_server = sys.modules.pop("yaraast.lsp.server", None)
    original_lsp_services = sys.modules.pop("yaraast.cli.lsp_services", None)

    try:
        lsp_pkg.__path__ = []
        result = runner.invoke(lsp, ["--stdio"])
        assert result.exit_code != 0
        assert isinstance(result.exception, ModuleNotFoundError)
        assert result.exception.name == "yaraast.lsp.server"
        assert result.output == ""
    finally:
        lsp_pkg.__path__ = original_path
        if original_server is not None:
            sys.modules["yaraast.lsp.server"] = original_server
        if original_lsp_services is not None:
            sys.modules["yaraast.cli.lsp_services"] = original_lsp_services
