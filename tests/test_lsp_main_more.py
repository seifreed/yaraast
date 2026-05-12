"""Tests for the LSP module entrypoint."""

from __future__ import annotations

import importlib

from click.testing import CliRunner
import pytest

from yaraast.cli.commands.lsp import lsp as lsp_cmd
from yaraast.lsp.__main__ import main


def test_lsp_package_exports_server_type() -> None:
    mod = importlib.reload(importlib.import_module("yaraast.lsp"))
    assert mod.YaraLanguageServer is not None


def test_lsp_main_raises_when_stdio_cannot_start_under_pytest_capture() -> None:
    with pytest.raises((ModuleNotFoundError, OSError)):
        main()


def test_lsp_command_stdio_starts_in_cli_runner() -> None:
    runner = CliRunner()

    result = runner.invoke(lsp_cmd, [])

    assert result.exit_code == 0
    assert "Starting YARAAST Language Server" in result.output
    assert "Using stdio for communication" in result.output


def test_lsp_command_tcp_rejects_negative_port() -> None:
    runner = CliRunner()

    result = runner.invoke(lsp_cmd, ["--tcp=-1"])

    assert result.exit_code == 2
    assert "Invalid value for '--tcp'" in result.output
