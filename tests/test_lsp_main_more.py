"""Tests for the LSP module entrypoint."""

from __future__ import annotations

import builtins
from collections.abc import Callable
import importlib
from types import ModuleType
from typing import Any

from click.testing import CliRunner
import pytest

from yaraast.cli.commands.lsp import lsp as lsp_cmd
from yaraast.lsp.__main__ import main

ImportFunction = Callable[[str, Any, Any, Any, int], ModuleType]


def test_lsp_package_exports_server_type() -> None:
    mod = importlib.reload(importlib.import_module("yaraast.lsp"))
    assert mod.YaraLanguageServer is not None


def test_lsp_package_tolerates_missing_optional_lsp_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaraast.lsp as lsp_pkg

    real_import: ImportFunction = builtins.__import__

    def fail_lsp_dependency_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaraast.lsp.server":
            raise ImportError("missing pygls", name="pygls")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_lsp_dependency_import)
    try:
        reloaded = importlib.reload(lsp_pkg)
        assert reloaded.YaraLanguageServer is None
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(lsp_pkg)


def test_lsp_package_propagates_internal_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaraast.lsp as lsp_pkg

    real_import: ImportFunction = builtins.__import__

    def fail_internal_lsp_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaraast.lsp.server":
            raise ImportError("broken server factory", name="yaraast.lsp.server_factory")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_internal_lsp_import)
    try:
        with pytest.raises(ImportError, match="broken server factory"):
            importlib.reload(lsp_pkg)
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(lsp_pkg)


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
