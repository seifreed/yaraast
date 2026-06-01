"""Tests for the LSP module entrypoint."""

from __future__ import annotations

import builtins
from collections.abc import Callable
import importlib
import sys
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


def test_lsp_server_import_propagates_pygls_internal_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaraast.lsp.server as lsp_server

    real_import: ImportFunction = builtins.__import__

    def fail_pygls_internal_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "pygls.lsp.server":
            raise ImportError("broken pygls protocol", name="pygls.protocol")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_pygls_internal_import)
    try:
        with pytest.raises(ImportError, match="broken pygls protocol"):
            importlib.reload(lsp_server)
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        sys.modules["yaraast.lsp.server"] = lsp_server
        importlib.reload(lsp_server)


def test_lsp_types_propagates_internal_lsprotocol_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaraast.lsp.lsp_types as lsp_types

    real_import: ImportFunction = builtins.__import__
    failed_once = False

    def fail_lsprotocol_internal_import_once(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        nonlocal failed_once
        if name == "lsprotocol.types" and not failed_once:
            failed_once = True
            raise ImportError("broken lsprotocol internals", name="lsprotocol._broken")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_lsprotocol_internal_import_once)
    try:
        with pytest.raises(ImportError, match="broken lsprotocol internals"):
            importlib.reload(lsp_types)
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(lsp_types)


def test_lsp_main_raises_when_stdio_cannot_start_under_pytest_capture() -> None:
    with pytest.raises((ModuleNotFoundError, OSError)):
        main()


def test_lsp_command_stdio_starts_in_cli_runner() -> None:
    runner = CliRunner()

    result = runner.invoke(lsp_cmd, [])

    assert result.exit_code == 0
    assert "Starting YARAAST Language Server" in result.output
    assert "Using stdio for communication" in result.output


def test_lsp_command_propagates_internal_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import: ImportFunction = builtins.__import__

    def fail_internal_lsp_services_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaraast.cli.lsp_services":
            raise ImportError("broken lsp services", name="yaraast.lsp.server_factory")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_internal_lsp_services_import)

    with pytest.raises(ImportError, match="broken lsp services"):
        CliRunner().invoke(lsp_cmd, [], catch_exceptions=False)


def test_lsp_command_reports_optional_dependency_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import: ImportFunction = builtins.__import__

    def fail_optional_lsp_dependency_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaraast.cli.lsp_services":
            raise ImportError("missing pygls", name="pygls")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_optional_lsp_dependency_import)

    result = CliRunner().invoke(lsp_cmd, [])

    assert result.exit_code != 0
    assert "Missing dependency" in result.output


def test_lsp_command_tcp_rejects_negative_port() -> None:
    runner = CliRunner()

    result = runner.invoke(lsp_cmd, ["--tcp=-1"])

    assert result.exit_code == 2
    assert "Invalid value for '--tcp'" in result.output
