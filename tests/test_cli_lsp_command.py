"""CLI tests for LSP command (no mocks)."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
import importlib
import sys
from types import ModuleType
from typing import NoReturn

import click
from click.testing import CliRunner, Result
import pytest

from yaraast.cli.commands.lsp import lsp


def _assert_abort_preserves_cause(result: Result, cause: BaseException) -> None:
    exception = result.exception
    assert isinstance(exception, click.Abort)
    assert exception.__cause__ is cause


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


def test_lsp_missing_dependency_abort_preserves_original_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__
    sentinel = ImportError("No module named pygls", name="pygls")

    def fail_lsp_services_import(
        name: str,
        globals_: Mapping[str, object] | None = None,
        locals_: Mapping[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "yaraast.cli.lsp_services":
            raise sentinel
        return original_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_lsp_services_import)

    result = CliRunner().invoke(lsp, [], standalone_mode=False)

    assert result.exit_code != 0
    assert "Missing dependency" in result.output
    _assert_abort_preserves_cause(result, sentinel)


def test_lsp_start_error_abort_preserves_original_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_services = ModuleType("yaraast.cli.lsp_services")
    sentinel = RuntimeError("lsp sentinel")

    def fail_create_lsp_server() -> NoReturn:
        raise sentinel

    def fail_start_lsp_server(_server: object, _tcp: int | None, _host: str) -> None:
        raise AssertionError("start_lsp_server should not be called")

    fake_services.__dict__["create_lsp_server"] = fail_create_lsp_server
    fake_services.__dict__["start_lsp_server"] = fail_start_lsp_server
    monkeypatch.setitem(sys.modules, "yaraast.cli.lsp_services", fake_services)

    result = CliRunner().invoke(lsp, [], standalone_mode=False)

    assert result.exit_code != 0
    assert "lsp sentinel" in result.output
    _assert_abort_preserves_cause(result, sentinel)
