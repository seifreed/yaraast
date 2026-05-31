from __future__ import annotations

import builtins
from collections.abc import Callable
from types import ModuleType
from typing import Any

import click
import pytest

from yaraast.cli.command_registry import register_commands

ImportFunction = Callable[[str, Any, Any, Any, int], ModuleType]


def test_register_commands_includes_lsp_command() -> None:
    group = click.Group("root")

    register_commands(group)

    assert "lsp" in group.commands


def test_register_commands_propagates_lsp_import_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import: ImportFunction = builtins.__import__

    def fail_lsp_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaraast.cli.commands.lsp":
            raise ImportError("broken lsp command")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_lsp_import)

    with pytest.raises(ImportError, match="broken lsp command"):
        register_commands(click.Group("root"))
