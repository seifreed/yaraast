"""Coverage tests for small utility modules."""

from __future__ import annotations

import importlib

import click
import pytest

import yaraast.ast.simple_nodes as simple_nodes
from yaraast.cli.libyara_handlers_common import run_or_abort
from yaraast.cli.libyara_reporting import LibYaraCommandError


class _Console:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, message) -> None:
        self.lines.append(str(message))


def test_simple_nodes_module_reexports_expected_names() -> None:
    assert "Rule" in simple_nodes.__all__
    assert "StringDefinition" in simple_nodes.__all__
    assert simple_nodes.Rule is not None
    assert simple_nodes.BooleanLiteral is not None


def test_lsp_init_exports_symbol() -> None:
    import yaraast.lsp as lsp_pkg

    reloaded = importlib.reload(lsp_pkg)
    assert hasattr(reloaded, "YaraLanguageServer")


def test_run_or_abort_success_and_errors() -> None:
    console = _Console()

    assert run_or_abort(lambda x: x + 1, console, 2) == 3

    with pytest.raises(click.Abort):
        run_or_abort(lambda: (_ for _ in ()).throw(LibYaraCommandError("x")), console)

    with pytest.raises(click.Abort):
        run_or_abort(lambda: (_ for _ in ()).throw(ValueError("bad")), console)
    assert any("Error: bad" in line for line in console.lines)
