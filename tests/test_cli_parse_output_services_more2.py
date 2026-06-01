"""More tests for parse output services (no mocks)."""

from __future__ import annotations

import builtins
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import click
import pytest

from yaraast.ast.base import YaraFile
from yaraast.cli import parse_output_services as po
from yaraast.parser import Parser

ImportFunction = Callable[[str, Any, Any, Any, int], ModuleType]


class _Err:
    def __init__(self, msg: str) -> None:
        self.msg = msg

    def format_error(self) -> str:
        return self.msg


def _ast() -> YaraFile:
    code = """
rule t {
  strings:
    $a = "x"
  condition:
    $a
}
""".strip()
    ast = Parser().parse(code)
    assert isinstance(ast, YaraFile)
    return ast


def test_parse_output_report_parsing_errors(capsys: pytest.CaptureFixture[str]) -> None:
    lexer = [_Err("lex1"), _Err("lex2"), _Err("lex3"), _Err("lex4"), _Err("lex5"), _Err("lex6")]
    parser = [_Err("par1"), _Err("par2")]

    po._report_parsing_errors(lexer, parser, ast=_ast())
    out = capsys.readouterr().out
    assert "Found 8 issue(s)" in out
    assert "Lexer Issues (6)" in out
    assert "and 1 more lexer issues" in out
    assert "Parser Issues (2)" in out
    assert "Partial parse successful" in out

    class FalsyYaraFile(YaraFile):
        def __bool__(self) -> bool:
            return False

    po._report_parsing_errors([_Err("lex")], [], ast=FalsyYaraFile(rules=_ast().rules))
    assert "Partial parse successful" in capsys.readouterr().out

    with pytest.raises(click.Abort):
        po._report_parsing_errors([_Err("x")], [], ast=None)


def test_parse_output_generators_for_all_formats(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ast = _ast()

    po._generate_output_by_format(ast, "yara", None)
    assert "rule t" in capsys.readouterr().out

    yara_file = tmp_path / "out.yar"
    po._generate_output_by_format(ast, "yara", str(yara_file))
    assert yara_file.exists()

    po._generate_output_by_format(ast, "json", None)
    assert '"type": "YaraFile"' in capsys.readouterr().out

    json_file = tmp_path / "out.json"
    po._generate_output_by_format(ast, "json", str(json_file))
    assert json_file.exists()

    po._generate_output_by_format(ast, "yaml", None)
    yaml_out = capsys.readouterr().out
    assert "type: YaraFile" in yaml_out

    yaml_file = tmp_path / "out.yaml"
    po._generate_output_by_format(ast, "yaml", str(yaml_file))
    assert yaml_file.exists()

    po._generate_output_by_format(ast, "tree", None)
    tree_out = capsys.readouterr().out
    assert "Rule: t" in tree_out

    tree_file = tmp_path / "out.tree.txt"
    po._generate_output_by_format(ast, "tree", str(tree_file))
    assert tree_file.exists()


@pytest.mark.parametrize("output_format", [None, 123])
def test_parse_output_rejects_non_string_formats(output_format: object) -> None:
    with pytest.raises(TypeError, match="output format must be a string"):
        po._generate_output_by_format(_ast(), output_format, None)


@pytest.mark.parametrize("output_format", ["", "xml", "text"])
def test_parse_output_rejects_unknown_formats(output_format: str) -> None:
    with pytest.raises(ValueError, match="output format must be one of: json, tree, yaml, yara"):
        po._generate_output_by_format(_ast(), output_format, None)


def test_parse_output_yaml_propagates_internal_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import: ImportFunction = builtins.__import__

    def fail_internal_yaml_import(
        name: str,
        globals_: Any = None,
        locals_: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "yaml":
            raise ImportError("broken yaml internals", name="yaml._broken")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fail_internal_yaml_import)

    with pytest.raises(ImportError, match="broken yaml internals"):
        po._generate_yaml_output(_ast(), None)
