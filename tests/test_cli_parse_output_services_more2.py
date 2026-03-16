"""More tests for parse output services (no mocks)."""

from __future__ import annotations

from pathlib import Path

import click
import pytest

from yaraast.cli import parse_output_services as po
from yaraast.parser import Parser


class _Err:
    def __init__(self, msg: str) -> None:
        self.msg = msg

    def format_error(self) -> str:
        return self.msg


def _ast():
    code = """
rule t {
  strings:
    $a = "x"
  condition:
    $a
}
""".strip()
    return Parser().parse(code)


def test_parse_output_report_parsing_errors(capsys) -> None:
    lexer = [_Err("lex1"), _Err("lex2"), _Err("lex3"), _Err("lex4"), _Err("lex5"), _Err("lex6")]
    parser = [_Err("par1"), _Err("par2")]

    po._report_parsing_errors(lexer, parser, ast=_ast())
    out = capsys.readouterr().out
    assert "Found 8 issue(s)" in out
    assert "Lexer Issues (6)" in out
    assert "and 1 more lexer issues" in out
    assert "Parser Issues (2)" in out
    assert "Partial parse successful" in out

    with pytest.raises(click.Abort):
        po._report_parsing_errors([_Err("x")], [], ast=None)


def test_parse_output_generators_for_all_formats(tmp_path: Path, capsys) -> None:
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
