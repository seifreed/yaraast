"""Additional tests for small CLI service helpers."""

from __future__ import annotations

from pathlib import Path

from yaraast.cli import optimize_services as osvc
from yaraast.cli import parse_output_services as pos
from yaraast.cli import serialize_services as ssvc
from yaraast.parser import Parser


class _Err:
    def __init__(self, text: str) -> None:
        self.text = text

    def format_error(self) -> str:
        return self.text


def _sample_ast():
    return Parser().parse(
        """
rule sample {
    strings:
        $a = "abc"
    condition:
        $a
}
""",
    )


def test_display_parser_errors_truncates_after_five(capsys) -> None:
    pos._display_parser_errors([_Err(f"parser-{i}") for i in range(7)])

    out = capsys.readouterr().out
    assert "Parser Issues (7)" in out
    assert "parser-0" in out
    assert "parser-4" in out
    assert "... and 2 more parser issues" in out


def test_calculate_improvement_returns_none_when_not_better() -> None:
    before = osvc.OptimizationAnalysis(total_issues=4, critical_issues=2)
    after_equal = osvc.OptimizationAnalysis(total_issues=4, critical_issues=1)
    after_worse = osvc.OptimizationAnalysis(total_issues=5, critical_issues=1)

    assert osvc.calculate_improvement(before, after_equal) is None
    assert osvc.calculate_improvement(before, after_worse) is None


def test_export_ast_yaml_non_minimal_returns_yaml_string(tmp_path: Path) -> None:
    ast = _sample_ast()
    result, stats = ssvc.export_ast(ast, "yaml", None, minimal=False)

    assert stats is None
    assert isinstance(result, str)
    assert "rules:" in result
    assert "sample" in result
