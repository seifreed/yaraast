"""Additional tests for small CLI service helpers."""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.cli import (
    optimize_services as osvc,
    parse_output_services as pos,
)
from yaraast.cli.serialize_service_helpers import export_with_serializer
from yaraast.errors import ParseError
from yaraast.parser import Parser


class _Err:
    def __init__(self, text: str) -> None:
        self.text = text

    def format_error(self) -> str:
        return self.text


def _sample_ast() -> YaraFile:
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


def _yarax_rule() -> str:
    return "rule x { condition: with xs = [1]: match xs { _ => true } }"


def _yaral_rule() -> str:
    return """
rule ev {
  events:
    $e.metadata.event_type = "X"
  match:
    $e over 5m
  condition:
    $e
}
"""


def test_display_parser_errors_truncates_after_five(
    capsys: pytest.CaptureFixture[str],
) -> None:
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


def test_optimize_services_preserve_yarax_condition() -> None:
    ast, errors, warnings = osvc.parse_yara_with_tolerance(_yarax_rule())
    generated = osvc.generate_code(ast)

    assert errors == []
    assert warnings == []
    assert ast.rules[0].condition.__class__.__name__ == "WithStatement"
    assert "with xs = [1]" in generated
    assert "match xs" in generated


def test_optimize_services_reject_yaral_without_tolerant_classic_parse() -> None:
    with pytest.raises(ParseError, match=r"YARA-L.*optimize"):
        osvc.parse_yara_with_tolerance(_yaral_rule())


def test_export_ast_yaml_non_minimal_returns_yaml_string() -> None:
    ast = _sample_ast()
    result, stats = export_with_serializer(ast, "yaml", None, minimal=False)

    assert stats is None
    assert isinstance(result, str)
    assert "rules:" in result
    assert "sample" in result
