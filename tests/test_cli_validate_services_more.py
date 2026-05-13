"""Additional tests for validate service helpers."""

from __future__ import annotations

from pathlib import Path

from yaraast.ast.base import YaraFile
from yaraast.cli import validate_services as vs
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import WithStatement


def _ast_with_regex_issue() -> YaraFile:
    code = """
rule regex_test {
    strings:
        $a = /abc{/
    condition:
        $a
}
"""
    return Parser().parse(code)


def test_read_test_data_without_path_returns_none() -> None:
    assert vs.read_test_data(None) is None


def test_yarax_check_varies_with_strict_flag() -> None:
    ast = _ast_with_regex_issue()

    strict_issues = vs.yarax_check(ast, strict=True)
    compatible_issues = vs.yarax_check(ast, strict=False)

    assert any(issue.issue_type == "unescaped_brace" for issue in strict_issues)
    assert not any(issue.issue_type == "unescaped_brace" for issue in compatible_issues)


def test_validate_rule_file_parses_yarax(tmp_path: Path) -> None:
    rule_path = tmp_path / "sample.yar"
    rule_path.write_text(
        """
rule yarax_sample {
    condition:
        with xs = [1]: match xs { _ => true }
}
""".strip(),
        encoding="utf-8",
    )

    ast, rules_count, imports_count, string_count = vs.validate_rule_file(str(rule_path))

    assert rules_count == 1
    assert imports_count == 0
    assert string_count == 0
    assert isinstance(ast.rules[0].condition, WithStatement)
