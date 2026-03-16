"""Additional tests for validate service helpers."""

from __future__ import annotations

from yaraast.cli import validate_services as vs
from yaraast.parser import Parser


def _ast_with_regex_issue():
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
