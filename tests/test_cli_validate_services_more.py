"""Additional tests for validate service helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.cli import validate_services as vs
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import WithStatement
from yaraast.yarax.compatibility_checker import YaraXCompatibilityChecker
from yaraast.yarax.feature_flags import YaraXFeatures


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


def test_read_test_data_accepts_string_and_path_inputs(tmp_path: Path) -> None:
    data_path = tmp_path / "sample.bin"
    data_path.write_bytes(b"abc")

    assert vs.read_test_data(data_path) == b"abc"
    assert vs.read_test_data(str(data_path)) == b"abc"


@pytest.mark.parametrize("test_data_path", [False, 0, object()])
def test_read_test_data_rejects_invalid_path_types(test_data_path: Any) -> None:
    with pytest.raises(TypeError, match="test data path must be a string or path-like object"):
        vs.read_test_data(cast(Any, test_data_path))


@pytest.mark.parametrize("path", ["", "   ", "\t"])
def test_read_test_data_rejects_empty_path(path: str) -> None:
    with pytest.raises(ValueError, match="test data path cannot be empty"):
        vs.read_test_data(path)


def test_read_test_data_rejects_empty_pathlike_path() -> None:
    class EmptyPathLike:
        def __fspath__(self) -> str:
            return ""

    with pytest.raises(ValueError, match="test data path cannot be empty"):
        vs.read_test_data(cast(Any, EmptyPathLike()))


def test_read_test_data_rejects_null_byte_path() -> None:
    with pytest.raises(ValueError, match="test data path cannot contain null bytes"):
        vs.read_test_data("\x00broken")


def test_yarax_check_varies_with_strict_flag() -> None:
    ast = _ast_with_regex_issue()

    strict_checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_strict())
    compatible_checker = YaraXCompatibilityChecker(YaraXFeatures.yarax_compatible())
    strict_issues = strict_checker.check(ast)
    compatible_issues = compatible_checker.check(ast)

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
