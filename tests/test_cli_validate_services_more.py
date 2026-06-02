"""Additional tests for validate service helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

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


def test_read_test_data_accepts_string_and_path_inputs(tmp_path: Path) -> None:
    data_path = tmp_path / "sample.bin"
    data_path.write_bytes(b"abc")

    assert vs.read_test_data(data_path) == b"abc"
    assert vs.read_test_data(str(data_path)) == b"abc"


@pytest.mark.parametrize("test_data_path", [False, 0, object()])
def test_read_test_data_rejects_invalid_path_types(test_data_path: Any) -> None:
    with pytest.raises(TypeError, match="test data path must be a string or path-like object"):
        vs.read_test_data(cast(Any, test_data_path))


def test_read_test_data_rejects_empty_path() -> None:
    with pytest.raises(ValueError, match="test data path cannot be empty"):
        vs.read_test_data("")


def test_read_test_data_rejects_empty_pathlike_path() -> None:
    class EmptyPathLike:
        def __fspath__(self) -> str:
            return ""

    with pytest.raises(ValueError, match="test data path cannot be empty"):
        vs.read_test_data(cast(Any, EmptyPathLike()))


def test_yarax_check_varies_with_strict_flag() -> None:
    ast = _ast_with_regex_issue()

    strict_issues = vs.yarax_check(ast, strict=True)
    compatible_issues = vs.yarax_check(ast, strict=False)

    assert any(issue.issue_type == "unescaped_brace" for issue in strict_issues)
    assert not any(issue.issue_type == "unescaped_brace" for issue in compatible_issues)


@pytest.mark.parametrize("strict", [None, 1, "yes", object()])
def test_yarax_check_rejects_invalid_strict_types(strict: Any) -> None:
    ast = _ast_with_regex_issue()

    with pytest.raises(TypeError, match="strict must be a boolean"):
        vs.yarax_check(ast, strict=cast(bool, strict))


@pytest.mark.parametrize("external", [None, "name=value", (123,), object()])
def test_parse_externals_rejects_invalid_input_types(external: Any) -> None:
    with pytest.raises(TypeError, match="external variables must be a tuple or list of strings"):
        vs.parse_externals(external)


def test_parse_externals_accepts_tuple_and_list_inputs() -> None:
    assert vs.parse_externals(("name=value",)) == {"name": "value"}
    assert vs.parse_externals(["name=value"]) == {"name": "value"}


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
