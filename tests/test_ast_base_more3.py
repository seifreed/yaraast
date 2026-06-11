"""Additional coverage for base AST helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.extern import ExternNamespace, ExternRule
from yaraast.ast.pragmas import IncludeOncePragma, Pragma, PragmaType


class _Visitor:
    def visit_yara_file(self, node: YaraFile) -> tuple[str, int, int]:
        return ("yara_file", len(node.rules), len(node.pragmas))


def test_yarafile_accept_and_pragma_lookup_paths() -> None:
    file_node = YaraFile()
    visitor = _Visitor()
    assert file_node.accept(visitor) == ("yara_file", 0, 0)

    include_once = IncludeOncePragma()
    define = Pragma(PragmaType.DEFINE, "define", ["X", "1"])
    file_node.add_pragma(include_once)
    file_node.add_pragma(define)

    include_pragmas = file_node.get_pragma_by_type(PragmaType.INCLUDE_ONCE)
    define_pragmas = file_node.get_pragma_by_type(PragmaType.DEFINE)
    missing_pragmas = file_node.get_pragma_by_type(PragmaType.UNDEF)

    assert include_pragmas == [include_once]
    assert define_pragmas == [define]
    assert missing_pragmas == []


def test_yarafile_rejects_invalid_extern_rules_and_pragmas_without_partial_update() -> None:
    file_node = YaraFile()
    extern_rule = ExternRule(name="r1")
    pragma = IncludeOncePragma()
    file_node.add_extern_rule(extern_rule)
    file_node.add_pragma(pragma)

    with pytest.raises(TypeError, match="Extern rule input must be an ExternRule"):
        file_node.add_extern_rule(cast(Any, object()))

    with pytest.raises(TypeError, match="Pragma input must be a Pragma"):
        file_node.add_pragma(cast(Any, object()))

    assert file_node.extern_rules == [extern_rule]
    assert file_node.pragmas == [pragma]


def test_get_extern_rule_by_name_none_path() -> None:
    file_node = YaraFile(
        extern_rules=[
            ExternRule(name="r1", namespace="ns1"),
            ExternRule(name="r2", namespace="ns2"),
        ]
    )

    assert file_node.get_extern_rule_by_name("r1", "wrong") is None
    assert file_node.get_extern_rule_by_name("missing", "ns1") is None


@pytest.mark.parametrize("name", [None, 1, b"r1", object()])
def test_get_extern_rule_by_name_rejects_non_string_names(name: Any) -> None:
    file_node = YaraFile()

    with pytest.raises(TypeError, match="YaraFile extern rule name must be a string"):
        file_node.get_extern_rule_by_name(cast(str, name))


@pytest.mark.parametrize("name", ["", "   ", "\t"])
def test_get_extern_rule_by_name_rejects_empty_names(name: str) -> None:
    file_node = YaraFile()

    with pytest.raises(ValueError, match="YaraFile extern rule name cannot be empty"):
        file_node.get_extern_rule_by_name(name)


@pytest.mark.parametrize("namespace", [1, b"ns", object()])
def test_get_extern_rule_by_name_rejects_non_string_namespaces(
    namespace: Any,
) -> None:
    file_node = YaraFile()

    with pytest.raises(TypeError, match="YaraFile extern namespace must be a string"):
        file_node.get_extern_rule_by_name("r1", cast(str, namespace))


@pytest.mark.parametrize("namespace", ["", "   ", "\t"])
def test_get_extern_rule_by_name_rejects_empty_namespaces(namespace: str) -> None:
    file_node = YaraFile()

    with pytest.raises(ValueError, match="YaraFile extern namespace cannot be empty"):
        file_node.get_extern_rule_by_name("r1", namespace)


def test_get_extern_rule_by_name_finds_namespaced_rules() -> None:
    nested_rule = ExternRule(name="nested")
    namespace = ExternNamespace(name="corp")
    namespace.add_extern_rule(nested_rule)
    file_node = YaraFile(namespaces=[namespace])

    assert file_node.get_extern_rule_by_name("nested", "corp") is nested_rule
    assert file_node.get_extern_rule_by_name("nested") is None
