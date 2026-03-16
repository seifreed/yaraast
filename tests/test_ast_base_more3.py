"""Additional coverage for base AST helpers."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.extern import ExternRule
from yaraast.ast.pragmas import IncludeOncePragma, Pragma, PragmaType


class _Visitor:
    def visit_yara_file(self, node):
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


def test_get_extern_rule_by_name_none_path() -> None:
    file_node = YaraFile(
        extern_rules=[
            ExternRule(name="r1", namespace="ns1"),
            ExternRule(name="r2", namespace="ns2"),
        ]
    )

    assert file_node.get_extern_rule_by_name("r1", "wrong") is None
    assert file_node.get_extern_rule_by_name("missing", "ns1") is None
