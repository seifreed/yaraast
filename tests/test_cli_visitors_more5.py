"""More tests for CLI visitors (no mocks)."""

from __future__ import annotations

from yaraast.ast.expressions import RegexLiteral, StringLiteral
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import StringOperatorExpression
from yaraast.cli.visitors import ASTDumper


def test_ast_dumper_additional_nodes() -> None:
    dumper = ASTDumper()

    regex = RegexLiteral(pattern="ab.*", modifiers="i")
    regex_dump = dumper.visit_regex_literal(regex)
    assert regex_dump["pattern"] == "ab.*"

    mod_ref = ModuleReference(module="pe")
    mod_dump = dumper.visit_module_reference(mod_ref)
    assert mod_dump["module"] == "pe"

    dict_access = DictionaryAccess(object=mod_ref, key="CompanyName")
    dict_dump = dumper.visit_dictionary_access(dict_access)
    assert dict_dump["key"] == "CompanyName"

    string_op = StringOperatorExpression(
        left=StringLiteral(value="hello"),
        operator="icontains",
        right=StringLiteral(value="he"),
    )
    string_op_dump = dumper.visit_string_operator_expression(string_op)
    assert string_op_dump["operator"] == "icontains"
