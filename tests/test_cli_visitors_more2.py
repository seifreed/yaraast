"""Extra tests for CLI visitors and condition formatter (no mocks)."""

from __future__ import annotations

from textwrap import dedent

from yaraast.ast.extern import ExternImport, ExternRuleReference
from yaraast.cli.visitors import ASTDumper, ConditionStringFormatter
from yaraast.parser import Parser


def test_condition_string_formatter_long_and_hash() -> None:
    code = dedent(
        """
        rule r {
            condition:
                md5(0,1) == "a" and sha1(0,1) == "b" and sha256(0,1) == "c" and true and false and true and true and true
        }
        """,
    )
    ast = Parser().parse(code)
    formatter = ConditionStringFormatter()
    formatted = formatter.format_condition(ast.rules[0].condition)
    assert formatted


def test_ast_dumper_extern_nodes() -> None:
    dumper = ASTDumper()
    imp = ExternImport(module_path="ext_rules", alias="ext", rules=["r1"])
    ref = ExternRuleReference(rule_name="r1", namespace="ext")

    imp_dump = dumper.visit_extern_import(imp)
    ref_dump = dumper.visit_extern_rule_reference(ref)

    assert "ext_rules" in imp_dump["module"]
    assert "r1" in ref_dump["name"]
