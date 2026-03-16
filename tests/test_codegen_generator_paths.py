from __future__ import annotations

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import ForExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    StringCount,
    StringLiteral,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.pragmas import CustomPragma, InRulePragma, PragmaBlock
from yaraast.codegen.generator import CodeGenerator


def test_codegen_in_for_of_variants_and_quantifiers() -> None:
    gen = CodeGenerator()

    for_expr = ForExpression(
        quantifier="all",
        variable="i",
        iterable=RangeExpression(IntegerLiteral(1), IntegerLiteral(3)),
        body=Identifier("i"),
    )
    assert gen.visit(for_expr) == "for all i in 1..3 : (i)"

    for_of_with_ast_quantifier = ForOfExpression(
        quantifier=IntegerLiteral(2),
        string_set=Identifier("them"),
        condition=Identifier("$a"),
    )
    assert gen.visit(for_of_with_ast_quantifier) == "for 2 of them : ($a)"

    for_of_without_condition = ForOfExpression(
        quantifier="any",
        string_set=Identifier("them"),
        condition=None,
    )
    assert gen.visit(for_of_without_condition) == "any of them"

    of_int = OfExpression(quantifier=3, string_set=Identifier("them"))
    assert gen.visit(of_int) == "3 of them"

    of_string_lit = OfExpression(quantifier=StringLiteral("all"), string_set=Identifier("them"))
    assert gen.visit(of_string_lit) == "all of them"

    of_expr = OfExpression(quantifier=Identifier("n"), string_set=Identifier("them"))
    assert gen.visit(of_expr) == "n of them"


def test_codegen_in_expression_parentheses_paths() -> None:
    gen = CodeGenerator()

    in_range = InExpression(
        subject="$a",
        range=ParenthesesExpression(RangeExpression(IntegerLiteral(0), IntegerLiteral(10))),
    )
    assert gen.visit(in_range) == "$a in (0..10)"

    in_single_ref = InExpression(
        subject="$a",
        range=ParenthesesExpression(StringCount("a")),
    )
    assert gen.visit(in_single_ref) == "$a in #a"

    in_other_parenthesized = InExpression(
        subject="$a",
        range=ParenthesesExpression(Identifier("entrypoint")),
    )
    assert gen.visit(in_other_parenthesized) == "$a in (entrypoint)"

    in_plain = InExpression(subject="$a", range=Identifier("filesize"))
    assert gen.visit(in_plain) == "$a in filesize"


def test_codegen_comment_extern_and_pragma_visit_methods() -> None:
    gen = CodeGenerator()

    assert gen.visit(Comment("hello")) == "// hello"

    group = CommentGroup(comments=[Comment("one"), Comment("two")])
    group.lines = ["one", "two"]
    assert gen.visit(group) == "// one\n// two"

    extern_import = ExternImport(module_path="mod.yar")
    extern_import.module = extern_import.module_path
    assert gen.visit(extern_import) == 'import "mod.yar"'

    namespace = ExternNamespace(name="ext")
    assert gen.visit(namespace) == "namespace ext"

    extern_rule_with_mod = ExternRule(name="R1", modifiers=["private"])
    assert gen.visit(extern_rule_with_mod) == "private rule R1"

    extern_rule_no_mod = ExternRule(name="R2", modifiers=[])
    assert gen.visit(extern_rule_no_mod) == "rule R2"

    extern_ref = ExternRuleReference(rule_name="RemoteRule")
    extern_ref.name = extern_ref.rule_name
    assert gen.visit(extern_ref) == "RemoteRule"

    file_pragma = CustomPragma(name="opt", arguments=["on"])
    assert gen.visit(file_pragma) == "#pragma opt on"

    in_rule = InRulePragma(pragma=file_pragma)
    assert gen.visit(in_rule) == "#pragma opt on"

    block = PragmaBlock(pragmas=[file_pragma])
    assert gen.visit(block) == "#pragma opt on"
