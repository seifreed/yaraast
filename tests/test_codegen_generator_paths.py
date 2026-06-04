from __future__ import annotations

import pytest

from yaraast.ast.base import ASTNode
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BooleanLiteral,
    DoubleLiteral,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modifiers import RuleModifier
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
    assert gen.visit(for_expr) == "for all i in (1..3) : (i)"

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

    for_of_raw_float = ForOfExpression(quantifier=0.5, string_set=Identifier("them"))
    assert gen.visit(for_of_raw_float) == "50% of them"

    for_of_literal_float = ForOfExpression(
        quantifier=DoubleLiteral(0.5), string_set=Identifier("them")
    )
    assert gen.visit(for_of_literal_float) == "50% of them"

    for_of_wildcard = ForOfExpression(
        quantifier="any",
        string_set=StringWildcard("$a*"),
        condition=BooleanLiteral(True),
    )
    assert gen.visit(for_of_wildcard) == "for any of ($a*) : (true)"

    of_int = OfExpression(quantifier=3, string_set=Identifier("them"))
    assert gen.visit(of_int) == "3 of them"

    of_string_lit = OfExpression(quantifier=StringLiteral("all"), string_set=Identifier("them"))
    assert gen.visit(of_string_lit) == "all of them"

    of_expr = OfExpression(quantifier=Identifier("n"), string_set=Identifier("them"))
    assert gen.visit(of_expr) == "n of them"

    of_list = OfExpression(quantifier=2, string_set=["$a", "$b"])
    assert gen.visit(of_list) == "2 of ($a, $b)"

    of_tuple = OfExpression(quantifier=2, string_set=("$a", "$b"))
    assert gen.visit(of_tuple) == "2 of ($a, $b)"

    of_frozenset = OfExpression(quantifier=2, string_set=frozenset(("$a", "$b")))
    assert gen.visit(of_frozenset) == "2 of ($a, $b)"

    of_node_list = OfExpression(
        quantifier="any",
        string_set=[StringIdentifier("$a"), StringIdentifier("$b")],
    )
    assert gen.visit(of_node_list) == "any of ($a, $b)"

    of_wildcard = OfExpression(quantifier="any", string_set=StringWildcard("$a*"))
    assert gen.visit(of_wildcard) == "any of ($a*)"

    of_raw_float = OfExpression(quantifier=0.5, string_set=Identifier("them"))
    assert gen.visit(of_raw_float) == "50% of them"

    for_of_raw = ForOfExpression(quantifier="all", string_set="them", condition=None)
    assert gen.visit(for_of_raw) == "all of them"

    for_of_node_list = ForOfExpression(
        quantifier="any",
        string_set=[StringIdentifier("$a"), StringIdentifier("$b")],
        condition=BooleanLiteral(True),
    )
    assert gen.visit(for_of_node_list) == "for any of ($a, $b) : (true)"


def test_codegen_renders_string_literals_as_references_inside_string_sets() -> None:
    gen = CodeGenerator()

    of_literals = OfExpression(
        quantifier="any",
        string_set=SetExpression([StringLiteral("$a"), StringLiteral("$b*")]),
    )
    assert gen.visit(of_literals) == "any of ($a, $b*)"

    for_of_parenthesized = ForOfExpression(
        quantifier="all",
        string_set=ParenthesesExpression(SetExpression([StringLiteral("$a")])),
        condition=StringIdentifier("$a"),
    )
    assert gen.visit(for_of_parenthesized) == "for all of ($a) : ($a)"


def test_codegen_generate_returns_direct_expression_output() -> None:
    assert CodeGenerator().generate(BooleanLiteral(True)) == "true"
    with pytest.raises(TypeError, match="Integer literal value must be an integer"):
        CodeGenerator().generate(IntegerLiteral(True))


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (
            RangeExpression(BooleanLiteral(True), IntegerLiteral(3)),
            "Range low bound must be integer",
        ),
        (
            RangeExpression(IntegerLiteral(0), BooleanLiteral(False)),
            "Range high bound must be integer",
        ),
        (
            ArrayAccess(Identifier("arr"), BooleanLiteral(True)),
            "Array index must be integer",
        ),
        (
            ArrayAccess(Identifier("arr"), ParenthesesExpression(BooleanLiteral(True))),
            "Array index must be integer",
        ),
    ],
)
def test_codegen_rejects_boolean_numeric_contexts(node: ASTNode, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        CodeGenerator().generate(node)


def test_codegen_in_expression_parentheses_paths() -> None:
    gen = CodeGenerator()

    in_range = InExpression(
        subject="$a",
        range=ParenthesesExpression(RangeExpression(IntegerLiteral(0), IntegerLiteral(10))),
    )
    assert gen.visit(in_range) == "$a in (0..10)"

    in_direct_range = InExpression(
        subject="$a",
        range=RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
    )
    assert gen.visit(in_direct_range) == "$a in (0..10)"

    in_of_direct_range = InExpression(
        subject=OfExpression(IntegerLiteral(1), Identifier("them")),
        range=RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
    )
    assert gen.visit(in_of_direct_range) == "1 of them in (0..10)"

    in_count_direct_range = InExpression(
        subject=StringCount("a"),
        range=RangeExpression(IntegerLiteral(0), IntegerLiteral(10)),
    )
    assert gen.visit(in_count_direct_range) == "#a in (0..10)"

    at_of_direct_offset = AtExpression(
        string_id=OfExpression(IntegerLiteral(1), Identifier("them")),
        offset=IntegerLiteral(0),
    )
    assert gen.visit(at_of_direct_offset) == "1 of them at 0"
    with pytest.raises(ValueError, match="At expression offset must be integer"):
        gen.visit(AtExpression("$a", BooleanLiteral(True)))
    with pytest.raises(ValueError, match="At expression offset must be integer"):
        gen.visit(AtExpression("$a", ParenthesesExpression(BooleanLiteral(False))))

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
    assert gen.visit(group) == "// one\n// two"

    extern_import = ExternImport(module_path="mod.yar")
    assert gen.visit(extern_import) == 'import "mod.yar"'

    namespace = ExternNamespace(name="ext")
    assert gen.visit(namespace) == "namespace ext"

    extern_rule_with_mod = ExternRule(name="R1", modifiers=[RuleModifier.from_string("private")])
    assert gen.visit(extern_rule_with_mod) == "extern rule private R1"

    extern_rule_no_mod = ExternRule(name="R2", modifiers=[], namespace="corp")
    assert gen.visit(extern_rule_no_mod) == "extern rule corp.R2"

    extern_ref = ExternRuleReference(rule_name="RemoteRule")
    assert gen.visit(extern_ref) == "RemoteRule"

    file_pragma = CustomPragma(name="opt", arguments=["on"])
    assert gen.visit(file_pragma) == "#pragma opt on"

    in_rule = InRulePragma(pragma=file_pragma)
    assert gen.visit(in_rule) == "#pragma opt on"

    block = PragmaBlock(pragmas=[file_pragma])
    assert gen.visit(block) == "#pragma opt on"
