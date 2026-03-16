"""Additional real coverage for expression type inference."""

from __future__ import annotations

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modules import DictionaryAccess
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.types._expr_inference import ExpressionTypeInference, _TypeBaseVisitor
from yaraast.types._registry import (
    BooleanType,
    IntegerType,
    StringType,
    TypeEnvironment,
    UnknownType,
)


def test_type_base_visitor_default_methods_return_unknown() -> None:
    visitor = _TypeBaseVisitor()

    nodes = [
        Comment("x"),
        CommentGroup([Comment("x")]),
        DefinedExpression(expression=IntegerLiteral(value=1)),
        StringOperatorExpression(
            left=StringLiteral(value="a"),
            operator="contains",
            right=StringLiteral(value="b"),
        ),
        ExternImport(module_path="ext"),
        ExternNamespace(name="ns"),
        ExternRule(name="r"),
        ExternRuleReference(rule_name="r"),
        InRulePragma(pragma=Pragma(pragma_type=PragmaType.PRAGMA, name="pragma")),
        Pragma(pragma_type=PragmaType.PRAGMA, name="pragma"),
        PragmaBlock(pragmas=[]),
    ]

    for node in nodes:
        out = visitor.visit(node)
        if isinstance(node, DefinedExpression | StringOperatorExpression):
            assert isinstance(out, BooleanType)
        else:
            assert isinstance(out, UnknownType)


def test_expr_inference_reports_undefined_string_variants() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert isinstance(inf.infer(StringCount(string_id="missing")), UnknownType)
    assert isinstance(inf.infer(StringOffset(string_id="missing")), UnknownType)
    assert isinstance(inf.infer(StringLength(string_id="missing")), UnknownType)

    assert "Undefined string: $missing" in inf.errors[0]
    assert "Undefined string: $missing" in inf.errors[1]
    assert "Undefined string: $missing" in inf.errors[2]


def test_expr_inference_string_length_invalid_index_reports_error() -> None:
    env = TypeEnvironment()
    env.add_string("$a")
    inf = ExpressionTypeInference(env)

    out = inf.infer(StringLength(string_id="a", index=StringLiteral(value="bad")))
    assert isinstance(out, IntegerType)
    assert "String length index must be integer" in inf.errors[0]


def test_expr_inference_comparison_and_builtin_function_paths() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    cmp_out = inf.infer(
        BinaryExpression(
            left=StringLiteral(value="x"),
            operator="==",
            right=IntegerLiteral(value=1),
        ),
    )
    assert isinstance(cmp_out, BooleanType)
    assert "Incompatible types for '=='" in inf.errors[0]

    right_bad = inf.infer(
        BinaryExpression(
            left=BooleanLiteral(value=True),
            operator="and",
            right=IntegerLiteral(value=1),
        ),
    )
    assert isinstance(right_bad, BooleanType)
    assert any("Right operand of 'and' must be boolean" in e for e in inf.errors)


def test_expr_inference_at_in_and_of_error_paths() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert isinstance(
        inf.infer(AtExpression(string_id="$a", offset=StringLiteral(value="bad"))),
        BooleanType,
    )
    assert any("Offset in 'at' expression must be integer" in e for e in inf.errors)

    assert isinstance(
        inf.infer(InExpression(subject="$a", range=IntegerLiteral(value=1))),
        BooleanType,
    )
    assert any("'in' expression requires range" in e for e in inf.errors)

    assert isinstance(
        inf.infer(
            OfExpression(
                quantifier=BooleanLiteral(value=True),
                string_set=IntegerLiteral(value=1),
            ),
        ),
        BooleanType,
    )
    assert any("'of' quantifier must be string or integer" in e for e in inf.errors)
    assert any("'of' requires string set" in e for e in inf.errors)


def test_expr_inference_helper_and_branch_edges() -> None:
    env = TypeEnvironment()
    inf = ExpressionTypeInference(env)

    assert inf._normalize_string_id("a") == "$a"
    assert inf._normalize_string_id("$a") == "$a"

    env.modules.add("")
    assert inf._resolve_module_type("") is None

    env2 = TypeEnvironment()
    env2.add_module("ghost")
    assert ExpressionTypeInference(env2)._resolve_module_type("ghost") is None

    high_bad = ExpressionTypeInference(TypeEnvironment())
    out = high_bad.infer(
        InExpression(
            subject="$a",
            range=RangeExpression(
                low=IntegerLiteral(value=1),
                high=StringLiteral(value="x"),
            ),
        ),
    )
    assert isinstance(out, BooleanType)
    assert any("Range high bound must be integer" in e for e in high_bad.errors)

    dict_env = TypeEnvironment()
    from yaraast.types._registry import DictionaryType

    dict_env.define("d", DictionaryType(StringType(), IntegerType()))
    dict_out = ExpressionTypeInference(dict_env).infer(
        DictionaryAccess(object=Identifier(name="d"), key="plain-key"),
    )
    assert isinstance(dict_out, IntegerType)

    set_env = TypeEnvironment()
    set_env.add_string("$a")
    fo = ExpressionTypeInference(set_env).infer(
        ForOfExpression(
            quantifier=IntegerLiteral(value=1),
            string_set=SetExpression(elements=[StringIdentifier(name="$a")]),
            condition=None,
        ),
    )
    assert isinstance(fo, BooleanType)
