"""Additional branch coverage for expression optimizer."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.rules import Rule
from yaraast.optimization.expression_optimizer import ExpressionOptimizer, optimize_expression


def test_integer_folding_all_remaining_operators() -> None:
    opt = ExpressionOptimizer()

    assert opt.visit(BinaryExpression(IntegerLiteral(9), "/", IntegerLiteral(3))) == IntegerLiteral(
        3
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(9), "%", IntegerLiteral(4))) == IntegerLiteral(
        1
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(6), "&", IntegerLiteral(3))) == IntegerLiteral(
        2
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(6), "|", IntegerLiteral(3))) == IntegerLiteral(
        7
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(6), "^", IntegerLiteral(3))) == IntegerLiteral(
        5
    )
    assert opt.visit(
        BinaryExpression(IntegerLiteral(3), "<<", IntegerLiteral(2))
    ) == IntegerLiteral(12)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(8), ">>", IntegerLiteral(1))
    ) == IntegerLiteral(4)

    assert opt.visit(
        BinaryExpression(IntegerLiteral(2), "!=", IntegerLiteral(3))
    ) == BooleanLiteral(True)
    assert opt.visit(BinaryExpression(IntegerLiteral(2), "<", IntegerLiteral(3))) == BooleanLiteral(
        True
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(4), ">", IntegerLiteral(3))) == BooleanLiteral(
        True
    )
    assert opt.visit(
        BinaryExpression(IntegerLiteral(3), "<=", IntegerLiteral(3))
    ) == BooleanLiteral(True)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(5), ">=", IntegerLiteral(3))
    ) == BooleanLiteral(True)


def test_integer_division_and_modulo_by_zero_do_not_fold() -> None:
    opt = ExpressionOptimizer()
    div = BinaryExpression(IntegerLiteral(9), "/", IntegerLiteral(0))
    mod = BinaryExpression(IntegerLiteral(9), "%", IntegerLiteral(0))

    assert opt.visit(div) is div
    assert opt.visit(mod) is mod


def test_identity_and_boolean_shortcuts_remaining_paths() -> None:
    opt = ExpressionOptimizer()
    x = Identifier("x")

    assert opt.visit(BinaryExpression(x, "+", IntegerLiteral(0))) == x
    assert opt.visit(BinaryExpression(IntegerLiteral(0), "+", x)) == x
    assert opt.visit(BinaryExpression(x, "*", IntegerLiteral(1))) == x
    assert opt.visit(BinaryExpression(IntegerLiteral(1), "*", x)) == x
    assert opt.visit(BinaryExpression(x, "*", IntegerLiteral(0))) == IntegerLiteral(0)
    assert opt.visit(BinaryExpression(IntegerLiteral(0), "*", x)) == IntegerLiteral(0)

    assert opt.visit(BinaryExpression(BooleanLiteral(True), "or", x)) == BooleanLiteral(True)
    assert opt.visit(BinaryExpression(BooleanLiteral(False), "or", x)) == x
    assert opt.visit(BinaryExpression(x, "and", BooleanLiteral(False))) == BooleanLiteral(False)
    assert opt.visit(BinaryExpression(x, "and", BooleanLiteral(True))) == x
    assert opt.visit(BinaryExpression(x, "or", BooleanLiteral(True))) == BooleanLiteral(True)
    assert opt.visit(BinaryExpression(x, "or", BooleanLiteral(False))) == x

    no_fold = BinaryExpression(BooleanLiteral(True), "==", BooleanLiteral(True))
    assert opt.visit(no_fold) is no_fold


def test_unary_parentheses_and_convenience_function() -> None:
    opt = ExpressionOptimizer()

    assert opt.visit(UnaryExpression("-", IntegerLiteral(7))) == IntegerLiteral(-7)
    assert opt.visit(UnaryExpression("~", IntegerLiteral(0))) == IntegerLiteral(-1)
    assert opt.visit(UnaryExpression("not", UnaryExpression("not", Identifier("y")))) == Identifier(
        "y"
    )

    not_simplified = ParenthesesExpression(
        expression=BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))
    )
    out = opt.visit_parentheses_expression(not_simplified)
    assert isinstance(out, IntegerLiteral)

    expr = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    assert optimize_expression(expr) == BooleanLiteral(False)


def test_visit_collection_and_access_nodes_and_set_dedup() -> None:
    opt = ExpressionOptimizer()

    arr = ArrayAccess(array=Identifier("arr"), index=IntegerLiteral(1))
    out_arr = opt.visit_array_access(arr)
    assert isinstance(out_arr.array, Identifier)
    assert isinstance(out_arr.index, IntegerLiteral)

    mem = MemberAccess(object=Identifier("obj"), member="name")
    out_mem = opt.visit_member_access(mem)
    assert isinstance(out_mem.object, Identifier)

    fn = FunctionCall(function="fn", arguments=[IntegerLiteral(1), IntegerLiteral(1)])
    out_fn = opt.visit_function_call(fn)
    assert len(out_fn.arguments) == 2

    rng = RangeExpression(low=IntegerLiteral(1), high=IntegerLiteral(3))
    out_rng = opt.visit_range_expression(rng)
    assert out_rng.low == IntegerLiteral(1)
    assert out_rng.high == IntegerLiteral(3)

    aset = SetExpression(
        elements=[
            IntegerLiteral(1),
            IntegerLiteral(1),
            BooleanLiteral(True),
            BooleanLiteral(True),
            Identifier("a"),
            Identifier("a"),
            StringLiteral("x"),
            StringLiteral("x"),
        ]
    )
    out_set = opt.visit_set_expression(aset)
    assert len(out_set.elements) == 5
    assert opt.optimization_count >= 3

    unique_set = SetExpression(elements=[IntegerLiteral(1), BooleanLiteral(False), Identifier("b")])
    untouched = opt.visit_set_expression(unique_set)
    assert untouched is unique_set
    assert len(untouched.elements) == 3


def test_visit_for_of_at_in_and_passthrough_methods() -> None:
    opt = ExpressionOptimizer()

    for_node = SimpleNamespace(iterable=Identifier("it"), body=Identifier("body"))
    of_node = SimpleNamespace(quantifier=IntegerLiteral(2), string_set=Identifier("s"))
    at_node = SimpleNamespace(offset=IntegerLiteral(4))
    in_node = SimpleNamespace(range=Identifier("r"))

    assert opt.visit_for_expression(for_node).iterable == Identifier("it")
    assert opt.visit_of_expression(of_node).string_set == Identifier("s")
    assert opt.visit_at_expression(at_node).offset == IntegerLiteral(4)
    assert opt.visit_in_expression(in_node).range == Identifier("r")

    no_attrs = SimpleNamespace()
    assert opt.visit_array_access(no_attrs) is no_attrs
    assert opt.visit_member_access(no_attrs) is no_attrs
    assert opt.visit_function_call(no_attrs) is no_attrs
    assert opt.visit_range_expression(no_attrs) is no_attrs
    assert opt.visit_set_expression(no_attrs) is no_attrs
    assert opt.visit_for_expression(no_attrs) is no_attrs
    assert opt.visit_of_expression(no_attrs) is no_attrs
    assert opt.visit_at_expression(no_attrs) is no_attrs
    assert opt.visit_in_expression(no_attrs) is no_attrs

    sid = StringIdentifier("$a")
    assert opt.visit_boolean_literal(BooleanLiteral(True)) == BooleanLiteral(True)
    assert opt.visit_integer_literal(IntegerLiteral(1)) == IntegerLiteral(1)
    assert opt.visit_identifier(Identifier("id")) == Identifier("id")
    assert opt.visit_string_identifier(sid) == sid
    assert opt.visit_string_count(StringCount("$a")) == StringCount("$a")
    assert opt.visit_string_offset(StringOffset("$a")) == StringOffset("$a")
    assert opt.visit_string_length(StringLength("$a")) == StringLength("$a")
    assert opt.visit_double_literal(SimpleNamespace(v=1.2)).v == 1.2
    assert opt.visit_string_literal(StringLiteral("z")) == StringLiteral("z")


def test_optimize_yarafile_and_rule_level_passthrough() -> None:
    opt = ExpressionOptimizer()
    rule1 = Rule(
        name="r1", condition=BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(True))
    )
    rule2 = Rule(name="r2", condition=None)
    yf = YaraFile(rules=[rule1, rule2])

    optimized, count = opt.optimize(yf)
    assert isinstance(optimized, YaraFile)
    assert count >= 1

    dummy = SimpleNamespace(x=1)
    assert opt.visit_yara_file(dummy) is dummy
    assert opt.visit_rule(dummy) is dummy
    assert opt.visit_import(dummy) is dummy
    assert opt.visit_include(dummy) is dummy
    assert opt.visit_tag(dummy) is dummy
    assert opt.visit_meta(dummy) is dummy
    assert opt.visit_plain_string(dummy) is dummy
    assert opt.visit_hex_string(dummy) is dummy
    assert opt.visit_regex_string(dummy) is dummy
