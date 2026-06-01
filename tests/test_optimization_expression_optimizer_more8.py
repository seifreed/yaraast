"""Additional branch coverage for expression optimizer."""

from __future__ import annotations

from types import SimpleNamespace

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
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
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.optimization.expression_optimizer import ExpressionOptimizer, optimize_expression
from yaraast.shared.integer_semantics import INT64_MAX, INT64_MIN


def test_integer_folding_all_remaining_operators() -> None:
    opt = ExpressionOptimizer()

    assert opt.visit(BinaryExpression(IntegerLiteral(9), "/", IntegerLiteral(3))) == IntegerLiteral(
        3
    )
    assert opt.visit(
        BinaryExpression(IntegerLiteral(9), "\\", IntegerLiteral(3))
    ) == IntegerLiteral(3)
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


def test_integer_constant_folding_uses_yara_int64_semantics() -> None:
    opt = ExpressionOptimizer()

    assert opt.visit(
        BinaryExpression(IntegerLiteral(INT64_MAX), "+", IntegerLiteral(1))
    ) == IntegerLiteral(INT64_MIN)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(INT64_MIN), "-", IntegerLiteral(1))
    ) == IntegerLiteral(INT64_MAX)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(1), "<<", IntegerLiteral(63))
    ) == IntegerLiteral(INT64_MIN)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(1), "<<", IntegerLiteral(64))
    ) == IntegerLiteral(0)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(-1), ">>", IntegerLiteral(64))
    ) == IntegerLiteral(0)
    assert opt.visit(UnaryExpression("-", IntegerLiteral(INT64_MIN))) == IntegerLiteral(INT64_MIN)
    assert opt.visit(UnaryExpression("~", IntegerLiteral(INT64_MIN))) == IntegerLiteral(INT64_MAX)

    overflow_div = BinaryExpression(IntegerLiteral(INT64_MIN), "\\", IntegerLiteral(-1))
    assert opt.visit(overflow_div) is overflow_div


def test_integer_division_and_modulo_by_zero_do_not_fold() -> None:
    opt = ExpressionOptimizer()
    div = BinaryExpression(IntegerLiteral(9), "/", IntegerLiteral(0))
    mod = BinaryExpression(IntegerLiteral(9), "%", IntegerLiteral(0))

    assert opt.visit(div) is div
    assert opt.visit(mod) is mod


def test_parentheses_elimination_counts_as_optimization() -> None:
    opt = ExpressionOptimizer()

    optimized = opt.optimize(ParenthesesExpression(BooleanLiteral(True)))

    assert optimized == BooleanLiteral(True)
    assert opt.optimization_count == 1


def test_expression_optimization_does_not_mutate_source_tree() -> None:
    expr = BinaryExpression(
        ParenthesesExpression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))),
        "==",
        IntegerLiteral(3),
    )
    original = BinaryExpression(
        ParenthesesExpression(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2))),
        "==",
        IntegerLiteral(3),
    )

    optimized = ExpressionOptimizer().optimize(expr)

    assert optimized == BooleanLiteral(True)
    assert expr == original
    assert isinstance(expr.left, ParenthesesExpression)


def test_large_integer_division_and_modulo_fold_without_float_conversion() -> None:
    opt = ExpressionOptimizer()
    large = 10**400 + 1

    assert opt.visit(
        BinaryExpression(IntegerLiteral(large), "/", IntegerLiteral(3))
    ) == IntegerLiteral(large // 3)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(-large), "/", IntegerLiteral(3))
    ) == IntegerLiteral(-(large // 3))
    assert opt.visit(
        BinaryExpression(IntegerLiteral(large), "%", IntegerLiteral(3))
    ) == IntegerLiteral(large % 3)
    assert opt.visit(
        BinaryExpression(IntegerLiteral(-large), "%", IntegerLiteral(3))
    ) == IntegerLiteral(-(large % 3))


def test_negative_shift_counts_do_not_crash_or_fold() -> None:
    opt = ExpressionOptimizer()
    expr = BinaryExpression(IntegerLiteral(1), "<<", UnaryExpression("-", IntegerLiteral(1)))

    optimized = opt.visit(expr)

    assert optimized is expr
    assert expr.right == IntegerLiteral(-1)


def test_identity_and_boolean_shortcuts_remaining_paths() -> None:
    opt = ExpressionOptimizer()
    x = Identifier("x")

    assert opt.visit(BinaryExpression(x, "+", IntegerLiteral(0))) == BinaryExpression(
        x, "+", IntegerLiteral(0)
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(0), "+", x)) == BinaryExpression(
        IntegerLiteral(0), "+", x
    )
    assert opt.visit(BinaryExpression(x, "*", IntegerLiteral(1))) == BinaryExpression(
        x, "*", IntegerLiteral(1)
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(1), "*", x)) == BinaryExpression(
        IntegerLiteral(1), "*", x
    )
    assert opt.visit(BinaryExpression(x, "*", IntegerLiteral(0))) == BinaryExpression(
        x, "*", IntegerLiteral(0)
    )
    assert opt.visit(BinaryExpression(IntegerLiteral(0), "*", x)) == BinaryExpression(
        IntegerLiteral(0), "*", x
    )

    assert opt.visit(BinaryExpression(BooleanLiteral(True), "or", x)) == BooleanLiteral(True)
    assert opt.visit(BinaryExpression(BooleanLiteral(False), "or", x)) == BinaryExpression(
        BooleanLiteral(False), "or", x
    )
    assert opt.visit(BinaryExpression(BooleanLiteral(True), "and", x)) == BinaryExpression(
        BooleanLiteral(True), "and", x
    )
    assert opt.visit(BinaryExpression(BooleanLiteral(False), "and", x)) == BooleanLiteral(False)
    assert opt.visit(BinaryExpression(x, "and", BooleanLiteral(False))) == BooleanLiteral(False)
    assert opt.visit(BinaryExpression(x, "and", BooleanLiteral(True))) == BinaryExpression(
        x, "and", BooleanLiteral(True)
    )
    assert opt.visit(BinaryExpression(x, "or", BooleanLiteral(True))) == BooleanLiteral(True)
    assert opt.visit(BinaryExpression(x, "or", BooleanLiteral(False))) == BinaryExpression(
        x, "or", BooleanLiteral(False)
    )

    no_fold = BinaryExpression(BooleanLiteral(True), "==", BooleanLiteral(True))
    assert opt.visit(no_fold) is no_fold


def test_optimizer_preserves_arithmetic_identity_semantics_for_unknown_types() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="external_string",
                condition=BinaryExpression(Identifier("external"), "+", IntegerLiteral(0)),
            )
        ]
    )

    original_evaluator = YaraEvaluator()
    original_evaluator.context.variables["external"] = "text"
    assert original_evaluator.evaluate_file(ast) == {"external_string": False}

    optimized, count = ExpressionOptimizer().optimize(ast)

    optimized_evaluator = YaraEvaluator()
    optimized_evaluator.context.variables["external"] = "text"
    assert optimized_evaluator.evaluate_file(optimized) == {"external_string": False}
    assert count == 0


def test_optimizer_preserves_boolean_identity_semantics_for_undefined_values() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="true_and_undefined",
                condition=BinaryExpression(
                    BinaryExpression(BooleanLiteral(True), "and", StringOffset("$missing")),
                    "==",
                    BooleanLiteral(False),
                ),
            ),
            Rule(
                name="false_or_undefined",
                condition=BinaryExpression(
                    BinaryExpression(BooleanLiteral(False), "or", StringOffset("$missing")),
                    "==",
                    BooleanLiteral(False),
                ),
            ),
        ]
    )

    assert YaraEvaluator().evaluate_file(ast) == {
        "true_and_undefined": True,
        "false_or_undefined": True,
    }

    optimized, count = ExpressionOptimizer().optimize(ast)

    assert YaraEvaluator().evaluate_file(optimized) == {
        "true_and_undefined": True,
        "false_or_undefined": True,
    }
    assert count == 0


def test_optimizer_preserves_boolean_identity_semantics_for_truthy_values() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="truthy_and_true",
                condition=BinaryExpression(
                    BinaryExpression(Identifier("external"), "and", BooleanLiteral(True)),
                    "==",
                    BooleanLiteral(True),
                ),
            ),
            Rule(
                name="truthy_or_false",
                condition=BinaryExpression(
                    BinaryExpression(Identifier("external"), "or", BooleanLiteral(False)),
                    "==",
                    BooleanLiteral(True),
                ),
            ),
        ]
    )

    original_evaluator = YaraEvaluator()
    original_evaluator.context.variables["external"] = "text"
    assert original_evaluator.evaluate_file(ast) == {
        "truthy_and_true": True,
        "truthy_or_false": True,
    }

    optimized, count = ExpressionOptimizer().optimize(ast)

    optimized_evaluator = YaraEvaluator()
    optimized_evaluator.context.variables["external"] = "text"
    assert optimized_evaluator.evaluate_file(optimized) == {
        "truthy_and_true": True,
        "truthy_or_false": True,
    }
    assert count == 0


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


def test_visit_collection_and_access_nodes_preserves_set_duplicates() -> None:
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
    assert len(out_set.elements) == 8
    assert opt.optimization_count == 0

    unique_set = SetExpression(elements=[IntegerLiteral(1), BooleanLiteral(False), Identifier("b")])
    untouched = opt.visit_set_expression(unique_set)
    assert untouched is unique_set
    assert len(untouched.elements) == 3


def test_for_expression_duplicate_iterable_values_are_semantic() -> None:
    opt = ExpressionOptimizer()
    expr = ForExpression(
        quantifier=2,
        variable="i",
        iterable=SetExpression([IntegerLiteral(1), IntegerLiteral(1)]),
        body=BinaryExpression(Identifier("i"), "==", IntegerLiteral(1)),
    )

    optimized = opt.visit_for_expression(expr)

    assert isinstance(optimized.iterable, SetExpression)
    assert optimized.iterable.elements == [IntegerLiteral(1), IntegerLiteral(1)]
    assert opt.optimization_count == 0


def test_string_offset_and_length_indexes_are_optimized() -> None:
    opt = ExpressionOptimizer()

    offset = StringOffset("$a", BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)))
    length = StringLength("$a", BinaryExpression(IntegerLiteral(5), "-", IntegerLiteral(3)))

    assert opt.visit_string_offset(offset).index == IntegerLiteral(3)
    assert opt.visit_string_length(length).index == IntegerLiteral(2)


def test_visit_for_of_at_in_and_passthrough_methods() -> None:
    opt = ExpressionOptimizer()

    for_node = SimpleNamespace(
        quantifier=BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)),
        iterable=Identifier("it"),
        body=Identifier("body"),
    )
    of_node = SimpleNamespace(quantifier=IntegerLiteral(2), string_set=Identifier("s"))
    raw_of_node = OfExpression(quantifier="any", string_set=["$a", "$b"])
    raw_for_of_node = ForOfExpression(
        quantifier="all",
        string_set=["$a", "$b"],
        condition=BooleanLiteral(True),
    )
    tuple_of_node = OfExpression(
        quantifier="any",
        string_set=(BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)), "$a"),
    )
    at_node = SimpleNamespace(offset=IntegerLiteral(4))
    in_node = SimpleNamespace(range=Identifier("r"))
    in_node_with_subject = SimpleNamespace(
        subject=BinaryExpression(IntegerLiteral(1), "+", IntegerLiteral(2)),
        range=Identifier("r"),
    )

    assert opt.visit_for_expression(for_node).iterable == Identifier("it")
    assert for_node.quantifier == IntegerLiteral(3)
    assert opt.visit_of_expression(of_node).string_set == Identifier("s")
    assert opt.visit_of_expression(raw_of_node).string_set == ["$a", "$b"]
    assert opt.visit_for_of_expression(raw_for_of_node).string_set == ["$a", "$b"]
    assert opt.visit_of_expression(tuple_of_node).string_set == (IntegerLiteral(3), "$a")
    assert opt.visit_at_expression(at_node).offset == IntegerLiteral(4)
    assert opt.visit_in_expression(in_node).range == Identifier("r")
    assert opt.visit_in_expression(in_node_with_subject).subject == IntegerLiteral(3)

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
