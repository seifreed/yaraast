"""Extra real coverage for complexity helpers and model."""

from __future__ import annotations

from yaraast.ast.conditions import ForExpression, ForOfExpression
from yaraast.ast.expressions import BinaryExpression, Identifier, IntegerLiteral, UnaryExpression
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.metrics.complexity_helpers import (
    calculate_cognitive_complexity,
    calculate_cyclomatic_complexity,
    calculate_expression_complexity,
    calculate_rule_complexity,
)
from yaraast.metrics.complexity_model import ComplexityMetrics


def test_complexity_helpers_cover_rule_expression_and_cognitive_paths() -> None:
    expr = BinaryExpression(
        left=UnaryExpression(operator="not", operand=Identifier(name="x")),
        operator="and",
        right=IntegerLiteral(value=1),
    )

    rule = Rule(
        name="helper_rule",
        modifiers=["private", "global"],
        strings=[
            PlainString(identifier="$a", value="abc"),
            HexString(identifier="$b", tokens=[HexByte(value=0x41)]),
            RegexString(identifier="$c", regex="ab+"),
        ],
        condition=expr,
    )

    assert calculate_rule_complexity(rule) > 1
    assert calculate_expression_complexity(expr) >= 1
    assert calculate_cyclomatic_complexity(expr) >= 2

    for_expr = ForExpression(
        quantifier="any",
        variable="i",
        iterable=IntegerLiteral(value=1),
        body=Identifier(name="i"),
    )
    for_of_expr = ForOfExpression(
        quantifier="all",
        string_set=Identifier(name="them"),
        condition=IntegerLiteral(value=1),
    )
    assert calculate_cognitive_complexity(for_expr) >= 4
    assert calculate_cognitive_complexity(for_of_expr) >= 4


def test_complexity_model_to_dict_quality_score_and_grades() -> None:
    metrics = ComplexityMetrics(
        total_rules=10,
        total_imports=1,
        total_includes=2,
        rules_with_strings=8,
        rules_with_meta=9,
        rules_with_tags=3,
        private_rules=1,
        global_rules=1,
        total_strings=12,
        plain_strings=6,
        hex_strings=3,
        regex_strings=3,
        strings_with_modifiers=4,
        max_condition_depth=9,
        avg_condition_depth=3.5,
        total_binary_ops=7,
        total_unary_ops=2,
        for_expressions=1,
        for_of_expressions=1,
        of_expressions=1,
        hex_wildcards=2,
        hex_jumps=1,
        hex_alternatives=1,
        regex_groups=3,
        regex_quantifiers=5,
        unused_strings=["r:$a", "r:$b"],
        complex_rules=["r1", "r2"],
        cyclomatic_complexity={"r1": 11},
        string_dependencies={"r1": {"$a", "$b"}},
        module_usage={"pe": 1},
    )

    data = metrics.to_dict()
    assert data["file_metrics"]["total_rules"] == 10
    assert sorted(data["dependencies"]["string_dependencies"]["r1"]) == ["$a", "$b"]
    assert data["quality_metrics"]["complex_rules"] == ["r1", "r2"]

    score = metrics.get_quality_score()
    assert score == 55.0
    assert metrics.get_complexity_grade() == "F"

    grade_cases = [
        (ComplexityMetrics(total_rules=1, rules_with_meta=1), "A"),
        (
            ComplexityMetrics(
                total_rules=10,
                rules_with_meta=0,
                max_condition_depth=6,
                unused_strings=["a"],
            ),
            "B",
        ),
        (
            ComplexityMetrics(
                total_rules=10,
                rules_with_meta=0,
                max_condition_depth=9,
                unused_strings=["a"],
            ),
            "C",
        ),
        (
            ComplexityMetrics(
                total_rules=10,
                rules_with_meta=0,
                max_condition_depth=6,
                unused_strings=["a", "b", "c", "d"],
                complex_rules=["r1"],
            ),
            "D",
        ),
        (
            ComplexityMetrics(
                total_rules=10,
                rules_with_meta=0,
                max_condition_depth=9,
                unused_strings=["a", "b", "c", "d"],
                complex_rules=["r1", "r2"],
            ),
            "F",
        ),
    ]

    for case_metrics, expected in grade_cases:
        assert case_metrics.get_complexity_grade() == expected
