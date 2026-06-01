"""Additional branch coverage for dead code eliminator."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.modifiers import RuleModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexString, PlainString, RegexString
from yaraast.codegen import CodeGenerator
from yaraast.evaluation.evaluator import YaraEvaluator
from yaraast.optimization.dead_code_eliminator import DeadCodeEliminator, eliminate_dead_code
from yaraast.optimization.rule_optimizer import RuleOptimizer
from yaraast.parser import Parser
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    ListExpression,
    WithDeclaration,
    WithStatement,
)


def test_contains_rule_reference_and_external_references() -> None:
    dce = DeadCodeEliminator()

    assert dce._contains_rule_reference(Identifier("other_rule")) is True
    assert dce._contains_rule_reference(Identifier("them")) is False
    assert (
        dce._contains_rule_reference(BinaryExpression(Identifier("true"), "and", Identifier("x")))
        is True
    )

    no_cond = Rule(name="a", condition=None)
    with_cond = Rule(name="b", condition=Identifier("ref_rule"))
    assert dce._has_external_references(no_cond) is False
    assert dce._has_external_references(with_cond) is True


def test_visit_methods_track_usage_and_passthrough_nodes() -> None:
    dce = DeadCodeEliminator()
    dce.in_condition = True

    assert dce.visit_string_identifier(StringIdentifier("$a")) == StringIdentifier("$a")
    assert "$a" in dce.used_strings

    assert dce.visit_identifier(Identifier("ref_rule")) == Identifier("ref_rule")
    assert "ref_rule" in dce.used_rules

    assert dce.visit_identifier(Identifier("any")) == Identifier("any")
    assert dce.visit_string_wildcard(StringWildcard("$x*")) == StringWildcard("$x*")
    assert "$x*" in dce.used_strings

    assert dce.visit_string_count(StringCount("$c")) == StringCount("$c")
    assert dce.visit_string_offset(StringOffset("$o")) == StringOffset("$o")
    assert dce.visit_string_length(StringLength("$l")) == StringLength("$l")
    assert "$c" in dce.used_strings and "$o" in dce.used_strings and "$l" in dce.used_strings

    dce.in_condition = False
    assert dce.visit_import(SimpleNamespace()) is not None
    assert dce.visit_include(SimpleNamespace()) is not None
    assert dce.visit_tag(SimpleNamespace()) is not None
    assert dce.visit_meta(SimpleNamespace()) is not None
    assert dce.visit_plain_string(PlainString(identifier="$p", value="x")) == PlainString(
        identifier="$p", value="x"
    )
    assert dce.visit_hex_string(HexString(identifier="$h", tokens=[])) == HexString(
        identifier="$h", tokens=[]
    )
    assert dce.visit_regex_string(RegexString(identifier="$r", regex="x")) == RegexString(
        identifier="$r", regex="x"
    )


def test_binary_and_unary_expression_simplifications() -> None:
    dce = DeadCodeEliminator()

    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    ) == BooleanLiteral(False)
    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(True), "or", BooleanLiteral(False))
    ) == BooleanLiteral(True)
    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(False), "and", Identifier("x"))
    ) == BooleanLiteral(False)
    assert dce.visit_binary_expression(
        BinaryExpression(BooleanLiteral(True), "or", Identifier("x"))
    ) == BooleanLiteral(True)
    assert dce.visit_binary_expression(
        BinaryExpression(Identifier("x"), "and", BooleanLiteral(False))
    ) == BooleanLiteral(False)
    assert dce.visit_binary_expression(
        BinaryExpression(Identifier("x"), "or", BooleanLiteral(True))
    ) == BooleanLiteral(True)

    assert dce.visit_unary_expression(
        UnaryExpression("not", BooleanLiteral(True))
    ) == BooleanLiteral(False)
    non_folded = UnaryExpression("-", BooleanLiteral(True))
    assert dce.visit_unary_expression(non_folded) is non_folded


def test_visit_rule_and_file_filtering_paths() -> None:
    dce = DeadCodeEliminator()

    rule_used = Rule(
        name="used",
        strings=[PlainString(identifier="$a", value="a"), PlainString(identifier="$b", value="b")],
        condition=StringIdentifier("$a"),
    )
    rule_false = Rule(name="drop_false", condition=BooleanLiteral(False))
    rule_ref = Rule(name="ref", condition=Identifier("used"))
    rule_private = Rule(name="priv", modifiers=["private"], condition=Identifier("other"))
    yf = YaraFile(rules=[rule_used, rule_false, rule_ref, rule_private])

    optimized, count = dce.eliminate(yf)

    assert count >= 2
    assert all(r.name != "drop_false" for r in optimized.rules)
    kept_used = next(r for r in optimized.rules if r.name == "used")
    assert [s.identifier for s in kept_used.strings] == ["$a"]


def test_referenced_false_rule_is_not_removed() -> None:
    ast = Parser().parse("""
        private rule helper {
            condition:
                false
        }

        rule main {
            condition:
                not helper
        }
    """)

    optimized, stats = RuleOptimizer().optimize(ast)
    output = CodeGenerator().generate(optimized)

    assert stats["dead_code_eliminations"] == 0
    assert [rule.name for rule in optimized.rules] == ["helper", "main"]
    assert "private rule helper" in output
    Parser().parse(output)


def test_global_false_rule_is_not_removed() -> None:
    ast = Parser().parse("""
        global rule gate {
            condition:
                false
        }

        rule hit {
            condition:
                true
        }
    """)

    optimized, stats = RuleOptimizer().optimize(ast)
    output = CodeGenerator().generate(optimized)

    assert stats["dead_code_eliminations"] == 0
    assert [rule.name for rule in optimized.rules] == ["gate", "hit"]
    assert "global rule gate" in output
    assert YaraEvaluator().evaluate_file(optimized) == {"gate": False, "hit": False}


def test_global_private_rule_is_not_removed_as_unreferenced_private() -> None:
    ast = Parser().parse("""
        global private rule gate {
            condition:
                false
        }

        rule hit {
            condition:
                true
        }
    """)

    optimized, stats = RuleOptimizer().optimize(ast)
    output = CodeGenerator().generate(optimized)

    assert stats["dead_code_eliminations"] == 0
    assert [rule.name for rule in optimized.rules] == ["gate", "hit"]
    assert "global private rule gate" in output
    assert YaraEvaluator().evaluate_file(optimized) == {"gate": False, "hit": False}


def test_dead_code_eliminator_keeps_private_rules_referenced_by_rule_wildcard() -> None:
    ast = Parser().parse("""
        private rule a1 {
            condition:
                false
        }

        private rule a2 {
            condition:
                true
        }

        rule main {
            condition:
                any of (a*)
        }
    """)

    optimized, count = DeadCodeEliminator().eliminate(ast)
    output = CodeGenerator().generate(optimized)

    assert count == 0
    assert [rule.name for rule in optimized.rules] == ["a1", "a2", "main"]
    assert "private rule a1" in output
    assert "private rule a2" in output
    Parser().parse(output)


def test_dead_code_eliminator_removes_unreferenced_private_rules_without_other_references() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="helper",
                modifiers=[RuleModifier.from_string("private")],
                condition=BooleanLiteral(True),
            ),
            Rule(name="legacy_helper", modifiers=["private"], condition=BooleanLiteral(True)),
            Rule(name="main", condition=BooleanLiteral(True)),
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 2
    assert [rule.name for rule in optimized.rules] == ["main"]


def test_dead_code_eliminator_ignores_member_roots_when_tracking_rule_references() -> None:
    dce = DeadCodeEliminator()
    ast = YaraFile(
        rules=[
            Rule(
                name="main",
                condition=MemberAccess(Identifier("pe"), "number_of_sections"),
            ),
            Rule(
                name="pe",
                modifiers=["private"],
                condition=BooleanLiteral(False),
            ),
        ],
    )

    optimized, count = dce.eliminate(ast)

    assert count == 1
    assert [rule.name for rule in optimized.rules] == ["main"]


def test_dead_code_eliminator_ignores_for_loop_variables_as_rule_references() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="main",
                condition=ForExpression(
                    quantifier="any",
                    variable="i",
                    iterable=SetExpression([IntegerLiteral(1)]),
                    body=BinaryExpression(Identifier("i"), "==", IntegerLiteral(1)),
                ),
            ),
            Rule(
                name="i",
                modifiers=["private"],
                condition=BooleanLiteral(True),
            ),
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 1
    assert [rule.name for rule in optimized.rules] == ["main"]


def test_dead_code_eliminator_ignores_yarax_locals_as_rule_references() -> None:
    cases = [
        (
            WithStatement(
                declarations=[WithDeclaration("x", IntegerLiteral(1))],
                body=Identifier("x"),
            ),
            ["x"],
        ),
        (
            ArrayComprehension(
                expression=Identifier("x"),
                variable="x",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            ["x"],
        ),
        (
            DictComprehension(
                key_expression=Identifier("k"),
                value_expression=Identifier("v"),
                key_variable="k",
                value_variable="v",
                iterable=ListExpression([IntegerLiteral(1)]),
            ),
            ["k", "v"],
        ),
        (
            LambdaExpression(parameters=["x"], body=Identifier("x")),
            ["x"],
        ),
    ]

    for condition, private_names in cases:
        ast = YaraFile(
            rules=[
                Rule(name="main", condition=condition),
                *[
                    Rule(
                        name=name,
                        modifiers=["private"],
                        condition=BooleanLiteral(True),
                    )
                    for name in private_names
                ],
            ]
        )

        optimized, count = DeadCodeEliminator().eliminate(ast)

        assert count == len(private_names)
        assert [rule.name for rule in optimized.rules] == ["main"]


def test_dead_code_eliminator_ignores_yarax_string_locals_as_string_references() -> None:
    cases = [
        StringIdentifier("$a"),
        StringCount("a"),
        StringOffset("a"),
        StringLength("a"),
        OfExpression("any", "$a"),
        OfExpression("any", SetExpression([StringIdentifier("$a")])),
        OfExpression("any", SetExpression([StringLiteral("$a")])),
    ]

    for condition in cases:
        ast = YaraFile(
            rules=[
                Rule(
                    name="shadowed_string",
                    strings=[PlainString(identifier="$a", value="value")],
                    condition=WithStatement(
                        declarations=[WithDeclaration("$a", IntegerLiteral(1))],
                        body=condition,
                    ),
                )
            ]
        )

        optimized, count = DeadCodeEliminator().eliminate(ast)

        assert count == 1
        assert optimized.rules[0].strings == []


def test_dead_code_eliminator_resolves_yarax_string_locals_in_string_sets() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="local_string_set",
                strings=[PlainString(identifier="$a", value="needle")],
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", StringLiteral("$a"))],
                    body=OfExpression("any", SetExpression([StringIdentifier("$x")])),
                ),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert [string.identifier for string in optimized.rules[0].strings] == ["$a"]


def test_string_wildcard_keeps_matching_strings() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="wildcard",
        strings=[
            PlainString(identifier="$api_one", value="a"),
            PlainString(identifier="$api_two", value="b"),
            PlainString(identifier="$other", value="c"),
        ],
        condition=StringWildcard("$api*"),
    )

    out_rule = dce.eliminate_dead_code(rule)

    assert [string.identifier for string in out_rule.strings] == ["$api_one", "$api_two"]


def test_dead_code_eliminator_named_wildcard_ignores_anonymous_internal_ids() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="anonymous_wildcard",
        strings=[
            PlainString(identifier="$alpha", value="a"),
            PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
        ],
        condition=StringWildcard("$a*"),
    )

    out_rule = dce.eliminate_dead_code(rule)

    assert [string.identifier for string in out_rule.strings] == ["$alpha"]


def test_dead_code_eliminator_global_wildcard_keeps_anonymous_strings() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="anonymous_global_wildcard",
        strings=[
            PlainString(identifier="$alpha", value="a"),
            PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
        ],
        condition=StringWildcard("$*"),
    )

    out_rule = dce.eliminate_dead_code(rule)

    assert [string.identifier for string in out_rule.strings] == ["$alpha", "$anon_1"]


def test_dead_code_eliminator_removes_strings_when_no_strings_are_used() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="no_string_refs",
        strings=[PlainString(identifier="$unused", value="unused")],
        condition=BooleanLiteral(True),
    )

    optimized, count = dce.eliminate(YaraFile(rules=[rule]))

    assert count == 1
    assert optimized.rules[0].strings == []


def test_dead_code_eliminator_keeps_raw_string_set_references() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="raw_sets",
        strings=[
            PlainString(identifier="$a", value="a"),
            PlainString(identifier="$b", value="b"),
            PlainString(identifier="$c", value="c"),
            PlainString(identifier="$unused", value="unused"),
        ],
        condition=OfExpression(
            "any",
            ["$a"],
        ),
    )

    out_rule = dce.eliminate_dead_code(rule)
    assert [string.identifier for string in out_rule.strings] == ["$a"]

    dce = DeadCodeEliminator()
    rule = Rule(
        name="literal_sets",
        strings=[
            PlainString(identifier="$a", value="a"),
            PlainString(identifier="$b", value="b"),
            PlainString(identifier="$c", value="c"),
        ],
        condition=ForOfExpression(
            "any",
            SetExpression([StringLiteral("$b"), StringLiteral("$c")]),
            condition=None,
        ),
    )
    out_rule = dce.eliminate_dead_code(rule)
    assert [string.identifier for string in out_rule.strings] == ["$b", "$c"]


def test_dead_code_eliminator_rejects_embedded_string_reference_operators() -> None:
    invalid_conditions = [
        (BinaryExpression(StringCount("#a"), ">", IntegerLiteral(0)), "#a"),
        (BinaryExpression(StringOffset("@a"), ">=", IntegerLiteral(0)), "@a"),
        (BinaryExpression(StringLength("!a"), ">", IntegerLiteral(0)), "!a"),
    ]

    for condition, invalid_reference in invalid_conditions:
        ast = YaraFile(
            rules=[
                Rule(
                    name="invalid_string_ref",
                    strings=[PlainString(identifier="$a", value="a")],
                    condition=condition,
                )
            ]
        )

        with pytest.raises(ValueError, match=f"Invalid string reference '{invalid_reference}'"):
            DeadCodeEliminator().eliminate(ast)


def test_dead_code_eliminator_keeps_parenthesized_string_literal_sets() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="literal_sets",
        strings=[
            PlainString(identifier="$a", value="a"),
            PlainString(identifier="$b", value="b"),
            PlainString(identifier="$unused", value="unused"),
        ],
        condition=ForOfExpression(
            "any",
            ParenthesesExpression(SetExpression([StringLiteral("$a"), StringLiteral("$b")])),
            condition=None,
        ),
    )

    out_rule = dce.eliminate_dead_code(rule)

    assert [string.identifier for string in out_rule.strings] == ["$a", "$b"]


def test_dead_code_eliminator_tracks_string_usage_per_rule() -> None:
    dce = DeadCodeEliminator()
    ast = YaraFile(
        rules=[
            Rule(
                name="one",
                strings=[
                    PlainString(identifier="$a", value="a"),
                    PlainString(identifier="$b", value="b"),
                ],
                condition=StringIdentifier("$a"),
            ),
            Rule(
                name="two",
                strings=[
                    PlainString(identifier="$a", value="a"),
                    PlainString(identifier="$b", value="b"),
                ],
                condition=StringIdentifier("$b"),
            ),
        ]
    )

    optimized, count = dce.eliminate(ast)

    assert count == 2
    assert [string.identifier for string in optimized.rules[0].strings] == ["$a"]
    assert [string.identifier for string in optimized.rules[1].strings] == ["$b"]


def test_dead_code_eliminator_tracks_string_usage_per_duplicate_rule_name() -> None:
    dce = DeadCodeEliminator()
    ast = YaraFile(
        rules=[
            Rule(
                name="dup",
                strings=[
                    PlainString(identifier="$a", value="a"),
                    PlainString(identifier="$b", value="b"),
                ],
                condition=StringIdentifier("$a"),
            ),
            Rule(
                name="dup",
                strings=[
                    PlainString(identifier="$a", value="a"),
                    PlainString(identifier="$b", value="b"),
                ],
                condition=StringIdentifier("$b"),
            ),
        ]
    )

    optimized, count = dce.eliminate(ast)

    assert count == 2
    assert [string.identifier for string in optimized.rules[0].strings] == ["$a"]
    assert [string.identifier for string in optimized.rules[1].strings] == ["$b"]


def test_dead_code_eliminator_does_not_mutate_source_rules() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="strings",
                strings=[
                    PlainString(identifier="$used", value="used"),
                    PlainString(identifier="$unused", value="unused"),
                ],
                condition=StringIdentifier("$used"),
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 1
    assert [string.identifier for string in optimized.rules[0].strings] == ["$used"]
    assert [string.identifier for string in ast.rules[0].strings] == ["$used", "$unused"]


def test_dead_code_eliminator_does_not_mutate_source_conditions() -> None:
    inner = BinaryExpression(BooleanLiteral(True), "and", BooleanLiteral(False))
    original_condition = BinaryExpression(inner, "or", StringIdentifier("$used"))
    ast = YaraFile(
        rules=[
            Rule(
                name="condition_tree",
                strings=[PlainString(identifier="$used", value="used")],
                condition=original_condition,
            )
        ]
    )

    optimized, count = DeadCodeEliminator().eliminate(ast)

    assert count == 0
    assert optimized.rules[0].condition == BinaryExpression(
        BooleanLiteral(False),
        "or",
        StringIdentifier("$used"),
    )
    assert ast.rules[0].condition is original_condition
    assert original_condition.left is inner
    assert original_condition.left == BinaryExpression(
        BooleanLiteral(True),
        "and",
        BooleanLiteral(False),
    )


def test_eliminate_dead_code_single_rule_and_convenience_wrapper() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="single",
        strings=[PlainString(identifier="$x", value="x"), PlainString(identifier="$y", value="y")],
        condition=StringIdentifier("$y"),
    )

    out_rule = dce.eliminate_dead_code(rule)
    assert [s.identifier for s in out_rule.strings] == ["$y"]

    # Wrapper currently returns the full eliminate() tuple.
    file_out, elim_count = eliminate_dead_code(YaraFile(rules=[rule]))
    assert isinstance(file_out, YaraFile)
    assert isinstance(elim_count, int)


def test_eliminate_dead_code_single_rule_resets_condition_context() -> None:
    dce = DeadCodeEliminator()
    rule = Rule(
        name="single",
        strings=[PlainString(identifier="$x", value="x")],
        condition=StringIdentifier("$x"),
    )

    dce.eliminate_dead_code(rule)
    dce.visit_string_identifier(StringIdentifier("$outside"))

    assert dce.in_condition is False
    assert dce.current_rule is None
    assert dce.current_rule_key is None
    assert "$outside" not in dce.used_strings


def test_visit_boolean_literal_passthrough() -> None:
    dce = DeadCodeEliminator()
    lit = BooleanLiteral(True)
    assert dce.visit_boolean_literal(lit) is lit
