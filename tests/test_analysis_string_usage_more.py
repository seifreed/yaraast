from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    BinaryExpression,
    Expression,
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement


class _FalsyStringIdentifier(StringIdentifier):
    def __bool__(self) -> bool:
        return False


def test_string_usage_analyzer_covers_offset_length_at_in_forof_and_of() -> None:
    ast = Parser().parse("""
rule advanced {
    strings:
        $a = "abc"
        $b = "def"
        $c = "ghi"
    condition:
        #a > 0 and @b[1] > 0 and !c[1] > 0 and $a at 0 and $b in (0..filesize) and all of them
}
""")
    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    used = set(results["advanced"]["used"])
    assert {"$a", "$b", "$c"} <= used
    assert results["advanced"]["unused"] == []
    assert analyzer.get_unused_strings() == {}
    assert analyzer.get_undefined_strings() == {}


def test_string_usage_analyzer_ignores_implicit_current_string_refs() -> None:
    ast = Parser().parse("""
rule implicit_current_string_usage {
    strings:
        $a = "abc"
        $b = "def"
    condition:
        for any of them : (
            $ at @missing_offset or
            $ in (@missing_range..filesize) or
            (# == 1 and @ == 0 and ! == 3)
        )
}
""")

    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    assert results["implicit_current_string_usage"]["used"] == [
        "$a",
        "$b",
        "$missing_offset",
        "$missing_range",
    ]
    assert results["implicit_current_string_usage"]["unused"] == []
    assert results["implicit_current_string_usage"]["undefined"] == [
        "$missing_offset",
        "$missing_range",
    ]


def test_string_usage_analyzer_respects_with_local_string_ref_shadowing() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="local_count",
                strings=[PlainString(identifier="$x", value="real")],
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", IntegerLiteral(1))],
                    body=BinaryExpression(
                        StringCount("x"),
                        ">",
                        IntegerLiteral(0),
                    ),
                ),
            )
        ]
    )

    results = StringUsageAnalyzer().analyze(ast)

    assert results["local_count"]["used"] == []
    assert results["local_count"]["unused"] == ["$x"]
    assert results["local_count"]["usage_rate"] == 0


def test_string_usage_analyzer_getters_and_direct_visitor_paths() -> None:
    analyzer = StringUsageAnalyzer()
    ast = Parser().parse("""
rule one {
    strings:
        $a = "a"
    condition:
        $missing
}
rule two {
    strings:
        $b = "b"
        $c = "c"
    condition:
        $b
}
""")
    analyzer.analyze(ast)

    assert analyzer.get_unused_strings("two") == {"two": ["$c"]}
    assert analyzer.get_undefined_strings("one") == {"one": ["$missing"]}

    analyzer.current_rule = None
    analyzer.in_condition = False
    analyzer.visit_string_definition(PlainString("$x", value="x"))
    analyzer.visit_string_identifier(StringIdentifier("$x"))
    analyzer.visit_string_count(StringCount("$x"))
    analyzer.visit_string_offset(StringOffset("$x", IntegerLiteral(1)))
    analyzer.visit_string_length(StringLength("$x", IntegerLiteral(1)))
    analyzer.visit_at_expression(AtExpression("$x", IntegerLiteral(0)))
    analyzer.visit_in_expression(InExpression("$x", IntegerLiteral(5)))
    analyzer.visit_for_of_expression(
        ForOfExpression("any", SetExpression([StringLiteral("$x")]), condition=Identifier("flag")),
    )
    analyzer.visit_of_expression(
        OfExpression(IntegerLiteral(1), SetExpression([StringLiteral("$x"), StringLiteral("$y")])),
    )
    analyzer.visit_set_expression(SetExpression([StringLiteral("$x"), StringLiteral("$y")]))

    analyzer.current_rule = "manual"
    analyzer.defined_strings["manual"] = {"$a", "$b"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    analyzer.visit_string_identifier(StringIdentifier("$a"))
    analyzer.visit_string_count(StringCount("$a"))
    analyzer.visit_string_offset(StringOffset("$a", IntegerLiteral(0)))
    analyzer.visit_string_length(StringLength("$b", IntegerLiteral(1)))
    analyzer.visit_at_expression(AtExpression("$a", IntegerLiteral(0)))
    analyzer.visit_in_expression(InExpression("$b", IntegerLiteral(5)))
    analyzer.visit_in_expression(
        InExpression(OfExpression(IntegerLiteral(1), Identifier("them")), IntegerLiteral(5))
    )
    analyzer.visit_for_of_expression(
        ForOfExpression("all", Identifier("them"), condition=StringIdentifier("$a")),
    )
    analyzer.visit_for_of_expression(
        ForOfExpression("all", Identifier("them"), condition=_FalsyStringIdentifier("$b")),
    )
    analyzer.visit_of_expression(OfExpression(IntegerLiteral(1), Identifier("them")))

    assert analyzer.used_strings["manual"] == {"$a", "$b"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_for_of_expression(ForOfExpression("all", "them", condition=None))
    assert analyzer.used_strings["manual"] == {"$a", "$b"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_of_expression(OfExpression("any", ["$a", "$b"]))
    assert analyzer.used_strings["manual"] == {"$a", "$b"}


def test_string_usage_analyzer_preserves_duplicate_rule_occurrences() -> None:
    ast = Parser().parse("""
rule dup_first {
    strings:
        $a = "a"
        $unused_first = "unused"
    condition:
        $a
}
rule dup_second {
    strings:
        $b = "b"
        $unused_second = "unused"
    condition:
        $b
}
""")
    ast.rules[0].name = "dup"
    ast.rules[1].name = "dup"

    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    assert list(results) == ["dup#1", "dup#2"]
    assert results["dup#1"]["used"] == ["$a"]
    assert results["dup#1"]["unused"] == ["$unused_first"]
    assert results["dup#2"]["used"] == ["$b"]
    assert results["dup#2"]["unused"] == ["$unused_second"]
    assert analyzer.get_unused_strings("dup#1") == {"dup#1": ["$unused_first"]}


def test_string_usage_public_lists_are_stably_sorted() -> None:
    ast = Parser().parse("""
rule ordered_usage {
    strings:
        $z = "z"
        $a = "a"
        $m = "m"
    condition:
        $a or $missing_z or $missing_a
}
""")
    analyzer = StringUsageAnalyzer()

    results = analyzer.analyze(ast)

    assert results["ordered_usage"]["defined"] == ["$a", "$m", "$z"]
    assert results["ordered_usage"]["used"] == ["$a", "$missing_a", "$missing_z"]
    assert results["ordered_usage"]["unused"] == ["$m", "$z"]
    assert results["ordered_usage"]["undefined"] == ["$missing_a", "$missing_z"]
    assert analyzer.get_unused_strings("ordered_usage") == {"ordered_usage": ["$m", "$z"]}
    assert analyzer.get_undefined_strings("ordered_usage") == {
        "ordered_usage": ["$missing_a", "$missing_z"]
    }


def test_string_usage_rate_ignores_undefined_references() -> None:
    ast = Parser().parse("""
rule inflated_usage {
    strings:
        $a = "a"
    condition:
        $a and $missing
}
""")

    result = StringUsageAnalyzer().analyze(ast)["inflated_usage"]

    assert result["used"] == ["$a", "$missing"]
    assert result["undefined"] == ["$missing"]
    assert result["usage_rate"] == 1.0


def test_string_usage_analyzer_visit_rule_without_strings_or_condition() -> None:
    analyzer = StringUsageAnalyzer()
    rule = Rule(name="empty", strings=[], condition=None)
    analyzer.visit_rule(rule)
    assert analyzer.defined_strings["empty"] == set()
    assert analyzer.used_strings["empty"] == set()


def test_string_usage_analyzer_traverses_condition_quantifier_nodes() -> None:
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.defined_strings["manual"] = {"$a", "$b"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    analyzer.visit(
        ForExpression(
            quantifier=StringCount("$b"),
            variable="i",
            iterable=SetExpression([IntegerLiteral(1)]),
            body=StringIdentifier("$a"),
        )
    )
    assert analyzer.used_strings["manual"] == {"$a", "$b"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_for_of_expression(ForOfExpression(StringCount("$b"), "$a"))
    assert analyzer.used_strings["manual"] == {"$a", "$b"}


@pytest.mark.parametrize(
    "condition",
    [
        StringIdentifier("#a"),
        StringCount("#a"),
        StringOffset("@a"),
        StringLength("!a"),
        StringWildcard("#a*"),
    ],
)
def test_string_usage_analyzer_rejects_embedded_string_reference_operators(
    condition: Expression,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_reference",
                strings=[PlainString(identifier="$a", value="value")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(ValueError, match="Invalid string reference"):
        StringUsageAnalyzer().analyze(ast)


def test_string_usage_analyzer_counts_string_literals_in_condition_sets() -> None:
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.defined_strings["manual"] = {"$a"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    analyzer.visit_of_expression(
        OfExpression(
            "any",
            SetExpression([StringLiteral("$a"), StringLiteral("$missing")]),
        )
    )
    assert analyzer.used_strings["manual"] == {"$a", "$missing"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_for_of_expression(
        ForOfExpression(
            "any",
            SetExpression([StringLiteral("$a"), StringLiteral("$missing")]),
            condition=None,
        )
    )
    assert analyzer.used_strings["manual"] == {"$a", "$missing"}


@pytest.mark.parametrize(
    "string_set",
    [
        StringLiteral(cast(Any, False)),
        StringIdentifier(cast(Any, False)),
        StringWildcard(cast(Any, False)),
    ],
)
def test_string_usage_analyzer_rejects_non_string_string_set_values(string_set: Any) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                "invalid_string_set",
                strings=[PlainString("$a", value="x")],
                condition=OfExpression("any", string_set),
            )
        ]
    )

    with pytest.raises(TypeError, match="String reference must be a string"):
        StringUsageAnalyzer().analyze(ast)


def test_string_usage_analyzer_respects_yarax_with_local_shadowing() -> None:
    ast = parse_yara_source("""
rule shadowed_string {
    strings:
        $a = "value"
    condition:
        with $a = 1: $a > 0
}

rule declaration_value_uses_string {
    strings:
        $a = "value"
    condition:
        with local = $a: local
}
""")

    results = StringUsageAnalyzer().analyze(ast)

    assert results["shadowed_string"]["used"] == []
    assert results["shadowed_string"]["unused"] == ["$a"]
    assert results["declaration_value_uses_string"]["used"] == ["$a"]
    assert results["declaration_value_uses_string"]["unused"] == []


def test_string_usage_analyzer_resolves_yarax_string_locals_in_string_sets() -> None:
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

    result = StringUsageAnalyzer().analyze(ast)["local_string_set"]

    assert result["used"] == ["$a"]
    assert result["unused"] == []
    assert result["undefined"] == []


def test_string_usage_analyzer_counts_parenthesized_string_literal_sets() -> None:
    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.defined_strings["manual"] = {"$a", "$missing"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    analyzer.visit_of_expression(
        OfExpression(
            "any",
            ParenthesesExpression(SetExpression([StringLiteral("$a"), StringLiteral("$missing")])),
        )
    )
    assert analyzer.used_strings["manual"] == {"$a", "$missing"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_for_of_expression(
        ForOfExpression(
            "any",
            ParenthesesExpression(SetExpression([StringLiteral("$a"), StringLiteral("$missing")])),
            condition=None,
        )
    )
    assert analyzer.used_strings["manual"] == {"$a", "$missing"}


def test_string_usage_analyzer_expands_wildcard_string_sets() -> None:
    ast = Parser().parse("""
rule wildcard_usage {
    strings:
        $a1 = "aaaa"
        $a2 = "bbbb"
        $b = "cccc"
    condition:
        any of ($a*)
}
""")

    result = StringUsageAnalyzer().analyze(ast)["wildcard_usage"]

    assert result["used"] == ["$a1", "$a2"]
    assert result["unused"] == ["$b"]
    assert result["undefined"] == []

    analyzer = StringUsageAnalyzer()
    analyzer.current_rule = "manual"
    analyzer.defined_strings["manual"] = {"$api1", "$api2", "$other"}
    analyzer.used_strings["manual"] = set()
    analyzer.in_condition = True

    analyzer.visit_of_expression(OfExpression("any", StringWildcard("$api*")))

    assert analyzer.used_strings["manual"] == {"$api1", "$api2"}


def test_string_usage_analyzer_ignores_rule_wildcard_sets() -> None:
    ast = Parser().parse("""
rule alpha_one {
    condition:
        true
}

rule alpha_two {
    condition:
        true
}

rule holder {
    strings:
        $alpha_local = "needle"
    condition:
        any of (alpha*)
}
""")

    result = StringUsageAnalyzer().analyze(ast)["holder"]

    assert result["used"] == []
    assert result["unused"] == ["$alpha_local"]
    assert result["undefined"] == []


def test_string_usage_analyzer_named_wildcard_ignores_anonymous_internal_ids() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_usage",
                strings=[
                    PlainString(identifier="$alpha", value="a"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                ],
                condition=StringWildcard("$a*"),
            )
        ]
    )

    result = StringUsageAnalyzer().analyze(ast)["anonymous_usage"]

    assert result["used"] == ["$alpha"]
    assert result["unused"] == ["$anon_1"]
    assert result["undefined"] == []


def test_string_usage_analyzer_global_wildcard_keeps_anonymous_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_global_usage",
                strings=[
                    PlainString(identifier="$alpha", value="a"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                ],
                condition=StringWildcard("$*"),
            )
        ]
    )

    result = StringUsageAnalyzer().analyze(ast)["anonymous_global_usage"]

    assert result["used"] == ["$alpha", "$anon_1"]
    assert result["unused"] == []
    assert result["undefined"] == []


def test_string_usage_analyzer_partial_branch_paths() -> None:
    analyzer = StringUsageAnalyzer()

    analyzer.current_rule = None
    analyzer.in_condition = False
    analyzer.visit_string_offset(StringOffset("$x"))
    analyzer.visit_string_length(StringLength("$x"))
    analyzer.visit_for_of_expression(ForOfExpression("any", Identifier("them"), condition=None))

    analyzer.current_rule = "branchy"
    analyzer.defined_strings["branchy"] = {"$a"}
    analyzer.used_strings["branchy"] = set()
    analyzer.in_condition = True
    analyzer.visit_for_of_expression(ForOfExpression("all", Identifier("them"), condition=None))

    assert analyzer.used_strings["branchy"] == {"$a"}
