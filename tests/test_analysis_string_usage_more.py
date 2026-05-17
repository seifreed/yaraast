from __future__ import annotations

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
    Identifier,
    IntegerLiteral,
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
    analyzer.visit_of_expression(OfExpression(IntegerLiteral(1), Identifier("them")))

    assert analyzer.used_strings["manual"] == {"$a", "$b"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_for_of_expression(ForOfExpression("all", "them", condition=None))
    assert analyzer.used_strings["manual"] == {"$a", "$b"}

    analyzer.used_strings["manual"] = set()
    analyzer.visit_of_expression(OfExpression("any", ["$a", "$b"]))
    assert analyzer.used_strings["manual"] == {"$a", "$b"}


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
