from __future__ import annotations

from yaraast.analysis.string_usage import StringUsageAnalyzer
from yaraast.ast.conditions import AtExpression, ForOfExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    IntegerLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser import Parser


def test_string_usage_analyzer_covers_offset_length_at_in_forof_and_of() -> None:
    ast = Parser().parse(
        """
rule advanced {
    strings:
        $a = "abc"
        $b = "def"
        $c = "ghi"
    condition:
        #a > 0 and @b[1] > 0 and !c[1] > 0 and $a at 0 and $b in (0..filesize) and all of them
}
"""
    )
    analyzer = StringUsageAnalyzer()
    results = analyzer.analyze(ast)

    used = set(results["advanced"]["used"])
    assert {"$a", "$b", "$c"} <= used
    assert results["advanced"]["unused"] == []
    assert analyzer.get_unused_strings() == {}
    assert analyzer.get_undefined_strings() == {}


def test_string_usage_analyzer_getters_and_direct_visitor_paths() -> None:
    analyzer = StringUsageAnalyzer()
    ast = Parser().parse(
        """
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
"""
    )
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
    analyzer.visit_for_of_expression(
        ForOfExpression("all", Identifier("them"), condition=StringIdentifier("$a")),
    )
    analyzer.visit_of_expression(OfExpression(IntegerLiteral(1), Identifier("them")))

    assert analyzer.used_strings["manual"] == {"$a", "$b"}


def test_string_usage_analyzer_visit_rule_without_strings_or_condition() -> None:
    analyzer = StringUsageAnalyzer()
    rule = Rule(name="empty", strings=[], condition=None)
    analyzer.visit_rule(rule)
    assert analyzer.defined_strings["empty"] == set()
    assert analyzer.used_strings["empty"] == set()


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
