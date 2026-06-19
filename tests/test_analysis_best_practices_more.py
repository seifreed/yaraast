from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.analysis.best_practices import AnalysisReport, BestPracticesAnalyzer
from yaraast.analysis.best_practices_helpers import get_hex_prefix
from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Expression,
    Identifier,
    IntegerLiteral,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, HexWildcard, PlainString, RegexString
from yaraast.parser import Parser
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    LambdaExpression,
    ListExpression,
    WithDeclaration,
    WithStatement,
)


def test_best_practices_report_helpers_and_integration_paths() -> None:
    report = AnalysisReport()
    report.add_suggestion("r1", "style", "info", "message", "line 1")
    report.add_suggestion("r2", "structure", "warning", "warn")
    report.add_suggestion("r3", "optimization", "error", "err")
    assert len(report.get_by_severity("info")) == 1
    assert len([s for s in report.suggestions if s.category == "style"]) == 1
    assert any(s.severity in ("warning", "error") for s in report.suggestions)
    assert report.suggestions[0].format() == "i [style] r1 (line 1): message"

    ast = Parser().parse(r"""
rule bad1 {
    strings:
        $1 = "ab"
        $a = "ab"
        $b = "a*b"
        $aa = "zzz"
        $ab = "zzzz"
        $dup = { 01 ?? ?? ?? }
        $regex = /(.+)+a.b/
    condition:
        $a
}

rule bad1_extra {
    condition:
        true
}

rule pe_only {
    condition:
        pe.is_pe
}
""")
    ast.rules[1].name = "bad1"
    ast.rules[0].strings.append(PlainString(identifier="$dup", value="duplicate"))
    analyzer = BestPracticesAnalyzer()
    result = analyzer.analyze(ast)

    messages = [s.message for s in result.suggestions]
    assert any("Duplicate rule name" in m for m in messages)
    assert any("Rule name should start with letter" in m for m in messages)
    assert any("should follow $name convention" in m for m in messages)
    assert any("might cause false positives" in m for m in messages)
    assert any("consider regex?" in m for m in messages)
    assert any("many wildcards" in m for m in messages)
    assert any("unescaped dots" in m for m in messages)
    assert any("catastrophic backtracking" in m for m in messages)
    assert any("Duplicate string identifier '$dup'" in m for m in messages)
    assert any("Similar string names" in m for m in messages)
    assert any("defined but never used" in m for m in messages)
    assert any("Rule has no strings defined" in m for m in messages)
    assert result.statistics == {"total_rules": 3, "total_imports": 0}


def test_best_practices_analyzes_falsy_present_rule_condition() -> None:
    class FalsyStringLiteral(StringLiteral):
        def __bool__(self) -> bool:
            return False

    ast = YaraFile(rules=[Rule(name="falsy_condition", condition=FalsyStringLiteral("flag"))])

    report = BestPracticesAnalyzer().analyze(ast)

    assert any(
        "Rule has no strings defined" in suggestion.message for suggestion in report.suggestions
    )


def test_best_practices_analyzer_handles_byte_plain_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="byte_rule",
                strings=[PlainString(identifier="$b", value=b"a*b")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    messages = [suggestion.message for suggestion in report.suggestions]

    assert any("Short string" in message for message in messages)
    assert any("consider regex?" in message for message in messages)


def test_best_practices_short_string_uses_utf8_byte_length() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="unicode_rule",
                strings=[
                    PlainString(identifier="$short", value="á", modifiers=[]),
                    PlainString(identifier="$long", value="éé", modifiers=[]),
                ],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    messages = [suggestion.message for suggestion in report.suggestions]

    assert any("Short string '$short' (2 bytes)" in message for message in messages)
    assert not any("Short string '$long'" in message for message in messages)


def test_best_practices_treats_string_count_as_string_usage() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="count_rule",
                strings=[PlainString(identifier="$a", value="value")],
                condition=BinaryExpression(StringCount("$a"), ">", IntegerLiteral(0)),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    assert not any(
        "String '$a' is defined but never used" in suggestion.message
        for suggestion in report.suggestions
    )


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
def test_best_practices_rejects_embedded_string_reference_operators(
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
        BestPracticesAnalyzer().analyze(ast)


def test_best_practices_treats_condition_string_set_forms_as_usage() -> None:
    ast = Parser().parse("""
rule set_usage {
    strings:
        $api1 = "aaaa"
        $api2 = "bbbb"
        $pos = "cccc"
        $range = "dddd"
    condition:
        any of ($api*) and $pos at 0 and $range in (0..filesize)
}

rule them_usage {
    strings:
        $one = "eeee"
        $two = "ffff"
    condition:
        all of them
}
""")

    report = BestPracticesAnalyzer().analyze(ast)

    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]
    assert unused_messages == []


@pytest.mark.parametrize(
    "string_set",
    [
        Identifier("$a"),
        SetExpression([Identifier("$a")]),
    ],
)
def test_best_practices_treats_identifier_string_set_items_as_usage(
    string_set: Any,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="identifier_string_set",
                strings=[
                    PlainString(identifier="$a", value="needle"),
                    PlainString(identifier="$unused", value="unused"),
                ],
                condition=OfExpression("any", string_set),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert "String '$a' is defined but never used in condition" not in unused_messages
    assert "String '$unused' is defined but never used in condition" in unused_messages


def test_best_practices_keeps_rule_wildcard_sets_out_of_string_usage() -> None:
    ast = Parser().parse("""
rule alpha_one {
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

    report = BestPracticesAnalyzer().analyze(ast)

    assert any(
        "String '$alpha_local' is defined but never used" in suggestion.message
        for suggestion in report.suggestions
    )


@pytest.mark.parametrize(
    "string_set",
    [
        StringLiteral(cast(Any, False)),
        StringIdentifier(cast(Any, False)),
        StringWildcard(cast(Any, False)),
    ],
)
def test_best_practices_rejects_non_string_string_set_values(string_set: Any) -> None:
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
        BestPracticesAnalyzer().analyze(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            InExpression(
                cast(Any, False),
                RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
            ),
            "String reference must be a string",
        ),
        (InExpression("$a", cast(Any, False)), "'in' range must be an AST node"),
    ],
)
def test_best_practices_rejects_invalid_in_expression_fields(
    condition: Any,
    message: str,
) -> None:
    ast = YaraFile(
        rules=[
            Rule(
                "invalid_in_expression",
                strings=[PlainString("$a", value="x")],
                condition=condition,
            )
        ]
    )

    with pytest.raises(TypeError, match=message):
        BestPracticesAnalyzer().analyze(ast)


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(rules=[Rule(cast(Any, False), condition=BooleanLiteral(True))]),
            "Rule name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_string_identifier",
                        strings=[PlainString(cast(Any, False), value="value")],
                        condition=BooleanLiteral(True),
                    )
                ]
            ),
            "String identifier must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_plain_value",
                        strings=[PlainString("$a", value=cast(Any, False))],
                        condition=StringIdentifier("$a"),
                    )
                ]
            ),
            "Plain string value must be text or bytes",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "invalid_regex_value",
                        strings=[RegexString("$a", regex=cast(Any, False))],
                        condition=StringIdentifier("$a"),
                    )
                ]
            ),
            "Regex value must be a string",
        ),
    ],
)
def test_best_practices_rejects_invalid_rule_and_string_fields(
    ast: YaraFile,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        BestPracticesAnalyzer().analyze(ast)


@pytest.mark.parametrize(
    "condition",
    [
        ForExpression(
            quantifier="any",
            variable=cast(Any, False),
            iterable=SetExpression([IntegerLiteral(1)]),
            body=BooleanLiteral(True),
        ),
        WithStatement(
            declarations=[WithDeclaration(cast(Any, False), IntegerLiteral(1))],
            body=BooleanLiteral(True),
        ),
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable=cast(Any, False),
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        DictComprehension(
            key_expression=Identifier("k"),
            value_expression=Identifier("v"),
            key_variable=cast(Any, False),
            value_variable="v",
            iterable=ListExpression([IntegerLiteral(1)]),
        ),
        LambdaExpression(parameters=[cast(Any, False)], body=BooleanLiteral(True)),
    ],
)
def test_best_practices_rejects_invalid_local_variable_names(condition: Any) -> None:
    ast = YaraFile(rules=[Rule("invalid_local", condition=condition)])

    with pytest.raises(TypeError, match="Local variable name must be a string"):
        BestPracticesAnalyzer().analyze(ast)


def test_best_practices_respects_yarax_with_local_string_shadowing() -> None:
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

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert "String '$a' is defined but never used in condition" in unused_messages
    assert len(unused_messages) == 1


def test_best_practices_respects_yarax_with_local_string_count_shadowing() -> None:
    ast = parse_yara_source("""
rule shadowed_count {
    strings:
        $a = "value"
    condition:
        with $a = 1: #a > 0
}
""")

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert unused_messages == ["String '$a' is defined but never used in condition"]


def test_best_practices_resolves_yarax_string_locals_in_string_sets() -> None:
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

    report = BestPracticesAnalyzer().analyze(ast)

    assert not any(
        "String '$a' is defined but never used" in suggestion.message
        for suggestion in report.suggestions
    )


def test_best_practices_named_wildcard_ignores_anonymous_internal_ids() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_usage",
                strings=[
                    PlainString(identifier="$alpha", value="value"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                ],
                condition=StringWildcard("$a*"),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)
    unused_messages = [
        suggestion.message
        for suggestion in report.suggestions
        if "defined but never used" in suggestion.message
    ]

    assert "String '$anon_1' is defined but never used in condition" in unused_messages
    assert "String '$alpha' is defined but never used in condition" not in unused_messages


def test_best_practices_global_wildcard_counts_anonymous_strings_as_used() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_global_usage",
                strings=[
                    PlainString(identifier="$alpha", value="value"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                ],
                condition=StringWildcard("$*"),
            )
        ]
    )

    report = BestPracticesAnalyzer().analyze(ast)

    assert not any(
        "defined but never used" in suggestion.message for suggestion in report.suggestions
    )


def test_best_practices_global_hex_patterns_and_helper_paths() -> None:
    ast = Parser().parse("""
rule hx1 {
    meta:
        author = "x"
    strings:
        $a = { 4D 5A 90 00 }
    condition:
        $a
}

rule hx2 {
    meta:
        author = "x"
    strings:
        $b = { 4D 5A 90 FF }
    condition:
        $b
}

rule bare {
    condition:
        true
}
""")
    analyzer = BestPracticesAnalyzer()
    analyzer.analyze(ast)

    analyzer.report = AnalysisReport()
    analyzer._hex_patterns = [
        (
            "$a",
            HexString(
                "$a",
                tokens=[HexByte(0x4D), HexByte(0x5A), HexByte(0x90), HexByte(0x00), HexByte(0xAA)],
            ),
        ),
        (
            "$b",
            HexString(
                "$b",
                tokens=[HexByte(0x4D), HexByte(0x5A), HexByte(0x90), HexByte(0x00), HexByte(0xBB)],
            ),
        ),
    ]
    analyzer._analyze_global_patterns()
    assert any(
        s.rule_name == "global" and "Similar hex patterns" in s.message
        for s in analyzer.report.suggestions
    )

    prefix = get_hex_prefix(
        HexString("$h", tokens=[HexByte(0x4D), HexWildcard(), HexByte(0x5A)]),
        4,
    )
    assert prefix == (0x4D, None, 0x5A)

    short_name_ast = Parser().parse("""
rule ab {
    meta:
        author = "x"
    strings:
        $a = "abcd"
    condition:
        $a
}
""")
    short_report = BestPracticesAnalyzer().analyze(short_name_ast)
    assert any("more descriptive rule names" in s.message for s in short_report.suggestions)

    assert analyzer._levenshtein_distance("abc", "abc") == 0
    assert analyzer._levenshtein_distance("abc", "ab") == 1
    assert analyzer._levenshtein_distance("abc", "") == 3


def test_best_practices_global_hex_patterns_include_all_rules() -> None:
    ast = Parser().parse("""
rule hx1 {
    strings:
        $a = { 4D 5A 90 00 AA }
    condition:
        $a
}

rule hx2 {
    strings:
        $b = { 4D 5A 90 00 BB }
    condition:
        $b
}
""")

    report = BestPracticesAnalyzer().analyze(ast)

    assert any(
        suggestion.rule_name == "global" and "Similar hex patterns: $a, $b" in suggestion.message
        for suggestion in report.suggestions
    )
