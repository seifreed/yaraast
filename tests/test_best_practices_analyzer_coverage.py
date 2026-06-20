"""Coverage for the BestPracticesAnalyzer warning paths.

Drives the analyzer over rules that trigger style/optimization/structure
suggestions, plus duplicate rule and string identifiers built directly (the
parser rejects duplicates, so those branches need constructed ASTs).
"""

from __future__ import annotations

import pytest

from yaraast.analysis.best_practices import BestPracticesAnalyzer
from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.rules import Rule
from yaraast.ast.strings import PlainString
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.parser import YaraXParser

WARNING_SOURCE = r"""
rule ab {
    condition:
        true
}

rule bad123name {
    strings:
        $a = "ab"
        $star = "ab*cd"
        $hex = { ?? ?? ?? 4D }
        $re = /a/
    condition:
        $a and $star and $hex and $re
}

rule clean_rule {
    condition:
        filesize > 0
}

rule string_set_usage {
    strings:
        $aa = "alpha"
        $ab = "beta"
        $c = "gamma"
    condition:
        any of them and any of ($a*) and 1 of ($aa, $ab) and 2 of ($zzz*) and
        #aa > 0 and @aa[1] > 0 and !ab > 0 and $aa at 0 and $c in (0..filesize) and
        for any i in (1..3) : ( i > 0 ) and for all of ($a*) : ( $ )
}
"""


def test_best_practices_emits_style_and_optimization_suggestions() -> None:
    report = BestPracticesAnalyzer().analyze(parse_yara_source(WARNING_SOURCE))

    assert report.suggestions
    assert report.statistics["total_rules"] == 4
    # Short rule name, bad rule name, short/pattern strings -> warnings and infos.
    assert report.get_by_severity("warning")
    assert report.get_by_severity("info")
    assert all(isinstance(s.format(), str) for s in report.suggestions)


def test_duplicate_rule_names_reported() -> None:
    ast = YaraFile(
        rules=[
            Rule(name="dup", condition=BooleanLiteral(value=True)),
            Rule(name="dup", condition=BooleanLiteral(value=True)),
        ]
    )
    report = BestPracticesAnalyzer().analyze(ast)
    assert any("Duplicate rule name" in s.message for s in report.suggestions)


def test_duplicate_string_identifiers_reported() -> None:
    rule = Rule(
        name="dupstrings",
        strings=[
            PlainString(identifier="$a", value="alpha"),
            PlainString(identifier="$a", value="beta"),
        ],
        condition=BooleanLiteral(value=True),
    )
    report = BestPracticesAnalyzer().analyze(YaraFile(rules=[rule]))
    assert any("Duplicate string identifier" in s.message for s in report.suggestions)


@pytest.mark.parametrize(
    "condition",
    [
        "[x for x in (1, 2, 3) if x > 0]",
        "{k: v for k, v in pairs}",
        "lambda x: x + 1",
    ],
)
def test_best_practices_visits_yarax_expressions(condition: str) -> None:
    expr = YaraXParser(condition).parse_expression()
    report = BestPracticesAnalyzer().analyze(YaraFile(rules=[Rule(name="yx", condition=expr)]))
    assert report is not None
