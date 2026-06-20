"""Coverage for ComplexityAnalyzer string-usage helpers and YARA-X visitors.

Drives the analyzer over a standard rule that uses wildcards, string sets and
count/offset/length references, plus YARA-X expression conditions
(comprehensions, tuples, lists, dicts, slices, lambdas, match) that exercise the
per-node-type visitor methods.
"""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.rules import Rule
from yaraast.metrics.complexity import ComplexityAnalyzer
from yaraast.parser.source import parse_yara_source
from yaraast.yarax.parser import YaraXParser

STANDARD_RULE = """rule strings_usage {
    strings:
        $a1 = "alpha"
        $a2 = "beta"
        $b = "gamma"
    condition:
        any of ($a*) and all of them and 2 of ($a1, $a2) and
        #a1 > 0 and @a1[1] > 0 and !b > 0 and $a1 at 0
}"""


def test_analyze_standard_rule_string_usage() -> None:
    metrics = ComplexityAnalyzer().analyze(parse_yara_source(STANDARD_RULE))
    assert metrics.cyclomatic_complexity["strings_usage"] > 0


@pytest.mark.parametrize(
    "condition",
    [
        "[x for x in (1, 2, 3) if x > 0]",
        "{k: v for k, v in pairs}",
        "(1, 2, 3)",
        "(1, 2, 3)[0]",
        "[1, 2, 3]",
        '{"k": 1, "j": 2}',
        "arr[0:2:1]",
        "lambda x: x + 1",
        "match v { 1 => true, _ => false }",
    ],
)
def test_analyze_yarax_expression_conditions(condition: str) -> None:
    expr = YaraXParser(condition).parse_expression()
    rule = Rule(name="yarax_rule", condition=expr)
    metrics = ComplexityAnalyzer().analyze(YaraFile(rules=[rule]))
    assert "yarax_rule" in metrics.cyclomatic_complexity
