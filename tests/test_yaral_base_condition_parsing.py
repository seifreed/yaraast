"""Coverage for the base YARA-L condition parser.

Parses YARA-L rules whose conditions exercise the comparison-value, regex,
arithmetic, null-check, n-of and field-reference branches in
``yaraast.yaral._parsing_conditions``.
"""

from __future__ import annotations

import pytest

from yaraast.yaral.parser import YaraLParser


def _parse_condition(condition: str) -> object:
    source = (
        "rule r {\n"
        "  events:\n"
        '    $e.metadata.event_type = "LOGIN"\n'
        "  condition:\n"
        f"    {condition}\n"
        "}"
    )
    return YaraLParser(source).parse()


@pytest.mark.parametrize(
    "condition",
    [
        "$e.field = true",
        "$e.field = false",
        "$e.field = 5",
        "$e.field = 3.14",
        '$e.field = "value"',
        "$e.field = /abc/i",
        "$e.field = /abc/ nocase",
        "$e.field = /abc/im",
        "($e.field) = 1",
        "$e.field is null",
        "$e.field is not null",
        "$e.count + 1 > 2",
        "$e.x - 2 < 10",
        "$e.x * 2 = 4",
        "#e > 2",
        "2 of ($e1, $e2)",
        '$e.principal.ip = "1.2.3.4"',
        '$e.udm["key"] = 1',
        "$e.list[0] = 1",
        "$e.a = $e.b",
        "not ($e.a = 1) and ($e.b = 2 or $e.c = 3)",
    ],
)
def test_parse_yaral_condition_forms(condition: str) -> None:
    parsed = _parse_condition(condition)
    assert parsed.rules


def test_unexpected_comparison_value_raises() -> None:
    with pytest.raises(Exception, match="Expected value after comparison operator"):
        _parse_condition("$e.field = )")
