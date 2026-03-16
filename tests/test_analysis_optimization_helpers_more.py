"""Additional real tests for optimization helper functions."""

from __future__ import annotations

from yaraast.analysis.optimization_helpers import (
    extract_comparison,
    from,
    get_condition_pattern,
    get_hex_prefix,
    get_variable_name,
    group_duplicate_strings,
    group_rules_by_pattern,
    hex_to_string,
    import,
    should_be_hex,
    yaraast.analysis.optimization_grouping_helpers,
)
from yaraast.ast.conditions import OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    Identifier,
    IntegerLiteral,
    StringCount,
    StringLiteral,
)
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, HexWildcard, PlainString, RegexString


def test_should_be_hex_and_hex_helpers() -> None:
    assert should_be_hex(PlainString(identifier="$a", value="\x01\x02A\x03")) is True
    assert should_be_hex(PlainString(identifier="$b", value="abcdef")) is False

    short_prefix = HexString(identifier="$h1", tokens=[HexByte(0xAA), HexByte(0xBB), HexByte(0xCC)])
    assert get_hex_prefix(short_prefix, 3) is None

    broken_prefix = HexString(
        identifier="$hbreak",
        tokens=[HexByte(0xAA), HexByte(0xBB), HexWildcard(), HexByte(0xCC), HexByte(0xDD)],
    )
    assert get_hex_prefix(broken_prefix, 5) is None

    full_prefix = HexString(
        identifier="$h2",
        tokens=[HexByte(0xAA), HexByte(0xBB), HexByte(0xCC), HexByte(0xDD), HexByte("EE")],
    )
    assert get_hex_prefix(full_prefix, 5) == (0xAA, 0xBB, 0xCC, 0xDD, "EE")
    assert hex_to_string(full_prefix) == "AA BB CC DD EE"

    mixed = HexString(identifier="$h3", tokens=[HexByte(0x10), object()])  # type: ignore[list-item]
    assert hex_to_string(mixed) == "10 ??"


def test_extract_comparison_and_variable_name_paths() -> None:
    cmp_expr = BinaryExpression(StringCount("a"), ">=", IntegerLiteral(3))
    assert extract_comparison(cmp_expr) == {"var": "#a", "op": ">=", "value": 3}

    non_cmp = BinaryExpression(Identifier("x"), "!=", IntegerLiteral(3))
    assert extract_comparison(non_cmp) is None

    no_int_rhs = BinaryExpression(Identifier("x"), ">", StringLiteral("3"))
    assert extract_comparison(no_int_rhs) is None

    assert get_variable_name(Identifier("x")) == "x"
    assert get_variable_name(StringCount("abc")) == "#abc"
    assert get_variable_name(IntegerLiteral(1)) is None


def test_condition_pattern_duplicate_strings_and_rule_grouping() -> None:
    assert (
        get_condition_pattern(BinaryExpression(IntegerLiteral(1), "and", IntegerLiteral(2)))
        == "and(...)"
    )
    assert get_condition_pattern(OfExpression(Identifier("any"), Identifier("them"))) == "of(...)"
    assert get_condition_pattern(IntegerLiteral(7)) == "IntegerLiteral"

    rules = [
        Rule(
            name="r1",
            strings=[PlainString(identifier="$a", value="same")],
            condition=Identifier("flag"),
        ),
        Rule(
            name="r2",
            strings=[PlainString(identifier="$b", value="same")],
            condition=Identifier("flag"),
        ),
        Rule(
            name="r3",
            strings=[
                HexString(
                    identifier="$c",
                    tokens=[HexByte(0xAA), HexByte(0xBB), HexByte(0xCC), HexByte(0xDD)],
                )
            ],
            condition=None,
        ),
        Rule(
            name="r4",
            strings=[
                HexString(
                    identifier="$d",
                    tokens=[HexByte(0xAA), HexByte(0xBB), HexByte(0xCC), HexByte(0xDD)],
                )
            ],
            condition=None,
        ),
        Rule(
            name="r5",
            strings=[RegexString(identifier="$re", regex="abc.*")],
            condition=Identifier("other"),
        ),
    ]

    duplicates = group_duplicate_strings(rules)
    assert duplicates[("plain", "same")] == ["r1", "r2"]
    assert duplicates[("hex", "AA BB CC DD")] == ["r3", "r4"]
    assert all("r5" not in names for names in duplicates.values())

    grouped = group_rules_by_pattern(rules, get_condition_pattern)
    assert grouped[(1, "Identifier")] == ["r1", "r2", "r5"]
    assert grouped[(1, None)] == ["r3", "r4"]
