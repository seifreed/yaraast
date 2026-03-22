"""Additional real coverage for semantic_validator_strings."""

from __future__ import annotations

from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_strings import StringIdentifierValidator


def test_string_identifier_validator_covers_plain_hex_regex_and_empty_id() -> None:
    result = ValidationResult()
    validator = StringIdentifierValidator(result)

    rule = Rule(
        name="dup_rule",
        strings=[
            PlainString(identifier="$a", value="one"),
            HexString(identifier="$a", tokens=[HexByte(value=0x41)]),
            RegexString(identifier="$", regex="ab+"),
            RegexString(identifier="$b", regex="cd+"),
        ],
    )

    validator.visit_rule(rule)

    assert result.is_valid is False
    assert len(result.errors) == 2
    assert any("Duplicate string identifier '$a'" in e.message for e in result.errors)
    assert any("Invalid empty string identifier '$'" in e.message for e in result.errors)
    assert validator.current_rule_strings == {"$a", "$b"}
