"""Additional real coverage for semantic_validator_strings."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.types.semantic_validator import SemanticValidator
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_strings import (
    StringIdentifierValidator,
    StringModifierApplicabilityValidator,
)


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


def test_string_modifier_applicability_validator_rejects_regex_only_on_non_regex() -> None:
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="bad_modifiers",
        strings=[
            PlainString(
                identifier="$plain",
                value="abc",
                modifiers=[StringModifier.from_name_value("dotall")],
            ),
            HexString(
                identifier="$hex",
                tokens=[HexByte(value=0x41)],
                modifiers=[StringModifier.from_name_value("multiline")],
            ),
            RegexString(
                identifier="$regex",
                regex="abc.*",
                modifiers=[StringModifier.from_name_value("dotall")],
            ),
        ],
    )

    validator.visit_rule(rule)

    assert result.is_valid is False
    assert len(result.errors) == 2
    assert any(
        "modifier 'dotall' used on plain string '$plain'" in e.message for e in result.errors
    )
    assert any("modifier 'multiline' used on hex string '$hex'" in e.message for e in result.errors)


def test_semantic_validator_reports_regex_only_modifiers_on_plain_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_plain",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("dotall")],
                    )
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any("Regex-only modifier 'dotall'" in error.message for error in result.errors)
