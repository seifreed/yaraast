"""Additional real coverage for semantic_validator_strings."""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import BooleanLiteral
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.parser import Parser
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


def test_semantic_validator_rejects_empty_text_and_hex_strings() -> None:
    ast = Parser().parse("""
        rule empty_strings {
            strings:
                $text = ""
                $hex = { }
            condition:
                any of them
        }
        """)

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any("Empty text string '$text'" in message for message in messages)
    assert any("Empty hex string '$hex'" in message for message in messages)


def test_semantic_validator_rejects_invalid_string_modifier_compatibility() -> None:
    ast = Parser().parse("""
        rule invalid_modifiers {
            strings:
                $hex = { 41 } wide
                $regex = /abc/ base64
                $combo1 = "abc" base64 nocase
                $combo2 = "abc" base64 fullword
                $combo3 = "abc" xor nocase
                $badalpha = "abc" base64("abc")
                $badxor = "abc" xor(0x100)
                $badrange = "abc" xor(5-1)
            condition:
                any of them
        }
        """)

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any("modifier 'wide' used on hex string '$hex'" in message for message in messages)
    assert any("modifier 'base64' used on regex string '$regex'" in message for message in messages)
    assert any(
        "modifier 'nocase' cannot be combined with 'base64'" in message for message in messages
    )
    assert any(
        "modifier 'fullword' cannot be combined with 'base64'" in message for message in messages
    )
    assert any("modifier 'nocase' cannot be combined with 'xor'" in message for message in messages)
    assert any(
        "base64 alphabet for string '$badalpha' must be 64 bytes" in message for message in messages
    )
    assert any(
        "xor key for string '$badxor' must be between 0 and 255" in message for message in messages
    )
    assert any(
        "xor range for string '$badrange' must have a lower bound no greater than the upper bound"
        in message
        for message in messages
    )


def test_semantic_validator_reports_unreferenced_string_definitions() -> None:
    ast = Parser().parse("""
        rule unreferenced_string {
            strings:
                $a = "abc"
                $b = "def"
            condition:
                $a
        }
        """)

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(
        "Unreferenced string '$b' in rule 'unreferenced_string'" in message for message in messages
    )


def test_semantic_validator_counts_string_sets_as_string_references() -> None:
    ast = Parser().parse("""
        rule them_reference {
            strings:
                $a = "abc"
                $b = "def"
            condition:
                any of them
        }

        rule wildcard_reference {
            strings:
                $a = "abc"
                $ab = "def"
            condition:
                any of ($a*)
        }

        rule for_of_reference {
            strings:
                $a = "abc"
                $b = "def"
            condition:
                for any of ($a, $b) : ( # > 0 )
        }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid is True
    assert result.errors == []
