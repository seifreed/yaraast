"""Additional real coverage for semantic_validator_strings."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
    SetExpression,
    StringIdentifier,
    StringLiteral,
    StringWildcard,
)
from yaraast.ast.modifiers import StringModifier
from yaraast.ast.rules import Rule
from yaraast.ast.strings import HexByte, HexString, PlainString, RegexString
from yaraast.parser import Parser
from yaraast.types.semantic_validator import SemanticValidator
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_strings import (
    StringIdentifierValidator,
    StringModifierApplicabilityValidator,
    UndefinedStringDetector,
)
from yaraast.yarax.ast_nodes import WithDeclaration, WithStatement


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


def test_semantic_validator_reports_non_string_string_definition_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_string_identifier",
                strings=[PlainString(identifier=cast(Any, False), value="x")],
                condition=BooleanLiteral(value=True),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(error.message == "String identifier must be a string" for error in result.errors)


def test_string_identifier_validator_ignores_anonymous_internal_identifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="anonymous_collision",
                strings=[
                    PlainString(identifier="$anon_1", value="named"),
                    PlainString(identifier="$anon_1", value="anonymous", is_anonymous=True),
                    PlainString(identifier="$anon_1", value="anonymous2", is_anonymous=True),
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )
    result = ValidationResult()
    validator = StringIdentifierValidator(result)

    validator.visit_rule(ast.rules[0])

    assert result.errors == []
    assert validator.current_rule_strings == {"$anon_1"}


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


def test_string_modifier_applicability_validator_rejects_regex_multiline_modifier() -> None:
    result = ValidationResult()
    validator = StringModifierApplicabilityValidator(result)

    rule = Rule(
        name="bad_regex_multiline",
        strings=[
            RegexString(
                identifier="$named",
                regex="^line",
                modifiers=[StringModifier.from_name_value("multiline")],
            ),
            RegexString(identifier="$raw", regex="^raw", modifiers=["m"]),
        ],
        condition=BinaryExpression(StringIdentifier("$named"), "or", StringIdentifier("$raw")),
    )

    validator.visit_rule(rule)

    messages = [error.message for error in result.errors]
    assert any("Unsupported regex modifier 'multiline'" in message for message in messages)
    assert any("Unsupported regex modifier 'm'" in message for message in messages)


def test_semantic_validator_rejects_classic_unsupported_string_modifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_classic_modifiers",
                strings=[
                    PlainString(
                        identifier="$case",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("case")],
                    ),
                    PlainString(
                        identifier="$utf",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("utf16")],
                    ),
                    PlainString(identifier="$raw", value="abc", modifiers=["i"]),
                    RegexString(
                        identifier="$regex",
                        regex="abc",
                        modifiers=[StringModifier.from_name_value("utf8")],
                    ),
                ],
                condition=BinaryExpression(
                    BinaryExpression(StringIdentifier("$case"), "or", StringIdentifier("$utf")),
                    "or",
                    BinaryExpression(StringIdentifier("$raw"), "or", StringIdentifier("$regex")),
                ),
            )
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert any("Unsupported string modifier 'case'" in message for message in messages)
    assert any("Unsupported string modifier 'utf16'" in message for message in messages)
    assert any("Unsupported string modifier 'i'" in message for message in messages)
    assert any("Unsupported regex modifier 'utf8'" in message for message in messages)


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


def test_semantic_validator_respects_yarax_with_local_string_variables() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="local_string",
                strings=[],
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", StringLiteral("test"))],
                    body=BinaryExpression(
                        StringIdentifier("$x"),
                        "matches",
                        StringLiteral("^test$"),
                    ),
                ),
            ),
            Rule(
                name="shadowed_string",
                strings=[PlainString(identifier="$x", value="real")],
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", IntegerLiteral(1))],
                    body=BinaryExpression(
                        StringIdentifier("$x"),
                        "==",
                        IntegerLiteral(1),
                    ),
                ),
            ),
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert not any(
        "Undefined string '$x' in rule 'local_string'" in message for message in messages
    )
    assert any(
        "Unreferenced string '$x' in rule 'shadowed_string'" in message for message in messages
    )


def test_semantic_validator_resolves_yarax_string_locals_in_string_sets() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="local_string_set",
                strings=[
                    PlainString(identifier="$a", value="needle"),
                    PlainString(identifier="$x", value="shadowed"),
                ],
                condition=WithStatement(
                    declarations=[WithDeclaration("$x", StringLiteral("$a"))],
                    body=OfExpression("any", SetExpression([StringIdentifier("$x")])),
                ),
            )
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert not any(
        "Unreferenced string '$a' in rule 'local_string_set'" in message for message in messages
    )
    assert not any(
        "Undefined string '$a' in rule 'local_string_set'" in message for message in messages
    )
    assert any(
        "Unreferenced string '$x' in rule 'local_string_set'" in message for message in messages
    )


def test_semantic_validator_rejects_empty_text_and_hex_strings() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_strings",
                strings=[PlainString(identifier="$text", value="")],
                condition=StringIdentifier("$text"),
            ),
            Rule(
                name="empty_hex",
                strings=[HexString(identifier="$hex", tokens=[])],
                condition=StringIdentifier("$hex"),
            ),
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any("Empty text string '$text'" in message for message in messages)
    assert any("Empty hex string '$hex'" in message for message in messages)


def test_semantic_validator_rejects_invalid_string_modifier_compatibility() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_modifiers",
                strings=[
                    HexString(
                        identifier="$hex",
                        tokens=[HexByte(value=0x41)],
                        modifiers=[StringModifier.from_name_value("wide")],
                    ),
                    RegexString(
                        identifier="$regex",
                        regex="abc",
                        modifiers=[StringModifier.from_name_value("base64")],
                    ),
                    PlainString(
                        identifier="$combo1",
                        value="abc",
                        modifiers=[
                            StringModifier.from_name_value("base64"),
                            StringModifier.from_name_value("nocase"),
                        ],
                    ),
                    PlainString(
                        identifier="$combo2",
                        value="abc",
                        modifiers=[
                            StringModifier.from_name_value("base64"),
                            StringModifier.from_name_value("fullword"),
                        ],
                    ),
                    PlainString(
                        identifier="$combo3",
                        value="abc",
                        modifiers=[
                            StringModifier.from_name_value("xor"),
                            StringModifier.from_name_value("nocase"),
                        ],
                    ),
                    PlainString(
                        identifier="$badalpha",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("base64", "abc")],
                    ),
                    PlainString(
                        identifier="$badxor",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", 0x100)],
                    ),
                    PlainString(
                        identifier="$badrange",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", (5, 1))],
                    ),
                ],
                condition=StringIdentifier("$hex"),
            )
        ]
    )

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


def test_semantic_validator_rejects_duplicate_string_modifiers() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="duplicate_modifiers",
                strings=[
                    PlainString(
                        identifier="$plain",
                        value="abc",
                        modifiers=[
                            StringModifier.from_name_value("ascii"),
                            StringModifier.from_name_value("ascii"),
                        ],
                    ),
                    PlainString(
                        identifier="$xor",
                        value="abc",
                        modifiers=[
                            StringModifier.from_name_value("xor"),
                            StringModifier.from_name_value("xor", (1, 3)),
                        ],
                    ),
                    HexString(
                        identifier="$hex",
                        tokens=[HexByte(value=0x41)],
                        modifiers=[
                            StringModifier.from_name_value("private"),
                            StringModifier.from_name_value("private"),
                        ],
                    ),
                    RegexString(
                        identifier="$regex",
                        regex="abc",
                        modifiers=[
                            StringModifier.from_name_value("nocase"),
                            StringModifier.from_name_value("nocase"),
                        ],
                    ),
                ],
                condition=StringIdentifier("$plain"),
            )
        ]
    )

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(
        "Duplicate string modifier 'ascii' on string '$plain'" in message for message in messages
    )
    assert any(
        "Duplicate string modifier 'xor' on string '$xor'" in message for message in messages
    )
    assert any(
        "Duplicate string modifier 'private' on string '$hex'" in message for message in messages
    )
    assert any(
        "Duplicate string modifier 'nocase' on string '$regex'" in message for message in messages
    )


def test_semantic_validator_rejects_invalid_string_modifier_collections() -> None:
    invalid_modifiers: Any = False
    string = PlainString(identifier="$a", value="abc")
    string.modifiers = invalid_modifiers
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier_collection",
                strings=[string],
                condition=StringIdentifier("$a"),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(
        "String modifiers for string '$a' in rule 'bad_modifier_collection' must be a list or tuple"
        in error.message
        for error in result.errors
    )


def test_semantic_validator_rejects_invalid_string_modifier_items() -> None:
    class BadModifier:
        name = False

    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier_items",
                strings=[
                    PlainString(identifier="$a", value="abc", modifiers=[cast(Any, False)]),
                    RegexString(identifier="$b", regex="abc", modifiers=[BadModifier()]),
                ],
                condition=StringIdentifier("$a"),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert (
        sum(
            "String modifiers for string" in error.message
            and "must contain strings or StringModifier nodes" in error.message
            for error in result.errors
        )
        == 2
    )


def test_semantic_validator_rejects_boolean_xor_modifier_values() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_boolean_xor",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", True)],
                    )
                ],
                condition=BooleanLiteral(True),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is False
    assert any(
        "xor key for string '$a' must be between 0 and 255" in error.message
        for error in result.errors
    )


def test_semantic_validator_rejects_non_yara_xor_text_values() -> None:
    bad_values = ["a", "ff", "1f", "0X0A", "+10"]

    for index, value in enumerate(bad_values):
        string_id = f"$s{index}"
        ast = YaraFile(
            rules=[
                Rule(
                    name=f"bad_xor_text_{index}",
                    strings=[
                        PlainString(
                            identifier=string_id,
                            value="abc",
                            modifiers=[StringModifier.from_name_value("xor", value)],
                        )
                    ],
                    condition=StringIdentifier(string_id),
                )
            ]
        )

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert any("xor key for string" in error.message for error in result.errors)


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


def test_semantic_validator_counts_identifier_string_set_items_as_references() -> None:
    for string_set in (Identifier("$a"), SetExpression([Identifier("$a")])):
        ast = YaraFile(
            rules=[
                Rule(
                    name="identifier_string_set",
                    strings=[PlainString(identifier="$a", value="abc")],
                    condition=OfExpression("any", string_set),
                )
            ]
        )

        result = SemanticValidator().validate(ast)

        assert result.is_valid is True
        assert result.errors == []


def test_semantic_validator_does_not_shadow_explicit_string_ref_with_external() -> None:
    ast = Parser().parse("""
        rule explicit_string_ref {
            strings:
                $a = "a"
                $b = "b"
            condition:
                1 of ($a, $b)
        }
        """)

    result = SemanticValidator(externals={"b": 1}).validate(ast)

    assert result.is_valid is True, [error.message for error in result.errors]


def test_semantic_validator_rejects_invalid_external_of_quantifiers() -> None:
    ast = Parser().parse("""
        rule external_quantifier {
            strings:
                $a = "a"
                $b = "b"
            condition:
                q of ($a, $b)
        }
        """)

    for value in (-1, 1.0, "any"):
        result = SemanticValidator(externals={"q": value}).validate(ast)

        assert result.is_valid is False
        assert any("Invalid of quantifier external 'q'" in error.message for error in result.errors)


def test_semantic_validator_accepts_integer_external_of_quantifiers() -> None:
    ast = Parser().parse("""
        rule external_quantifier {
            strings:
                $a = "a"
                $b = "b"
            condition:
                q of ($a, $b)
        }
        """)

    for value in (0, False, 1):
        result = SemanticValidator(externals={"q": value}).validate(ast)

        assert result.is_valid is True, [error.message for error in result.errors]


def test_semantic_validator_rejects_invalid_external_for_of_quantifiers() -> None:
    ast = Parser().parse("""
        rule external_quantifier {
            strings:
                $a = "a"
                $b = "b"
            condition:
                for q of ($a, $b) : (true)
        }
        """)

    for value in (-1, 1.0, "any"):
        result = SemanticValidator(externals={"q": value}).validate(ast)

        assert result.is_valid is False
        assert any(
            "Invalid for...of quantifier external 'q'" in error.message for error in result.errors
        )


def test_semantic_validator_accepts_bare_string_literal_string_set_items() -> None:
    ast = YaraFile(
        rules=[
            Rule(
                name="literal_string_set_items",
                strings=[
                    PlainString(identifier="$a", value="abc"),
                    PlainString(identifier="$api_call", value="def"),
                ],
                condition=ForOfExpression(
                    "any",
                    SetExpression([StringLiteral("a"), StringLiteral("api*")]),
                    BooleanLiteral(True),
                ),
            )
        ]
    )

    result = SemanticValidator().validate(ast)

    assert result.is_valid is True
    assert result.errors == []


def test_semantic_validator_allows_implicit_current_string_position_checks() -> None:
    ast = Parser().parse("""
        rule implicit_current_string_at {
            strings:
                $a = "abc"
            condition:
                for any of them : ($ at 0)
        }

        rule implicit_current_string_in {
            strings:
                $a = "abc"
            condition:
                for any of them : ($ in (0..10))
        }
        """)

    result = SemanticValidator().validate(ast)

    assert result.is_valid is True
    assert result.errors == []


def test_undefined_string_detector_checks_children_of_implicit_position_checks() -> None:
    ast = Parser().parse("""
        rule implicit_at_with_missing_offset {
            strings:
                $a = "abc"
            condition:
                for any of them : ($ at @b)
        }

        rule implicit_in_with_missing_range_bound {
            strings:
                $a = "abc"
            condition:
                for any of them : ($ in (@c..10))
        }
        """)
    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    for rule in ast.rules:
        detector.check_rule(rule)

    messages = [error.message for error in result.errors]
    assert any(
        "Undefined string '$b' in rule 'implicit_at_with_missing_offset'" in message
        for message in messages
    )
    assert any(
        "Undefined string '$c' in rule 'implicit_in_with_missing_range_bound'" in message
        for message in messages
    )


def test_undefined_string_detector_visits_falsy_present_condition() -> None:
    class FalsyStringIdentifier(StringIdentifier):
        def __bool__(self) -> bool:
            return False

    result = ValidationResult()
    detector = UndefinedStringDetector(result)

    detector.check_rule(Rule(name="falsy_condition", condition=FalsyStringIdentifier("$missing")))

    assert any(
        "Undefined string '$missing' in rule 'falsy_condition'" in error.message
        for error in result.errors
    )


def test_semantic_validator_rejects_invalid_them_string_sets() -> None:
    ast = Parser().parse("""
        rule no_strings {
            condition:
                any of them
        }
        """)

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(
        "Undefined string pattern '$*' in rule 'no_strings'" in message for message in messages
    )


def test_semantic_validator_does_not_match_anonymous_strings_with_named_wildcards() -> None:
    ast = Parser().parse("""
        rule anonymous_named_wildcard {
            strings:
                $ = "abc"
                $ = "def"
            condition:
                any of ($a*)
        }

        rule anonymous_global_wildcard {
            strings:
                $ = "abc"
                $ = "def"
            condition:
                any of ($*)
        }
        """)

    result = SemanticValidator().validate(ast)
    messages = [error.message for error in result.errors]

    assert result.is_valid is False
    assert any(
        "Undefined string pattern '$a*' in rule 'anonymous_named_wildcard'" in message
        for message in messages
    )
    assert not any(
        "anonymous_global_wildcard" in message and "Undefined string pattern" in message
        for message in messages
    )


def test_semantic_validator_reports_non_string_string_references() -> None:
    conditions = [
        StringIdentifier(cast(Any, False)),
        OfExpression("any", [StringIdentifier(cast(Any, False))]),
        OfExpression("any", [StringLiteral(cast(Any, False))]),
        OfExpression("any", [StringWildcard(cast(Any, False))]),
        OfExpression("any", Identifier(cast(Any, False))),
    ]

    for condition in conditions:
        ast = YaraFile(
            rules=[
                Rule(
                    "invalid_string_reference",
                    strings=[PlainString("$a", value="x")],
                    condition=condition,
                )
            ]
        )

        result = SemanticValidator().validate(ast)

        assert result.is_valid is False
        assert any(error.message == "String reference must be a string" for error in result.errors)
