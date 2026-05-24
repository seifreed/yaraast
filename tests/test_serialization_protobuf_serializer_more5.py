"""Additional coverage for protobuf serializer modifier paths."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.base import Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import AtExpression, ForExpression, ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import RuleModifier, StringModifier
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import StringOperatorExpression
from yaraast.ast.pragmas import (
    ConditionalDirective,
    CustomPragma,
    DefineDirective,
    InRulePragma,
    PragmaScope,
    PragmaType,
)
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import HexAlternative, HexByte, HexString, PlainString, RegexString
from yaraast.errors import SerializationError
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_conversion import protobuf_to_ast, protobuf_to_string
from yaraast.serialization.protobuf_serializer import ProtobufSerializer


def test_protobuf_serializer_hex_modifier_with_value() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="hexmods",
                strings=[
                    HexString(
                        identifier="$h",
                        tokens=[HexByte(value=0x41)],
                        modifiers=[StringModifier.from_name_value("xor", "10-20")],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    text = serializer.serialize_text(ast)
    assert "10-20" in text


def test_protobuf_serializer_preserves_string_modifier_aliases() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="regex_aliases",
                strings=[
                    RegexString(
                        identifier="$r",
                        regex="ab.*",
                        modifiers=["i", "s", StringModifier.from_name_value("fullword")],
                    ),
                ],
                condition=StringIdentifier("$r"),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    modifiers = restored.rules[0].strings[0].modifiers

    assert modifiers[:2] == ["i", "s"]
    assert isinstance(modifiers[2], StringModifier)
    assert modifiers[2].name == "fullword"


def test_protobuf_conversion_escapes_unknown_modifier_string_values() -> None:
    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "vendor_modifier"
    pb_modifier.value = 'a"\\b\n'

    restored = protobuf_to_string(pb_string)

    assert isinstance(restored, PlainString)
    assert restored.modifiers == ['vendor_modifier("a\\"\\\\b\\n")']


def test_protobuf_serializer_rejects_non_finite_modifier_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_modifier",
                strings=[
                    PlainString(
                        identifier="$a",
                        value="abc",
                        modifiers=[StringModifier.from_name_value("xor", cast(Any, float("nan")))],
                    )
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="String modifier value must be finite"):
        serializer.serialize(ast)

    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    pb_modifier = pb_string.plain.modifiers.add()
    pb_modifier.name = "vendor_modifier"
    pb_modifier.typed_value.double_value = float("inf")

    with pytest.raises(SerializationError, match="String modifier value must be finite"):
        protobuf_to_string(pb_string)


def test_protobuf_serializer_does_not_coerce_invalid_xor_range_values_to_ints() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="invalid_xor_ranges",
                strings=[
                    PlainString(
                        "$bool_range",
                        value="a",
                        modifiers=[StringModifier.from_name_value("xor", cast(Any, (True, 3)))],
                    ),
                    PlainString(
                        "$float_range",
                        value="b",
                        modifiers=[StringModifier.from_name_value("xor", cast(Any, (1.5, 3)))],
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert [string.modifiers[0].value for string in restored.rules[0].strings] == [
        "True-3",
        "1.5-3",
    ]


def test_protobuf_conversion_parses_legacy_hex_xor_modifier_values() -> None:
    pb_string = yara_ast_pb2.StringDefinition()
    pb_string.identifier = "$a"
    pb_string.plain.value = "abc"
    key_modifier = pb_string.plain.modifiers.add()
    key_modifier.name = "xor"
    key_modifier.value = "0xff"
    range_modifier = pb_string.plain.modifiers.add()
    range_modifier.name = "xor"
    range_modifier.value = "0x01-0xff"

    restored = protobuf_to_string(pb_string)

    assert isinstance(restored, PlainString)
    assert [modifier.value for modifier in restored.modifiers] == [255, (1, 255)]


@pytest.mark.parametrize(
    ("token_kind", "field_name", "value", "message"),
    [
        ("byte", "value", "-1", "HexByte value must be a byte"),
        ("byte", "value", "999", "HexByte value must be a byte"),
        ("byte", "value", "GG", "HexByte value must be a byte"),
        ("negated_byte", "value", "999", "HexNegatedByte value must be a byte"),
        ("nibble", "value", 16, "HexNibble value must be a nibble"),
        ("nibble", "value", -1, "HexNibble value must be a nibble"),
        ("jump", "min_jump", -1, "HexJump min_jump must be a non-negative integer"),
    ],
)
def test_protobuf_deserialization_rejects_invalid_hex_token_scalars(
    token_kind: str,
    field_name: str,
    value: str | int,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_hex"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_token = pb_string.hex.tokens.add()
    setattr(getattr(pb_token, token_kind), field_name, value)
    pb_rule.condition.boolean_literal.value = True

    with pytest.raises(SerializationError, match=message):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserialization_rejects_descending_hex_jump_bounds() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_hex_jump"
    pb_string = pb_rule.strings.add()
    pb_string.identifier = "$h"
    pb_token = pb_string.hex.tokens.add()
    pb_token.jump.min_jump = 5
    pb_token.jump.max_jump = 3
    pb_rule.condition.boolean_literal.value = True

    with pytest.raises(SerializationError, match="HexJump min_jump cannot exceed max_jump"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_non_finite_double_literals() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_double",
                condition=DoubleLiteral(float("nan")),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
        serializer.serialize(ast)

    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_double"
    pb_rule.condition.double_literal.value = float("inf")

    with pytest.raises(SerializationError, match="DoubleLiteral value must be finite"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_serializer_rejects_non_finite_meta_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta",
                meta=[Meta("score", cast(Any, float("nan")))],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="Meta value must be finite"):
        serializer.serialize(ast)

    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "bad_meta"
    pb_rule.condition.boolean_literal.value = True
    pb_meta = pb_rule.meta_entries.add()
    pb_meta.key = "score"
    pb_meta.value.double_value = float("inf")

    with pytest.raises(SerializationError, match="Meta value must be finite"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())

    legacy_pb_file = yara_ast_pb2.YaraFile()
    legacy_pb_rule = legacy_pb_file.rules.add()
    legacy_pb_rule.name = "bad_legacy_meta"
    legacy_pb_rule.condition.boolean_literal.value = True
    legacy_pb_rule.meta["score"].double_value = float("-inf")

    with pytest.raises(SerializationError, match="Meta value must be finite"):
        serializer.deserialize(binary_data=legacy_pb_file.SerializeToString())


def test_protobuf_serializer_rejects_unsupported_meta_and_pragma_parameter_values() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    bad_meta_value = cast(Any, ["not", "a", "scalar"])
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta_value",
                meta=[Meta("labels", bad_meta_value)],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(
        SerializationError,
        match="Meta value must be a string, integer, boolean, or finite float",
    ):
        serializer.serialize(ast)

    bad_parameter_value = cast(Any, {"nested": "value"})
    pragma_ast = YaraFile(
        pragmas=[CustomPragma("vendor", parameters={"config": bad_parameter_value})],
    )

    with pytest.raises(
        SerializationError,
        match="Pragma parameter value must be a string, integer, boolean, or finite float",
    ):
        serializer.serialize(pragma_ast)


def test_protobuf_serializer_rejects_non_string_meta_and_pragma_parameter_keys() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_meta_key",
                meta=[Meta(cast(Any, 123), "value")],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match="Meta key must be a string"):
        serializer.serialize(ast)

    bad_parameters = {cast(Any, 1): "value"}
    pragma_ast = YaraFile(pragmas=[CustomPragma("vendor", parameters=bad_parameters)])

    with pytest.raises(SerializationError, match="Pragma parameters keys must be strings"):
        serializer.serialize(pragma_ast)


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (YaraFile(imports=[Import(cast(Any, 123))]), "Import module must be a string"),
        (
            YaraFile(imports=[Import("pe", alias=cast(Any, 123))]),
            "Import alias must be a string",
        ),
        (YaraFile(includes=[Include(cast(Any, 123))]), "Include path must be a string"),
        (
            YaraFile(rules=[Rule(cast(Any, 123), condition=BooleanLiteral(True))]),
            "Rule name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="bad_tag",
                        tags=[Tag(cast(Any, 123))],
                        condition=BooleanLiteral(True),
                    ),
                ],
            ),
            "Tag name must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_non_string_file_and_rule_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("string_def", "message"),
    [
        (
            PlainString(identifier=cast(Any, 123), value="abc"),
            "PlainString identifier must be a string",
        ),
        (
            PlainString(identifier="$a", value=cast(Any, ["abc"])),
            "PlainString value must be a string or bytes",
        ),
        (
            HexString(identifier=cast(Any, 123), tokens=[HexByte(0x90)]),
            "HexString identifier must be a string",
        ),
        (
            RegexString(identifier=cast(Any, 123), regex="abc"),
            "RegexString identifier must be a string",
        ),
        (
            RegexString(identifier="$r", regex=cast(Any, 123)),
            "RegexString regex must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_string_definition_fields(
    string_def: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="bad_string_fields",
                strings=[string_def],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize("invalid_flag", [cast(Any, "yes"), cast(Any, 1)])
def test_protobuf_serializer_rejects_invalid_anonymous_string_flags(
    invalid_flag: Any,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    invalid_cases: list[tuple[Any, str]] = [
        (
            PlainString(identifier="$a", value="abc", is_anonymous=invalid_flag),
            "PlainString is_anonymous must be a boolean",
        ),
        (
            HexString(
                identifier="$h",
                tokens=[HexByte(0x90)],
                is_anonymous=invalid_flag,
            ),
            "HexString is_anonymous must be a boolean",
        ),
        (
            RegexString(identifier="$r", regex="abc", is_anonymous=invalid_flag),
            "RegexString is_anonymous must be a boolean",
        ),
    ]

    for string_def, message in invalid_cases:
        ast = YaraFile(
            rules=[
                Rule(
                    name="bad_anonymous_flag",
                    strings=[string_def],
                    condition=BooleanLiteral(value=True),
                ),
            ],
        )

        with pytest.raises(SerializationError, match=message):
            serializer.serialize(ast)


def test_protobuf_serializer_preserves_empty_hex_string() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    empty_hex = HexString(identifier="$h", tokens=[])
    ast = YaraFile(
        rules=[
            Rule(
                name="empty_hex_string",
                strings=[empty_hex],
                condition=BooleanLiteral(True),
            )
        ]
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.rules[0].strings == [empty_hex]


def _invalid_modifier_and_hex_container_cases() -> list[tuple[YaraFile, str]]:
    bad_rule_modifiers = Rule("bad_rule_modifiers", condition=BooleanLiteral(True))
    cast(Any, bad_rule_modifiers).modifiers = False

    bad_rule_modifier = Rule("bad_rule_modifier", condition=BooleanLiteral(True))
    cast(Any, bad_rule_modifier).modifiers = [object()]

    bad_extern_rule_modifiers = ExternRule("ExternalRule")
    cast(Any, bad_extern_rule_modifiers).modifiers = False

    bad_extern_rule_modifier = ExternRule("ExternalRule")
    cast(Any, bad_extern_rule_modifier).modifiers = [object()]

    bad_plain_modifiers = PlainString(identifier="$a", value="abc")
    cast(Any, bad_plain_modifiers).modifiers = False

    bad_plain_modifier = PlainString(identifier="$a", value="abc")
    cast(Any, bad_plain_modifier).modifiers = [object()]

    bad_hex_tokens = HexString(identifier="$h", tokens=[HexByte(0x90)])
    cast(Any, bad_hex_tokens).tokens = False

    bad_hex_modifiers = HexString(identifier="$h", tokens=[HexByte(0x90)])
    cast(Any, bad_hex_modifiers).modifiers = False

    bad_hex_modifier = HexString(identifier="$h", tokens=[HexByte(0x90)])
    cast(Any, bad_hex_modifier).modifiers = [object()]

    bad_regex_modifiers = RegexString(identifier="$r", regex="abc")
    cast(Any, bad_regex_modifiers).modifiers = False

    bad_regex_modifier = RegexString(identifier="$r", regex="abc")
    cast(Any, bad_regex_modifier).modifiers = [object()]

    bad_alternatives = HexAlternative(alternatives=[[HexByte(0x90)]])
    cast(Any, bad_alternatives).alternatives = False

    return [
        (
            YaraFile(rules=[bad_rule_modifiers]),
            "Rule modifiers must be a list",
        ),
        (
            YaraFile(rules=[bad_rule_modifier]),
            "Rule modifiers item must be RuleModifier or string",
        ),
        (
            YaraFile(extern_rules=[bad_extern_rule_modifiers]),
            "ExternRule modifiers must be a list",
        ),
        (
            YaraFile(extern_rules=[bad_extern_rule_modifier]),
            "ExternRule modifiers item must be RuleModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_plain_modifiers",
                        strings=[bad_plain_modifiers],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "PlainString modifiers must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_plain_modifier",
                        strings=[bad_plain_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "PlainString modifiers item must be StringModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule("bad_hex_tokens", strings=[bad_hex_tokens], condition=BooleanLiteral(True))
                ],
            ),
            "HexString tokens must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_hex_modifiers",
                        strings=[bad_hex_modifiers],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "HexString modifiers must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_hex_modifier",
                        strings=[bad_hex_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "HexString modifiers item must be StringModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_regex_modifiers",
                        strings=[bad_regex_modifiers],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "RegexString modifiers must be a list",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_regex_modifier",
                        strings=[bad_regex_modifier],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "RegexString modifiers item must be StringModifier or string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        "bad_alternatives",
                        strings=[
                            HexString(identifier="$h", tokens=[bad_alternatives]),
                        ],
                        condition=BooleanLiteral(True),
                    )
                ],
            ),
            "HexAlternative alternatives must be a list",
        ),
    ]


@pytest.mark.parametrize(("ast", "message"), _invalid_modifier_and_hex_container_cases())
def test_protobuf_serializer_rejects_invalid_modifier_and_hex_container_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("ast", "message"),
    [
        (
            YaraFile(extern_rules=[ExternRule(cast(Any, 123))]),
            "ExternRule name must be a string",
        ),
        (
            YaraFile(extern_rules=[ExternRule("ExternalRule", namespace=cast(Any, 123))]),
            "ExternRule namespace must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport(cast(Any, 123))]),
            "ExternImport module_path must be a string",
        ),
        (
            YaraFile(extern_imports=[ExternImport("external_rules", alias=cast(Any, 123))]),
            "ExternImport alias must be a string",
        ),
        (
            YaraFile(
                extern_imports=[ExternImport("external_rules", rules=cast(Any, ["A", 123]))],
            ),
            "ExternImport rules must be a list of strings",
        ),
        (
            YaraFile(namespaces=[ExternNamespace(cast(Any, 123))]),
            "ExternNamespace name must be a string",
        ),
        (
            YaraFile(
                rules=[
                    Rule(
                        name="bad_pragma_position",
                        pragmas=[InRulePragma(CustomPragma("vendor"), position=cast(Any, 123))],
                        condition=BooleanLiteral(True),
                    ),
                ],
            ),
            "InRulePragma position must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_extern_and_in_rule_pragma_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _invalid_file_container_cases() -> list[tuple[YaraFile, str]]:
    bad_imports = YaraFile(imports=[Import("pe")])
    cast(Any, bad_imports).imports = False

    bad_import = YaraFile(imports=[Import("pe")])
    cast(Any, bad_import).imports = [object()]

    bad_includes = YaraFile(includes=[Include("rules.yar")])
    cast(Any, bad_includes).includes = False

    bad_include = YaraFile(includes=[Include("rules.yar")])
    cast(Any, bad_include).includes = [object()]

    bad_extern_rules = YaraFile(extern_rules=[ExternRule("ExternalRule")])
    cast(Any, bad_extern_rules).extern_rules = False

    bad_extern_rule = YaraFile(extern_rules=[ExternRule("ExternalRule")])
    cast(Any, bad_extern_rule).extern_rules = [object()]

    bad_extern_imports = YaraFile(extern_imports=[ExternImport("external_rules")])
    cast(Any, bad_extern_imports).extern_imports = False

    bad_extern_import = YaraFile(extern_imports=[ExternImport("external_rules")])
    cast(Any, bad_extern_import).extern_imports = [object()]

    bad_pragmas = YaraFile(pragmas=[CustomPragma("vendor")])
    cast(Any, bad_pragmas).pragmas = False

    bad_pragma = YaraFile(pragmas=[CustomPragma("vendor")])
    cast(Any, bad_pragma).pragmas = [object()]

    bad_namespaces = YaraFile(namespaces=[ExternNamespace("corp")])
    cast(Any, bad_namespaces).namespaces = False

    bad_namespace = YaraFile(namespaces=[ExternNamespace("corp")])
    cast(Any, bad_namespace).namespaces = [object()]

    namespace_with_bad_rules = ExternNamespace("corp")
    cast(Any, namespace_with_bad_rules).extern_rules = False

    namespace_with_bad_rule = ExternNamespace("corp")
    cast(Any, namespace_with_bad_rule).extern_rules = [object()]

    bad_rules = YaraFile(rules=[Rule(name="ok")])
    cast(Any, bad_rules).rules = False

    bad_rule = YaraFile(rules=[Rule(name="ok")])
    cast(Any, bad_rule).rules = [object()]

    return [
        (bad_imports, "YaraFile imports must be a list"),
        (bad_import, "YaraFile imports item must be Import"),
        (bad_includes, "YaraFile includes must be a list"),
        (bad_include, "YaraFile includes item must be Include"),
        (bad_extern_rules, "YaraFile extern_rules must be a list"),
        (bad_extern_rule, "YaraFile extern_rules item must be ExternRule"),
        (bad_extern_imports, "YaraFile extern_imports must be a list"),
        (bad_extern_import, "YaraFile extern_imports item must be ExternImport"),
        (bad_pragmas, "YaraFile pragmas must be a list"),
        (bad_pragma, "YaraFile pragmas item must be Pragma"),
        (bad_namespaces, "YaraFile namespaces must be a list"),
        (bad_namespace, "YaraFile namespaces item must be ExternNamespace"),
        (
            YaraFile(namespaces=[namespace_with_bad_rules]),
            "ExternNamespace extern_rules must be a list",
        ),
        (
            YaraFile(namespaces=[namespace_with_bad_rule]),
            "ExternNamespace extern_rules item must be ExternRule",
        ),
        (bad_rules, "YaraFile rules must be a list"),
        (bad_rule, "YaraFile rules item must be Rule"),
    ]


@pytest.mark.parametrize(("ast", "message"), _invalid_file_container_cases())
def test_protobuf_serializer_rejects_invalid_file_container_fields(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _invalid_rule_container_cases() -> list[tuple[Rule, str]]:
    bad_tags = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_tags).tags = False

    bad_tag = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_tag).tags = [object()]

    bad_meta = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_meta).meta = False

    bad_meta_entry = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_meta_entry).meta = [object()]

    bad_strings = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_strings).strings = False

    bad_string = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_string).strings = [object()]

    bad_pragmas = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_pragmas).pragmas = False

    bad_pragma = Rule(name="bad_rule_container", condition=BooleanLiteral(True))
    cast(Any, bad_pragma).pragmas = [object()]

    return [
        (bad_tags, "Rule tags must be a list"),
        (bad_tag, "Rule tags item must be Tag"),
        (bad_meta, "Rule meta must be a list"),
        (bad_meta_entry, "Rule meta item must be Meta or MetaEntry"),
        (bad_strings, "Rule strings must be a list"),
        (bad_string, "Rule strings item must be StringDefinition"),
        (bad_pragmas, "Rule pragmas must be a list"),
        (bad_pragma, "Rule pragmas item must be InRulePragma"),
    ]


@pytest.mark.parametrize(("rule", "message"), _invalid_rule_container_cases())
def test_protobuf_serializer_rejects_invalid_rule_container_fields(
    rule: Rule,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[rule])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _custom_pragma_with_parameters(parameters: Any) -> CustomPragma:
    pragma = CustomPragma("vendor")
    cast(Any, pragma).parameters = parameters
    return pragma


@pytest.mark.parametrize(
    ("pragma", "message"),
    [
        (CustomPragma(cast(Any, 123)), "Pragma name must be a string"),
        (
            CustomPragma("vendor", arguments=cast(Any, "on")),
            "Pragma arguments must be a list of strings",
        ),
        (
            CustomPragma("vendor", arguments=cast(Any, ["on", 1])),
            "Pragma arguments must be a list of strings",
        ),
        (
            _custom_pragma_with_parameters(False),
            "Pragma parameters must be a mapping",
        ),
        (
            _custom_pragma_with_parameters([("level", 1)]),
            "Pragma parameters must be a mapping",
        ),
        (DefineDirective(cast(Any, 123)), "Pragma macro_name must be a string"),
        (
            DefineDirective("FLAG", macro_value=cast(Any, 123)),
            "Pragma macro_value must be a string",
        ),
        (
            ConditionalDirective(PragmaType.IFDEF, condition=cast(Any, 123)),
            "Pragma condition must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_pragma_fields(
    pragma: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(YaraFile(pragmas=[pragma]))


def test_protobuf_serializer_rejects_invalid_pragma_type() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pragma = CustomPragma("vendor")
    cast(Any, pragma).pragma_type = 123

    with pytest.raises(SerializationError, match="Pragma pragma_type must be a string"):
        serializer.serialize(YaraFile(pragmas=[pragma]))


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (
            BinaryExpression(BooleanLiteral(True), cast(Any, 123), BooleanLiteral(False)),
            "BinaryExpression operator must be a string",
        ),
        (
            UnaryExpression(cast(Any, 123), BooleanLiteral(True)),
            "UnaryExpression operator must be a string",
        ),
        (FunctionCall(cast(Any, 123), []), "FunctionCall function must be a string"),
        (
            MemberAccess(Identifier("pe"), cast(Any, 123)),
            "MemberAccess member must be a string",
        ),
        (
            ForExpression("any", cast(Any, 123), StringIdentifier("$a"), BooleanLiteral(True)),
            "ForExpression variable must be a string",
        ),
        (
            AtExpression(cast(Any, 123), IntegerLiteral(0)),
            "AtExpression string_id must be a string",
        ),
        (ModuleReference(cast(Any, ["pe"])), "ModuleReference module must be a string"),
        (
            DictionaryAccess(Identifier("items"), cast(Any, 123)),
            "DictionaryAccess key must be a string or expression",
        ),
        (
            DictionaryAccess(Identifier("items"), cast(Any, object())),
            "DictionaryAccess key must be a string or expression",
        ),
        (
            ExternRuleReference(cast(Any, 123)),
            "ExternRuleReference rule_name must be a string",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=cast(Any, False)),
            "ExternRuleReference namespace must be a string",
        ),
        (
            ExternRuleReference("ExternalRule", namespace=cast(Any, object())),
            "ExternRuleReference namespace must be a string",
        ),
        (
            StringOperatorExpression(StringLiteral("a"), cast(Any, 123), StringLiteral("b")),
            "StringOperatorExpression operator must be a string",
        ),
    ],
)
def test_protobuf_serializer_rejects_invalid_expression_scalar_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_expression_scalar", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        (Identifier(cast(Any, ["id"])), "Identifier name must be a string"),
        (StringIdentifier(cast(Any, 123)), "StringIdentifier name must be a string"),
        (StringWildcard(cast(Any, 123)), "StringWildcard pattern must be a string"),
        (StringCount(cast(Any, 123)), "StringCount string_id must be a string"),
        (StringOffset(cast(Any, 123)), "StringOffset string_id must be a string"),
        (StringLength(cast(Any, 123)), "StringLength string_id must be a string"),
        (IntegerLiteral(cast(Any, True)), "IntegerLiteral value must be an integer"),
        (IntegerLiteral(cast(Any, "1")), "IntegerLiteral value must be an integer"),
        (StringLiteral(cast(Any, True)), "StringLiteral value must be a string"),
        (RegexLiteral(cast(Any, 123)), "RegexLiteral pattern must be a string"),
        (RegexLiteral("abc", cast(Any, ["i"])), "RegexLiteral modifiers must be a string"),
        (BooleanLiteral(cast(Any, "true")), "BooleanLiteral value must be a boolean"),
    ],
)
def test_protobuf_serializer_rejects_invalid_expression_leaf_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_expression_leaf", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def _invalid_expression_container_cases() -> list[tuple[Any, str]]:
    set_bad_elements = SetExpression([IntegerLiteral(1)])
    cast(Any, set_bad_elements).elements = False

    set_bad_element = SetExpression([IntegerLiteral(1)])
    cast(Any, set_bad_element).elements = [object()]

    call_bad_arguments = FunctionCall("fn", [IntegerLiteral(1)])
    cast(Any, call_bad_arguments).arguments = False

    call_bad_argument = FunctionCall("fn", [IntegerLiteral(1)])
    cast(Any, call_bad_argument).arguments = [object()]

    return [
        (set_bad_elements, "SetExpression elements must be a list"),
        (set_bad_element, "SetExpression elements item must be Expression"),
        (call_bad_arguments, "FunctionCall arguments must be a list"),
        (call_bad_argument, "FunctionCall arguments item must be Expression"),
    ]


@pytest.mark.parametrize(("condition", "message"), _invalid_expression_container_cases())
def test_protobuf_serializer_rejects_invalid_expression_container_fields(
    condition: Any,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(rules=[Rule(name="invalid_expression_container", condition=condition)])

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_preserves_file_externs_and_pragmas() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        extern_rules=[
            ExternRule(
                name="ExternalRule",
                modifiers=[RuleModifier.from_string("private")],
                namespace="legacy",
            ),
        ],
        extern_imports=[
            ExternImport(
                module_path="external_rules",
                alias="ext",
                rules=["ExternalRule"],
            ),
        ],
        pragmas=[
            CustomPragma(
                name="optimize",
                arguments=["off"],
                parameters={"level": 2},
                scope=PragmaScope.FILE,
            ),
        ],
        namespaces=[
            ExternNamespace(
                name="corp",
                extern_rules=[ExternRule(name="NamespacedRule")],
            ),
        ],
        rules=[
            Rule(
                name="uses_pragmas",
                pragmas=[
                    InRulePragma(
                        pragma=CustomPragma(
                            name="rule_hint",
                            arguments=["fast"],
                            parameters={"enabled": True},
                            scope=PragmaScope.RULE,
                        ),
                        position="before_condition",
                    ),
                ],
                condition=BooleanLiteral(value=True),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.extern_rules[0].name == "ExternalRule"
    assert str(restored.extern_rules[0].modifiers[0]) == "private"
    assert restored.extern_rules[0].namespace == "legacy"
    assert restored.extern_imports[0].module_path == "external_rules"
    assert restored.extern_imports[0].alias == "ext"
    assert restored.extern_imports[0].rules == ["ExternalRule"]
    restored_file_pragma = restored.pragmas[0]
    assert isinstance(restored_file_pragma, CustomPragma)
    assert restored_file_pragma.name == "optimize"
    assert restored_file_pragma.parameters == {"level": 2}
    assert restored.namespaces[0].name == "corp"
    assert restored.namespaces[0].extern_rules[0].name == "NamespacedRule"
    assert restored.rules[0].pragmas[0].position == "before_condition"
    restored_rule_pragma = restored.rules[0].pragmas[0].pragma
    assert isinstance(restored_rule_pragma, CustomPragma)
    assert restored_rule_pragma.name == "rule_hint"
    assert restored_rule_pragma.scope == PragmaScope.RULE
    assert restored_rule_pragma.parameters == {"enabled": True}


def test_protobuf_serialize_rejects_invalid_pragma_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pragma = CustomPragma(name="custom", scope=PragmaScope.FILE)
    cast(Any, pragma).scope = "secret"

    with pytest.raises(SerializationError, match="Pragma scope must be a valid pragma scope"):
        serializer.serialize(YaraFile(pragmas=[pragma]))


def test_protobuf_deserialize_rejects_invalid_pragma_scope() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    pb_file: Any = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = "custom"
    pb_pragma.name = "custom"
    pb_pragma.scope = "secret"

    with pytest.raises(SerializationError, match="Pragma scope must be a valid pragma scope"):
        serializer.deserialize(binary_data=pb_file.SerializeToString())


def test_protobuf_deserializes_legacy_meta_map_in_stable_key_order() -> None:
    pb_file = yara_ast_pb2.YaraFile()
    pb_rule = pb_file.rules.add()
    pb_rule.name = "legacy_meta"
    for key in ("zeta", "alpha", "middle", "beta"):
        pb_rule.meta[key].string_value = key

    restored = protobuf_to_ast(pb_file)

    assert [entry.key for entry in restored.rules[0].meta] == [
        "alpha",
        "beta",
        "middle",
        "zeta",
    ]


def test_protobuf_deserializes_pragma_parameters_in_stable_key_order() -> None:
    pb_file = yara_ast_pb2.YaraFile()
    pb_pragma = pb_file.pragmas.add()
    pb_pragma.pragma_type = "custom"
    pb_pragma.name = "vendor"
    for key in ("k9", "k1", "k5", "k2", "k8", "k3", "k7", "k4"):
        pb_pragma.parameters[key].string_value = key

    restored = protobuf_to_ast(pb_file)

    assert isinstance(restored.pragmas[0], CustomPragma)
    assert list(restored.pragmas[0].parameters) == [
        "k1",
        "k2",
        "k3",
        "k4",
        "k5",
        "k7",
        "k8",
        "k9",
    ]


def test_protobuf_serializer_uses_deterministic_map_encoding() -> None:
    keys = ("k9", "k1", "k5", "k2", "k8", "k3", "k7", "k4")
    serializer = ProtobufSerializer(include_metadata=False)
    first = YaraFile(
        pragmas=[CustomPragma("vendor", parameters={key: key for key in keys})],
    )
    second = YaraFile(
        pragmas=[CustomPragma("vendor", parameters={key: key for key in reversed(keys)})],
    )

    assert serializer.serialize(first) == serializer.serialize(second)


def test_protobuf_serializer_preserves_extern_rule_reference_condition() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(
                name="uses_external",
                condition=cast(
                    Any,
                    ExternRuleReference(rule_name="ExternalRule", namespace="legacy"),
                ),
            ),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))
    condition = restored.rules[0].condition

    assert isinstance(condition, ExternRuleReference)
    assert condition.rule_name == "ExternalRule"
    assert condition.namespace == "legacy"


def test_protobuf_serializer_preserves_empty_string_sets() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    ast = YaraFile(
        rules=[
            Rule(name="of_empty", condition=OfExpression(IntegerLiteral(0), [])),
            Rule(name="for_of_empty", condition=ForOfExpression("any", [], None)),
        ],
    )

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    of_condition = restored.rules[0].condition
    for_of_condition = restored.rules[1].condition
    assert isinstance(of_condition, OfExpression)
    assert of_condition.string_set == []
    assert isinstance(for_of_condition, ForOfExpression)
    assert for_of_condition.string_set == []


def _invalid_comment_metadata_cases() -> list[tuple[YaraFile, str]]:
    bad_leading_comments = Rule(name="bad_leading_comments", condition=BooleanLiteral(True))
    cast(Any, bad_leading_comments).leading_comments = False

    bad_leading_comment = Rule(name="bad_leading_comment", condition=BooleanLiteral(True))
    bad_leading_comment.leading_comments = cast(Any, [object()])

    bad_trailing_comment = Rule(name="bad_trailing_comment", condition=BooleanLiteral(True))
    bad_trailing_comment.trailing_comment = cast(Any, object())

    bad_comment_group = CommentGroup([Comment("ok")])
    cast(Any, bad_comment_group).comments = False
    group_rule = Rule(name="bad_comment_group", condition=BooleanLiteral(True))
    cast(Any, group_rule).trailing_comment = bad_comment_group

    bad_comment_group_item = CommentGroup([Comment("ok")])
    cast(Any, bad_comment_group_item).comments = [object()]
    group_item_rule = Rule(name="bad_comment_group_item", condition=BooleanLiteral(True))
    cast(Any, group_item_rule).trailing_comment = bad_comment_group_item

    bad_comment_text = Rule(name="bad_comment_text", condition=BooleanLiteral(True))
    bad_comment_text.trailing_comment = Comment(cast(Any, 123))

    bad_comment_multiline = Rule(name="bad_comment_multiline", condition=BooleanLiteral(True))
    bad_comment_multiline.trailing_comment = Comment("ok", is_multiline=cast(Any, "true"))

    return [
        (YaraFile(rules=[bad_leading_comments]), "leading_comments must be a list"),
        (
            YaraFile(rules=[bad_leading_comment]),
            "leading_comments item must be Comment or CommentGroup",
        ),
        (
            YaraFile(rules=[bad_trailing_comment]),
            "trailing_comment must be Comment or CommentGroup",
        ),
        (YaraFile(rules=[group_rule]), "CommentGroup comments must be a list"),
        (
            YaraFile(rules=[group_item_rule]),
            "CommentGroup comments item must be Comment",
        ),
        (YaraFile(rules=[bad_comment_text]), "Comment text must be a string"),
        (
            YaraFile(rules=[bad_comment_multiline]),
            "Comment is_multiline must be a boolean",
        ),
    ]


@pytest.mark.parametrize(("ast", "message"), _invalid_comment_metadata_cases())
def test_protobuf_serializer_rejects_invalid_comment_metadata(
    ast: YaraFile,
    message: str,
) -> None:
    serializer = ProtobufSerializer(include_metadata=False)

    with pytest.raises(SerializationError, match=message):
        serializer.serialize(ast)


def test_protobuf_serializer_preserves_node_comment_metadata() -> None:
    serializer = ProtobufSerializer(include_metadata=False)
    plain = PlainString(identifier="$a", value="abc")
    plain.leading_comments = [Comment("string lead", is_multiline=True)]
    condition = BooleanLiteral(True)
    condition.trailing_comment = Comment("condition tail")
    meta = Meta("author", "me")
    meta.leading_comments = [Comment("meta lead")]
    rule = Rule(name="commented", meta=[meta], strings=[plain], condition=condition)
    rule.leading_comments = [Comment("rule lead")]
    rule.trailing_comment = Comment("rule tail")
    ast = YaraFile(rules=[rule])
    ast.location = Location(1, 1, file="sample.yar", end_line=6, end_column=1)
    ast.trailing_comment = cast(Any, CommentGroup([Comment("file end"), Comment("final")]))

    restored = serializer.deserialize(binary_data=serializer.serialize(ast))

    assert restored.location == Location(1, 1, file="sample.yar", end_line=6, end_column=1)
    assert isinstance(restored.trailing_comment, CommentGroup)
    assert restored.trailing_comment.comments[1].text == "final"
    assert restored.rules[0].leading_comments[0].text == "rule lead"
    assert restored.rules[0].trailing_comment is not None
    assert restored.rules[0].trailing_comment.text == "rule tail"
    assert restored.rules[0].meta[0].leading_comments[0].text == "meta lead"
    restored_plain = restored.rules[0].strings[0]
    assert restored_plain.leading_comments[0].is_multiline is True
    restored_condition = restored.rules[0].condition
    assert restored_condition is not None
    assert restored_condition.trailing_comment is not None
    assert restored_condition.trailing_comment.text == "condition tail"
