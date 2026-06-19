"""Additional tests for modifier enums and helpers (no mocks)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.ast.modifiers import (
    MetaEntry,
    MetaScope,
    RuleModifier,
    RuleModifierType,
    StringModifier,
    StringModifierType,
)
from yaraast.errors import ValidationError


def test_string_modifier_type_parsing_and_str() -> None:
    assert StringModifierType.from_string("AsCiI") == StringModifierType.ASCII
    assert str(StringModifierType.WIDE) == "wide"

    with pytest.raises(ValidationError):
        StringModifierType.from_string("unknown_mod")


def test_rule_modifier_type_parsing_and_str() -> None:
    assert RuleModifierType.from_string("PRIVATE") == RuleModifierType.PRIVATE
    assert str(RuleModifierType.GLOBAL) == "global"

    with pytest.raises(ValidationError):
        RuleModifierType.from_string("not-a-mod")


def test_meta_scope_fallback_and_meta_entry_str() -> None:
    assert MetaScope.from_string("private") == MetaScope.PRIVATE
    assert MetaScope.from_string("nonsense") == MetaScope.PUBLIC
    assert str(MetaScope.PROTECTED) == "protected"

    private_entry = MetaEntry.from_key_value("k", "v", "private")
    escaped_entry = MetaEntry.from_key_value("description", 'a"\\b\n')
    public_entry = MetaEntry.from_key_value("n", 1)
    float_entry = MetaEntry.from_key_value("score", 1.5)
    boolean_entry = MetaEntry.from_key_value("enabled", True)
    private_boolean_entry = MetaEntry.from_key_value("disabled", False, "private")
    assert private_entry.is_private is True
    assert public_entry.is_public is True
    assert str(private_entry).startswith("private:")
    assert str(escaped_entry) == 'description = "a\\"\\\\b\\n"'
    assert str(public_entry) == "n = 1"
    assert str(float_entry) == "score = 1.5"
    assert str(boolean_entry) == "enabled = true"
    assert str(private_boolean_entry) == "private:disabled = false"


def test_string_and_rule_modifier_helpers() -> None:
    modifier = StringModifier.from_name_value("wide")
    assert modifier.name == "wide"
    assert str(modifier) == "wide"

    modifier_with_value = StringModifier.from_name_value("xor", 10)
    assert str(modifier_with_value) == "xor(10)"

    modifier_with_range = StringModifier.from_name_value("xor", (1, 3))
    assert str(modifier_with_range) == "xor(1-3)"

    modifier_with_hex_string = StringModifier.from_name_value("xor", "0x10")
    assert str(modifier_with_hex_string) == "xor(0x10)"

    modifier_with_hex_range_string = StringModifier.from_name_value("xor", "0x01-0xff")
    assert str(modifier_with_hex_range_string) == "xor(0x01-0xff)"

    alphabet = "A" * 64
    modifier_with_string = StringModifier.from_name_value("base64", alphabet)
    assert str(modifier_with_string) == f'base64("{alphabet}")'
    modifier_with_escaped_string = StringModifier.from_name_value("base64", 'a"\\b\n')
    assert str(modifier_with_escaped_string) == 'base64("a\\"\\\\b\\n")'

    assert modifier_with_value.name == "xor"

    rule_mod = RuleModifier.from_string("global")
    assert rule_mod.name == "global"
    assert str(rule_mod) == "global"


@pytest.mark.parametrize(
    ("modifier", "message"),
    [
        (
            StringModifier(cast(Any, "wide")),
            "StringModifier modifier_type must be a StringModifierType",
        ),
        (
            RuleModifier(cast(Any, "private")),
            "RuleModifier modifier_type must be a RuleModifierType",
        ),
    ],
)
def test_modifier_name_properties_reject_invalid_internal_state(
    modifier: StringModifier | RuleModifier,
    message: str,
) -> None:
    with pytest.raises(TypeError, match=message):
        _ = modifier.name


@pytest.mark.parametrize(
    ("entry", "property_name"),
    [
        (MetaEntry("key", "value", cast(Any, "private")), "is_private"),
        (MetaEntry("key", "value", cast(Any, object())), "is_public"),
    ],
)
def test_meta_entry_scope_properties_reject_invalid_internal_state(
    entry: MetaEntry,
    property_name: str,
) -> None:
    with pytest.raises(TypeError, match="Meta scope must be a MetaScope"):
        _ = entry.is_private if property_name == "is_private" else entry.is_public


def test_modifier_accept_and_factory_helpers() -> None:
    class _Visitor:
        def visit_string_modifier(self, node: StringModifier) -> tuple[str, object]:
            return (node.name, node.value)

    modifier = StringModifier.from_name_value("xor", 7)
    assert modifier.accept(_Visitor()) == ("xor", 7)

    rule_modifier = RuleModifier.from_string("private")
    assert rule_modifier.modifier_type == RuleModifierType.PRIVATE

    meta_entry = MetaEntry.from_key_value("author", "seifreed", "protected")
    assert meta_entry.scope == MetaScope.PROTECTED
    assert str(meta_entry) == 'protected:author = "seifreed"'


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (
            StringModifier(cast(Any, "xor")),
            TypeError,
            "StringModifier modifier_type must be a StringModifierType",
        ),
        (
            StringModifier(StringModifierType.XOR, cast(Any, False)),
            TypeError,
            "StringModifier value must be a string, number, tuple, or null",
        ),
        (
            StringModifier(StringModifierType.XOR, cast(Any, (1,))),
            TypeError,
            "StringModifier tuple value must contain two integers",
        ),
        (
            StringModifier(StringModifierType.XOR, cast(Any, (False, 2))),
            TypeError,
            "StringModifier tuple value must contain two integers",
        ),
        (
            StringModifier(StringModifierType.XOR, cast(Any, float("nan"))),
            ValueError,
            "StringModifier value must be finite",
        ),
        (
            RuleModifier(cast(Any, "private")),
            TypeError,
            "RuleModifier modifier_type must be a RuleModifierType",
        ),
        (MetaEntry("", "value"), ValueError, "Meta key cannot be empty"),
        (
            MetaEntry("key", cast(Any, None)),
            TypeError,
            "Meta value must be a string, integer, boolean, or finite float",
        ),
        (
            MetaEntry("key", cast(Any, float("inf"))),
            TypeError,
            "Meta value must be a string, integer, boolean, or finite float",
        ),
        (
            MetaEntry("key", "value", cast(Any, "public")),
            TypeError,
            "Meta scope must be a MetaScope",
        ),
    ],
)
def test_modifier_string_reprs_reject_invalid_fields(
    node: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        str(node)


def test_modifier_helpers_reject_invalid_inputs_at_creation_time() -> None:
    invalid_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: StringModifierType.from_string(cast(Any, object())),
            "String modifier input must be a string",
        ),
        (
            lambda: RuleModifierType.from_string(cast(Any, object())),
            "Rule modifier input must be a string",
        ),
        (
            lambda: MetaScope.from_string(cast(Any, object())),
            "Meta scope input must be a string",
        ),
        (
            lambda: StringModifier.from_name_value(cast(Any, object())),
            "String modifier input must be a string",
        ),
        (
            lambda: RuleModifier.from_string(cast(Any, object())),
            "Rule modifier input must be a string",
        ),
        (
            lambda: MetaEntry.from_key_value(cast(Any, object()), "value"),
            "Meta key must be a string",
        ),
        (
            lambda: MetaEntry.from_key_value("key", cast(Any, object())),
            "Meta value must be a string, integer, boolean, or finite float",
        ),
        (
            lambda: MetaEntry.from_key_value("key", cast(Any, float("nan"))),
            "Meta value must be a string, integer, boolean, or finite float",
        ),
        (
            lambda: MetaEntry.from_key_value("key", "value", cast(Any, object())),
            "Meta scope input must be a string",
        ),
    ]

    for factory, message in invalid_cases:
        with pytest.raises(TypeError, match=message):
            factory()

    empty_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: MetaEntry.from_key_value("", "value"),
            "Meta key cannot be empty",
        ),
        (
            lambda: MetaEntry.from_key_value("key", "value", ""),
            "Meta scope input cannot be empty",
        ),
        (
            lambda: MetaScope.from_string("   "),
            "Meta scope input cannot be empty",
        ),
    ]
    for factory, message in empty_cases:
        with pytest.raises(ValueError, match=message):
            factory()
