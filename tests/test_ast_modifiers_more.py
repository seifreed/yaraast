"""Additional tests for modifier enums and helpers (no mocks)."""

from __future__ import annotations

import pytest

from yaraast.ast.modifiers import (
    MetaEntry,
    MetaScope,
    RuleModifier,
    RuleModifierType,
    StringModifier,
    StringModifierType,
    create_meta_entry,
    create_rule_modifier,
    create_string_modifier,
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
    public_entry = MetaEntry.from_key_value("n", 1)
    assert private_entry.is_private is True
    assert public_entry.is_public is True
    assert str(private_entry).startswith("private:")
    assert str(public_entry) == "n = 1"


def test_string_and_rule_modifier_helpers() -> None:
    modifier = StringModifier.from_name_value("wide")
    assert modifier.name == "wide"
    assert str(modifier) == "wide"

    modifier_with_value = StringModifier.from_name_value("xor", 10)
    assert str(modifier_with_value) == "xor(10)"

    assert modifier_with_value.name == "xor"

    rule_mod = RuleModifier.from_string("global")
    assert rule_mod.name == "global"
    assert str(rule_mod) == "global"


def test_modifier_accept_and_factory_helpers() -> None:
    class _Visitor:
        def visit_string_modifier(self, node: StringModifier) -> tuple[str, object]:
            return (node.name, node.value)

    modifier = create_string_modifier("xor", 7)
    assert modifier.accept(_Visitor()) == ("xor", 7)

    rule_modifier = create_rule_modifier("private")
    assert rule_modifier.modifier_type == RuleModifierType.PRIVATE

    meta_entry = create_meta_entry("author", "seifreed", "protected")
    assert meta_entry.scope == MetaScope.PROTECTED
    assert str(meta_entry) == 'protected:author = "seifreed"'
