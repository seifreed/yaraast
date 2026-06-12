"""Additional tests for rule-related AST nodes (no mocks)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from yaraast.ast.modifiers import MetaEntry, RuleModifier, RuleModifierType
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaType
from yaraast.ast.rules import Rule, Tag


def test_rule_modifier_flags_and_meta_entries() -> None:
    rule = Rule(
        name="r1",
        modifiers=["private", RuleModifier(modifier_type=RuleModifierType.GLOBAL)],
        tags=[Tag(name="tag")],
        meta={"owner": "me"},
    )
    assert rule.is_private is True
    assert rule.is_global is True

    entries = rule.get_meta_entries()
    assert len(entries) == 1
    assert entries[0].key == "owner"

    private_meta = [MetaEntry.from_key_value("secret", "x", "private")]
    public_meta = [MetaEntry.from_key_value("pub", 1)]
    rule.meta = private_meta + public_meta
    assert [m.key for m in rule.get_private_meta()] == ["secret"]
    assert [m.key for m in rule.get_public_meta()] == ["pub"]


def test_rule_get_meta_value_uses_last_duplicate_key_value() -> None:
    rule = Rule(
        name="duplicate_meta",
        meta=[
            MetaEntry.from_key_value("owner", "first"),
            MetaEntry.from_key_value("owner", "last"),
        ],
    )

    assert rule.get_meta_value("owner") == "last"


@pytest.mark.parametrize("key", [None, 1, b"owner", object()])
def test_rule_get_meta_value_rejects_non_string_keys(key: Any) -> None:
    rule = Rule(name="r1")

    with pytest.raises(TypeError, match="Rule meta key must be a string"):
        rule.get_meta_value(cast(str, key))


@pytest.mark.parametrize(
    ("modifiers", "message"),
    [
        (cast(Any, object()), "Rule modifiers must be a list"),
        ([cast(Any, object())], "Rule modifiers item must be RuleModifier or string"),
        ([""], "Rule modifier name cannot be empty"),
    ],
)
def test_rule_modifier_flags_reject_invalid_modifier_state(
    modifiers: Any,
    message: str,
) -> None:
    rule = Rule(name="r1")
    rule.modifiers = modifiers

    with pytest.raises((TypeError, ValueError), match=message):
        _ = rule.is_private

    with pytest.raises((TypeError, ValueError), match=message):
        _ = rule.is_global


@pytest.mark.parametrize(
    ("meta", "message"),
    [
        (cast(Any, object()), "Rule meta must be a list or tuple"),
        ([cast(Any, object())], "Rule meta must contain Meta or MetaEntry nodes"),
    ],
)
def test_rule_meta_accessors_reject_invalid_meta_state(
    meta: Any,
    message: str,
) -> None:
    rule = Rule(name="r1")
    rule.meta = meta

    with pytest.raises(TypeError, match=message):
        rule.get_meta_value("owner")

    with pytest.raises(TypeError, match=message):
        rule.get_private_meta()

    with pytest.raises(TypeError, match=message):
        rule.get_public_meta()


def test_rule_pragmas_by_position() -> None:
    rule = Rule(name="r2")
    pragma_before = InRulePragma(
        pragma=Pragma(PragmaType.DEFINE, "define"), position="before_strings"
    )
    pragma_after = InRulePragma(
        pragma=Pragma(PragmaType.DEFINE, "define"), position="after_strings"
    )

    rule.add_pragma(pragma_before)
    rule.add_pragma(pragma_after)

    before = rule.get_pragmas_by_position("before_strings")
    after = rule.get_pragmas_by_position("after_strings")
    assert before == [pragma_before]
    assert after == [pragma_after]


@pytest.mark.parametrize("position", [None, 1, b"before_strings", object()])
def test_rule_get_pragmas_by_position_rejects_non_string_positions(
    position: Any,
) -> None:
    rule = Rule(name="r2")

    with pytest.raises(TypeError, match="Rule pragma position must be a string"):
        rule.get_pragmas_by_position(cast(str, position))


@pytest.mark.parametrize(
    ("pragmas", "message"),
    [
        (cast(Any, "bad"), "Rule.pragmas must be a list or tuple"),
        ([cast(Any, object())], "Rule.pragmas must contain InRulePragma nodes"),
    ],
)
def test_rule_get_pragmas_by_position_rejects_invalid_pragma_state(
    pragmas: Any,
    message: str,
) -> None:
    rule = Rule(name="r2")
    rule.pragmas = pragmas

    with pytest.raises(TypeError, match=message):
        rule.get_pragmas_by_position("before_strings")


def test_rule_rejects_invalid_pragmas_without_partial_update() -> None:
    rule = Rule(name="r2")
    pragma = InRulePragma(pragma=Pragma(PragmaType.DEFINE, "define"))
    rule.add_pragma(pragma)

    with pytest.raises(TypeError, match="Rule pragma input must be an InRulePragma"):
        rule.add_pragma(cast(Any, object()))

    assert rule.pragmas == [pragma]


def test_rule_add_pragma_validates_structure_without_partial_update() -> None:
    rule = Rule(name="r2")
    pragma = InRulePragma(pragma=Pragma(PragmaType.DEFINE, "define"))
    rule.add_pragma(pragma)

    with pytest.raises(ValueError, match="InRulePragma position cannot be empty"):
        rule.add_pragma(InRulePragma(pragma=Pragma(PragmaType.PRAGMA, "vendor"), position=""))

    assert rule.pragmas == [pragma]
