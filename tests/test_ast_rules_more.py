"""Additional tests for rule-related AST nodes (no mocks)."""

from __future__ import annotations

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
