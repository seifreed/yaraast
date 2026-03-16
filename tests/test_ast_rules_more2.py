"""Additional coverage for rule-related AST nodes."""

from __future__ import annotations

from yaraast.ast.modifiers import RuleModifier, RuleModifierType
from yaraast.ast.rules import Import, Include, Rule, Tag


class _Visitor:
    def visit_import(self, node):
        return ("import", node.module, node.alias)

    def visit_include(self, node):
        return ("include", node.path)

    def visit_tag(self, node):
        return ("tag", node.name)

    def visit_rule(self, node):
        return ("rule", node.name)


def test_import_include_tag_and_rule_accept_methods() -> None:
    visitor = _Visitor()

    assert Import(module="pe", alias="p").accept(visitor) == ("import", "pe", "p")
    assert Include(path="inc.yar").accept(visitor) == ("include", "inc.yar")
    assert Tag(name="malware").accept(visitor) == ("tag", "malware")
    assert Rule(name="r1").accept(visitor) == ("rule", "r1")


def test_rule_modifier_flags_negative_and_mixed_paths() -> None:
    plain = Rule(name="plain")
    assert plain.is_private is False
    assert plain.is_global is False

    only_global_mod = Rule(
        name="g",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.GLOBAL)],
    )
    assert only_global_mod.is_private is False
    assert only_global_mod.is_global is True

    only_private_mod = Rule(
        name="p",
        modifiers=[RuleModifier(modifier_type=RuleModifierType.PRIVATE)],
    )
    assert only_private_mod.is_private is True
    assert only_private_mod.is_global is False

    string_global = Rule(name="gs", modifiers=["global"])
    assert string_global.is_global is True
    assert string_global.is_private is False

    unrelated_string_mods = Rule(name="s", modifiers=["something-else"])
    assert unrelated_string_mods.is_private is False
    assert unrelated_string_mods.is_global is False
