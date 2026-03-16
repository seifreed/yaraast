"""Additional coverage for extern AST nodes."""

from __future__ import annotations

from yaraast.ast.extern import (
    ExternImport,
    ExternNamespace,
    ExternRule,
    ExternRuleReference,
    create_extern_rule,
)


class _Visitor:
    def visit_extern_rule(self, node):
        return ("rule", node.name)

    def visit_extern_rule_reference(self, node):
        return ("ref", node.qualified_name)

    def visit_extern_import(self, node):
        return ("import", node.module_path)

    def visit_extern_namespace(self, node):
        return ("namespace", node.name)


def test_extern_accepts_and_non_selective_import_str() -> None:
    visitor = _Visitor()

    rule = ExternRule(name="R1")
    ref = ExternRuleReference(rule_name="R1")
    imp = ExternImport(module_path="ext_rules")
    ns = ExternNamespace(name="ext")

    assert rule.accept(visitor) == ("rule", "R1")
    assert ref.accept(visitor) == ("ref", "R1")
    assert imp.accept(visitor) == ("import", "ext_rules")
    assert ns.accept(visitor) == ("namespace", "ext")
    assert str(imp) == 'import "ext_rules"'


def test_extern_namespace_negative_lookup_and_factory_without_modifiers() -> None:
    ns = ExternNamespace(name="ext")
    rule = ExternRule(name="R1")
    ns.add_extern_rule(rule)

    assert ns.get_rule_by_name("missing") is None
    assert str(ns) == "namespace ext"

    helper_rule = create_extern_rule("R2")
    assert helper_rule.modifiers == []
    assert helper_rule.namespace is None
