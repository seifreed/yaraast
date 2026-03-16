"""Additional tests for extern AST nodes (no mocks)."""

from __future__ import annotations

from yaraast.ast.extern import (
    ExternImport,
    ExternNamespace,
    ExternRule,
    ExternRuleReference,
    create_extern_import,
    create_extern_reference,
    create_extern_rule,
)
from yaraast.ast.modifiers import RuleModifier, RuleModifierType


def test_extern_rule_flags_and_str() -> None:
    extern_rule = ExternRule(
        name="RuleA",
        modifiers=[
            RuleModifier(modifier_type=RuleModifierType.PRIVATE),
            RuleModifier(modifier_type=RuleModifierType.GLOBAL),
        ],
        namespace="ext",
    )
    assert extern_rule.is_private is True
    assert extern_rule.is_global is True
    assert "extern rule" in str(extern_rule)
    assert "ext.RuleA" in str(extern_rule)


def test_extern_rule_reference_and_helpers() -> None:
    ref = ExternRuleReference(rule_name="R1", namespace="ns")
    assert ref.qualified_name == "ns.R1"
    assert str(ref) == "ns.R1"

    helper_ref = create_extern_reference("R2")
    assert helper_ref.qualified_name == "R2"

    helper_rule = create_extern_rule("R3", modifiers=["private"])
    assert helper_rule.is_private is True


def test_extern_import_and_namespace() -> None:
    imp = ExternImport(module_path="ext_rules", alias="ext", rules=["r1", "r2"])
    assert imp.is_selective_import is True
    assert str(imp) == 'import "ext_rules" (r1, r2) as ext'

    helper_imp = create_extern_import("ext_rules")
    assert helper_imp.is_selective_import is False

    ns = ExternNamespace(name="ns")
    rule = ExternRule(name="R1")
    ns.add_extern_rule(rule)
    assert rule.namespace == "ns"
    assert ns.get_rule_by_name("R1") == rule
