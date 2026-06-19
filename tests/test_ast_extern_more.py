"""Real tests for extern AST nodes (no mocks)."""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.extern import (
    ExternImport,
    ExternNamespace,
    ExternRule,
    ExternRuleReference,
)


def test_extern_rule_properties_and_str() -> None:
    rule = ExternRule(name="r1", modifiers=cast(Any, ["private"]), namespace="ns")
    assert rule.name == "r1"
    assert rule.namespace == "ns"
    assert rule.is_private is True
    assert "extern rule" in str(rule)


def test_extern_reference_and_import() -> None:
    ref = ExternRuleReference(rule_name="r2", namespace="ns")
    assert ref.qualified_name == "ns.r2"

    imp = ExternImport(module_path="ext_rules", alias="ext", rules=["r1", "r2"])
    assert imp.is_selective_import is True
    assert "as ext" in str(imp)


def test_extern_namespace_add_and_get() -> None:
    ns = ExternNamespace(name="ns")
    rule = ExternRule(name="r3")
    ns.add_extern_rule(rule)
    assert rule.namespace == "ns"
    assert ns.get_rule_by_name("r3") is rule
