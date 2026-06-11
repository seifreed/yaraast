"""Additional coverage for extern AST nodes."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

import pytest

from yaraast.ast.extern import (
    ExternImport,
    ExternNamespace,
    ExternRule,
    ExternRuleReference,
    create_extern_import,
    create_extern_reference,
    create_extern_rule,
)


class _Visitor:
    def visit_extern_rule(self, node: ExternRule) -> tuple[str, str]:
        return ("rule", node.name)

    def visit_extern_rule_reference(self, node: ExternRuleReference) -> tuple[str, str]:
        return ("ref", node.qualified_name)

    def visit_extern_import(self, node: ExternImport) -> tuple[str, str]:
        return ("import", node.module_path)

    def visit_extern_namespace(self, node: ExternNamespace) -> tuple[str, str]:
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


@pytest.mark.parametrize("name", [None, 1, b"R1", object()])
def test_extern_namespace_rejects_non_string_rule_lookup_names(name: Any) -> None:
    ns = ExternNamespace(name="ext")

    with pytest.raises(TypeError, match="ExternNamespace rule name must be a string"):
        ns.get_rule_by_name(cast(str, name))


@pytest.mark.parametrize("name", ["", "   "])
def test_extern_namespace_rejects_empty_rule_lookup_names(name: str) -> None:
    ns = ExternNamespace(name="ext")

    with pytest.raises(ValueError, match="ExternNamespace rule name cannot be empty"):
        ns.get_rule_by_name(name)


def test_extern_namespace_rejects_invalid_rule_inputs_without_partial_update() -> None:
    ns = ExternNamespace(name="ext")
    rule = ExternRule(name="R1")
    ns.add_extern_rule(rule)

    with pytest.raises(TypeError, match="Extern rule input must be an ExternRule"):
        ns.add_extern_rule(cast(Any, object()))

    assert ns.extern_rules == [rule]


def test_extern_helpers_reject_invalid_inputs_at_creation_time() -> None:
    invalid_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: create_extern_rule(cast(Any, object())),
            "ExternRule name must be a string",
        ),
        (
            lambda: create_extern_rule("R1", modifiers=cast(Any, "private")),
            "ExternRule modifiers must be a list of strings",
        ),
        (
            lambda: create_extern_rule("R1", modifiers=cast(Any, [object()])),
            "ExternRule modifiers must be a list of strings",
        ),
        (
            lambda: create_extern_rule("R1", namespace=cast(Any, object())),
            "ExternRule namespace must be a string",
        ),
        (
            lambda: create_extern_reference(cast(Any, object())),
            "ExternRuleReference rule_name must be a string",
        ),
        (
            lambda: create_extern_reference("R1", namespace=cast(Any, object())),
            "ExternRuleReference namespace must be a string",
        ),
        (
            lambda: create_extern_import(cast(Any, object())),
            "ExternImport module_path must be a string",
        ),
        (
            lambda: create_extern_import("external", alias=cast(Any, object())),
            "ExternImport alias must be a string",
        ),
        (
            lambda: create_extern_import("external", rules=cast(Any, "R1")),
            "ExternImport rules must be a list of strings",
        ),
        (
            lambda: create_extern_import("external", rules=cast(Any, [object()])),
            "ExternImport rules must be a list of strings",
        ),
    ]

    for factory, message in invalid_cases:
        with pytest.raises(TypeError, match=message):
            factory()

    empty_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: create_extern_rule(""),
            "ExternRule name cannot be empty",
        ),
        (
            lambda: create_extern_rule("R1", namespace="   "),
            "ExternRule namespace cannot be empty",
        ),
        (
            lambda: create_extern_reference(""),
            "ExternRuleReference rule_name cannot be empty",
        ),
        (
            lambda: create_extern_reference("R1", namespace=""),
            "ExternRuleReference namespace cannot be empty",
        ),
        (
            lambda: create_extern_import("   "),
            "ExternImport module_path cannot be empty",
        ),
        (
            lambda: create_extern_import("external", alias=""),
            "ExternImport alias cannot be empty",
        ),
        (
            lambda: create_extern_import("external", rules=[""]),
            "ExternImport rules must contain non-empty strings",
        ),
    ]

    for factory, message in empty_cases:
        with pytest.raises(ValueError, match=message):
            factory()
