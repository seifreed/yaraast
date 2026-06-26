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
)
from yaraast.errors import ValidationError


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


def test_extern_namespace_str_and_factory_without_modifiers() -> None:
    ns = ExternNamespace(name="ext", extern_rules=[ExternRule(name="R1", namespace="ext")])
    assert str(ns) == "namespace ext"

    helper_rule = ExternRule(name="R2")
    assert helper_rule.modifiers == []
    assert helper_rule.namespace is None


@pytest.mark.parametrize(
    ("modifiers", "property_name", "error_type", "message"),
    [
        (
            cast(Any, "private"),
            "is_private",
            TypeError,
            "ExternRule modifiers must be a list",
        ),
        (
            [cast(Any, object())],
            "is_global",
            TypeError,
            "ExternRule modifiers item must be RuleModifier or string",
        ),
        (
            [""],
            "is_private",
            ValueError,
            "ExternRule modifier name cannot be empty",
        ),
        (
            ["bad modifier"],
            "is_private",
            ValidationError,
            "Invalid ExternRule modifier identifier",
        ),
        (
            ["bad-modifier"],
            "is_global",
            ValidationError,
            "Invalid ExternRule modifier identifier",
        ),
        (
            ["1modifier"],
            "is_private",
            ValidationError,
            "Invalid ExternRule modifier identifier",
        ),
    ],
)
def test_extern_rule_modifier_properties_reject_invalid_internal_state(
    modifiers: Any,
    property_name: str,
    error_type: type[Exception],
    message: str,
) -> None:
    rule = ExternRule("Remote")
    rule.modifiers = modifiers

    with pytest.raises(error_type, match=message):
        _ = rule.is_private if property_name == "is_private" else rule.is_global


@pytest.mark.parametrize(
    ("extern_rules", "error_type", "message"),
    [
        (
            cast(Any, "bad"),
            TypeError,
            "ExternNamespace extern_rules must be a list",
        ),
        (
            [cast(Any, object())],
            TypeError,
            "ExternNamespace extern_rules item must be ExternRule",
        ),
        (
            [ExternRule(cast(Any, 123))],
            TypeError,
            "ExternRule name must be a string",
        ),
        (
            [ExternRule("")],
            ValueError,
            "ExternRule name cannot be empty",
        ),
    ],
)
def test_extern_namespace_validation_rejects_invalid_internal_state(
    extern_rules: Any,
    error_type: type[Exception],
    message: str,
) -> None:
    ns = ExternNamespace(name="ext")
    ns.extern_rules = extern_rules

    with pytest.raises(error_type, match=message):
        ns.validate_structure()


@pytest.mark.parametrize(
    ("node", "error_type", "message"),
    [
        (ExternRule(""), ValueError, "ExternRule name cannot be empty"),
        (
            ExternRule("R1", modifiers=cast(Any, False)),
            TypeError,
            "ExternRule modifiers must be a list",
        ),
        (
            ExternRule("R1", modifiers=cast(Any, [""])),
            ValueError,
            "ExternRule modifier name cannot be empty",
        ),
        (
            ExternRule("R1", modifiers=cast(Any, ["bad modifier"])),
            ValidationError,
            "Invalid ExternRule modifier identifier",
        ),
        (ExternRule("R1", namespace="   "), ValueError, "ExternRule namespace cannot be empty"),
        (
            ExternRule("R1", namespace=cast(Any, False)),
            TypeError,
            "ExternRule namespace must be a string",
        ),
        (ExternRuleReference(""), ValueError, "ExternRuleReference rule_name cannot be empty"),
        (
            ExternRuleReference("R1", namespace=""),
            ValueError,
            "ExternRuleReference namespace cannot be empty",
        ),
        (ExternImport(""), ValueError, "ExternImport module_path cannot be empty"),
        (ExternImport("external", alias=""), ValueError, "ExternImport alias cannot be empty"),
        (
            ExternImport("external", alias=cast(Any, False)),
            TypeError,
            "ExternImport alias must be a string",
        ),
        (
            ExternImport("external", rules=cast(Any, False)),
            TypeError,
            "ExternImport rules must be a list of strings",
        ),
        (
            ExternImport("external", rules=[""]),
            ValueError,
            "ExternImport rules must contain non-empty strings",
        ),
        (ExternNamespace(""), ValueError, "ExternNamespace name cannot be empty"),
    ],
)
def test_extern_string_reprs_reject_invalid_fields(
    node: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        str(node)


def test_extern_helpers_reject_invalid_inputs_at_creation_time() -> None:
    invalid_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: ExternRule(name=cast(Any, object())).validate_structure(),
            "ExternRule name must be a string",
        ),
        (
            lambda: ExternRule(name="R1", modifiers=cast(Any, "private")).validate_structure(),
            "ExternRule modifiers must be a list",
        ),
        (
            lambda: ExternRule(name="R1", modifiers=cast(Any, [object()])).validate_structure(),
            "ExternRule modifiers item must be RuleModifier or string",
        ),
        (
            lambda: ExternRule(name="R1", namespace=cast(Any, object())).validate_structure(),
            "ExternRule namespace must be a string",
        ),
        (
            lambda: ExternRuleReference(rule_name=cast(Any, object())).validate_structure(),
            "ExternRuleReference rule_name must be a string",
        ),
        (
            lambda: ExternRuleReference(
                rule_name="R1", namespace=cast(Any, object())
            ).validate_structure(),
            "ExternRuleReference namespace must be a string",
        ),
        (
            lambda: ExternImport(module_path=cast(Any, object())).validate_structure(),
            "ExternImport module_path must be a string",
        ),
        (
            lambda: ExternImport(
                module_path="external", alias=cast(Any, object())
            ).validate_structure(),
            "ExternImport alias must be a string",
        ),
        (
            lambda: ExternImport(
                module_path="external", rules=cast(Any, "R1")
            ).validate_structure(),
            "ExternImport rules must be a list of strings",
        ),
        (
            lambda: ExternImport(
                module_path="external", rules=cast(Any, [object()])
            ).validate_structure(),
            "ExternImport rules must be a list of strings",
        ),
    ]

    for factory, message in invalid_cases:
        with pytest.raises(TypeError, match=message):
            factory()

    empty_cases: list[tuple[Callable[[], object], str]] = [
        (
            lambda: ExternRule(name="").validate_structure(),
            "ExternRule name cannot be empty",
        ),
        (
            lambda: ExternRule(name="R1", namespace="   ").validate_structure(),
            "ExternRule namespace cannot be empty",
        ),
        (
            lambda: ExternRuleReference(rule_name="").validate_structure(),
            "ExternRuleReference rule_name cannot be empty",
        ),
        (
            lambda: ExternRuleReference(rule_name="R1", namespace="").validate_structure(),
            "ExternRuleReference namespace cannot be empty",
        ),
        (
            lambda: ExternImport(module_path="   ").validate_structure(),
            "ExternImport module_path cannot be empty",
        ),
        (
            lambda: ExternImport(module_path="external", alias="").validate_structure(),
            "ExternImport alias cannot be empty",
        ),
        (
            lambda: ExternImport(module_path="external", rules=[""]).validate_structure(),
            "ExternImport rules must contain non-empty strings",
        ),
    ]

    for factory, message in empty_cases:
        with pytest.raises(ValueError, match=message):
            factory()
