"""External rule declarations and references."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import ASTNode, _VisitorType, require_optional_string, require_string
from yaraast.ast.expressions import Expression
from yaraast.string_escaping import escape_string_source_value

if TYPE_CHECKING:
    from yaraast.ast.modifiers import RuleModifier


def _normalize_string_list(values: list[str] | None, field_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        msg = f"{field_name} must be a list of strings"
        raise TypeError(msg)
    return list(values)


@dataclass
class ExternRule(ASTNode):
    """External rule declaration.

    Represents 'extern rule RuleName' declarations that reference
    rules defined in other YARA files or modules.
    """

    name: str
    modifiers: list[RuleModifier] = field(default_factory=list)
    namespace: str | None = None  # Optional namespace for rule

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_rule(self)

    @property
    def is_private(self) -> bool:
        """Check if extern rule is private."""
        return any(str(modifier) == "private" for modifier in self.modifiers)

    @property
    def is_global(self) -> bool:
        """Check if extern rule is global."""
        return any(str(modifier) == "global" for modifier in self.modifiers)

    def __str__(self) -> str:
        """String representation of extern rule."""
        modifier_str = " ".join(str(mod) for mod in self.modifiers)
        prefix = f"{modifier_str} " if modifier_str else ""
        namespace_str = f"{self.namespace}." if self.namespace else ""
        return f"extern rule {prefix}{namespace_str}{self.name}"


@dataclass
class ExternRuleReference(Expression):
    """Reference to an external rule in expressions.

    Used when referencing extern rules in conditions or other expressions.
    """

    rule_name: str
    namespace: str | None = None

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_rule_reference(self)

    @property
    def qualified_name(self) -> str:
        """Get the fully qualified rule name."""
        if self.namespace:
            return f"{self.namespace}.{self.rule_name}"
        return self.rule_name

    def __str__(self) -> str:
        return self.qualified_name


@dataclass
class ExternImport(ASTNode):
    """Import statement for external rule modules.

    Represents imports that bring external rules into scope,
    such as 'import "external_rules"'.
    """

    module_path: str
    alias: str | None = None
    rules: list[str] = field(default_factory=list)  # Specific rules to import

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_import(self)

    @property
    def is_selective_import(self) -> bool:
        """Check if this is a selective import (specific rules only)."""
        return len(self.rules) > 0

    def __str__(self) -> str:
        """String representation of extern import."""
        module_path = escape_string_source_value(self.module_path)
        if self.is_selective_import:
            rules_str = ", ".join(self.rules)
            base = f'import "{module_path}" ({rules_str})'
        else:
            base = f'import "{module_path}"'

        if self.alias:
            base += f" as {self.alias}"

        return base


@dataclass
class ExternNamespace(ASTNode):
    """Namespace declaration for organizing external rules.

    Allows grouping related extern rules under a common namespace.
    """

    name: str
    extern_rules: list[ExternRule] = field(default_factory=list)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_namespace(self)

    def add_extern_rule(self, extern_rule: ExternRule) -> None:
        """Add an extern rule to this namespace."""
        if not isinstance(extern_rule, ExternRule):
            msg = "Extern rule input must be an ExternRule"
            raise TypeError(msg)
        extern_rule.namespace = self.name
        self.extern_rules.append(extern_rule)

    def get_rule_by_name(self, name: str) -> ExternRule | None:
        """Get extern rule by name within this namespace."""
        for rule in self.extern_rules:
            if rule.name == name:
                return rule
        return None

    def __str__(self) -> str:
        return f"namespace {self.name}"


# Convenience functions for creating extern constructs


def create_extern_rule(
    name: str,
    modifiers: list[str] | None = None,
    namespace: str | None = None,
) -> ExternRule:
    """Create an extern rule with string modifiers."""
    from yaraast.ast.modifiers import RuleModifier

    rule_name = require_string(name, "ExternRule name")
    rule_namespace = require_optional_string(namespace, "ExternRule namespace")
    rule_modifiers = []
    for mod_str in _normalize_string_list(modifiers, "ExternRule modifiers"):
        rule_modifiers.append(RuleModifier.from_string(mod_str))

    return ExternRule(name=rule_name, modifiers=rule_modifiers, namespace=rule_namespace)


def create_extern_reference(
    rule_name: str,
    namespace: str | None = None,
) -> ExternRuleReference:
    """Create an extern rule reference."""
    return ExternRuleReference(
        rule_name=require_string(rule_name, "ExternRuleReference rule_name"),
        namespace=require_optional_string(namespace, "ExternRuleReference namespace"),
    )


def create_extern_import(
    module_path: str,
    alias: str | None = None,
    rules: list[str] | None = None,
) -> ExternImport:
    """Create an extern import statement."""
    return ExternImport(
        module_path=require_string(module_path, "ExternImport module_path"),
        alias=require_optional_string(alias, "ExternImport alias"),
        rules=_normalize_string_list(rules, "ExternImport rules"),
    )
