"""External rule declarations and references."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING, Any

from yaraast.ast.base import (
    ASTNode,
    _require_nonempty_string,
    _require_optional_nonempty_string,
    _VisitorType,
)
from yaraast.ast.expressions import Expression
from yaraast.ast.modifiers import require_rule_modifier_identifier
from yaraast.errors import ValidationError
from yaraast.lexer.lexer_tables import KEYWORDS, YARA_IDENTIFIER_MAX_LENGTH
from yaraast.string_escaping import escape_string_source_value

if TYPE_CHECKING:
    from yaraast.ast.modifiers import RuleModifier

_YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YARA_KEYWORDS = frozenset(KEYWORDS)


def _validate_yara_identifier(name: object, kind: str) -> str:
    if not isinstance(name, str):
        msg = f"{kind.capitalize()} identifier must be a string for libyara output"
        raise TypeError(msg)
    if (
        len(name) <= YARA_IDENTIFIER_MAX_LENGTH
        and _YARA_IDENTIFIER_RE.fullmatch(name) is not None
        and name not in _YARA_KEYWORDS
    ):
        return name
    msg = f"Invalid {kind} identifier '{name}' for libyara output"
    raise ValueError(msg)


def _validate_quoted_field_text(value: str, field_name: str) -> None:
    if '"' in value or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        msg = f"{field_name} must not contain quotes or control characters"
        raise ValueError(msg)


def _validate_yara_identifier_path(path: object, kind: str) -> str:
    if not isinstance(path, str):
        msg = f"{kind.capitalize()} identifier must be a string for libyara output"
        raise TypeError(msg)
    parts = path.split(".")
    if not parts or any(part == "" for part in parts):
        msg = f"Invalid {kind} identifier '{path}' for libyara output"
        raise ValueError(msg)
    for part in parts:
        _validate_yara_identifier(part, kind)
    return path


def _normalize_string_list(values: list[str] | None, field_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        msg = f"{field_name} must be a list of strings"
        raise TypeError(msg)
    if any(not item.strip() for item in values):
        msg = f"{field_name} must contain non-empty strings"
        raise ValueError(msg)
    return list(values)


def _validate_rule_identifiers(values: list[str], field_name: str) -> None:
    for value in values:
        _validate_yara_identifier_path(value, field_name)


def _normalize_extern_rule_modifiers(modifiers: Any) -> list[str]:
    from yaraast.ast.modifiers import RuleModifier, RuleModifierType

    if not isinstance(modifiers, list):
        msg = "ExternRule modifiers must be a list"
        raise TypeError(msg)

    normalized = []
    for modifier in modifiers:
        if isinstance(modifier, RuleModifier):
            modifier.validate_structure()
            normalized.append(str(modifier))
        elif isinstance(modifier, str):
            try:
                normalized.append(str(RuleModifier.from_string(modifier)))
            except (ValueError, ValidationError) as exc:
                modifier_name = require_rule_modifier_identifier(
                    modifier,
                    "ExternRule modifier",
                )
                try:
                    RuleModifierType.from_string(modifier_name)
                except ValidationError:
                    msg = f"Invalid rule modifier '{modifier_name}'"
                    raise ValueError(msg) from exc
                normalized.append(modifier_name)
        else:
            msg = "ExternRule modifiers item must be RuleModifier or string"
            raise TypeError(msg)
    return normalized


@dataclass
class ExternRule(ASTNode):
    """External rule declaration.

    Represents 'extern rule RuleName' declarations that reference
    rules defined in other YARA files or modules.
    """

    name: str
    modifiers: list[RuleModifier] = field(default_factory=list)
    namespace: str | None = None  # Optional namespace for rule

    def validate_structure(self) -> None:
        """Validate extern rule fields before direct analysis."""
        _require_nonempty_string(self.name, "ExternRule name")
        _validate_yara_identifier(self.name, "extern rule")
        _normalize_extern_rule_modifiers(self.modifiers)
        if self.namespace is not None:
            _require_optional_nonempty_string(self.namespace, "ExternRule namespace")
            _validate_yara_identifier_path(self.namespace, "namespace")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_rule(self)

    @property
    def is_private(self) -> bool:
        """Check if extern rule is private."""
        return "private" in _normalize_extern_rule_modifiers(self.modifiers)

    @property
    def is_global(self) -> bool:
        """Check if extern rule is global."""
        return "global" in _normalize_extern_rule_modifiers(self.modifiers)

    def __str__(self) -> str:
        """String representation of extern rule."""
        name = _require_nonempty_string(self.name, "ExternRule name")
        modifiers = _normalize_extern_rule_modifiers(self.modifiers)
        namespace = _require_optional_nonempty_string(
            self.namespace,
            "ExternRule namespace",
        )
        modifier_str = " ".join(modifiers)
        prefix = f"{modifier_str} " if modifier_str else ""
        namespace_str = f"{namespace}." if namespace is not None else ""
        return f"extern rule {prefix}{namespace_str}{name}"


@dataclass
class ExternRuleReference(Expression):
    """Reference to an external rule in expressions.

    Used when referencing extern rules in conditions or other expressions.
    """

    rule_name: str
    namespace: str | None = None

    def validate_structure(self) -> None:
        """Validate extern rule reference fields before direct analysis."""
        _require_nonempty_string(self.rule_name, "ExternRuleReference rule_name")
        _validate_yara_identifier(self.rule_name, "extern rule")
        if self.namespace is not None:
            _require_optional_nonempty_string(self.namespace, "ExternRuleReference namespace")
            _validate_yara_identifier_path(self.namespace, "namespace")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_rule_reference(self)

    @property
    def qualified_name(self) -> str:
        """Get the fully qualified rule name."""
        rule_name = _require_nonempty_string(
            self.rule_name,
            "ExternRuleReference rule_name",
        )
        namespace = _require_optional_nonempty_string(
            self.namespace,
            "ExternRuleReference namespace",
        )
        if namespace is not None:
            return f"{namespace}.{rule_name}"
        return rule_name

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

    def validate_structure(self) -> None:
        """Validate extern import fields before direct analysis."""
        module_path = _require_nonempty_string(self.module_path, "ExternImport module_path")
        _validate_quoted_field_text(module_path, "ExternImport module_path")
        _require_optional_nonempty_string(self.alias, "ExternImport alias")
        if self.alias is not None:
            _validate_yara_identifier(self.alias, "import alias")
        _normalize_string_list(self.rules, "ExternImport rules")
        _validate_rule_identifiers(self.rules, "extern rule")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_import(self)

    @property
    def is_selective_import(self) -> bool:
        """Check if this is a selective import (specific rules only)."""
        return len(_normalize_string_list(self.rules, "ExternImport rules")) > 0

    def __str__(self) -> str:
        """String representation of extern import."""
        module_path = escape_string_source_value(
            _require_nonempty_string(self.module_path, "ExternImport module_path")
        )
        alias = _require_optional_nonempty_string(self.alias, "ExternImport alias")
        rules = _normalize_string_list(self.rules, "ExternImport rules")
        if rules:
            rules_str = ", ".join(rules)
            base = f'import "{module_path}" ({rules_str})'
        else:
            base = f'import "{module_path}"'

        if alias is not None:
            base += f" as {alias}"

        return base


@dataclass
class ExternNamespace(ASTNode):
    """Namespace declaration for organizing external rules.

    Allows grouping related extern rules under a common namespace.
    """

    name: str
    extern_rules: list[ExternRule] = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate namespace fields before direct analysis."""
        _require_nonempty_string(self.name, "ExternNamespace name")
        _validate_yara_identifier(self.name, "namespace")
        self._validated_extern_rules()

    def _validated_extern_rules(self) -> list[ExternRule]:
        if not isinstance(self.extern_rules, list):
            msg = "ExternNamespace extern_rules must be a list"
            raise TypeError(msg)
        extern_rules = []
        for extern_rule in self.extern_rules:
            if not isinstance(extern_rule, ExternRule):
                msg = "ExternNamespace extern_rules item must be ExternRule"
                raise TypeError(msg)
            extern_rule.validate_structure()
            extern_rules.append(extern_rule)
        return extern_rules

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_extern_namespace(self)

    def __str__(self) -> str:
        name = _require_nonempty_string(self.name, "ExternNamespace name")
        return f"namespace {name}"
