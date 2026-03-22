"""String identifier semantic validation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from yaraast.ast.base import ASTNode
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.visitor.defaults import DefaultASTVisitor

if TYPE_CHECKING:
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import StringDefinition


class StringIdentifierValidator(DefaultASTVisitor[None]):
    """Validator for string identifier uniqueness within rules."""

    def __init__(self, result: ValidationResult) -> None:
        super().__init__(default=None)
        self.result = result
        self.current_rule_strings: set[str] = set()
        self.current_rule_name: str | None = None

    def visit_rule(self, node: Rule) -> None:
        self.current_rule_strings.clear()
        self.current_rule_name = node.name

        for string_def in node.strings:
            self.visit(string_def)

    def visit_string_definition(self, node: StringDefinition) -> None:
        # Normalize: always use $ prefix for consistency with type environment
        identifier = node.identifier if node.identifier.startswith("$") else f"${node.identifier}"

        if identifier == "$":
            self.result.add_error(
                f"Invalid empty string identifier '$' in rule '{self.current_rule_name}'",
                node.location,
                "String identifiers must have a name after '$', e.g. '$s1'.",
            )
            return

        if identifier in self.current_rule_strings:
            self.result.add_error(
                f"Duplicate string identifier '{identifier}' in rule '{self.current_rule_name}'",
                node.location,
                f"String identifiers must be unique within each rule. Consider renaming to '{identifier}_2' or similar.",
            )
        else:
            self.current_rule_strings.add(identifier)

    def visit_plain_string(self, node) -> None:
        self.visit_string_definition(node)

    def visit_hex_string(self, node) -> None:
        self.visit_string_definition(node)

    def visit_regex_string(self, node) -> None:
        self.visit_string_definition(node)


class UndefinedStringDetector:
    """Detects string identifiers used in conditions but not defined in strings section."""

    def __init__(self, result: ValidationResult) -> None:
        self.result = result

    def check_rule(self, rule: Rule) -> None:
        """Check a rule for undefined string references in its condition."""
        if not rule.condition:
            return

        # Collect defined string identifiers (normalized to $name format)
        defined = set()
        for string_def in rule.strings:
            sid = string_def.identifier
            if not sid.startswith("$"):
                sid = f"${sid}"
            defined.add(sid)

        # Walk condition to find string references
        referenced = set()
        self._collect_string_refs(rule.condition, referenced)

        # Report undefined strings
        for ref in referenced:
            normalized = ref if ref.startswith("$") else f"${ref}"
            # Check exact match and wildcard patterns
            if normalized.endswith("*"):
                prefix = normalized[:-1]
                if not any(d.startswith(prefix) for d in defined):
                    self.result.add_error(
                        f"Undefined string pattern '{normalized}' in rule '{rule.name}'",
                        suggestion="Define matching strings in the strings section.",
                    )
            elif normalized not in defined:
                self.result.add_error(
                    f"Undefined string '{normalized}' in rule '{rule.name}'",
                    suggestion="Add a string definition in the strings section.",
                )

    def _collect_string_refs(self, node: ASTNode, refs: set[str]) -> None:
        """Recursively collect string identifier references from an expression."""
        from yaraast.ast.conditions import AtExpression, InExpression
        from yaraast.ast.expressions import (
            StringCount,
            StringIdentifier,
            StringLength,
            StringOffset,
            StringWildcard,
        )

        if isinstance(node, StringIdentifier):
            refs.add(node.name)
        elif isinstance(node, StringWildcard):
            refs.add(node.pattern)
        elif isinstance(node, StringCount | StringOffset | StringLength):
            refs.add(f"${node.string_id}" if not node.string_id.startswith("$") else node.string_id)
        elif isinstance(node, AtExpression):
            refs.add(node.string_id if node.string_id.startswith("$") else f"${node.string_id}")
        elif isinstance(node, InExpression) and isinstance(node.subject, str):
            refs.add(node.subject if node.subject.startswith("$") else f"${node.subject}")

        # Recurse into children
        for child in node.children():
            self._collect_string_refs(child, refs)
