"""YARA-X compatibility checker."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from yaraast.ast.expressions import BinaryExpression, Identifier, SetExpression
from yaraast.visitor import ASTVisitor
from yaraast.yarax.feature_flags import YaraXFeatures

if TYPE_CHECKING:
    from yaraast.ast.base import Location, YaraFile
    from yaraast.ast.conditions import OfExpression
    from yaraast.ast.rules import Rule
    from yaraast.ast.strings import HexJump, HexString, PlainString, RegexString


class CompatibilityIssue:
    """Represents a compatibility issue between YARA and YARA-X."""

    def __init__(
        self,
        severity: str,
        location: Location | None,
        issue_type: str,
        message: str,
        suggestion: str = "",
    ):
        self.severity = severity  # "error", "warning", "info"
        self.location = location
        self.issue_type = issue_type
        self.message = message
        self.suggestion = suggestion

    def __str__(self) -> str:
        loc = f"{self.location.line}:{self.location.column}" if self.location else "unknown"
        return f"[{self.severity.upper()}] {loc}: {self.message}"


class YaraXCompatibilityChecker(ASTVisitor[None]):
    """Check YARA rules for YARA-X compatibility."""

    def __init__(self, features: YaraXFeatures | None = None) -> None:
        self.features = features or YaraXFeatures.yarax_strict()
        self.issues: list[CompatibilityIssue] = []
        self.current_rule: str | None = None

    def check(self, yara_file: YaraFile) -> list[CompatibilityIssue]:
        """Check YARA file for compatibility issues."""
        self.issues.clear()
        self.visit(yara_file)
        return self.issues

    def _add_issue(
        self,
        severity: str,
        issue_type: str,
        message: str,
        suggestion: str = "",
        location: Location | None = None,
    ) -> None:
        """Add a compatibility issue."""
        self.issues.append(
            CompatibilityIssue(
                severity=severity,
                location=location,
                issue_type=issue_type,
                message=message,
                suggestion=suggestion,
            )
        )

    def visit_rule(self, node: Rule) -> None:
        """Check rule for compatibility issues."""
        self.current_rule = node.name

        # Check for duplicate modifiers
        if self.features.disallow_duplicate_modifiers:
            seen_modifiers = set()
            for modifier in node.modifiers:
                if modifier in seen_modifiers:
                    self._add_issue(
                        "error",
                        "duplicate_modifier",
                        f"Duplicate '{modifier}' modifier in rule '{node.name}'",
                        f"Remove duplicate '{modifier}' modifier",
                        node.location,
                    )
                seen_modifiers.add(modifier)

        # Visit rule components
        # Handle meta as either dict or list
        if isinstance(node.meta, dict):
            # Meta is a dictionary, check values
            for _key, _value in node.meta.items():
                # Check meta values directly
                pass
        elif isinstance(node.meta, list):
            # Meta is a list of Meta objects
            for meta in node.meta:
                if hasattr(meta, "accept"):
                    self.visit(meta)

        for string_def in node.strings:
            self.visit(string_def)

        self.visit(node.condition)

        self.current_rule = None

    def visit_plain_string(self, node: PlainString) -> None:
        """Check plain string compatibility."""
        # Check base64 modifier
        has_base64 = any(m.name in ("base64", "base64wide") for m in node.modifiers)
        if (
            has_base64
            and self.features.minimum_base64_length > 0
            and len(node.value) < self.features.minimum_base64_length
        ):
            self._add_issue(
                "error",
                "base64_too_short",
                f"Base64 pattern '{node.value}' is shorter than minimum length {self.features.minimum_base64_length}",
                f"Use a base64 pattern with at least {self.features.minimum_base64_length} characters",
                node.location,
            )

        # Check XOR with fullword
        has_xor = any(m.name == "xor" for m in node.modifiers)
        has_fullword = any(m.name == "fullword" for m in node.modifiers)

        if (
            has_xor
            and has_fullword
            and self.features.strict_xor_fullword
            and not re.match(r"^[a-zA-Z0-9].*[a-zA-Z0-9]$", node.value)
        ):
            self._add_issue(
                "warning",
                "xor_fullword_boundary",
                f"String '{node.value}' with XOR and fullword may have stricter boundary checking in YARA-X",
                "Ensure string has proper alphanumeric boundaries",
                node.location,
            )

    def visit_regex_string(self, node: RegexString) -> None:
        """Check regex string compatibility."""
        if self.features.strict_regex_escaping:
            # Check for unescaped { outside of repetition
            pattern = node.regex
            i = 0
            while i < len(pattern):
                if pattern[i] == "\\":
                    # Skip escaped character
                    i += 2
                    continue
                if pattern[i] == "{":
                    # Check if this is a valid quantifier pattern like {3,5}
                    # Look ahead to see if it follows the pattern {number} or {number,} or {number,number}
                    j = i + 1
                    is_valid_quantifier = False

                    if j < len(pattern):
                        # Skip digits
                        while j < len(pattern) and pattern[j].isdigit():
                            j += 1

                        # Check if it's {n} or {n,} or {n,m}
                        if j < len(pattern):
                            if pattern[j] == "}":  # {n}
                                is_valid_quantifier = True
                            elif pattern[j] == "," and j + 1 < len(pattern):  # {n,?
                                j += 1
                                if pattern[j] == "}":  # {n,}
                                    is_valid_quantifier = True
                                else:
                                    # Skip more digits for {n,m}
                                    while j < len(pattern) and pattern[j].isdigit():
                                        j += 1
                                    if j < len(pattern) and pattern[j] == "}":  # {n,m}
                                        is_valid_quantifier = True

                    # If it's not a valid quantifier, it's an unescaped brace
                    if not is_valid_quantifier:
                        self._add_issue(
                            "error",
                            "unescaped_brace",
                            f"Unescaped '{{' in regex pattern at position {i}",
                            "Escape the brace with '\\{'",
                            node.location,
                        )
                i += 1

        if self.features.validate_escape_sequences:
            # Check for invalid escape sequences
            invalid_escapes = re.findall(r"\\([^\\abfnrtv0-7xdDsSwW.*+?{}()\[\]|^$])", node.regex)
            for escape in invalid_escapes:
                self._add_issue(
                    "error",
                    "invalid_escape",
                    f"Invalid escape sequence '\\{escape}' in regex",
                    "Remove or fix the escape sequence",
                    node.location,
                )

    def visit_hex_string(self, node: HexString) -> None:
        """Check hex string compatibility."""
        for token in node.tokens:
            self.visit(token)

    def visit_hex_jump(self, node: HexJump) -> None:
        """Check hex jump compatibility."""
        if self.features.validate_hex_bounds:
            # YARA-X accepts hex and octal values in bounds
            # This is actually an enhancement, so we might want to note it
            pass

    def visit_of_expression(self, node: OfExpression) -> None:
        """Check 'of' expression compatibility."""
        # YARA-X allows tuples of boolean expressions
        if self.features.allow_tuple_of_expressions and isinstance(node.string_set, SetExpression):
            for elem in node.string_set.elements:
                if isinstance(elem, BinaryExpression):
                    self._add_issue(
                        "info",
                        "yarax_feature",
                        "Using YARA-X feature: boolean expressions in 'of' statement",
                        "This feature is not available in original YARA",
                        node.location,
                    )
                    break

        self.visit(node.quantifier)
        self.visit(node.string_set)

    def visit_identifier(self, node: Identifier) -> None:
        """Check for 'with' statement usage."""
        # The 'with' statement would be parsed differently, but we can detect attempts
        if node.name == "with" and self.current_rule and not self.features.allow_with_statement:
            self._add_issue(
                "error",
                "unsupported_feature",
                "'with' statement is only available in YARA-X",
                "Rewrite without using 'with' statement for YARA compatibility",
                node.location,
            )

    def get_report(self) -> dict[str, Any]:
        """Generate compatibility report."""
        errors = [i for i in self.issues if i.severity == "error"]
        warnings = [i for i in self.issues if i.severity == "warning"]
        infos = [i for i in self.issues if i.severity == "info"]

        return {
            "compatible": len(errors) == 0,
            "total_issues": len(self.issues),
            "errors": len(errors),
            "warnings": len(warnings),
            "info": len(infos),
            "issues_by_type": self._group_by_type(),
            "yarax_features_used": self._get_yarax_features_used(),
            "migration_difficulty": self._assess_migration_difficulty(),
        }

    def _group_by_type(self) -> dict[str, list[CompatibilityIssue]]:
        """Group issues by type."""
        grouped: dict[str, list[CompatibilityIssue]] = {}
        for issue in self.issues:
            if issue.issue_type not in grouped:
                grouped[issue.issue_type] = []
            grouped[issue.issue_type].append(issue)
        return grouped

    def _get_yarax_features_used(self) -> list[str]:
        """Get list of YARA-X specific features used."""
        features = []
        for issue in self.issues:
            if issue.issue_type == "yarax_feature":
                features.append(issue.message.split(": ", 1)[1])
        return list(set(features))

    def _assess_migration_difficulty(self) -> str:
        """Assess difficulty of migrating to YARA-X."""
        errors = sum(1 for i in self.issues if i.severity == "error")
        warnings = sum(1 for i in self.issues if i.severity == "warning")

        if errors == 0 and warnings == 0:
            return "trivial"
        if errors == 0:
            return "easy"
        if errors <= 5:
            return "moderate"
        return "difficult"

    # Implement all required abstract methods with default behavior
    def visit_yara_file(self, node):
        """Visit YARA file."""
        for rule in node.rules:
            self.visit(rule)

    def visit_array_access(self, node):
        # Not needed for compatibility checking
        pass

    def visit_at_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_binary_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_boolean_literal(self, node):
        # Not needed for compatibility checking
        pass

    def visit_comment(self, node):
        # Not needed for compatibility checking
        pass

    def visit_comment_group(self, node):
        # Not needed for compatibility checking
        pass

    def visit_condition(self, node):
        # Not needed for compatibility checking
        pass

    def visit_defined_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_dictionary_access(self, node):
        # Not needed for compatibility checking
        pass

    def visit_double_literal(self, node):
        # Not needed for compatibility checking
        pass

    def visit_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_extern_import(self, node):
        # Not needed for compatibility checking
        pass

    def visit_extern_namespace(self, node):
        # Not needed for compatibility checking
        pass

    def visit_extern_rule(self, node):
        # Not needed for compatibility checking
        pass

    def visit_extern_rule_reference(self, node):
        # Not needed for compatibility checking
        pass

    def visit_for_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_for_of_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_function_call(self, node):
        # Not needed for compatibility checking
        pass

    def visit_hex_alternative(self, node):
        # Not needed for compatibility checking
        pass

    def visit_hex_byte(self, node):
        # Not needed for compatibility checking
        pass

    def visit_hex_nibble(self, node):
        # Not needed for compatibility checking
        pass

    def visit_hex_token(self, node):
        # Not needed for compatibility checking
        pass

    def visit_hex_wildcard(self, node):
        # Not needed for compatibility checking
        pass

    def visit_import(self, node):
        # Not needed for compatibility checking
        pass

    def visit_in_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_in_rule_pragma(self, node):
        # Not needed for compatibility checking
        pass

    def visit_include(self, node):
        # Not needed for compatibility checking
        pass

    def visit_integer_literal(self, node):
        # Not needed for compatibility checking
        pass

    def visit_member_access(self, node):
        # Not needed for compatibility checking
        pass

    def visit_meta(self, node):
        # Not needed for compatibility checking
        pass

    def visit_module_reference(self, node):
        # Not needed for compatibility checking
        pass

    def visit_parentheses_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_pragma(self, node):
        # Not needed for compatibility checking
        pass

    def visit_pragma_block(self, node):
        # Not needed for compatibility checking
        pass

    def visit_range_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_regex_literal(self, node):
        # Not needed for compatibility checking
        pass

    def visit_set_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_count(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_definition(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_identifier(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_length(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_literal(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_modifier(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_offset(self, node):
        # Not needed for compatibility checking
        pass

    def visit_string_operator_expression(self, node):
        # Not needed for compatibility checking
        pass

    def visit_tag(self, node):
        # Not needed for compatibility checking
        pass

    def visit_unary_expression(self, node):
        # Not needed for compatibility checking
        pass


# Alias for compatibility
CompatibilityChecker = YaraXCompatibilityChecker
