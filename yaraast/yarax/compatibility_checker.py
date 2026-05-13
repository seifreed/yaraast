"""YARA-X compatibility checker."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from yaraast.ast.expressions import BinaryExpression, Identifier, SetExpression
from yaraast.visitor import DefaultASTVisitor
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
    ) -> None:
        self.severity = severity  # "error", "warning", "info"
        self.location = location
        self.issue_type = issue_type
        self.message = message
        self.suggestion = suggestion

    def __str__(self) -> str:
        loc = f"{self.location.line}:{self.location.column}" if self.location else "unknown"
        return f"[{self.severity.upper()}] {loc}: {self.message}"


class YaraXCompatibilityChecker(DefaultASTVisitor[None]):
    """Check YARA rules for YARA-X compatibility."""

    def __init__(self, features: YaraXFeatures | None = None) -> None:
        super().__init__(default=None)
        self.features = features or YaraXFeatures.yarax_strict()
        self.issues: list[CompatibilityIssue] = []
        self.current_rule: str | None = None
        self._reported_yarax_features: set[str] = set()

    def check(self, yara_file: YaraFile) -> list[CompatibilityIssue]:
        """Check YARA file for compatibility issues."""
        self.issues.clear()
        self._reported_yarax_features.clear()
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
            ),
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
        has_base64 = any(
            self._modifier_name(modifier) in ("base64", "base64wide") for modifier in node.modifiers
        )
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
        has_xor = any(self._modifier_name(modifier) == "xor" for modifier in node.modifiers)
        has_fullword = any(
            self._modifier_name(modifier) == "fullword" for modifier in node.modifiers
        )

        if (
            has_xor
            and has_fullword
            and self.features.strict_xor_fullword
            and not self._has_alnum_boundaries(node.value)
        ):
            self._add_issue(
                "warning",
                "xor_fullword_boundary",
                f"String '{node.value}' with XOR and fullword may have stricter boundary checking in YARA-X",
                "Ensure string has proper alphanumeric boundaries",
                node.location,
            )

    def _modifier_name(self, modifier: object) -> str:
        return str(getattr(modifier, "name", modifier))

    def _has_alnum_boundaries(self, value: str | bytes) -> bool:
        if isinstance(value, bytes):
            return (
                bool(value) and self._is_ascii_alnum(value[0]) and self._is_ascii_alnum(value[-1])
            )
        return re.match(r"^[a-zA-Z0-9].*[a-zA-Z0-9]$", value) is not None

    def _is_ascii_alnum(self, value: int) -> bool:
        return 48 <= value <= 57 or 65 <= value <= 90 or 97 <= value <= 122

    def visit_regex_string(self, node: RegexString) -> None:
        """Check regex string compatibility."""
        if self.features.strict_regex_escaping:
            self._check_unescaped_braces(node)

        if self.features.validate_escape_sequences:
            self._check_invalid_escape_sequences(node)

    def _check_unescaped_braces(self, node: RegexString) -> None:
        """Check for unescaped { outside of repetition."""
        pattern = node.regex
        i = 0
        while i < len(pattern):
            if pattern[i] == "\\":
                # Skip escaped character
                i += 2
                continue
            if pattern[i] == "{" and not self._is_valid_quantifier(pattern, i):
                self._add_issue(
                    "error",
                    "unescaped_brace",
                    f"Unescaped '{{' in regex pattern at position {i}",
                    "Escape the brace with '\\{'",
                    node.location,
                )
            i += 1

    def _is_valid_quantifier(self, pattern: str, start_pos: int) -> bool:
        """Check if brace at position is part of a valid quantifier."""
        j = start_pos + 1
        if j >= len(pattern):
            return False

        # Skip initial digits
        if not self._skip_digits(pattern, j):
            return False
        j = self._get_position_after_digits(pattern, j)

        if j >= len(pattern):
            return False

        # Check patterns: {n}, {n,}, {n,m}
        if pattern[j] == "}":
            return True  # {n} pattern

        if pattern[j] == "," and j + 1 < len(pattern):
            j += 1
            if pattern[j] == "}":
                return True  # {n,} pattern

            # Check for {n,m} pattern
            if self._skip_digits(pattern, j):
                j = self._get_position_after_digits(pattern, j)
                return j < len(pattern) and pattern[j] == "}"

        return False

    def _skip_digits(self, pattern: str, pos: int) -> bool:
        """Check if position starts with digits."""
        return pos < len(pattern) and pattern[pos].isdigit()

    def _get_position_after_digits(self, pattern: str, start_pos: int) -> int:
        """Get position after consuming all digits."""
        pos = start_pos
        while pos < len(pattern) and pattern[pos].isdigit():
            pos += 1
        return pos

    def _check_invalid_escape_sequences(self, node: RegexString) -> None:
        """Check for invalid escape sequences in regex."""
        invalid_escapes = re.findall(
            r"\\([^\\abfnrtv0-7xdDsSwWbBuU<>.*+?{}()\[\]|^$])",
            node.regex,
        )
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
        if self.features.allow_tuple_of_expressions and isinstance(
            node.string_set,
            SetExpression,
        ):
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

        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)

    def _visit_ast_value(self, value: Any) -> None:
        if hasattr(value, "accept"):
            self.visit(value)
        elif isinstance(value, list | tuple):
            for item in value:
                self._visit_ast_value(item)

    def _is_yara_compatibility_mode(self) -> bool:
        return not self.features.modular_parser

    def _add_yarax_feature(self, feature: str, node: Any, suggestion: str = "") -> None:
        if not self._is_yara_compatibility_mode() or feature in self._reported_yarax_features:
            return
        self._reported_yarax_features.add(feature)
        self._add_issue(
            "error",
            "yarax_feature",
            f"Using YARA-X feature: {feature}",
            suggestion or "Rewrite without YARA-X-specific syntax for YARA compatibility",
            getattr(node, "location", None),
        )

    def visit_with_statement(self, node) -> None:
        """Check YARA-X with statement compatibility."""
        if not self.features.allow_with_statement:
            self._add_yarax_feature(
                "with statements",
                node,
                "Inline the declarations or rewrite the condition without with-statements",
            )
        for declaration in node.declarations:
            self.visit(declaration)
        self.visit(node.body)

    def visit_with_declaration(self, node) -> None:
        self._visit_ast_value(node.value)

    def visit_binary_expression(self, node) -> None:
        self._visit_ast_value(node.left)
        self._visit_ast_value(node.right)

    def visit_unary_expression(self, node) -> None:
        self._visit_ast_value(node.operand)

    def visit_parentheses_expression(self, node) -> None:
        self._visit_ast_value(node.expression)

    def visit_set_expression(self, node) -> None:
        self._visit_ast_value(node.elements)

    def visit_range_expression(self, node) -> None:
        self._visit_ast_value(node.low)
        self._visit_ast_value(node.high)

    def visit_function_call(self, node) -> None:
        self._visit_ast_value(node.arguments)

    def visit_array_access(self, node) -> None:
        self._visit_ast_value(node.array)
        self._visit_ast_value(node.index)

    def visit_member_access(self, node) -> None:
        self._visit_ast_value(node.object)

    def visit_dictionary_access(self, node) -> None:
        self._visit_ast_value(node.object)
        self._visit_ast_value(node.key)

    def visit_defined_expression(self, node) -> None:
        self._visit_ast_value(node.expression)

    def visit_string_operator_expression(self, node) -> None:
        self._visit_ast_value(node.left)
        self._visit_ast_value(node.right)

    def visit_for_expression(self, node) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.body)

    def visit_for_of_expression(self, node) -> None:
        self._visit_ast_value(node.quantifier)
        self._visit_ast_value(node.string_set)
        self._visit_ast_value(node.condition)

    def visit_at_expression(self, node) -> None:
        self._visit_ast_value(node.offset)

    def visit_in_expression(self, node) -> None:
        self._visit_ast_value(node.subject)
        self._visit_ast_value(node.range)

    def visit_array_comprehension(self, node) -> None:
        self._add_yarax_feature("array comprehensions", node)
        self._visit_ast_value(node.expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)

    def visit_dict_comprehension(self, node) -> None:
        self._add_yarax_feature("dict comprehensions", node)
        self._visit_ast_value(node.key_expression)
        self._visit_ast_value(node.value_expression)
        self._visit_ast_value(node.iterable)
        self._visit_ast_value(node.condition)

    def visit_tuple_expression(self, node) -> None:
        self._add_yarax_feature("tuple expressions", node)
        self._visit_ast_value(node.elements)

    def visit_tuple_indexing(self, node) -> None:
        self._add_yarax_feature("tuple indexing", node)
        self._visit_ast_value(node.tuple_expr)
        self._visit_ast_value(node.index)

    def visit_list_expression(self, node) -> None:
        self._add_yarax_feature("list expressions", node)
        self._visit_ast_value(node.elements)

    def visit_dict_expression(self, node) -> None:
        self._add_yarax_feature("dict expressions", node)
        self._visit_ast_value(node.items)

    def visit_dict_item(self, node) -> None:
        self._visit_ast_value(node.key)
        self._visit_ast_value(node.value)

    def visit_slice_expression(self, node) -> None:
        self._add_yarax_feature("slice expressions", node)
        self._visit_ast_value(node.target)
        self._visit_ast_value(node.start)
        self._visit_ast_value(node.stop)
        self._visit_ast_value(node.step)

    def visit_lambda_expression(self, node) -> None:
        self._add_yarax_feature("lambda expressions", node)
        self._visit_ast_value(node.body)

    def visit_pattern_match(self, node) -> None:
        self._add_yarax_feature("pattern matching", node)
        self._visit_ast_value(node.value)
        self._visit_ast_value(node.cases)
        self._visit_ast_value(node.default)

    def visit_match_case(self, node) -> None:
        self._visit_ast_value(node.pattern)
        self._visit_ast_value(node.result)

    def visit_spread_operator(self, node) -> None:
        self._add_yarax_feature("spread operators", node)
        self._visit_ast_value(node.expression)

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
    def visit_yara_file(self, node) -> None:
        """Visit YARA file."""
        for rule in node.rules:
            self.visit(rule)
