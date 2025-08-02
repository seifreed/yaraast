"""YARA-X compatibility checker."""

import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.conditions import (
    AtExpression,
    Condition,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    Expression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    UnaryExpression,
)
from yaraast.ast.meta import Meta
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
    StringModifier,
)
from yaraast.visitor import ASTVisitor
from yaraast.yarax.feature_flags import YaraXFeatures


class CompatibilityIssue:
    """Represents a compatibility issue between YARA and YARA-X."""

    def __init__(self, severity: str, location: Optional[Location],
                 issue_type: str, message: str, suggestion: str = ""):
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

    def __init__(self, features: Optional[YaraXFeatures] = None):
        self.features = features or YaraXFeatures.yarax_strict()
        self.issues: List[CompatibilityIssue] = []
        self.current_rule: Optional[str] = None

    def check(self, yara_file: YaraFile) -> List[CompatibilityIssue]:
        """Check YARA file for compatibility issues."""
        self.issues.clear()
        self.visit(yara_file)
        return self.issues

    def _add_issue(self, severity: str, issue_type: str, message: str,
                   suggestion: str = "", location: Optional[Location] = None):
        """Add a compatibility issue."""
        self.issues.append(CompatibilityIssue(
            severity=severity,
            location=location,
            issue_type=issue_type,
            message=message,
            suggestion=suggestion
        ))

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
                        node.location
                    )
                seen_modifiers.add(modifier)

        # Visit rule components
        for meta in node.meta:
            self.visit(meta)

        for string_def in node.strings:
            self.visit(string_def)

        self.visit(node.condition)

        self.current_rule = None

    def visit_plain_string(self, node: PlainString) -> None:
        """Check plain string compatibility."""
        # Check base64 modifier
        has_base64 = any(m.name in ("base64", "base64wide") for m in node.modifiers)
        if has_base64 and self.features.minimum_base64_length > 0:
            if len(node.value) < self.features.minimum_base64_length:
                self._add_issue(
                    "error",
                    "base64_too_short",
                    f"Base64 pattern '{node.value}' is shorter than minimum length {self.features.minimum_base64_length}",
                    f"Use a base64 pattern with at least {self.features.minimum_base64_length} characters",
                    node.location
                )

        # Check XOR with fullword
        has_xor = any(m.name == "xor" for m in node.modifiers)
        has_fullword = any(m.name == "fullword" for m in node.modifiers)

        if has_xor and has_fullword and self.features.strict_xor_fullword:
            # Check if string has alphanumeric boundaries
            if not re.match(r'^[a-zA-Z0-9].*[a-zA-Z0-9]$', node.value):
                self._add_issue(
                    "warning",
                    "xor_fullword_boundary",
                    f"String '{node.value}' with XOR and fullword may have stricter boundary checking in YARA-X",
                    "Ensure string has proper alphanumeric boundaries",
                    node.location
                )

    def visit_regex_string(self, node: RegexString) -> None:
        """Check regex string compatibility."""
        if self.features.strict_regex_escaping:
            # Check for unescaped { outside of repetition
            pattern = node.regex
            i = 0
            while i < len(pattern):
                if pattern[i] == '\\':
                    # Skip escaped character
                    i += 2
                    continue
                elif pattern[i] == '{':
                    # Check if this is part of a repetition {n,m}
                    if i == 0 or pattern[i-1] in '({|':
                        self._add_issue(
                            "error",
                            "unescaped_brace",
                            f"Unescaped '{{' in regex pattern",
                            "Escape the brace with '\\{'",
                            node.location
                        )
                i += 1

        if self.features.validate_escape_sequences:
            # Check for invalid escape sequences
            invalid_escapes = re.findall(r'\\([^\\abfnrtv0-7xdDsSwW.*+?{}()\[\]|^$])', node.regex)
            for escape in invalid_escapes:
                self._add_issue(
                    "error",
                    "invalid_escape",
                    f"Invalid escape sequence '\\{escape}' in regex",
                    f"Remove or fix the escape sequence",
                    node.location
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
        if self.features.allow_tuple_of_expressions:
            # This is a new feature, check if it's being used
            if isinstance(node.string_set, SetExpression):
                for elem in node.string_set.elements:
                    if isinstance(elem, BinaryExpression):
                        self._add_issue(
                            "info",
                            "yarax_feature",
                            "Using YARA-X feature: boolean expressions in 'of' statement",
                            "This feature is not available in original YARA",
                            node.location
                        )
                        break

        self.visit(node.quantifier)
        self.visit(node.string_set)

    def visit_identifier(self, node: Identifier) -> None:
        """Check for 'with' statement usage."""
        # The 'with' statement would be parsed differently, but we can detect attempts
        if node.name == "with" and self.current_rule:
            if not self.features.allow_with_statement:
                self._add_issue(
                    "error",
                    "unsupported_feature",
                    "'with' statement is only available in YARA-X",
                    "Rewrite without using 'with' statement for YARA compatibility",
                    node.location
                )

    def get_report(self) -> Dict[str, Any]:
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
            "migration_difficulty": self._assess_migration_difficulty()
        }

    def _group_by_type(self) -> Dict[str, List[CompatibilityIssue]]:
        """Group issues by type."""
        grouped = {}
        for issue in self.issues:
            if issue.issue_type not in grouped:
                grouped[issue.issue_type] = []
            grouped[issue.issue_type].append(issue)
        return grouped

    def _get_yarax_features_used(self) -> List[str]:
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
        elif errors == 0:
            return "easy"
        elif errors <= 5:
            return "moderate"
        else:
            return "difficult"
