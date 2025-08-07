"""YARA-L semantic validator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        EventAssignment,
        EventsSection,
        EventStatement,
        EventVariable,
        MatchSection,
        UDMFieldPath,
        YaraLFile,
        YaraLRule,
    )


@dataclass
class ValidationError:
    """Represents a validation error in YARA-L rules."""

    severity: str  # "error", "warning", "info"
    rule_name: str
    section: str
    message: str
    suggestion: str = ""

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.rule_name}/{self.section}: {self.message}"


class YaraLValidator(ASTVisitor[None]):
    """Semantic validator for YARA-L rules."""

    # Valid UDM fields for different event types
    VALID_UDM_FIELDS = {
        "metadata": [
            "event_type",
            "event_timestamp",
            "product_name",
            "vendor_name",
            "description",
            "product_version",
            "product_event_type",
            "ingested_timestamp",
        ],
        "principal": [
            "hostname",
            "ip",
            "port",
            "mac",
            "user",
            "process",
            "file",
            "user_id",
            "email",
            "domain",
            "asset_id",
            "location",
        ],
        "target": [
            "hostname",
            "ip",
            "port",
            "mac",
            "user",
            "process",
            "file",
            "user_id",
            "email",
            "domain",
            "asset_id",
            "url",
            "resource",
        ],
        "observer": ["hostname", "ip", "port", "mac", "asset_id", "location"],
        "src": ["ip", "port", "mac", "hostname", "location", "country", "region"],
        "dst": ["ip", "port", "mac", "hostname", "location", "country", "region"],
        "network": [
            "application_protocol",
            "direction",
            "ip_protocol",
            "received_bytes",
            "sent_bytes",
            "session_duration",
            "session_id",
        ],
        "security_result": [
            "action",
            "category",
            "confidence",
            "severity",
            "rule_name",
            "detection_fields",
            "summary",
            "action_details",
        ],
        "about": ["file", "process", "user", "resource", "labels"],
    }

    # Valid aggregation functions
    VALID_AGGREGATIONS = [
        "count",
        "count_distinct",
        "sum",
        "avg",
        "min",
        "max",
        "array",
        "array_distinct",
        "string_concat",
    ]

    # Valid time units for windows
    VALID_TIME_UNITS = ["s", "m", "h", "d", "seconds", "minutes", "hours", "days"]

    def __init__(self) -> None:
        """Initialize validator."""
        self.errors: list[ValidationError] = []
        self.warnings: list[ValidationError] = []
        self.current_rule: str | None = None
        self.defined_events: set[str] = set()
        self.used_events: set[str] = set()
        self.defined_match_vars: set[str] = set()
        self.used_match_vars: set[str] = set()
        self.defined_outcome_vars: set[str] = set()

    def validate(self, ast: YaraLFile) -> tuple[list[ValidationError], list[ValidationError]]:
        """Validate YARA-L file and return errors and warnings.

        Args:
            ast: YARA-L AST to validate

        Returns:
            Tuple of (errors, warnings)
        """
        self.errors.clear()
        self.warnings.clear()
        self.visit(ast)
        return self.errors, self.warnings

    def _add_error(self, section: str, message: str, suggestion: str = "") -> None:
        """Add validation error."""
        self.errors.append(
            ValidationError(
                severity="error",
                rule_name=self.current_rule or "unknown",
                section=section,
                message=message,
                suggestion=suggestion,
            )
        )

    def _add_warning(self, section: str, message: str, suggestion: str = "") -> None:
        """Add validation warning."""
        self.warnings.append(
            ValidationError(
                severity="warning",
                rule_name=self.current_rule or "unknown",
                section=section,
                message=message,
                suggestion=suggestion,
            )
        )

    def visit_yaral_file(self, node: YaraLFile) -> None:
        """Validate YARA-L file."""
        if not node.rules:
            self._add_warning("file", "Empty YARA-L file")

        rule_names = set()
        for rule in node.rules:
            if rule.name in rule_names:
                self._add_error(
                    "file",
                    f"Duplicate rule name: {rule.name}",
                    "Use unique names for each rule",
                )
            rule_names.add(rule.name)
            self.visit(rule)

    def visit_yaral_rule(self, node: YaraLRule) -> None:
        """Validate YARA-L rule."""
        self.current_rule = node.name
        self.defined_events.clear()
        self.used_events.clear()
        self.defined_match_vars.clear()
        self.used_match_vars.clear()
        self.defined_outcome_vars.clear()

        # Validate rule name
        if not node.name:
            self._add_error("rule", "Rule must have a name")
        elif not node.name[0].isalpha() and node.name[0] != "_":
            self._add_error(
                "rule",
                f"Rule name '{node.name}' must start with letter or underscore",
                "Use valid identifier format",
            )

        # Check required sections
        if not node.events:
            self._add_error(
                "rule",
                "Rule must have an events section",
                "Add 'events:' section to define event patterns",
            )

        if not node.condition:
            self._add_error(
                "rule",
                "Rule must have a condition section",
                "Add 'condition:' section to define matching conditions",
            )

        # Validate sections if present
        if node.meta:
            self._validate_meta_section(node.meta)

        if node.events:
            self.visit(node.events)

        if node.match:
            self._validate_match_section(node.match)

        if node.condition:
            self._validate_condition_section(node.condition)

        if node.outcome:
            self._validate_outcome_section(node.outcome)

        if node.options:
            self._validate_options_section(node.options)

        # Cross-section validation
        self._validate_cross_sections()

    def visit_events_section(self, node: EventsSection) -> None:
        """Validate events section."""
        if not node.statements:
            self._add_error(
                "events",
                "Events section cannot be empty",
                "Add at least one event statement",
            )

        for statement in node.statements:
            self.visit(statement)

    def visit_event_statement(self, node: EventStatement) -> None:
        """Validate event statement."""
        if node.event:
            self.visit(node.event)

        if not node.assignments:
            self._add_warning(
                "events",
                f"Event {node.event.name if node.event else 'unknown'} has no field assignments",
                "Add field assignments to constrain the event",
            )

        for assignment in node.assignments:
            self.visit(assignment)

    def visit_event_variable(self, node: EventVariable) -> None:
        """Validate event variable."""
        if not node.name.startswith("$"):
            self._add_error(
                "events",
                f"Event variable '{node.name}' must start with $",
                "Use format like $e, $e1, $event",
            )

        if node.name in self.defined_events:
            self._add_error(
                "events",
                f"Duplicate event variable: {node.name}",
                "Use unique event variable names",
            )

        self.defined_events.add(node.name)

    def visit_event_assignment(self, node: EventAssignment) -> None:
        """Validate event assignment."""
        # Validate field path
        if node.field_path:
            self._validate_udm_field_path(node.field_path)

        # Validate operator
        valid_operators = ["=", "!=", ">", "<", ">=", "<=", "=~", "!~"]
        if node.operator not in valid_operators:
            self._add_error(
                "events",
                f"Invalid operator '{node.operator}' in event assignment",
                f"Use one of: {', '.join(valid_operators)}",
            )

        # Validate regex operators
        if node.operator in ["=~", "!~"] and (
            not isinstance(node.value, str)
            or not (node.value.startswith("/") and node.value.endswith("/"))
        ):
            self._add_warning(
                "events",
                f"Regex operator {node.operator} should be used with regex pattern",
                "Use format: /pattern/",
            )

    def _validate_udm_field_path(self, node: UDMFieldPath) -> None:
        """Validate UDM field path."""
        if not node.parts:
            self._add_error("events", "Empty UDM field path")
            return

        # Check if first part is valid UDM namespace
        namespace = node.parts[0]
        if namespace not in self.VALID_UDM_FIELDS:
            self._add_warning(
                "events",
                f"Unknown UDM namespace: {namespace}",
                f"Valid namespaces: {', '.join(self.VALID_UDM_FIELDS.keys())}",
            )
        elif len(node.parts) > 1:
            # Check if field is valid for namespace
            field = node.parts[1]
            valid_fields = self.VALID_UDM_FIELDS[namespace]
            if field not in valid_fields:
                self._add_warning(
                    "events",
                    f"Unknown field '{field}' for namespace '{namespace}'",
                    f"Valid fields: {', '.join(valid_fields[:5])}...",
                )

    def _validate_meta_section(self, node: Any) -> None:
        """Validate meta section."""
        required_meta = ["author", "description"]
        found_keys = set()

        if hasattr(node, "entries"):
            for entry in node.entries:
                found_keys.add(entry.key)

                # Validate specific meta fields
                if entry.key == "severity" and isinstance(entry.value, str):
                    valid_severities = [
                        "informational",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ]
                    if entry.value.lower() not in valid_severities:
                        self._add_warning(
                            "meta",
                            f"Invalid severity value: {entry.value}",
                            f"Use one of: {', '.join(valid_severities)}",
                        )

        # Check for recommended meta fields
        for key in required_meta:
            if key not in found_keys:
                self._add_warning(
                    "meta",
                    f"Missing recommended meta field: {key}",
                    f"Add '{key}' to meta section",
                )

    def _validate_match_section(self, node: MatchSection) -> None:
        """Validate match section."""
        if not node.variables:
            self._add_warning(
                "match",
                "Match section has no variables",
                "Define match variables for correlation",
            )

        for var in node.variables:
            if var.name in self.defined_match_vars:
                self._add_error(
                    "match",
                    f"Duplicate match variable: {var.name}",
                    "Use unique match variable names",
                )
            self.defined_match_vars.add(var.name)

        # Validate time window
        if (
            node.time_window
            and hasattr(node.time_window, "unit")
            and node.time_window.unit not in self.VALID_TIME_UNITS
        ):
            self._add_error(
                "match",
                f"Invalid time unit: {node.time_window.unit}",
                f"Use one of: {', '.join(self.VALID_TIME_UNITS)}",
            )

            if hasattr(node.time_window, "duration"):
                if node.time_window.duration <= 0:
                    self._add_error(
                        "match",
                        "Time window duration must be positive",
                        "Use positive duration value",
                    )
                elif node.time_window.duration > 30 and node.time_window.unit in [
                    "d",
                    "days",
                ]:
                    self._add_warning(
                        "match",
                        f"Large time window: {node.time_window.duration} {node.time_window.unit}",
                        "Consider using smaller time windows for better performance",
                    )

    def _validate_condition_section(self, node: Any) -> None:
        """Validate condition section."""
        if not hasattr(node, "expression") or not node.expression:
            self._add_error(
                "condition",
                "Condition section cannot be empty",
                "Add condition expression",
            )

        # Check for event references
        # This would need deeper AST traversal in a real implementation

    def _validate_outcome_section(self, node: Any) -> None:
        """Validate outcome section."""
        if hasattr(node, "variables"):
            for var_name in node.variables:
                if var_name in self.defined_outcome_vars:
                    self._add_error(
                        "outcome",
                        f"Duplicate outcome variable: {var_name}",
                        "Use unique outcome variable names",
                    )
                self.defined_outcome_vars.add(var_name)

                # Check for reserved names
                reserved = ["risk_score", "severity", "confidence"]
                if var_name not in reserved and not var_name.startswith("$"):
                    self._add_warning(
                        "outcome",
                        f"Outcome variable '{var_name}' should start with $ or use reserved name",
                        f"Reserved names: {', '.join(reserved)}",
                    )

    def _validate_options_section(self, node: Any) -> None:
        """Validate options section."""
        valid_options = [
            "allow_zero_values",
            "case_sensitive",
            "max_events",
            "max_matches",
            "timeout",
            "output_format",
        ]

        if hasattr(node, "options"):
            for key in node.options:
                if key not in valid_options:
                    self._add_warning(
                        "options",
                        f"Unknown option: {key}",
                        f"Valid options: {', '.join(valid_options)}",
                    )

    def _validate_cross_sections(self) -> None:
        """Validate cross-section references."""
        # Check if all used events are defined
        undefined_events = self.used_events - self.defined_events
        for event in undefined_events:
            self._add_error(
                "condition",
                f"Undefined event variable: {event}",
                "Define event in events section",
            )

        # Check if all defined events are used
        unused_events = self.defined_events - self.used_events
        for event in unused_events:
            self._add_warning(
                "events",
                f"Unused event variable: {event}",
                "Remove unused event or use it in condition",
            )

        # Check match variables usage
        unused_match_vars = self.defined_match_vars - self.used_match_vars
        for var in unused_match_vars:
            self._add_warning(
                "match",
                f"Unused match variable: {var}",
                "Remove unused variable or use it in outcome",
            )
