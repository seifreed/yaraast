"""YARA-L semantic validator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from yaraast.yaral.validator_conditions import ConditionValidationMixin
from yaraast.yaral.validator_events import EventValidationMixin
from yaraast.yaral.validator_match import MatchValidationMixin
from yaraast.yaral.validator_meta import MetaValidationMixin
from yaraast.yaral.validator_options import OptionsValidationMixin
from yaraast.yaral.validator_outcomes import OutcomeValidationMixin
from yaraast.yaral.validator_rules import RuleValidationMixin
from yaraast.yaral.visitor_base import YaraLVisitor

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import YaraLFile


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


class YaraLValidator(
    RuleValidationMixin,
    EventValidationMixin,
    MatchValidationMixin,
    ConditionValidationMixin,
    OutcomeValidationMixin,
    OptionsValidationMixin,
    MetaValidationMixin,
    YaraLVisitor[None],
):
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
