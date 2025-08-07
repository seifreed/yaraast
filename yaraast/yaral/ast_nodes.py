"""YARA-L specific AST nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.ast.base import ASTNode


@dataclass
class YaraLRule(ASTNode):
    """YARA-L rule AST node."""

    name: str
    meta: MetaSection | None = None
    events: EventsSection | None = None
    match: MatchSection | None = None
    condition: ConditionSection | None = None
    outcome: OutcomeSection | None = None
    options: OptionsSection | None = None


@dataclass
class MetaSection(ASTNode):
    """YARA-L meta section."""

    entries: list[MetaEntry] = field(default_factory=list)


@dataclass
class MetaEntry(ASTNode):
    """Meta entry (key-value pair)."""

    key: str
    value: str | int | bool


@dataclass
class EventsSection(ASTNode):
    """YARA-L events section."""

    statements: list[EventStatement] = field(default_factory=list)


@dataclass
class EventStatement(ASTNode):
    """Single event statement."""


@dataclass
class EventAssignment(EventStatement):
    """Event field assignment: $e.field = value."""

    event_var: EventVariable
    field_path: UDMFieldPath
    operator: str  # =, !=, >, <, >=, <=, in, regex, etc.
    value: str | int | EventVariable | UDMFieldPath | ReferenceList
    modifiers: list[str] = field(default_factory=list)  # nocase, etc.


@dataclass
class EventVariable(ASTNode):
    """Event variable like $e, $e1, $login."""

    name: str


@dataclass
class UDMFieldPath(ASTNode):
    """UDM field path like metadata.event_type or principal.hostname."""

    parts: list[str]

    @property
    def path(self) -> str:
        return ".".join(self.parts)


@dataclass
class UDMFieldAccess(ASTNode):
    """Access to UDM field with event variable."""

    event: EventVariable
    field: UDMFieldPath

    @property
    def full_path(self) -> str:
        return f"{self.event.name}.{self.field.path}"


@dataclass
class ReferenceList(ASTNode):
    """Reference list like %suspicious_ips%."""

    name: str


@dataclass
class MatchSection(ASTNode):
    """YARA-L match section for time windows."""

    variables: list[MatchVariable] = field(default_factory=list)


@dataclass
class MatchVariable(ASTNode):
    """Match variable with time window."""

    variable: str  # Variable name (without $)
    time_window: TimeWindow


@dataclass
class TimeWindow(ASTNode):
    """Time window specification."""

    duration: int
    unit: str  # s, m, h, d
    modifier: str | None = None  # 'every' for grouped windows

    @property
    def as_string(self) -> str:
        prefix = f"{self.modifier} " if self.modifier else ""
        return f"{prefix}{self.duration}{self.unit}"


@dataclass
class ConditionSection(ASTNode):
    """YARA-L condition section."""

    expression: ConditionExpression


@dataclass
class ConditionExpression(ASTNode):
    """Base class for condition expressions."""


@dataclass
class BinaryCondition(ConditionExpression):
    """Binary condition (AND, OR)."""

    operator: str  # and, or
    left: ConditionExpression
    right: ConditionExpression


@dataclass
class UnaryCondition(ConditionExpression):
    """Unary condition (NOT)."""

    operator: str  # not
    operand: ConditionExpression


@dataclass
class EventCountCondition(ConditionExpression):
    """Event count condition like #e > 5."""

    event: str  # Event variable name (without $)
    operator: str  # >, <, >=, <=, ==, !=
    count: int


@dataclass
class EventExistsCondition(ConditionExpression):
    """Check if event exists: $e1."""

    event: str  # Event variable name


@dataclass
class JoinCondition(ConditionExpression):
    """Join condition between events."""

    left_event: str
    right_event: str
    join_type: str = "inner"  # inner, left, right, full


@dataclass
class OutcomeSection(ASTNode):
    """YARA-L outcome section for extracting data."""

    assignments: list[OutcomeAssignment] = field(default_factory=list)


@dataclass
class OutcomeAssignment(ASTNode):
    """Outcome variable assignment."""

    variable: str  # Variable name (with $)
    expression: OutcomeExpression


@dataclass
class OutcomeExpression(ASTNode):
    """Base class for outcome expressions."""


@dataclass
class AggregationFunction(OutcomeExpression):
    """Aggregation function call."""

    function: str  # count, count_distinct, sum, min, max, array, etc.
    arguments: list[UDMFieldAccess | str]

    @property
    def call_string(self) -> str:
        args = ", ".join(str(arg) for arg in self.arguments)
        return f"{self.function}({args})"


@dataclass
class ConditionalExpression(OutcomeExpression):
    """Conditional expression: if(condition, true_value, false_value)."""

    condition: Any  # Can be various condition types
    true_value: Any
    false_value: Any


@dataclass
class ArithmeticExpression(OutcomeExpression):
    """Arithmetic expression."""

    operator: str  # +, -, *, /
    left: Any
    right: Any


@dataclass
class OptionsSection(ASTNode):
    """YARA-L options section."""

    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class RegexPattern(ASTNode):
    """Regex pattern with optional flags."""

    pattern: str
    flags: list[str] = field(default_factory=list)  # nocase, etc.

    @property
    def as_string(self) -> str:
        flags_str = " ".join(self.flags) if self.flags else ""
        return f"/{self.pattern}/ {flags_str}".strip()


@dataclass
class CIDRExpression(ASTNode):
    """CIDR expression for IP matching."""

    field: UDMFieldAccess
    cidr: str  # e.g., "192.168.1.0/24"


@dataclass
class FunctionCall(ASTNode):
    """Function call like re.regex() or cidr()."""

    function: str
    arguments: list[Any]

    @property
    def call_string(self) -> str:
        args = ", ".join(str(arg) for arg in self.arguments)
        return f"{self.function}({args})"


@dataclass
class YaraLFile(ASTNode):
    """YARA-L file containing multiple rules."""

    rules: list[YaraLRule] = field(default_factory=list)

    def add_rule(self, rule: YaraLRule) -> None:
        """Add a rule to the file."""
        self.rules.append(rule)
