"""YARA-L specific AST nodes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from yaraast.ast.base import ASTNode, _require_nonempty_string, _VisitorType, require_string
from yaraast.regex_literals import escape_regex_delimiter

type YaraLValue = ASTNode | str | int | float | bool | None
type OutcomeValue = YaraLValue


class RawOutcomeExpression(str):
    """Source-preserving YARA-L outcome expression fragment."""


class RawConditionValue(str):
    """Source-preserving YARA-L condition comparison value."""


class StringLiteral(str):
    """YARA-L quoted string literal value.

    Distinguishes a parsed quoted-string value from a bare reference token
    (``$var`` / ``%list%``) so the generator always re-emits it quoted, even
    when its content begins with ``$`` or ``%``.
    """


def _register_yaml_str_representers() -> None:
    """Make YARA-L ``str`` marker subclasses YAML-serializable as plain strings.

    ``yaml.safe_dump`` rejects unknown ``str`` subclasses, which would crash any
    AST serialization (for example ``asdict`` output) that contains these source-
    preserving fragments. Representing them as plain strings keeps serialization
    lossless without leaking the internal marker types.
    """
    try:
        import yaml
    except ImportError:
        return

    representer = yaml.representer.SafeRepresenter.represent_str
    for marker in (RawOutcomeExpression, RawConditionValue, StringLiteral):
        yaml.SafeDumper.add_representer(marker, representer)


_register_yaml_str_representers()


def _validate_child_structure(node: ASTNode) -> None:
    node.validate_metadata()
    validate_structure = getattr(node, "validate_structure", None)
    if callable(validate_structure):
        validate_structure()


def _require_yaral_node(value: Any, field_name: str, node_type: type[Any], node_name: str) -> Any:
    if not isinstance(value, node_type):
        msg = f"{field_name} must be a {node_name}"
        raise TypeError(msg)
    _validate_child_structure(value)
    return value


def _require_optional_yaral_node(
    value: Any,
    field_name: str,
    node_type: type[Any],
    node_name: str,
) -> Any | None:
    if value is None:
        return None
    if not isinstance(value, node_type):
        msg = f"{field_name} must be an {node_name} or None"
        raise TypeError(msg)
    _validate_child_structure(value)
    return value


def _require_yaral_node_sequence(
    values: Any,
    field_name: str,
    node_type: type[Any],
    node_name: str,
) -> list[Any]:
    if not isinstance(values, list):
        msg = f"{field_name} must be a list"
        raise TypeError(msg)
    for value in values:
        if not isinstance(value, node_type):
            msg = f"{field_name} must contain {node_name} nodes"
            raise TypeError(msg)
        _validate_child_structure(value)
    return values


def _require_yaral_string_sequence(values: Any, field_name: str) -> list[str]:
    if not isinstance(values, list):
        msg = f"{field_name} must be a list"
        raise TypeError(msg)
    for value in values:
        _require_nonempty_string(value, f"{field_name} item")
    return values


def _require_yaral_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"{field_name} must be an integer"
        raise TypeError(msg)
    return int(value)


def _validate_yaral_value(value: Any, field_name: str) -> None:
    if value is None or isinstance(value, str | int | float | bool):
        return
    if isinstance(value, ASTNode):
        _validate_child_structure(value)
        return
    msg = f"{field_name} must be a YARA-L value"
    raise TypeError(msg)


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

    def validate_structure(self) -> None:
        """Validate YARA-L rule fields before generation or optimization."""
        self.validate_metadata()
        _require_nonempty_string(self.name, "YaraLRule name")
        _require_optional_yaral_node(self.meta, "YaraLRule meta", MetaSection, "MetaSection")
        _require_optional_yaral_node(
            self.events, "YaraLRule events", EventsSection, "EventsSection"
        )
        _require_optional_yaral_node(self.match, "YaraLRule match", MatchSection, "MatchSection")
        _require_optional_yaral_node(
            self.condition,
            "YaraLRule condition",
            ConditionSection,
            "ConditionSection",
        )
        _require_optional_yaral_node(
            self.outcome,
            "YaraLRule outcome",
            OutcomeSection,
            "OutcomeSection",
        )
        _require_optional_yaral_node(
            self.options,
            "YaraLRule options",
            OptionsSection,
            "OptionsSection",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_rule(self)

    @property
    def rule_type(self) -> str:
        """Classify rule as single-event or multi-event based on content."""
        if not self.events:
            return "single_event"
        event_vars = set()
        for stmt in self.events.statements:
            if hasattr(stmt, "event_var") and hasattr(stmt.event_var, "name"):
                event_vars.add(stmt.event_var.name)
        return "multi_event" if len(event_vars) > 1 else "single_event"


@dataclass
class MetaSection(ASTNode):
    """YARA-L meta section."""

    entries: list[MetaEntry] = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate YARA-L meta entries."""
        self.validate_metadata()
        _require_yaral_node_sequence(
            self.entries,
            "MetaSection entries",
            MetaEntry,
            "MetaEntry",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_meta_section(self)


@dataclass
class MetaEntry(ASTNode):
    """Meta entry (key-value pair)."""

    key: str
    value: str | int | bool

    def validate_structure(self) -> None:
        """Validate YARA-L meta entry scalar fields."""
        self.validate_metadata()
        _require_nonempty_string(self.key, "MetaEntry key")
        if not isinstance(self.value, str | int | bool):
            msg = "MetaEntry value must be a string, integer, or boolean"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_meta_entry(self)


@dataclass
class EventsSection(ASTNode):
    """YARA-L events section."""

    statements: list[EventStatement] = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate YARA-L event statements."""
        self.validate_metadata()
        _require_yaral_node_sequence(
            self.statements,
            "EventsSection statements",
            EventStatement,
            "EventStatement",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_events_section(self)


@dataclass
class EventStatement(ASTNode):
    """Single event statement."""

    text: str = field(default="", kw_only=True)

    def validate_structure(self) -> None:
        """Validate raw event statement fields."""
        self.validate_metadata()
        require_string(self.text, "EventStatement text")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_event_statement(self)


@dataclass
class EventAssignment(EventStatement):
    """Event field assignment: $e.field = value."""

    event_var: EventVariable
    field_path: UDMFieldPath
    operator: str  # =, !=, >, <, >=, <=, in, regex, etc.
    value: YaraLValue
    modifiers: list[str] = field(default_factory=list)  # nocase, etc.

    def validate_structure(self) -> None:
        """Validate event assignment structure."""
        super().validate_structure()
        _require_yaral_node(
            self.event_var,
            "EventAssignment event_var",
            EventVariable,
            "EventVariable",
        )
        _require_yaral_node(
            self.field_path,
            "EventAssignment field_path",
            UDMFieldPath,
            "UDMFieldPath",
        )
        _require_nonempty_string(self.operator, "EventAssignment operator")
        _validate_yaral_value(self.value, "EventAssignment value")
        _require_yaral_string_sequence(self.modifiers, "EventAssignment modifiers")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_event_assignment(self)


@dataclass
class EventVariable(ASTNode):
    """Event variable like $e, $e1, $login."""

    name: str

    def validate_structure(self) -> None:
        """Validate event variable fields."""
        self.validate_metadata()
        _require_nonempty_string(self.name, "EventVariable name")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_event_variable(self)


@dataclass
class UDMFieldPath(ASTNode):
    """UDM field path like metadata.event_type or principal.hostname."""

    parts: list[str]

    def validate_structure(self) -> None:
        """Validate UDM field path parts."""
        self.validate_metadata()
        _require_yaral_string_sequence(self.parts, "UDMFieldPath parts")

    @property
    def path(self) -> str:
        return _format_udm_field_path(self.parts)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_udm_field_path(self)


@dataclass
class UDMFieldAccess(ASTNode):
    """Access to UDM field with event variable."""

    event: EventVariable | None
    field: UDMFieldPath

    def validate_structure(self) -> None:
        """Validate UDM field access structure."""
        self.validate_metadata()
        _require_optional_yaral_node(
            self.event,
            "UDMFieldAccess event",
            EventVariable,
            "EventVariable",
        )
        _require_yaral_node(self.field, "UDMFieldAccess field", UDMFieldPath, "UDMFieldPath")

    @property
    def full_path(self) -> str:
        if self.event is None:
            return self.field.path
        return f"{self.event.name}.{self.field.path}"

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_udm_field_access(self)


def _format_udm_field_path(parts: list[str]) -> str:
    if not parts:
        return ""
    path = parts[0]
    for part in parts[1:]:
        if part.startswith("["):
            path += part
        else:
            path += f".{part}"
    return path


@dataclass
class ReferenceList(ASTNode):
    """Reference list like %suspicious_ips%."""

    name: str

    def validate_structure(self) -> None:
        """Validate reference list fields."""
        self.validate_metadata()
        _require_nonempty_string(self.name, "ReferenceList name")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_reference_list(self)


@dataclass
class MatchSection(ASTNode):
    """YARA-L match section for time windows."""

    variables: list[MatchVariable] = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate match variables."""
        self.validate_metadata()
        _require_yaral_node_sequence(
            self.variables,
            "MatchSection variables",
            MatchVariable,
            "MatchVariable",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_match_section(self)


@dataclass
class MatchVariable(ASTNode):
    """Match variable with time window."""

    variable: str  # Variable name (without $)
    time_window: TimeWindow
    grouping_field: UDMFieldAccess | None = None  # Field used for grouping

    def validate_structure(self) -> None:
        """Validate match variable fields."""
        self.validate_metadata()
        _require_nonempty_string(self.variable, "MatchVariable variable")
        _require_yaral_node(self.time_window, "MatchVariable time_window", TimeWindow, "TimeWindow")
        _require_optional_yaral_node(
            self.grouping_field,
            "MatchVariable grouping_field",
            UDMFieldAccess,
            "UDMFieldAccess",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_match_variable(self)


@dataclass
class TimeWindow(ASTNode):
    """Time window specification."""

    duration: int
    unit: str  # s, m, h, d
    modifier: str | None = None  # 'every' for grouped windows

    def validate_structure(self) -> None:
        """Validate time window scalar fields."""
        self.validate_metadata()
        _require_yaral_int(self.duration, "TimeWindow duration")
        _require_nonempty_string(self.unit, "TimeWindow unit")
        if self.modifier is not None:
            _require_nonempty_string(self.modifier, "TimeWindow modifier")

    @property
    def as_string(self) -> str:
        prefix = f"{self.modifier} " if self.modifier else ""
        return f"{prefix}{self.duration}{self.unit}"

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_time_window(self)


@dataclass
class ConditionSection(ASTNode):
    """YARA-L condition section."""

    expression: ConditionExpression | None

    def validate_structure(self) -> None:
        """Validate condition section."""
        self.validate_metadata()
        _require_optional_yaral_node(
            self.expression,
            "ConditionSection expression",
            ConditionExpression,
            "ConditionExpression",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_condition_section(self)


@dataclass
class ConditionExpression(ASTNode):
    """Base class for condition expressions."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_condition_expression(self)


@dataclass
class BinaryCondition(ConditionExpression):
    """Binary condition (AND, OR)."""

    operator: str  # and, or
    left: ConditionExpression
    right: ConditionExpression

    def validate_structure(self) -> None:
        """Validate binary condition fields."""
        self.validate_metadata()
        _require_nonempty_string(self.operator, "BinaryCondition operator")
        _validate_yaral_value(self.left, "BinaryCondition left")
        _validate_yaral_value(self.right, "BinaryCondition right")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_binary_condition(self)


@dataclass
class UnaryCondition(ConditionExpression):
    """Unary condition (NOT)."""

    operator: str  # not
    operand: ConditionExpression | None

    def validate_structure(self) -> None:
        """Validate unary condition fields."""
        self.validate_metadata()
        _require_nonempty_string(self.operator, "UnaryCondition operator")
        _require_optional_yaral_node(
            self.operand,
            "UnaryCondition operand",
            ConditionExpression,
            "ConditionExpression",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_unary_condition(self)


@dataclass
class EventCountCondition(ConditionExpression):
    """Event count condition like #e > 5."""

    event: str  # Event variable name (without $)
    operator: str  # >, <, >=, <=, ==, !=
    count: int

    def validate_structure(self) -> None:
        """Validate event count condition fields."""
        self.validate_metadata()
        _require_nonempty_string(self.event, "EventCountCondition event")
        _require_nonempty_string(self.operator, "EventCountCondition operator")
        _require_yaral_int(self.count, "EventCountCondition count")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_event_count_condition(self)


@dataclass
class EventExistsCondition(ConditionExpression):
    """Check if event exists: $e1."""

    event: str  # Event variable name

    def validate_structure(self) -> None:
        """Validate event existence condition fields."""
        self.validate_metadata()
        _require_nonempty_string(self.event, "EventExistsCondition event")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_event_exists_condition(self)


@dataclass
class VariableComparisonCondition(ConditionExpression):
    """Variable comparison condition like $var > 5 or $dc_count > 3."""

    variable: str  # Variable name (with or without $)
    operator: str  # >, <, >=, <=, ==, !=
    value: Any  # Comparison value

    def validate_structure(self) -> None:
        """Validate variable comparison condition fields."""
        self.validate_metadata()
        _require_nonempty_string(self.variable, "VariableComparisonCondition variable")
        _require_nonempty_string(self.operator, "VariableComparisonCondition operator")
        _validate_yaral_value(self.value, "VariableComparisonCondition value")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_variable_comparison_condition(self)


@dataclass
class JoinCondition(ConditionExpression):
    """Join condition between events."""

    left_event: str
    right_event: str
    join_type: str = "inner"  # inner, left, right, full

    def validate_structure(self) -> None:
        """Validate join condition fields."""
        self.validate_metadata()
        _require_nonempty_string(self.left_event, "JoinCondition left_event")
        _require_nonempty_string(self.right_event, "JoinCondition right_event")
        _require_nonempty_string(self.join_type, "JoinCondition join_type")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_join_condition(self)


@dataclass
class NOfCondition(ConditionExpression):
    """Quantified event matching: N of ($e1, $e2, $e3)."""

    count: int
    events: list[str]

    def validate_structure(self) -> None:
        """Validate N-of condition fields."""
        self.validate_metadata()
        _require_yaral_int(self.count, "NOfCondition count")
        _require_yaral_string_sequence(self.events, "NOfCondition events")

    def accept(self, visitor: _VisitorType) -> Any:
        if hasattr(visitor, "visit_yaral_n_of_condition"):
            return visitor.visit_yaral_n_of_condition(self)
        return visitor.visit_yaral_condition_expression(self)


@dataclass
class NullCheckCondition(ConditionExpression):
    """Null check: field is null / field is not null."""

    field: Any  # UDMFieldAccess
    negated: bool = False  # True for 'is not null'

    def validate_structure(self) -> None:
        """Validate null check condition fields."""
        self.validate_metadata()
        if not isinstance(self.field, UDMFieldAccess | str):
            msg = "NullCheckCondition field must be a UDMFieldAccess or string"
            raise TypeError(msg)
        if isinstance(self.field, UDMFieldAccess):
            self.field.validate_structure()
        else:
            _require_nonempty_string(self.field, "NullCheckCondition field")
        if not isinstance(self.negated, bool):
            msg = "NullCheckCondition negated must be a boolean"
            raise TypeError(msg)

    def accept(self, visitor: _VisitorType) -> Any:
        if hasattr(visitor, "visit_yaral_null_check_condition"):
            return visitor.visit_yaral_null_check_condition(self)
        return visitor.visit_yaral_condition_expression(self)


@dataclass
class OutcomeSection(ASTNode):
    """YARA-L outcome section for extracting data."""

    assignments: list[OutcomeAssignment] = field(default_factory=list)

    def validate_structure(self) -> None:
        """Validate outcome assignments."""
        self.validate_metadata()
        _require_yaral_node_sequence(
            self.assignments,
            "OutcomeSection assignments",
            OutcomeAssignment,
            "OutcomeAssignment",
        )

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_outcome_section(self)


@dataclass
class OutcomeAssignment(ASTNode):
    """Outcome variable assignment."""

    variable: str  # Variable name (with $)
    expression: OutcomeValue

    def validate_structure(self) -> None:
        """Validate outcome assignment fields."""
        self.validate_metadata()
        _require_nonempty_string(self.variable, "OutcomeAssignment variable")
        _validate_yaral_value(self.expression, "OutcomeAssignment expression")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_outcome_assignment(self)


@dataclass
class OutcomeExpression(ASTNode):
    """Base class for outcome expressions."""

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_outcome_expression(self)


@dataclass
class AggregationFunction(OutcomeExpression):
    """Aggregation function call."""

    function: str  # count, count_distinct, sum, min, max, array, etc.
    arguments: list[YaraLValue]

    def validate_structure(self) -> None:
        """Validate aggregation function fields."""
        self.validate_metadata()
        _require_nonempty_string(self.function, "AggregationFunction function")
        if not isinstance(self.arguments, list):
            msg = "AggregationFunction arguments must be a list"
            raise TypeError(msg)
        for argument in self.arguments:
            _validate_yaral_value(argument, "AggregationFunction argument")

    @property
    def call_string(self) -> str:
        args = ", ".join(_format_yaral_call_argument(arg) for arg in self.arguments)
        return f"{self.function}({args})"

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_aggregation_function(self)


@dataclass
class ConditionalExpression(OutcomeExpression):
    """Conditional expression: if(condition, true_value, false_value)."""

    condition: Any  # Can be various condition types
    true_value: Any
    false_value: Any

    def validate_structure(self) -> None:
        """Validate conditional outcome expression fields."""
        self.validate_metadata()
        _validate_yaral_value(self.condition, "ConditionalExpression condition")
        _validate_yaral_value(self.true_value, "ConditionalExpression true_value")
        _validate_yaral_value(self.false_value, "ConditionalExpression false_value")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_conditional_expression(self)


@dataclass
class ArithmeticExpression(OutcomeExpression):
    """Arithmetic expression."""

    operator: str  # +, -, *, /
    left: Any
    right: Any

    def validate_structure(self) -> None:
        """Validate arithmetic expression fields."""
        self.validate_metadata()
        _require_nonempty_string(self.operator, "ArithmeticExpression operator")
        _validate_yaral_value(self.left, "ArithmeticExpression left")
        _validate_yaral_value(self.right, "ArithmeticExpression right")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_arithmetic_expression(self)


@dataclass
class OptionsSection(ASTNode):
    """YARA-L options section."""

    options: dict[str, Any] = field(default_factory=dict)

    def validate_structure(self) -> None:
        """Validate options section fields."""
        self.validate_metadata()
        if not isinstance(self.options, dict):
            msg = "OptionsSection options must be a dictionary"
            raise TypeError(msg)
        for key, value in self.options.items():
            _require_nonempty_string(key, "OptionsSection option key")
            _validate_yaral_value(value, "OptionsSection option value")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_options_section(self)


@dataclass
class RegexPattern(ASTNode):
    """Regex pattern with optional flags."""

    pattern: str
    flags: list[str] = field(default_factory=list)  # nocase, etc.

    def validate_structure(self) -> None:
        """Validate regex pattern fields."""
        self.validate_metadata()
        require_string(self.pattern, "RegexPattern pattern")
        _require_yaral_string_sequence(self.flags, "RegexPattern flags")

    @property
    def as_string(self) -> str:
        inline_flags = "".join(flag for flag in self.flags if len(flag) == 1)
        word_flags = [flag for flag in self.flags if len(flag) > 1]
        pattern = escape_regex_delimiter(self.pattern)
        rendered = f"/{pattern}/{inline_flags}"
        if word_flags:
            rendered = f"{rendered} {' '.join(word_flags)}"
        return rendered

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_regex_pattern(self)


@dataclass
class CIDRExpression(ASTNode):
    """CIDR expression for IP matching."""

    field: UDMFieldAccess
    cidr: str  # e.g., "192.168.1.0/24"

    def validate_structure(self) -> None:
        """Validate CIDR expression fields."""
        self.validate_metadata()
        _require_yaral_node(self.field, "CIDRExpression field", UDMFieldAccess, "UDMFieldAccess")
        _require_nonempty_string(self.cidr, "CIDRExpression cidr")

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_cidr_expression(self)


@dataclass
class FunctionCall(ASTNode):
    """Function call like re.regex() or cidr()."""

    function: str
    arguments: list[Any]

    def validate_structure(self) -> None:
        """Validate function call fields."""
        self.validate_metadata()
        _require_nonempty_string(self.function, "FunctionCall function")
        if not isinstance(self.arguments, list):
            msg = "FunctionCall arguments must be a list"
            raise TypeError(msg)
        for argument in self.arguments:
            _validate_yaral_value(argument, "FunctionCall argument")

    @property
    def call_string(self) -> str:
        args = ", ".join(_format_yaral_call_argument(arg) for arg in self.arguments)
        return f"{self.function}({args})"

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_function_call(self)


def _format_yaral_call_argument(value: Any) -> str:
    if isinstance(value, UDMFieldAccess):
        return value.full_path
    if isinstance(value, EventVariable):
        return value.name
    if isinstance(value, RegexPattern):
        return value.as_string
    if isinstance(value, AggregationFunction | FunctionCall):
        return value.call_string
    return str(value)


@dataclass
class YaraLFile(ASTNode):
    """YARA-L file containing multiple rules."""

    rules: list[YaraLRule] = field(default_factory=list)

    def validate_structure(self, *, deep: bool = True) -> None:
        """Validate YARA-L file fields before traversal."""
        self.validate_metadata()
        rules = _require_yaral_node_sequence(
            self.rules,
            "YaraLFile rules",
            YaraLRule,
            "YaraLRule",
        )
        if deep:
            for rule in rules:
                rule.validate_structure()

    def add_rule(self, rule: YaraLRule) -> None:
        """Add a rule to the file."""
        if not isinstance(rule, YaraLRule):
            msg = "YaraL rule input must be a YaraLRule"
            raise TypeError(msg)
        self.rules.append(rule)

    def accept(self, visitor: _VisitorType) -> Any:
        return visitor.visit_yaral_file(self)


# YARA-L 2.0 built-in functions registry for validation and completion
YARAL_BUILTIN_FUNCTIONS: dict[str, dict[str, str]] = {
    # String functions (Gap 1)
    "strings.concat": {"args": "str, str, ...", "returns": "string", "doc": "Concatenate strings"},
    "strings.to_lower": {"args": "str", "returns": "string", "doc": "Convert to lowercase"},
    "strings.to_upper": {"args": "str", "returns": "string", "doc": "Convert to uppercase"},
    "strings.base64_decode": {"args": "str", "returns": "string", "doc": "Decode base64 string"},
    "strings.coalesce": {
        "args": "str, str, ...",
        "returns": "string",
        "doc": "Return first non-empty string",
    },
    # Regex functions (Gap 2)
    "re.regex": {
        "args": "field, pattern",
        "returns": "bool",
        "doc": "Match regex pattern against field",
    },
    "re.capture": {
        "args": "field, pattern",
        "returns": "string",
        "doc": "Capture regex group from field",
    },
    # Timestamp functions (Gap 3)
    "timestamp.get_date": {
        "args": "timestamp, timezone",
        "returns": "string",
        "doc": "Get date string from timestamp",
    },
    "timestamp.get_hour": {
        "args": "timestamp",
        "returns": "integer",
        "doc": "Get hour from timestamp",
    },
    "timestamp.get_minute": {
        "args": "timestamp",
        "returns": "integer",
        "doc": "Get minute from timestamp",
    },
    "timestamp.get_second": {
        "args": "timestamp",
        "returns": "integer",
        "doc": "Get second from timestamp",
    },
    "timestamp.get_day_of_week": {
        "args": "timestamp",
        "returns": "integer",
        "doc": "Get day of week (1=Monday)",
    },
    "timestamp.get_week": {"args": "timestamp", "returns": "integer", "doc": "Get ISO week number"},
    "timestamp.current_timestamp": {"args": "", "returns": "timestamp", "doc": "Current time"},
    # Array functions (Gap 4)
    "arrays.length": {"args": "array", "returns": "integer", "doc": "Get array length"},
    "arrays.contains": {
        "args": "array, value",
        "returns": "bool",
        "doc": "Check if array contains value",
    },
    # Math functions (Gap 5)
    "math.abs": {"args": "number", "returns": "number", "doc": "Absolute value"},
    "math.log": {"args": "number", "returns": "float", "doc": "Natural logarithm"},
    "math.round": {"args": "number, decimals", "returns": "float", "doc": "Round to N decimals"},
    # Network functions (Gap 6)
    "net.ip_in_range_cidr": {
        "args": "ip, cidr",
        "returns": "bool",
        "doc": "Check if IP is in CIDR range",
    },
    # Aggregation functions (used in outcome)
    "count": {"args": "field", "returns": "integer", "doc": "Count occurrences"},
    "count_distinct": {"args": "field", "returns": "integer", "doc": "Count distinct values"},
    "sum": {"args": "field", "returns": "number", "doc": "Sum values"},
    "avg": {"args": "field", "returns": "number", "doc": "Average value"},
    "min": {"args": "field", "returns": "number", "doc": "Minimum value"},
    "max": {"args": "field", "returns": "number", "doc": "Maximum value"},
    "array": {"args": "field", "returns": "array", "doc": "Values as array"},
    "array_distinct": {"args": "field", "returns": "array", "doc": "Distinct values as array"},
    "earliest": {"args": "field", "returns": "any", "doc": "Earliest value"},
    "latest": {"args": "field", "returns": "any", "doc": "Latest value"},
    "string_concat": {"args": "field", "returns": "string", "doc": "Concatenate string values"},
}
