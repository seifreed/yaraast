from __future__ import annotations

from yaraast.lexer.tokens import TokenType as T
from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    CIDRExpression,
    ConditionalExpression,
    ConditionExpression,
    ConditionSection,
    EventAssignment,
    EventCountCondition,
    EventExistsCondition,
    EventsSection,
    EventStatement,
    EventVariable,
    FunctionCall,
    JoinCondition,
    MatchSection,
    MatchVariable,
    MetaEntry,
    MetaSection,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    VariableComparisonCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.lexer import YaraLLexer


class _Visitor:
    def visit_yaral_rule(self, node: YaraLRule) -> str:
        return node.name

    def visit_yaral_meta_section(self, node: MetaSection) -> int:
        return len(node.entries)

    def visit_yaral_meta_entry(self, node: MetaEntry) -> str:
        return f"{node.key}={node.value}"

    def visit_yaral_events_section(self, node: EventsSection) -> int:
        return len(node.statements)

    def visit_yaral_event_statement(self, node: EventStatement) -> str:
        return f"event:{node.__class__.__name__}"

    def visit_yaral_event_assignment(self, node: EventAssignment) -> str:
        return node.operator

    def visit_yaral_event_variable(self, node: EventVariable) -> str:
        return node.name

    def visit_yaral_udm_field_path(self, node: UDMFieldPath) -> str:
        return node.path

    def visit_yaral_udm_field_access(self, node: UDMFieldAccess) -> str:
        return node.full_path

    def visit_yaral_reference_list(self, node: ReferenceList) -> str:
        return node.name

    def visit_yaral_match_section(self, node: MatchSection) -> int:
        return len(node.variables)

    def visit_yaral_match_variable(self, node: MatchVariable) -> str:
        return node.variable

    def visit_yaral_time_window(self, node: TimeWindow) -> str:
        return node.as_string

    def visit_yaral_condition_section(self, node: ConditionSection):
        return node.expression

    def visit_yaral_condition_expression(self, node: ConditionExpression) -> str:
        return node.__class__.__name__

    def visit_yaral_unary_condition(self, node) -> str:
        return f"unary:{node.operator}"

    def visit_yaral_binary_condition(self, node) -> str:
        return node.operator

    def visit_yaral_event_count_condition(self, node: EventCountCondition) -> int:
        return node.count

    def visit_yaral_event_exists_condition(self, node: EventExistsCondition) -> str:
        return node.event

    def visit_yaral_variable_comparison_condition(
        self,
        node: VariableComparisonCondition,
    ) -> str:
        return f"cmp:{node.variable}{node.operator}{node.value}"

    def visit_yaral_join_condition(self, node: JoinCondition) -> str:
        return f"join:{node.left_event}:{node.right_event}:{node.join_type}"

    def visit_yaral_outcome_section(self, node: OutcomeSection) -> int:
        return len(node.assignments)

    def visit_yaral_outcome_assignment(self, node: OutcomeAssignment) -> str:
        return node.variable

    def visit_yaral_outcome_expression(self, node: OutcomeExpression) -> str:
        return node.__class__.__name__

    def visit_yaral_conditional_expression(
        self,
        node: ConditionalExpression,
    ) -> str:
        return f"if:{node.true_value}:{node.false_value}"

    def visit_yaral_aggregation_function(self, node: AggregationFunction) -> str:
        return node.call_string

    def visit_yaral_arithmetic_expression(self, node: ArithmeticExpression) -> str:
        return node.operator

    def visit_yaral_options_section(self, node) -> dict:
        return node.options

    def visit_yaral_regex_pattern(self, node: RegexPattern) -> str:
        return node.as_string

    def visit_yaral_cidr_expression(self, node: CIDRExpression) -> str:
        return node.cidr

    def visit_yaral_function_call(self, node: FunctionCall) -> str:
        return node.call_string

    def visit_yaral_file(self, node: YaraLFile) -> int:
        return len(node.rules)


def test_yaral_ast_nodes_accept_and_call_string_paths() -> None:
    from yaraast.yaral.ast_nodes import UnaryCondition

    visitor = _Visitor()

    assert YaraLRule(name="r").accept(visitor) == "r"
    assert MetaSection(entries=[MetaEntry(key="k", value=True)]).accept(visitor) == 1
    assert MetaEntry(key="k", value=1).accept(visitor) == "k=1"
    assert EventsSection(statements=[]).accept(visitor) == 0
    assert EventStatement().accept(visitor) == "event:EventStatement"
    event_var = EventVariable(name="$e")
    path = UDMFieldPath(parts=["metadata", "event_type"])
    access = UDMFieldAccess(event=event_var, field=path)
    assert (
        EventAssignment(event_var=event_var, field_path=path, operator="=", value="x").accept(
            visitor
        )
        == "="
    )
    assert event_var.accept(visitor) == "$e"
    assert path.accept(visitor) == "metadata.event_type"
    assert access.accept(visitor) == "$e.metadata.event_type"
    assert ReferenceList(name="%list%").accept(visitor) == "%list%"
    tw = TimeWindow(duration=5, unit="m", modifier="every")
    assert MatchSection(variables=[]).accept(visitor) == 0
    assert MatchVariable(variable="e", time_window=tw).accept(visitor) == "e"
    assert tw.accept(visitor) == "every 5m"
    expr = ConditionExpression()
    assert ConditionSection(expression=expr).accept(visitor) is expr
    assert expr.accept(visitor) == "ConditionExpression"
    assert UnaryCondition(operator="not", operand=object()).accept(visitor) == "unary:not"
    from yaraast.yaral.ast_nodes import BinaryCondition

    assert (
        BinaryCondition(
            operator="and", left=ConditionExpression(), right=ConditionExpression()
        ).accept(visitor)
        == "and"
    )
    assert EventCountCondition(event="e", operator=">", count=3).accept(visitor) == 3
    assert EventExistsCondition(event="$e").accept(visitor) == "$e"
    assert (
        VariableComparisonCondition(variable="$x", operator=">=", value=5).accept(visitor)
        == "cmp:$x>=5"
    )
    assert JoinCondition(left_event="$a", right_event="$b").accept(visitor) == "join:$a:$b:inner"
    assert OutcomeSection(assignments=[]).accept(visitor) == 0
    assert (
        OutcomeAssignment(variable="$out", expression=OutcomeExpression()).accept(visitor) == "$out"
    )
    assert OutcomeExpression().accept(visitor) == "OutcomeExpression"
    assert (
        ConditionalExpression(condition=True, true_value="t", false_value="f").accept(visitor)
        == "if:t:f"
    )
    assert AggregationFunction(function="count", arguments=["$e"]).accept(visitor) == "count($e)"
    assert ArithmeticExpression(operator="+", left=1, right=2).accept(visitor) == "+"
    from yaraast.yaral.ast_nodes import OptionsSection

    assert OptionsSection(options={"sample": True}).accept(visitor) == {"sample": True}
    assert RegexPattern(pattern="abc", flags=["nocase"]).accept(visitor) == "/abc/ nocase"
    assert CIDRExpression(field=access, cidr="10.0.0.0/8").accept(visitor) == "10.0.0.0/8"

    assert FunctionCall(function="re.regex", arguments=["$e", "x"]).call_string == "re.regex($e, x)"
    assert FunctionCall(function="empty", arguments=[]).call_string == "empty()"
    assert FunctionCall(function="empty", arguments=[]).accept(visitor) == "empty()"
    yf = YaraLFile()
    yf.add_rule(YaraLRule(name="r1"))
    assert yf.accept(visitor) == 1


def test_yaral_lexer_hits_iteration_cap_and_multiline_backtick_regex() -> None:
    regex_tokens = YaraLLexer("`first\nsecond`").tokenize()
    regex_token = next(tok for tok in regex_tokens if tok.type == T.REGEX)
    assert regex_token.value == "first\nsecond"

    many_tokens = YaraLLexer(" ".join(["("] * 10002)).tokenize()
    assert many_tokens[-1].type == T.EOF
    assert len(many_tokens) == 10001


def test_yaral_lexer_handles_unterminated_comment_string_and_regex_edges() -> None:
    unterminated_comment = YaraLLexer("/* no end")
    comment_tokens = unterminated_comment.tokenize()
    assert comment_tokens[-1].type == T.EOF

    unterminated_string = YaraLLexer('"abc')
    string_tokens = unterminated_string.tokenize()
    assert string_tokens[0].type == T.STRING
    assert string_tokens[0].value == "abc"

    escaped_regex = YaraLLexer(r"/a\/b/")
    regex_token = escaped_regex._read_regex()
    assert regex_token.type == T.REGEX
    assert regex_token.value == r"/a\/b/"

    unterminated_backtick = YaraLLexer("`abc")
    backtick_tokens = unterminated_backtick.tokenize()
    assert backtick_tokens[0].type == T.REGEX

    unterminated_slash_regex = YaraLLexer("/abc")
    slash_regex_token = unterminated_slash_regex._read_regex()
    assert slash_regex_token.type == T.REGEX
    assert slash_regex_token.value == "/abc/"
