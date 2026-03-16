"""Additional YARA-L optimizer coverage tests without mocks."""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    BinaryCondition,
    CIDRExpression,
    ConditionalExpression,
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
    OptionsSection,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    ReferenceList,
    RegexPattern,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    UnaryCondition,
    VariableComparisonCondition,
    YaraLFile,
    YaraLRule,
)
from yaraast.yaral.optimizer import OptimizationStats, YaraLOptimizer


def _build_rule() -> YaraLRule:
    ev = EventVariable(name="$e")
    stmt = EventAssignment(
        event_var=ev,
        field_path=UDMFieldPath(parts=["metadata", "event_type"]),
        operator="=",
        value="LOGIN",
    )
    cond = ConditionSection(expression=EventExistsCondition(event="$e"))
    return YaraLRule(
        name="r",
        events=EventsSection(statements=[stmt]),
        match=MatchSection(
            variables=[MatchVariable(variable="e", time_window=TimeWindow(duration=5, unit="m"))]
        ),
        condition=cond,
        outcome=OutcomeSection(
            assignments=[OutcomeAssignment(variable="$x", expression=OutcomeExpression())]
        ),
        options=OptionsSection(options={"sample": True}),
    )


def test_optimizer_optimize_and_direct_visitors() -> None:
    opt = YaraLOptimizer()
    ast = YaraLFile(rules=[_build_rule()])
    optimized, stats = opt.optimize(ast)
    assert len(optimized.rules) == 1
    assert isinstance(stats, OptimizationStats)
    assert "Optimizations:" in str(stats)

    ev = EventVariable(name="$e")
    path = UDMFieldPath(parts=["principal", "ip"])
    ref = ReferenceList(name="list")

    assert opt.visit_yaral_events_section(EventsSection())
    assert opt.visit_yaral_event_statement(EventStatement())
    assert opt.visit_yaral_event_assignment(
        EventAssignment(event_var=ev, field_path=path, operator="=", value=ref)
    )
    assert opt.visit_yaral_event_variable(ev) == ev
    assert opt.visit_yaral_udm_field_path(path) == path
    assert opt.visit_yaral_reference_list(ref) == ref

    tw = TimeWindow(duration=1, unit="h")
    mv = MatchVariable(variable="e", time_window=tw)
    ms = MatchSection(variables=[mv])
    assert opt.visit_yaral_match_section(ms) == ms
    assert opt.visit_yaral_match_variable(mv) == mv
    assert opt.visit_yaral_time_window(tw) == tw

    ec = EventCountCondition(event="e", operator=">", count=1)
    ex = EventExistsCondition(event="e")
    vc = VariableComparisonCondition(variable="$x", operator="==", value=1)
    jc = JoinCondition(left_event="$e1", right_event="$e2")
    bc = BinaryCondition(operator="and", left=ex, right=ec)
    uc = UnaryCondition(operator="not", operand=ex)

    assert opt.visit_yaral_condition_expression(ex) == ex
    assert opt.visit_yaral_binary_condition(bc)
    assert opt.visit_yaral_unary_condition(uc) == uc
    assert opt.visit_yaral_event_count_condition(ec) == ec
    assert opt.visit_yaral_event_exists_condition(ex) == ex
    assert opt.visit_yaral_variable_comparison_condition(vc) == vc
    assert opt.visit_yaral_join_condition(jc) == jc

    out_expr = OutcomeExpression()
    out_assign = OutcomeAssignment(variable="$x", expression=out_expr)
    out_sec = OutcomeSection(assignments=[out_assign])
    assert opt.visit_yaral_outcome_section(out_sec) == out_sec
    assert opt.visit_yaral_outcome_assignment(out_assign) == out_assign
    assert opt.visit_yaral_outcome_expression(out_expr) == out_expr

    agg = AggregationFunction(function="count", arguments=["$e"])
    cexpr = ConditionalExpression(condition=True, true_value=1, false_value=0)
    aexpr = ArithmeticExpression(operator="+", left=1, right=2)
    opts = OptionsSection(options={"x": 1})
    regex = RegexPattern(pattern="ab+")
    cidr = CIDRExpression(field=UDMFieldAccess(event=ev, field=path), cidr="10.0.0.0/8")
    fn = FunctionCall(function="re.regex", arguments=["ab"])

    assert opt.visit_yaral_aggregation_function(agg) == agg
    assert opt.visit_yaral_conditional_expression(cexpr) == cexpr
    assert opt.visit_yaral_arithmetic_expression(aexpr) == aexpr
    assert opt.visit_yaral_options_section(opts) == opts
    assert opt.visit_yaral_regex_pattern(regex) == regex
    assert opt.visit_yaral_cidr_expression(cidr) == cidr
    assert opt.visit_yaral_function_call(fn) == fn
