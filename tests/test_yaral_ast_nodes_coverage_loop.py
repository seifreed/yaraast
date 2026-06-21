# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""Regression tests for yaraast.yaral.ast_nodes targeting previously uncovered lines.

Each test constructs real node instances, invokes real methods, and asserts
exact outcomes. No mocks, no stubs, no inline suppressions.
"""

from __future__ import annotations

import pytest

from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    ArithmeticExpression,
    BinaryCondition,
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
    NOfCondition,
    NullCheckCondition,
    OptionsSection,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
    RawConditionValue,
    RawOutcomeExpression,
    ReferenceList,
    RegexPattern,
    StringLiteral,
    TimeWindow,
    UDMFieldAccess,
    UDMFieldPath,
    UnaryCondition,
    VariableComparisonCondition,
    YaraLFile,
    YaraLRule,
    _format_udm_field_path,
    _format_yaral_call_argument,
)
from yaraast.yaral.visitor_base import YaraLVisitor

# ---------------------------------------------------------------------------
# Minimal visitor that returns the node type name so accept() calls are real
# ---------------------------------------------------------------------------


class _RecordingVisitor(YaraLVisitor[str]):
    """Visitor returning the class name of the visited node."""

    def _visit_yaral_node(self, node: object) -> str:
        return type(node).__name__


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _event_var(name: str = "$e") -> EventVariable:
    return EventVariable(name=name)


def _udm_path(*parts: str) -> UDMFieldPath:
    return UDMFieldPath(parts=list(parts))


def _udm_access(event: EventVariable | None, *parts: str) -> UDMFieldAccess:
    return UDMFieldAccess(event=event, field=_udm_path(*parts))


def _time_window(duration: int = 5, unit: str = "m", modifier: str | None = None) -> TimeWindow:
    return TimeWindow(duration=duration, unit=unit, modifier=modifier)


# ===========================================================================
# _format_udm_field_path (lines 351-359)
# ===========================================================================


class TestFormatUDMFieldPath:
    def test_empty_parts_returns_empty_string(self) -> None:
        """Lines 351-352: early-return for empty list."""
        assert _format_udm_field_path([]) == ""

    def test_single_part(self) -> None:
        """Line 353: single-element path has no separator."""
        assert _format_udm_field_path(["hostname"]) == "hostname"

    def test_dot_separated_parts(self) -> None:
        """Lines 354-358: multiple parts joined with dots."""
        assert _format_udm_field_path(["principal", "hostname"]) == "principal.hostname"

    def test_bracket_subscript_no_dot(self) -> None:
        """Line 355-356: subscript part must not add a leading dot."""
        assert _format_udm_field_path(["labels", "[0]"]) == "labels[0]"

    def test_mixed_dot_and_subscript(self) -> None:
        """Line 359: mix produces correct compound path."""
        result = _format_udm_field_path(["metadata", "labels", "[1]", "value"])
        assert result == "metadata.labels[1].value"


# ===========================================================================
# UDMFieldPath.path property (line 316)
# ===========================================================================


class TestUDMFieldPathProperty:
    def test_path_delegates_to_format(self) -> None:
        """Line 316: .path calls _format_udm_field_path on .parts."""
        node = _udm_path("principal", "ip")
        assert node.path == "principal.ip"


# ===========================================================================
# UDMFieldAccess.validate_structure and full_path (lines 331-344, 347)
# ===========================================================================


class TestUDMFieldAccess:
    def test_validate_structure_with_event(self) -> None:
        """Lines 331-338: validate_structure succeeds with EventVariable set."""
        node = _udm_access(_event_var("$e"), "metadata", "event_type")
        node.validate_structure()  # must not raise

    def test_validate_structure_without_event(self) -> None:
        """Lines 331-338: validate_structure succeeds with event=None."""
        node = _udm_access(None, "principal", "hostname")
        node.validate_structure()  # must not raise

    def test_full_path_with_event(self) -> None:
        """Line 344: full_path prefixes event variable name."""
        node = _udm_access(_event_var("$login"), "target", "user", "userid")
        assert node.full_path == "$login.target.user.userid"

    def test_full_path_without_event(self) -> None:
        """Line 342-343: full_path returns only field path when event is None."""
        node = _udm_access(None, "network", "http", "method")
        assert node.full_path == "network.http.method"

    def test_accept_calls_visitor(self) -> None:
        """Line 347: accept dispatches to visit_yaral_udm_field_access."""
        node = _udm_access(_event_var("$e"), "principal", "ip")
        result = node.accept(_RecordingVisitor())
        assert result == "UDMFieldAccess"


# ===========================================================================
# _validate_child_structure — callable validate_structure branch (line 56)
# ===========================================================================


class TestValidateChildStructure:
    def test_child_with_validate_structure_is_called(self) -> None:
        """Line 56: _validate_child_structure calls validate_structure when present.

        This is exercised indirectly via any _require_yaral_node call on a node
        that has a validate_structure() method.
        """
        access = _udm_access(_event_var("$e"), "principal", "hostname")
        # _require_yaral_node on UDMFieldAccess triggers _validate_child_structure
        # which calls access.validate_structure() (line 56 branch)
        access.validate_structure()  # must not raise


# ===========================================================================
# _require_yaral_node TypeError branches (lines 62-63)
# ===========================================================================


class TestRequireYaralNodeErrors:
    def test_wrong_type_raises_typeerror(self) -> None:
        """Lines 62-63: passing a non-node raises TypeError."""
        node = CIDRExpression(
            field=_udm_access(_event_var("$e"), "principal", "ip"),
            cidr="10.0.0.0/8",
        )
        # Replace field with invalid type to trigger _require_yaral_node error
        node.field = "not-a-node"  # type: ignore[assignment]
        with pytest.raises(TypeError, match="CIDRExpression field must be a UDMFieldAccess"):
            node.validate_structure()


# ===========================================================================
# _require_optional_yaral_node TypeError branch (lines 77-78)
# ===========================================================================


class TestRequireOptionalYaralNodeErrors:
    def test_wrong_type_raises_typeerror(self) -> None:
        """Lines 77-78: non-None, wrong-type value raises TypeError."""
        rule = YaraLRule(name="test_rule")
        rule.meta = "not-a-meta-section"  # type: ignore[assignment]
        with pytest.raises(TypeError, match="YaraLRule meta must be an MetaSection"):
            rule.validate_structure()


# ===========================================================================
# _require_yaral_node_sequence TypeError branches (lines 90-91, 94-95)
# ===========================================================================


class TestRequireYaralNodeSequenceErrors:
    def test_non_list_raises_typeerror(self) -> None:
        """Lines 90-91: a non-list value raises TypeError."""
        section = MetaSection()
        section.entries = "not-a-list"  # type: ignore[assignment]
        with pytest.raises(TypeError, match="MetaSection entries must be a list"):
            section.validate_structure()

    def test_wrong_element_type_raises_typeerror(self) -> None:
        """Lines 94-95: a list containing a wrong-type element raises TypeError."""
        section = EventsSection()
        section.statements = ["plain-string"]  # type: ignore[list-item]
        with pytest.raises(TypeError, match="EventsSection statements must contain EventStatement"):
            section.validate_structure()


# ===========================================================================
# _require_yaral_string_sequence TypeError branch (lines 102-103)
# ===========================================================================


class TestRequireYaralStringSequenceErrors:
    def test_non_list_raises_typeerror(self) -> None:
        """Lines 102-103: non-list raises TypeError."""
        path = _udm_path("principal")
        path.parts = "not-a-list"  # type: ignore[assignment]
        with pytest.raises(TypeError, match="UDMFieldPath parts must be a list"):
            path.validate_structure()


# ===========================================================================
# _require_yaral_int branches (lines 110-113)
# ===========================================================================


class TestRequireYaralInt:
    def test_bool_raises_typeerror(self) -> None:
        """Lines 110-112: bool is rejected even though bool is a subclass of int."""
        tw = _time_window(duration=5, unit="m")
        tw.duration = True
        with pytest.raises(TypeError, match="TimeWindow duration must be an integer"):
            tw.validate_structure()

    def test_float_raises_typeerror(self) -> None:
        """Lines 110-112: float is rejected."""
        cond = EventCountCondition(event="e", operator=">", count=3)
        cond.count = 3.5  # type: ignore[assignment]
        with pytest.raises(TypeError, match="EventCountCondition count must be an integer"):
            cond.validate_structure()

    def test_valid_int_returns_int(self) -> None:
        """Line 113: a valid int is returned unchanged."""
        tw = _time_window(duration=10, unit="h")
        tw.validate_structure()
        assert tw.duration == 10


# ===========================================================================
# _validate_yaral_value ASTNode branch and error branch (lines 119-123)
# ===========================================================================


class TestValidateYaralValue:
    def test_astnode_value_is_accepted(self) -> None:
        """Lines 119-121: an ASTNode outcome expression is valid."""
        udm = _udm_access(_event_var("$e"), "principal", "ip")
        assignment = OutcomeAssignment(variable="$result", expression=udm)
        assignment.validate_structure()  # must not raise

    def test_invalid_value_type_raises_typeerror(self) -> None:
        """Lines 122-123: an object that is neither ASTNode nor scalar raises TypeError."""
        assignment = OutcomeAssignment(variable="$result", expression=object())  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="OutcomeAssignment expression must be a YARA-L value"):
            assignment.validate_structure()


# ===========================================================================
# YaraLRule.rule_type property (lines 172-178)
# ===========================================================================


class TestYaraLRuleRuleType:
    def test_no_events_returns_single_event(self) -> None:
        """Lines 172-173: no events section → single_event."""
        rule = YaraLRule(name="no_events_rule")
        assert rule.rule_type == "single_event"

    def test_one_event_variable_returns_single_event(self) -> None:
        """Line 178: one unique event variable → single_event."""
        ev = _event_var("$e")
        field = _udm_path("metadata", "event_type")
        assignment = EventAssignment(
            event_var=ev,
            field_path=field,
            operator="=",
            value="NETWORK_CONNECTION",
        )
        events = EventsSection(statements=[assignment])
        rule = YaraLRule(name="single_ev_rule", events=events)
        assert rule.rule_type == "single_event"

    def test_two_distinct_event_variables_returns_multi_event(self) -> None:
        """Line 178: two different event variables → multi_event."""
        ev1 = _event_var("$e1")
        ev2 = _event_var("$e2")
        a1 = EventAssignment(
            event_var=ev1,
            field_path=_udm_path("metadata", "event_type"),
            operator="=",
            value="NETWORK_CONNECTION",
        )
        a2 = EventAssignment(
            event_var=ev2,
            field_path=_udm_path("principal", "hostname"),
            operator="=",
            value="corp-pc",
        )
        events = EventsSection(statements=[a1, a2])
        rule = YaraLRule(name="multi_ev_rule", events=events)
        assert rule.rule_type == "multi_event"

    def test_plain_event_statement_without_event_var_skipped(self) -> None:
        """Lines 175-176: statements lacking event_var attribute are skipped."""
        stmt = EventStatement(text='$e.metadata.event_type = "NETWORK_CONNECTION"')
        events = EventsSection(statements=[stmt])
        rule = YaraLRule(name="plain_stmt_rule", events=events)
        # No real event_var attribute → skipped → still single_event
        assert rule.rule_type == "single_event"


# ===========================================================================
# MetaEntry.validate_structure TypeError branch (lines 213-214)
# ===========================================================================


class TestMetaEntryValidation:
    def test_invalid_value_type_raises_typeerror(self) -> None:
        """Lines 213-214: a non-(str|int|bool) value raises TypeError."""
        entry = MetaEntry(key="author", value=["invalid"])  # type: ignore[arg-type]
        with pytest.raises(
            TypeError, match="MetaEntry value must be a string, integer, or boolean"
        ):
            entry.validate_structure()

    def test_string_value_accepted(self) -> None:
        """Validate_structure succeeds for string value."""
        entry = MetaEntry(key="author", value="Marc")
        entry.validate_structure()

    def test_int_value_accepted(self) -> None:
        """Validate_structure succeeds for integer value."""
        entry = MetaEntry(key="severity", value=3)
        entry.validate_structure()

    def test_bool_value_accepted(self) -> None:
        """Validate_structure succeeds for boolean value."""
        entry = MetaEntry(key="is_active", value=True)
        entry.validate_structure()


# ===========================================================================
# EventStatement.accept (line 252)
# ===========================================================================


class TestEventStatementAccept:
    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 252: accept calls visit_yaral_event_statement."""
        stmt = EventStatement(text='$e.metadata.event_type = "NETWORK_CONNECTION"')
        result = stmt.accept(_RecordingVisitor())
        assert result == "EventStatement"


# ===========================================================================
# ReferenceList.validate_structure and accept (lines 370-371, 374)
# ===========================================================================


class TestReferenceList:
    def test_validate_structure_succeeds(self) -> None:
        """Lines 370-371: validate_structure validates non-empty name."""
        node = ReferenceList(name="suspicious_ips")
        node.validate_structure()  # must not raise

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 374: accept calls visit_yaral_reference_list."""
        node = ReferenceList(name="bad_domains")
        result = node.accept(_RecordingVisitor())
        assert result == "ReferenceList"


# ===========================================================================
# MatchSection.validate_structure and accept (lines 385-386, 394)
# ===========================================================================


class TestMatchSection:
    def test_validate_structure_with_variables(self) -> None:
        """Lines 385-386: validate_structure validates MatchVariable sequence."""
        tw = _time_window(5, "m")
        mv = MatchVariable(variable="e", time_window=tw)
        section = MatchSection(variables=[mv])
        section.validate_structure()  # must not raise

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 394: accept calls visit_yaral_match_section."""
        section = MatchSection(variables=[])
        result = section.accept(_RecordingVisitor())
        assert result == "MatchSection"


# ===========================================================================
# MatchVariable.validate_structure and accept (lines 407-410, 418)
# ===========================================================================


class TestMatchVariable:
    def test_validate_structure_without_grouping(self) -> None:
        """Lines 407-410: validate_structure succeeds when grouping_field is None."""
        tw = _time_window(10, "m")
        mv = MatchVariable(variable="e", time_window=tw)
        mv.validate_structure()  # must not raise

    def test_validate_structure_with_grouping(self) -> None:
        """Lines 407-410: validate_structure succeeds when grouping_field is set."""
        tw = _time_window(10, "m")
        gf = _udm_access(_event_var("$e"), "principal", "user", "userid")
        mv = MatchVariable(variable="e", time_window=tw, grouping_field=gf)
        mv.validate_structure()  # must not raise

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 418: accept calls visit_yaral_match_variable."""
        tw = _time_window(5, "m")
        mv = MatchVariable(variable="e", time_window=tw)
        result = mv.accept(_RecordingVisitor())
        assert result == "MatchVariable"


# ===========================================================================
# TimeWindow.validate_structure, as_string, accept (lines 431-435, 439-440, 443)
# ===========================================================================


class TestTimeWindow:
    def test_validate_structure_no_modifier(self) -> None:
        """Lines 431-433: validate_structure passes without modifier."""
        tw = _time_window(5, "m")
        tw.validate_structure()

    def test_validate_structure_with_modifier(self) -> None:
        """Lines 434-435: modifier branch is validated when set."""
        tw = _time_window(1, "h", modifier="every")
        tw.validate_structure()

    def test_as_string_no_modifier(self) -> None:
        """Line 440: as_string without modifier produces '<duration><unit>'."""
        tw = _time_window(15, "m")
        assert tw.as_string == "15m"

    def test_as_string_with_modifier(self) -> None:
        """Lines 439-440: as_string with modifier prefixes it."""
        tw = _time_window(1, "h", modifier="every")
        assert tw.as_string == "every 1h"

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 443: accept calls visit_yaral_time_window."""
        tw = _time_window(5, "m")
        result = tw.accept(_RecordingVisitor())
        assert result == "TimeWindow"


# ===========================================================================
# ConditionExpression.accept base class (line 471)
# ===========================================================================


class TestConditionExpressionBase:
    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 471: accept calls visit_yaral_condition_expression on bare base class."""
        # ConditionExpression is a concrete @dataclass with no required fields.
        node = ConditionExpression()
        result = node.accept(_RecordingVisitor())
        assert result == "ConditionExpression"


# ===========================================================================
# BinaryCondition.validate_structure and accept (lines 484-487, 490)
# ===========================================================================


class TestBinaryCondition:
    def test_validate_structure(self) -> None:
        """Lines 484-487: validate_structure with valid fields."""
        left = EventExistsCondition(event="$e1")
        right = EventExistsCondition(event="$e2")
        node = BinaryCondition(operator="and", left=left, right=right)
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 490: accept calls visit_yaral_binary_condition."""
        left = EventExistsCondition(event="$e1")
        right = EventExistsCondition(event="$e2")
        node = BinaryCondition(operator="and", left=left, right=right)
        result = node.accept(_RecordingVisitor())
        assert result == "BinaryCondition"


# ===========================================================================
# UnaryCondition.validate_structure and accept (lines 502-504, 512)
# ===========================================================================


class TestUnaryCondition:
    def test_validate_structure_with_operand(self) -> None:
        """Lines 502-504: validate_structure succeeds with an operand."""
        inner = EventExistsCondition(event="$e1")
        node = UnaryCondition(operator="not", operand=inner)
        node.validate_structure()

    def test_validate_structure_without_operand(self) -> None:
        """Lines 502-504: validate_structure succeeds when operand is None."""
        node = UnaryCondition(operator="not", operand=None)
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 512: accept calls visit_yaral_unary_condition."""
        inner = EventExistsCondition(event="$e1")
        node = UnaryCondition(operator="not", operand=inner)
        result = node.accept(_RecordingVisitor())
        assert result == "UnaryCondition"


# ===========================================================================
# EventCountCondition.validate_structure and accept (lines 525-528, 531)
# ===========================================================================


class TestEventCountCondition:
    def test_validate_structure(self) -> None:
        """Lines 525-528: validate_structure with valid fields."""
        node = EventCountCondition(event="e", operator=">", count=5)
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 531: accept calls visit_yaral_event_count_condition."""
        node = EventCountCondition(event="e", operator=">", count=5)
        result = node.accept(_RecordingVisitor())
        assert result == "EventCountCondition"


# ===========================================================================
# VariableComparisonCondition.validate_structure and accept (lines 559-562, 565)
# ===========================================================================


class TestVariableComparisonCondition:
    def test_validate_structure(self) -> None:
        """Lines 559-562: validate_structure succeeds with valid fields."""
        node = VariableComparisonCondition(variable="$count", operator=">", value=3)
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 565: accept calls visit_yaral_variable_comparison_condition."""
        node = VariableComparisonCondition(variable="$count", operator=">", value=3)
        result = node.accept(_RecordingVisitor())
        assert result == "VariableComparisonCondition"


# ===========================================================================
# JoinCondition.validate_structure and accept (lines 578-581, 584)
# ===========================================================================


class TestJoinCondition:
    def test_validate_structure(self) -> None:
        """Lines 578-581: validate_structure succeeds with valid fields."""
        node = JoinCondition(left_event="$e1", right_event="$e2", join_type="inner")
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 584: accept calls visit_yaral_join_condition."""
        node = JoinCondition(left_event="$e1", right_event="$e2", join_type="inner")
        result = node.accept(_RecordingVisitor())
        assert result == "JoinCondition"


# ===========================================================================
# NOfCondition.validate_structure and accept (lines 596-603)
# ===========================================================================


class TestNOfCondition:
    def test_validate_structure(self) -> None:
        """Lines 596-598: validate_structure with valid fields."""
        node = NOfCondition(count=2, events=["$e1", "$e2", "$e3"])
        node.validate_structure()

    def test_accept_with_visitor_method(self) -> None:
        """Lines 601-602: accept dispatches to visit_yaral_n_of_condition when present."""
        node = NOfCondition(count=2, events=["$e1", "$e2"])
        result = node.accept(_RecordingVisitor())
        assert result == "NOfCondition"

    def test_accept_fallback_to_condition_expression(self) -> None:
        """Line 603: accept falls back to visit_yaral_condition_expression when the
        visitor does not expose visit_yaral_n_of_condition.

        A visitor that subclasses raw ASTVisitor (not YaraLVisitor) will have
        hasattr(..., 'visit_yaral_n_of_condition') == False.  The node then
        delegates to visit_yaral_condition_expression instead.
        """
        from yaraast.visitor import ASTVisitor

        class _MinimalVisitor(ASTVisitor[str]):
            def _default_visit(self, node: object) -> str:
                return "base"

            def visit_yaral_condition_expression(self, node: object) -> str:
                return "fallback:" + type(node).__name__

        visitor = _MinimalVisitor()
        assert not hasattr(visitor, "visit_yaral_n_of_condition")

        node = NOfCondition(count=1, events=["$e1"])
        result = node.accept(visitor)
        assert result == "fallback:NOfCondition"


# ===========================================================================
# NullCheckCondition.validate_structure and accept (lines 615-630)
# ===========================================================================


class TestNullCheckCondition:
    def test_validate_structure_with_udm_field_access(self) -> None:
        """Lines 615, 619-620: UDMFieldAccess field validated via its own validate_structure."""
        field = _udm_access(_event_var("$e"), "principal", "ip")
        node = NullCheckCondition(field=field, negated=False)
        node.validate_structure()

    def test_validate_structure_with_string_field(self) -> None:
        """Lines 615, 621-622: string field path is validated via _require_nonempty_string."""
        node = NullCheckCondition(field="$e.principal.ip", negated=True)
        node.validate_structure()

    def test_validate_structure_wrong_field_type_raises_typeerror(self) -> None:
        """Lines 616-618: non-UDMFieldAccess, non-string raises TypeError."""
        node = NullCheckCondition(field=42, negated=False)
        with pytest.raises(
            TypeError, match="NullCheckCondition field must be a UDMFieldAccess or string"
        ):
            node.validate_structure()

    def test_validate_structure_wrong_negated_type_raises_typeerror(self) -> None:
        """Lines 623-625: non-bool negated raises TypeError."""
        node = NullCheckCondition(field="$e.field", negated=1)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="NullCheckCondition negated must be a boolean"):
            node.validate_structure()

    def test_accept_with_visitor_method(self) -> None:
        """Lines 628-629: accept dispatches to visit_yaral_null_check_condition when present."""
        node = NullCheckCondition(field="$e.field", negated=False)
        result = node.accept(_RecordingVisitor())
        assert result == "NullCheckCondition"

    def test_accept_fallback_to_condition_expression(self) -> None:
        """Line 630: accept falls back to visit_yaral_condition_expression when the
        visitor does not expose visit_yaral_null_check_condition.
        """
        from yaraast.visitor import ASTVisitor

        class _MinimalVisitor(ASTVisitor[str]):
            def _default_visit(self, node: object) -> str:
                return "base"

            def visit_yaral_condition_expression(self, node: object) -> str:
                return "fallback:" + type(node).__name__

        visitor = _MinimalVisitor()
        assert not hasattr(visitor, "visit_yaral_null_check_condition")

        node = NullCheckCondition(field="$e.field", negated=False)
        result = node.accept(visitor)
        assert result == "fallback:NullCheckCondition"


# ===========================================================================
# OutcomeSection.validate_structure and accept (lines 641-642, 650)
# ===========================================================================


class TestOutcomeSection:
    def test_validate_structure(self) -> None:
        """Lines 641-642: validate_structure validates OutcomeAssignment sequence."""
        assignment = OutcomeAssignment(variable="$severity", expression="HIGH")
        section = OutcomeSection(assignments=[assignment])
        section.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 650: accept calls visit_yaral_outcome_section."""
        section = OutcomeSection(assignments=[])
        result = section.accept(_RecordingVisitor())
        assert result == "OutcomeSection"


# ===========================================================================
# OutcomeAssignment.validate_structure and accept (lines 662-664, 667)
# ===========================================================================


class TestOutcomeAssignment:
    def test_validate_structure(self) -> None:
        """Lines 662-664: validate_structure with valid scalar expression."""
        node = OutcomeAssignment(variable="$severity", expression="HIGH")
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 667: accept calls visit_yaral_outcome_assignment."""
        node = OutcomeAssignment(variable="$severity", expression=1)
        result = node.accept(_RecordingVisitor())
        assert result == "OutcomeAssignment"


# ===========================================================================
# OutcomeExpression base class accept (line 675)
# ===========================================================================


class TestOutcomeExpressionBase:
    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 675: accept calls visit_yaral_outcome_expression on bare base class."""
        node = OutcomeExpression()
        result = node.accept(_RecordingVisitor())
        assert result == "OutcomeExpression"


# ===========================================================================
# AggregationFunction.validate_structure, call_string, accept (lines 687-701)
# ===========================================================================


class TestAggregationFunction:
    def test_validate_structure_with_arguments(self) -> None:
        """Lines 687-693: validate_structure iterates arguments and validates each."""
        field = _udm_access(_event_var("$e"), "principal", "ip")
        node = AggregationFunction(function="count_distinct", arguments=[field])
        node.validate_structure()

    def test_validate_structure_non_list_arguments_raises_typeerror(self) -> None:
        """Lines 689-691: non-list arguments raises TypeError."""
        node = AggregationFunction(function="count", arguments="bad")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="AggregationFunction arguments must be a list"):
            node.validate_structure()

    def test_call_string_no_arguments(self) -> None:
        """Lines 697-698: call_string with no arguments."""
        node = AggregationFunction(function="count", arguments=[])
        assert node.call_string == "count()"

    def test_call_string_with_arguments(self) -> None:
        """Lines 697-698: call_string with arguments formatted by _format_yaral_call_argument."""
        node = AggregationFunction(function="sum", arguments=["$e.network.sent_bytes"])
        assert node.call_string == "sum($e.network.sent_bytes)"

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 701: accept calls visit_yaral_aggregation_function."""
        node = AggregationFunction(function="count", arguments=[])
        result = node.accept(_RecordingVisitor())
        assert result == "AggregationFunction"


# ===========================================================================
# ConditionalExpression.validate_structure and accept (lines 714-717, 720)
# ===========================================================================


class TestConditionalExpression:
    def test_validate_structure(self) -> None:
        """Lines 714-717: validate_structure accepts valid scalar operands."""
        node = ConditionalExpression(condition=True, true_value="HIGH", false_value="LOW")
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 720: accept calls visit_yaral_conditional_expression."""
        node = ConditionalExpression(condition=True, true_value="HIGH", false_value="LOW")
        result = node.accept(_RecordingVisitor())
        assert result == "ConditionalExpression"


# ===========================================================================
# ArithmeticExpression.validate_structure and accept (lines 733-736, 739)
# ===========================================================================


class TestArithmeticExpression:
    def test_validate_structure(self) -> None:
        """Lines 733-736: validate_structure with valid fields."""
        node = ArithmeticExpression(operator="+", left=1, right=2)
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 739: accept calls visit_yaral_arithmetic_expression."""
        node = ArithmeticExpression(operator="*", left=3, right=4)
        result = node.accept(_RecordingVisitor())
        assert result == "ArithmeticExpression"


# ===========================================================================
# OptionsSection.validate_structure and accept (lines 750-756, 759)
# ===========================================================================


class TestOptionsSection:
    def test_validate_structure_with_options(self) -> None:
        """Lines 750-756: validate_structure iterates key-value pairs."""
        node = OptionsSection(options={"max_concurrent_queries": 1})
        node.validate_structure()

    def test_validate_structure_non_dict_raises_typeerror(self) -> None:
        """Lines 751-753: non-dict options raises TypeError."""
        node = OptionsSection(options="bad")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="OptionsSection options must be a dictionary"):
            node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 759: accept calls visit_yaral_options_section."""
        node = OptionsSection(options={})
        result = node.accept(_RecordingVisitor())
        assert result == "OptionsSection"


# ===========================================================================
# RegexPattern.validate_structure, as_string, accept (lines 771-773, 777-783, 786)
# ===========================================================================


class TestRegexPattern:
    def test_validate_structure(self) -> None:
        """Lines 771-773: validate_structure validates pattern and flags."""
        node = RegexPattern(pattern="evil.*", flags=["i"])
        node.validate_structure()

    def test_as_string_no_flags(self) -> None:
        """Lines 777-780: as_string with no flags."""
        node = RegexPattern(pattern="hello", flags=[])
        result = node.as_string
        # Pattern with no flags: /hello/
        assert result.startswith("/") and result.endswith("/")
        assert "hello" in result

    def test_as_string_inline_flag(self) -> None:
        """Lines 777-780: single-character flags become inline after the closing /."""
        node = RegexPattern(pattern="test", flags=["i"])
        result = node.as_string
        assert result.endswith("/i") or "/i" in result

    def test_as_string_word_flag(self) -> None:
        """Lines 781-782: multi-character flags are appended after a space."""
        node = RegexPattern(pattern="example", flags=["nocase"])
        result = node.as_string
        assert "nocase" in result
        # word_flag appended with a space separator
        assert " nocase" in result

    def test_as_string_mixed_flags(self) -> None:
        """Lines 777-783: inline and word flags both present."""
        node = RegexPattern(pattern="data", flags=["i", "nocase"])
        result = node.as_string
        assert "/i" in result or "i" in result
        assert "nocase" in result

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 786: accept calls visit_yaral_regex_pattern."""
        node = RegexPattern(pattern="x", flags=[])
        result = node.accept(_RecordingVisitor())
        assert result == "RegexPattern"


# ===========================================================================
# CIDRExpression.validate_structure and accept (lines 798-800, 803)
# ===========================================================================


class TestCIDRExpression:
    def test_validate_structure(self) -> None:
        """Lines 798-800: validate_structure with valid UDMFieldAccess and CIDR."""
        field = _udm_access(_event_var("$e"), "principal", "ip")
        node = CIDRExpression(field=field, cidr="192.168.0.0/16")
        node.validate_structure()

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 803: accept calls visit_yaral_cidr_expression."""
        field = _udm_access(_event_var("$e"), "principal", "ip")
        node = CIDRExpression(field=field, cidr="10.0.0.0/8")
        result = node.accept(_RecordingVisitor())
        assert result == "CIDRExpression"


# ===========================================================================
# FunctionCall.validate_structure, call_string, accept (lines 815-821, 825-826, 829)
# ===========================================================================


class TestFunctionCall:
    def test_validate_structure_with_arguments(self) -> None:
        """Lines 815-821: validate_structure iterates arguments."""
        node = FunctionCall(function="re.regex", arguments=["evil.*"])
        node.validate_structure()

    def test_validate_structure_non_list_arguments_raises_typeerror(self) -> None:
        """Lines 817-819: non-list arguments raises TypeError."""
        node = FunctionCall(function="re.regex", arguments="bad")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="FunctionCall arguments must be a list"):
            node.validate_structure()

    def test_call_string_no_args(self) -> None:
        """Lines 825-826: call_string with no arguments."""
        node = FunctionCall(function="timestamp.current_timestamp", arguments=[])
        assert node.call_string == "timestamp.current_timestamp()"

    def test_call_string_with_args(self) -> None:
        """Lines 825-826: call_string with string arguments."""
        node = FunctionCall(function="strings.to_lower", arguments=["HELLO"])
        assert node.call_string == "strings.to_lower(HELLO)"

    def test_accept_dispatches_to_visitor(self) -> None:
        """Line 829: accept calls visit_yaral_function_call."""
        node = FunctionCall(function="re.regex", arguments=[])
        result = node.accept(_RecordingVisitor())
        assert result == "FunctionCall"


# ===========================================================================
# _format_yaral_call_argument (lines 833-841)
# ===========================================================================


class TestFormatYaralCallArgument:
    def test_udm_field_access_returns_full_path(self) -> None:
        """Lines 833-834: UDMFieldAccess input returns its full_path."""
        node = _udm_access(_event_var("$e"), "principal", "hostname")
        result = _format_yaral_call_argument(node)
        assert result == "$e.principal.hostname"

    def test_event_variable_returns_name(self) -> None:
        """Lines 835-836: EventVariable input returns its name."""
        node = _event_var("$login")
        result = _format_yaral_call_argument(node)
        assert result == "$login"

    def test_regex_pattern_returns_as_string(self) -> None:
        """Lines 837-838: RegexPattern input returns its as_string."""
        node = RegexPattern(pattern="abc", flags=[])
        result = _format_yaral_call_argument(node)
        assert result == node.as_string

    def test_aggregation_function_returns_call_string(self) -> None:
        """Lines 839-840: AggregationFunction returns its call_string."""
        node = AggregationFunction(function="count", arguments=[])
        result = _format_yaral_call_argument(node)
        assert result == "count()"

    def test_function_call_returns_call_string(self) -> None:
        """Lines 839-840: FunctionCall returns its call_string."""
        node = FunctionCall(function="re.capture", arguments=["field"])
        result = _format_yaral_call_argument(node)
        assert result == "re.capture(field)"

    def test_scalar_returns_str(self) -> None:
        """Line 841: any other value is converted to str."""
        assert _format_yaral_call_argument(42) == "42"
        assert _format_yaral_call_argument("hello") == "hello"
        assert _format_yaral_call_argument(3.14) == "3.14"


# ===========================================================================
# YaraLFile.validate_structure deep mode and add_rule (lines 859->exit, 865-869)
# ===========================================================================


class TestYaraLFile:
    def test_validate_structure_deep_validates_each_rule(self) -> None:
        """Line 859->exit: deep=True (default) calls validate_structure on each rule."""
        rule = YaraLRule(name="valid_rule")
        yfile = YaraLFile(rules=[rule])
        yfile.validate_structure(deep=True)  # must not raise

    def test_validate_structure_shallow_skips_rule_validation(self) -> None:
        """Lines 853-858: deep=False skips individual rule validation."""
        rule = YaraLRule(name="valid_rule")
        yfile = YaraLFile(rules=[rule])
        yfile.validate_structure(deep=False)  # must not raise

    def test_add_rule_appends_valid_rule(self) -> None:
        """Lines 865-869: add_rule validates and appends the rule."""
        rule = YaraLRule(name="new_rule")
        yfile = YaraLFile()
        yfile.add_rule(rule)
        assert len(yfile.rules) == 1
        assert yfile.rules[0] is rule

    def test_add_rule_rejects_non_yaral_rule(self) -> None:
        """Lines 865-867: add_rule raises TypeError for non-YaraLRule input."""
        yfile = YaraLFile()
        with pytest.raises(TypeError, match="YaraL rule input must be a YaraLRule"):
            yfile.add_rule("not-a-rule")  # type: ignore[arg-type]


# ===========================================================================
# Marker str subclasses (StringLiteral, RawOutcomeExpression, RawConditionValue)
# ===========================================================================


class TestMarkerStrSubclasses:
    def test_string_literal_is_str(self) -> None:
        """StringLiteral is a str subclass preserving its value."""
        val = StringLiteral("example")
        assert isinstance(val, str)
        assert val == "example"

    def test_raw_outcome_expression_is_str(self) -> None:
        """RawOutcomeExpression is a str subclass."""
        val = RawOutcomeExpression("$e.count + 1")
        assert isinstance(val, str)
        assert val == "$e.count + 1"

    def test_raw_condition_value_is_str(self) -> None:
        """RawConditionValue is a str subclass."""
        val = RawConditionValue("192.168.1.1")
        assert isinstance(val, str)
        assert val == "192.168.1.1"

    def test_yaml_serialization_of_markers(self) -> None:
        """_register_yaml_str_representers allows safe_dump of marker subclasses."""
        yaml = pytest.importorskip("yaml")
        for cls in (StringLiteral, RawOutcomeExpression, RawConditionValue):
            instance = cls("test_value")
            dumped = yaml.safe_dump(instance)
            assert "test_value" in dumped


# ===========================================================================
# Remaining accept() and validate_structure() paths not yet exercised
# by this isolated file (lines 167, 198, 217, 237, 248-249, 267-285,
# 300, 319, 454-455, 463, 546, 872)
# ===========================================================================


class TestRemainingAcceptPaths:
    """Cover accept() dispatch for nodes whose accept methods were not yet
    invoked in this test file, ensuring every visitor dispatch line is hit."""

    def test_yaral_rule_accept(self) -> None:
        """Line 167: YaraLRule.accept dispatches to visit_yaral_rule."""
        rule = YaraLRule(name="my_rule")
        result = rule.accept(_RecordingVisitor())
        assert result == "YaraLRule"

    def test_meta_section_accept(self) -> None:
        """Line 198: MetaSection.accept dispatches to visit_yaral_meta_section."""
        section = MetaSection(entries=[])
        result = section.accept(_RecordingVisitor())
        assert result == "MetaSection"

    def test_meta_entry_accept(self) -> None:
        """Line 217: MetaEntry.accept dispatches to visit_yaral_meta_entry."""
        entry = MetaEntry(key="author", value="Marc")
        result = entry.accept(_RecordingVisitor())
        assert result == "MetaEntry"

    def test_events_section_accept(self) -> None:
        """Line 237: EventsSection.accept dispatches to visit_yaral_events_section."""
        section = EventsSection(statements=[])
        result = section.accept(_RecordingVisitor())
        assert result == "EventsSection"

    def test_event_statement_validate_structure(self) -> None:
        """Lines 248-249: EventStatement.validate_structure validates text field."""
        stmt = EventStatement(text='$e.metadata.event_type = "NETWORK_CONNECTION"')
        stmt.validate_structure()  # must not raise

    def test_event_assignment_validate_structure(self) -> None:
        """Lines 267-282: EventAssignment.validate_structure validates all fields."""
        ev = _event_var("$e")
        field = _udm_path("metadata", "event_type")
        node = EventAssignment(
            event_var=ev,
            field_path=field,
            operator="=",
            value="NETWORK_CONNECTION",
        )
        node.validate_structure()  # must not raise

    def test_event_assignment_accept(self) -> None:
        """Line 285: EventAssignment.accept dispatches to visit_yaral_event_assignment."""
        ev = _event_var("$e")
        field = _udm_path("metadata", "event_type")
        node = EventAssignment(
            event_var=ev,
            field_path=field,
            operator="=",
            value="NETWORK_CONNECTION",
        )
        result = node.accept(_RecordingVisitor())
        assert result == "EventAssignment"

    def test_event_variable_accept(self) -> None:
        """Line 300: EventVariable.accept dispatches to visit_yaral_event_variable."""
        node = _event_var("$e")
        result = node.accept(_RecordingVisitor())
        assert result == "EventVariable"

    def test_udm_field_path_accept(self) -> None:
        """Line 319: UDMFieldPath.accept dispatches to visit_yaral_udm_field_path."""
        node = _udm_path("principal", "hostname")
        result = node.accept(_RecordingVisitor())
        assert result == "UDMFieldPath"

    def test_condition_section_validate_structure(self) -> None:
        """Lines 454-455: ConditionSection.validate_structure with None expression."""
        section = ConditionSection(expression=None)
        section.validate_structure()  # must not raise

    def test_condition_section_accept(self) -> None:
        """Line 463: ConditionSection.accept dispatches to visit_yaral_condition_section."""
        section = ConditionSection(expression=None)
        result = section.accept(_RecordingVisitor())
        assert result == "ConditionSection"

    def test_event_exists_condition_accept(self) -> None:
        """Line 546: EventExistsCondition.accept dispatches correctly."""
        node = EventExistsCondition(event="$e1")
        result = node.accept(_RecordingVisitor())
        assert result == "EventExistsCondition"

    def test_yaral_file_accept(self) -> None:
        """Line 872: YaraLFile.accept dispatches to visit_yaral_file."""
        yfile = YaraLFile(rules=[])
        result = yfile.accept(_RecordingVisitor())
        assert result == "YaraLFile"


# ===========================================================================
# Branch 56->exit: _validate_child_structure with a node lacking validate_structure
# ===========================================================================


class TestValidateChildStructureNonCallable:
    """Cover the branch where validate_structure is not present on the child node.

    ConditionExpression and OutcomeExpression are @dataclass nodes that do not
    define validate_structure.  When passed as a child value, getattr returns
    None and callable(None) is False, so the function returns without calling
    anything (branch 56->exit).
    """

    def test_condition_expression_child_no_validate_structure(self) -> None:
        """Branch 56->exit: ConditionExpression lacks validate_structure.

        ConditionSection holds an optional ConditionExpression.  Calling
        validate_structure on ConditionSection invokes _require_optional_yaral_node,
        which calls _validate_child_structure on the bare ConditionExpression.
        Since ConditionExpression has no validate_structure, the branch exits
        without calling it.
        """
        inner = ConditionExpression()
        section = ConditionSection(expression=inner)
        # This must not raise and must exercise the non-callable branch.
        section.validate_structure()
        # Confirm the expression is unchanged — no side effect from the branch.
        assert section.expression is inner

    def test_outcome_expression_child_no_validate_structure(self) -> None:
        """Branch 56->exit: OutcomeExpression lacks validate_structure.

        OutcomeAssignment.validate_structure calls _validate_yaral_value on its
        expression.  When expression is an OutcomeExpression (an ASTNode with no
        validate_structure), _validate_child_structure exercises the 56->exit branch.
        """
        inner = OutcomeExpression()
        assignment = OutcomeAssignment(variable="$result", expression=inner)
        assignment.validate_structure()
        assert assignment.expression is inner
