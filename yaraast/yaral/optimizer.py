"""YARA-L optimizer for query performance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from yaraast.visitor import ASTVisitor

if TYPE_CHECKING:
    from yaraast.yaral.ast_nodes import (
        BinaryCondition,
        ConditionExpression,
        ConditionSection,
        EventAssignment,
        EventsSection,
        EventStatement,
        MatchSection,
        OutcomeSection,
        UDMFieldPath,
        YaraLFile,
        YaraLRule,
    )


@dataclass
class OptimizationStats:
    """Statistics about optimizations performed."""

    rules_optimized: int = 0
    conditions_simplified: int = 0
    events_optimized: int = 0
    redundant_checks_removed: int = 0
    indexes_suggested: int = 0
    time_windows_optimized: int = 0
    joins_optimized: int = 0

    def __str__(self) -> str:
        return (
            f"Optimizations: {self.rules_optimized} rules, "
            f"{self.conditions_simplified} conditions simplified, "
            f"{self.events_optimized} events optimized, "
            f"{self.redundant_checks_removed} redundant checks removed"
        )


class YaraLOptimizer(ASTVisitor[Any]):
    """Optimizer for YARA-L rules to improve query performance."""

    def __init__(self) -> None:
        """Initialize optimizer."""
        self.stats = OptimizationStats()
        self.indexed_fields = set()  # Fields that should be indexed
        self.current_rule = None

    def optimize(self, ast: YaraLFile) -> tuple[YaraLFile, OptimizationStats]:
        """Optimize YARA-L file and return optimized AST with stats.

        Args:
            ast: Original YARA-L AST

        Returns:
            Tuple of (optimized AST, optimization stats)
        """
        self.stats = OptimizationStats()
        optimized_ast = self.visit(ast)
        return optimized_ast, self.stats

    def visit_yaral_file(self, node: YaraLFile) -> YaraLFile:
        """Optimize YARA-L file."""
        optimized_rules = []

        for rule in node.rules:
            optimized_rule = self.visit(rule)
            if optimized_rule != rule:
                self.stats.rules_optimized += 1
            optimized_rules.append(optimized_rule)

        return YaraLFile(rules=optimized_rules)

    def visit_yaral_rule(self, node: YaraLRule) -> YaraLRule:
        """Optimize individual YARA-L rule."""
        self.current_rule = node.name
        self.indexed_fields.clear()

        # Optimize each section
        optimized_events = None
        if node.events:
            optimized_events = self.visit(node.events)

        optimized_match = None
        if node.match:
            optimized_match = self._optimize_match_section(node.match)

        optimized_condition = None
        if node.condition:
            optimized_condition = self._optimize_condition_section(node.condition)

        optimized_outcome = None
        if node.outcome:
            optimized_outcome = self._optimize_outcome_section(node.outcome)

        # Create optimized rule
        optimized_rule = YaraLRule(
            name=node.name,
            meta=node.meta,  # Meta doesn't need optimization
            events=optimized_events,
            match=optimized_match,
            condition=optimized_condition,
            outcome=optimized_outcome,
            options=self._optimize_options(node.options),
        )

        return optimized_rule

    def visit_events_section(self, node: EventsSection) -> EventsSection:
        """Optimize events section."""
        optimized_statements = []

        # Group similar event patterns for better performance
        event_groups = self._group_event_statements(node.statements)

        for group in event_groups:
            if len(group) > 1:
                # Combine similar events
                combined = self._combine_event_statements(group)
                optimized_statements.append(combined)
                self.stats.events_optimized += len(group) - 1
            else:
                # Optimize individual statement
                optimized = self._optimize_event_statement(group[0])
                optimized_statements.append(optimized)

        return EventsSection(statements=optimized_statements)

    def _optimize_event_statement(self, stmt: EventStatement) -> EventStatement:
        """Optimize individual event statement."""
        if not stmt.assignments:
            return stmt

        # Reorder assignments for better performance
        # Put most selective filters first
        optimized_assignments = self._reorder_assignments(stmt.assignments)

        # Remove redundant checks
        optimized_assignments = self._remove_redundant_assignments(optimized_assignments)

        # Identify fields that should be indexed
        for assignment in optimized_assignments:
            if self._should_index_field(assignment):
                self.indexed_fields.add(self._field_path_to_string(assignment.field_path))
                self.stats.indexes_suggested += 1

        return EventStatement(
            event=stmt.event,
            assignments=optimized_assignments,
        )

    def _reorder_assignments(self, assignments: list[EventAssignment]) -> list[EventAssignment]:
        """Reorder assignments for optimal query performance."""
        # Score each assignment based on selectivity
        scored = []
        for assignment in assignments:
            score = self._calculate_selectivity_score(assignment)
            scored.append((score, assignment))

        # Sort by score (higher score = more selective = should be first)
        scored.sort(key=lambda x: x[0], reverse=True)

        return [assignment for _, assignment in scored]

    def _calculate_selectivity_score(self, assignment: EventAssignment) -> float:
        """Calculate selectivity score for an assignment."""
        score = 0.0

        # Equality checks are most selective
        if assignment.operator == "=":
            score += 10.0
        elif assignment.operator == "!=":
            score += 8.0
        elif assignment.operator in [">", "<", ">=", "<="]:
            score += 5.0
        elif assignment.operator in ["=~", "!~"]:
            score += 3.0

        # Some fields are naturally more selective
        field_str = self._field_path_to_string(assignment.field_path)
        if "event_type" in field_str:
            score += 5.0
        elif "hostname" in field_str or "ip" in field_str:
            score += 4.0
        elif "user" in field_str:
            score += 3.0
        elif "timestamp" in field_str:
            score += 2.0

        # String literals are more selective than patterns
        if isinstance(assignment.value, str) and not assignment.value.startswith(
            "/"
        ):  # Not a regex
            score += 2.0

        return score

    def _remove_redundant_assignments(
        self, assignments: list[EventAssignment]
    ) -> list[EventAssignment]:
        """Remove redundant or contradictory assignments."""
        optimized = []
        seen_fields = {}

        for assignment in assignments:
            field_str = self._field_path_to_string(assignment.field_path)

            # Check for contradictions
            if field_str in seen_fields:
                prev_assignment = seen_fields[field_str]
                if self._are_contradictory(prev_assignment, assignment):
                    # This would make the condition always false
                    # Keep the more restrictive one
                    if self._is_more_restrictive(assignment, prev_assignment):
                        # Replace previous with this one
                        optimized = [a for a in optimized if a != prev_assignment]
                        optimized.append(assignment)
                        seen_fields[field_str] = assignment
                    self.stats.redundant_checks_removed += 1
                elif self._are_redundant(prev_assignment, assignment):
                    # Skip this one, it's redundant
                    self.stats.redundant_checks_removed += 1
                else:
                    # Both are needed
                    optimized.append(assignment)
            else:
                optimized.append(assignment)
                seen_fields[field_str] = assignment

        return optimized

    def _optimize_match_section(self, match: MatchSection) -> MatchSection:
        """Optimize match section."""
        if not match:
            return match

        # Optimize time window
        optimized_window = match.time_window
        if match.time_window:
            optimized_window = self._optimize_time_window(match.time_window)

        # Optimize match variables
        optimized_vars = []
        for var in match.variables:
            # Remove unused match variables
            if self._is_match_var_used(var.name):
                optimized_vars.append(var)

        return MatchSection(
            variables=optimized_vars,
            time_window=optimized_window,
        )

    def _optimize_time_window(self, window: Any) -> Any:
        """Optimize time window for performance."""
        # Convert large windows to more efficient units
        if hasattr(window, "duration") and hasattr(window, "unit"):
            duration = window.duration
            unit = window.unit

            # Convert seconds to minutes/hours/days
            if unit in ["s", "seconds"] and duration >= 3600:
                new_duration = duration // 3600
                new_unit = "h"
                self.stats.time_windows_optimized += 1
                window.duration = new_duration
                window.unit = new_unit
            elif unit in ["m", "minutes"] and duration >= 1440:
                new_duration = duration // 1440
                new_unit = "d"
                self.stats.time_windows_optimized += 1
                window.duration = new_duration
                window.unit = new_unit

        return window

    def _optimize_condition_section(self, condition: ConditionSection) -> ConditionSection:
        """Optimize condition section."""
        if not condition or not condition.expression:
            return condition

        # Optimize the condition expression
        optimized_expr = self._optimize_condition_expression(condition.expression)

        return ConditionSection(expression=optimized_expr)

    def _optimize_condition_expression(self, expr: ConditionExpression) -> ConditionExpression:
        """Optimize condition expression using boolean algebra."""
        # Simplify boolean expressions
        if isinstance(expr, BinaryCondition):
            return self._optimize_binary_condition(expr)

        # Remove double negations
        if (
            hasattr(expr, "operator")
            and expr.operator == "not"
            and hasattr(expr, "operand")
            and hasattr(expr.operand, "operator")
            and expr.operand.operator == "not"
        ):
            # Double negation: not (not X) = X
            self.stats.conditions_simplified += 1
            return expr.operand.operand

        return expr

    def _optimize_binary_condition(self, cond: BinaryCondition) -> BinaryCondition:
        """Optimize binary conditions."""
        # Recursively optimize left and right
        optimized_left = self._optimize_condition_expression(cond.left) if cond.left else cond.left
        optimized_right = (
            self._optimize_condition_expression(cond.right) if cond.right else cond.right
        )

        # Apply boolean algebra simplifications
        if cond.operator == "and":
            return self._optimize_and_condition(optimized_left, optimized_right)
        if cond.operator == "or":
            return self._optimize_or_condition(optimized_left, optimized_right)

        return BinaryCondition(
            left=optimized_left,
            operator=cond.operator,
            right=optimized_right,
        )

    def _optimize_and_condition(self, left: Any, right: Any) -> Any:
        """Optimize AND condition using boolean algebra rules."""
        # Boolean algebra rule: X and true = X
        if self._is_always_true(right):
            self.stats.conditions_simplified += 1
            return left
        if self._is_always_true(left):
            self.stats.conditions_simplified += 1
            return right

        # Boolean algebra rule: X and false = false
        if self._is_always_false(right) or self._is_always_false(left):
            self.stats.conditions_simplified += 1
            return self._create_false_condition()

        # Boolean algebra rule: X and X = X
        if self._are_equal_conditions(left, right):
            self.stats.conditions_simplified += 1
            return left

        return BinaryCondition(left=left, operator="and", right=right)

    def _optimize_or_condition(self, left: Any, right: Any) -> Any:
        """Optimize OR condition using boolean algebra rules."""
        # Boolean algebra rule: X or false = X
        if self._is_always_false(right):
            self.stats.conditions_simplified += 1
            return left
        if self._is_always_false(left):
            self.stats.conditions_simplified += 1
            return right

        # Boolean algebra rule: X or true = true
        if self._is_always_true(right) or self._is_always_true(left):
            self.stats.conditions_simplified += 1
            return self._create_true_condition()

        # Boolean algebra rule: X or X = X
        if self._are_equal_conditions(left, right):
            self.stats.conditions_simplified += 1
            return left

        return BinaryCondition(left=left, operator="or", right=right)

    def _optimize_outcome_section(self, outcome: OutcomeSection) -> OutcomeSection:
        """Optimize outcome section."""
        if not outcome:
            return outcome

        # Remove unused outcome variables
        optimized_vars = {}
        if hasattr(outcome, "variables"):
            for var_name, var_expr in outcome.variables.items():
                # Keep only used variables or required ones
                if self._is_outcome_var_used(var_name) or var_name in [
                    "risk_score",
                    "severity",
                ]:
                    optimized_vars[var_name] = var_expr

        return OutcomeSection(
            variables=optimized_vars,
            conditional_expressions=(
                outcome.conditional_expressions
                if hasattr(outcome, "conditional_expressions")
                else []
            ),
        )

    def _optimize_options(self, options: Any) -> Any:
        """Optimize options for better performance."""
        if not options:
            return options

        # Add performance-related options if not present
        if hasattr(options, "options"):
            if "max_events" not in options.options:
                # Set reasonable default to prevent runaway queries
                options.options["max_events"] = 10000

            if "timeout" not in options.options:
                # Set query timeout to prevent long-running queries
                options.options["timeout"] = "5m"

        return options

    # Helper methods
    def _group_event_statements(self, statements: list) -> list[list]:
        """Group similar event statements for optimization."""
        groups = []

        for stmt in statements:
            added = False
            for group in groups:
                if self._are_similar_events(stmt, group[0]):
                    group.append(stmt)
                    added = True
                    break

            if not added:
                groups.append([stmt])

        return groups

    def _are_similar_events(self, stmt1: EventStatement, stmt2: EventStatement) -> bool:
        """Check if two event statements are similar enough to combine."""
        # Same event variable
        if (
            hasattr(stmt1, "event")
            and hasattr(stmt2, "event")
            and stmt1.event
            and stmt2.event
            and stmt1.event.name != stmt2.event.name
        ):
            return False

        # Check for overlapping field assignments
        fields1 = set()
        fields2 = set()

        if hasattr(stmt1, "assignments"):
            for assignment in stmt1.assignments:
                fields1.add(self._field_path_to_string(assignment.field_path))

        if hasattr(stmt2, "assignments"):
            for assignment in stmt2.assignments:
                fields2.add(self._field_path_to_string(assignment.field_path))

        # If they have significant overlap, they're similar
        overlap = len(fields1 & fields2)
        return overlap > 0 and overlap >= min(len(fields1), len(fields2)) * 0.5

    def _combine_event_statements(self, group: list[EventStatement]) -> EventStatement | None:
        """Combine similar event statements into one optimized statement."""
        if not group:
            return None

        if len(group) == 1:
            return group[0]

        # Use the first statement as base
        base = group[0]
        combined_assignments = list(base.assignments) if hasattr(base, "assignments") else []

        # Add unique assignments from other statements
        seen_fields = set()
        for assignment in combined_assignments:
            seen_fields.add(self._field_path_to_string(assignment.field_path))

        for stmt in group[1:]:
            if hasattr(stmt, "assignments"):
                for assignment in stmt.assignments:
                    field_str = self._field_path_to_string(assignment.field_path)
                    if field_str not in seen_fields:
                        combined_assignments.append(assignment)
                        seen_fields.add(field_str)

        # Optimize the combined assignments
        combined_assignments = self._reorder_assignments(combined_assignments)
        combined_assignments = self._remove_redundant_assignments(combined_assignments)

        return EventStatement(
            event=base.event,
            assignments=combined_assignments,
        )

    def _field_path_to_string(self, field_path: UDMFieldPath) -> str:
        """Convert field path to string for comparison."""
        if hasattr(field_path, "parts"):
            return ".".join(field_path.parts)
        return str(field_path)

    def _should_index_field(self, assignment: EventAssignment) -> bool:
        """Determine if a field should be indexed for performance."""
        # Equality checks benefit most from indexes
        if assignment.operator == "=":
            return True

        # Range queries on timestamps benefit from indexes
        field_str = self._field_path_to_string(assignment.field_path)
        if "timestamp" in field_str and assignment.operator in [">", "<", ">=", "<="]:
            return True

        # High cardinality fields benefit from indexes
        high_cardinality_fields = [
            "hostname",
            "ip",
            "user_id",
            "session_id",
            "event_id",
        ]
        return any(field in field_str for field in high_cardinality_fields)

    def _are_contradictory(self, assign1: EventAssignment, assign2: EventAssignment) -> bool:
        """Check if two assignments are contradictory."""
        # Same field with = and != same value
        if assign1.operator == "=" and assign2.operator == "!=":
            return assign1.value == assign2.value
        if assign1.operator == "!=" and assign2.operator == "=":
            return assign1.value == assign2.value

        # Range contradictions
        if (
            assign1.operator == ">"
            and assign2.operator == "<"
            and isinstance(assign1.value, int | float)
            and isinstance(assign2.value, int | float)
        ):
            return assign1.value >= assign2.value

        return False

    def _are_redundant(self, assign1: EventAssignment, assign2: EventAssignment) -> bool:
        """Check if one assignment makes another redundant."""
        # Same field, same operator, same value
        if assign1.operator == assign2.operator and assign1.value == assign2.value:
            return True

        # Range redundancy
        if (
            assign1.operator == ">="
            and assign2.operator == ">"
            and isinstance(assign1.value, int | float)
            and isinstance(assign2.value, int | float)
        ):
            return assign1.value >= assign2.value

        return False

    def _is_more_restrictive(self, assign1: EventAssignment, assign2: EventAssignment) -> bool:
        """Check if assign1 is more restrictive than assign2."""
        # Equality is more restrictive than inequality
        if assign1.operator == "=" and assign2.operator != "=":
            return True

        # Smaller ranges are more restrictive
        if (
            assign1.operator in [">", ">="]
            and assign2.operator in [">", ">="]
            and isinstance(assign1.value, int | float)
            and isinstance(assign2.value, int | float)
        ):
            return assign1.value > assign2.value

        return False

    def _is_match_var_used(self, var_name: str) -> bool:
        """Check if a match variable is used in outcome or other sections."""
        # This would require full AST traversal in a complete implementation
        # For now, assume all are used
        return True

    def _is_outcome_var_used(self, var_name: str) -> bool:
        """Check if an outcome variable is used elsewhere."""
        # Reserved variables are always considered used
        return var_name in ["risk_score", "severity", "confidence"]

    def _is_always_true(self, expr: Any) -> bool:
        """Check if expression is always true."""
        # Check for literal true or tautologies
        return bool(hasattr(expr, "value") and expr.value is True)

    def _is_always_false(self, expr: Any) -> bool:
        """Check if expression is always false."""
        # Check for literal false or contradictions
        return bool(hasattr(expr, "value") and expr.value is False)

    def _are_equal_conditions(self, expr1: Any, expr2: Any) -> bool:
        """Check if two conditions are equal."""
        # Simple equality check - could be expanded
        return str(expr1) == str(expr2)

    def _create_true_condition(self) -> ConditionExpression:
        """Create an always-true condition."""
        # Create a simple true condition
        from yaraast.yaral.ast_nodes import EventExistsCondition

        return EventExistsCondition(event="true", negated=False)

    def _create_false_condition(self) -> ConditionExpression:
        """Create an always-false condition."""
        # Create a simple false condition
        from yaraast.yaral.ast_nodes import EventExistsCondition

        return EventExistsCondition(event="true", negated=True)
