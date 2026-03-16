from __future__ import annotations

from yaraast.yaral.ast_nodes import OutcomeAssignment
from yaraast.yaral.validator import YaraLValidator


def test_visit_yaral_outcome_assignment_without_accept_expression() -> None:
    validator = YaraLValidator()
    validator.current_rule = "r5"

    assignment = OutcomeAssignment(variable="$plain", expression=123)
    validator.visit_yaral_outcome_assignment(assignment)

    assert "$plain" in validator.defined_outcome_vars
    assert validator.errors == []
    assert validator.warnings == []
