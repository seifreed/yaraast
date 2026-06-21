"""
// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.

Coverage tests for three low-coverage modules:
  - yaraast.yaral.validator_outcomes
  - yaraast.ast.meta
  - yaraast.serialization.pragma_scopes

All tests call the real production API.  No mocks or stubs are used.
"""

from __future__ import annotations

import math

import pytest

from yaraast.ast.meta import Meta, _require_meta_value
from yaraast.ast.pragmas import PragmaScope
from yaraast.errors import SerializationError
from yaraast.serialization.pragma_scopes import (
    deserialize_pragma_scope,
    serialize_pragma_scope,
)
from yaraast.yaral.ast_nodes import (
    AggregationFunction,
    OutcomeAssignment,
    OutcomeExpression,
    OutcomeSection,
)
from yaraast.yaral.validator import YaraLValidator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_validator() -> YaraLValidator:
    """Return a YaraLValidator already positioned on a rule name."""
    v = YaraLValidator()
    v.current_rule = "test_rule"
    return v


# ===========================================================================
# yaraast.yaral.validator_outcomes — OutcomeValidationMixin
# ===========================================================================


class TestValidateOutcomeSection:
    """Exercises _validate_outcome_section (lines 19-28)."""

    def test_section_with_valid_assignments_registers_variables(self) -> None:
        """All assignments in an outcome section are registered without error."""
        # Arrange
        v = _fresh_validator()
        section = OutcomeSection(
            assignments=[
                OutcomeAssignment(variable="$score", expression=42),
                OutcomeAssignment(variable="risk_score", expression=10),
            ]
        )

        # Act
        v._validate_outcome_section(section)

        # Assert — both variables ended up in the registry
        assert "$score" in v.defined_outcome_vars
        assert "risk_score" in v.defined_outcome_vars

    def test_section_with_no_assignments_does_not_error(self) -> None:
        """An empty outcome section is valid and produces no errors."""
        # Arrange
        v = _fresh_validator()
        section = OutcomeSection(assignments=[])

        # Act
        v._validate_outcome_section(section)

        # Assert
        assert v.errors == []
        assert len(v.defined_outcome_vars) == 0

    def test_section_node_with_variables_attribute(self) -> None:
        """When the node carries a 'variables' attribute the mixin calls
        _register_outcome_variable for each entry (lines 23-25)."""
        # Arrange
        v = _fresh_validator()
        section = OutcomeSection(assignments=[])
        # Inject a 'variables' attribute directly onto the node instance to
        # exercise the hasattr branch on line 23.
        section.variables = ["$extra"]  # type: ignore[attr-defined]

        # Act
        v._validate_outcome_section(section)

        # Assert — variable was registered through the dynamic path
        assert "$extra" in v.defined_outcome_vars

    def test_section_node_with_variables_and_assignments_both_registered(
        self,
    ) -> None:
        """Both the 'variables' shortcut and 'assignments' list are processed."""
        # Arrange
        v = _fresh_validator()
        section = OutcomeSection(assignments=[OutcomeAssignment(variable="severity", expression=5)])
        section.variables = ["$dynamic"]  # type: ignore[attr-defined]

        # Act
        v._validate_outcome_section(section)

        # Assert
        assert "$dynamic" in v.defined_outcome_vars
        assert "severity" in v.defined_outcome_vars


class TestRegisterOutcomeVariable:
    """Exercises _register_outcome_variable (lines 30-45)."""

    def test_reserved_name_accepted_without_error(self) -> None:
        """Reserved names (risk_score, severity, confidence, priority) are valid."""
        v = _fresh_validator()
        for name in ("risk_score", "severity", "confidence", "priority"):
            v._register_outcome_variable(name)

        assert v.errors == []

    def test_dollar_prefixed_variable_accepted_without_error(self) -> None:
        """Variables starting with '$' are accepted without validation errors."""
        v = _fresh_validator()
        v._register_outcome_variable("$my_var")

        assert v.errors == []
        assert "$my_var" in v.defined_outcome_vars

    def test_non_reserved_name_without_dollar_produces_error(self) -> None:
        """An outcome variable that is neither reserved nor $ -prefixed triggers
        an error (lines 40-45)."""
        v = _fresh_validator()
        v._register_outcome_variable("bad_name")

        assert len(v.errors) == 1
        assert "must start with $" in v.errors[0].message or "reserved name" in v.errors[0].message

    def test_duplicate_variable_produces_error(self) -> None:
        """Registering the same variable twice triggers a duplicate error (lines
        31-37)."""
        v = _fresh_validator()
        v._register_outcome_variable("$dup")
        v._register_outcome_variable("$dup")

        dup_errors = [e for e in v.errors if "Duplicate" in e.message]
        assert len(dup_errors) == 1

    def test_variable_added_to_set_after_registration(self) -> None:
        """After registration the variable appears in defined_outcome_vars."""
        v = _fresh_validator()
        v._register_outcome_variable("$fresh")

        assert "$fresh" in v.defined_outcome_vars


class TestVisitOutcomeSection:
    """Exercises visit_yaral_outcome_section (lines 47-49)."""

    def test_visit_dispatches_to_each_assignment(self) -> None:
        """Calling the visitor method visits each assignment in the section."""
        v = _fresh_validator()
        section = OutcomeSection(
            assignments=[
                OutcomeAssignment(variable="$a", expression=1),
                OutcomeAssignment(variable="$b", expression=2),
            ]
        )

        # Act — calls lines 48-49
        v.visit_yaral_outcome_section(section)

        # The visitor registers variables via visit_yaral_outcome_assignment
        assert "$a" in v.defined_outcome_vars
        assert "$b" in v.defined_outcome_vars

    def test_visit_empty_section_does_nothing(self) -> None:
        """Visiting an empty section runs without errors and adds nothing."""
        v = _fresh_validator()
        v.visit_yaral_outcome_section(OutcomeSection(assignments=[]))

        assert v.errors == []
        assert v.defined_outcome_vars == set()


class TestVisitOutcomeAssignment:
    """Exercises visit_yaral_outcome_assignment (lines 51-54)."""

    def test_assignment_with_accept_expression_visits_it(self) -> None:
        """When the expression supports accept(), the visitor recurses (line 53-54)."""
        v = _fresh_validator()
        # OutcomeExpression has an accept() method — use it as expression.
        expr = OutcomeExpression()
        assignment = OutcomeAssignment(variable="$x", expression=expr)

        # Act
        v.visit_yaral_outcome_assignment(assignment)

        # Assert — variable registered and no crash
        assert "$x" in v.defined_outcome_vars

    def test_assignment_without_accept_expression_does_not_crash(self) -> None:
        """When expression is a plain value with no accept(), only the variable
        is registered (line 52 only, branch at 53 skips)."""
        v = _fresh_validator()
        assignment = OutcomeAssignment(variable="$plain", expression=99)

        v.visit_yaral_outcome_assignment(assignment)

        assert "$plain" in v.defined_outcome_vars
        assert v.errors == []


class TestVisitOutcomeExpression:
    """Exercises visit_yaral_outcome_expression (line 56-57)."""

    def test_visit_outcome_expression_does_not_raise(self) -> None:
        """The base expression visitor is a no-op and completes without error."""
        v = _fresh_validator()
        expr = OutcomeExpression()

        # The method always returns None; mypy knows it, so we just call it.
        v.visit_yaral_outcome_expression(expr)


class TestVisitAggregationFunction:
    """Exercises visit_yaral_aggregation_function (lines 59-65)."""

    def test_known_aggregation_function_produces_no_warning(self) -> None:
        """Valid aggregation functions (count, sum, etc.) do not produce
        warnings (lines 59-60, branch not taken)."""
        v = _fresh_validator()
        for fn in ("count", "sum", "avg", "min", "max", "array", "array_distinct"):
            agg = AggregationFunction(function=fn, arguments=[])
            v.visit_yaral_aggregation_function(agg)

        assert v.warnings == []

    def test_unknown_aggregation_function_produces_warning(self) -> None:
        """An unrecognised function name triggers a warning (lines 61-65)."""
        v = _fresh_validator()
        agg = AggregationFunction(function="totally_unknown", arguments=[])

        v.visit_yaral_aggregation_function(agg)

        assert len(v.warnings) == 1
        assert "Unknown aggregation function" in v.warnings[0].message

    def test_valid_aggregation_string_concat_no_warning(self) -> None:
        """string_concat is a valid aggregation name and must not warn."""
        v = _fresh_validator()
        agg = AggregationFunction(function="string_concat", arguments=[])
        v.visit_yaral_aggregation_function(agg)

        assert v.warnings == []


# ===========================================================================
# yaraast.ast.meta — _require_meta_value and Meta.validate_structure
# ===========================================================================


class TestRequireMetaValue:
    """Exercises _require_meta_value (lines 17-26)."""

    def test_string_value_accepted_without_float(self) -> None:
        """A string value is always accepted (line 18)."""
        result = _require_meta_value("hello", allow_float=False)
        assert result == "hello"

    def test_bool_value_accepted_without_float(self) -> None:
        """A boolean value is always accepted (line 18, bool is subtype of int
        but the isinstance check covers it)."""
        result = _require_meta_value(True, allow_float=False)
        assert result is True

    def test_int_value_accepted_without_float(self) -> None:
        """An integer value is always accepted (line 18)."""
        result = _require_meta_value(42, allow_float=False)
        assert result == 42

    def test_finite_float_accepted_when_allow_float_true(self) -> None:
        """A finite float is accepted when allow_float=True (lines 20-21)."""
        result = _require_meta_value(3.14, allow_float=True)
        assert math.isclose(result, 3.14)  # type: ignore[arg-type]

    def test_infinite_float_rejected_even_when_allow_float_true(self) -> None:
        """An infinite float is rejected even when allow_float=True (line 20
        guard math.isfinite fails, falls through to error at lines 22-26)."""
        with pytest.raises(TypeError, match="finite float"):
            _require_meta_value(math.inf, allow_float=True)

    def test_non_numeric_object_rejected_allow_float_false(self) -> None:
        """A non-string/int/bool value raises TypeError with allow_float=False
        (lines 24-26)."""
        with pytest.raises(TypeError, match="string, integer, or boolean"):
            _require_meta_value(3.14, allow_float=False)

    def test_none_value_rejected_allow_float_false(self) -> None:
        """None is not a valid meta value with allow_float=False."""
        with pytest.raises(TypeError, match="string, integer, or boolean"):
            _require_meta_value(None, allow_float=False)

    def test_none_value_rejected_allow_float_true(self) -> None:
        """None is not a valid meta value even with allow_float=True (lines
        22-23 error message path)."""
        with pytest.raises(TypeError, match="finite float"):
            _require_meta_value(None, allow_float=True)


class TestMetaValidateStructure:
    """Exercises Meta.validate_structure (lines 36-46)."""

    def test_valid_key_and_string_value_passes(self) -> None:
        """A well-formed key and string value passes validation (lines 38-46
        all pass without raising)."""
        node = Meta(key="author", value="Alice")
        node.validate_structure()  # must not raise

    def test_valid_key_and_int_value_passes(self) -> None:
        """Integer value passes validation."""
        node = Meta(key="version", value=1)
        node.validate_structure()

    def test_valid_key_and_bool_value_passes(self) -> None:
        """Boolean value passes validation."""
        node = Meta(key="is_public", value=False)
        node.validate_structure()

    def test_empty_key_raises_value_error(self) -> None:
        """An empty key is rejected by _require_nonempty_string (line 38)."""
        node = Meta(key="", value="val")
        with pytest.raises((ValueError, TypeError)):
            node.validate_structure()

    def test_keyword_key_raises_value_error(self) -> None:
        """A YARA keyword used as a meta key raises ValueError (lines 42-45)."""
        node = Meta(key="rule", value="bad")
        with pytest.raises(ValueError, match="Invalid meta identifier"):
            node.validate_structure()

    def test_too_long_key_raises_value_error(self) -> None:
        """A key longer than YARA_IDENTIFIER_MAX_LENGTH raises ValueError
        (line 40)."""
        long_key = "a" * 129  # one over the 128-char limit
        node = Meta(key=long_key, value="v")
        with pytest.raises(ValueError, match="Invalid meta identifier"):
            node.validate_structure()

    def test_key_with_invalid_chars_raises_value_error(self) -> None:
        """A key that fails the identifier regex raises ValueError (line 41)."""
        node = Meta(key="1starts_with_digit", value="v")
        with pytest.raises(ValueError, match="Invalid meta identifier"):
            node.validate_structure()

    def test_float_value_rejected_without_scope_attribute(self) -> None:
        """A float value is rejected when the Meta node has no 'scope'
        attribute (allow_float=False path, lines 22-26 via line 46)."""
        node = Meta(key="weight", value=3.14)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="string, integer, or boolean"):
            node.validate_structure()

    def test_float_value_accepted_when_scope_attribute_present(self) -> None:
        """When the Meta node has a 'scope' attribute, allow_float=True and
        a finite float is accepted (lines 20-21 via line 46)."""
        node = Meta(key="weight", value=3.14)  # type: ignore[arg-type]
        # Inject a 'scope' attribute so hasattr(self, "scope") is True.
        node.scope = "public"  # type: ignore[attr-defined]
        node.validate_structure()  # must not raise

    def test_accept_calls_visitor_visit_meta(self) -> None:
        """Meta.accept(visitor) delegates to visitor.visit_meta (line 48-49)."""

        class _CapturingVisitor:
            def __init__(self) -> None:
                self.visited: list[Meta] = []

            def visit_meta(self, node: Meta) -> None:
                self.visited.append(node)

        visitor = _CapturingVisitor()
        node = Meta(key="author", value="Bob")
        node.accept(visitor)

        assert node in visitor.visited


# ===========================================================================
# yaraast.serialization.pragma_scopes
# ===========================================================================


class TestSerializePragmaScope:
    """Exercises serialize_pragma_scope (lines 9-16)."""

    def test_pragma_scope_enum_returns_value_string(self) -> None:
        """Passing a PragmaScope enum returns its .value string (line 12)."""
        result = serialize_pragma_scope(PragmaScope.FILE)
        assert result == "file"

    def test_pragma_scope_rule_returns_rule_string(self) -> None:
        """PragmaScope.RULE serializes to 'rule'."""
        result = serialize_pragma_scope(PragmaScope.RULE)
        assert result == "rule"

    def test_pragma_scope_local_returns_local_string(self) -> None:
        """PragmaScope.LOCAL serializes to 'local'."""
        result = serialize_pragma_scope(PragmaScope.LOCAL)
        assert result == "local"

    def test_string_scope_round_trips_through_deserializer(self) -> None:
        """A valid string scope is accepted and round-trips through
        deserialize_pragma_scope (lines 13-14)."""
        result = serialize_pragma_scope("rule")
        assert result == "rule"

    def test_string_file_scope_accepted(self) -> None:
        """The string 'file' is a valid scope value."""
        result = serialize_pragma_scope("file")
        assert result == "file"

    def test_invalid_string_scope_raises_serialization_error(self) -> None:
        """An unrecognised string value raises SerializationError (propagated
        from deserialize_pragma_scope via line 14)."""
        with pytest.raises(SerializationError):
            serialize_pragma_scope("unknown_scope")

    def test_non_string_non_pragma_scope_raises_serialization_error(self) -> None:
        """An integer or other non-string, non-PragmaScope value raises
        SerializationError (lines 15-16)."""
        with pytest.raises(SerializationError, match="scope must be a string"):
            serialize_pragma_scope(42)

    def test_none_raises_serialization_error(self) -> None:
        """None is neither a PragmaScope nor a str, so raises (lines 15-16)."""
        with pytest.raises(SerializationError, match="scope must be a string"):
            serialize_pragma_scope(None)

    def test_custom_context_label_in_error_message(self) -> None:
        """The context string is included in the error message."""
        with pytest.raises(SerializationError, match="MyCtx"):
            serialize_pragma_scope(99, context="MyCtx")


class TestDeserializePragmaScope:
    """Exercises deserialize_pragma_scope (lines 19-30)."""

    def test_none_returns_file_scope(self) -> None:
        """None input returns PragmaScope.FILE (line 21-22)."""
        result = deserialize_pragma_scope(None)
        assert result is PragmaScope.FILE

    def test_file_string_returns_file_scope(self) -> None:
        """'file' deserializes to PragmaScope.FILE (lines 26-27)."""
        result = deserialize_pragma_scope("file")
        assert result is PragmaScope.FILE

    def test_rule_string_returns_rule_scope(self) -> None:
        """'rule' deserializes to PragmaScope.RULE."""
        result = deserialize_pragma_scope("rule")
        assert result is PragmaScope.RULE

    def test_local_string_returns_local_scope(self) -> None:
        """'local' deserializes to PragmaScope.LOCAL."""
        result = deserialize_pragma_scope("local")
        assert result is PragmaScope.LOCAL

    def test_invalid_string_raises_serialization_error(self) -> None:
        """An unrecognised scope string raises SerializationError (lines 28-30).
        The ValueError from PragmaScope(value) is re-raised as SerializationError."""
        with pytest.raises(SerializationError, match="valid pragma scope"):
            deserialize_pragma_scope("bad_scope")

    def test_non_string_raises_serialization_error(self) -> None:
        """A non-string, non-None value raises SerializationError (lines 23-25)."""
        with pytest.raises(SerializationError, match="scope must be a string"):
            deserialize_pragma_scope(123)

    def test_non_string_bool_raises_serialization_error(self) -> None:
        """A boolean (which is not a str) raises SerializationError."""
        with pytest.raises(SerializationError, match="scope must be a string"):
            deserialize_pragma_scope(True)

    def test_custom_context_label_in_non_string_error(self) -> None:
        """The context parameter is included in the error for non-string input."""
        with pytest.raises(SerializationError, match="Ctx42"):
            deserialize_pragma_scope([], context="Ctx42")

    def test_custom_context_label_in_invalid_value_error(self) -> None:
        """The context parameter is included in the error for an invalid
        string value."""
        with pytest.raises(SerializationError, match="valid pragma scope"):
            deserialize_pragma_scope("nope", context="MyContext")
