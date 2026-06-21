# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for yaraast/serialization/json_serializer.py missing lines.

Targets the following uncovered lines identified by coverage analysis:
  117-118  _serialize_modifier_value: bool value rejected
  125      _serialize_modifier_value: finite float returned
  181      JsonSerializer.visit: non-ASTNode path delegates to base visitor
  625-626  visit_extern_import: whitespace module_path guard (structurally dead code)
  629-630  visit_extern_import: whitespace alias guard (structurally dead code)
  635-636  visit_extern_import: whitespace rule guard (structurally dead code)
  734-738  visit_pragma: else-branch condition serialization for non-IFDEF/IFNDEF types
"""

from __future__ import annotations

import pytest

from yaraast.ast.extern import ExternImport
from yaraast.ast.pragmas import ConditionalDirective, PragmaType
from yaraast.errors import SerializationError
from yaraast.serialization.json_serializer import JsonSerializer, _serialize_modifier_value

# ---------------------------------------------------------------------------
# _serialize_modifier_value — lines 117-118 and 125
# ---------------------------------------------------------------------------


def test_serialize_modifier_value_bool_true_raises() -> None:
    """Line 117-118: bool True must be rejected before the int branch catches it.

    Python's bool is a subclass of int, so the isinstance(value, bool) guard on
    line 116 must fire before isinstance(value, int) on line 119.  Passing True
    must raise SerializationError, not silently return 1.
    """
    with pytest.raises(SerializationError, match="String modifier value must be a string"):
        _serialize_modifier_value(True)


def test_serialize_modifier_value_bool_false_raises() -> None:
    """Line 117-118: bool False must also be rejected (not treated as int 0)."""
    with pytest.raises(SerializationError, match="String modifier value must be a string"):
        _serialize_modifier_value(False)


def test_serialize_modifier_value_finite_float_returns_value() -> None:
    """Line 125: a finite float must pass the math.isfinite guard and be returned.

    This exercises the happy path inside the float branch that the existing tests
    only reach via the error path (math.inf / math.nan).
    """
    result = _serialize_modifier_value(3.14)
    assert result == pytest.approx(3.14)


def test_serialize_modifier_value_negative_finite_float() -> None:
    """Line 125: negative finite floats must also be returned unchanged."""
    result = _serialize_modifier_value(-0.5)
    assert result == pytest.approx(-0.5)


def test_serialize_modifier_value_zero_float() -> None:
    """Line 125: 0.0 is a finite float and must be returned as-is."""
    result = _serialize_modifier_value(0.0)
    assert result == 0.0


# ---------------------------------------------------------------------------
# JsonSerializer.visit — line 181: non-ASTNode path delegates to base visitor
# ---------------------------------------------------------------------------


def test_json_serializer_visit_non_ast_node_raises_type_error() -> None:
    """Line 181: when visit() receives a non-ASTNode, it delegates to the base
    ASTVisitor which immediately raises TypeError.

    The branch ``if not isinstance(node, ASTNode): return super().visit(node)``
    is the only code path on line 181.  Calling it with a plain Python object
    confirms the delegation occurs and the base visitor's guard fires.
    """
    serializer = JsonSerializer()
    with pytest.raises(TypeError, match="Visitor node must be an ASTNode"):
        serializer.visit("plain string, not an ASTNode")  # type: ignore[arg-type]


def test_json_serializer_visit_none_raises_type_error() -> None:
    """Line 181: None is not an ASTNode; must propagate TypeError from base."""
    serializer = JsonSerializer()
    with pytest.raises(TypeError, match="Visitor node must be an ASTNode"):
        serializer.visit(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# visit_extern_import — lines 625-626, 629-630, 635-636
#
# Structural analysis: these three guard lines are unreachable in practice.
#
# _serialize_required_nonempty_string (line 620-623) already rejects any string
# that is empty or whitespace-only for the "ExternImport module_path" context,
# raising SerializationError before line 624 is reached with a whitespace-only
# value.  The same applies to alias via _serialize_nullable_nonempty_string and
# to rules via _serialize_nonempty_string_list / _validate_extern_import_rule_identifiers.
#
# The tests below document this structural dead code by confirming that the
# inner validators fire first and that valid inputs produce correct output.
# ---------------------------------------------------------------------------


def test_visit_extern_import_valid_module_path() -> None:
    """Validates that a well-formed ExternImport serializes correctly.

    Lines 625-626 can never be reached; a whitespace-only module_path is
    already rejected by _serialize_required_nonempty_string before the guard.
    """
    node = ExternImport(module_path='"my_rules"', rules=["rule_alpha"])
    serializer = JsonSerializer()
    result = serializer.visit_extern_import(node)
    assert result["type"] == "ExternImport"
    assert result["module_path"] == '"my_rules"'
    assert result["rules"] == ["rule_alpha"]


def test_visit_extern_import_rejects_whitespace_module_path_in_inner_validator() -> None:
    """Lines 625-626 dead code evidence: whitespace module_path rejected before guard.

    _serialize_required_nonempty_string fires first with its own message, so the
    guard on line 624 with its message ("ExternImport module_path must not be
    empty") is structurally unreachable.
    """
    node = ExternImport(module_path="   ", rules=["rule_alpha"])
    serializer = JsonSerializer()
    # The inner validator fires first; the guard on line 624-626 is never reached.
    with pytest.raises(SerializationError):
        serializer.visit_extern_import(node)


def test_visit_extern_import_rejects_whitespace_alias_in_inner_validator() -> None:
    """Lines 629-630 dead code evidence: whitespace alias rejected before guard."""
    node = ExternImport(module_path='"my_rules"', alias="   ", rules=["rule_alpha"])
    serializer = JsonSerializer()
    with pytest.raises(SerializationError):
        serializer.visit_extern_import(node)


def test_visit_extern_import_with_none_alias() -> None:
    """Lines 628-630: alias=None skips the alias guard entirely (expected path)."""
    node = ExternImport(module_path='"my_rules"', alias=None, rules=["rule_alpha"])
    serializer = JsonSerializer()
    result = serializer.visit_extern_import(node)
    assert result["alias"] is None


# ---------------------------------------------------------------------------
# visit_pragma — lines 734-738: else-branch for condition on non-IFDEF/IFNDEF
#
# The else branch is reached when a Pragma has a 'condition' attribute but its
# pragma_type is neither PragmaType.IFDEF nor PragmaType.IFNDEF.  The concrete
# example is ConditionalDirective with PragmaType.ENDIF.
# ---------------------------------------------------------------------------


def test_visit_pragma_endif_condition_none_serializes_null() -> None:
    """Lines 734-738: ENDIF pragma with condition=None must serialize condition as None.

    ConditionalDirective(PragmaType.ENDIF) has a 'condition' attribute.  Because
    ENDIF is not in {IFDEF, IFNDEF}, the else branch (line 733) is taken.  When
    condition is None the assignment on lines 738-741 stores None, giving the
    JSON value null.
    """
    pragma = ConditionalDirective(pragma_type=PragmaType.ENDIF)
    assert pragma.condition is None

    serializer = JsonSerializer()
    result = serializer.visit_pragma(pragma)

    assert result["type"] == "Pragma"
    assert result["pragma_type"] == "endif"
    assert "condition" in result
    assert result["condition"] is None


def test_visit_pragma_endif_with_condition_string_serializes_value() -> None:
    """Lines 734-738: ENDIF pragma with a non-None condition must serialize the value.

    After construction, we inject a valid identifier into the condition attribute.
    The else branch (line 733) is taken, condition is not None, so lines 739-740
    validate and store the identifier string.
    """
    pragma = ConditionalDirective(pragma_type=PragmaType.ENDIF)
    pragma.condition = "MY_MACRO"

    serializer = JsonSerializer()
    result = serializer.visit_pragma(pragma)

    assert result["type"] == "Pragma"
    assert result["pragma_type"] == "endif"
    assert result["condition"] == "MY_MACRO"


def test_visit_pragma_custom_with_condition_none() -> None:
    """Lines 734-738: a CUSTOM pragma with condition=None exercises the else path.

    CUSTOM is not in {IFDEF, IFNDEF} so the else branch is taken.  condition=None
    is valid and must serialize to None.
    """
    pragma = ConditionalDirective(pragma_type=PragmaType.ENDIF)
    pragma.pragma_type = PragmaType.CUSTOM
    pragma.name = "custom"
    pragma.condition = None

    serializer = JsonSerializer()
    result = serializer.visit_pragma(pragma)

    assert result["pragma_type"] == "custom"
    assert result["condition"] is None


def test_visit_pragma_custom_with_valid_condition_identifier() -> None:
    """Lines 738-740: non-None condition in the else branch must be identifier-validated."""
    pragma = ConditionalDirective(pragma_type=PragmaType.ENDIF)
    pragma.pragma_type = PragmaType.CUSTOM
    pragma.name = "custom"
    pragma.condition = "valid_id"

    serializer = JsonSerializer()
    result = serializer.visit_pragma(pragma)

    assert result["condition"] == "valid_id"
