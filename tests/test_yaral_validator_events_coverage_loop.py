# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage-completion tests for yaraast.yaral.validator_events.

Targets the lines that remain uncovered after test_yaral_validator_events_more.py:

    24->31   visit_events_section: non-empty statements branch (skip error, enter for loop)
    32       for statement in node.statements: self.visit(statement)
    78->81   visit_event_assignment: event_var is falsy branch skip
    81->84   visit_event_assignment: field_path is falsy branch skip
    101      _is_regex_value: hasattr(value, "pattern") -> return True
    112-113  _validate_udm_field_path: normalized parts empty -> second error branch
    121->exit _validate_udm_field_path: valid namespace with only 1 part (elif not taken)
    164-184  _extract_udm_validation_segments: bracket notation path (full function body)
    168-170  _extract_udm_validation_segments: no-bracket path with segment appended
    172-183  _extract_udm_validation_segments: bracket found: segment before + bracket content

Note: line 168->170 (False branch of 'if segment:' at line 168) is structurally
unreachable.  The 'while index < len(part)' guard guarantees that when
bracket_index == -1, part[index:] has at least one character, so 'segment' is
always truthy at that point.  This is documented below rather than fabricated.

All tests go through the real YaraLValidator (which inherits EventValidationMixin)
and the real module-level helpers _normalize_udm_validation_parts and
_extract_udm_validation_segments.  No mocks, stubs, or test doubles are used.
"""

from __future__ import annotations

from yaraast.yaral.ast_nodes import (
    EventAssignment,
    EventsSection,
    EventStatement,
    EventVariable,
    UDMFieldPath,
)
from yaraast.yaral.validator import YaraLValidator
from yaraast.yaral.validator_events import (
    _extract_udm_validation_segments,
    _normalize_udm_validation_parts,
)

# ---------------------------------------------------------------------------
# Helpers used across multiple tests
# ---------------------------------------------------------------------------


def _fresh_validator() -> YaraLValidator:
    """Return a YaraLValidator with current_rule pre-set."""
    v = YaraLValidator()
    v.current_rule = "test_rule"
    return v


def _make_assignment(
    var_name: str,
    parts: list[str],
    operator: str = "=",
    value: str = "LOGIN",
) -> EventAssignment:
    return EventAssignment(
        event_var=EventVariable(name=var_name),
        field_path=UDMFieldPath(parts=parts),
        operator=operator,
        value=value,
    )


# ---------------------------------------------------------------------------
# Lines 24->31, 32 - visit_events_section with non-empty statements
# ---------------------------------------------------------------------------


def test_events_section_with_statements_visits_each_child() -> None:
    """Non-empty EventsSection skips the empty-section error and visits children.

    This exercises the False branch of `if not node.statements` (24->31) and
    the `for statement ...` body at line 32.
    """
    validator = _fresh_validator()
    ev = EventVariable(name="$e")
    fp = UDMFieldPath(parts=["metadata", "event_type"])
    assignment = EventAssignment(
        event_var=ev,
        field_path=fp,
        operator="=",
        value="LOGIN",
    )
    section = EventsSection(statements=[assignment])

    validator.visit_events_section(section)

    # The section itself produced no error (no "cannot be empty" message)
    assert not any("Events section cannot be empty" in e.message for e in validator.errors)
    # The child EventAssignment was visited - a valid assignment produces no errors/warnings
    assert validator.errors == []
    assert validator.warnings == []


def test_events_section_visits_multiple_children_in_order() -> None:
    """Multiple EventAssignment children in EventsSection are all visited.

    Validates the for-loop at line 32 iterates over every statement.
    """
    validator = _fresh_validator()
    a1 = _make_assignment("$e", ["metadata", "event_type"])
    a2 = _make_assignment("$e", ["principal", "ip"])  # $e already defined; allow_existing=True
    section = EventsSection(statements=[a1, a2])

    validator.visit_events_section(section)

    # Both children visited without errors (event variable re-use allowed in assignments)
    assert validator.errors == []
    assert validator.warnings == []


def test_events_section_visits_child_that_produces_warning() -> None:
    """Visiting a child EventStatement (no assignments) records the warning.

    Confirms the for-loop at line 32 propagates side effects from child visitors.
    """
    validator = _fresh_validator()
    # Base EventStatement has no assignments attribute; visit_event_statement
    # treats absence of assignments as empty and emits a warning.
    stmt = EventStatement(text='$e.metadata.event_type = "LOGIN"')
    section = EventsSection(statements=[stmt])

    validator.visit_events_section(section)

    assert not any("Events section cannot be empty" in e.message for e in validator.errors)
    assert any("has no field assignments" in w.message for w in validator.warnings)


# ---------------------------------------------------------------------------
# Lines 78->81 - visit_event_assignment: event_var is falsy (None)
# ---------------------------------------------------------------------------


def test_event_assignment_with_none_event_var_skips_define_event_variable() -> None:
    """When event_var is None, _define_event_variable is not called (line 78->81 False).

    EventAssignment stores event_var as EventVariable at runtime but the type
    annotation allows None at the dataclass level.  Passing None exercises the
    `if hasattr(node, 'event_var') and node.event_var:` False branch without
    errors.  The field_path validation runs normally.
    """
    validator = _fresh_validator()
    # event_var=None is accepted by the dataclass constructor; the validator's
    # hasattr check passes (the attribute exists) but the truthiness check fails.
    assignment = EventAssignment(
        event_var=None,  # type: ignore[arg-type]
        field_path=UDMFieldPath(parts=["metadata", "event_type"]),
        operator="=",
        value="LOGIN",
    )

    validator.visit_event_assignment(assignment)

    # No errors: field_path is valid; no duplicate-var check triggered
    assert validator.errors == []
    assert validator.warnings == []


# ---------------------------------------------------------------------------
# Lines 81->84 - visit_event_assignment: field_path is falsy
# ---------------------------------------------------------------------------


def test_event_assignment_with_none_field_path_skips_udm_validation() -> None:
    """When field_path is None, _validate_udm_field_path is not called (line 81->84 False).

    The event_var is processed normally (defining '$e' in defined_events via
    allow_existing=True), but UDM validation is entirely skipped.
    """
    validator = _fresh_validator()
    assignment = EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=None,  # type: ignore[arg-type]
        operator="=",
        value="LOGIN",
    )

    validator.visit_event_assignment(assignment)

    # '$e' is now defined (allow_existing=True path executed)
    assert "e" in validator.defined_events
    # No UDM errors emitted because field_path was skipped
    assert validator.errors == []


def test_event_assignment_with_both_none_skips_both_optional_blocks() -> None:
    """Both event_var and field_path None: both optional blocks are skipped entirely."""
    validator = _fresh_validator()
    assignment = EventAssignment(
        event_var=None,  # type: ignore[arg-type]
        field_path=None,  # type: ignore[arg-type]
        operator="=",
        value="LOGIN",
    )

    validator.visit_event_assignment(assignment)

    assert validator.errors == []
    assert validator.warnings == []


# ---------------------------------------------------------------------------
# Line 101 - _is_regex_value: object with .pattern attribute returns True
# ---------------------------------------------------------------------------


class _PatternHolder:
    """Object with a .pattern attribute - simulates a compiled regex value.

    Used to verify that _is_regex_value returns True at line 101 when the
    value has a .pattern attribute, preventing a spurious regex-usage warning.
    """

    pattern: str = "/test/"


def test_event_assignment_regex_operator_with_pattern_value_no_warning() -> None:
    """_is_regex_value returns True immediately when value has .pattern (line 101).

    The consequence is that no regex-usage warning is emitted for =~ operator.
    """
    validator = _fresh_validator()
    assignment = EventAssignment(
        event_var=EventVariable(name="$e"),
        field_path=UDMFieldPath(parts=["metadata", "event_type"]),
        operator="=~",
        value=_PatternHolder(),  # type: ignore[arg-type]
    )

    validator.visit_event_assignment(assignment)

    # No "Regex operator ... should be used with regex pattern" warning expected
    # because _is_regex_value returned True at line 101 (pattern attr path)
    assert not any("Regex operator" in w.message for w in validator.warnings)
    assert validator.errors == []


def test_is_regex_value_returns_true_for_pattern_attribute_directly() -> None:
    """Direct call to _is_regex_value with a .pattern-holder returns True at line 101."""
    validator = _fresh_validator()
    assert validator._is_regex_value(_PatternHolder()) is True


def test_is_regex_value_returns_true_for_slash_delimited_string() -> None:
    """_is_regex_value returns True for a /pattern/ string (non-pattern-attr path)."""
    validator = _fresh_validator()
    assert validator._is_regex_value("/some-pattern/") is True


def test_is_regex_value_returns_false_for_plain_string() -> None:
    """_is_regex_value returns False for a string that is not /.../ delimited."""
    validator = _fresh_validator()
    assert validator._is_regex_value("plain_value") is False


def test_is_regex_value_returns_false_for_integer() -> None:
    """_is_regex_value returns False for an integer value (no .pattern, not a str)."""
    validator = _fresh_validator()
    assert validator._is_regex_value(42) is False


# ---------------------------------------------------------------------------
# Lines 112-113 - _validate_udm_field_path: normalized parts empty
# ---------------------------------------------------------------------------


def test_validate_udm_field_path_empty_after_normalization_adds_error() -> None:
    """UDMFieldPath with a single empty-string part produces the second Empty error.

    _normalize_udm_validation_parts(['']) calls _extract_udm_validation_segments('')
    which returns [] because the while loop body is never entered (len('') == 0),
    so normalized stays empty.  Lines 112-113 fire.
    """
    validator = _fresh_validator()

    # UDMFieldPath with a single empty-string element passes the first guard
    # (node.parts is non-empty) but produces an empty normalized list.
    validator._validate_udm_field_path(UDMFieldPath(parts=[""]))

    assert any("Empty UDM field path" in e.message for e in validator.errors)


# ---------------------------------------------------------------------------
# Line 121->exit - valid namespace with only 1 part (elif not taken)
# ---------------------------------------------------------------------------


def test_validate_udm_field_path_valid_namespace_single_part_no_warning() -> None:
    """A path that resolves to a single known namespace emits no warning.

    namespace is in VALID_UDM_FIELDS but len(parts) == 1, so the
    `elif len(parts) > 1` branch at line 121 is skipped (121->exit).
    """
    validator = _fresh_validator()

    # Single-element list containing a known namespace name
    validator._validate_udm_field_path(UDMFieldPath(parts=["metadata"]))

    assert validator.errors == []
    assert validator.warnings == []


def test_validate_udm_field_path_principal_namespace_single_part_no_warning() -> None:
    """Single-part 'principal' namespace: elif skipped just as with 'metadata'."""
    validator = _fresh_validator()

    validator._validate_udm_field_path(UDMFieldPath(parts=["principal"]))

    assert validator.errors == []
    assert validator.warnings == []


# ---------------------------------------------------------------------------
# Lines 164-184 - _extract_udm_validation_segments: full bracket paths
#
# Structural note: the False branch of 'if segment:' at line 168 (168->170)
# is not reachable in practice.  The while guard 'index < len(part)' ensures
# part[index:] always contains at least one character when bracket_index == -1,
# so 'segment' is always truthy at that point.  No test is fabricated for it.
# ---------------------------------------------------------------------------


def test_extract_segments_empty_string_returns_empty_list() -> None:
    """Empty input: while loop never entered, returns [].  Exercises line 164 False exit."""
    result = _extract_udm_validation_segments("")
    assert result == []


def test_extract_segments_plain_segment_no_bracket() -> None:
    """No bracket: lines 166-170 are taken (bracket_index == -1 path).

    segment is non-empty -> appended -> break.
    """
    result = _extract_udm_validation_segments("hostname")
    assert result == ["hostname"]


def test_extract_segments_bracket_with_quoted_key() -> None:
    """Bracket with double-quoted content: lines 172-174, 180-182 taken.

    segment before bracket is appended (lines 173-174), bracket_value is
    quoted (line 181 True) so inner key is appended (line 182).
    """
    result = _extract_udm_validation_segments('field["key"]')
    assert result == ["field", "key"]


def test_extract_segments_bracket_at_start_no_leading_segment() -> None:
    """Bracket at index 0: segment before bracket is '' -> line 173 False, not appended."""
    result = _extract_udm_validation_segments('["namespace"]')
    assert result == ["namespace"]


def test_extract_segments_bracket_with_unquoted_content_not_appended() -> None:
    """Bracket value not double-quoted: line 181 False -> bracket_value not appended.

    Only the segment before the bracket is included; content inside is ignored.
    """
    result = _extract_udm_validation_segments("field[0]")
    # segment 'field' is appended, '0' is not (not quoted), nothing after ']'
    assert result == ["field"]


def test_extract_segments_bracket_with_unquoted_content_with_trailing() -> None:
    """Non-quoted bracket content skipped; segment after ']' is captured next iteration."""
    result = _extract_udm_validation_segments("a[b]c")
    assert result == ["a", "c"]


def test_extract_segments_unclosed_bracket_breaks() -> None:
    """Unclosed bracket: end_index == -1 -> lines 177-178 (break).

    Segment before the bracket IS appended; no content after break.
    """
    result = _extract_udm_validation_segments("field[unclosed")
    assert result == ["field"]


def test_extract_segments_unclosed_bracket_at_start() -> None:
    """Unclosed bracket at index 0: empty leading segment, then break at line 178."""
    result = _extract_udm_validation_segments("[unclosed")
    # No segment before bracket; no close bracket -> break immediately
    assert result == []


def test_extract_segments_multiple_brackets_all_quoted() -> None:
    """Multiple brackets in one part: loop iterates several times.

    Each bracket pass exercises lines 164-183 repeatedly, with the trailing
    plain segment captured at lines 166-170 on the final iteration.
    """
    result = _extract_udm_validation_segments('a["b"]["c"]d')
    assert result == ["a", "b", "c", "d"]


def test_extract_segments_bracket_value_single_quoted_char() -> None:
    """Single-char quoted bracket_value: len('\"x\"') == 3 >= 2 and quoted, so appended."""
    result = _extract_udm_validation_segments('field["x"]')
    # bracket_value = '"x"' (3 chars), conditions at line 181 True -> 'x' appended
    assert result == ["field", "x"]


def test_extract_segments_bracket_value_empty_not_appended() -> None:
    """Empty bracket_value (length 0 < 2): line 181 False, bracket content skipped."""
    result = _extract_udm_validation_segments("field[]rest")
    # bracket_value='' (len=0 < 2) -> not appended; 'rest' captured next iteration
    assert result == ["field", "rest"]


def test_extract_segments_bracket_value_empty_quotes() -> None:
    """Bracket with empty quoted string '\"\"': bracket_value len 2, [0]==[-1]=='\"' -> appended."""
    result = _extract_udm_validation_segments('field[""]')
    # bracket_value='""' (len=2), [0]=='"' [1]=='"', so inner value '' appended
    assert "field" in result
    assert "" in result


# ---------------------------------------------------------------------------
# _normalize_udm_validation_parts: single dotted part vs multi-part
# ---------------------------------------------------------------------------


def test_normalize_single_dotted_part_splits_on_dot() -> None:
    """Single element with '.' is split on dot; each segment goes through _extract.

    This exercises the ternary True branch in _normalize_udm_validation_parts.
    """
    result = _normalize_udm_validation_parts(["metadata.event_type"])
    assert result == ["metadata", "event_type"]


def test_normalize_multi_part_uses_parts_directly() -> None:
    """Multi-element list is used as-is (ternary False branch in normalize)."""
    result = _normalize_udm_validation_parts(["metadata", "event_type"])
    assert result == ["metadata", "event_type"]


def test_normalize_single_dotted_part_with_bracket_notation() -> None:
    """Single dotted part containing bracket notation is split then bracket-extracted."""
    result = _normalize_udm_validation_parts(['principal["hostname"]'])
    # Splitting on '.' gives ['principal["hostname"]'] (no dot present)
    # then _extract processes bracket: segment='principal', bracket_value='"hostname"'
    assert result == ["principal", "hostname"]


# ---------------------------------------------------------------------------
# Integration: bracket-notation path through _validate_udm_field_path
# ---------------------------------------------------------------------------


def test_validate_udm_field_path_bracket_notation_known_field() -> None:
    """UDMFieldPath with bracket notation resolves to known namespace+field without warning."""
    validator = _fresh_validator()

    # 'principal["hostname"]' -> normalize -> ['principal', 'hostname']
    # namespace 'principal' is known, 'hostname' is a valid field -> no warning
    validator._validate_udm_field_path(UDMFieldPath(parts=['principal["hostname"]']))

    assert validator.errors == []
    assert validator.warnings == []


def test_validate_udm_field_path_bracket_notation_unknown_field() -> None:
    """Bracket notation that resolves to an unknown field emits the field warning."""
    validator = _fresh_validator()

    # 'principal["nonexistent"]' -> namespace 'principal' known, field 'nonexistent' unknown
    validator._validate_udm_field_path(UDMFieldPath(parts=['principal["nonexistent"]']))

    assert validator.errors == []
    assert any("Unknown field 'nonexistent'" in w.message for w in validator.warnings)


def test_validate_udm_field_path_bracket_notation_namespace_only() -> None:
    """Single bracket segment resolves to a namespace only: elif not taken (121->exit)."""
    validator = _fresh_validator()

    # '["metadata"]' -> bracket_value='"metadata"' -> normalize -> ['metadata']
    # namespace 'metadata' known, len(normalized)==1 -> elif len(parts) > 1 skipped
    validator._validate_udm_field_path(UDMFieldPath(parts=['["metadata"]']))

    assert validator.errors == []
    assert validator.warnings == []
