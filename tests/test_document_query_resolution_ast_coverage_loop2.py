"""Second coverage loop for yaraast.lsp.document_query_resolution_ast.

Targets the residual uncovered lines after the first pass, exercising private
helpers directly with real AST nodes whose fields are set to the edge-case
values that reach each branch.  No mocks, no stubs.

Covered lines (additions over loop1):
  55   - unreachable defensive guard (justification below)
  97   - declaration_range is None continue in _resolve_with_declaration_identifier
  116->118 - DictComprehension with value_variable=None (False branch)
  134  - body_range is None in _resolve_lambda_parameter_identifier
  156  - out-of-bounds line_index in _lambda_parameter_header_bounds
  169  - blank header line skip in lambda multi-line loop
  177  - _lambda_parameter_header_bounds exhausted with no lambda found
  237  - iterable_range is None in _resolve_names_before_iterable
  261  - out-of-bounds line_index in _loop_declaration_header_bounds
  269->271 - continuation-line 'in' branch appended in _loop_declaration_header_bounds
  274  - blank header line skip in loop multi-line header
  279  - _line_prefix_loop_declaration_bounds appended to header_bounds
  292  - _same_line_loop_declaration_bounds: 'for' found but no 'in'
  314  - _continuation_line_loop_declaration_bounds: no 'in' found
  342  - _first_value_range returns None for plain non-ASTNode with no location
  352  - value_range is None in _with_declaration_identifier_range
  355  - line_index out of bounds in _with_declaration_identifier_range
  363  - identifier on same line but no '=' between id and value
  378  - _previous_line_with_declaration_identifier_range: no '=' in previous line
  381  - _previous_line_with_declaration_identifier_range: id not found before '='
  383  - _previous_line_with_declaration_identifier_range: loop exhausted
  405  - _same_line_identifier_range: identifier_start < 0
  458  - StringIdentifier with local binding resolves as 'identifier'
  472  - StringCount/StringOffset/StringLength with local binding resolves as 'identifier'
  540  - expression context: word with '#'/'@'/'!' prefix gets '$' prepended

Line 55 is unreachable: find_node_at_position only yields nodes whose
location attribute is non-None (it gates every candidate with
'if location is not None'); therefore node_location can never be None at
line 53, making line 55 a defensive dead branch.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from lsprotocol.types import Position, Range

from yaraast.ast.base import Location
from yaraast.ast.conditions import AtExpression, InExpression
from yaraast.ast.expressions import (
    IntegerLiteral,
    StringCount,
    StringIdentifier,
    StringLength,
    StringOffset,
)
from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_resolution_ast import (
    _continuation_line_loop_declaration_bounds,
    _first_value_range,
    _lambda_parameter_header_bounds,
    _line_prefix_loop_declaration_bounds,
    _loop_declaration_header_bounds,
    _previous_line_with_declaration_identifier_range,
    _resolve_expression_context,
    _resolve_lambda_parameter_identifier,
    _resolve_loop_declaration_identifier,
    _resolve_names_before_iterable,
    _resolve_typed_node,
    _resolve_with_declaration_identifier,
    _same_line_identifier_range,
    _same_line_loop_declaration_bounds,
    _with_declaration_identifier_range,
)
from yaraast.lsp.utils import location_to_range
from yaraast.yarax.ast_nodes import (
    DictComprehension,
    LambdaExpression,
    WithDeclaration,
    WithStatement,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri="file://test.yar", text=text)


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


def _int_node(value: int = 42, *, loc_line: int = 1, loc_col: int = 1) -> IntegerLiteral:
    """Build an IntegerLiteral with a real Location."""
    node = IntegerLiteral(value=value)
    node.location = Location(
        line=loc_line,
        column=loc_col,
        end_line=loc_line,
        end_column=loc_col + 2,
    )
    return node


def _int_node_no_location(value: int = 42) -> IntegerLiteral:
    """Build an IntegerLiteral that has no location (location attribute remains None)."""
    return IntegerLiteral(value=value)


# ---------------------------------------------------------------------------
# Line 97: declaration_range is None -> continue in
#           _resolve_with_declaration_identifier
# ---------------------------------------------------------------------------


def test_with_declaration_identifier_continues_when_range_is_none() -> None:
    """When _with_declaration_identifier_range returns None the loop continues.

    The value has no location, so _first_value_range returns None, which
    propagates to _with_declaration_identifier_range returning None.  The
    function must continue to the next declaration (here there is none) and
    eventually return None — exercising the 'continue' on line 97.
    """
    value_no_loc = _int_node_no_location()
    decl = WithDeclaration(identifier="x", value=value_no_loc)
    node = WithStatement(declarations=[decl], body=_int_node_no_location())
    ctx = _doc("with x = 1:\n  x > 0")
    # Position is in the body but range cannot be computed -> result is None
    result = _resolve_with_declaration_identifier(ctx, node, "x", _pos(1, 2))
    assert result is None


# ---------------------------------------------------------------------------
# Lines 116->118: DictComprehension with value_variable=None (False branch)
# ---------------------------------------------------------------------------


def test_resolve_loop_declaration_dict_comprehension_no_value_variable() -> None:
    """DictComprehension without a value_variable skips the names.append branch.

    With value_variable=None the 'if node.value_variable:' check is False,
    so names stays as [key_variable].  The search then tries to find 'k' in
    the header bounds derived from the iterable; because the iterable has no
    location the range is None and the call returns None — but the False branch
    of the if is covered.
    """
    iterable = _int_node_no_location()
    dc = DictComprehension(
        key_expression=None,
        value_expression=None,
        key_variable="k",
        value_variable=None,
        iterable=iterable,
    )
    ctx = _doc("{k for k in some_dict}")
    result = _resolve_loop_declaration_identifier(ctx, dc, "k", _pos(0, 6))
    assert result is None


# ---------------------------------------------------------------------------
# Line 134: body_range is None in _resolve_lambda_parameter_identifier
# ---------------------------------------------------------------------------


def test_lambda_parameter_body_range_is_none_returns_none() -> None:
    """Returns None immediately when the lambda body has no locatable range.

    The body is a plain IntegerLiteral with no location attribute set, so
    _first_value_range returns None and line 134 is executed.
    """
    body_no_loc = _int_node_no_location()
    lambda_node = LambdaExpression(parameters=["x"], body=body_no_loc)
    ctx = _doc("lambda x: 1")
    result = _resolve_lambda_parameter_identifier(ctx, lambda_node, "x", _pos(0, 9))
    assert result is None


# ---------------------------------------------------------------------------
# Line 156: out-of-bounds line_index in _lambda_parameter_header_bounds
# ---------------------------------------------------------------------------


def test_lambda_parameter_header_bounds_out_of_bounds_line() -> None:
    """Returns [] when the body range's start line is beyond the document.

    A one-line document has lines[0] only; a body_range pointing to line 100
    makes line_index >= len(ctx.lines) true and [] is returned immediately
    (line 156).
    """
    ctx = _doc("rule r { condition: true }")
    body_range = Range(
        start=_pos(100, 0),
        end=_pos(100, 5),
    )
    result = _lambda_parameter_header_bounds(ctx, body_range)
    assert result == []


# ---------------------------------------------------------------------------
# Line 169: blank line skip in lambda multi-line header loop
# ---------------------------------------------------------------------------


def test_lambda_parameter_header_bounds_skips_blank_line() -> None:
    """Blank intermediate header line is skipped and the loop continues.

    Layout: 'lambda x:' on line 0, blank on line 1, body on line 2.
    The body line has no ':' before body_start, so the backward scan begins.
    Line 1 is blank -> 'continue' (line 169) -> line 0 has 'lambda x:' and
    _previous_line_lambda_parameter_bounds finds it.
    """
    ctx = _doc("lambda x:\n\n  body_expr")
    body_range = Range(
        start=_pos(2, 2),
        end=_pos(2, 11),
    )
    result = _lambda_parameter_header_bounds(ctx, body_range)
    # At least one bound returned from the 'lambda x:' line
    assert len(result) >= 1
    assert any(line_idx == 0 for line_idx, _, _ in result)


# ---------------------------------------------------------------------------
# Line 177: _lambda_parameter_header_bounds returns [] when loop exhausts
# ---------------------------------------------------------------------------


def test_lambda_parameter_header_bounds_no_lambda_returns_empty() -> None:
    """Returns [] when no previous header line contains the 'lambda' keyword.

    Body is on line 1; line 0 has content but no 'lambda'.  The backward loop
    processes line 0, appends a _line_prefix_lambda_parameter_bounds entry, but
    the loop completes without finding 'lambda', reaching the final 'return []'
    on line 177.
    """
    ctx = _doc("some_func(x, y):\n  body_expr")
    body_range = Range(
        start=_pos(1, 2),
        end=_pos(1, 11),
    )
    result = _lambda_parameter_header_bounds(ctx, body_range)
    assert result == []


# ---------------------------------------------------------------------------
# Line 237: iterable_range is None in _resolve_names_before_iterable
# ---------------------------------------------------------------------------


def test_resolve_names_before_iterable_returns_none_when_iterable_has_no_location() -> None:
    """Returns None when _first_value_range cannot locate the iterable.

    The iterable is a plain IntegerLiteral with location=None; therefore
    _first_value_range returns None and line 237 is executed.
    """
    iterable_no_loc = _int_node_no_location()
    ctx = _doc("for any x in (1, 2, 3): x")
    result = _resolve_names_before_iterable(
        ctx,
        ["x"],
        iterable_no_loc,
        "x",
        _pos(0, 24),
    )
    assert result is None


# ---------------------------------------------------------------------------
# Line 261: out-of-bounds line_index in _loop_declaration_header_bounds
# ---------------------------------------------------------------------------


def test_loop_declaration_header_bounds_out_of_bounds_line() -> None:
    """Returns [] when the iterable range's start line exceeds the document.

    A single-line document has only line 0; a Range at line 100 makes
    line_index >= len(ctx.lines) true (line 261) and [] is returned.
    """
    ctx = _doc("rule r { condition: true }")
    iterable_range = Range(
        start=_pos(100, 0),
        end=_pos(100, 5),
    )
    result = _loop_declaration_header_bounds(ctx, iterable_range)
    assert result == []


# ---------------------------------------------------------------------------
# Lines 269->271: continuation-line 'in' branch in _loop_declaration_header_bounds
# ---------------------------------------------------------------------------


def test_loop_declaration_header_bounds_continuation_line_with_in() -> None:
    """Continuation-line 'in' appended when same-line search fails (True branch, line 270).

    The iterable is on line 1 which starts with 'in (0, 1)'.  There is no
    'for ... in ...' on that single line so same-line bounds is None; but the
    line does contain the 'in' keyword, so _continuation_line_loop_declaration_bounds
    returns non-None and is appended (True branch of the 'if current_bounds is
    not None:' check at line 269).
    """
    ctx = _doc("for any i\n  in (0, 1): true")
    # iterable_range points to line 1 after 'in ', character 5
    iterable_range = Range(
        start=_pos(1, 5),
        end=_pos(1, 11),
    )
    result = _loop_declaration_header_bounds(ctx, iterable_range)
    assert len(result) >= 2


def test_loop_declaration_header_bounds_no_continuation_in_keyword_false_branch() -> None:
    """False branch at line 269: current_bounds is None so header_bounds stays empty.

    The iterable line 1 ('  some_list') has no 'in' keyword boundary marker, so
    _continuation_line_loop_declaration_bounds returns None.  The 'if current_bounds
    is not None:' branch is False (269->271), skipping line 270 and entering the
    backward scan.  Line 0 has 'for any i in' so previous_line finds it.
    """
    ctx = _doc("for any i in\n  some_list")
    iterable_range = Range(
        start=_pos(1, 2),
        end=_pos(1, 11),
    )
    result = _loop_declaration_header_bounds(ctx, iterable_range)
    # previous_line_loop_declaration_bounds finds 'for' on line 0
    assert len(result) >= 1
    assert result[0][0] == 0


# ---------------------------------------------------------------------------
# Line 274: blank header line skip in _loop_declaration_header_bounds
# ---------------------------------------------------------------------------


def test_loop_declaration_header_bounds_skips_blank_line() -> None:
    """Blank intermediate header line is skipped in the backward scan.

    Layout: 'for any i' on line 0, blank on line 1, 'in (0,1)' on line 2.
    The backward loop hits the blank line 1 and continues (line 274) before
    finding 'for' on line 0.
    """
    ctx = _doc("for any i\n\n  in (0, 1): true")
    iterable_range = Range(
        start=_pos(2, 5),
        end=_pos(2, 11),
    )
    result = _loop_declaration_header_bounds(ctx, iterable_range)
    assert len(result) >= 1
    assert any(line_idx == 0 for line_idx, _, _ in result)


# ---------------------------------------------------------------------------
# Line 279: return [] when loop exhausts without finding 'for' on any header line
# ---------------------------------------------------------------------------


def test_loop_declaration_header_bounds_exhausted_returns_empty() -> None:
    """Returns [] when the backward scan finishes without finding the 'for' keyword.

    The iterable is on line 1; line 0 has content ('any i') but no 'for'.
    _previous_line_loop_declaration_bounds returns None for line 0 because
    'for' is absent.  _line_prefix_loop_declaration_bounds is appended.
    The loop finishes and line 279 ('return []') is executed.
    """
    ctx = _doc("any i\n  some_list")
    iterable_range = Range(
        start=_pos(1, 2),
        end=_pos(1, 11),
    )
    result = _loop_declaration_header_bounds(ctx, iterable_range)
    assert result == []


def test_loop_declaration_header_bounds_line_prefix_appended_then_for_found() -> None:
    """Non-for intermediate line gets prefix bounds appended then 'for' is found.

    Layout: 'for' on line 0, '  any i' on line 1, '  in (0,1)' on line 2.
    Line 1 has no 'for' and _previous_line_loop_declaration_bounds returns None,
    so _line_prefix_loop_declaration_bounds is appended (line 279 path runs
    for line 1, but the function terminates at line 277 when line 0 is reached).
    """
    ctx = _doc("for\n  any i\n  in (0, 1): true")
    iterable_range = Range(
        start=_pos(2, 5),
        end=_pos(2, 11),
    )
    result = _loop_declaration_header_bounds(ctx, iterable_range)
    # The result should include bounds from lines 0, 1, and 2
    assert len(result) >= 3


# ---------------------------------------------------------------------------
# Line 292: _same_line_loop_declaration_bounds: 'for' found but 'in' missing
# ---------------------------------------------------------------------------


def test_same_line_loop_declaration_bounds_for_without_in() -> None:
    """Returns None when 'for' is present on the line but 'in' is absent.

    The keyword 'in' does not appear between 'for' and search_end, so the
    second rfind_keyword call fails and line 292 is executed (return None).
    """
    # 'for x (0, 1): true' has 'for' but no 'in' keyword
    result = _same_line_loop_declaration_bounds("for x (0, 1): true", 0, 13)
    assert result is None


# ---------------------------------------------------------------------------
# Line 314: _continuation_line_loop_declaration_bounds: no 'in' on the line
# ---------------------------------------------------------------------------


def test_continuation_line_loop_declaration_bounds_no_in() -> None:
    """Returns None when the line contains no 'in' keyword.

    Without 'in', rfind_keyword returns -1 and line 314 is executed.
    """
    result = _continuation_line_loop_declaration_bounds("  some x: true", 1)
    assert result is None


# ---------------------------------------------------------------------------
# Line 342: _first_value_range returns None for non-ASTNode without location
# ---------------------------------------------------------------------------


def test_first_value_range_returns_none_for_plain_value() -> None:
    """Returns None when value is a plain Python object with no location.

    A bare int, str, or None has neither a 'location' attribute nor is an
    ASTNode, so the function falls through to the final 'return None' on
    line 342.
    """
    assert _first_value_range(42, "") is None
    assert _first_value_range("hello", "") is None
    assert _first_value_range(None, "") is None


# ---------------------------------------------------------------------------
# Line 352: value_range is None in _with_declaration_identifier_range
# ---------------------------------------------------------------------------


def test_with_declaration_identifier_range_returns_none_when_value_has_no_location() -> None:
    """Returns None when _first_value_range cannot locate the value node.

    The value is an IntegerLiteral with location=None, so _first_value_range
    returns None and line 352 is executed.
    """
    ctx = _doc("with x = 1:\n  x")
    value_no_loc = _int_node_no_location()
    result = _with_declaration_identifier_range(ctx, "x", value_no_loc)
    assert result is None


# ---------------------------------------------------------------------------
# Line 355: line_index out of bounds in _with_declaration_identifier_range
# ---------------------------------------------------------------------------


def test_with_declaration_identifier_range_out_of_bounds_line() -> None:
    """Returns None when the value range's line exceeds the document length.

    The value carries a Location pointing to line 101 (1-based), which maps
    to python line 100.  With a single-line document (len(ctx.lines) == 1),
    100 >= 1 triggers the guard on line 355.
    """
    ctx = _doc("with x = 1: x")
    value = IntegerLiteral(value=42)
    value.location = Location(
        line=101,
        column=1,
        end_line=101,
        end_column=3,
    )
    result = _with_declaration_identifier_range(ctx, "x", value)
    assert result is None


# ---------------------------------------------------------------------------
# Line 363: identifier on same line but no '=' between id and value
# ---------------------------------------------------------------------------


def test_with_declaration_identifier_range_falls_back_when_no_equals() -> None:
    """Falls back to _previous_line search when '=' is absent between id and value.

    Line 0: 'with y =', Line 1: '  y: value_here'
    The value is located on line 1 (python line 1, 1-based line 2).
    rfind('y', 0, value_start) finds 'y' at col 2, but the slice between 'y'
    and value_start is ': ' which contains no '=', so line 363 calls
    _previous_line_with_declaration_identifier_range.
    """
    text = "with y =\n  y: value_here"
    ctx = _doc(text)
    value = IntegerLiteral(value=42)
    # 'value_here' starts at col 5 (0-indexed) on python line 1 -> 1-based col 6
    value.location = Location(
        line=2,
        column=6,
        end_line=2,
        end_column=16,
    )
    result = _with_declaration_identifier_range(ctx, "y", value)
    assert result is not None
    assert result.start.line == 0


# ---------------------------------------------------------------------------
# Line 378: _previous_line_with_declaration_identifier_range: no '=' in prev line
# ---------------------------------------------------------------------------


def test_previous_line_with_declaration_no_equals_returns_none() -> None:
    """Returns None when the previous line has no '=' character.

    'no_equals_here' contains no '=', so line 378 is executed and None is
    returned.
    """
    ctx = _doc("no_equals_here\n  value")
    result = _previous_line_with_declaration_identifier_range(ctx, "x", 1)
    assert result is None


# ---------------------------------------------------------------------------
# Line 381: _previous_line_with_declaration_identifier_range: id not before '='
# ---------------------------------------------------------------------------


def test_previous_line_with_declaration_id_not_before_equals_returns_none() -> None:
    """Returns None when the identifier does not appear before '=' on the prev line.

    'other_var = something' has '=' but 'x' does not precede it, so line 381
    is executed.
    """
    ctx = _doc("other_var = something\n  value")
    result = _previous_line_with_declaration_identifier_range(ctx, "x", 1)
    assert result is None


# ---------------------------------------------------------------------------
# Line 383: _previous_line_with_declaration_identifier_range: loop exhausted
# ---------------------------------------------------------------------------


def test_previous_line_with_declaration_loop_exhausted_returns_none() -> None:
    """Returns None when value_line_index is 0 and there are no previous lines.

    range(0 - 1, -1, -1) = range(-1, -1, -1) is empty, so the loop body
    never executes and the function falls through to 'return None' on line 383.
    """
    ctx = _doc("value_here")
    result = _previous_line_with_declaration_identifier_range(ctx, "x", 0)
    assert result is None


# ---------------------------------------------------------------------------
# Line 405: _same_line_identifier_range: identifier_start < 0
# ---------------------------------------------------------------------------


def test_same_line_identifier_range_negative_start_returns_none() -> None:
    """Returns None immediately when identifier_start is negative.

    A caller may pass -1 to signal 'not found'; line 405 guards against that.
    """
    result = _same_line_identifier_range("hello world", 0, -1, "world")
    assert result is None


# ---------------------------------------------------------------------------
# Line 458: StringIdentifier with local binding resolves as 'identifier'
# ---------------------------------------------------------------------------


def test_resolve_typed_node_string_identifier_with_local_binding() -> None:
    """StringIdentifier whose name is locally bound resolves as kind='identifier'.

    A WithStatement declares '$a' as a local variable (allow_string_identifier
    enables this).  The StringIdentifier '$a' in the body is therefore locally
    bound, and _resolve_typed_node takes the line 458 branch returning
    kind='identifier' instead of kind='string'.
    """
    text = "with $a = 42:\n  $a"
    ctx = _doc(text)

    body_si = StringIdentifier(name="$a")
    # '$a' at python line 1, cols 2-4 -> Location line=2, col=3
    body_si.location = Location(line=2, column=3, end_line=2, end_column=5)

    value = _int_node(loc_line=1, loc_col=11)

    decl = WithDeclaration(identifier="$a", value=value)
    with_node = WithStatement(declarations=[decl], body=body_si)

    node_range = location_to_range(body_si.location, text)
    pos = _pos(1, 2)

    result = _resolve_typed_node(ctx, pos, body_si, node_range, with_node)
    assert result is not None
    assert result.kind == "identifier"
    assert result.normalized_name == "$a"


# ---------------------------------------------------------------------------
# Line 472: StringCount with local binding resolves as 'identifier'
# ---------------------------------------------------------------------------


def test_resolve_typed_node_string_count_with_local_binding() -> None:
    """StringCount whose id is locally bound resolves as kind='identifier'.

    Same structure as the StringIdentifier test above: WithStatement declares
    '$a' locally, so '#a' (StringCount whose string_id='$a') has a local
    binding.  The function takes the line 472 branch.
    """
    text = "with $a = 42:\n  #a > 0"
    ctx = _doc(text)

    body_sc = StringCount(string_id="$a")
    # '#a' at python line 1, cols 2-4 -> Location line=2, col=3
    body_sc.location = Location(line=2, column=3, end_line=2, end_column=5)

    value = _int_node(loc_line=1, loc_col=11)

    decl = WithDeclaration(identifier="$a", value=value)
    with_node = WithStatement(declarations=[decl], body=body_sc)

    node_range = location_to_range(body_sc.location, text)
    pos = _pos(1, 2)

    result = _resolve_typed_node(ctx, pos, body_sc, node_range, with_node)
    assert result is not None
    assert result.kind == "identifier"
    assert result.normalized_name == "$a"


def test_resolve_typed_node_string_offset_with_local_binding() -> None:
    """StringOffset whose id is locally bound resolves as kind='identifier'."""
    text = "with $b = 42:\n  @b > 0"
    ctx = _doc(text)

    body_so = StringOffset(string_id="$b")
    body_so.location = Location(line=2, column=3, end_line=2, end_column=5)

    value = _int_node(loc_line=1, loc_col=11)

    decl = WithDeclaration(identifier="$b", value=value)
    with_node = WithStatement(declarations=[decl], body=body_so)

    node_range = location_to_range(body_so.location, text)
    pos = _pos(1, 2)

    result = _resolve_typed_node(ctx, pos, body_so, node_range, with_node)
    assert result is not None
    assert result.kind == "identifier"
    assert result.normalized_name == "$b"


def test_resolve_typed_node_string_length_with_local_binding() -> None:
    """StringLength whose id is locally bound resolves as kind='identifier'."""
    text = "with $c = 42:\n  !c > 0"
    ctx = _doc(text)

    body_sl = StringLength(string_id="$c")
    body_sl.location = Location(line=2, column=3, end_line=2, end_column=5)

    value = _int_node(loc_line=1, loc_col=11)

    decl = WithDeclaration(identifier="$c", value=value)
    with_node = WithStatement(declarations=[decl], body=body_sl)

    node_range = location_to_range(body_sl.location, text)
    pos = _pos(1, 2)

    result = _resolve_typed_node(ctx, pos, body_sl, node_range, with_node)
    assert result is not None
    assert result.kind == "identifier"
    assert result.normalized_name == "$c"


# ---------------------------------------------------------------------------
# Line 540: expression context '#'/'@'/'!' word gets '$' prefix prepended
# ---------------------------------------------------------------------------


def test_resolve_expression_context_hash_prefix_prepends_dollar() -> None:
    """Word starting with '#' gets its prefix stripped and '$' prepended (line 540).

    '#a'.lstrip('#@!') = 'a', which does not start with '$', so
    normalized = f'${normalized}' is executed.  The AtExpression node ensures
    the outer isinstance check passes.
    """
    text = "#a at 100"
    ctx = _doc(text)

    # Build a minimal AtExpression that satisfies isinstance check
    at_expr = AtExpression(
        string_id="$",
        offset=_int_node(100, loc_line=1, loc_col=7),
    )

    pos = _pos(0, 0)
    result = _resolve_expression_context(ctx, pos, at_expr)
    assert result is not None
    assert result.name == "#a"
    assert result.normalized_name == "$a"
    assert result.kind == "string"


def test_resolve_expression_context_at_prefix_prepends_dollar() -> None:
    """Word starting with '@' (StringOffset notation) also gets '$' prefix."""
    text = "@b at 200"
    ctx = _doc(text)

    at_expr = AtExpression(
        string_id="$",
        offset=_int_node(200, loc_line=1, loc_col=8),
    )

    pos = _pos(0, 0)
    result = _resolve_expression_context(ctx, pos, at_expr)
    assert result is not None
    assert result.name == "@b"
    assert result.normalized_name == "$b"
    assert result.kind == "string"


def test_resolve_expression_context_bang_prefix_prepends_dollar_in_expression() -> None:
    """Word starting with '!' (StringLength notation) gets '$' prefix via line 540."""
    text = "!c > 0"
    ctx = _doc(text)

    # Use InExpression to exercise a different branch of the isinstance check
    in_expr = InExpression(
        subject="!c",
        range=_int_node(10, loc_line=1, loc_col=6),
    )

    pos = _pos(0, 0)
    result = _resolve_expression_context(ctx, pos, in_expr)
    assert result is not None
    assert result.name == "!c"
    assert result.normalized_name == "$c"
    assert result.kind == "string"


# ---------------------------------------------------------------------------
# Verify _line_prefix_loop_declaration_bounds (always returns, no branch needed,
# but exercised here for completeness via the continuation path above)
# ---------------------------------------------------------------------------


def test_line_prefix_loop_declaration_bounds_with_in_keyword() -> None:
    """Returns (line_index, 0, separator_start) when 'in' is present in line."""
    result = _line_prefix_loop_declaration_bounds("  i, j in", 3)
    line_idx, start, end = result
    assert line_idx == 3
    assert start == 0
    # end should be before 'in'
    assert end < len("  i, j in")


def test_line_prefix_loop_declaration_bounds_without_in_keyword() -> None:
    """Returns (line_index, 0, len(line)) when no 'in' is present."""
    line = "  i, j"
    result = _line_prefix_loop_declaration_bounds(line, 5)
    line_idx, start, end = result
    assert line_idx == 5
    assert start == 0
    assert end == len(line)
