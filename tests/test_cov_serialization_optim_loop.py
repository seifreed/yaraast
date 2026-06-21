"""
Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Coverage targets
----------------
The tests below exercise the following source positions that are reported as
uncovered or partially covered by the project's coverage configuration.

Confirmed-reachable targets
~~~~~~~~~~~~~~~~~~~~~~~~~~~
* yaraast/optimization/expression_optimizer.py  line 112
  ``_is_static_numeric_identity_operand``: the
  ``return _integer_literal_value(node) is not None`` path, which is taken
  when the operand is an ``IntegerLiteral``.  Called directly so the line is
  recorded; when invoked through the full optimizer the early two-IntegerLiteral
  constant-fold at visit_binary_expression line 276 fires first and bypasses
  ``_simplify_identity`` entirely.

Confirmed-dead-code targets (documented here so the analysis is not lost)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The remaining lines and branches listed in the task specification are all
protected by an upstream guard that fires before the target line is reached.
The pattern is: a helper such as ``_protobuf_required_nonempty_string``,
``_serialize_required_nonempty_string``, ``_deserialize_nonempty_string_field``,
or ``_deserialize_required_nullable_nonempty_string_field`` already calls
``_is_empty_nonempty_text`` / ``_is_empty_nonempty_field``, which raises
``SerializationError`` for whitespace-only strings before execution can
arrive at the redundant ``.strip()`` check in the outer function.

Specifically:
- protobuf_conversion.py  709-710, 718-719, 725-726 (convert_extern_import_to_protobuf):
  _protobuf_required_nonempty_string checks _is_empty_nonempty_text, which raises for
  whitespace strings with non-exempt contexts, so the redundant .strip() checks are
  never reached.
- protobuf_conversion.py  2068-2069, 2079-2080 (protobuf_to_extern_import): same as above.
- protobuf_conversion.py  branch [389,362] (float meta value for plain Meta without scope):
  _copy_python_value_to_legacy_meta_value at line 431 raises for float values before
  execution reaches line 389.
- protobuf_conversion.py  1409 (_restore_quantifier_text return int(value)):
  _validate_quantifier_value converts digit strings to integers before _restore_quantifier_text
  can test isdigit(), so the return is always via line 1406 (isinstance int/float).
- protobuf_conversion.py  1413-1414 (float string quantifier): _validate_quantifier_text
  always raises for parseable float strings via _invalid_quantifier before _restore_quantifier_text
  reaches line 1411.
- simple_roundtrip_helpers.py  1202-1203, 1206-1207, 1212-1213 (ExternImport serialize):
  _serialize_required_nonempty_string raises for whitespace strings via _is_empty_nonempty_text.
- simple_roundtrip_helpers.py  2048-2049, 2052-2053 (ExternImport deserialize):
  _deserialize_nonempty_string_field raises for whitespace strings via _is_empty_nonempty_field.
- json_serializer.py  625-626, 629-630, 635-636 (visit_extern_import):
  same guard as simple_roundtrip_helpers.
- json_serializer_deserialize.py  1198 (else: meta = []):
  _deserialize_required_field ensures "meta" is always present at that point; the elif
  at 1194 always fires for non-list/non-dict meta values.
- json_serializer_deserialize.py  1542-1543 (whitespace alias guard):
  _deserialize_required_nullable_nonempty_string_field raises first.
- json_serializer_deserialize.py  branch [164,166]:
  _deserialize_expression can only return None for None or {} inputs; a non-empty dict
  always matches a factory or raises, never returns None.
- json_serializer_deserialize.py  branch [1714,1716]:
  all registered factories return ASTNode subclasses.
- expression_optimizer.py  branches [223,-222] and [226,-225] (@overload stubs):
  never executed at runtime.
- expression_optimizer.py  branches [443,445] and [445,447] (ForOfExpression hasattr):
  ForOfExpression always has quantifier and string_set attrs.
- types/_expr_inference_ops.py  1560, 1616 (_infer_string_set_value returns StringSetType):
  every value that _classify_of_set_value classifies as "string" also causes
  _infer_string_set_value to return StringSetType.
- types/_expr_inference_ops.py  branch [905,909] (DictionaryAccess.key):
  DictionaryAccess always has a key attr.
- types/_expr_inference_ops.py  branch [932,931] (hasattr elem accept):
  all valid string-set elements are ASTNode subclasses with accept.
- types/_expr_inference_ops.py  branch [1155,1157] (operator "^" else path):
  all operators before "^" in the dispatch chain are handled first; the false branch
  from the last elif in the chain is structurally unreachable.
"""

from __future__ import annotations

from typing import Any

from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    BinaryExpression,
    BooleanLiteral,
    Identifier,
    IntegerLiteral,
)
from yaraast.optimization.expression_optimizer import (
    ExpressionOptimizer,
    _is_static_numeric_identity_operand,
)
from yaraast.serialization import yara_ast_pb2
from yaraast.serialization.protobuf_conversion import (
    protobuf_to_expression as _protobuf_to_expression_impl,
)

# The conversion helper is intentionally untyped in production; bind it through
# an Any alias so calling it from these annotated tests stays type-clean.
protobuf_to_expression: Any = _protobuf_to_expression_impl

# ---------------------------------------------------------------------------
# protobuf_conversion.py — line 1409
# _restore_quantifier_text: return int(value) when text is a digit-string
# ---------------------------------------------------------------------------


def _make_of_expr_with_quantifier_text(text: str) -> yara_ast_pb2.Expression:
    """Build an OfExpression protobuf with a quantifier_text field set."""
    pb = yara_ast_pb2.Expression()
    pb.of_expression.quantifier_text = text
    pb.of_expression.string_set_text = "them"
    return pb


def _make_for_expr_with_quantifier_text(text: str) -> yara_ast_pb2.Expression:
    """Build a ForExpression protobuf with a plain (non-expr) quantifier field."""
    pb = yara_ast_pb2.Expression()
    pb.for_expression.quantifier = text
    pb.for_expression.variable = "i"
    pb.for_expression.iterable.range_expression.low.integer_literal.value = 0
    pb.for_expression.iterable.range_expression.high.integer_literal.value = 5
    pb.for_expression.body.boolean_literal.value = True
    return pb


def test_restore_quantifier_text_plain_integer_for_of_expression() -> None:
    """OfExpression quantifier_text '3' is converted to the integer 3.

    _validate_quantifier_value parses '3' as the integer 3 immediately.
    _restore_quantifier_text returns at line 1406 via the
    ``isinstance(restored_value, int | float)`` guard.
    """
    pb = _make_of_expr_with_quantifier_text("3")
    result = protobuf_to_expression(pb)

    assert isinstance(result, OfExpression)
    assert result.quantifier == 3
    assert isinstance(result.quantifier, int)


def test_restore_quantifier_text_larger_integer_for_of_expression() -> None:
    """OfExpression quantifier_text '10' is converted to the integer 10.

    Confirms the fast integer path in _restore_quantifier_text for
    multi-digit values.
    """
    pb = _make_of_expr_with_quantifier_text("10")
    result = protobuf_to_expression(pb)

    assert isinstance(result, OfExpression)
    assert result.quantifier == 10
    assert isinstance(result.quantifier, int)


def test_restore_quantifier_text_sign_prefixed_integer_for_expression() -> None:
    """ForExpression quantifier text '+2' is restored to the integer 2.

    _validate_quantifier_text normalises '+2' to the integer 2.
    _restore_quantifier_text returns it via the int/float guard at line 1406.
    """
    pb = _make_for_expr_with_quantifier_text("+2")
    result = protobuf_to_expression(pb)

    assert result.quantifier == 2
    assert isinstance(result.quantifier, int)


def test_restore_quantifier_text_plain_integer_for_expression() -> None:
    """ForExpression quantifier text '5' is restored to the integer 5.

    Exercises the for-expression path through _restore_quantifier_text with
    allow_percentage=False.
    """
    pb = _make_for_expr_with_quantifier_text("5")
    result = protobuf_to_expression(pb)

    assert result.quantifier == 5
    assert isinstance(result.quantifier, int)


def test_restore_quantifier_text_keyword_all_for_of_expression() -> None:
    """OfExpression quantifier_text 'all' is left as the string 'all'.

    'all' is returned directly by _validate_quantifier_text at line 314.
    _validate_quantifier_value returns the string 'all'.
    In _restore_quantifier_text: 'all' is not int/float, 'all'.isdigit() is
    False, 'all' contains 'e' so the float-string branch at line 1411 is
    entered but float('all') raises ValueError, the except clause fires, and
    the value is returned unchanged.
    """
    pb = _make_of_expr_with_quantifier_text("all")
    result = protobuf_to_expression(pb)

    assert isinstance(result, OfExpression)
    assert result.quantifier == "all"
    assert isinstance(result.quantifier, str)


def test_restore_quantifier_text_keyword_any_of_expression() -> None:
    """OfExpression quantifier_text 'any' passes through as the string 'any'."""
    pb = _make_of_expr_with_quantifier_text("any")
    result = protobuf_to_expression(pb)

    assert isinstance(result, OfExpression)
    assert result.quantifier == "any"


# ---------------------------------------------------------------------------
# expression_optimizer.py — line 112
# _is_static_numeric_identity_operand: path that returns from IntegerLiteral
# ---------------------------------------------------------------------------


def test_is_static_numeric_identity_operand_integer_literal_with_valid_value() -> None:
    """_is_static_numeric_identity_operand returns True for IntegerLiteral(5).

    This directly calls the function so that line 112 —
    ``return _integer_literal_value(node) is not None`` — is recorded as
    executed.  When called through the full optimizer the two-IntegerLiteral
    constant-fold at line 276 fires first, bypassing _simplify_identity
    entirely, so the direct call is the only path to line 112.
    """
    node = IntegerLiteral(value=5)
    result = _is_static_numeric_identity_operand(node)
    assert result is True


def test_is_static_numeric_identity_operand_integer_literal_with_bool_value() -> None:
    """_is_static_numeric_identity_operand returns False for IntegerLiteral(True).

    ``_integer_literal_value`` returns None for bool-valued IntegerLiterals.
    The function therefore returns False at line 112.
    """
    node = IntegerLiteral(value=True)  # bool, not a plain int
    result = _is_static_numeric_identity_operand(node)
    assert result is False


def test_is_static_numeric_identity_operand_filesize_identifier() -> None:
    """_is_static_numeric_identity_operand returns True for Identifier('filesize').

    This exercises line 113, confirming both branches of the function are
    reachable.
    """
    node = Identifier(name="filesize")
    result = _is_static_numeric_identity_operand(node)
    assert result is True


def test_is_static_numeric_identity_operand_unknown_identifier() -> None:
    """_is_static_numeric_identity_operand returns False for generic Identifier.

    An identifier whose name is not 'filesize' or 'entrypoint' is not a
    statically numeric operand (line 113 returns False).
    """
    node = Identifier(name="my_variable")
    result = _is_static_numeric_identity_operand(node)
    assert result is False


def test_expression_optimizer_integer_literal_plus_zero_identity() -> None:
    """Optimising IntegerLiteral(5) + IntegerLiteral(0) returns IntegerLiteral(5).

    Both operands are IntegerLiterals, so the early constant-folding path at
    visit_binary_expression line 276 handles it (5+0=5).  The result is
    correct even though the optimizer reaches it via constant folding rather
    than via _simplify_identity.
    """
    optimizer = ExpressionOptimizer()
    expr = BinaryExpression(
        left=IntegerLiteral(value=5),
        right=IntegerLiteral(value=0),
        operator="+",
    )

    result = optimizer.optimize(expr)

    assert isinstance(result, IntegerLiteral)
    assert result.value == 5


def test_expression_optimizer_integer_literal_multiply_by_one_identity() -> None:
    """Optimising IntegerLiteral(7) * IntegerLiteral(1) returns IntegerLiteral(7).

    Both operands are IntegerLiterals.  Constant folding yields 7*1=7.
    """
    optimizer = ExpressionOptimizer()
    expr = BinaryExpression(
        left=IntegerLiteral(value=7),
        right=IntegerLiteral(value=1),
        operator="*",
    )

    result = optimizer.optimize(expr)

    assert isinstance(result, IntegerLiteral)
    assert result.value == 7


def test_expression_optimizer_zero_plus_integer_literal_identity() -> None:
    """Optimising IntegerLiteral(0) + IntegerLiteral(9) returns IntegerLiteral(9).

    Both operands are IntegerLiterals.  Constant folding yields 0+9=9.
    """
    optimizer = ExpressionOptimizer()
    expr = BinaryExpression(
        left=IntegerLiteral(value=0),
        right=IntegerLiteral(value=9),
        operator="+",
    )

    result = optimizer.optimize(expr)

    assert isinstance(result, IntegerLiteral)
    assert result.value == 9


def test_expression_optimizer_one_multiply_integer_literal_identity() -> None:
    """Optimising IntegerLiteral(1) * IntegerLiteral(4) returns IntegerLiteral(4).

    Both operands are IntegerLiterals.  Constant folding yields 1*4=4.
    """
    optimizer = ExpressionOptimizer()
    expr = BinaryExpression(
        left=IntegerLiteral(value=1),
        right=IntegerLiteral(value=4),
        operator="*",
    )

    result = optimizer.optimize(expr)

    assert isinstance(result, IntegerLiteral)
    assert result.value == 4


def test_expression_optimizer_filesize_plus_zero_identity() -> None:
    """Optimising Identifier('filesize') + IntegerLiteral(0) returns Identifier('filesize').

    _is_static_numeric_identity_operand is called for the Identifier, which
    exercises the ``isinstance(node, Identifier) and node.name in {filesize, entrypoint}``
    return path (line 113).  Combined with the previous tests, both sub-paths
    in the function are covered.
    """
    optimizer = ExpressionOptimizer()
    expr = BinaryExpression(
        left=Identifier(name="filesize"),
        right=IntegerLiteral(value=0),
        operator="+",
    )

    result = optimizer.optimize(expr)

    assert isinstance(result, Identifier)
    assert result.name == "filesize"


def test_expression_optimizer_count_optimization() -> None:
    """Optimising a constant BooleanLiteral expression returns unchanged.

    This validates the optimizer runs end-to-end and produces the same
    BooleanLiteral when there is nothing to fold.
    """
    optimizer = ExpressionOptimizer()
    lit = BooleanLiteral(value=True)
    result = optimizer.optimize(lit)
    assert isinstance(result, BooleanLiteral)
    assert result.value is True


def test_expression_optimizer_integer_literal_with_bool_value_not_simplified() -> None:
    """An IntegerLiteral whose value is a bool is not treated as a numeric identity.

    _integer_literal_value returns None for bool-valued IntegerLiterals, so
    _is_static_numeric_identity_operand returns False and the identity
    simplification is skipped.  The expression must be returned unchanged.
    """
    optimizer = ExpressionOptimizer()
    expr = BinaryExpression(
        left=IntegerLiteral(value=True),  # bool — _integer_literal_value returns None
        right=IntegerLiteral(value=0),
        operator="+",
    )
    result = optimizer.optimize(expr)

    assert isinstance(result, BinaryExpression)


# ---------------------------------------------------------------------------
# ForOfExpression optimisation round-trip (drives visit_for_of_expression)
# ---------------------------------------------------------------------------


def test_expression_optimizer_for_of_expression_passthrough() -> None:
    """Optimising a ForOfExpression does not alter it when there is nothing to fold.

    This exercises visit_for_of_expression in the optimizer and confirms that
    the node is returned intact.
    """
    optimizer = ExpressionOptimizer()
    node = ForOfExpression(quantifier="any", string_set="them", condition=None)

    result = optimizer.visit(node)

    assert isinstance(result, ForOfExpression)
    assert result.quantifier == "any"
    assert result.string_set == "them"


def test_expression_optimizer_for_of_expression_folds_quantifier() -> None:
    """An integer identity in a ForOfExpression quantifier is simplified.

    ForOfExpression(quantifier=IntegerLiteral(3) + IntegerLiteral(0), ...) should
    have its quantifier collapsed to IntegerLiteral(3) by the optimizer.
    """
    optimizer = ExpressionOptimizer()
    node = ForOfExpression(
        quantifier=BinaryExpression(
            left=IntegerLiteral(value=3),
            right=IntegerLiteral(value=0),
            operator="+",
        ),
        string_set="them",
        condition=None,
    )

    result = optimizer.visit(node)

    assert isinstance(result, ForOfExpression)
    assert isinstance(result.quantifier, IntegerLiteral)
    assert result.quantifier.value == 3
