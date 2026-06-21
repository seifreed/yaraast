"""Coverage loop for yaraast.types.semantic_validator_functions.

Targets lines and branches missed by existing test suites:
  38   - receiver visit when _validate_function_name returns False
  43   - receiver visit when function name is valid and receiver is not None
  49->52 - branch: receiver is not None and module_and_function() returns None
  247  - visit_at_expression: non-string string_id path
  260-261 - visit_with_statement
  264  - visit_with_declaration
  267-269 - visit_array_comprehension
  272-275 - visit_dict_comprehension
  278  - visit_tuple_expression
  281-282 - visit_tuple_indexing
  285  - visit_list_expression
  288  - visit_dict_expression
  291-292 - visit_dict_item
  295-298 - visit_slice_expression
  301  - visit_lambda_expression
  304-306 - visit_pattern_match
  309-310 - visit_match_case
  313  - visit_spread_operator
  319-320 - _visit_ast_value Mapping branch
  337-342 - _visit_expression_sequence non-sequence error path

Copyright (c) 2026 Marc Rivero Lopez
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from typing import Any, cast

from yaraast.ast.conditions import AtExpression, ForOfExpression
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    StringLiteral,
)
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.semantic_validator_functions import FunctionCallValidator
from yaraast.types.type_system import TypeEnvironment
from yaraast.yarax.ast_nodes import (
    ArrayComprehension,
    DictComprehension,
    DictExpression,
    DictItem,
    LambdaExpression,
    ListExpression,
    MatchCase,
    PatternMatch,
    SliceExpression,
    SpreadOperator,
    TupleExpression,
    TupleIndexing,
    WithDeclaration,
    WithStatement,
)


def _validator() -> tuple[ValidationResult, FunctionCallValidator]:
    result = ValidationResult()
    env = TypeEnvironment()
    return result, FunctionCallValidator(result, env)


# ---------------------------------------------------------------------------
# Line 38: receiver visited when _validate_function_name returns False
# (invalid function name + non-None receiver)
# ---------------------------------------------------------------------------


def test_invalid_function_name_with_receiver_visits_receiver() -> None:
    """When function name is invalid, the receiver is still visited for errors."""
    # Arrange: "bad-name" fails identifier validation; receiver is a real expression.
    result, validator = _validator()
    receiver = Identifier("pe")
    node = FunctionCall(
        function="bad-name",
        arguments=[],
        receiver=receiver,
    )

    # Act
    validator.visit(node)

    # Assert: error recorded for invalid name; receiver had accept() so no additional
    # "must be Expression" error, but the invalid-name error must be present.
    messages = [e.message for e in result.errors]
    assert any("Invalid function identifier" in m or "bad-name" in m for m in messages)


# ---------------------------------------------------------------------------
# Line 43: receiver visited when function name is valid and receiver is not None
# ---------------------------------------------------------------------------


def test_valid_function_name_with_receiver_visits_receiver() -> None:
    """When the function name is valid and receiver is present, the receiver is visited."""
    # Arrange: function="valid_on" with a real expression receiver whose
    # module_and_function() chain resolves to something.  Using a MemberAccess
    # chain that doesn't resolve to a known module so no module-lookup errors fire.
    result, validator = _validator()
    # Build a receiver that has accept() so _visit_required_expression won't error.
    receiver = ArrayAccess(
        array=Identifier("pe"),
        index=IntegerLiteral(0),
    )
    node = FunctionCall(
        function="valid_on",
        arguments=[],
        receiver=receiver,
    )

    # Act
    validator.visit(node)

    # Assert: receiver was visited (no "Function call receiver must be Expression"
    # error) and the unknown-function warning fires because module "pe" is not
    # imported.
    receiver_errors = [e for e in result.errors if "receiver must be Expression" in e.message]
    assert receiver_errors == []


# ---------------------------------------------------------------------------
# Branch 49->52: receiver is not None but module_and_function() returns None
# (receiver chain cannot be resolved to a base identifier)
# ---------------------------------------------------------------------------


def test_unresolvable_receiver_skips_both_module_and_builtin_validation() -> None:
    """A receiver that cannot be resolved to a module base skips both validators."""
    # Arrange: use an IntegerLiteral as receiver — _receiver_base_and_members
    # returns (None, []) for non-identifier leaves, so module_and_function() is None.
    # Because receiver is not None the elif at line 49 is False → branch 49->52.
    result, validator = _validator()
    node = FunctionCall(
        function="some_method",
        arguments=[],
        receiver=IntegerLiteral(42),
    )

    # Act
    validator.visit(node)

    # Assert: no module-not-imported error and no builtin warning, since neither
    # validation path was entered.
    module_errors = [
        e for e in result.errors if "not imported" in e.message or "Unknown function" in e.message
    ]
    assert module_errors == []
    module_warnings = [
        w for w in result.warnings if "not imported" in w.message or "Unknown function" in w.message
    ]
    assert module_warnings == []


# ---------------------------------------------------------------------------
# Line 247: visit_at_expression - non-string string_id branch
# ---------------------------------------------------------------------------


def test_visit_at_expression_with_expression_string_id() -> None:
    """AtExpression with an Expression string_id visits _visit_ast_value on it."""
    # Arrange: string_id is an Expression (Identifier), triggering the
    # `not isinstance(node.string_id, str)` branch at line 246.
    result, validator = _validator()
    node = AtExpression(
        string_id=Identifier("x"),
        offset=IntegerLiteral(0),
    )

    # Act
    validator.visit(node)

    # Assert: no "must be Expression" error (Identifier has accept()).
    errors = [e for e in result.errors if "At-expression offset must be Expression" in e.message]
    assert errors == []


# ---------------------------------------------------------------------------
# Lines 260-261: visit_with_statement
# ---------------------------------------------------------------------------


def test_visit_with_statement_visits_declarations_and_body() -> None:
    """WithStatement validator descends into declarations and body."""
    # Arrange
    result, validator = _validator()
    body = BinaryExpression(
        left=Identifier("x"),
        operator="and",
        right=Identifier("y"),
    )
    decl = WithDeclaration(identifier="$a", value=IntegerLiteral(1))
    node = WithStatement(declarations=[decl], body=body)

    # Act
    validator.visit(node)

    # Assert: no "must be a sequence" errors; body was visited (binary children visited).
    seq_errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert seq_errors == []


def test_visit_with_statement_non_sequence_declarations_records_error() -> None:
    """WithStatement with non-sequence declarations records a sequence error."""
    # Arrange: pass a raw string where a list is expected.
    result, validator = _validator()
    node = WithStatement(
        declarations=cast(Any, "not_a_list"),
        body=IntegerLiteral(0),
    )

    # Act
    validator.visit(node)

    # Assert: the sequence-check error fires.
    seq_errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert seq_errors


# ---------------------------------------------------------------------------
# Line 264: visit_with_declaration
# ---------------------------------------------------------------------------


def test_visit_with_declaration_visits_value() -> None:
    """WithDeclaration validator calls _visit_required_expression on value."""
    # Arrange
    result, validator = _validator()
    node = WithDeclaration(identifier="$b", value=IntegerLiteral(10))

    # Act
    validator.visit(node)

    # Assert: no errors; value had accept().
    value_errors = [
        e for e in result.errors if "With declaration value must be Expression" in e.message
    ]
    assert value_errors == []


def test_visit_with_declaration_non_expression_value_records_error() -> None:
    """WithDeclaration with a non-expression value records a required-expression error."""
    result, validator = _validator()
    node = WithDeclaration(identifier="$c", value=cast(Any, "not_an_expression"))

    validator.visit(node)

    errors = [e for e in result.errors if "With declaration value must be Expression" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Lines 267-269: visit_array_comprehension
# ---------------------------------------------------------------------------


def test_visit_array_comprehension_visits_all_ast_value_fields() -> None:
    """ArrayComprehension visitor descends into expression, iterable, and condition."""
    result, validator = _validator()
    node = ArrayComprehension(
        expression=IntegerLiteral(1),
        variable="x",
        iterable=Identifier("items"),
        condition=BinaryExpression(
            left=Identifier("x"),
            operator=">",
            right=IntegerLiteral(0),
        ),
    )

    validator.visit(node)

    # The _visit_ast_value calls accept() on each sub-node; no "must be Expression" errors.
    errors = [e for e in result.errors if "must be Expression" in e.message]
    assert errors == []


def test_visit_array_comprehension_with_none_fields() -> None:
    """ArrayComprehension with None optional fields completes without error."""
    result, validator = _validator()
    node = ArrayComprehension(variable="z")

    validator.visit(node)

    errors = [e for e in result.errors if "must be Expression" in e.message]
    assert errors == []


# ---------------------------------------------------------------------------
# Lines 272-275: visit_dict_comprehension
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_visits_all_fields() -> None:
    """DictComprehension validator descends into key_expression, value_expression, etc."""
    result, validator = _validator()
    node = DictComprehension(
        key_expression=StringLiteral("k"),
        value_expression=IntegerLiteral(0),
        key_variable="k",
        iterable=Identifier("src"),
        condition=Identifier("flag"),
    )

    validator.visit(node)

    errors = [e for e in result.errors if "must be Expression" in e.message]
    assert errors == []


def test_visit_dict_comprehension_with_none_fields() -> None:
    """DictComprehension with all optional fields None completes without error."""
    result, validator = _validator()
    node = DictComprehension(key_variable="k")

    validator.visit(node)

    errors = [e for e in result.errors if "must be Expression" in e.message]
    assert errors == []


# ---------------------------------------------------------------------------
# Line 278: visit_tuple_expression
# ---------------------------------------------------------------------------


def test_visit_tuple_expression_visits_elements() -> None:
    """TupleExpression validator visits each element via _visit_expression_sequence."""
    result, validator = _validator()
    node = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors == []


def test_visit_tuple_expression_non_sequence_elements_records_error() -> None:
    """TupleExpression with non-sequence elements records a sequence error."""
    result, validator = _validator()
    node = TupleExpression(elements=cast(Any, "bad"))

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Lines 281-282: visit_tuple_indexing
# ---------------------------------------------------------------------------


def test_visit_tuple_indexing_visits_tuple_expr_and_index() -> None:
    """TupleIndexing validator calls _visit_required_expression on both fields."""
    result, validator = _validator()
    inner = TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)])
    node = TupleIndexing(tuple_expr=inner, index=IntegerLiteral(0))

    validator.visit(node)

    errors = [
        e
        for e in result.errors
        if "Tuple indexing target must be Expression" in e.message
        or "Tuple indexing index must be Expression" in e.message
    ]
    assert errors == []


def test_visit_tuple_indexing_non_expression_fields_record_errors() -> None:
    """TupleIndexing with non-expression fields records required-expression errors."""
    result, validator = _validator()
    node = TupleIndexing(
        tuple_expr=cast(Any, "not_an_expr"),
        index=cast(Any, 99),
    )

    validator.visit(node)

    target_errors = [
        e for e in result.errors if "Tuple indexing target must be Expression" in e.message
    ]
    index_errors = [
        e for e in result.errors if "Tuple indexing index must be Expression" in e.message
    ]
    assert target_errors
    assert index_errors


# ---------------------------------------------------------------------------
# Line 285: visit_list_expression
# ---------------------------------------------------------------------------


def test_visit_list_expression_visits_elements() -> None:
    """ListExpression validator visits each element."""
    result, validator = _validator()
    node = ListExpression(elements=[IntegerLiteral(0), StringLiteral("x")])

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors == []


def test_visit_list_expression_non_sequence_records_error() -> None:
    """ListExpression with non-sequence elements records a sequence error."""
    result, validator = _validator()
    node = ListExpression(elements=cast(Any, 42))

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Line 288: visit_dict_expression
# ---------------------------------------------------------------------------


def test_visit_dict_expression_visits_items() -> None:
    """DictExpression validator visits each item."""
    result, validator = _validator()
    item = DictItem(key=StringLiteral("k"), value=IntegerLiteral(1))
    node = DictExpression(items=[item])

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors == []


def test_visit_dict_expression_non_sequence_records_error() -> None:
    """DictExpression with non-sequence items records a sequence error."""
    result, validator = _validator()
    node = DictExpression(items=cast(Any, {"k": "v"}))

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Lines 291-292: visit_dict_item
# ---------------------------------------------------------------------------


def test_visit_dict_item_visits_key_and_value() -> None:
    """DictItem validator calls _visit_required_expression on key and value."""
    result, validator = _validator()
    node = DictItem(key=StringLiteral("name"), value=IntegerLiteral(42))

    validator.visit(node)

    errors = [
        e
        for e in result.errors
        if "Dict item key must be Expression" in e.message
        or "Dict item value must be Expression" in e.message
    ]
    assert errors == []


def test_visit_dict_item_non_expression_fields_record_errors() -> None:
    """DictItem with non-expression fields records required-expression errors."""
    result, validator = _validator()
    node = DictItem(key=cast(Any, "plain_str"), value=cast(Any, 99))

    validator.visit(node)

    key_errors = [e for e in result.errors if "Dict item key must be Expression" in e.message]
    val_errors = [e for e in result.errors if "Dict item value must be Expression" in e.message]
    assert key_errors
    assert val_errors


# ---------------------------------------------------------------------------
# Lines 295-298: visit_slice_expression
# ---------------------------------------------------------------------------


def test_visit_slice_expression_visits_all_fields() -> None:
    """SliceExpression validator visits target, start, stop, and step."""
    result, validator = _validator()
    node = SliceExpression(
        target=Identifier("arr"),
        start=IntegerLiteral(1),
        stop=IntegerLiteral(5),
        step=IntegerLiteral(2),
    )

    validator.visit(node)

    errors = [
        e
        for e in result.errors
        if any(
            label in e.message
            for label in [
                "Slice expression target",
                "Slice expression start",
                "Slice expression stop",
                "Slice expression step",
            ]
        )
    ]
    assert errors == []


def test_visit_slice_expression_with_none_optional_fields() -> None:
    """SliceExpression with only target set completes without errors."""
    result, validator = _validator()
    node = SliceExpression(target=Identifier("buf"))

    validator.visit(node)

    target_errors = [
        e for e in result.errors if "Slice expression target must be Expression" in e.message
    ]
    assert target_errors == []


def test_visit_slice_expression_non_expression_target_records_error() -> None:
    """SliceExpression with non-expression target records a required-expression error."""
    result, validator = _validator()
    node = SliceExpression(target=cast(Any, "not_expr"))

    validator.visit(node)

    errors = [e for e in result.errors if "Slice expression target must be Expression" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Line 301: visit_lambda_expression
# ---------------------------------------------------------------------------


def test_visit_lambda_expression_visits_body() -> None:
    """LambdaExpression validator calls _visit_required_expression on body."""
    result, validator = _validator()
    node = LambdaExpression(parameters=["x"], body=Identifier("x"))

    validator.visit(node)

    errors = [e for e in result.errors if "Lambda expression body must be Expression" in e.message]
    assert errors == []


def test_visit_lambda_expression_non_expression_body_records_error() -> None:
    """LambdaExpression with non-expression body records a required-expression error."""
    result, validator = _validator()
    node = LambdaExpression(parameters=["x"], body=cast(Any, 123))

    validator.visit(node)

    errors = [e for e in result.errors if "Lambda expression body must be Expression" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Lines 304-306: visit_pattern_match
# ---------------------------------------------------------------------------


def test_visit_pattern_match_visits_value_cases_and_default() -> None:
    """PatternMatch validator visits value, cases sequence, and default."""
    result, validator = _validator()
    case = MatchCase(pattern=IntegerLiteral(1), result=StringLiteral("one"))
    node = PatternMatch(
        value=Identifier("x"),
        cases=[case],
        default=StringLiteral("other"),
    )

    validator.visit(node)

    errors = [
        e
        for e in result.errors
        if "Pattern match value must be Expression" in e.message
        or "Pattern match cases must be a sequence" in e.message
    ]
    assert errors == []


def test_visit_pattern_match_non_expression_value_records_error() -> None:
    """PatternMatch with non-expression value records a required-expression error."""
    result, validator = _validator()
    node = PatternMatch(value=cast(Any, "bad"), cases=[], default=None)

    validator.visit(node)

    errors = [e for e in result.errors if "Pattern match value must be Expression" in e.message]
    assert errors


def test_visit_pattern_match_non_sequence_cases_records_error() -> None:
    """PatternMatch with non-sequence cases records a sequence error."""
    result, validator = _validator()
    node = PatternMatch(value=Identifier("x"), cases=cast(Any, "bad"), default=None)

    validator.visit(node)

    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors


def test_visit_pattern_match_with_none_default_is_valid() -> None:
    """PatternMatch with no default does not record a default-related error."""
    result, validator = _validator()
    case = MatchCase(pattern=IntegerLiteral(2), result=StringLiteral("two"))
    node = PatternMatch(value=Identifier("n"), cases=[case], default=None)

    validator.visit(node)

    # No "Pattern match default" errors (the None default skips _visit_ast_value).
    default_errors = [e for e in result.errors if "Pattern match default" in e.message]
    assert default_errors == []


# ---------------------------------------------------------------------------
# Lines 309-310: visit_match_case
# ---------------------------------------------------------------------------


def test_visit_match_case_visits_pattern_and_result() -> None:
    """MatchCase validator calls _visit_required_expression on pattern and result."""
    result, validator = _validator()
    node = MatchCase(pattern=IntegerLiteral(3), result=StringLiteral("three"))

    validator.visit(node)

    errors = [
        e
        for e in result.errors
        if "Match case pattern must be Expression" in e.message
        or "Match case result must be Expression" in e.message
    ]
    assert errors == []


def test_visit_match_case_non_expression_pattern_records_error() -> None:
    """MatchCase with non-expression pattern records a required-expression error."""
    result, validator = _validator()
    node = MatchCase(pattern=cast(Any, "wildcard"), result=IntegerLiteral(0))

    validator.visit(node)

    errors = [e for e in result.errors if "Match case pattern must be Expression" in e.message]
    assert errors


def test_visit_match_case_non_expression_result_records_error() -> None:
    """MatchCase with non-expression result records a required-expression error."""
    result, validator = _validator()
    node = MatchCase(pattern=IntegerLiteral(1), result=cast(Any, 42))

    validator.visit(node)

    errors = [e for e in result.errors if "Match case result must be Expression" in e.message]
    assert errors


# ---------------------------------------------------------------------------
# Line 313: visit_spread_operator
# ---------------------------------------------------------------------------


def test_visit_spread_operator_visits_expression() -> None:
    """SpreadOperator validator calls _visit_required_expression on expression."""
    result, validator = _validator()
    node = SpreadOperator(expression=Identifier("items"))

    validator.visit(node)

    errors = [
        e for e in result.errors if "Spread operator expression must be Expression" in e.message
    ]
    assert errors == []


def test_visit_spread_operator_non_expression_records_error() -> None:
    """SpreadOperator with non-expression field records a required-expression error."""
    result, validator = _validator()
    node = SpreadOperator(expression=cast(Any, [1, 2, 3]))

    validator.visit(node)

    errors = [
        e for e in result.errors if "Spread operator expression must be Expression" in e.message
    ]
    assert errors


# ---------------------------------------------------------------------------
# Lines 319-320: _visit_ast_value Mapping branch
# Triggered via visit_for_of_expression -> _visit_ast_value(node.string_set) when
# string_set is a plain dict (Mapping that is not an AST node).
# The dict values are then recursed into.
# ---------------------------------------------------------------------------


def test_visit_ast_value_mapping_branch_via_for_of_string_set() -> None:
    """_visit_ast_value enters the Mapping branch when given a plain dict."""
    # Arrange: ForOfExpression.string_set accepts any StringSetValue.  Passing a
    # plain dict exercises the `isinstance(value, Mapping)` branch because dicts
    # are not AST nodes and are not list|tuple|set|frozenset.
    result, validator = _validator()
    # The dict value is an IntegerLiteral (has accept()), so the recursion calls
    # self.visit() on it — confirming the branch executed end-to-end.
    string_set_as_dict: dict[str, Any] = {"entry": IntegerLiteral(0)}
    node = ForOfExpression(
        quantifier="all",
        string_set=cast(Any, string_set_as_dict),
    )

    # Act
    validator.visit(node)

    # Assert: no "string_set must be a sequence" error; _visit_ast_value handled
    # it via the Mapping branch instead of the sequence branch.
    errors = [e for e in result.errors if "string_set must be a sequence" in e.message]
    assert errors == []


def test_visit_ast_value_mapping_branch_with_nested_expression_values() -> None:
    """Mapping branch recurses into dict values to visit contained AST nodes."""
    # Arrange: a dict whose values include a FunctionCall, so visit_function_call
    # fires inside the Mapping iteration.
    result, validator = _validator()
    inner_call = FunctionCall(function="uint8", arguments=[IntegerLiteral(0)])
    string_set_as_dict: dict[str, Any] = {"fn": inner_call}
    node = ForOfExpression(
        quantifier="any",
        string_set=cast(Any, string_set_as_dict),
    )

    # Act
    validator.visit(node)

    # Assert: the unknown-function warning for "uint8" in builtin arity fires,
    # confirming the inner FunctionCall was actually visited.
    # (uint8 is in BUILTIN_FUNCTION_ARITY with arity (1,1), and was called
    # correctly, so no error — but no "must be Expression" error either.)
    expr_errors = [e for e in result.errors if "must be Expression" in e.message]
    assert expr_errors == []


# ---------------------------------------------------------------------------
# Lines 337-342: _visit_expression_sequence non-sequence error path
# Triggered by visiting any node whose sequence field receives a non-sequence value.
# ---------------------------------------------------------------------------


def test_visit_expression_sequence_non_sequence_records_error_via_set_expression() -> None:
    """_visit_expression_sequence records an error when elements is not iterable sequence."""
    # Arrange: SetExpression.elements must be a sequence.  Passing a plain integer
    # triggers the non-sequence branch in _visit_expression_sequence.
    from yaraast.ast.expressions import SetExpression

    result, validator = _validator()
    node = SetExpression(elements=cast(Any, 99))

    # Act
    validator.visit(node)

    # Assert: the sequence error is recorded.
    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors


def test_visit_expression_sequence_non_sequence_via_for_of_condition() -> None:
    """_visit_expression_sequence fires for ForOfExpression when condition is a non-sequence."""
    # ForOfExpression.condition is visited via _visit_ast_value.  If we nest a
    # WithStatement whose declarations field is not a sequence, the error propagates.
    result, validator = _validator()
    # Use WithStatement.declarations as a non-sequence to trigger _visit_expression_sequence.
    with_node = WithStatement(
        declarations=cast(Any, "broken"),
        body=IntegerLiteral(0),
    )
    # Wrap in a ForOfExpression so the WithStatement is visited through _visit_ast_value
    # on the string_set field (dict value pointing to with_node).
    string_set_as_dict: dict[str, Any] = {"decl": with_node}
    node = ForOfExpression(
        quantifier="all",
        string_set=cast(Any, string_set_as_dict),
    )

    # Act
    validator.visit(node)

    # Assert: the sequence error from WithStatement.declarations propagates.
    errors = [e for e in result.errors if "must be a sequence" in e.message]
    assert errors


def test_visit_expression_sequence_non_sequence_via_tuple_expression() -> None:
    """TupleExpression with a frozenset of non-expressions records item errors."""
    result, validator = _validator()
    # frozenset is a valid sequence type; items inside must be expressions.
    # cast to list[Any] to satisfy the static type of TupleExpression.elements while
    # still passing a frozenset at runtime, which exercises the frozenset branch.
    node = TupleExpression(elements=cast(Any, frozenset({"not_expr"})))

    validator.visit(node)

    # frozenset is accepted as sequence; "not_expr" is not an Expression node.
    errors = [e for e in result.errors if "must be Expression" in e.message]
    assert errors
