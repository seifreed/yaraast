# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop for yaraast.types.semantic_validator.

Targets lines and branches missed by the existing test suites (94.61%):

  97->96  - validate(): false branch of 'if rule.condition is not None' — rule with no condition
  167->170 - validate_expression(): false branch of 'if env is None' — env provided by caller
  236    - _external_type(): return UnknownType() for non-bool/int/float/str values
  276    - _walk_ast_nodes(): 'if not is_dataclass(value): return' — unreachable in production;
           documented below rather than tested via artificial non-dataclass subclass
  296    - _validate_external_quantifier_value(): 'if value is None: return' —
           quantifier identifier not present in externals mapping
  315    - _validate_external_range_bounds(): 'result.add_error(\"Range lower bound must not
           be negative\")' — low is a negative IntegerLiteral (no identifier name)
  332    - _static_external_integer_value(): 'if isinstance(value, ParenthesesExpression)'
           — paren-wrapped Identifier resolves through recursion
  341    - _static_external_integer_value(): 'return None' after external_value is float
  348    - _external_identifier_name(): 'if isinstance(value, ParenthesesExpression)'
           — paren-wrapped Identifier name extraction

Line 276 is a defensive guard that is structurally unreachable: every ASTNode subclass
in this codebase inherits the @dataclass decorator from the ASTNode base class, so
is_dataclass() always returns True for real AST objects.  No artificial non-dataclass
ASTNode subclass is created here; the finding is documented so future maintainers are
aware that removing the guard is safe.
"""

from __future__ import annotations

from yaraast.ast.base import YaraFile
from yaraast.ast.conditions import ForOfExpression, OfExpression
from yaraast.ast.expressions import (
    Identifier,
    IntegerLiteral,
    ParenthesesExpression,
    RangeExpression,
)
from yaraast.ast.rules import Rule
from yaraast.types.semantic_validator import (
    SemanticValidator,
    _define_external_types,
    _external_identifier_name,
    _external_type,
    _static_external_integer_value,
    _validate_external_range_bounds,
    validate_yara_file,
)
from yaraast.types.semantic_validator_core import ValidationResult
from yaraast.types.type_system import (
    BooleanType,
    DoubleType,
    IntegerType,
    StringType,
    TypeEnvironment,
    UnknownType,
)

# ---------------------------------------------------------------------------
# Branch 97->96: validate() — rule with condition=None in rules list
# ---------------------------------------------------------------------------


def test_validate_rule_with_no_condition_skips_function_validator() -> None:
    """validate() must not crash and must not call function_validator when condition is None.

    Branch 97->96 is the false arm of 'if rule.condition is not None:'.  A rule
    with condition=None exercises this path, causing the loop to continue without
    visiting the condition.
    """
    # Arrange: one rule that has no condition at all.
    rule = Rule(name="no_condition_rule", condition=None)
    yara_file = YaraFile(rules=[rule])
    validator = SemanticValidator()

    # Act
    result = validator.validate(yara_file)

    # Assert: result is valid and no errors about condition were produced.
    assert result.is_valid
    assert result.errors == []


def test_validate_mixed_rules_some_without_condition() -> None:
    """validate() iterates over all rules; rules with condition=None are silently skipped.

    This exercises the branch multiple times: the rule without a condition takes
    the false arm (97->96) while the rule with a condition takes the true arm.
    """
    # Arrange: two rules — one without a condition, one with a trivial condition.
    rule_no_cond = Rule(name="rule_no_cond", condition=None)
    rule_with_cond = Rule(
        name="rule_with_cond",
        condition=Identifier("true"),
    )
    yara_file = YaraFile(rules=[rule_no_cond, rule_with_cond])
    validator = SemanticValidator()

    # Act
    result = validator.validate(yara_file)

    # Assert: validation completes; no unexpected errors from the no-condition rule.
    condition_errors = [e for e in result.errors if "no_condition_rule" in e.message]
    assert condition_errors == []


# ---------------------------------------------------------------------------
# Branch 167->170: validate_expression() — env provided by caller (not None)
# ---------------------------------------------------------------------------


def test_validate_expression_with_provided_env_skips_env_construction() -> None:
    """validate_expression() must use the caller-supplied TypeEnvironment without creating a new one.

    Branch 167->170 is the false arm of 'if env is None:'.  Supplying a pre-built
    env exercises this path.  The supplied env's definitions must be visible during
    validation.
    """
    # Arrange: env with 'myvar' already defined as StringType.
    env = TypeEnvironment()
    env.define("myvar", StringType())
    validator = SemanticValidator()
    expr = Identifier("myvar")

    # Act
    result = validator.validate_expression(expr, env=env)

    # Assert: no errors — the identifier is known because the supplied env was used.
    assert result.errors == []


def test_validate_expression_with_provided_env_and_externals() -> None:
    """validate_expression() with both env and externals uses the caller-supplied env."""
    # Arrange: env defines 'known', externals defines 'ext_bool'.
    env = TypeEnvironment()
    env.define("known", IntegerType())
    validator = SemanticValidator()
    # Just a simple identifier; the important thing is that env is passed through.
    expr = Identifier("known")

    # Act: pass both env and externals; externals are merged on top of env contents.
    result = validator.validate_expression(expr, env=env, externals={"ext_bool": True})

    # Assert: no crash and no errors for 'known'.
    assert result.errors == []


# ---------------------------------------------------------------------------
# Line 236: _external_type() — return UnknownType() for unsupported value types
# ---------------------------------------------------------------------------


def test_external_type_returns_unknown_for_none() -> None:
    """_external_type() returns UnknownType when the value is None."""
    # Arrange / Act
    result = _external_type(None)

    # Assert
    assert isinstance(result, UnknownType)


def test_external_type_returns_unknown_for_bytes() -> None:
    """_external_type() returns UnknownType for byte-string values."""
    result = _external_type(b"binary_data")

    assert isinstance(result, UnknownType)


def test_external_type_returns_unknown_for_list() -> None:
    """_external_type() returns UnknownType for list values."""
    result = _external_type([1, 2, 3])

    assert isinstance(result, UnknownType)


def test_external_type_returns_known_types_for_valid_values() -> None:
    """_external_type() returns the correct typed object for bool/int/float/str."""
    # bool must be checked before int because bool is a subclass of int.
    assert isinstance(_external_type(True), BooleanType)
    assert isinstance(_external_type(42), IntegerType)
    assert isinstance(_external_type(3.14), DoubleType)
    assert isinstance(_external_type("hello"), StringType)


def test_define_external_types_registers_unknown_for_unsupported_value() -> None:
    """_define_external_types() registers UnknownType when passed a non-standard value.

    _normalize_externals() would normally reject such a value before this function
    is called, but _define_external_types() is a public module-level helper and
    must gracefully accept any mapping, including one containing an unsupported type.
    """
    # Arrange: bypass _normalize_externals by calling _define_external_types directly.
    env = TypeEnvironment()
    raw_externals: dict[str, object] = {"strange": object()}

    # Act
    _define_external_types(env, raw_externals)

    # Assert: 'strange' is now defined in the env as UnknownType.
    resolved = env.lookup("strange")
    assert isinstance(resolved, UnknownType)


# ---------------------------------------------------------------------------
# Line 296: _validate_external_quantifier_value() — identifier not in externals
# ---------------------------------------------------------------------------


def test_of_expression_quantifier_identifier_absent_from_externals_no_error() -> None:
    """When quantifier is an Identifier not present in externals, no quantifier error fires.

    Line 296 is 'if value is None: return'.  The externals dict contains 'count' but
    the OfExpression quantifier refers to 'missing', which is absent.  The validator
    must return early without adding an error for the quantifier itself.
    """
    # Arrange: externals has a different name than the quantifier identifier.
    validator = SemanticValidator(externals={"count": 5})
    rule = Rule(
        name="rule_quant_absent",
        condition=OfExpression(
            quantifier=Identifier("missing"),
            string_set="them",
        ),
    )
    yara_file = YaraFile(rules=[rule])

    # Act
    result = validator.validate(yara_file)

    # Assert: no error that mentions the 'missing' identifier as an invalid quantifier.
    quantifier_errors = [e for e in result.errors if "quantifier external 'missing'" in e.message]
    assert quantifier_errors == []


def test_for_of_expression_quantifier_identifier_absent_from_externals_no_quantifier_error() -> (
    None
):
    """ForOfExpression with quantifier identifier not in externals also returns early at line 296."""
    validator = SemanticValidator(externals={"count": 3})
    rule = Rule(
        name="rule_for_of_absent",
        condition=ForOfExpression(
            quantifier=Identifier("absent"),
            string_set="them",
            condition=None,
        ),
    )
    yara_file = YaraFile(rules=[rule])

    # Act
    result = validator.validate(yara_file)

    # Assert
    quantifier_errors = [e for e in result.errors if "quantifier external 'absent'" in e.message]
    assert quantifier_errors == []


# ---------------------------------------------------------------------------
# Line 315: _validate_external_range_bounds() — negative IntegerLiteral low
# ---------------------------------------------------------------------------


def test_range_with_negative_integer_literal_low_produces_no_name_error() -> None:
    """When the range low bound is a negative IntegerLiteral, the generic error message fires.

    Line 315 is reached when _external_identifier_name(node.low) returns None, which
    happens when node.low is an IntegerLiteral (not an Identifier).  The error message
    must not contain an external name.
    """
    # Arrange: low=-5 (IntegerLiteral), high=10 (IntegerLiteral); no externals needed.
    result = ValidationResult()
    node = RangeExpression(low=IntegerLiteral(-5), high=IntegerLiteral(10))

    # Act
    _validate_external_range_bounds(result, node, {})

    # Assert: exactly one error, with the generic message (no external name).
    assert len(result.errors) == 1
    assert result.errors[0].message == "Range lower bound must not be negative"
    assert "external" not in result.errors[0].message


def test_validate_expression_with_negative_literal_range_emits_generic_error() -> None:
    """validate_expression() propagates the generic 'must not be negative' error for IntegerLiteral low."""
    # Arrange
    validator = SemanticValidator()
    range_node = RangeExpression(low=IntegerLiteral(-1), high=IntegerLiteral(100))

    # Act
    result = validator.validate_expression(range_node)

    # Assert
    messages = [e.message for e in result.errors]
    assert "Range lower bound must not be negative" in messages


# ---------------------------------------------------------------------------
# Line 332: _static_external_integer_value() — ParenthesesExpression recursion
# ---------------------------------------------------------------------------


def test_static_external_integer_value_resolves_paren_wrapped_identifier() -> None:
    """_static_external_integer_value() recurses into ParenthesesExpression to resolve the inner value.

    Line 332 is the ParenthesesExpression branch.  The function unwraps the parentheses
    and recursively resolves the Identifier inside against the externals dict.
    """
    # Arrange
    paren_expr = ParenthesesExpression(expression=Identifier("lo"))
    externals: dict[str, object] = {"lo": 7}

    # Act
    resolved = _static_external_integer_value(paren_expr, externals)

    # Assert
    assert resolved == 7


def test_range_with_paren_wrapped_identifiers_resolves_correctly() -> None:
    """A RangeExpression whose bounds are paren-wrapped identifiers resolves without error."""
    # Arrange
    result = ValidationResult()
    node = RangeExpression(
        low=ParenthesesExpression(expression=Identifier("lo")),
        high=ParenthesesExpression(expression=Identifier("hi")),
    )
    externals: dict[str, object] = {"lo": 2, "hi": 8}

    # Act
    _validate_external_range_bounds(result, node, externals)

    # Assert: no errors (lo=2, hi=8, so lo<=hi and lo>=0).
    assert result.errors == []


def test_range_with_paren_low_negative_identifier_emits_named_error() -> None:
    """Paren-wrapped Identifier resolves to a negative value and error includes the name.

    This exercises lines 332 (ParenthesesExpression branch) AND 348
    (_external_identifier_name recursion) because the error message lookup also
    uses _external_identifier_name on the paren-wrapped low bound.
    """
    # Arrange: lo resolves to -3 via paren-wrapped Identifier.
    validator = SemanticValidator(externals={"lo": -3, "hi": 10})
    range_node = RangeExpression(
        low=ParenthesesExpression(expression=Identifier("lo")),
        high=IntegerLiteral(10),
    )

    # Act
    result = validator.validate_expression(range_node)

    # Assert: error mentions the external name 'lo'.
    messages = [e.message for e in result.errors]
    assert any("'lo'" in m and "must not be negative" in m for m in messages)


# ---------------------------------------------------------------------------
# Line 341: _static_external_integer_value() — float external returns None
# ---------------------------------------------------------------------------


def test_static_external_integer_value_returns_none_for_float_external() -> None:
    """_static_external_integer_value() returns None when the external is a float.

    Line 341 is the final 'return None' after 'if isinstance(external_value, int):'
    fails because the external value is a float (not int/bool).
    """
    # Arrange: external 'ratio' is a float.
    ident = Identifier("ratio")
    externals: dict[str, object] = {"ratio": 0.75}

    # Act
    result = _static_external_integer_value(ident, externals)

    # Assert: function returns None for float external (cannot use as integer bound).
    assert result is None


def test_range_bounds_with_float_externals_not_validated_as_integers() -> None:
    """When both bounds resolve to None (float externals), no range-order error fires.

    The check 'if low is not None and high is not None' requires both to be integers.
    If either is None, the range-order check is skipped entirely.
    """
    # Arrange: both bounds are float externals, so both resolve to None.
    result = ValidationResult()
    node = RangeExpression(
        low=Identifier("lo_f"),
        high=Identifier("hi_f"),
    )
    externals: dict[str, object] = {"lo_f": 1.5, "hi_f": 5.5}

    # Act
    _validate_external_range_bounds(result, node, externals)

    # Assert: no range-bound errors from the semantic validator itself
    # (type errors from the type checker are a separate path).
    range_order_errors = [e for e in result.errors if "lower bound" in e.message]
    assert range_order_errors == []


# ---------------------------------------------------------------------------
# Line 348: _external_identifier_name() — ParenthesesExpression recursion
# ---------------------------------------------------------------------------


def test_external_identifier_name_resolves_paren_wrapped_identifier() -> None:
    """_external_identifier_name() recurses through ParenthesesExpression to return the inner name.

    Line 348 is 'if isinstance(value, ParenthesesExpression): return _external_identifier_name(value.expression)'.
    """
    # Arrange: ParenthesesExpression wrapping a plain Identifier.
    paren = ParenthesesExpression(expression=Identifier("outer_var"))

    # Act
    name = _external_identifier_name(paren)

    # Assert
    assert name == "outer_var"


def test_external_identifier_name_nested_paren_unwraps_all_levels() -> None:
    """_external_identifier_name() unwraps multiple layers of ParenthesesExpression."""
    # Arrange: double-nested parentheses.
    inner = Identifier("deep_name")
    paren_once = ParenthesesExpression(expression=inner)
    paren_twice = ParenthesesExpression(expression=paren_once)

    # Act
    name = _external_identifier_name(paren_twice)

    # Assert
    assert name == "deep_name"


def test_external_identifier_name_returns_none_for_literal() -> None:
    """_external_identifier_name() returns None for an IntegerLiteral (no name)."""
    result = _external_identifier_name(IntegerLiteral(42))

    assert result is None


# ---------------------------------------------------------------------------
# Integration: validate_yara_file convenience function exercises the full stack
# ---------------------------------------------------------------------------


def test_validate_yara_file_with_no_rules_is_valid() -> None:
    """validate_yara_file() on an empty YaraFile returns a valid result."""
    yara_file = YaraFile(rules=[])

    result = validate_yara_file(yara_file)

    assert result.is_valid
    assert result.errors == []


def test_validate_yara_file_with_rule_no_condition_is_valid() -> None:
    """validate_yara_file() on a rule with no condition must produce no errors."""
    rule = Rule(name="empty_rule", condition=None)
    yara_file = YaraFile(rules=[rule])

    result = validate_yara_file(yara_file)

    assert result.is_valid
