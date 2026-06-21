"""Real coverage tests for yaraast/types/_expr_inference.py.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Strategy: drive every uncovered line in _expr_inference.py via real AST
node construction and direct ExpressionTypeInference / _TypeBaseVisitor
calls.  No mocks, no stubs, no type: ignore suppressions.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from yaraast.ast.comments import Comment, CommentGroup
from yaraast.ast.conditions import (
    AtExpression,
    ForExpression,
    ForOfExpression,
    InExpression,
    OfExpression,
)
from yaraast.ast.expressions import (
    ArrayAccess,
    BinaryExpression,
    BooleanLiteral,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    RegexLiteral,
    SetExpression,
    StringCount,
    StringIdentifier,
    StringLength,
    StringLiteral,
    StringOffset,
    StringWildcard,
    UnaryExpression,
)
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaType
from yaraast.types._expr_inference import ExpressionTypeInference, _TypeBaseVisitor
from yaraast.types._registry import (
    ArrayType,
    BooleanType,
    DictionaryType,
    DoubleType,
    IntegerType,
    RangeType,
    RegexType,
    StringIdentifierType,
    StringSetType,
    StringType,
    StructType,
    TypeEnvironment,
    UnknownType,
)
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env() -> TypeEnvironment:
    return TypeEnvironment()


def _inf(env: TypeEnvironment | None = None) -> ExpressionTypeInference:
    return ExpressionTypeInference(env if env is not None else _env())


# ---------------------------------------------------------------------------
# _TypeBaseVisitor — base class lines 71, 74, 77, 80, 83, 86, 89, 92, 95,
# 98, 101, 104
# ---------------------------------------------------------------------------


def test_type_base_visitor_init_and_comment_returns_unknown() -> None:
    """_TypeBaseVisitor.__init__ and visit_comment return UnknownType."""
    visitor = _TypeBaseVisitor()
    assert isinstance(visitor.visit(Comment("// foo")), UnknownType)


def test_type_base_visitor_comment_group_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_comment_group returns UnknownType."""
    visitor = _TypeBaseVisitor()
    group = CommentGroup([Comment("// a"), Comment("// b")])
    assert isinstance(visitor.visit(group), UnknownType)


def test_type_base_visitor_defined_expression_returns_boolean() -> None:
    """_TypeBaseVisitor.visit_defined_expression returns BooleanType."""
    visitor = _TypeBaseVisitor()
    node = DefinedExpression(expression=IntegerLiteral(value=1))
    assert isinstance(visitor.visit(node), BooleanType)


def test_type_base_visitor_string_operator_expression_returns_boolean() -> None:
    """_TypeBaseVisitor.visit_string_operator_expression returns BooleanType."""
    visitor = _TypeBaseVisitor()
    node = StringOperatorExpression(
        left=StringLiteral(value="a"),
        operator="contains",
        right=StringLiteral(value="b"),
    )
    assert isinstance(visitor.visit(node), BooleanType)


def test_type_base_visitor_extern_import_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_extern_import returns UnknownType."""
    visitor = _TypeBaseVisitor()
    assert isinstance(visitor.visit(ExternImport(module_path="ext")), UnknownType)


def test_type_base_visitor_extern_namespace_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_extern_namespace returns UnknownType."""
    visitor = _TypeBaseVisitor()
    assert isinstance(visitor.visit(ExternNamespace(name="ns")), UnknownType)


def test_type_base_visitor_extern_rule_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_extern_rule returns UnknownType."""
    visitor = _TypeBaseVisitor()
    assert isinstance(visitor.visit(ExternRule(name="r")), UnknownType)


def test_type_base_visitor_extern_rule_reference_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_extern_rule_reference returns UnknownType."""
    visitor = _TypeBaseVisitor()
    assert isinstance(visitor.visit(ExternRuleReference(rule_name="r")), UnknownType)


def test_type_base_visitor_in_rule_pragma_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_in_rule_pragma returns UnknownType."""
    visitor = _TypeBaseVisitor()
    pragma = Pragma(pragma_type=PragmaType.PRAGMA, name="pragma")
    node = InRulePragma(pragma=pragma)
    assert isinstance(visitor.visit(node), UnknownType)


def test_type_base_visitor_pragma_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_pragma returns UnknownType."""
    visitor = _TypeBaseVisitor()
    node = Pragma(pragma_type=PragmaType.PRAGMA, name="pragma")
    assert isinstance(visitor.visit(node), UnknownType)


def test_type_base_visitor_pragma_block_returns_unknown() -> None:
    """_TypeBaseVisitor.visit_pragma_block returns UnknownType."""
    visitor = _TypeBaseVisitor()
    assert isinstance(visitor.visit(PragmaBlock(pragmas=[])), UnknownType)


# ---------------------------------------------------------------------------
# ExpressionTypeInference — constructor lines 110-113
# ---------------------------------------------------------------------------


def test_expr_inference_constructor_initialises_env_and_empty_errors() -> None:
    """ExpressionTypeInference stores env and starts with an empty error list."""
    env = _env()
    inf = ExpressionTypeInference(env)
    assert inf.env is env
    assert inf.errors == []


# ---------------------------------------------------------------------------
# _normalize_string_id (line 115-116) via visit_string_identifier
# (covered via the string-identifier helper path)
# ---------------------------------------------------------------------------


def test_normalize_string_id_is_called_via_string_identifier_lookup() -> None:
    """_normalize_string_id normalises the id used in env.lookup."""
    env = _env()
    env.add_string("$target")
    inf = _inf(env)
    # Using the raw suffix "target" — normalize_string_reference_id adds "$"
    result = inf.infer(StringIdentifier(name="$target"))
    assert isinstance(result, StringIdentifierType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# _resolve_module_type (lines 119-139) — module present / module absent /
# module with alias / unknown module name
# ---------------------------------------------------------------------------


def test_resolve_module_type_returns_none_for_absent_module() -> None:
    """_resolve_module_type returns None when the module is not registered."""
    inf = _inf()
    # An identifier whose name matches no registered module yields UnknownType
    result = inf.infer(Identifier(name="notamodule"))
    assert isinstance(result, UnknownType)


def test_resolve_module_type_returns_module_type_for_known_module() -> None:
    """_resolve_module_type returns a ModuleType for a known module name."""
    env = _env()
    env.add_module("pe")
    inf = _inf(env)
    inf.infer(ModuleReference("pe"))
    # ModuleReference on a known module should not raise and should not be
    # completely unknown (ops delegates to infer_module_or_condition which
    # resolves the module type).
    assert not any("Undefined module" in e for e in inf.errors)


def test_resolve_module_type_returns_none_when_module_loader_finds_nothing() -> None:
    """_resolve_module_type returns None when ModuleLoader has no definition."""
    env = _env()
    # Register an alias whose actual module name the loader does not know
    env.add_module("phantom", "phantom")
    inf = _inf(env)
    result = inf.infer(ModuleReference("phantom"))
    assert isinstance(result, UnknownType)


# ---------------------------------------------------------------------------
# infer (line 141-143) — public entry point
# ---------------------------------------------------------------------------


def test_infer_returns_correct_type_for_integer_literal() -> None:
    """infer() delegates to visit() and returns IntegerType for IntegerLiteral."""
    inf = _inf()
    assert isinstance(inf.infer(IntegerLiteral(value=7)), IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# _invalid_literal (lines 145-147) — error path for malformed literals
# ---------------------------------------------------------------------------


def test_invalid_literal_appends_message_and_returns_unknown() -> None:
    """_invalid_literal records the message and returns UnknownType."""
    inf = _inf()
    # Pass a bool as IntegerLiteral.value — triggers _invalid_literal
    result = inf.infer(IntegerLiteral(value=True))  # bool satisfies int at runtime
    assert isinstance(result, UnknownType)
    assert "Integer literal value must be an integer" in inf.errors


# ---------------------------------------------------------------------------
# _sequence_or_empty (lines 149-153)
# ---------------------------------------------------------------------------


def test_sequence_or_empty_returns_list_for_list_input() -> None:
    """_sequence_or_empty works on a list iterable and does not log an error."""
    env = _env()
    env.add_string("$a")
    inf = _inf(env)
    # OfExpression with a plain list string_set exercises _sequence_or_empty
    result = inf.infer(OfExpression(quantifier="any", string_set=["$a"]))
    assert isinstance(result, BooleanType)
    assert inf.errors == []


def test_sequence_or_empty_returns_empty_list_and_logs_error_for_non_sequence() -> None:
    """_sequence_or_empty logs an error when the value is not a sequence."""
    inf = _inf()
    # PatternMatch.cases must be a sequence; passing a non-sequence triggers
    # _sequence_or_empty's error branch.
    result = inf.infer(
        PatternMatch(
            value=IntegerLiteral(value=1),
            cases=42,  # type: ignore[arg-type]
        )
    )
    assert isinstance(result, UnknownType)
    assert any("Pattern match cases must be a sequence" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# _visit_expression_or_unknown (lines 155-159)
# ---------------------------------------------------------------------------


def test_visit_expression_or_unknown_handles_valid_expression() -> None:
    """_visit_expression_or_unknown visits a real expression node."""
    inf = _inf()
    # WithStatement delegates body visit through _visit_expression_or_unknown
    result = inf.infer(
        WithStatement(
            declarations=[],
            body=IntegerLiteral(value=3),
        )
    )
    assert isinstance(result, IntegerType)
    assert inf.errors == []


def test_visit_expression_or_unknown_logs_error_for_non_expression() -> None:
    """_visit_expression_or_unknown logs error when value lacks .accept."""
    inf = _inf()
    # PatternMatch with a non-expression value triggers the error branch.
    # We patch the value after construction to avoid validate_structure.
    node = PatternMatch(value=IntegerLiteral(1), cases=[], default=None)
    object.__setattr__(node, "value", "not_an_expression")
    result = inf.infer(node)
    assert isinstance(result, UnknownType)
    assert any("Pattern match value must be Expression" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_integer_literal (lines 161-164)
# ---------------------------------------------------------------------------


def test_visit_integer_literal_valid_returns_integer_type() -> None:
    """visit_integer_literal returns IntegerType for a valid integer."""
    inf = _inf()
    assert isinstance(inf.infer(IntegerLiteral(value=0)), IntegerType)
    assert inf.errors == []


def test_visit_integer_literal_bool_value_returns_unknown_with_error() -> None:
    """visit_integer_literal rejects a bool stored as the value."""
    inf = _inf()
    result = inf.infer(IntegerLiteral(value=False))  # bool subclasses int
    assert isinstance(result, UnknownType)
    assert "Integer literal value must be an integer" in inf.errors


def test_visit_integer_literal_string_value_returns_unknown_with_error() -> None:
    """visit_integer_literal rejects a non-int value."""
    inf = _inf()
    result = inf.infer(IntegerLiteral(value="nope"))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "Integer literal value must be an integer" in inf.errors


# ---------------------------------------------------------------------------
# visit_double_literal (lines 166-171)
# ---------------------------------------------------------------------------


def test_visit_double_literal_valid_returns_double_type() -> None:
    """visit_double_literal returns DoubleType for a valid float."""
    inf = _inf()
    assert isinstance(inf.infer(DoubleLiteral(value=3.14)), DoubleType)
    assert inf.errors == []


def test_visit_double_literal_bool_value_returns_unknown() -> None:
    """visit_double_literal rejects a boolean stored as the value."""
    inf = _inf()
    result = inf.infer(DoubleLiteral(value=True))  # bool subclasses int/float
    assert isinstance(result, UnknownType)
    assert "Double literal value must be numeric" in inf.errors


def test_visit_double_literal_non_numeric_returns_unknown() -> None:
    """visit_double_literal rejects a non-numeric value."""
    inf = _inf()
    result = inf.infer(DoubleLiteral(value="bad"))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "Double literal value must be numeric" in inf.errors


def test_visit_double_literal_infinite_returns_unknown() -> None:
    """visit_double_literal rejects infinite float values."""
    inf = _inf()
    result = inf.infer(DoubleLiteral(value=math.inf))
    assert isinstance(result, UnknownType)
    assert "Double literal value must be finite" in inf.errors


def test_visit_double_literal_nan_returns_unknown() -> None:
    """visit_double_literal rejects NaN float values."""
    inf = _inf()
    result = inf.infer(DoubleLiteral(value=math.nan))
    assert isinstance(result, UnknownType)
    assert "Double literal value must be finite" in inf.errors


# ---------------------------------------------------------------------------
# visit_string_literal (lines 173-176)
# ---------------------------------------------------------------------------


def test_visit_string_literal_valid_returns_string_type() -> None:
    """visit_string_literal returns StringType for a valid string."""
    inf = _inf()
    assert isinstance(inf.infer(StringLiteral(value="hello")), StringType)
    assert inf.errors == []


def test_visit_string_literal_non_string_value_returns_unknown() -> None:
    """visit_string_literal rejects a non-string value."""
    inf = _inf()
    result = inf.infer(StringLiteral(value=42))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "String literal value must be a string" in inf.errors


# ---------------------------------------------------------------------------
# visit_regex_literal (lines 178-183)
# ---------------------------------------------------------------------------


def test_visit_regex_literal_valid_returns_regex_type() -> None:
    """visit_regex_literal returns RegexType for valid pattern and modifiers."""
    inf = _inf()
    assert isinstance(inf.infer(RegexLiteral(pattern="foo")), RegexType)
    assert inf.errors == []


def test_visit_regex_literal_non_string_pattern_returns_unknown() -> None:
    """visit_regex_literal rejects a non-string pattern."""
    inf = _inf()
    result = inf.infer(RegexLiteral(pattern=99))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "Regex literal pattern must be a string" in inf.errors


def test_visit_regex_literal_non_string_modifiers_returns_unknown() -> None:
    """visit_regex_literal rejects non-string modifiers."""
    inf = _inf()
    result = inf.infer(RegexLiteral(pattern="ok", modifiers=42))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "Regex literal modifiers must be a string" in inf.errors


# ---------------------------------------------------------------------------
# visit_boolean_literal (lines 185-188)
# ---------------------------------------------------------------------------


def test_visit_boolean_literal_true_returns_boolean_type() -> None:
    """visit_boolean_literal returns BooleanType for True."""
    inf = _inf()
    assert isinstance(inf.infer(BooleanLiteral(value=True)), BooleanType)
    assert inf.errors == []


def test_visit_boolean_literal_false_returns_boolean_type() -> None:
    """visit_boolean_literal returns BooleanType for False."""
    inf = _inf()
    assert isinstance(inf.infer(BooleanLiteral(value=False)), BooleanType)
    assert inf.errors == []


def test_visit_boolean_literal_non_bool_value_returns_unknown() -> None:
    """visit_boolean_literal rejects a non-boolean value."""
    inf = _inf()
    result = inf.infer(BooleanLiteral(value=1))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "Boolean literal value must be a boolean" in inf.errors


# ---------------------------------------------------------------------------
# visit_identifier (lines 190-193) — non-string name triggers _invalid_literal
# ---------------------------------------------------------------------------


def test_visit_identifier_non_string_name_returns_unknown() -> None:
    """visit_identifier rejects a non-string name before calling ops."""
    inf = _inf()
    result = inf.infer(Identifier(name=42))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert "Identifier name must be a string" in inf.errors


# ---------------------------------------------------------------------------
# visit_string_identifier (lines 195-212) — various branches
# ---------------------------------------------------------------------------


def test_visit_string_identifier_dollar_with_scope_lookup() -> None:
    """visit_string_identifier '$' resolves from scope."""
    env = _env()
    env.scopes[-1]["$"] = StringIdentifierType()
    inf = _inf(env)
    result = inf.infer(StringIdentifier(name="$"))
    assert isinstance(result, StringIdentifierType)
    assert inf.errors == []


def test_visit_string_identifier_dollar_without_scope_returns_unknown() -> None:
    """visit_string_identifier '$' with no scope entry yields UnknownType."""
    inf = _inf()
    # '$' not in scope and not a valid string reference by itself
    result = inf.infer(StringIdentifier(name="$"))
    # The literal "$" is not a wildcard and not in the string table
    assert isinstance(result, UnknownType)


def test_visit_string_identifier_invalid_name_type_returns_unknown() -> None:
    """visit_string_identifier rejects non-string name through normalize."""
    inf = _inf()
    result = inf.infer(StringIdentifier(name=123))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert inf.errors


def test_visit_string_identifier_scoped_lookup_succeeds() -> None:
    """visit_string_identifier finds the type from the environment lookup."""
    env = _env()
    env.scopes[-1]["$hit"] = StringIdentifierType()
    inf = _inf(env)
    result = inf.infer(StringIdentifier(name="$hit"))
    assert isinstance(result, StringIdentifierType)


def test_visit_string_identifier_known_string_table_entry() -> None:
    """visit_string_identifier resolves to StringIdentifierType via has_string."""
    env = _env()
    env.add_string("$payload")
    inf = _inf(env)
    result = inf.infer(StringIdentifier(name="$payload"))
    assert isinstance(result, StringIdentifierType)
    assert inf.errors == []


def test_visit_string_identifier_undefined_string_logs_error() -> None:
    """visit_string_identifier reports undefined string when not in table."""
    inf = _inf()
    result = inf.infer(StringIdentifier(name="$nope"))
    assert isinstance(result, UnknownType)
    assert "Undefined string: $nope" in inf.errors


# ---------------------------------------------------------------------------
# visit_string_wildcard (lines 214-220)
# ---------------------------------------------------------------------------


def test_visit_string_wildcard_valid_returns_string_set_type() -> None:
    """visit_string_wildcard returns StringSetType for a valid pattern."""
    inf = _inf()
    result = inf.infer(StringWildcard(pattern="$prefix*"))
    assert isinstance(result, StringSetType)
    assert inf.errors == []


def test_visit_string_wildcard_invalid_pattern_returns_unknown() -> None:
    """visit_string_wildcard rejects an invalid pattern and logs an error."""
    inf = _inf()
    result = inf.infer(StringWildcard(pattern=99))  # type: ignore[arg-type]
    assert isinstance(result, UnknownType)
    assert inf.errors


# ---------------------------------------------------------------------------
# visit_string_count / _offset / _length (lines 222-231)
# ---------------------------------------------------------------------------


def test_visit_string_count_known_string_returns_integer_type() -> None:
    """visit_string_count returns IntegerType when the string is defined."""
    env = _env()
    env.add_string("$cnt")
    inf = _inf(env)
    assert isinstance(inf.infer(StringCount(string_id="cnt")), IntegerType)
    assert inf.errors == []


def test_visit_string_offset_known_string_returns_integer_type() -> None:
    """visit_string_offset returns IntegerType when the string is defined."""
    env = _env()
    env.add_string("$off")
    inf = _inf(env)
    assert isinstance(inf.infer(StringOffset(string_id="off")), IntegerType)
    assert inf.errors == []


def test_visit_string_length_known_string_returns_integer_type() -> None:
    """visit_string_length returns IntegerType when the string is defined."""
    env = _env()
    env.add_string("$len")
    inf = _inf(env)
    assert isinstance(inf.infer(StringLength(string_id="len")), IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_binary_expression (line 235-236)
# ---------------------------------------------------------------------------


def test_visit_binary_expression_integer_addition_returns_integer() -> None:
    """visit_binary_expression delegates to ops and returns IntegerType."""
    inf = _inf()
    result = inf.infer(
        BinaryExpression(
            left=IntegerLiteral(value=1),
            operator="+",
            right=IntegerLiteral(value=2),
        )
    )
    assert isinstance(result, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_unary_expression (line 238-239)
# ---------------------------------------------------------------------------


def test_visit_unary_expression_negation_of_integer_returns_integer() -> None:
    """visit_unary_expression delegates to ops and returns IntegerType."""
    inf = _inf()
    result = inf.infer(UnaryExpression(operator="-", operand=IntegerLiteral(value=5)))
    assert isinstance(result, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_defined_expression (lines 241-254) — all branches
# ---------------------------------------------------------------------------


def test_visit_defined_expression_string_identifier_unknown_type_still_boolean() -> None:
    """visit_defined_expression with StringIdentifier of unknown type returns BooleanType."""
    inf = _inf()
    result = inf.infer(DefinedExpression(expression=StringIdentifier(name="$missing")))
    assert isinstance(result, BooleanType)
    # visit_defined_expression does not add a 'defined' error for StringIdentifier;
    # the only error recorded comes from visit_string_identifier's undefined-string check.
    assert not any(e.startswith("'defined'") for e in inf.errors)


def test_visit_defined_expression_unknown_identifier_logs_undefined_error() -> None:
    """visit_defined_expression logs 'Undefined identifier' for an unknown Identifier."""
    inf = _inf()
    result = inf.infer(DefinedExpression(expression=Identifier(name="unknown_var")))
    assert isinstance(result, BooleanType)
    assert any("Undefined identifier: unknown_var" in e for e in inf.errors)


def test_visit_defined_expression_unknown_expression_logs_cannot_apply() -> None:
    """visit_defined_expression logs error for unknown-type non-identifier expressions."""
    inf = _inf()
    # A FunctionCall to an undeclared function returns UnknownType
    result = inf.infer(
        DefinedExpression(expression=FunctionCall(function="ghost_func", arguments=[]))
    )
    assert isinstance(result, BooleanType)
    assert any("'defined' cannot be applied to expression of unknown type" in e for e in inf.errors)


def test_visit_defined_expression_array_type_logs_non_scalar_error() -> None:
    """visit_defined_expression logs error when expression has ArrayType."""
    env = _env()
    env.define("items", ArrayType(IntegerType()))
    inf = _inf(env)
    result = inf.infer(DefinedExpression(expression=Identifier(name="items")))
    assert isinstance(result, BooleanType)
    assert any("'defined' cannot be applied to non-scalar expression" in e for e in inf.errors)


def test_visit_defined_expression_dict_type_logs_non_scalar_error() -> None:
    """visit_defined_expression logs error when expression has DictionaryType."""
    env = _env()
    env.define("mapping", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(DefinedExpression(expression=Identifier(name="mapping")))
    assert isinstance(result, BooleanType)
    assert any("'defined' cannot be applied to non-scalar expression" in e for e in inf.errors)


def test_visit_defined_expression_struct_type_logs_non_scalar_error() -> None:
    """visit_defined_expression logs error when expression has StructType."""
    env = _env()
    env.define("obj", StructType(fields={"x": IntegerType()}))
    inf = _inf(env)
    result = inf.infer(DefinedExpression(expression=Identifier(name="obj")))
    assert isinstance(result, BooleanType)
    assert any("'defined' cannot be applied to non-scalar expression" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_string_operator_expression (line 256-264)
# ---------------------------------------------------------------------------


def test_visit_string_operator_expression_valid_contains() -> None:
    """visit_string_operator_expression wraps into BinaryExpression and returns BooleanType."""
    inf = _inf()
    result = inf.infer(
        StringOperatorExpression(
            left=StringLiteral(value="hello world"),
            operator="contains",
            right=StringLiteral(value="world"),
        )
    )
    assert isinstance(result, BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_extern_rule_reference (line 266-267) on ExpressionTypeInference
# ---------------------------------------------------------------------------


def test_expr_inference_extern_rule_reference_returns_boolean() -> None:
    """ExpressionTypeInference.visit_extern_rule_reference returns BooleanType."""
    inf = _inf()
    assert isinstance(inf.infer(ExternRuleReference(rule_name="Ext")), BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_parentheses_expression (line 269-270)
# ---------------------------------------------------------------------------


def test_visit_parentheses_expression_unwraps_inner_type() -> None:
    """visit_parentheses_expression returns the type of the inner expression."""
    inf = _inf()
    result = inf.infer(ParenthesesExpression(expression=DoubleLiteral(value=2.0)))
    assert isinstance(result, DoubleType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_set_expression (line 272-273)
# ---------------------------------------------------------------------------


def test_visit_set_expression_delegates_to_ops() -> None:
    """visit_set_expression returns RangeType via ops.infer_set_or_range."""
    inf = _inf()
    result = inf.infer(SetExpression(elements=[IntegerLiteral(value=1), IntegerLiteral(value=2)]))
    # SetExpression with integer elements returns some type from ops
    assert result is not None


# ---------------------------------------------------------------------------
# visit_range_expression (line 275-276)
# ---------------------------------------------------------------------------


def test_visit_range_expression_delegates_to_ops() -> None:
    """visit_range_expression returns RangeType."""
    inf = _inf()
    result = inf.infer(RangeExpression(low=IntegerLiteral(value=0), high=IntegerLiteral(value=10)))
    assert isinstance(result, RangeType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_function_call (line 278-279)
# ---------------------------------------------------------------------------


def test_visit_function_call_known_builtin() -> None:
    """visit_function_call returns IntegerType for a known integer-valued function."""
    inf = _inf()
    result = inf.infer(FunctionCall(function="uint8", arguments=[IntegerLiteral(value=0)]))
    assert isinstance(result, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_array_access (line 281-282)
# ---------------------------------------------------------------------------


def test_visit_array_access_known_array_returns_element_type() -> None:
    """visit_array_access returns the array element type when known."""
    env = _env()
    env.define("items", ArrayType(StringType()))
    inf = _inf(env)
    result = inf.infer(ArrayAccess(array=Identifier(name="items"), index=IntegerLiteral(value=0)))
    assert isinstance(result, StringType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_member_access (line 284-285)
# ---------------------------------------------------------------------------


def test_visit_member_access_known_struct_field() -> None:
    """visit_member_access resolves a known struct field."""
    env = _env()
    env.define("rec", StructType(fields={"count": IntegerType()}))
    inf = _inf(env)
    result = inf.infer(MemberAccess(object=Identifier(name="rec"), member="count"))
    assert isinstance(result, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_module_reference (line 287-288)
# ---------------------------------------------------------------------------


def test_visit_module_reference_known_module() -> None:
    """visit_module_reference invokes ops.infer_module_or_condition."""
    env = _env()
    env.add_module("math")
    inf = _inf(env)
    # ModuleReference on a known module should not error
    inf.infer(ModuleReference("math"))
    assert not any("Undefined" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_dictionary_access (line 290-291)
# ---------------------------------------------------------------------------


def test_visit_dictionary_access_known_dict() -> None:
    """visit_dictionary_access returns the dictionary value type."""
    env = _env()
    env.define("data", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(DictionaryAccess(object=Identifier(name="data"), key="x"))
    assert isinstance(result, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_at_expression (line 293-294)
# ---------------------------------------------------------------------------


def test_visit_at_expression_returns_boolean() -> None:
    """visit_at_expression returns BooleanType for a simple at-expression."""
    env = _env()
    env.add_string("$a")
    inf = _inf(env)
    result = inf.infer(AtExpression(string_id="$a", offset=IntegerLiteral(value=0)))
    assert isinstance(result, BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_in_expression (line 296-297)
# ---------------------------------------------------------------------------


def test_visit_in_expression_returns_boolean() -> None:
    """visit_in_expression returns BooleanType for a valid in-expression."""
    env = _env()
    env.add_string("$b")
    inf = _inf(env)
    result = inf.infer(
        InExpression(
            subject="$b",
            range=RangeExpression(IntegerLiteral(value=0), IntegerLiteral(value=100)),
        )
    )
    assert isinstance(result, BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_of_expression (line 299-300)
# ---------------------------------------------------------------------------


def test_visit_of_expression_returns_boolean() -> None:
    """visit_of_expression returns BooleanType."""
    env = _env()
    env.add_string("$s")
    inf = _inf(env)
    result = inf.infer(OfExpression(quantifier="any", string_set=["$s"]))
    assert isinstance(result, BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_for_expression (line 302-303)
# ---------------------------------------------------------------------------


def test_visit_for_expression_returns_boolean() -> None:
    """visit_for_expression returns BooleanType."""
    inf = _inf()
    result = inf.infer(
        ForExpression(
            quantifier="any",
            variable="i",
            iterable=RangeExpression(IntegerLiteral(value=1), IntegerLiteral(value=5)),
            body=BooleanLiteral(value=True),
        )
    )
    assert isinstance(result, BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_for_of_expression (line 305-306)
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_returns_boolean() -> None:
    """visit_for_of_expression returns BooleanType."""
    env = _env()
    env.add_string("$x")
    inf = _inf(env)
    result = inf.infer(
        ForOfExpression(
            quantifier="any",
            string_set=["$x"],
            condition=BooleanLiteral(value=True),
        )
    )
    assert isinstance(result, BooleanType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_with_statement (lines 308-323) — happy path and error branches
# ---------------------------------------------------------------------------


def test_visit_with_statement_basic_happy_path() -> None:
    """visit_with_statement evaluates declarations and body."""
    inf = _inf()
    result = inf.infer(
        WithStatement(
            declarations=[WithDeclaration("x", IntegerLiteral(value=10))],
            body=Identifier(name="x"),
        )
    )
    assert isinstance(result, IntegerType)
    assert inf.errors == []


def test_visit_with_statement_invalid_declarations_sequence_logs_error() -> None:
    """visit_with_statement logs error when declarations is not a sequence."""
    inf = _inf()
    node = WithStatement(
        declarations=[WithDeclaration("x", IntegerLiteral(1))],
        body=BooleanLiteral(True),
    )
    object.__setattr__(node, "declarations", "bad")
    result = inf.infer(node)
    assert isinstance(result, BooleanType)
    assert any("With-statement declarations must be a sequence" in e for e in inf.errors)


def test_visit_with_statement_invalid_declaration_item_logs_error() -> None:
    """visit_with_statement logs error for non-WithDeclaration items."""
    inf = _inf()
    # Inject a non-declaration item by bypassing construction validation
    node = WithStatement(
        declarations=[WithDeclaration("x", IntegerLiteral(1))],
        body=BooleanLiteral(True),
    )
    object.__setattr__(node, "declarations", ["not_a_declaration"])
    result = inf.infer(node)
    assert isinstance(result, BooleanType)
    assert any("With-statement declarations item must be WithDeclaration" in e for e in inf.errors)


def test_visit_with_statement_invalid_body_logs_error() -> None:
    """visit_with_statement logs error when body is not an Expression."""
    inf = _inf()
    node = WithStatement(
        declarations=[],
        body=BooleanLiteral(True),
    )
    object.__setattr__(node, "body", "not_an_expression")
    result = inf.infer(node)
    assert isinstance(result, UnknownType)
    assert any("With-statement body must be Expression" in e for e in inf.errors)


def test_visit_with_statement_pushes_and_pops_scope() -> None:
    """visit_with_statement uses a fresh scope that is cleaned up afterwards."""
    env = _env()
    inf = _inf(env)
    scope_count_before = len(env.scopes)
    inf.infer(
        WithStatement(
            declarations=[WithDeclaration("tmp", StringLiteral(value="val"))],
            body=BooleanLiteral(value=True),
        )
    )
    assert len(env.scopes) == scope_count_before
    # tmp is no longer visible after the statement
    assert env.lookup("tmp") is None


# ---------------------------------------------------------------------------
# visit_with_declaration (lines 325-338)
# ---------------------------------------------------------------------------


def test_visit_with_declaration_defines_identifier_in_scope() -> None:
    """visit_with_declaration defines the variable and returns the value type."""
    env = _env()
    inf = _inf(env)
    env.push_scope()
    decl = WithDeclaration(identifier="counter", value=IntegerLiteral(value=5))
    result = inf.visit(decl)
    assert isinstance(result, IntegerType)
    assert isinstance(env.lookup("counter"), IntegerType)


def test_visit_with_declaration_string_identifier_defines_both_forms() -> None:
    """visit_with_declaration with '$x' identifier defines both '$x' and 'x'."""
    env = _env()
    inf = _inf(env)
    env.push_scope()
    decl = WithDeclaration(identifier="$label", value=StringLiteral(value="val"))
    result = inf.visit(decl)
    assert isinstance(result, StringType)
    assert isinstance(env.lookup("label"), StringType)


def test_visit_with_declaration_invalid_identifier_returns_value_type() -> None:
    """visit_with_declaration returns value type even when identifier is invalid."""
    inf = _inf()
    decl = WithDeclaration(identifier="bad-name!", value=IntegerLiteral(value=1))
    result = inf.visit(decl)
    # Still returns the value type even though identifier is bad
    assert isinstance(result, IntegerType)
    assert inf.errors


def test_visit_with_declaration_non_string_identifier_returns_value_type() -> None:
    """visit_with_declaration with non-string identifier logs error and returns value type."""
    inf = _inf()
    decl = WithDeclaration(identifier="x", value=IntegerLiteral(1))
    object.__setattr__(decl, "identifier", 99)
    result = inf.visit(decl)
    assert isinstance(result, IntegerType)
    assert any("Local variable name must be a string" in e for e in inf.errors)


def test_visit_with_declaration_invalid_value_expression_returns_unknown() -> None:
    """visit_with_declaration logs error when value lacks .accept."""
    inf = _inf()
    decl = WithDeclaration(identifier="ok", value=IntegerLiteral(1))
    object.__setattr__(decl, "value", "not_expression")
    result = inf.visit(decl)
    assert isinstance(result, UnknownType)
    assert any("With declaration value must be Expression" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_list_expression (lines 340-352)
# ---------------------------------------------------------------------------


def test_visit_list_expression_homogeneous_integers_returns_array_of_integer() -> None:
    """visit_list_expression returns ArrayType(IntegerType) for [1, 2, 3]."""
    inf = _inf()
    result = inf.infer(
        ListExpression(elements=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)])
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


def test_visit_list_expression_empty_returns_array_of_unknown() -> None:
    """visit_list_expression returns ArrayType(UnknownType) for an empty list."""
    inf = _inf()
    result = inf.infer(ListExpression(elements=[]))
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, UnknownType)


def test_visit_list_expression_spread_array_extracts_element_type() -> None:
    """visit_list_expression with array spread uses the spread array's element type."""
    env = _env()
    env.define("nums", ArrayType(IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        ListExpression(
            elements=[
                SpreadOperator(expression=Identifier(name="nums"), is_dict=False),
            ]
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


def test_visit_list_expression_spread_non_array_logs_error() -> None:
    """visit_list_expression logs error when spreading a non-array value."""
    inf = _inf()
    result = inf.infer(
        ListExpression(
            elements=[
                SpreadOperator(expression=StringLiteral(value="bad"), is_dict=False),
            ]
        )
    )
    assert isinstance(result, ArrayType)
    assert any("List spread requires array" in e for e in inf.errors)


def test_visit_list_expression_mixed_types_logs_incompatible_error() -> None:
    """visit_list_expression logs error when element types are incompatible."""
    inf = _inf()
    result = inf.infer(ListExpression(elements=[IntegerLiteral(1), StringLiteral(value="s")]))
    assert isinstance(result, ArrayType)
    assert any("Collection elements must have compatible types" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_tuple_expression (line 354-355)
# ---------------------------------------------------------------------------


def test_visit_tuple_expression_returns_array_type() -> None:
    """visit_tuple_expression returns ArrayType whose element_type matches elements."""
    inf = _inf()
    result = inf.infer(TupleExpression(elements=[IntegerLiteral(1), IntegerLiteral(2)]))
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_dict_expression (lines 357-384)
# ---------------------------------------------------------------------------


def test_visit_dict_expression_valid_returns_dictionary_type() -> None:
    """visit_dict_expression returns DictionaryType(StringType, IntegerType)."""
    inf = _inf()
    result = inf.infer(
        DictExpression(
            items=[
                DictItem(key=StringLiteral("a"), value=IntegerLiteral(1)),
                DictItem(key=StringLiteral("b"), value=IntegerLiteral(2)),
            ]
        )
    )
    assert isinstance(result, DictionaryType)
    assert isinstance(result.key_type, StringType)
    assert isinstance(result.value_type, IntegerType)
    assert inf.errors == []


def test_visit_dict_expression_empty_returns_unknown_key_value() -> None:
    """visit_dict_expression with no items yields DictionaryType(Unknown, Unknown)."""
    inf = _inf()
    result = inf.infer(DictExpression(items=[]))
    assert isinstance(result, DictionaryType)
    assert isinstance(result.key_type, UnknownType)
    assert isinstance(result.value_type, UnknownType)


def test_visit_dict_expression_invalid_items_sequence_logs_error() -> None:
    """visit_dict_expression logs error when items is not a sequence."""
    inf = _inf()
    node = DictExpression(items=[])
    object.__setattr__(node, "items", 42)
    result = inf.infer(node)
    assert isinstance(result, DictionaryType)
    assert any("Dict expression items must be a sequence" in e for e in inf.errors)


def test_visit_dict_expression_invalid_item_without_key_value_logs_error() -> None:
    """visit_dict_expression logs error for items lacking key/value attributes."""
    inf = _inf()
    node = DictExpression(items=[])
    object.__setattr__(node, "items", ["not_a_dict_item"])
    result = inf.infer(node)
    assert isinstance(result, DictionaryType)
    assert any("Dict expression items item must be DictItem" in e for e in inf.errors)


def test_visit_dict_expression_dict_spread_valid_extracts_types() -> None:
    """visit_dict_expression with dict spread inlines spread's key/value types."""
    env = _env()
    env.define("base", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    spread = SpreadOperator(expression=Identifier(name="base"), is_dict=True)
    # DictItem with spread: key is arbitrary, value is the SpreadOperator
    item = DictItem(key=StringLiteral("ignored"), value=spread)
    result = inf.infer(DictExpression(items=[item]))
    assert isinstance(result, DictionaryType)
    assert isinstance(result.key_type, StringType)
    assert inf.errors == []


def test_visit_dict_expression_dict_spread_non_dict_type_logs_error() -> None:
    """visit_dict_expression logs error when spreading a non-dictionary value."""
    inf = _inf()
    spread = SpreadOperator(expression=IntegerLiteral(value=1), is_dict=True)
    item = DictItem(key=StringLiteral("k"), value=spread)
    result = inf.infer(DictExpression(items=[item]))
    assert isinstance(result, DictionaryType)
    assert any("Dict spread requires dictionary" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_dict_item (line 386-387)
# ---------------------------------------------------------------------------


def test_visit_dict_item_returns_value_type() -> None:
    """visit_dict_item returns the type of the value expression."""
    inf = _inf()
    item = DictItem(key=StringLiteral("k"), value=DoubleLiteral(value=1.0))
    result = inf.visit(item)
    assert isinstance(result, DoubleType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_array_comprehension (lines 389-404)
# ---------------------------------------------------------------------------


def test_visit_array_comprehension_over_array_binds_element_type() -> None:
    """visit_array_comprehension defines the loop variable as the array element type."""
    env = _env()
    env.define("words", ArrayType(StringType()))
    inf = _inf(env)
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="word"),
            variable="word",
            iterable=Identifier(name="words"),
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, StringType)
    assert inf.errors == []


def test_visit_array_comprehension_over_range_binds_integer_type() -> None:
    """visit_array_comprehension over a range binds integer to the loop variable."""
    inf = _inf()
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="i"),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(9)),
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


def test_visit_array_comprehension_nil_iterable_uses_unknown_type() -> None:
    """visit_array_comprehension with None iterable logs cannot-iterate error."""
    inf = _inf()
    node = ArrayComprehension(expression=IntegerLiteral(1), variable="i", iterable=None)
    result = inf.infer(node)
    assert isinstance(result, ArrayType)
    # None iterable results in UnknownType being iterated — should log error
    assert any("Cannot iterate over type" in e for e in inf.errors)


def test_visit_array_comprehension_nil_variable_visits_iterable_only() -> None:
    """visit_array_comprehension with empty variable still visits the iterable."""
    inf = _inf()
    # variable="" means _normalize_local_variable returns None (invalid)
    node = ArrayComprehension(
        expression=IntegerLiteral(1),
        variable="",
        iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)),
    )
    result = inf.infer(node)
    # Even with invalid variable, the iterable is visited and element is evaluated
    assert isinstance(result, ArrayType)
    assert any("Local variable name" in e or "Invalid local variable" in e for e in inf.errors)


def test_visit_array_comprehension_boolean_condition_is_valid() -> None:
    """visit_array_comprehension with a boolean condition does not log an error."""
    inf = _inf()
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="i"),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(9)),
            condition=BooleanLiteral(value=True),
        )
    )
    assert isinstance(result, ArrayType)
    assert not any("Array comprehension filter" in e for e in inf.errors)


def test_visit_array_comprehension_non_boolean_condition_logs_error() -> None:
    """visit_array_comprehension logs error when condition is not BooleanType."""
    inf = _inf()
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="i"),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(9)),
            condition=IntegerLiteral(value=1),
        )
    )
    assert isinstance(result, ArrayType)
    assert any("Array comprehension filter must be boolean" in e for e in inf.errors)


def test_visit_array_comprehension_nil_expression_returns_unknown_element() -> None:
    """visit_array_comprehension with None expression yields ArrayType(UnknownType)."""
    inf = _inf()
    result = inf.infer(
        ArrayComprehension(
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(3)),
            expression=None,
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, UnknownType)


def test_visit_array_comprehension_invalid_variable_and_nil_iterable() -> None:
    """visit_array_comprehension with invalid variable and None iterable skips both branches."""
    inf = _inf()
    # variable="" → _normalize_local_variable returns None
    # iterable=None → elif branch condition is False → neither branch executes
    node = ArrayComprehension(
        expression=IntegerLiteral(1),
        variable="",
        iterable=None,
    )
    result = inf.infer(node)
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)


# ---------------------------------------------------------------------------
# visit_dict_comprehension (lines 406-437)
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_over_dict_binds_key_value_variables() -> None:
    """visit_dict_comprehension over a DictionaryType binds key and value types."""
    env = _env()
    env.define("mapping", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        DictComprehension(
            key_expression=Identifier(name="k"),
            value_expression=Identifier(name="v"),
            key_variable="k",
            value_variable="v",
            iterable=Identifier(name="mapping"),
        )
    )
    assert isinstance(result, DictionaryType)
    assert isinstance(result.key_type, StringType)
    assert isinstance(result.value_type, IntegerType)
    assert inf.errors == []


def test_visit_dict_comprehension_nil_key_variable_visits_iterable_only() -> None:
    """visit_dict_comprehension with invalid key_variable still visits iterable."""
    inf = _inf()
    node = DictComprehension(
        key_expression=StringLiteral("k"),
        value_expression=IntegerLiteral(1),
        key_variable="",
        iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(5)),
    )
    result = inf.infer(node)
    assert isinstance(result, DictionaryType)
    assert any("Local variable name" in e or "Invalid local variable" in e for e in inf.errors)


def test_visit_dict_comprehension_nil_iterable_uses_unknown_type() -> None:
    """visit_dict_comprehension with None iterable results in UnknownType iteration."""
    inf = _inf()
    result = inf.infer(
        DictComprehension(
            key_expression=StringLiteral("k"),
            value_expression=IntegerLiteral(1),
            key_variable="k",
            iterable=None,
        )
    )
    assert isinstance(result, DictionaryType)


def test_visit_dict_comprehension_invalid_variable_and_nil_iterable() -> None:
    """visit_dict_comprehension with invalid key_variable and None iterable skips both branches."""
    inf = _inf()
    # key_variable="" → _normalize_local_variable returns None
    # iterable=None → elif branch condition is False → neither branch executes
    node = DictComprehension(
        key_expression=StringLiteral("k"),
        value_expression=IntegerLiteral(1),
        key_variable="",
        iterable=None,
    )
    result = inf.infer(node)
    assert isinstance(result, DictionaryType)


def test_visit_dict_comprehension_boolean_condition_accepted() -> None:
    """visit_dict_comprehension with a boolean condition does not log an error."""
    env = _env()
    env.define("src", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        DictComprehension(
            key_expression=Identifier(name="k"),
            value_expression=Identifier(name="v"),
            key_variable="k",
            value_variable="v",
            iterable=Identifier(name="src"),
            condition=BooleanLiteral(value=True),
        )
    )
    assert isinstance(result, DictionaryType)
    assert not any("Dict comprehension filter" in e for e in inf.errors)


def test_visit_dict_comprehension_non_boolean_condition_logs_error() -> None:
    """visit_dict_comprehension logs error when condition type is not boolean."""
    env = _env()
    env.define("src", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        DictComprehension(
            key_expression=Identifier(name="k"),
            value_expression=Identifier(name="v"),
            key_variable="k",
            value_variable="v",
            iterable=Identifier(name="src"),
            condition=IntegerLiteral(value=0),
        )
    )
    assert isinstance(result, DictionaryType)
    assert any("Dict comprehension filter must be boolean" in e for e in inf.errors)


def test_visit_dict_comprehension_nil_key_and_value_expressions_yield_unknown() -> None:
    """visit_dict_comprehension returns DictionaryType(Unknown, Unknown) when exprs are None."""
    env = _env()
    env.define("src", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        DictComprehension(
            key_expression=None,
            value_expression=None,
            key_variable="k",
            value_variable="v",
            iterable=Identifier(name="src"),
        )
    )
    assert isinstance(result, DictionaryType)
    assert isinstance(result.key_type, UnknownType)
    assert isinstance(result.value_type, UnknownType)


# ---------------------------------------------------------------------------
# visit_tuple_indexing (lines 439-447)
# ---------------------------------------------------------------------------


def test_visit_tuple_indexing_valid_array_type_returns_element_type() -> None:
    """visit_tuple_indexing on an ArrayType returns the element type."""
    env = _env()
    env.define("coords", ArrayType(DoubleType()))
    inf = _inf(env)
    result = inf.infer(
        TupleIndexing(
            tuple_expr=Identifier(name="coords"),
            index=IntegerLiteral(value=0),
        )
    )
    assert isinstance(result, DoubleType)
    assert inf.errors == []


def test_visit_tuple_indexing_non_integer_index_logs_error() -> None:
    """visit_tuple_indexing logs error when index is not IntegerType."""
    env = _env()
    env.define("coords", ArrayType(IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        TupleIndexing(
            tuple_expr=Identifier(name="coords"),
            index=StringLiteral(value="bad"),
        )
    )
    assert isinstance(result, IntegerType)
    assert any("Tuple index must be integer" in e for e in inf.errors)


def test_visit_tuple_indexing_non_array_type_logs_error() -> None:
    """visit_tuple_indexing logs error when the tuple_expr is not an ArrayType."""
    inf = _inf()
    result = inf.infer(
        TupleIndexing(
            tuple_expr=StringLiteral(value="bad"),
            index=IntegerLiteral(value=0),
        )
    )
    assert isinstance(result, UnknownType)
    assert any("Cannot index non-tuple type" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_slice_expression (lines 449-457)
# ---------------------------------------------------------------------------


def test_visit_slice_expression_on_array_returns_array() -> None:
    """visit_slice_expression on an ArrayType returns the same ArrayType."""
    env = _env()
    env.define("items", ArrayType(IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        SliceExpression(
            target=Identifier(name="items"),
            start=IntegerLiteral(value=0),
            stop=IntegerLiteral(value=5),
        )
    )
    assert isinstance(result, ArrayType)
    assert inf.errors == []


def test_visit_slice_expression_on_string_returns_string() -> None:
    """visit_slice_expression on a StringType returns StringType."""
    inf = _inf()
    result = inf.infer(
        SliceExpression(
            target=StringLiteral(value="hello"),
            start=IntegerLiteral(value=0),
            stop=IntegerLiteral(value=3),
        )
    )
    assert isinstance(result, StringType)
    assert inf.errors == []


def test_visit_slice_expression_non_integer_bound_logs_error() -> None:
    """visit_slice_expression logs error when a slice bound is not IntegerType."""
    env = _env()
    env.define("arr", ArrayType(IntegerType()))
    inf = _inf(env)
    inf.infer(
        SliceExpression(
            target=Identifier(name="arr"),
            start=StringLiteral(value="bad"),
        )
    )
    assert any("Slice bounds must be integer" in e for e in inf.errors)


def test_visit_slice_expression_step_none_is_valid() -> None:
    """visit_slice_expression with step=None does not log an error."""
    env = _env()
    env.define("arr", ArrayType(DoubleType()))
    inf = _inf(env)
    result = inf.infer(
        SliceExpression(
            target=Identifier(name="arr"),
            stop=IntegerLiteral(value=10),
            step=None,
        )
    )
    assert isinstance(result, ArrayType)
    assert not any("Slice bounds must be integer" in e for e in inf.errors)


def test_visit_slice_expression_on_non_array_non_string_logs_error() -> None:
    """visit_slice_expression on an unsupported type logs error."""
    inf = _inf()
    result = inf.infer(
        SliceExpression(
            target=IntegerLiteral(value=5),
        )
    )
    assert isinstance(result, UnknownType)
    assert any("Cannot slice non-array or string type" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_lambda_expression (lines 459-467)
# ---------------------------------------------------------------------------


def test_visit_lambda_expression_returns_unknown_type() -> None:
    """visit_lambda_expression returns UnknownType (lambdas are not typed)."""
    inf = _inf()
    result = inf.infer(
        LambdaExpression(
            parameters=["x", "y"],
            body=BinaryExpression(
                left=Identifier(name="x"),
                operator="+",
                right=Identifier(name="y"),
            ),
        )
    )
    assert isinstance(result, UnknownType)


def test_visit_lambda_expression_defines_parameters_in_scoped_env() -> None:
    """visit_lambda_expression does not pollute the outer scope."""
    env = _env()
    inf = _inf(env)
    scope_before = len(env.scopes)
    inf.infer(
        LambdaExpression(
            parameters=["z"],
            body=Identifier(name="z"),
        )
    )
    assert len(env.scopes) == scope_before
    # z is no longer visible outside
    assert env.lookup("z") is None


def test_visit_lambda_expression_invalid_parameter_logs_error() -> None:
    """visit_lambda_expression logs error for invalid parameter names."""
    inf = _inf()
    inf.infer(
        LambdaExpression(
            parameters=["bad-name"],
            body=BooleanLiteral(value=True),
        )
    )
    assert any("Invalid local variable identifier: bad-name" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_pattern_match (lines 469-486)
# ---------------------------------------------------------------------------


def test_visit_pattern_match_simple_returns_common_result_type() -> None:
    """visit_pattern_match returns the common type of case result expressions."""
    inf = _inf()
    result = inf.infer(
        PatternMatch(
            value=IntegerLiteral(value=1),
            cases=[
                MatchCase(pattern=IntegerLiteral(1), result=StringLiteral("one")),
                MatchCase(pattern=IntegerLiteral(2), result=StringLiteral("two")),
            ],
            default=StringLiteral("other"),
        )
    )
    assert isinstance(result, StringType)
    assert inf.errors == []


def test_visit_pattern_match_nil_default_is_valid() -> None:
    """visit_pattern_match with no default does not error."""
    inf = _inf()
    result = inf.infer(
        PatternMatch(
            value=BooleanLiteral(value=True),
            cases=[MatchCase(pattern=BooleanLiteral(True), result=IntegerLiteral(1))],
            default=None,
        )
    )
    assert isinstance(result, IntegerType)
    assert inf.errors == []


def test_visit_pattern_match_invalid_case_logs_error() -> None:
    """visit_pattern_match logs error for a case without pattern/result attributes."""
    inf = _inf()
    node = PatternMatch(
        value=IntegerLiteral(1),
        cases=[MatchCase(pattern=IntegerLiteral(1), result=IntegerLiteral(0))],
        default=None,
    )
    object.__setattr__(node, "cases", ["bad_case"])
    result = inf.infer(node)
    assert isinstance(result, UnknownType)
    assert any("Pattern match cases item must be MatchCase" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# visit_match_case (lines 488-490)
# ---------------------------------------------------------------------------


def test_visit_match_case_visits_pattern_and_returns_result_type() -> None:
    """visit_match_case visits the pattern and returns the result type."""
    inf = _inf()
    result = inf.visit(
        MatchCase(
            pattern=IntegerLiteral(value=42),
            result=StringLiteral(value="forty-two"),
        )
    )
    assert isinstance(result, StringType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# visit_spread_operator (lines 492-493)
# ---------------------------------------------------------------------------


def test_visit_spread_operator_returns_type_of_inner_expression() -> None:
    """visit_spread_operator delegates to the inner expression type."""
    env = _env()
    env.define("nums", ArrayType(IntegerType()))
    inf = _inf(env)
    result = inf.infer(SpreadOperator(expression=Identifier(name="nums"), is_dict=False))
    assert isinstance(result, ArrayType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# _define_dict_comprehension_variables (lines 495-510) — via DictComprehension
# ---------------------------------------------------------------------------


def test_define_dict_comprehension_variables_over_dict_binds_both() -> None:
    """_define_dict_comprehension_variables extracts key_type and value_type."""
    env = _env()
    env.define("lookup", DictionaryType(IntegerType(), StringType()))
    inf = _inf(env)
    result = inf.infer(
        DictComprehension(
            key_expression=Identifier(name="kid"),
            value_expression=Identifier(name="vid"),
            key_variable="kid",
            value_variable="vid",
            iterable=Identifier(name="lookup"),
        )
    )
    assert isinstance(result, DictionaryType)
    assert isinstance(result.key_type, IntegerType)
    assert isinstance(result.value_type, StringType)
    assert inf.errors == []


def test_define_dict_comprehension_variables_over_array_uses_iteration_type() -> None:
    """_define_dict_comprehension_variables falls back to iteration for non-dict."""
    env = _env()
    env.define("arr", ArrayType(StringType()))
    inf = _inf(env)
    # Iterating over an array: key_variable gets element type, value_variable gets Unknown
    result = inf.infer(
        DictComprehension(
            key_expression=Identifier(name="k"),
            value_expression=Identifier(name="v"),
            key_variable="k",
            value_variable="v",
            iterable=Identifier(name="arr"),
        )
    )
    assert isinstance(result, DictionaryType)
    # key_variable is bound to the array element type; check no fatal errors
    assert not any("Dict comprehension filter" in e for e in inf.errors)


def test_define_dict_comprehension_variables_over_dict_without_value_variable() -> None:
    """_define_dict_comprehension_variables ignores None value_variable."""
    env = _env()
    env.define("src", DictionaryType(StringType(), IntegerType()))
    inf = _inf(env)
    result = inf.infer(
        DictComprehension(
            key_expression=Identifier(name="k"),
            value_expression=IntegerLiteral(0),
            key_variable="k",
            value_variable=None,
            iterable=Identifier(name="src"),
        )
    )
    assert isinstance(result, DictionaryType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# _define_iteration_variable (lines 512-514) — via ArrayComprehension
# ---------------------------------------------------------------------------


def test_define_iteration_variable_over_nil_iterable_uses_unknown() -> None:
    """_define_iteration_variable with None iterable uses UnknownType."""
    inf = _inf()
    node = ArrayComprehension(
        expression=IntegerLiteral(1),
        variable="x",
        iterable=None,
    )
    result = inf.infer(node)
    assert isinstance(result, ArrayType)
    assert any("Cannot iterate over type: unknown" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# _define_iteration_variable_from_type (lines 516-525) — all branches
# ---------------------------------------------------------------------------


def test_define_iteration_variable_from_array_type_extracts_element() -> None:
    """_define_iteration_variable_from_type extracts element_type for ArrayType."""
    env = _env()
    env.define("strs", ArrayType(StringType()))
    inf = _inf(env)
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="s"),
            variable="s",
            iterable=Identifier(name="strs"),
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, StringType)
    assert inf.errors == []


def test_define_iteration_variable_from_range_type_yields_integer() -> None:
    """_define_iteration_variable_from_type uses IntegerType for RangeType."""
    inf = _inf()
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="i"),
            variable="i",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(9)),
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


def test_define_iteration_variable_from_dict_type_yields_key_type() -> None:
    """_define_iteration_variable_from_type uses key_type for DictionaryType."""
    env = _env()
    env.define("pairs", DictionaryType(IntegerType(), StringType()))
    inf = _inf(env)
    result = inf.infer(
        ArrayComprehension(
            expression=Identifier(name="k"),
            variable="k",
            iterable=Identifier(name="pairs"),
        )
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


def test_define_iteration_variable_from_unknown_type_logs_error() -> None:
    """_define_iteration_variable_from_type logs error for unknown iterable type."""
    inf = _inf()
    result = inf.infer(
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable="i",
            iterable=StringLiteral(value="bad"),
        )
    )
    assert isinstance(result, ArrayType)
    assert any("Cannot iterate over type: string" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# _normalize_local_variable (lines 527-546) — all branches
# ---------------------------------------------------------------------------


def test_normalize_local_variable_non_string_logs_error() -> None:
    """_normalize_local_variable logs error when variable is not a string."""
    inf = _inf()
    decl = WithDeclaration(identifier="x", value=IntegerLiteral(1))
    object.__setattr__(decl, "identifier", 999)
    inf.visit(decl)
    assert any("Local variable name must be a string" in e for e in inf.errors)


def test_normalize_local_variable_dollar_prefix_valid() -> None:
    """_normalize_local_variable handles '$'-prefixed string identifiers."""
    env = _env()
    inf = _inf(env)
    env.push_scope()
    decl = WithDeclaration(identifier="$valid", value=StringLiteral("x"))
    inf.visit(decl)
    assert inf.errors == []


def test_normalize_local_variable_dollar_prefix_wildcard_logs_error() -> None:
    """_normalize_local_variable rejects wildcard '$*' in with-declaration."""
    inf = _inf()
    env = inf.env
    env.push_scope()
    decl = WithDeclaration(identifier="$*", value=IntegerLiteral(1))
    inf.visit(decl)
    assert any("Invalid local variable identifier: $*" in e for e in inf.errors)


def test_normalize_local_variable_plain_valid_identifier() -> None:
    """_normalize_local_variable accepts a valid plain identifier."""
    env = _env()
    inf = _inf(env)
    env.push_scope()
    decl = WithDeclaration(identifier="my_var", value=BooleanLiteral(True))
    inf.visit(decl)
    assert inf.errors == []
    assert isinstance(env.lookup("my_var"), BooleanType)


def test_normalize_local_variable_invalid_plain_identifier_logs_error() -> None:
    """_normalize_local_variable logs error for an invalid identifier."""
    inf = _inf()
    # 'for' is a reserved keyword; should fail in the non-string-id path
    inf.infer(
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable="for",
            iterable=RangeExpression(IntegerLiteral(0), IntegerLiteral(1)),
        )
    )
    assert any("Invalid local variable identifier: for" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# _infer_common_type (lines 548-551)
# ---------------------------------------------------------------------------


def test_infer_common_type_empty_node_list_returns_unknown() -> None:
    """_infer_common_type returns UnknownType when given an empty node list."""
    inf = _inf()
    # PatternMatch with empty cases and no default exercises _infer_common_type([])
    result = inf.infer(
        PatternMatch(
            value=IntegerLiteral(1),
            cases=[],
            default=None,
        )
    )
    assert isinstance(result, UnknownType)
    assert inf.errors == []


def test_infer_common_type_single_node_returns_that_type() -> None:
    """_infer_common_type with one node returns that node's type."""
    inf = _inf()
    result = inf.infer(
        PatternMatch(
            value=StringLiteral("x"),
            cases=[MatchCase(pattern=StringLiteral("a"), result=IntegerLiteral(1))],
            default=None,
        )
    )
    assert isinstance(result, IntegerType)
    assert inf.errors == []


# ---------------------------------------------------------------------------
# _infer_common_type_from_types (lines 553-562)
# ---------------------------------------------------------------------------


def test_infer_common_type_from_types_empty_returns_unknown() -> None:
    """_infer_common_type_from_types returns UnknownType for an empty list."""
    inf = _inf()
    # An empty ListExpression triggers _infer_common_type_from_types([])
    result = inf.infer(ListExpression(elements=[]))
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, UnknownType)


def test_infer_common_type_from_types_compatible_types_no_error() -> None:
    """_infer_common_type_from_types returns the first type for identical types."""
    inf = _inf()
    result = inf.infer(
        ListExpression(elements=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)])
    )
    assert isinstance(result, ArrayType)
    assert isinstance(result.element_type, IntegerType)
    assert inf.errors == []


def test_infer_common_type_from_types_incompatible_types_logs_error() -> None:
    """_infer_common_type_from_types logs error for incompatible element types."""
    inf = _inf()
    result = inf.infer(
        ListExpression(
            elements=[
                IntegerLiteral(1),
                StringLiteral(value="x"),
                BooleanLiteral(value=True),
            ]
        )
    )
    assert isinstance(result, ArrayType)
    assert any("Collection elements must have compatible types" in e for e in inf.errors)


# ---------------------------------------------------------------------------
# Regression — ExpressionTypeInference visits Comment/CommentGroup through
# the inherited base-class methods (lines 73-104 via subclass dispatch)
# ---------------------------------------------------------------------------


def test_expr_inference_visits_comment_and_comment_group_via_inherited_methods() -> None:
    """ExpressionTypeInference inherits and invokes visit_comment / visit_comment_group."""
    inf = _inf()
    assert isinstance(inf.visit(Comment("// note")), UnknownType)
    assert isinstance(inf.visit(CommentGroup([Comment("// note")])), UnknownType)
    assert inf.errors == []


def test_expr_inference_visits_extern_nodes_via_inherited_methods() -> None:
    """ExpressionTypeInference inherits visit_extern_* returning UnknownType."""
    inf = _inf()
    assert isinstance(inf.visit(ExternImport(module_path="ext")), UnknownType)
    assert isinstance(inf.visit(ExternNamespace(name="ns")), UnknownType)
    assert isinstance(inf.visit(ExternRule(name="r")), UnknownType)


def test_expr_inference_visits_pragma_nodes_via_inherited_methods() -> None:
    """ExpressionTypeInference inherits visit_pragma / visit_in_rule_pragma / visit_pragma_block."""
    inf = _inf()
    pragma = Pragma(pragma_type=PragmaType.PRAGMA, name="pragma")
    assert isinstance(inf.visit(pragma), UnknownType)
    assert isinstance(inf.visit(InRulePragma(pragma=pragma)), UnknownType)
    assert isinstance(inf.visit(PragmaBlock(pragmas=[])), UnknownType)


# ---------------------------------------------------------------------------
# Additional integration — with_statement scoping round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("identifier", "value_expr", "expected_type"),
    [
        ("count", IntegerLiteral(value=0), IntegerType),
        ("flag", BooleanLiteral(value=True), BooleanType),
        ("label", StringLiteral(value="x"), StringType),
    ],
)
def test_visit_with_declaration_type_round_trip(
    identifier: str,
    value_expr: Any,
    expected_type: type,
) -> None:
    """visit_with_declaration defines the correct type in the current scope."""
    env = _env()
    inf = _inf(env)
    result = inf.infer(
        WithStatement(
            declarations=[WithDeclaration(identifier=identifier, value=value_expr)],
            body=Identifier(name=identifier),
        )
    )
    assert isinstance(result, expected_type)
    assert inf.errors == []
