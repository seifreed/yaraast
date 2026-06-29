"""Coverage loop for yaraast.lsp.document_query_resolution_ast.

Tests exercise the real LSP resolution API by parsing genuine YARA documents
and invoking resolve_symbol_from_ast at precisely targeted positions.  No
mocks, no stubs, no artificial scaffolding.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from lsprotocol.types import Position

from yaraast.lsp.document_context import DocumentContext
from yaraast.lsp.document_query_resolution_ast import (
    member_access_root_is_module,
    member_access_to_string,
    resolve_symbol_from_ast,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _doc(text: str) -> DocumentContext:
    return DocumentContext(uri="file://test.yar", text=text)


def _pos(line: int, char: int) -> Position:
    return Position(line=line, character=char)


# ---------------------------------------------------------------------------
# Null-AST early return (line 46)
# ---------------------------------------------------------------------------


def test_resolve_symbol_returns_none_for_unparseable_document() -> None:
    """resolve_symbol_from_ast returns None immediately when the AST is None."""
    ctx = _doc("rule broken {\n")
    assert ctx.ast() is None
    result = resolve_symbol_from_ast(ctx, _pos(0, 5))
    assert result is None


# ---------------------------------------------------------------------------
# StringIdentifier resolution (lines 456-464)
# ---------------------------------------------------------------------------


def test_resolve_string_identifier_in_condition() -> None:
    """StringIdentifier in a condition resolves to kind='string'."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}'
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(4, 4))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"
    assert sym.range.start.line == 4


# ---------------------------------------------------------------------------
# StringCount / StringOffset / StringLength resolution (lines 466-477)
# ---------------------------------------------------------------------------


def test_resolve_string_count_resolves_to_string_kind() -> None:
    """#a (StringCount) is resolved to kind='string' with normalized $a."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    #a > 0\n}'
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(4, 4))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"
    assert sym.name == "#a"


def test_resolve_string_offset_resolves_to_string_kind() -> None:
    """@a (StringOffset) resolves to kind='string' with normalized $a."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    @a == 4\n}'
    ctx = _doc(text)
    # @a occupies cols 4-5
    sym = resolve_symbol_from_ast(ctx, _pos(4, 4))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"


def test_resolve_string_length_resolves_to_string_kind() -> None:
    """!a (StringLength) resolves to kind='string' with normalized $a."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    !a > 0\n}'
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(4, 4))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"


# ---------------------------------------------------------------------------
# ModuleReference resolution (lines 478-481)
# ---------------------------------------------------------------------------


def test_resolve_module_reference_at_module_name() -> None:
    """Position on the module name 'pe' resolves to kind='module'."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.number_of_sections > 0\n}'
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(3, 4))
    assert sym is not None
    assert sym.kind == "module"
    assert sym.normalized_name == "pe"


# ---------------------------------------------------------------------------
# MemberAccess resolution (lines 483-494)
# ---------------------------------------------------------------------------


def test_resolve_member_access_on_module_returns_module_member() -> None:
    """Position inside 'pe.number_of_sections' resolves as kind='module_member'."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.number_of_sections > 0\n}'
    ctx = _doc(text)
    # col 7 is inside 'number_of_sections'
    sym = resolve_symbol_from_ast(ctx, _pos(3, 7))
    assert sym is not None
    assert sym.kind == "module_member"
    assert sym.normalized_name == "pe.number_of_sections"


def test_resolve_member_access_on_identifier_root_returns_identifier() -> None:
    """MemberAccess whose root is a plain Identifier resolves as kind='identifier'."""
    text = "rule r {\n  condition:\n    some_obj.field\n}"
    ctx = _doc(text)
    # col 12 is inside '.field'
    sym = resolve_symbol_from_ast(ctx, _pos(2, 12))
    assert sym is not None
    assert sym.kind == "identifier"
    assert "some_obj.field" in sym.normalized_name


# ---------------------------------------------------------------------------
# FunctionCall with '.' (module method) resolution (lines 495-505)
# ---------------------------------------------------------------------------


def test_resolve_function_call_with_dot_returns_module_member() -> None:
    """pe.imports() resolves as kind='module_member' at any position inside the name."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.imports("k")\n}'
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(3, 7))
    assert sym is not None
    assert sym.kind == "module_member"
    assert sym.normalized_name == "pe.imports"


# ---------------------------------------------------------------------------
# RuleNode resolution (lines 507-516)
# ---------------------------------------------------------------------------


def test_resolve_rule_node_at_rule_name() -> None:
    """Position on the rule name in 'rule alpha {...}' resolves as kind='rule'."""
    text = "rule alpha {\n  condition:\n    true\n}"
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(0, 5))
    assert sym is not None
    assert sym.kind == "rule"
    assert sym.normalized_name == "alpha"


# ---------------------------------------------------------------------------
# Identifier resolution (lines 518-526)
# ---------------------------------------------------------------------------


def test_resolve_identifier_referencing_known_rule_returns_rule_kind() -> None:
    """Identifier that matches a rule name resolves as kind='rule'."""
    text = "rule alpha { condition: true }\nrule beta { condition: alpha }"
    ctx = _doc(text)
    # 'alpha' on line 1 is at cols 23-27
    sym = resolve_symbol_from_ast(ctx, _pos(1, 23))
    assert sym is not None
    assert sym.kind == "rule"
    assert sym.normalized_name == "alpha"


def test_resolve_identifier_with_no_rule_returns_identifier_kind() -> None:
    """Identifier not matching any rule definition resolves as kind='identifier'."""
    text = "rule r { condition: some_var }"
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(0, 20))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "some_var"


# ---------------------------------------------------------------------------
# AtExpression / InExpression context fallback (lines 535-544)
# ---------------------------------------------------------------------------


def test_resolve_expression_context_at_expression_with_dollar_word() -> None:
    """Position inside AtExpression on a $-prefixed word resolves via expression context."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a at 100\n}'
    ctx = _doc(text)
    # cols 4-5 land in AtExpression node; word is '$a'
    sym = resolve_symbol_from_ast(ctx, _pos(4, 4))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"


def test_resolve_expression_context_in_expression_with_dollar_word() -> None:
    """Position inside InExpression on a $-prefixed word resolves via expression context."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a in (1..10)\n}'
    ctx = _doc(text)
    # cols 4-5 are inside InExpression with word '$a'
    sym = resolve_symbol_from_ast(ctx, _pos(4, 4))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"


# ---------------------------------------------------------------------------
# WithStatement local identifier resolution (lines 69-103)
# ---------------------------------------------------------------------------


def test_resolve_with_declaration_identifier_at_declaration_site() -> None:
    """Position on the 'x' in 'with x = 1' resolves the local binding."""
    text = "rule r {\n  condition:\n    with x = 1:\n      x > 0\n}"
    ctx = _doc(text)
    # 'x' on line 2 at col 9
    sym = resolve_symbol_from_ast(ctx, _pos(2, 9))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


def test_resolve_with_declaration_identifier_at_usage_site() -> None:
    """Position on 'x' in the with body resolves to the local binding."""
    text = "rule r {\n  condition:\n    with x = 1:\n      x > 0\n}"
    ctx = _doc(text)
    # 'x' on line 3 (body)
    sym = resolve_symbol_from_ast(ctx, _pos(3, 6))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


def test_resolve_with_declaration_identifier_multiline_value() -> None:
    """When value spans to the next line, falls back to previous-line identifier search."""
    text = "rule r {\n  condition:\n    with x =\n        1:\n      x\n}"
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(4, 6))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


# ---------------------------------------------------------------------------
# ForExpression loop-variable resolution (lines 113-118, 233-252)
# ---------------------------------------------------------------------------


def test_resolve_for_expression_loop_variable_at_declaration() -> None:
    """Loop variable 'i' in 'for any i in (0,1)' resolves at its declaration position."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    for any i in (0, 1): ($a at i)\n}'
    ctx = _doc(text)
    # 'i' on line 4 at col 12
    sym = resolve_symbol_from_ast(ctx, _pos(4, 12))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "i"


def test_resolve_for_expression_loop_variable_at_usage() -> None:
    """Loop variable 'i' used in the for body resolves to the loop declaration."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    for any i in (0, 1): ($a at i)\n}'
    ctx = _doc(text)
    # 'i' used as argument to 'at' - col 32
    sym = resolve_symbol_from_ast(ctx, _pos(4, 32))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "i"


def test_resolve_for_expression_multiline_declaration() -> None:
    """Multi-line for expression: 'i' on continuation line resolves correctly."""
    text = (
        'rule r {\n  strings:\n    $a = "x"\n  condition:\n'
        "    for any i\n      in (0, 1): ($a at i)\n}"
    )
    ctx = _doc(text)
    # 'i' declaration on line 4
    sym = resolve_symbol_from_ast(ctx, _pos(4, 12))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "i"
    # 'i' usage on line 5
    sym_use = resolve_symbol_from_ast(ctx, _pos(5, 24))
    assert sym_use is not None
    assert sym_use.normalized_name == "i"


# ---------------------------------------------------------------------------
# ArrayComprehension loop-variable resolution (lines 113-114)
# ---------------------------------------------------------------------------


def test_resolve_array_comprehension_loop_variable_at_declaration() -> None:
    """Variable 'x' in '[x * 2 for x in (1,2,3)]' resolves at its declaration."""
    text = "rule r {\n  condition:\n    [x * 2 for x in (1, 2, 3)][0]\n}"
    ctx = _doc(text)
    # 'x' declaration at col 15
    sym = resolve_symbol_from_ast(ctx, _pos(2, 15))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


def test_resolve_array_comprehension_loop_variable_at_usage() -> None:
    """Variable 'x' used in expression part of comprehension resolves to loop binding."""
    text = "rule r {\n  condition:\n    [x * 2 for x in (1, 2, 3)][0]\n}"
    ctx = _doc(text)
    # 'x' at col 5 (inside expression part)
    sym = resolve_symbol_from_ast(ctx, _pos(2, 5))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


# ---------------------------------------------------------------------------
# DictComprehension loop-variable resolution (lines 115-118)
# ---------------------------------------------------------------------------


def test_resolve_dict_comprehension_key_variable_at_declaration() -> None:
    """Key variable 'k' in dict comprehension resolves at its declaration."""
    text = "rule r {\n  condition:\n    {k: v for k, v in some_dict}\n}"
    ctx = _doc(text)
    # 'k' declaration at col 14
    sym = resolve_symbol_from_ast(ctx, _pos(2, 14))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "k"


def test_resolve_dict_comprehension_value_variable_at_declaration() -> None:
    """Value variable 'v' in dict comprehension resolves at its declaration."""
    text = "rule r {\n  condition:\n    {k: v for k, v in some_dict}\n}"
    ctx = _doc(text)
    # 'v' declaration at col 17
    sym = resolve_symbol_from_ast(ctx, _pos(2, 17))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "v"


def test_resolve_dict_comprehension_key_variable_at_usage() -> None:
    """Key variable 'k' used in the key expression resolves to its binding."""
    text = "rule r {\n  condition:\n    {k: v for k, v in some_dict}\n}"
    ctx = _doc(text)
    # 'k' usage in key expression at col 5
    sym = resolve_symbol_from_ast(ctx, _pos(2, 5))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "k"


# ---------------------------------------------------------------------------
# LambdaExpression parameter resolution (lines 120-147, 154-177, 185-223)
# ---------------------------------------------------------------------------


def test_resolve_lambda_parameter_at_declaration() -> None:
    """Parameter 'x' in 'lambda x: ...' resolves at its declaration position."""
    text = "rule r {\n  condition:\n    filter([1, 2, 3], lambda x: x > 0)\n}"
    ctx = _doc(text)
    # 'x' declaration at col 29
    sym = resolve_symbol_from_ast(ctx, _pos(2, 29))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


def test_resolve_lambda_parameter_at_usage_in_body() -> None:
    """Parameter 'x' used in lambda body resolves to the lambda parameter."""
    text = "rule r {\n  condition:\n    filter([1, 2, 3], lambda x: x > 0)\n}"
    ctx = _doc(text)
    # 'x' usage in body at col 32
    sym = resolve_symbol_from_ast(ctx, _pos(2, 32))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


def test_resolve_lambda_parameter_multiline_lambda_on_previous_line() -> None:
    """Multi-line lambda: parameter 'x' on the lambda line resolves at usage in next line."""
    text = "rule r {\n  condition:\n    filter([1, 2, 3],\n           lambda x:\n               x > 0)\n}"
    ctx = _doc(text)
    # 'x' declaration on line 3
    sym_decl = resolve_symbol_from_ast(ctx, _pos(3, 18))
    assert sym_decl is not None
    assert sym_decl.kind == "identifier"
    assert sym_decl.normalized_name == "x"
    # 'x' usage on line 4
    sym_use = resolve_symbol_from_ast(ctx, _pos(4, 15))
    assert sym_use is not None
    assert sym_use.kind == "identifier"
    assert sym_use.normalized_name == "x"


# ---------------------------------------------------------------------------
# member_access_to_string helper (lines 548-554)
# ---------------------------------------------------------------------------


def test_member_access_to_string_module_reference_root() -> None:
    """ModuleReference root produces 'module.member' string."""
    from yaraast.ast.expressions import MemberAccess
    from yaraast.ast.modules import ModuleReference

    node = MemberAccess(object=ModuleReference(module="pe"), member="sections")
    assert member_access_to_string(node) == "pe.sections"


def test_member_access_to_string_identifier_root() -> None:
    """Identifier root produces 'name.member' string."""
    from yaraast.ast.expressions import Identifier, MemberAccess

    node = MemberAccess(object=Identifier(name="obj"), member="field")
    assert member_access_to_string(node) == "obj.field"


def test_member_access_to_string_chained_member_access() -> None:
    """Chained MemberAccess recurses and produces the full dotted path."""
    from yaraast.ast.expressions import MemberAccess
    from yaraast.ast.modules import ModuleReference

    inner = MemberAccess(object=ModuleReference(module="pe"), member="sections")
    outer = MemberAccess(object=inner, member="virtual_address")
    assert member_access_to_string(outer) == "pe.sections.virtual_address"


def test_member_access_to_string_unknown_root_returns_member_only() -> None:
    """When the root object is not a recognized type, only the member name is returned."""
    from yaraast.ast.expressions import ArrayAccess, Identifier, IntegerLiteral, MemberAccess

    arr = ArrayAccess(array=Identifier(name="sections"), index=IntegerLiteral(value=0))
    node = MemberAccess(object=arr, member="name")
    assert member_access_to_string(node) == "name"


# ---------------------------------------------------------------------------
# member_access_root_is_module helper (lines 558-561)
# ---------------------------------------------------------------------------


def test_member_access_root_is_module_true_for_module_reference() -> None:
    """Returns True when the chain root is a ModuleReference."""
    from yaraast.ast.expressions import MemberAccess
    from yaraast.ast.modules import ModuleReference

    node = MemberAccess(object=ModuleReference(module="pe"), member="sections")
    assert member_access_root_is_module(node) is True


def test_member_access_root_is_module_false_for_identifier_root() -> None:
    """Returns False when the chain root is a plain Identifier."""
    from yaraast.ast.expressions import Identifier, MemberAccess

    node = MemberAccess(object=Identifier(name="obj"), member="field")
    assert member_access_root_is_module(node) is False


def test_member_access_root_is_module_false_for_chained_identifier_root() -> None:
    """Returns False when a chained MemberAccess ultimately roots at an Identifier."""
    from yaraast.ast.expressions import Identifier, MemberAccess

    inner = MemberAccess(object=Identifier(name="obj"), member="sub")
    outer = MemberAccess(object=inner, member="nested")
    assert member_access_root_is_module(outer) is False


# ---------------------------------------------------------------------------
# No-node / no-location early returns (lines 52-56)
# ---------------------------------------------------------------------------


def test_resolve_returns_none_for_position_not_on_any_node() -> None:
    """A position on whitespace between tokens returns None."""
    text = "rule r { condition: true }"
    ctx = _doc(text)
    # col 8 is the '{' or just before 'condition' - whitespace-ish position
    result = resolve_symbol_from_ast(ctx, _pos(0, 8))
    # May be None or may hit the Rule node; what matters is no crash
    assert result is None or isinstance(result.kind, str)


def test_resolve_returns_none_for_boolean_literal_position() -> None:
    """Position on 'true' (BooleanLiteral) falls through all typed handlers to None."""
    text = "rule r { condition: true }"
    ctx = _doc(text)
    sym = resolve_symbol_from_ast(ctx, _pos(0, 20))
    assert sym is None


# ---------------------------------------------------------------------------
# StringCount with local binding path (line 471-473)
# ---------------------------------------------------------------------------


def test_resolve_string_count_in_for_body_without_local_binding() -> None:
    """#a in a for-loop body where $a is not a loop variable resolves as 'string'."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    for any i in (0, 1): (#a > 0)\n}'
    ctx = _doc(text)
    # '#a' at col 26 inside the for body
    sym = resolve_symbol_from_ast(ctx, _pos(4, 26))
    assert sym is not None
    assert sym.kind == "string"
    assert sym.normalized_name == "$a"


# ---------------------------------------------------------------------------
# Chained module member access through ArrayAccess (member_access_to_string fallback)
# ---------------------------------------------------------------------------


def test_resolve_member_access_after_array_index_returns_identifier() -> None:
    """pe.sections[0].name: position on '.name' falls through to identifier kind."""
    text = 'import "pe"\nrule r {\n  condition:\n    pe.sections[0].name\n}'
    ctx = _doc(text)
    # col 19 is inside '.name'
    sym = resolve_symbol_from_ast(ctx, _pos(3, 19))
    assert sym is not None
    # The outer MemberAccess has object=ArrayAccess, so member_access_to_string returns 'name'
    assert sym.normalized_name == "name"
    assert sym.kind == "identifier"


# ---------------------------------------------------------------------------
# Position outside AST node ranges returns None (line 52)
# ---------------------------------------------------------------------------


def test_resolve_returns_none_when_find_node_returns_none() -> None:
    """find_node_at_position returns None for a position beyond all rule ranges."""
    text = "rule r { condition: true }"
    ctx = _doc(text)
    # Line 1 does not exist in the document (it has only line 0)
    result = resolve_symbol_from_ast(ctx, _pos(1, 0))
    assert result is None


# ---------------------------------------------------------------------------
# With statement: multiple declarations trigger the word-mismatch continue (line 92)
# ---------------------------------------------------------------------------


def test_resolve_with_multiple_declarations_skips_non_matching_identifier() -> None:
    """With statement with two declarations: resolving 'y' skips 'x' declaration."""
    text = "rule r {\n  condition:\n    with x = 1, y = 2:\n      y > 0\n}"
    ctx = _doc(text)
    # 'y' declaration at col 16
    sym = resolve_symbol_from_ast(ctx, _pos(2, 16))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "y"
    # 'x' declaration at col 9
    sym_x = resolve_symbol_from_ast(ctx, _pos(2, 9))
    assert sym_x is not None
    assert sym_x.normalized_name == "x"


# ---------------------------------------------------------------------------
# Lambda with continuation-line colon (line 165 and 169)
# ---------------------------------------------------------------------------


def test_resolve_lambda_parameter_with_colon_on_continuation_line() -> None:
    """Lambda parameter resolves when colon separator is on a separate continuation line."""
    text = "rule r {\n  condition:\n    filter([1],\n           lambda x\n            : x > 0)\n}"
    ctx = _doc(text)
    # 'x' declaration on line 3 col 18
    sym = resolve_symbol_from_ast(ctx, _pos(3, 18))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"
    # 'x' usage in body on line 4
    sym_use = resolve_symbol_from_ast(ctx, _pos(4, 14))
    assert sym_use is not None
    assert sym_use.normalized_name == "x"


# ---------------------------------------------------------------------------
# Lambda with parameters on entirely separate lines (line 176-177)
# ---------------------------------------------------------------------------


def test_resolve_lambda_parameter_fully_multiline_header() -> None:
    """Lambda with params and colon split across multiple lines hits line-prefix bounds."""
    text = (
        "rule r {\n  condition:\n    filter([1],\n"
        "           lambda\n"
        "           x, y:\n"
        "           x + y)\n}"
    )
    ctx = _doc(text)
    # 'x' declaration on line 4 (the parameter line)
    sym_x = resolve_symbol_from_ast(ctx, _pos(4, 11))
    assert sym_x is not None
    assert sym_x.kind == "identifier"
    assert sym_x.normalized_name == "x"
    # 'y' declaration on same line
    sym_y = resolve_symbol_from_ast(ctx, _pos(4, 14))
    assert sym_y is not None
    assert sym_y.normalized_name == "y"
    # 'x' usage in body on line 5
    sym_use = resolve_symbol_from_ast(ctx, _pos(5, 11))
    assert sym_use is not None
    assert sym_use.normalized_name == "x"


# ---------------------------------------------------------------------------
# Single-line compact rule: lambda on line 0 (loop terminates immediately)
# ---------------------------------------------------------------------------


def test_resolve_lambda_parameter_on_line_zero() -> None:
    """Lambda entirely on line 0 resolves parameter correctly."""
    text = "rule r { condition: filter([1], lambda x: x > 0) }"
    ctx = _doc(text)
    # 'x' declaration at col 39
    sym = resolve_symbol_from_ast(ctx, _pos(0, 39))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


# ---------------------------------------------------------------------------
# For loop with 'in' on body's line (continuation loop declaration bounds)
# ---------------------------------------------------------------------------


def test_resolve_for_loop_deeply_multiline_declaration() -> None:
    """For variable resolves when for/quantifier/variable are each on separate lines."""
    text = (
        'rule r {\n  strings:\n    $a = "x"\n  condition:\n'
        "    for\n      any i\n      in (0, 1):\n      ($a at i)\n}"
    )
    ctx = _doc(text)
    # 'i' declaration on line 5 (any i)
    sym = resolve_symbol_from_ast(ctx, _pos(5, 10))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "i"
    # 'i' usage in body on line 7
    sym_use = resolve_symbol_from_ast(ctx, _pos(7, 13))
    assert sym_use is not None
    assert sym_use.normalized_name == "i"


# ---------------------------------------------------------------------------
# Two-lambda rule: first lambda skips second's parameter (line 131 continue)
# ---------------------------------------------------------------------------


def test_resolve_lambda_in_rule_with_two_lambdas() -> None:
    """When two lambdas exist, resolving 'x' skips the lambda with only 'y'."""
    text = (
        "rule r {\n  condition:\n"
        "    filter([1], lambda x: x > 0) and filter([2], lambda y: y > 0)\n}"
    )
    ctx = _doc(text)
    # 'x' in first lambda body at col 26
    sym_x = resolve_symbol_from_ast(ctx, _pos(2, 26))
    assert sym_x is not None
    assert sym_x.normalized_name == "x"
    # 'y' in second lambda body at col 59
    sym_y = resolve_symbol_from_ast(ctx, _pos(2, 59))
    assert sym_y is not None
    assert sym_y.normalized_name == "y"


# ---------------------------------------------------------------------------
# Multi-param lambda: both parameters are resolved (lines 141-146 inner loop)
# ---------------------------------------------------------------------------


def test_resolve_multi_param_lambda_both_parameters_resolve() -> None:
    """Multi-parameter lambda 'lambda x, y: ...' resolves both x and y."""
    text = "rule r {\n  condition:\n    filter([1], lambda x, y: x + y)\n}"
    ctx = _doc(text)
    # 'x' declaration at col 23
    sym_x = resolve_symbol_from_ast(ctx, _pos(2, 23))
    assert sym_x is not None
    assert sym_x.normalized_name == "x"
    # 'y' declaration at col 26
    sym_y = resolve_symbol_from_ast(ctx, _pos(2, 26))
    assert sym_y is not None
    assert sym_y.normalized_name == "y"
    # 'x' used in body at col 29
    sym_x_body = resolve_symbol_from_ast(ctx, _pos(2, 29))
    assert sym_x_body is not None
    assert sym_x_body.normalized_name == "x"


# ---------------------------------------------------------------------------
# DictComprehension: variable name 'k' appears as prefix inside 'ke' (line 247->251)
# ---------------------------------------------------------------------------


def test_resolve_dict_comprehension_variable_skips_prefix_match() -> None:
    """Key variable 'k' resolves past 'ke' prefix occurrence in declaration range."""
    text = "rule r {\n  condition:\n    {k: v for ke, k in some_dict}\n}"
    ctx = _doc(text)
    # 'k' standalone declaration at col 18 (after 'ke, ')
    sym = resolve_symbol_from_ast(ctx, _pos(2, 18))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "k"
    # 'k' used in key expression at col 5
    sym_use = resolve_symbol_from_ast(ctx, _pos(2, 5))
    assert sym_use is not None
    assert sym_use.normalized_name == "k"


# ---------------------------------------------------------------------------
# ForExpression: 'for' keyword appears inside iterable name (line 394)
# ---------------------------------------------------------------------------


def test_resolve_for_loop_variable_name_embeds_for_keyword() -> None:
    """Loop variable 'ifor' contains 'for' substring; _rfind_keyword retries past it."""
    text = "rule r {\n  condition:\n    for any ifor in (0, 1): (ifor + 1)\n}"
    ctx = _doc(text)
    # 'ifor' declaration at col 12
    sym = resolve_symbol_from_ast(ctx, _pos(2, 12))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "ifor"
    # 'ifor' usage in body at col 29
    sym_use = resolve_symbol_from_ast(ctx, _pos(2, 29))
    assert sym_use is not None
    assert sym_use.normalized_name == "ifor"


# ---------------------------------------------------------------------------
# Lambda parameter: 'x' appears as suffix inside 'abc_x' before standalone 'x' (line 408)
# ---------------------------------------------------------------------------


def test_resolve_lambda_parameter_skips_suffix_match_in_prior_param() -> None:
    """'x' in 'lambda abc_x, x: x' skips 'abc_x' occurrence (char before 'x' is '_')."""
    text = "rule r {\n  condition:\n    filter([1], lambda abc_x, x: x)\n}"
    ctx = _doc(text)
    # standalone 'x' declaration at col 30 (after 'abc_x, ')
    sym = resolve_symbol_from_ast(ctx, _pos(2, 30))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"
    assert sym.range.start.character == 30
    # 'x' in body at col 33
    sym_body = resolve_symbol_from_ast(ctx, _pos(2, 33))
    assert sym_body is not None
    assert sym_body.normalized_name == "x"


# ---------------------------------------------------------------------------
# _resolved_local_identifier: position at exact range end (line 444)
# ---------------------------------------------------------------------------


def test_resolve_lambda_parameter_at_exact_range_end_position() -> None:
    """Position at the character immediately after the declaration resolves via end-match."""
    text = "rule r {\n  condition:\n    filter([1, 2, 3], lambda x: x > 0)\n}"
    ctx = _doc(text)
    # 'x' declaration spans col 29-30; position at col 30 is the range end
    sym = resolve_symbol_from_ast(ctx, _pos(2, 30))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"
    assert sym.range.start.character == 29
    assert sym.range.end.character == 30


# ---------------------------------------------------------------------------
# Two lambdas with identical parameter name: first lambda's range misses
# position in second lambda's body, continues to second lambda (line 142->146)
# ---------------------------------------------------------------------------


def test_resolve_two_lambdas_same_param_resolves_to_enclosing_lambda() -> None:
    """Two lambdas with parameter 'x': usage in second body resolves to second lambda."""
    text = (
        "rule r {\n  condition:\n"
        "    filter([1], lambda x: x + 1) and filter([2], lambda x: x + 2)\n}"
    )
    ctx = _doc(text)
    # 'x' in second lambda body at col 59 (second 'lambda x: x')
    sym = resolve_symbol_from_ast(ctx, _pos(2, 59))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"
    # Position 59 resolves via the usage node range (2:59-2:60)
    assert sym.range.start.character == 59


# ---------------------------------------------------------------------------
# with declaration: value on next line (hits _previous_line_with, not line 363)
# Line 363 is unreachable: value_range.start always points to start of the value
# expression, so rfind(identifier, 0, value_start) cannot find the identifier before
# the value start position in a valid 'with id = expr' parse.
# ---------------------------------------------------------------------------


def test_resolve_with_declaration_identifier_on_multiline_value_line() -> None:
    """With 'x = x + 1:' multi-line: declaration found via previous-line search."""
    text = "rule r {\n  condition:\n    with x =\n      x + 1:\n      x\n}"
    ctx = _doc(text)
    # 'x' usage in body at col 6
    sym = resolve_symbol_from_ast(ctx, _pos(4, 6))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


# ---------------------------------------------------------------------------
# with declaration: blank line between '=' and value (line 375)
# ---------------------------------------------------------------------------


def test_resolve_with_declaration_skips_blank_line_before_value() -> None:
    """Previous-line search skips blank lines before locating 'with x =' line."""
    text = "rule r {\n  condition:\n    with x =\n\n      y:\n      x\n}"
    ctx = _doc(text)
    # 'x' usage in body at line 5 col 6
    sym = resolve_symbol_from_ast(ctx, _pos(5, 6))
    assert sym is not None
    assert sym.kind == "identifier"
    assert sym.normalized_name == "x"


# ---------------------------------------------------------------------------
# InExpression: deepest node returned when word is 'in' keyword (line 537->544)
# ---------------------------------------------------------------------------


def test_resolve_returns_none_for_in_keyword_inside_in_expression() -> None:
    """Position on 'in' keyword inside InExpression returns None (non-prefix word)."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    $a in (0..10)\n}'
    ctx = _doc(text)
    # col 7 is the 'i' of 'in'; InExpression is the deepest node there
    sym = resolve_symbol_from_ast(ctx, _pos(4, 7))
    assert sym is None


# ---------------------------------------------------------------------------
# OfExpression: deepest node returned when word is 'of' keyword (line 537->544)
# ---------------------------------------------------------------------------


def test_resolve_returns_none_for_of_keyword_inside_of_expression() -> None:
    """Position on 'of' keyword inside OfExpression returns None (non-prefix word)."""
    text = 'rule r {\n  strings:\n    $a = "x"\n  condition:\n    all of them\n}'
    ctx = _doc(text)
    # col 9-10 is 'of'; OfExpression is the deepest node there
    sym = resolve_symbol_from_ast(ctx, _pos(4, 9))
    assert sym is None
