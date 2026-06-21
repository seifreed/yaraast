"""Regression tests for yaraast.visitor.base_expressions — BaseVisitorExpressionsMixin.

Drives every uncovered line and branch in the mixin by dispatching real AST nodes
through a concrete BaseVisitor subclass.  No mocks, stubs, or inline suppressions.

Copyright (c) 2026 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import pytest

from yaraast.ast.conditions import (
    AtExpression,
    Condition,
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
    Expression,
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
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.visitor.base import BaseVisitor
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
# Concrete visitor that records which node types were visited and what child
# nodes were traversed into.  All visit_* methods fall through to the mixin
# defaults, except the leaf types used as traversal sentinels.
# ---------------------------------------------------------------------------


class _TrackingVisitor(BaseVisitor[None]):
    """Records every leaf-type visit so tests can assert traversal order."""

    def __init__(self) -> None:
        self.log: list[tuple[str, object]] = []

    def visit_integer_literal(self, node: IntegerLiteral) -> None:
        self.log.append(("int", node.value))

    def visit_double_literal(self, node: DoubleLiteral) -> None:
        self.log.append(("float", node.value))

    def visit_string_literal(self, node: StringLiteral) -> None:
        self.log.append(("str", node.value))

    def visit_regex_literal(self, node: RegexLiteral) -> None:
        self.log.append(("re", node.pattern))

    def visit_boolean_literal(self, node: BooleanLiteral) -> None:
        self.log.append(("bool", node.value))

    def visit_identifier(self, node: Identifier) -> None:
        self.log.append(("id", node.name))

    def visit_string_identifier(self, node: StringIdentifier) -> None:
        self.log.append(("str_id", node.name))

    def visit_string_wildcard(self, node: StringWildcard) -> None:
        self.log.append(("wild", node.pattern))

    def visit_string_count(self, node: StringCount) -> None:
        self.log.append(("count", node.string_id))

    def visit_module_reference(self, node: ModuleReference) -> None:
        self.log.append(("mod", node.module))


# ---------------------------------------------------------------------------
# Leaf-node visit methods (lines 67, 73, 76, 79, 93, 99)
# These methods do nothing but return _noop().  Coverage requires calling them
# through the dispatch chain so the return statement executes.
# ---------------------------------------------------------------------------


def test_visit_expression_returns_none() -> None:
    """Line 67: visit_expression calls _noop and returns None."""
    visitor: _TrackingVisitor = _TrackingVisitor()
    result = visitor.visit_expression(Expression())
    assert result is None


def test_visit_identifier_noop_path() -> None:
    """Line 73: visit_identifier default path returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_identifier(Identifier("x"))
    assert result is None


def test_visit_string_identifier_noop_path() -> None:
    """Line 76: visit_string_identifier default path returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_string_identifier(StringIdentifier("$s"))
    assert result is None


def test_visit_string_wildcard_noop_path() -> None:
    """Line 79: visit_string_wildcard default path returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_string_wildcard(StringWildcard("$*"))
    assert result is None


def test_visit_string_count_noop_path() -> None:
    """Line 79 (visit_string_count): default path returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_string_count(StringCount("#s"))
    assert result is None


def test_visit_double_literal_noop_path() -> None:
    """Line 93: visit_double_literal default path returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_double_literal(DoubleLiteral(3.14))
    assert result is None


def test_visit_regex_literal_noop_path() -> None:
    """Line 99: visit_regex_literal default path returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_regex_literal(RegexLiteral("foo.*"))
    assert result is None


# ---------------------------------------------------------------------------
# StringOffset and StringLength — index traversal (lines 82-83, 86-87)
# ---------------------------------------------------------------------------


def test_visit_string_offset_with_index_traverses_child() -> None:
    """Lines 82-83: visit_string_offset visits node.index when present."""
    visitor = _TrackingVisitor()
    visitor.visit(StringOffset(string_id="#hits", index=IntegerLiteral(2)))
    assert visitor.log == [("int", 2)]


def test_visit_string_offset_without_index_is_noop() -> None:
    """Lines 82-83 (None branch): _visit_if with None returns immediately."""
    visitor = _TrackingVisitor()
    visitor.visit(StringOffset(string_id="#hits"))
    assert visitor.log == []


def test_visit_string_length_with_index_traverses_child() -> None:
    """Lines 86-87: visit_string_length visits node.index when present."""
    visitor = _TrackingVisitor()
    visitor.visit(StringLength(string_id="#len", index=IntegerLiteral(3)))
    assert visitor.log == [("int", 3)]


def test_visit_string_length_without_index_is_noop() -> None:
    """Lines 86-87 (None branch): _visit_if with None returns immediately."""
    visitor = _TrackingVisitor()
    visitor.visit(StringLength(string_id="#len"))
    assert visitor.log == []


# ---------------------------------------------------------------------------
# Binary, unary, parentheses (lines 105-107, 110-111, 116-117)
# ---------------------------------------------------------------------------


def test_visit_binary_expression_traverses_both_operands() -> None:
    """Lines 105-107: visit_binary_expression visits left then right."""
    visitor = _TrackingVisitor()
    visitor.visit(
        BinaryExpression(
            left=IntegerLiteral(10),
            operator=">",
            right=IntegerLiteral(5),
        )
    )
    assert visitor.log == [("int", 10), ("int", 5)]


def test_visit_unary_expression_traverses_operand() -> None:
    """Lines 110-111: visit_unary_expression visits operand."""
    visitor = _TrackingVisitor()
    visitor.visit(UnaryExpression(operator="not", operand=BooleanLiteral(True)))
    assert visitor.log == [("bool", True)]


def test_visit_parentheses_expression_traverses_inner() -> None:
    """Lines 116-117: visit_parentheses_expression visits inner expression."""
    visitor = _TrackingVisitor()
    visitor.visit(ParenthesesExpression(expression=DoubleLiteral(1.5)))
    assert visitor.log == [("float", 1.5)]


# ---------------------------------------------------------------------------
# Set and range (lines 120-121, 124-126)
# ---------------------------------------------------------------------------


def test_visit_set_expression_traverses_all_elements() -> None:
    """Lines 120-121: visit_set_expression visits every element."""
    visitor = _TrackingVisitor()
    visitor.visit(SetExpression(elements=[IntegerLiteral(1), IntegerLiteral(2), IntegerLiteral(3)]))
    assert visitor.log == [("int", 1), ("int", 2), ("int", 3)]


def test_visit_range_expression_traverses_low_and_high() -> None:
    """Lines 124-126: visit_range_expression visits low then high."""
    visitor = _TrackingVisitor()
    visitor.visit(RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(100)))
    assert visitor.log == [("int", 0), ("int", 100)]


# ---------------------------------------------------------------------------
# FunctionCall (lines 129-131)
# ---------------------------------------------------------------------------


def test_visit_function_call_traverses_receiver_and_arguments() -> None:
    """Lines 129-131: visit_function_call visits receiver then each argument."""
    visitor = _TrackingVisitor()
    visitor.visit(
        FunctionCall(
            function="pe.sections",
            arguments=[IntegerLiteral(0), IntegerLiteral(1)],
            receiver=ModuleReference("pe"),
        )
    )
    assert visitor.log == [("mod", "pe"), ("int", 0), ("int", 1)]


def test_visit_function_call_without_receiver_traverses_only_arguments() -> None:
    """Lines 129-131 (None receiver): receiver is skipped, args are visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        FunctionCall(function="math.min", arguments=[IntegerLiteral(3), IntegerLiteral(7)])
    )
    assert visitor.log == [("int", 3), ("int", 7)]


# ---------------------------------------------------------------------------
# ArrayAccess and MemberAccess (lines 134-136, 139-140)
# ---------------------------------------------------------------------------


def test_visit_array_access_traverses_array_and_index() -> None:
    """Lines 134-136: visit_array_access visits array then index."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ArrayAccess(
            array=ModuleReference("pe"),
            index=IntegerLiteral(0),
        )
    )
    assert visitor.log == [("mod", "pe"), ("int", 0)]


def test_visit_member_access_traverses_object() -> None:
    """Lines 139-140: visit_member_access visits object node."""
    visitor = _TrackingVisitor()
    visitor.visit(MemberAccess(object=ModuleReference("math"), member="min"))
    assert visitor.log == [("mod", "math")]


# ---------------------------------------------------------------------------
# Condition (line 143)
# ---------------------------------------------------------------------------


def test_visit_condition_returns_none() -> None:
    """Line 143: visit_condition is a no-op and returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_condition(Condition())
    assert result is None


# ---------------------------------------------------------------------------
# ForExpression — both quantifier branches (lines 146-150)
# ---------------------------------------------------------------------------


def test_visit_for_expression_with_astnode_quantifier_traverses_it() -> None:
    """Lines 146-150 (isinstance True): quantifier is an ASTNode and gets visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ForExpression(
            quantifier=Identifier("limit"),
            variable="i",
            iterable=ModuleReference("pe"),
            body=IntegerLiteral(1),
        )
    )
    # quantifier Identifier, iterable ModuleReference, body IntegerLiteral
    assert visitor.log == [("id", "limit"), ("mod", "pe"), ("int", 1)]


def test_visit_for_expression_with_string_quantifier_skips_it() -> None:
    """Lines 146-150 (isinstance False): string quantifier is not visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ForExpression(
            quantifier="all",
            variable="i",
            iterable=ModuleReference("math"),
            body=IntegerLiteral(0),
        )
    )
    # quantifier is a str — not visited; only iterable and body are
    assert visitor.log == [("mod", "math"), ("int", 0)]


# ---------------------------------------------------------------------------
# ForOfExpression (lines 153-156)
# ---------------------------------------------------------------------------


def test_visit_for_of_expression_traverses_quantifier_string_set_condition() -> None:
    """Lines 153-156: visits quantifier, string_set (via _visit_value), and condition."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ForOfExpression(
            quantifier=Identifier("n"),
            string_set=Identifier("them"),
            condition=BooleanLiteral(True),
        )
    )
    assert visitor.log == [("id", "n"), ("id", "them"), ("bool", True)]


def test_visit_for_of_expression_with_list_string_set() -> None:
    """Lines 153-156: _visit_value handles a list string_set."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ForOfExpression(
            quantifier="any",
            string_set=[StringIdentifier("$a"), StringWildcard("$b*")],
        )
    )
    assert visitor.log == [("str_id", "$a"), ("wild", "$b*")]


def test_visit_for_of_expression_without_condition_skips_it() -> None:
    """Lines 153-156 (None condition): _visit_if returns immediately for None."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ForOfExpression(
            quantifier="all",
            string_set="them",
        )
    )
    # No ASTNode children; log stays empty
    assert visitor.log == []


# ---------------------------------------------------------------------------
# AtExpression — both string_id branches (lines 159-162)
# ---------------------------------------------------------------------------


def test_visit_at_expression_with_astnode_string_id_traverses_it() -> None:
    """Lines 159-162 (isinstance True): string_id is an ASTNode and gets visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        AtExpression(
            string_id=Identifier("dyn_str"),
            offset=IntegerLiteral(100),
        )
    )
    assert visitor.log == [("id", "dyn_str"), ("int", 100)]


def test_visit_at_expression_with_string_id_skips_it() -> None:
    """Lines 159-162 (isinstance False): plain-string string_id is not visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        AtExpression(
            string_id="$literal",
            offset=IntegerLiteral(50),
        )
    )
    assert visitor.log == [("int", 50)]


# ---------------------------------------------------------------------------
# InExpression — both subject branches (lines 165-168)
# ---------------------------------------------------------------------------


def test_visit_in_expression_with_astnode_subject_traverses_it() -> None:
    """Lines 165-168 (isinstance True): subject is ASTNode and gets visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        InExpression(
            subject=Identifier("val"),
            range=RangeExpression(low=IntegerLiteral(0), high=IntegerLiteral(10)),
        )
    )
    assert visitor.log == [("id", "val"), ("int", 0), ("int", 10)]


def test_visit_in_expression_with_string_subject_skips_it() -> None:
    """Lines 165-168 (isinstance False): plain-string subject is not visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        InExpression(
            subject="$s",
            range=RangeExpression(low=IntegerLiteral(1), high=IntegerLiteral(5)),
        )
    )
    assert visitor.log == [("int", 1), ("int", 5)]


# ---------------------------------------------------------------------------
# OfExpression (lines 171-173)
# ---------------------------------------------------------------------------


def test_visit_of_expression_traverses_quantifier_and_string_set() -> None:
    """Lines 171-173: visits quantifier and string_set via _visit_value."""
    visitor = _TrackingVisitor()
    visitor.visit(
        OfExpression(
            quantifier=Identifier("k"),
            string_set=[StringIdentifier("$a"), StringIdentifier("$b")],
        )
    )
    assert visitor.log == [("id", "k"), ("str_id", "$a"), ("str_id", "$b")]


def test_visit_of_expression_with_string_quantifier() -> None:
    """Lines 171-173 (_visit_value non-ASTNode path): string quantifier is skipped."""
    visitor = _TrackingVisitor()
    visitor.visit(OfExpression(quantifier="all", string_set="them"))
    assert visitor.log == []


# ---------------------------------------------------------------------------
# ModuleReference (line 176)
# ---------------------------------------------------------------------------


def test_visit_module_reference_noop_path() -> None:
    """Line 176: visit_module_reference default is a no-op returning None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit_module_reference(ModuleReference("pe"))
    assert result is None


# ---------------------------------------------------------------------------
# DictionaryAccess — both key branches (lines 179-182)
# ---------------------------------------------------------------------------


def test_visit_dictionary_access_with_astnode_key_traverses_it() -> None:
    """Lines 179-182 (isinstance True): key is ASTNode and gets visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        DictionaryAccess(
            object=ModuleReference("pe"),
            key=IntegerLiteral(0),
        )
    )
    assert visitor.log == [("mod", "pe"), ("int", 0)]


def test_visit_dictionary_access_with_string_key_skips_key() -> None:
    """Lines 179-182 (isinstance False): string key is not visited."""
    visitor = _TrackingVisitor()
    visitor.visit(
        DictionaryAccess(
            object=ModuleReference("pe"),
            key="sections",
        )
    )
    assert visitor.log == [("mod", "pe")]


# ---------------------------------------------------------------------------
# DefinedExpression (lines 185-186)
# ---------------------------------------------------------------------------


def test_visit_defined_expression_traverses_inner() -> None:
    """Lines 185-186: visit_defined_expression visits the wrapped expression."""
    visitor = _TrackingVisitor()
    visitor.visit(DefinedExpression(expression=IntegerLiteral(7)))
    assert visitor.log == [("int", 7)]


# ---------------------------------------------------------------------------
# StringOperatorExpression (lines 191-193)
# ---------------------------------------------------------------------------


def test_visit_string_operator_expression_traverses_left_and_right() -> None:
    """Lines 191-193: visit_string_operator_expression visits left then right."""
    visitor = _TrackingVisitor()
    visitor.visit(
        StringOperatorExpression(
            left=StringLiteral("foo"),
            operator="contains",
            right=StringLiteral("bar"),
        )
    )
    assert visitor.log == [("str", "foo"), ("str", "bar")]


# ---------------------------------------------------------------------------
# YARA-X: WithStatement and WithDeclaration (lines 196-198, 201-202)
# ---------------------------------------------------------------------------


def test_visit_with_statement_traverses_declarations_and_body() -> None:
    """Lines 196-198: visit_with_statement visits all declarations then body."""
    visitor = _TrackingVisitor()
    visitor.visit(
        WithStatement(
            declarations=[
                WithDeclaration(identifier="x", value=IntegerLiteral(1)),
                WithDeclaration(identifier="y", value=IntegerLiteral(2)),
            ],
            body=IntegerLiteral(3),
        )
    )
    # Declarations each contain an IntegerLiteral; body is IntegerLiteral(3).
    assert visitor.log == [("int", 1), ("int", 2), ("int", 3)]


def test_visit_with_declaration_traverses_value() -> None:
    """Lines 201-202: visit_with_declaration visits the value expression."""
    visitor = _TrackingVisitor()
    visitor.visit(WithDeclaration(identifier="limit", value=DoubleLiteral(0.5)))
    assert visitor.log == [("float", 0.5)]


# ---------------------------------------------------------------------------
# YARA-X: ArrayComprehension (lines 205-208)
# ---------------------------------------------------------------------------


def test_visit_array_comprehension_traverses_all_fields() -> None:
    """Lines 205-208: visits expression, iterable, and condition."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ArrayComprehension(
            expression=IntegerLiteral(1),
            variable="x",
            iterable=ModuleReference("pe"),
            condition=BooleanLiteral(False),
        )
    )
    assert visitor.log == [("int", 1), ("mod", "pe"), ("bool", False)]


def test_visit_array_comprehension_without_condition_skips_it() -> None:
    """Lines 205-208 (None condition): _visit_if skips None."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ArrayComprehension(
            expression=IntegerLiteral(9),
            variable="i",
            iterable=ModuleReference("math"),
        )
    )
    assert visitor.log == [("int", 9), ("mod", "math")]


# ---------------------------------------------------------------------------
# YARA-X: DictComprehension (lines 211-215)
# ---------------------------------------------------------------------------


def test_visit_dict_comprehension_traverses_all_fields() -> None:
    """Lines 211-215: visits key_expression, value_expression, iterable, condition."""
    visitor = _TrackingVisitor()
    visitor.visit(
        DictComprehension(
            key_expression=StringLiteral("k"),
            value_expression=IntegerLiteral(0),
            key_variable="k",
            iterable=ModuleReference("pe"),
            condition=BooleanLiteral(True),
        )
    )
    assert visitor.log == [("str", "k"), ("int", 0), ("mod", "pe"), ("bool", True)]


def test_visit_dict_comprehension_without_condition_skips_it() -> None:
    """Lines 211-215 (None condition): _visit_if skips None."""
    visitor = _TrackingVisitor()
    visitor.visit(
        DictComprehension(
            key_expression=StringLiteral("key"),
            value_expression=DoubleLiteral(1.0),
            key_variable="k",
            iterable=ModuleReference("math"),
        )
    )
    assert visitor.log == [("str", "key"), ("float", 1.0), ("mod", "math")]


# ---------------------------------------------------------------------------
# YARA-X: TupleIndexing (lines 222-224)
# ---------------------------------------------------------------------------


def test_visit_tuple_indexing_traverses_tuple_and_index() -> None:
    """Lines 222-224: visit_tuple_indexing visits tuple_expr then index."""
    visitor = _TrackingVisitor()
    visitor.visit(
        TupleIndexing(
            tuple_expr=TupleExpression(elements=[IntegerLiteral(10), IntegerLiteral(20)]),
            index=IntegerLiteral(0),
        )
    )
    # TupleExpression _visit_all visits 10 then 20; then index 0
    assert visitor.log == [("int", 10), ("int", 20), ("int", 0)]


# ---------------------------------------------------------------------------
# YARA-X: DictExpression (lines 231-232)
# ---------------------------------------------------------------------------


def test_visit_dict_expression_traverses_all_items() -> None:
    """Lines 231-232: visit_dict_expression visits every DictItem."""
    visitor = _TrackingVisitor()
    visitor.visit(
        DictExpression(
            items=[
                DictItem(key=StringLiteral("a"), value=IntegerLiteral(1)),
                DictItem(key=StringLiteral("b"), value=IntegerLiteral(2)),
            ]
        )
    )
    assert visitor.log == [("str", "a"), ("int", 1), ("str", "b"), ("int", 2)]


# ---------------------------------------------------------------------------
# YARA-X: DictItem (lines 235-237)
# ---------------------------------------------------------------------------


def test_visit_dict_item_traverses_key_and_value() -> None:
    """Lines 235-237: visit_dict_item visits key then value."""
    visitor = _TrackingVisitor()
    visitor.visit(DictItem(key=StringLiteral("field"), value=DoubleLiteral(3.14)))
    assert visitor.log == [("str", "field"), ("float", 3.14)]


# ---------------------------------------------------------------------------
# YARA-X: SliceExpression (lines 240-244)
# ---------------------------------------------------------------------------


def test_visit_slice_expression_with_all_fields_traverses_all() -> None:
    """Lines 240-244: visits target, start, stop, step when all are present."""
    visitor = _TrackingVisitor()
    visitor.visit(
        SliceExpression(
            target=ModuleReference("pe"),
            start=IntegerLiteral(0),
            stop=IntegerLiteral(10),
            step=IntegerLiteral(2),
        )
    )
    assert visitor.log == [("mod", "pe"), ("int", 0), ("int", 10), ("int", 2)]


def test_visit_slice_expression_with_none_fields_skips_them() -> None:
    """Lines 240-244 (None fields): _visit_if skips None start, stop, step."""
    visitor = _TrackingVisitor()
    visitor.visit(
        SliceExpression(
            target=ModuleReference("math"),
        )
    )
    assert visitor.log == [("mod", "math")]


# ---------------------------------------------------------------------------
# YARA-X: LambdaExpression (lines 247-248)
# ---------------------------------------------------------------------------


def test_visit_lambda_expression_traverses_body() -> None:
    """Lines 247-248: visit_lambda_expression visits body."""
    visitor = _TrackingVisitor()
    visitor.visit(LambdaExpression(parameters=["x", "y"], body=IntegerLiteral(42)))
    assert visitor.log == [("int", 42)]


# ---------------------------------------------------------------------------
# YARA-X: SpreadOperator (lines 262-263)
# ---------------------------------------------------------------------------


def test_visit_spread_operator_traverses_expression() -> None:
    """Lines 262-263: visit_spread_operator visits the wrapped expression."""
    visitor = _TrackingVisitor()
    visitor.visit(SpreadOperator(expression=ModuleReference("pe")))
    assert visitor.log == [("mod", "pe")]


# ---------------------------------------------------------------------------
# Cross-cutting: return values from default no-op mixin are always None
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Literal noop paths — must use a passthrough visitor (no overrides) so the
# mixin body executes (lines 90, 96, 102).
# ---------------------------------------------------------------------------


def test_visit_integer_literal_mixin_noop_returns_none() -> None:
    """Line 90: visit_integer_literal mixin body executes and returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit(IntegerLiteral(0))
    assert result is None


def test_visit_string_literal_mixin_noop_returns_none() -> None:
    """Line 96: visit_string_literal mixin body executes and returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit(StringLiteral("hello"))
    assert result is None


def test_visit_boolean_literal_mixin_noop_returns_none() -> None:
    """Line 102: visit_boolean_literal mixin body executes and returns None."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit(BooleanLiteral(False))
    assert result is None


# ---------------------------------------------------------------------------
# YARA-X: ListExpression (lines 227-228)
# ---------------------------------------------------------------------------


def test_visit_list_expression_traverses_all_elements() -> None:
    """Lines 227-228: visit_list_expression visits every element."""
    visitor = _TrackingVisitor()
    visitor.visit(
        ListExpression(elements=[IntegerLiteral(10), IntegerLiteral(20), IntegerLiteral(30)])
    )
    assert visitor.log == [("int", 10), ("int", 20), ("int", 30)]


def test_visit_list_expression_empty_list_produces_no_visits() -> None:
    """Lines 227-228 (empty list): _visit_all iterates nothing."""
    visitor = _TrackingVisitor()
    visitor.visit(ListExpression(elements=[]))
    assert visitor.log == []


# ---------------------------------------------------------------------------
# YARA-X: PatternMatch and MatchCase (lines 251-259)
# ---------------------------------------------------------------------------


def test_visit_pattern_match_traverses_value_cases_and_default() -> None:
    """Lines 251-254: visit_pattern_match visits value, all cases, then default."""
    visitor = _TrackingVisitor()
    visitor.visit(
        PatternMatch(
            value=IntegerLiteral(1),
            cases=[
                MatchCase(pattern=IntegerLiteral(2), result=IntegerLiteral(3)),
                MatchCase(pattern=IntegerLiteral(4), result=IntegerLiteral(5)),
            ],
            default=IntegerLiteral(0),
        )
    )
    # value=1, case1: pattern=2 result=3, case2: pattern=4 result=5, default=0
    assert visitor.log == [
        ("int", 1),
        ("int", 2),
        ("int", 3),
        ("int", 4),
        ("int", 5),
        ("int", 0),
    ]


def test_visit_pattern_match_without_default_skips_it() -> None:
    """Lines 251-254 (None default): _visit_if skips None."""
    visitor = _TrackingVisitor()
    visitor.visit(
        PatternMatch(
            value=IntegerLiteral(7),
            cases=[MatchCase(pattern=IntegerLiteral(8), result=IntegerLiteral(9))],
        )
    )
    assert visitor.log == [("int", 7), ("int", 8), ("int", 9)]


def test_visit_match_case_traverses_pattern_and_result() -> None:
    """Lines 257-259: visit_match_case visits pattern then result."""
    visitor = _TrackingVisitor()
    visitor.visit(MatchCase(pattern=DoubleLiteral(1.1), result=StringLiteral("ok")))
    assert visitor.log == [("float", 1.1), ("str", "ok")]


# ---------------------------------------------------------------------------
# Cross-cutting: return values from default no-op mixin are always None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "node",
    [
        Expression(),
        Identifier("filesize"),
        StringIdentifier("$s"),
        StringWildcard("$*"),
        StringCount("#hits"),
        DoubleLiteral(1.5),
        RegexLiteral("pattern"),
        Condition(),
        ModuleReference("pe"),
    ],
)
def test_all_noop_visit_methods_return_none(node: object) -> None:
    """Every method that only calls _noop() returns None from the default mixin."""

    class _PassthroughVisitor(BaseVisitor[None]):
        pass

    result = _PassthroughVisitor().visit(node)  # type: ignore[arg-type]
    assert result is None
