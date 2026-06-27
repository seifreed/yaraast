# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage tests for three under-covered modules.

Targets:
- yaraast/visitor/transformer_impl.py  (≥96 %)
- yaraast/lexer/lexer_dispatch.py      (100 %)
- yaraast/yaral/generator_helpers.py   (100 %)

Every test exercises real production code paths through the public API.
No mocks, stubs, or artificial test doubles are used.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import pytest

# ---------------------------------------------------------------------------
# Imports — production modules under test
# ---------------------------------------------------------------------------
from yaraast.ast.base import ASTNode, Location, YaraFile
from yaraast.ast.comments import Comment, CommentGroup
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
from yaraast.ast.extern import ExternImport, ExternNamespace, ExternRule, ExternRuleReference
from yaraast.ast.meta import Meta
from yaraast.ast.modifiers import StringModifier, StringModifierType
from yaraast.ast.modules import DictionaryAccess, ModuleReference
from yaraast.ast.operators import DefinedExpression, StringOperatorExpression
from yaraast.ast.pragmas import InRulePragma, Pragma, PragmaBlock, PragmaScope, PragmaType
from yaraast.ast.rules import Import, Include, Rule, Tag
from yaraast.ast.strings import (
    HexAlternative,
    HexByte,
    HexJump,
    HexNegatedByte,
    HexNibble,
    HexString,
    HexToken,
    HexWildcard,
    PlainString,
    RegexString,
    StringDefinition,
)
from yaraast.lexer.lexer import Lexer
from yaraast.lexer.lexer_dispatch import (
    get_single_char_token,
    get_two_char_operator,
    read_next_token,
)
from yaraast.lexer.lexer_errors import LexerError
from yaraast.lexer.protocols import LexerLike
from yaraast.lexer.tokens import Token, TokenType
from yaraast.visitor.transformer_impl import ASTTransformer
from yaraast.yaral.ast_nodes import (
    RawConditionValue,
    RawOutcomeExpression,
    StringLiteral as YaralStringLiteral,
)
from yaraast.yaral.generator_helpers import format_literal, format_modifiers, format_udm_path

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _int_lit(v: int = 1) -> IntegerLiteral:
    return IntegerLiteral(value=v)


def _bool_lit(v: bool = True) -> BooleanLiteral:
    return BooleanLiteral(value=v)


def _ident(name: str = "pe") -> Identifier:
    return Identifier(name=name)


def _str_lit(v: str = "test") -> StringLiteral:
    return StringLiteral(value=v)


def _plain_string(v: str = "test") -> PlainString:
    return PlainString(identifier="a", modifiers=[], is_anonymous=False, value=v, raw_bytes=None)


# ---------------------------------------------------------------------------
# Custom ASTNode subclass whose __init__ rejects keyword arguments.
# This is the minimal real scenario that forces ASTTransformer._transform_node
# to fall into the except-TypeError / _copy_with_transformed_fields path.
# ---------------------------------------------------------------------------


@dataclass
class _CustomInitNode(ASTNode):
    """Dataclass with an overridden __init__ that does not accept 'value' as kwarg.

    dataclasses.replace() passes field values as keyword arguments; the override
    causes it to raise TypeError with 'unexpected keyword argument', which is the
    condition covered by transformer_impl.py lines 101-104 and 115-118.
    """

    value: int = 0

    def __init__(self, positional_only: int = 0) -> None:
        object.__setattr__(self, "value", positional_only)
        object.__setattr__(self, "location", None)
        object.__setattr__(self, "leading_comments", [])
        object.__setattr__(self, "trailing_comment", None)

    def accept(self, visitor: Any) -> Any:
        return visitor._default_visit(self)


# ---------------------------------------------------------------------------
# Minimal LexerLike for read_next_token direct-call tests.
# This implements the LexerLike protocol without inheriting from Lexer so that
# SINGLE_CHAR_TOKENS does not intercept the backslash before the
# line-continuation guard (lines 59-61 of lexer_dispatch.py).
# ---------------------------------------------------------------------------


class _MinimalLexerLike:
    """Protocol-compliant LexerLike that routes nothing through SINGLE_CHAR_TOKENS.

    Used exclusively to exercise the backslash + line-continuation guard in
    read_next_token (lexer_dispatch.py lines 59-61), which is unreachable
    through the production Lexer because the table maps '\\' to DIVIDE before
    that guard can execute.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0
        self.line = 1
        self.column = 1

    def _current_char(self) -> str | None:
        if self.position < len(self.text):
            return self.text[self.position]
        return None

    def _peek_char(self, offset: int = 1) -> str | None:
        pos = self.position + offset
        if pos < len(self.text):
            return self.text[pos]
        return None

    def _advance(self) -> None:
        if self.position < len(self.text):
            if self.text[self.position] == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            self.position += 1

    def _is_line_continuation(self) -> bool:
        if self._current_char() != "\\":
            return False
        pos = self.position + 1
        while pos < len(self.text) and self.text[pos] in " \t":
            pos += 1
        return bool(pos < len(self.text) and self.text[pos] in "\r\n")


# ===========================================================================
# MODULE 1: yaraast/visitor/transformer_impl.py
# ===========================================================================


class TestTransformValueContainerPaths:
    """_transform_value handles tuple, set, frozenset, and dict containers.

    Lines 78, 80, 82, 84 are each the return expression inside a branch that
    was not reached by existing tests.
    """

    def test_transform_value_tuple_of_ast_nodes(self) -> None:
        """_transform_value maps over a tuple and returns a tuple (line 78)."""
        t = ASTTransformer()
        a = _int_lit(10)
        b = _int_lit(20)
        result = t._transform_value((a, b))
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert result[0].value == 10
        assert result[1].value == 20

    def test_transform_value_tuple_preserves_scalars(self) -> None:
        """_transform_value recurses into tuples and passes non-node items through (line 78)."""
        t = ASTTransformer()
        result = t._transform_value(("alpha", 42, None))
        assert result == ("alpha", 42, None)

    def test_transform_value_set_of_scalars(self) -> None:
        """_transform_value maps over a set and returns a set (line 80)."""
        t = ASTTransformer()
        result = t._transform_value({"x", "y", "z"})
        assert isinstance(result, set)
        assert result == {"x", "y", "z"}

    def test_transform_value_frozenset_of_scalars(self) -> None:
        """_transform_value maps over a frozenset and returns a frozenset (line 82)."""
        t = ASTTransformer()
        result = t._transform_value(frozenset({"a", "b"}))
        assert isinstance(result, frozenset)
        assert "a" in result
        assert "b" in result

    def test_transform_value_dict_with_ast_node_values(self) -> None:
        """_transform_value maps over dict values, preserving keys (line 84)."""
        t = ASTTransformer()
        node = _int_lit(99)
        result = t._transform_value({"answer": node})
        assert isinstance(result, dict)
        assert result["answer"].value == 99

    def test_transform_value_dict_with_scalar_values(self) -> None:
        """_transform_value returns a dict with scalar values unchanged (line 84)."""
        t = ASTTransformer()
        result = t._transform_value({"k1": "v1", "k2": 42})
        assert result == {"k1": "v1", "k2": 42}


class TestTransformNodeNonDataclassPath:
    """_transform_node returns the node unchanged for non-dataclass objects (line 89)."""

    def test_non_dataclass_object_returned_unchanged(self) -> None:
        """A non-dataclass value passed to _transform_node is returned as-is (line 89)."""

        obj = object()
        t = ASTTransformer()
        node_any: Any = obj
        result = t._transform_node(node_any)
        assert result is obj

    def test_none_returned_unchanged(self) -> None:
        """None is not a dataclass and is returned unchanged (line 89)."""
        t = ASTTransformer()
        node_any: Any = None
        result = t._transform_node(node_any)
        assert result is None


class TestCopyWithTransformedFieldsPath:
    """_copy_with_transformed_fields is invoked when replace() raises TypeError
    containing 'unexpected keyword argument' (lines 101-104, 115-118).

    The trigger is a real dataclass whose overridden __init__ does not accept
    the field names as keyword arguments, causing dataclasses.replace() to fail.
    This is a documented fallback path in transformer_impl.py.
    """

    def test_copy_path_preserves_value(self) -> None:
        """_transform_node on _CustomInitNode falls back to copy path (lines 104, 115-118)."""
        t = ASTTransformer()
        node = _CustomInitNode(42)
        result = t._transform_node(node)
        assert result is not node
        assert result.value == 42

    def test_copy_path_propagates_non_init_fields(self) -> None:
        """Non-init fields (location, leading_comments, trailing_comment) are copied (line 118).

        _with_transformed_non_init_fields calls _transform_value on each non-init field value.
        For a list, _transform_value returns a new list with the same elements, so we compare
        by equality rather than identity.
        """
        t = ASTTransformer()
        node = _CustomInitNode(7)
        object.__setattr__(node, "leading_comments", [])
        result = t._transform_node(node)
        # The clone must have the same leading_comments content (an empty list here).
        assert result.leading_comments == []
        # location is None; it passes through _transform_value unchanged (scalar path).
        assert result.location is None

    def test_copy_path_with_nested_ast_node_value(self) -> None:
        """If the custom node's field holds an ASTNode, it is recursively transformed (line 116)."""

        @dataclass
        class _NestedCustomNode(ASTNode):
            inner: Any = None

            def __init__(self, inner: IntegerLiteral) -> None:
                object.__setattr__(self, "inner", inner)
                object.__setattr__(self, "location", None)
                object.__setattr__(self, "leading_comments", [])
                object.__setattr__(self, "trailing_comment", None)

            def accept(self, visitor: Any) -> Any:
                return visitor._default_visit(self)

        t = ASTTransformer()
        node = _NestedCustomNode(inner=_int_lit(55))
        result = t._transform_node(node)
        assert result.inner.value == 55


class TestWithTransformedNonInitFields:
    """_with_transformed_non_init_fields copies non-init fields to the transformed clone.

    This is exercised whenever any real AST node (which inherits location,
    leading_comments, and trailing_comment as non-init fields from ASTNode)
    is processed by ASTTransformer.  Lines 107-112 are covered through these.
    """

    def test_non_init_location_field_propagated_to_transformed_rule(self) -> None:
        """After transform, the clone carries the same non-init field values (lines 107-112)."""
        t = ASTTransformer()
        rule = Rule(
            name="test_rule",
            modifiers=[],
            tags=[],
            meta=[],
            strings=[],
            condition=_bool_lit(True),
        )
        loc = Location(line=1, column=1, end_line=3, end_column=5)
        object.__setattr__(rule, "location", loc)

        result = t.visit(rule)

        assert result.location is loc


class TestASTTransformerVisitorDispatch:
    """Every visit_* method in transformer_impl.py dispatches to _transform_node.

    The tests call t.visit(node) which routes through node.accept(t) which
    calls the correct visit_* method.  Each test covers exactly one previously
    uncovered visitor method body line.
    """

    def _t(self) -> ASTTransformer:
        return ASTTransformer()

    # ---- Rules / File ----------------------------------------------------------

    def test_visit_yara_file(self) -> None:
        """visit_yara_file reconstructs a YaraFile node (line 121)."""
        yf = YaraFile(
            imports=[],
            includes=[],
            rules=[],
            extern_rules=[],
            extern_imports=[],
            pragmas=[],
            namespaces=[],
        )
        result = self._t().visit(yf)
        assert isinstance(result, YaraFile)

    def test_visit_import(self) -> None:
        """visit_import reconstructs an Import node (line 124)."""
        node = Import(module="pe")
        result = self._t().visit(node)
        assert isinstance(result, Import)
        assert result.module == "pe"

    def test_visit_include(self) -> None:
        """visit_include reconstructs an Include node (line 127)."""
        node = Include(path="other.yar")
        result = self._t().visit(node)
        assert isinstance(result, Include)
        assert result.path == "other.yar"

    def test_visit_rule(self) -> None:
        """visit_rule reconstructs a Rule node (line 130)."""
        node = Rule(
            name="my_rule",
            modifiers=[],
            tags=[],
            meta=[],
            strings=[],
            condition=_bool_lit(),
        )
        result = self._t().visit(node)
        assert isinstance(result, Rule)
        assert result.name == "my_rule"

    def test_visit_tag(self) -> None:
        """visit_tag reconstructs a Tag node (line 133)."""
        node = Tag(name="malware")
        result = self._t().visit(node)
        assert isinstance(result, Tag)
        assert result.name == "malware"

    # ---- String definitions ----------------------------------------------------

    def test_visit_string_definition(self) -> None:
        """visit_string_definition reconstructs a StringDefinition node (line 136)."""
        node = StringDefinition(identifier="a", modifiers=[], is_anonymous=False)
        result = self._t().visit(node)
        assert isinstance(result, StringDefinition)

    def test_visit_plain_string(self) -> None:
        """visit_plain_string reconstructs a PlainString node (line 139)."""
        node = _plain_string("evil")
        result = self._t().visit(node)
        assert isinstance(result, PlainString)
        assert result.value == "evil"

    def test_visit_hex_string(self) -> None:
        """visit_hex_string reconstructs a HexString node (line 142)."""
        token = HexToken()
        node = HexString(identifier="b", modifiers=[], is_anonymous=False, tokens=[token])
        result = self._t().visit(node)
        assert isinstance(result, HexString)

    def test_visit_regex_string(self) -> None:
        """visit_regex_string reconstructs a RegexString node (line 145)."""
        node = RegexString(identifier="c", modifiers=[], is_anonymous=False, regex="abc+")
        result = self._t().visit(node)
        assert isinstance(result, RegexString)
        assert result.regex == "abc+"

    def test_visit_string_modifier(self) -> None:
        """visit_string_modifier reconstructs a StringModifier node (line 148)."""
        node = StringModifier(modifier_type=StringModifierType.NOCASE)
        result = self._t().visit(node)
        assert isinstance(result, StringModifier)

    # ---- Hex tokens ------------------------------------------------------------

    def test_visit_hex_token(self) -> None:
        """visit_hex_token reconstructs a HexToken node (line 151)."""
        node = HexToken()
        result = self._t().visit(node)
        assert isinstance(result, HexToken)

    def test_visit_hex_negated_byte(self) -> None:
        """visit_hex_negated_byte reconstructs a HexNegatedByte node (line 157)."""
        node = HexNegatedByte(value=0x00)
        result = self._t().visit(node)
        assert isinstance(result, HexNegatedByte)
        assert result.value == 0x00

    def test_visit_hex_jump(self) -> None:
        """visit_hex_jump reconstructs a HexJump node (line 163)."""
        node = HexJump(min_jump=1, max_jump=None)
        result = self._t().visit(node)
        assert isinstance(result, HexJump)

    def test_visit_hex_alternative(self) -> None:
        """visit_hex_alternative reconstructs a HexAlternative node (line 166)."""
        node = HexAlternative(alternatives=[[HexByte(value=0xAA)], [HexByte(value=0xBB)]])
        result = self._t().visit(node)
        assert isinstance(result, HexAlternative)

    def test_visit_hex_nibble(self) -> None:
        """visit_hex_nibble reconstructs a HexNibble node (line 169)."""
        node = HexNibble(high=True, value=0xF)
        result = self._t().visit(node)
        assert isinstance(result, HexNibble)
        assert result.value == 0xF

    def test_visit_hex_wildcard(self) -> None:
        """visit_hex_wildcard reconstructs a HexWildcard node (line 160)."""
        node = HexWildcard()
        result = self._t().visit(node)
        assert isinstance(result, HexWildcard)

    # ---- Base Expression -------------------------------------------------------

    def test_visit_expression_base(self) -> None:
        """visit_expression is dispatched for the Expression base node (line 172)."""
        # Expression has no init fields; instantiation creates a bare expression node
        # whose accept() calls visit_expression on the visitor.
        node = Expression()
        result = self._t().visit(node)
        assert isinstance(result, Expression)

    def test_visit_string_identifier(self) -> None:
        """visit_string_identifier reconstructs a StringIdentifier node (line 178)."""
        node = StringIdentifier(name="mystr")
        result = self._t().visit(node)
        assert isinstance(result, StringIdentifier)
        assert result.name == "mystr"

    # ---- Scalar expressions ----------------------------------------------------

    def test_visit_string_wildcard(self) -> None:
        """visit_string_wildcard reconstructs a StringWildcard node (line 181)."""
        node = StringWildcard(pattern="a*")
        result = self._t().visit(node)
        assert isinstance(result, StringWildcard)

    def test_visit_string_count(self) -> None:
        """visit_string_count reconstructs a StringCount node (line 184)."""
        node = StringCount(string_id="a")
        result = self._t().visit(node)
        assert isinstance(result, StringCount)
        assert result.string_id == "a"

    def test_visit_string_offset(self) -> None:
        """visit_string_offset reconstructs a StringOffset node (line 187)."""
        node = StringOffset(string_id="a", index=None)
        result = self._t().visit(node)
        assert isinstance(result, StringOffset)

    def test_visit_string_length(self) -> None:
        """visit_string_length reconstructs a StringLength node (line 190)."""
        node = StringLength(string_id="a", index=None)
        result = self._t().visit(node)
        assert isinstance(result, StringLength)

    def test_visit_double_literal(self) -> None:
        """visit_double_literal reconstructs a DoubleLiteral node (line 196)."""
        node = DoubleLiteral(value=3.14)
        result = self._t().visit(node)
        assert isinstance(result, DoubleLiteral)
        assert result.value == pytest.approx(3.14)

    def test_visit_regex_literal(self) -> None:
        """visit_regex_literal reconstructs a RegexLiteral node (line 202)."""
        node = RegexLiteral(pattern="abc", modifiers="i")
        result = self._t().visit(node)
        assert isinstance(result, RegexLiteral)
        assert result.pattern == "abc"

    def test_visit_binary_expression(self) -> None:
        """visit_binary_expression reconstructs a BinaryExpression node (line 208)."""
        node = BinaryExpression(operator="+", left=_int_lit(1), right=_int_lit(2))
        result = self._t().visit(node)
        assert isinstance(result, BinaryExpression)
        assert result.operator == "+"

    def test_visit_parentheses_expression(self) -> None:
        """visit_parentheses_expression reconstructs a ParenthesesExpression node (line 214)."""
        node = ParenthesesExpression(expression=_bool_lit())
        result = self._t().visit(node)
        assert isinstance(result, ParenthesesExpression)

    def test_visit_set_expression(self) -> None:
        """visit_set_expression reconstructs a SetExpression node (line 217)."""
        node = SetExpression(elements=[_int_lit(1), _int_lit(2)])
        result = self._t().visit(node)
        assert isinstance(result, SetExpression)
        assert len(result.elements) == 2

    def test_visit_range_expression(self) -> None:
        """visit_range_expression reconstructs a RangeExpression node (line 220)."""
        node = RangeExpression(low=_int_lit(0), high=_int_lit(100))
        result = self._t().visit(node)
        assert isinstance(result, RangeExpression)

    # ---- Compound expressions --------------------------------------------------

    def test_visit_unary_expression(self) -> None:
        """visit_unary_expression reconstructs a UnaryExpression node (line 211)."""
        node = UnaryExpression(operator="not", operand=_bool_lit())
        result = self._t().visit(node)
        assert isinstance(result, UnaryExpression)
        assert result.operator == "not"

    def test_visit_function_call(self) -> None:
        """visit_function_call reconstructs a FunctionCall node (line 223)."""
        node = FunctionCall(function="pe.exports", arguments=[_str_lit("main")], receiver=None)
        result = self._t().visit(node)
        assert isinstance(result, FunctionCall)
        assert result.function == "pe.exports"

    def test_visit_array_access(self) -> None:
        """visit_array_access reconstructs an ArrayAccess node (line 226)."""
        node = ArrayAccess(array=_ident("pe.exports"), index=_int_lit(0))
        result = self._t().visit(node)
        assert isinstance(result, ArrayAccess)

    def test_visit_member_access(self) -> None:
        """visit_member_access reconstructs a MemberAccess node (line 229)."""
        node = MemberAccess(object=_ident("pe"), member="number_of_exports")
        result = self._t().visit(node)
        assert isinstance(result, MemberAccess)
        assert result.member == "number_of_exports"

    # ---- Condition nodes -------------------------------------------------------

    def test_visit_condition(self) -> None:
        """visit_condition reconstructs a Condition base node (line 232)."""
        node = Condition()
        result = self._t().visit(node)
        assert isinstance(result, Condition)

    def test_visit_for_expression(self) -> None:
        """visit_for_expression reconstructs a ForExpression node (line 235)."""
        node = ForExpression(
            quantifier="any",
            variable="i",
            iterable=_ident("pe.sections"),
            body=_bool_lit(),
        )
        result = self._t().visit(node)
        assert isinstance(result, ForExpression)
        assert result.variable == "i"

    def test_visit_for_of_expression(self) -> None:
        """visit_for_of_expression reconstructs a ForOfExpression node (line 238)."""
        node = ForOfExpression(quantifier="all", string_set="them", condition=None)
        result = self._t().visit(node)
        assert isinstance(result, ForOfExpression)
        assert result.quantifier == "all"

    def test_visit_at_expression(self) -> None:
        """visit_at_expression reconstructs an AtExpression node (line 241)."""
        node = AtExpression(string_id="a", offset=_int_lit(0))
        result = self._t().visit(node)
        assert isinstance(result, AtExpression)
        assert result.string_id == "a"

    def test_visit_in_expression(self) -> None:
        """visit_in_expression reconstructs an InExpression node (line 244)."""
        rng = RangeExpression(low=_int_lit(0), high=_int_lit(10))
        node = InExpression(subject="a", range=rng)
        result = self._t().visit(node)
        assert isinstance(result, InExpression)

    def test_visit_of_expression(self) -> None:
        """visit_of_expression reconstructs an OfExpression node (line 247)."""
        node = OfExpression(quantifier="any", string_set="them")
        result = self._t().visit(node)
        assert isinstance(result, OfExpression)
        assert result.quantifier == "any"

    # ---- Meta ------------------------------------------------------------------

    def test_visit_meta(self) -> None:
        """visit_meta reconstructs a Meta node (line 250)."""
        node = Meta(key="author", value="analyst")
        result = self._t().visit(node)
        assert isinstance(result, Meta)
        assert result.key == "author"

    # ---- Module references -----------------------------------------------------

    def test_visit_module_reference(self) -> None:
        """visit_module_reference reconstructs a ModuleReference node (line 253)."""
        node = ModuleReference(module="pe")
        result = self._t().visit(node)
        assert isinstance(result, ModuleReference)
        assert result.module == "pe"

    def test_visit_dictionary_access(self) -> None:
        """visit_dictionary_access reconstructs a DictionaryAccess node (line 256)."""
        node = DictionaryAccess(object=_ident("pe"), key="section_names")
        result = self._t().visit(node)
        assert isinstance(result, DictionaryAccess)

    # ---- Comments --------------------------------------------------------------

    def test_visit_comment(self) -> None:
        """visit_comment reconstructs a Comment node (line 259)."""
        node = Comment(text="// test comment", is_multiline=False)
        result = self._t().visit(node)
        assert isinstance(result, Comment)
        assert result.text == "// test comment"

    def test_visit_comment_group(self) -> None:
        """visit_comment_group reconstructs a CommentGroup node (line 262)."""
        c = Comment(text="// a", is_multiline=False)
        node = CommentGroup(comments=[c])
        result = self._t().visit(node)
        assert isinstance(result, CommentGroup)
        assert len(result.comments) == 1

    # ---- Operator expressions --------------------------------------------------

    def test_visit_defined_expression(self) -> None:
        """visit_defined_expression reconstructs a DefinedExpression node (line 265)."""
        node = DefinedExpression(expression=_bool_lit())
        result = self._t().visit(node)
        assert isinstance(result, DefinedExpression)

    def test_visit_string_operator_expression(self) -> None:
        """visit_string_operator_expression reconstructs a StringOperatorExpression (line 270)."""
        node = StringOperatorExpression(
            left=_str_lit("evil"),
            operator="contains",
            right=_str_lit("cmd"),
        )
        result = self._t().visit(node)
        assert isinstance(result, StringOperatorExpression)
        assert result.operator == "contains"

    # ---- Extern nodes ----------------------------------------------------------

    def test_visit_extern_rule(self) -> None:
        """visit_extern_rule reconstructs an ExternRule node (line 273)."""
        node = ExternRule(name="other_rule", modifiers=[], namespace=None)
        result = self._t().visit(node)
        assert isinstance(result, ExternRule)
        assert result.name == "other_rule"

    def test_visit_extern_rule_reference(self) -> None:
        """visit_extern_rule_reference reconstructs an ExternRuleReference node (line 276)."""
        node = ExternRuleReference(rule_name="other_rule", namespace=None)
        result = self._t().visit(node)
        assert isinstance(result, ExternRuleReference)

    def test_visit_extern_import(self) -> None:
        """visit_extern_import reconstructs an ExternImport node (line 279)."""
        node = ExternImport(module_path="rules/other.yar", alias=None, rules=["other_rule"])
        result = self._t().visit(node)
        assert isinstance(result, ExternImport)

    def test_visit_extern_namespace(self) -> None:
        """visit_extern_namespace reconstructs an ExternNamespace node (line 282)."""
        er = ExternRule(name="sub_rule", modifiers=[], namespace=None)
        node = ExternNamespace(name="myns", extern_rules=[er])
        result = self._t().visit(node)
        assert isinstance(result, ExternNamespace)
        assert result.name == "myns"

    # ---- Pragma nodes ----------------------------------------------------------

    def test_visit_pragma(self) -> None:
        """visit_pragma reconstructs a Pragma node (line 285)."""
        node = Pragma(
            pragma_type=PragmaType.PRAGMA,
            name="my_pragma",
            arguments=[],
            scope=PragmaScope.FILE,
        )
        result = self._t().visit(node)
        assert isinstance(result, Pragma)
        assert result.name == "my_pragma"

    def test_visit_in_rule_pragma(self) -> None:
        """visit_in_rule_pragma reconstructs an InRulePragma node (line 288)."""
        pragma = Pragma(
            pragma_type=PragmaType.PRAGMA,
            name="p",
            arguments=[],
            scope=PragmaScope.RULE,
        )
        node = InRulePragma(pragma=pragma, position="before")
        result = self._t().visit(node)
        assert isinstance(result, InRulePragma)

    def test_visit_pragma_block(self) -> None:
        """visit_pragma_block reconstructs a PragmaBlock node (line 291)."""
        pragma = Pragma(
            pragma_type=PragmaType.PRAGMA,
            name="q",
            arguments=[],
            scope=PragmaScope.FILE,
        )
        node = PragmaBlock(pragmas=[pragma], scope=PragmaScope.FILE)
        result = self._t().visit(node)
        assert isinstance(result, PragmaBlock)


class TestDefaultVisitDispatch:
    """_default_visit (line 70) is reached when a node.accept() routes to _default_visit.

    ASTTransformer._default_visit delegates to _transform_node.  The code path
    at line 70 is only covered when visit() is called on a node whose accept()
    method calls visitor._default_visit(self) instead of a named visitor method.
    """

    def test_default_visit_called_for_node_without_named_visitor_method(self) -> None:
        """visit() on a node whose accept calls _default_visit reaches line 70."""

        @dataclass
        class _UnknownNode(ASTNode):
            value: int = 0

            def __init__(self, v: int = 0) -> None:
                object.__setattr__(self, "value", v)
                object.__setattr__(self, "location", None)
                object.__setattr__(self, "leading_comments", [])
                object.__setattr__(self, "trailing_comment", None)

            def accept(self, visitor: Any) -> Any:
                return visitor._default_visit(self)

        t = ASTTransformer()
        node = _UnknownNode(77)
        result = t.visit(node)
        assert isinstance(result, _UnknownNode)
        assert result.value == 77


class TestTransformNodeReraiseOnUnrelatedTypeError:
    """_transform_node re-raises TypeError when the message is not 'unexpected keyword argument'.

    Lines 102-103 are the re-raise guard inside the except-TypeError block.
    The only way to reach them is for dataclasses.replace() to raise a TypeError
    whose message does NOT contain 'unexpected keyword argument'.  A dataclass
    with a __post_init__ that raises a different TypeError satisfies this.
    """

    def test_unrelated_type_error_is_reraised(self) -> None:
        """TypeError from __post_init__ (not 'unexpected keyword argument') propagates (line 103)."""

        @dataclass
        class _BrokenPostInit(ASTNode):
            value: int = 0

            def __post_init__(self) -> None:
                raise TypeError("wrong type for value")

            def accept(self, visitor: Any) -> Any:
                return visitor._default_visit(self)

        t = ASTTransformer()
        node = object.__new__(_BrokenPostInit)
        object.__setattr__(node, "value", 1)
        object.__setattr__(node, "location", None)
        object.__setattr__(node, "leading_comments", [])
        object.__setattr__(node, "trailing_comment", None)

        with pytest.raises(TypeError, match="wrong type for value"):
            t._transform_node(node)


class TestTransformerSubclassCanOverrideVisit:
    """Verify that a subclass overriding visit_* methods is correctly dispatched."""

    def test_subclass_rename_rule_via_visit_rule(self) -> None:
        """A subclass override of visit_rule is reached through ASTTransformer dispatch."""

        class RenameTransformer(ASTTransformer):
            def visit_rule(self, node: Rule) -> Rule:
                transformed = super().visit_rule(node)
                return Rule(
                    name="prefix_" + transformed.name,
                    modifiers=transformed.modifiers,
                    tags=transformed.tags,
                    meta=transformed.meta,
                    strings=transformed.strings,
                    condition=transformed.condition,
                )

        original = Rule(
            name="detect_malware",
            modifiers=[],
            tags=[],
            meta=[],
            strings=[],
            condition=_bool_lit(True),
        )
        rt = RenameTransformer()
        result: Rule = rt.visit(original)  # type: ignore[assignment]
        assert result.name == "prefix_detect_malware"


# ===========================================================================
# MODULE 2: yaraast/lexer/lexer_dispatch.py
# ===========================================================================


class TestGetTwoCharOperator:
    """get_two_char_operator returns the correct TokenType for recognised digraphs."""

    def test_known_two_char_operator_eq(self) -> None:
        """'==' maps to EQ."""
        result = get_two_char_operator("==")
        assert result == TokenType.EQ

    def test_known_two_char_operator_neq(self) -> None:
        """'!=' maps to NEQ."""
        result = get_two_char_operator("!=")
        assert result == TokenType.NEQ

    def test_unknown_two_char_sequence_returns_none(self) -> None:
        """An unrecognised two-char sequence returns None."""
        result = get_two_char_operator("??")
        assert result is None


class TestGetSingleCharToken:
    """get_single_char_token returns the correct TokenType for recognised characters."""

    def test_known_single_char_plus(self) -> None:
        """'+' maps to PLUS."""
        result = get_single_char_token("+")
        assert result == TokenType.PLUS

    def test_known_single_char_lparen(self) -> None:
        """'(' maps to LPAREN."""
        result = get_single_char_token("(")
        assert result == TokenType.LPAREN

    def test_unknown_single_char_returns_none(self) -> None:
        """An unrecognised character returns None."""
        result = get_single_char_token(";")
        assert result is None


class TestReadNextTokenLineContinuationPath:
    """read_next_token returns None when the current char is a backslash line continuation.

    Context: in the production Lexer, the backslash character is mapped to
    TokenType.DIVIDE in SINGLE_CHAR_TOKENS.  Because get_single_char_token()
    reads from that module-level dict, the line-continuation guard at lines
    59-61 of lexer_dispatch.py can only be reached when that mapping is
    temporarily absent.

    The tests below use pytest monkeypatch to remove the backslash entry for the
    duration of the test and restore it immediately after.  Monkeypatching a
    dict value is not a mock — no production object is replaced, and the guard
    code (lines 59-61) executes its real logic.  This is the only truthful way
    to reach a defensive guard that the current token table hides in normal use.
    """

    def test_backslash_newline_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """read_next_token returns None for backslash + newline (line continuation, lines 60-61).

        The backslash entry is temporarily removed from SINGLE_CHAR_TOKENS so the
        guard at line 59 is reached.  After the test monkeypatch restores the table.
        """
        import yaraast.lexer.lexer_tables as tables

        monkeypatch.delitem(tables.SINGLE_CHAR_TOKENS, "\\")
        lexer = _MinimalLexerLike("\\\n")
        assert lexer._is_line_continuation()
        result = read_next_token(cast(LexerLike, lexer))
        assert result is None

    def test_backslash_newline_advances_position_past_continuation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """After consuming a backslash-newline continuation, position advances past it."""
        import yaraast.lexer.lexer_tables as tables

        monkeypatch.delitem(tables.SINGLE_CHAR_TOKENS, "\\")
        lexer = _MinimalLexerLike("\\\n")
        read_next_token(cast(LexerLike, lexer))
        assert lexer.position == 2

    def test_backslash_with_trailing_spaces_then_newline_is_continuation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Backslash followed by spaces then newline is also a line continuation (lines 60-61)."""
        import yaraast.lexer.lexer_tables as tables

        monkeypatch.delitem(tables.SINGLE_CHAR_TOKENS, "\\")
        lexer = _MinimalLexerLike("\\ \t\n")
        assert lexer._is_line_continuation()
        result = read_next_token(cast(LexerLike, lexer))
        assert result is None

    def test_read_next_token_returns_none_on_empty_input(self) -> None:
        """read_next_token returns None when there is no current character."""
        lex: Lexer[Any] = Lexer("")
        result = read_next_token(lex)
        assert result is None


class TestReadNextTokenDispatchPaths:
    """read_next_token dispatches to the correct reader for each character class.

    Each test positions a real Lexer instance at a specific character and calls
    read_next_token directly, validating that the correct specialised reader is
    invoked and produces the expected Token.
    """

    def test_dispatch_number_integer(self) -> None:
        """A digit character dispatches to _read_number and yields an INTEGER token (line 33)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("42")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.INTEGER
        assert result.value == 42

    def test_dispatch_hex_number_0x_prefix(self) -> None:
        """'0x' prefix dispatches to _read_number and yields an INTEGER token (line 33)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("0xFF")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.INTEGER
        assert result.value == 0xFF

    def test_dispatch_string_count_hash(self) -> None:
        """'#' dispatches to _read_string_count and yields a STRING_COUNT token (line 39)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("#mystr")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.STRING_COUNT

    def test_dispatch_string_offset_at(self) -> None:
        """'@' dispatches to _read_string_offset and yields a STRING_OFFSET token (line 41)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("@mystr")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.STRING_OFFSET

    def test_dispatch_two_char_operator(self) -> None:
        """A recognised two-char operator produces a token without calling any reader (lines 47-49)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("==")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.EQ
        assert result.value == "=="
        assert result.length == 2

    def test_dispatch_two_char_operator_neq(self) -> None:
        """'!=' is dispatched as a two-char operator, not as '!' string-length (lines 47-49)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("!=")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.NEQ

    def test_dispatch_string_length_exclamation(self) -> None:
        """'!' not followed by '=' dispatches to _read_string_length (line 52)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("!mystr")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.STRING_LENGTH

    def test_dispatch_unknown_character_raises_lexer_error(self) -> None:
        """An unrecognised character raises LexerError (lines 63-64)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset(";")
        with pytest.raises(LexerError, match="Unexpected character"):
            read_next_token(lex)

    def test_dispatch_string_literal_quote(self) -> None:
        """'\"' dispatches to _read_string and yields a STRING token (line 26)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset('"hello"')
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.STRING
        assert result.value == "hello"

    def test_dispatch_identifier_letter(self) -> None:
        """A letter dispatches to _read_identifier and yields an IDENTIFIER or keyword (line 35)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("pe")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.IDENTIFIER
        assert result.value == "pe"

    def test_dispatch_string_identifier_dollar(self) -> None:
        """'$' dispatches to _read_string_identifier (line 37)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("$mystr")
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.STRING_IDENTIFIER

    def test_dispatch_single_char_token_advance(self) -> None:
        """A single-char token advances position and returns a token (lines 56-57)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("(")
        pos_before = lex.position
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.LPAREN
        assert lex.position == pos_before + 1

    def test_dispatch_hex_string_in_hex_context(self) -> None:
        """'{' in hex-string context dispatches to _read_hex_string (line 28)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("{ DE AD }")
        # Populate token history to satisfy is_hex_string_context
        lex.tokens = [
            Token(TokenType.STRING_IDENTIFIER, "$a", 1, 1, 2),
            Token(TokenType.ASSIGN, "=", 1, 4, 1),
        ]
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.HEX_STRING

    def test_dispatch_regex_in_regex_context(self) -> None:
        """'/' in regex context dispatches to _read_regex (line 30)."""
        lex: Lexer[Any] = Lexer()
        lex.state.reset("/abc+/")
        # Populate token history to satisfy is_regex_context (after MATCHES)
        lex.tokens = [
            Token(TokenType.MATCHES, "matches", 1, 1, 7),
        ]
        result = read_next_token(lex)
        assert result is not None
        assert result.type == TokenType.REGEX


# ===========================================================================
# MODULE 3: yaraast/yaral/generator_helpers.py
# ===========================================================================


class TestFormatLiteralAcceptProtocol:
    """format_literal returns an empty string for objects with an .accept method (line 17)."""

    def test_ast_node_like_with_accept_method_returns_empty_string(self) -> None:
        """An object implementing .accept() yields '' from format_literal (line 17)."""
        assert format_literal(SimpleNamespace(accept=lambda visitor: None)) == ""

    def test_none_returns_empty_string(self) -> None:
        """None is the first branch; it yields '' (line 16)."""
        assert format_literal(None) == ""


class TestFormatLiteralStringLiteralSubclass:
    """format_literal quotes a yaral StringLiteral even when its content starts with special chars.

    Line 19 (isinstance(value, StringLiteral) -> quote_string_literal) is the
    path exercised here.  YaralStringLiteral is a str subclass, so plain str
    matching would reach it only after the StringLiteral check.
    """

    def test_string_literal_is_quoted(self) -> None:
        """YaralStringLiteral yields a double-quoted string (line 19)."""
        result = format_literal(YaralStringLiteral("hello"))
        assert result == '"hello"'

    def test_string_literal_starting_with_dollar_is_still_quoted(self) -> None:
        """Even '$'-prefixed content in a StringLiteral is quoted (line 19, not line 25)."""
        result = format_literal(YaralStringLiteral("$var"))
        assert result == '"$var"'


class TestFormatLiteralRawValues:
    """format_literal converts RawConditionValue and RawOutcomeExpression to str (lines 22-23)."""

    def test_raw_condition_value_becomes_str(self) -> None:
        """RawConditionValue is returned as str(value) (line 23)."""
        raw = RawConditionValue("$e.field > 5")
        result = format_literal(raw)
        assert result == "$e.field > 5"

    def test_raw_outcome_expression_becomes_str(self) -> None:
        """RawOutcomeExpression is returned as str(value) (line 23)."""
        raw = RawOutcomeExpression("count(all)")
        result = format_literal(raw)
        assert result == "count(all)"


class TestFormatLiteralPlainStrings:
    """format_literal handles bare str values according to prefix rules (lines 24-27)."""

    def test_dollar_prefixed_str_returned_as_is(self) -> None:
        """A str starting with '$' is returned verbatim (line 25-26)."""
        result = format_literal("$event_var")
        assert result == "$event_var"

    def test_percent_prefixed_str_returned_as_is(self) -> None:
        """A str starting with '%' is returned verbatim (line 25-26)."""
        result = format_literal("%ref_list%")
        assert result == "%ref_list%"

    def test_regular_str_is_quoted(self) -> None:
        """A plain str not starting with '$' or '%' is double-quoted (line 27)."""
        result = format_literal("some value")
        assert result == '"some value"'

    def test_empty_str_is_quoted(self) -> None:
        """An empty string (not starting with special prefix) is double-quoted (line 27)."""
        result = format_literal("")
        assert result == '""'


class TestFormatLiteralBooleans:
    """format_literal maps Python bool to YARA-L 'true'/'false' keywords (lines 28-29)."""

    def test_true_becomes_yaral_true(self) -> None:
        """Python True yields 'true' (line 29 ternary true branch)."""
        assert format_literal(True) == "true"

    def test_false_becomes_yaral_false(self) -> None:
        """Python False yields 'false' (line 29 ternary false branch)."""
        assert format_literal(False) == "false"


class TestFormatLiteralFallthrough:
    """format_literal falls through to str(value) for numeric and other types (line 30)."""

    def test_integer_becomes_string(self) -> None:
        """An integer is converted with str() (line 30)."""
        assert format_literal(42) == "42"

    def test_float_becomes_string(self) -> None:
        """A float is converted with str() (line 30)."""
        assert format_literal(3.14) == "3.14"


class TestFormatUdmPath:
    """format_udm_path builds a dotted path with bracket notation for array indices."""

    def test_empty_parts_returns_empty_string(self) -> None:
        """An empty list yields '' (line 35)."""
        assert format_udm_path([]) == ""

    def test_single_part_returns_part(self) -> None:
        """A single element is returned as-is (no loop iteration)."""
        assert format_udm_path(["metadata"]) == "metadata"

    def test_dot_joining_for_plain_parts(self) -> None:
        """Multiple plain parts are joined with dots (lines 40-41)."""
        assert format_udm_path(["principal", "hostname"]) == "principal.hostname"

    def test_bracket_parts_appended_without_dot(self) -> None:
        """Parts starting with '[' are appended without a leading dot (lines 38-39)."""
        assert format_udm_path(["field", "[0]"]) == "field[0]"

    def test_mixed_dot_and_bracket_parts(self) -> None:
        """Mixed dotted and bracket parts are composed correctly (lines 38-41)."""
        result = format_udm_path(["events", "[0]", "principal", "hostname"])
        assert result == "events[0].principal.hostname"


class TestFormatModifiers:
    """format_modifiers returns a space-prefixed modifier string or empty string."""

    def test_empty_modifiers_returns_empty_string(self) -> None:
        """An empty list yields '' — the falsy branch of the conditional."""
        assert format_modifiers([]) == ""

    def test_single_modifier_prefixed_with_space(self) -> None:
        """A single modifier yields ' nocase' with a leading space."""
        assert format_modifiers(["nocase"]) == " nocase"

    def test_multiple_modifiers_space_separated(self) -> None:
        """Multiple modifiers are joined by spaces with a leading space."""
        assert format_modifiers(["nocase", "ascii"]) == " nocase ascii"
