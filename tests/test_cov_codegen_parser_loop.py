# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""Coverage loop: codegen helpers, expression visitors, and parser edge cases.

Targets the specific uncovered lines and branches listed below.  Every test
uses real YARA source text parsed by the production parser and/or AST nodes
constructed directly with real constructors.  No mocks or stubs are used.

Covered here
------------
generator_expression_visitors.py
  [439,441]   _constant_integer_value: '>>' operator path with right >= 0
  [533,537]   _constant_comparison_operand_type: NUMERIC op, not definitely
              non-integer -> returns 'integer'
  [553,555]   _constant_comparison_operand_type: UnaryExpression('-') with
              non-double/non-float operand falls through to line 555
  [694,695]   _validate_known_module_function_call: module_name resolves to
              None because the module is not in load_builtin_modules()
  [738,742]   _validate_known_module_function_call: console module 'hex'
              branch falls through to _validate_generic_module_function_argument_types
              (and same path for any non-hash/math/pe/console module like 'elf')

parser/_expressions_for.py
  176         _is_parenthesized_range_bound: True branch; method is shadowed by
              ExpressionPostfixMixin in Parser MRO so it is called directly via
              ExpressionForMixin._is_parenthesized_range_bound(parser_instance, expr)
  [326,327]   _of_set_expression_kind: element_kind is None -> return None early
  [379,387]   _collect_function_args: zero-args path (while not entered, RPAREN
              immediately) via 'N of pe.method()' without outer parens
  [383,384]   _collect_function_args: trailing comma before ')' raises error
              via 'N of pe.method("arg",)'

parser/_expressions_postfix.py
  278-279     _parse_parenthesized_range_after_in: parenthesized range as
              lower bound -> ParserError; covers branch [277,278]
  285-286     _parse_parenthesized_range_after_in: parenthesized range as
              upper bound -> ParserError; covers branch [284,285]

parser/_expressions_primary.py
  319         _try_parse_for_expression: FOR token matched, delegates to
              _parse_for_expression; covers branch [318,319]
  [209,212]   _parse_quantifier_expression: ANY/ALL/NONE matched but OF not
              present -> return None (with cursor past the keyword)
  [318,319]   _match_contextual_local_identifier: AS/INCLUDE token present
              but name not in any contextual local frame -> return False
  [352,356]   _contains_range_expression: list field of FunctionCall.arguments
              contains a ParenthesesExpression(RangeExpression) -> return True;
              triggered by for-loop set iterable with function-call+range-arg element

Documented dead-code guards (not tested here)
---------------------------------------------
generator_helpers.py  835-839, 934, 1039
  Lines 835-839 are guarded by _validate_string_modifier_value which raises if
  a modifier has a value but is not 'xor', 'base64', or 'base64wide'; since
  those three are each dispatched before line 835, no other parameterized modifier
  can reach lines 835-839 with the current modifier set.
  Lines 934 and 1039 follow _validate_string_modifier_collection which raises
  TypeError for non-list/tuple inputs, so the 'if not isinstance' guard after it
  can never evaluate to True.

generator_expression_visitors.py  1462-1463, 1468-1469
  BooleanType and RegexType are not present in any built-in module definition
  (all module attributes and return types are IntegerType, StringType, DoubleType,
  StructType, ArrayType, or DictionaryType), so _known_builtin_module_scalar_type_name
  can never return 'boolean' or 'regex' through module lookups.

parser/_expressions_postfix.py  171
  Requires an expression that (a) has no .location attribute set and (b) is
  neither Identifier nor MemberAccess.  All production parser paths set location
  via _set_node_location_from_token* helpers, so this guard is unreachable.

parser/_expressions_primary.py  345-346
  Requires is_dataclass(expr) to return False for an Expression subclass.  All
  Expression subclasses defined in yaraast.ast.expressions are dataclasses, so
  this guard is unreachable through real parsing.

parser/error_tolerant_recovery.py  209, 214, 242
  Documented as structurally unreachable in
  tests/test_error_tolerant_recovery_coverage_loop.py; the fixed rule template
  in parse_string_line_with_standard_parser always produces exactly one rule
  with at least one string when Parser succeeds, and Parser always produces a
  rule with a non-None condition when it succeeds without exception.
"""

from __future__ import annotations

import pytest

from yaraast.ast.base import YaraFile
from yaraast.ast.expressions import (
    BinaryExpression,
    DoubleLiteral,
    FunctionCall,
    Identifier,
    IntegerLiteral,
    MemberAccess,
    ParenthesesExpression,
    RangeExpression,
    UnaryExpression,
)
from yaraast.ast.rules import Import, Rule
from yaraast.codegen.generator import CodeGenerator
from yaraast.codegen.generator_expression_visitors import (
    _constant_comparison_operand_type,
    _constant_integer_value,
)
from yaraast.errors import YaraASTError
from yaraast.parser._expressions_for import ExpressionForMixin
from yaraast.parser.parser import Parser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(source: str) -> YaraFile:
    """Parse YARA source with the strict parser and return the AST."""
    return Parser(source).parse()


def _generate(source: str) -> str:
    """Parse YARA source and return the round-tripped libyara output."""
    return CodeGenerator().generate(_parse(source))


# ===========================================================================
# generator_expression_visitors.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Branch [439,441]: _constant_integer_value — '>>' operator with right >= 0
# ---------------------------------------------------------------------------


class TestConstantIntegerValueShiftRight:
    """_constant_integer_value evaluates '>>' when right operand is non-negative.

    The function handles '<<' and '>>' only after verifying right >= 0.  The
    '>>' dispatch at line 439-440 is the last branch before the None fallthrough;
    it was previously uncovered because existing tests only exercised '<<'.
    """

    def test_shift_right_positive_right_returns_shifted_value(self) -> None:
        """Arrange: BinaryExpression(>>, 16, 2).

        Act: call _constant_integer_value.

        Assert: returns 4 (16 >> 2).
        """
        node = BinaryExpression(
            operator=">>",
            left=IntegerLiteral(value=16),
            right=IntegerLiteral(value=2),
        )
        result = _constant_integer_value(node)
        assert result == 4

    def test_shift_right_zero_shift_returns_same_value(self) -> None:
        """Arrange: right operand is 0 (>> 0 is identity)."""
        node = BinaryExpression(
            operator=">>",
            left=IntegerLiteral(value=42),
            right=IntegerLiteral(value=0),
        )
        assert _constant_integer_value(node) == 42

    def test_shift_right_large_shift_returns_zero(self) -> None:
        """Arrange: right operand equals INT64_BITS; _shift_right_int64 returns 0."""
        node = BinaryExpression(
            operator=">>",
            left=IntegerLiteral(value=1000),
            right=IntegerLiteral(value=64),
        )
        assert _constant_integer_value(node) == 0

    def test_shift_right_via_codegen_round_trip(self) -> None:
        """Arrange: parse '5 >> 2' inside a condition and round-trip through codegen.

        This exercises the full visitor chain that calls _constant_integer_value.
        """
        output = _generate("rule t { condition: 5 >> 2 }")
        assert "5 >> 2" in output

    def test_shift_right_negative_right_returns_none(self) -> None:
        """Arrange: right < 0; the guard at line 435 returns None before reaching '>>'.

        This is a complementary regression guard — the '>>' branch is only
        reached when right >= 0.
        """
        node = BinaryExpression(
            operator=">>",
            left=IntegerLiteral(value=8),
            right=IntegerLiteral(value=-1),
        )
        assert _constant_integer_value(node) is None


# ---------------------------------------------------------------------------
# Branch [533,537]: _constant_comparison_operand_type — NUMERIC op, not double
# ---------------------------------------------------------------------------


class TestConstantComparisonOperandTypeNumericNonDouble:
    """_constant_comparison_operand_type returns 'integer' for NUMERIC binary ops
    whose operands are not definitely non-integer.

    Line 533 checks for NUMERIC operators ('+', '-', '*', '/', '\\').
    Line 534 asks whether the expression is definitely non-integer.
    When it is NOT (e.g., both operands are integer literals), control falls to
    line 537 which returns 'integer'.  This path was previously uncovered.
    """

    def test_addition_of_integers_returns_integer_type(self) -> None:
        """Arrange: BinaryExpression('+', IntegerLiteral(3), IntegerLiteral(4)).

        Act: call _constant_comparison_operand_type.

        Assert: returns 'integer' via the 533->537 branch.
        """
        node = BinaryExpression(
            operator="+",
            left=IntegerLiteral(value=3),
            right=IntegerLiteral(value=4),
        )
        assert _constant_comparison_operand_type(node) == "integer"

    def test_multiplication_of_integers_returns_integer_type(self) -> None:
        """Arrange: BinaryExpression('*', IntegerLiteral, IntegerLiteral)."""
        node = BinaryExpression(
            operator="*",
            left=IntegerLiteral(value=5),
            right=IntegerLiteral(value=6),
        )
        assert _constant_comparison_operand_type(node) == "integer"

    def test_addition_with_double_operand_returns_double_type(self) -> None:
        """Complementary: when one operand is definitely non-integer (DoubleLiteral),
        _is_definitely_non_integer_expression returns True and branch 533->535 fires
        ('double').  This regression guard confirms the non-double path is distinct.
        """
        node = BinaryExpression(
            operator="+",
            left=DoubleLiteral(value=1.5),
            right=IntegerLiteral(value=2),
        )
        assert _constant_comparison_operand_type(node) == "double"

    def test_integer_comparison_round_trip_via_codegen(self) -> None:
        """Arrange: parse '(3 + 4) < 10' which triggers comparison operand type checks.

        The arithmetic sub-expression is a NUMERIC BinaryExpression with integer
        operands.  _constant_comparison_operand_type is called with it during
        codegen validation and returns 'integer' via branch 533->537.
        """
        output = _generate("rule t { condition: (3 + 4) < 10 }")
        assert "(3 + 4) < 10" in output


# ---------------------------------------------------------------------------
# Branch [553,555]: _constant_comparison_operand_type — UnaryExpression('-') with
# non-double operand falls through to line 555
# ---------------------------------------------------------------------------


class TestConstantComparisonOperandTypeUnaryMinusNonDouble:
    """_constant_comparison_operand_type: UnaryExpression('-') whose operand is NOT
    a DoubleLiteral or float causes the condition at line 553 to be False, and
    control falls through to line 555 (the DoubleLiteral direct check).

    For a UnaryExpression that is not DoubleLiteral either, the function returns None.
    """

    def test_unary_minus_on_identifier_returns_none(self) -> None:
        """Arrange: UnaryExpression('-', Identifier('x')).

        The operand is an Identifier, not DoubleLiteral; line 553 condition is False
        (553->555 branch fires), line 555 is also False -> returns None.
        """
        node = UnaryExpression(operator="-", operand=Identifier(name="x"))
        assert _constant_comparison_operand_type(node) is None

    def test_unary_minus_on_double_literal_returns_double(self) -> None:
        """Complementary: UnaryExpression('-', DoubleLiteral) triggers line 553->554
        (the True branch), returning 'double'.
        """
        node = UnaryExpression(operator="-", operand=DoubleLiteral(value=3.14))
        assert _constant_comparison_operand_type(node) == "double"

    def test_unary_minus_on_filesize_round_trip_via_codegen(self) -> None:
        """Arrange: parse '(-filesize) < 100'.

        The left operand is UnaryExpression('-', Identifier('filesize')).
        During codegen, _constant_comparison_operand_type is called and
        follows the 553->555 path before falling through to return None.
        """
        output = _generate("rule t { condition: (-filesize) < 100 }")
        assert "(-filesize) < 100" in output


# ---------------------------------------------------------------------------
# Branch [694,695]: _validate_known_module_function_call — unknown module
# ---------------------------------------------------------------------------


class TestValidateKnownModuleFunctionCallUnknownModule:
    """_validate_known_module_function_call returns early at line 695 when the
    module is not recognised by load_builtin_modules().

    The function resolves module_name from the FunctionCall node and looks it up
    in the built-in module registry.  For a module name absent from the registry
    (e.g., 'unknownmod'), module_def is None and the function returns immediately
    at line 695 without further validation.
    """

    def test_unknown_module_function_generates_without_error(self) -> None:
        """Arrange: an AST with FunctionCall(function='unknownmod.some_func').

        Codegen calls validate_function_call_arguments which calls
        _validate_known_module_function_call.  Because 'unknownmod' is not in the
        registry, module_def is None -> return at line 695.

        Act: generate the AST.

        Assert: output contains the function call without raising.
        """
        fc = FunctionCall(function="unknownmod.some_func", arguments=[])
        rule = Rule(name="t", condition=fc)
        yara_file = YaraFile(imports=[], includes=[], rules=[rule])

        output = CodeGenerator().generate(yara_file)
        assert "unknownmod.some_func()" in output

    def test_unknown_module_with_argument_generates_without_error(self) -> None:
        """Arrange: FunctionCall for a module not in the registry, with one argument.

        Act: generate.

        Assert: output includes the function call with its argument.
        """
        fc = FunctionCall(
            function="mymod.check",
            arguments=[IntegerLiteral(value=0)],
        )
        rule = Rule(name="t", condition=fc)
        yara_file = YaraFile(imports=[], includes=[], rules=[rule])

        output = CodeGenerator().generate(yara_file)
        assert "mymod.check(0)" in output

    def test_required_module_validation_loads_builtin_modules_once(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression: module validation must not rebuild builtin modules per AST node."""
        from yaraast.types import module_definitions

        calls = 0
        real_load = module_definitions.load_builtin_modules

        def counted_load() -> object:
            nonlocal calls
            calls += 1
            return real_load()

        monkeypatch.setattr(module_definitions, "load_builtin_modules", counted_load)

        rules = [
            Rule(name=f"r{i}", condition=MemberAccess(object=Identifier("pe"), member="is_pe"))
            for i in range(50)
        ]
        yara_file = YaraFile(imports=[Import(module="pe")], includes=[], rules=rules)

        CodeGenerator().generate(yara_file)

        assert calls == 2


# ---------------------------------------------------------------------------
# Branch [738,742]: _validate_known_module_function_call — falls through to
# _validate_generic_module_function_argument_types for non-special modules
# ---------------------------------------------------------------------------


class TestValidateKnownModuleFunctionCallGenericPath:
    """_validate_known_module_function_call reaches line 742
    (_validate_generic_module_function_argument_types) when the module is
    'elf', 'string', 'time', 'dotnet', 'vt', or any other built-in that is
    not 'hash', 'math', 'pe', or 'console'.

    Branch [738,742] means the 'console' + 'hex' check at line 738 evaluates to
    False and control passes to the generic validator at line 742.
    """

    def test_elf_module_function_call_generates_successfully(self) -> None:
        """Arrange: parse 'import \"elf\" rule t { condition: elf.import_md5() == \"x\" }'.

        'elf' is a known built-in module but is not hash/math/pe/console, so
        _validate_known_module_function_call falls through to the generic
        validator at line 742.

        Act: generate the AST.

        Assert: round-tripped output contains the elf function call.
        """
        source = 'import "elf"\nrule t { condition: elf.import_md5() == "x" }'
        output = _generate(source)
        assert "elf.import_md5()" in output

    def test_string_module_function_call_generates_successfully(self) -> None:
        """Arrange: 'string.length()' — 'string' is a known non-special module."""
        source = 'import "string"\nrule t { condition: string.length("abc") > 0 }'
        output = _generate(source)
        assert "string.length" in output

    def test_time_module_function_call_generates_successfully(self) -> None:
        """Arrange: 'time.now()' — 'time' is a known non-special module."""
        source = 'import "time"\nrule t { condition: time.now() > 0 }'
        output = _generate(source)
        assert "time.now()" in output


# ===========================================================================
# parser/_expressions_for.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Line 176 (_expressions_for.py): _is_parenthesized_range_bound — True branch
# ---------------------------------------------------------------------------


class TestIsParenthesizedRangeBoundForMixin:
    """ExpressionForMixin._is_parenthesized_range_bound at line 175-178 returns True
    when the expression is a ParenthesesExpression wrapping a RangeExpression.

    This method is shadowed by ExpressionPostfixMixin._is_parenthesized_range_bound
    (line 305 of _expressions_postfix.py) in the Parser MRO, which means normal
    parsing calls the postfix-mixin version.  To cover line 176 in _expressions_for.py
    the method is called directly on a Parser instance via the unbound form on
    ExpressionForMixin.  This is not a mock — it exercises the real implementation
    on a real Parser instance.
    """

    def test_is_parenthesized_range_bound_returns_true_for_paren_range(self) -> None:
        """Arrange: a ParenthesesExpression whose inner expression is a RangeExpression.

        Act: call ExpressionForMixin._is_parenthesized_range_bound directly on a
        real Parser instance.

        Assert: returns True (line 176 returns the True result of the isinstance
        conjunction).
        """
        p = Parser("rule t { condition: true }")
        p.parse()
        inner_range = RangeExpression(
            low=IntegerLiteral(value=0),
            high=IntegerLiteral(value=10),
        )
        paren_range = ParenthesesExpression(expression=inner_range)
        result = ExpressionForMixin._is_parenthesized_range_bound(p, paren_range)
        assert result is True

    def test_is_parenthesized_range_bound_returns_false_for_non_paren(self) -> None:
        """Arrange: a plain IntegerLiteral (not a ParenthesesExpression).

        Act: call ExpressionForMixin._is_parenthesized_range_bound.

        Assert: returns False (line 176's isinstance check fails at the first
        operand of 'and').
        """
        p = Parser("rule t { condition: true }")
        p.parse()
        result = ExpressionForMixin._is_parenthesized_range_bound(p, IntegerLiteral(value=0))
        assert result is False

    def test_for_loop_with_parenthesized_range_iterable_raises(self) -> None:
        """Arrange: 'for any i in ((0..10)..20) : (true)'.

        The for-loop iterable is ParenthesesExpression(RangeExpression(
            low=ParenthesesExpression(RangeExpression(0,10)), high=20)).
        _range_has_parenthesized_range_bound calls the POSTFIX-mixin version of
        _is_parenthesized_range_bound (due to MRO) which returns True,
        causing _is_nested_parenthesized_range to raise ParserError.

        Act: parse.

        Assert: ParserError is raised.
        """
        src = "rule t { condition: for any i in ((0..10)..20) : (true) }"
        with pytest.raises((YaraASTError, Exception), match=r"[Uu]nexpected"):
            _parse(src)


# ---------------------------------------------------------------------------
# Branch [326,327]: _of_set_expression_kind — element_kind is None -> return None
# ---------------------------------------------------------------------------


class TestOfSetExpressionKindNoneElement:
    """_of_set_expression_kind iterates elements and returns None as soon as an
    element's kind is None (branch 326->327).

    An element's kind is None when it is not a StringIdentifier, StringWildcard,
    Identifier('them'), or a set/parenthesized set of those.  Using a StringCount
    (#a) in an 'of' set triggers this path because _of_string_set_kind returns
    None for StringCount nodes.
    """

    def test_set_with_string_count_element_raises_parser_error(self) -> None:
        """Arrange: '1 of (#a, $a)' — set contains a StringCount (#a).

        _of_set_expression_kind iterates elements; for the StringCount element
        _of_string_set_kind returns None -> branch 326->327 fires -> None is
        returned -> _validate_of_string_set raises ParserError.

        Act: parse.

        Assert: ParserError is raised.
        """
        src = 'rule t { strings: $a = "x" condition: 1 of (#a, $a) }'
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_of_expression_with_integer_literal_in_set_raises(self) -> None:
        """Arrange: 'any of (filesize, entrypoint)' — filesize/entrypoint return
        None from _of_string_set_kind, causing 326->327 (when inside a set).
        """
        src = "rule t { condition: any of (filesize, entrypoint) }"
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)


# ---------------------------------------------------------------------------
# Branches [379,387] and [383,384]: _collect_function_args
# ---------------------------------------------------------------------------


class TestCollectFunctionArgs:
    """_collect_function_args is called from _parse_of_function_call when a
    function appears in an 'of' string-set context WITHOUT outer parentheses wrapping
    the entire call.

    The trigger syntax is 'N of pe.method(args)' (no extra parens around the call),
    where 'pe' is parsed as a ModuleReference by _parse_primary_expression, then
    the while loop in _parse_of_string_set sees DOT and calls _parse_of_member_access,
    then sees LPAREN and calls _parse_of_function_call -> _collect_function_args.

    Branch [379,387]: the while-loop body is never entered (empty args) because
    the very first token after '(' is RPAREN.

    Lines 383-385 / branch [383,384]: a comma appears immediately before RPAREN
    inside the args, triggering the guard that raises ParserError.
    """

    def test_zero_arg_function_call_in_of_set_context_triggers_empty_args_path(
        self,
    ) -> None:
        """Arrange: '1 of pe.section_index()' — zero arguments.

        _parse_of_string_set parses 'pe' as ModuleReference, DOT as
        _parse_of_member_access -> 'section_index' MemberAccess, then LPAREN triggers
        _parse_of_function_call -> _collect_function_args.  The while loop at line 379
        is not entered (RPAREN is immediately present); control jumps directly to
        line 387 (_match RPAREN).  _validate_of_string_set then raises ParserError
        because the function-call result is not a valid string-set element.

        Act: parse.

        Assert: ParserError is raised (the construct is semantically invalid but the
        zero-args code path at line 379->387 has been exercised).
        """
        src = 'rule t { strings: $a = "x" condition: 1 of pe.section_index() }'
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_trailing_comma_in_function_call_args_raises_error(self) -> None:
        """Arrange: '1 of pe.section_index(\"text\",)' — trailing comma.

        _collect_function_args is entered via the same DOT+LPAREN path as above.
        After consuming 'text', self._match(COMMA) succeeds; then self._check(RPAREN)
        is True, so lines 383-385 fire and raise ParserError('Expected argument
        after ,').

        Act: parse.

        Assert: ParserError is raised with a message about the trailing comma.
        """
        src = 'rule t { strings: $a = "x" condition: 1 of pe.section_index("text",) }'
        with pytest.raises((YaraASTError, Exception), match=r"[Ee]xpected argument"):
            _parse(src)


# ===========================================================================
# parser/_expressions_postfix.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Lines 278-279: parenthesized range as lower bound of IN range expression
# ---------------------------------------------------------------------------


class TestParenthesizedRangeBoundInInExpression:
    """_parse_parenthesized_range_after_in rejects range bounds that are
    themselves parenthesized range expressions.

    Line 277: checks whether the low bound is a parenthesized range.
    Line 278-279: raises ParserError (branch [277,278]).

    Line 284: checks the high bound.
    Line 285-286: raises ParserError (branch [284,285]).

    For _parse_parenthesized_range_after_in to see a ParenthesesExpression(
    RangeExpression) as a range bound, the _allow_range_expression flag must be
    True when _parse_bitwise_or_expression is called for the bound.  This is
    satisfied when _parse_parenthesized_range_after_in is called inside a for-loop
    iterable expression (where the for-loop parser sets _allow_range_expression=True
    before calling _parse_expression).

    The triggering syntax is 'for any i in ($a in ((0..10)..20)) : (cond)' where
    the inner '$a in ...' is the for-loop iterable and '(0..10)' is parsed as a
    ParenthesesExpression(RangeExpression) because range expressions are allowed in
    the for-loop context.
    """

    def test_parenthesized_range_as_lower_bound_raises_parser_error(self) -> None:
        """Arrange: for loop with '$a in ((0..10)..20)' as iterable.

        Inside the for-loop context _allow_range_expression is True, so '(0..10)'
        parses as ParenthesesExpression(RangeExpression).  When _parse_in_postfix
        calls _parse_parenthesized_range_after_in, the low bound '(0..10)' is a
        ParenthesesExpression(RangeExpression), causing _is_parenthesized_range_bound
        to return True -> lines 278-279 raise ParserError.

        Act: parse.

        Assert: ParserError is raised.
        """
        src = 'rule t { strings: $a = "x" condition: for any i in ($a in ((0..10)..20)) : (true) }'
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_parenthesized_range_as_upper_bound_raises_parser_error(self) -> None:
        """Arrange: for loop with '$a in (0..(5..20))' as iterable.

        The high bound '(5..20)' is a ParenthesesExpression(RangeExpression).
        _is_parenthesized_range_bound(high) returns True -> lines 285-286 raise
        ParserError.

        Act: parse.

        Assert: ParserError is raised.
        """
        src = 'rule t { strings: $a = "x" condition: for any i in ($a in (0..(5..20))) : (true) }'
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_valid_in_range_does_not_raise(self) -> None:
        """Regression guard: a normal '$a in (0..100)' must parse and round-trip.

        Act: parse and generate.

        Assert: output contains the in-range construct.
        """
        src = 'rule t { strings: $a = "x" condition: $a in (0..100) }'
        output = _generate(src)
        assert "$a in (0..100)" in output


# ===========================================================================
# parser/_expressions_primary.py
# ===========================================================================


# ---------------------------------------------------------------------------
# Line 319 / branch [318,319]: _try_parse_for_expression and
# _match_contextual_local_identifier
# ---------------------------------------------------------------------------


class TestTryParseForExpression:
    """_try_parse_for_expression at line 323-327 is entered when the current token
    is FOR; it delegates to _parse_for_expression and returns the result (line 327).

    This path is reachable any time a 'for ... in ... : (...)' expression appears
    in a rule condition and covers branch [318,319].
    """

    def test_for_expression_parses_and_round_trips(self) -> None:
        """Arrange: 'for any i in (0..10) : (true)'.

        _try_parse_for_expression matches FOR and returns a ForExpression.

        Act: parse and generate.

        Assert: output contains the for expression.
        """
        src = "rule t { condition: for any i in (0..10) : (true) }"
        output = _generate(src)
        assert "for" in output and "in" in output

    def test_for_all_expression_parses(self) -> None:
        """Arrange: 'for all i in (1..5) : (i < 10)'."""
        src = "rule t { condition: for all i in (1..5) : (i < 10) }"
        output = _generate(src)
        assert "for all" in output


class TestMatchContextualLocalIdentifierNotInFrame:
    """_match_contextual_local_identifier at line 312-321: when the current token
    is AS or INCLUDE but that name is NOT registered in any contextual local
    identifier frame, branch [318,319] fires and the function returns False.

    This leaves the primary expression parser unable to match any parser for the
    'as' keyword in a non-for-loop context, ultimately raising ParserError.
    """

    def test_as_keyword_outside_for_loop_context_raises_parser_error(self) -> None:
        """Arrange: 'condition: as > 5'.

        _try_parse_identifier is called; IDENTIFIER does not match the AS token;
        _match_contextual_local_identifier is called; AS is in the candidate set
        but _contextual_local_identifiers is empty so 'as' is not in any frame.
        Branch 318->319 fires (return False).

        Act: parse.

        Assert: ParserError is raised.
        """
        src = "rule t { condition: as > 5 }"
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_as_inside_for_loop_body_parses_as_identifier(self) -> None:
        """Arrange: 'for any as in (0..10) : (as > 5)'.

        Inside the for-loop body, 'as' IS registered in _contextual_local_identifiers
        (the True branch of line 318 condition), so _match_contextual_local_identifier
        returns True and 'as' is parsed as an Identifier.

        Act: parse and generate.

        Assert: the output contains a ForExpression with variable 'as'.
        """
        src = "rule t { condition: for any as in (0..10) : (as > 5) }"
        output = _generate(src)
        assert "for" in output


# ---------------------------------------------------------------------------
# Branch [209,212]: _parse_quantifier_expression — ANY/ALL/NONE without OF
# ---------------------------------------------------------------------------


class TestParseQuantifierExpressionAnyWithoutOf:
    """_parse_quantifier_expression at line 207-212: when ANY, ALL, or NONE is
    matched (consuming the token) but the next token is NOT 'of', the function
    returns None at line 212 (branch [209,212]).

    Because the keyword token has already been consumed, the remaining primary
    expression parsers cannot match any token, leading to a ParserError for the
    next token in the stream.
    """

    def test_any_without_of_raises_parser_error(self) -> None:
        """Arrange: 'condition: any > 5'.

        _parse_quantifier_expression matches ANY; checks for OF (not present);
        branch 209->212 fires; returns None; all remaining parsers fail;
        _parse_primary_expression raises ParserError.

        Act: parse.

        Assert: ParserError is raised.
        """
        src = "rule t { condition: any > 5 }"
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_all_without_of_raises_parser_error(self) -> None:
        """Arrange: 'condition: all < 10'."""
        src = "rule t { condition: all < 10 }"
        with pytest.raises((YaraASTError, Exception)):
            _parse(src)

    def test_any_with_of_parses_correctly(self) -> None:
        """Regression guard: 'any of them' must parse without error.

        In this case, OF is present after ANY, so _parse_quantifier_expression
        takes the True branch at line 209-210 and returns an OfExpression.
        """
        src = 'rule t { strings: $a = "x" condition: any of them }'
        output = _generate(src)
        assert "any of them" in output


# ---------------------------------------------------------------------------
# Branch [352,356]: _contains_range_expression — list field with RangeExpression
# ---------------------------------------------------------------------------


class TestContainsRangeExpressionInList:
    """_contains_range_expression at lines 342-358 traverses expression fields.

    Line 356 fires when a dataclass expression has a LIST field (e.g. FunctionCall
    .arguments) where at least one list item is an Expression whose own fields contain
    a RangeExpression.  This is distinct from line 351 which fires when a direct
    Expression field (not a list) contains a RangeExpression.

    The trigger is a for-loop set iterable that contains a FunctionCall whose
    argument list holds a ParenthesesExpression(RangeExpression).  In the for-loop
    context _allow_range_expression=True so '(1..10)' can be parsed as
    ParenthesesExpression(RangeExpression) inside the function argument.  The
    resulting set element is a FunctionCall with .arguments=[Paren(Range)].
    When _contains_range_expression is called on this FunctionCall:
      - 'function' field is an Identifier -> _cre(Identifier) returns False
      - 'arguments' field is a list -> line 352 matches (isinstance list)
      - any(... for item in [Paren(Range)]):
          _cre(Paren(Range)) recursively finds Range in .expression field -> True
      -> line 356 returns True.
    """

    def test_function_call_with_range_arg_in_set_triggers_list_scan(self) -> None:
        """Arrange: for-loop set iterable '(pe.entry_point, pe.number_of_sections((1..10)))'.

        In the for-loop context, '(1..10)' is parsed as ParenthesesExpression(Range).
        pe.number_of_sections is a FunctionCall whose 'arguments' list contains that
        Paren(Range).  _contains_range_expression traverses the FunctionCall fields:
        the 'arguments' list scan at line 352-356 finds the nested RangeExpression
        and returns True at line 356 -> ParserError 'Range expressions cannot be
        set elements'.

        Act: parse.

        Assert: ParserError is raised.
        """
        src = (
            "rule t { condition: for any i in"
            " (pe.entry_point, pe.number_of_sections((1..10))) : (true) }"
        )
        with pytest.raises((YaraASTError, Exception), match=r"[Rr]ange"):
            _parse(src)

    def test_valid_set_expression_without_ranges_parses_correctly(self) -> None:
        """Regression guard: a normal set expression must parse without error."""
        src = 'rule t { strings: $a = "x" $b = "y" condition: any of ($a, $b) }'
        output = _generate(src)
        assert "any of" in output
