"""Tests for 'of ... in (range)' and 'of ... at offset' syntax support."""

import pytest
import yara

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ParenthesesExpression,
    StringCount,
    StringWildcard,
    UnaryExpression,
)
from yaraast.codegen import CodeGenerator
from yaraast.parser import Parser
from yaraast.parser._shared import ParserError
from yaraast.types import TypeChecker


class TestOfInSyntax:
    """Test parsing of 'of' expressions with 'in' range syntax."""

    def test_simple_string_in_range(self) -> None:
        """Test that simple $string in (range) still works."""
        yara_code = """
        rule test {
            strings:
                $a = "test"
            condition:
                $a in (0..100)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)
        assert isinstance(ast.rules[0].condition.subject, str)
        assert ast.rules[0].condition.subject == "$a"

    def test_string_count_in_range(self) -> None:
        """Test that #string in (range) parses as a count range check."""
        yara_code = """
        rule test {
            strings:
                $a = "test"
            condition:
                #a in (0..100)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)
        assert isinstance(ast.rules[0].condition.subject, StringCount)

    def test_string_count_in_range_allows_negative_dynamic_range_bound(self) -> None:
        """libyara allows negative static bounds when the full range is dynamic."""
        yara_code = """
        rule test {
            strings:
                $a = "a"
                $b = "b"
            condition:
                #a in (-10..#b)
        }
        """

        ast = Parser().parse(yara_code)
        condition = ast.rules[0].condition

        assert isinstance(condition, InExpression)
        assert isinstance(condition.subject, StringCount)
        yara.compile(source=CodeGenerator().generate(ast))

    def test_string_count_in_range_rejects_negative_static_range_bound(self) -> None:
        yara_code = """
        rule test {
            strings:
                $a = "a"
            condition:
                #a in (-10..10)
        }
        """

        with pytest.raises(ParserError, match="Range lower bound can not be negative"):
            Parser().parse(yara_code)

    def test_at_offset_accepts_bitwise_string_count_in_expression(self) -> None:
        """libyara accepts bitwise offsets containing string count range checks."""
        from yaraast.ast.expressions import BinaryExpression

        yara_code = """
        rule test {
            strings:
                $a = "a"
                $b = "b"
            condition:
                $b at ~ 50 | #a in (@a..25)
        }
        """

        ast = Parser().parse(yara_code)
        condition = ast.rules[0].condition

        assert isinstance(condition, AtExpression)
        assert isinstance(condition.offset, BinaryExpression)
        assert condition.offset.operator == "|"
        assert isinstance(condition.offset.right, InExpression)

        generated = CodeGenerator().generate(ast)
        yara.compile(source=generated)

    @pytest.mark.parametrize(
        "condition",
        [
            "-1 of them",
            "~1 of them",
            "-(1 of them)",
            "~(1 of them)",
            "-any of them",
            "-1 of them at 0",
            "-1 of them in (0..100)",
            "-$a",
            "-$a in (0..100)",
            "~$a",
            "-($a at 0)",
            "~($a at 0)",
        ],
    )
    def test_numeric_unary_operators_reject_string_condition_operands(
        self,
        condition: str,
    ) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError):
            Parser().parse(yara_code)

    @pytest.mark.parametrize("condition", ["-#a in (0..1)", "~#a < 0", "not 1 of them"])
    def test_valid_unary_quantifier_neighbors_still_parse(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1

    @pytest.mark.parametrize(
        ("condition", "expected"),
        [
            ("1 of (alpha)", "1 of (alpha)"),
            ("all of (alpha, beta)", "all of (alpha, beta)"),
            ("any of (alpha*)", "any of (alpha*)"),
        ],
    )
    def test_of_expression_accepts_rule_sets(
        self,
        condition: str,
        expected: str,
    ) -> None:
        yara_code = f"""
        rule alpha {{
            condition:
                true
        }}
        rule beta {{
            condition:
                true
        }}
        rule probe {{
            condition:
                {condition}
        }}
        """
        ast = Parser().parse(yara_code)

        assert TypeChecker().check(ast) == []
        assert expected in CodeGenerator().generate(ast)

    def test_rule_wildcard_set_parses_as_bare_wildcard(self) -> None:
        yara_code = """
        rule alpha {
            condition:
                true
        }
        rule probe {
            condition:
                any of (alpha*)
        }
        """

        ast = Parser().parse(yara_code)
        condition = ast.rules[-1].condition

        assert isinstance(condition, OfExpression)
        assert isinstance(condition.string_set, ParenthesesExpression)
        assert isinstance(condition.string_set.expression, StringWildcard)
        assert condition.string_set.expression.pattern == "alpha*"

    def test_rule_set_rejects_unresolved_rule_references(self) -> None:
        yara_code = """
        rule probe {
            condition:
                any of (missing)
        }
        """

        ast = Parser().parse(yara_code)

        assert TypeChecker().check(ast) == ["Undefined rule: missing"]

    @pytest.mark.parametrize(
        "condition",
        [
            "any of (alpha) at 0",
            "1 of (alpha) at 0",
            "any of (alpha*) in (0..10)",
        ],
    )
    def test_rule_sets_reject_at_and_in_restrictions(self, condition: str) -> None:
        yara_code = f"""
        rule alpha {{
            condition:
                true
        }}
        rule probe {{
            condition:
                {condition}
        }}
        """

        with pytest.raises(ParserError, match="Rule sets cannot use"):
            Parser().parse(yara_code)

    def test_mixed_string_and_rule_sets_are_rejected(self) -> None:
        yara_code = """
        rule alpha {
            condition:
                true
        }
        rule probe {
            strings:
                $a = "test"
            condition:
                any of ($a, alpha)
        }
        """

        with pytest.raises(ParserError, match="Mixed string and rule sets"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "any of (1)",
            "any of (true)",
            'any of ("$a")',
            "any of (/x/)",
            "any of (filesize)",
            "any of (pe.is_32bit())",
        ],
    )
    def test_of_expression_rejects_non_identifier_string_sets(self, condition: str) -> None:
        yara_code = f"""
        import "pe"
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """

        with pytest.raises(ParserError, match="Expected string or rule identifier"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "pe",
            "any of (pe)",
        ],
    )
    def test_module_named_rules_can_be_referenced_as_rules(self, condition: str) -> None:
        yara_code = f"""
        rule pe {{
            condition:
                true
        }}
        rule probe {{
            condition:
                {condition}
        }}
        """

        ast = Parser().parse(yara_code)

        assert TypeChecker().check(ast) == []

    def test_imported_module_name_is_not_scalar_rule_reference(self) -> None:
        yara_code = """
        import "pe"
        rule pe {
            condition:
                true
        }
        rule probe {
            condition:
                pe
        }
        """

        ast = Parser().parse(yara_code)

        assert TypeChecker().check(ast) == [
            "Rule condition must be boolean, integer, double, regex, string, "
            "or string identifier, got module(pe)"
        ]

    @pytest.mark.parametrize(
        "condition",
        [
            "any of (them)",
            "for any of (them) : ( $ )",
        ],
    )
    def test_parenthesized_them_set_is_rejected(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """

        with pytest.raises(ParserError, match="'them' cannot be parenthesized"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "any of them",
            "for any of them : ( $ )",
        ],
    )
    def test_unparenthesized_them_set_still_parses(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """

        ast = Parser().parse(yara_code)

        assert TypeChecker().check(ast) == []

    @pytest.mark.parametrize("condition", ["@a in (0..100)", "!a in (0..100)"])
    def test_string_offset_and_length_do_not_support_in_range(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError, match="IN keyword can only be used"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "$a at true",
            "$a at false",
            '$a at "x"',
            "$a at /x/",
            "$a at 0.5",
            "$a at $a",
            "$a at 0 + true",
        ],
    )
    def test_at_rejects_non_integer_offset_expressions(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError, match="AT offset must be an integer expression"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "$a in (true..1)",
            "$a in (0..true)",
            '$a in ("x"..1)',
            '$a in (0.."x")',
            "$a in (/x/..1)",
            "$a in (0.5..1)",
            "$a in (0..0.5)",
            "$a in ($a..filesize)",
            "$a in (0 + true..filesize)",
        ],
    )
    def test_in_rejects_non_integer_range_bound_expressions(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError, match="IN range bounds must be integer expressions"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "$a in (-1..0)",
            "#a in (-1..0)",
            "all of them in (-1..0)",
            "$a in (0-1..0)",
            "for any i in (-1..1) : (true)",
        ],
    )
    def test_static_ranges_reject_negative_lower_bounds(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError, match="Range lower bound can not be negative"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "$a in (0..-1)",
            "#a in (0..-1)",
            "all of them in (0..-1)",
            "$a in (0..0-1)",
            "for any i in (0..-1) : (true)",
        ],
    )
    def test_static_ranges_reject_inverted_bounds(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError, match="Range lower bound must be less than upper bound"):
            Parser().parse(yara_code)

    @pytest.mark.parametrize(
        "condition",
        [
            "$a at -1",
            "all of them at -1",
            "$a in (uint8(0)-1..0)",
            "$a in (0..uint8(0)-1)",
        ],
    )
    def test_negative_offsets_and_dynamic_ranges_still_parse(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test"
            condition:
                {condition}
        }}
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1

    def test_all_of_wildcard_in_range(self) -> None:
        """Test 'all of ($a*) in (range)' syntax."""
        yara_code = """
        rule test {
            strings:
                $a1 = "test1"
                $a2 = "test2"
            condition:
                all of ($a*) in (0..100)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)
        assert isinstance(ast.rules[0].condition.subject, OfExpression)

    def test_any_of_strings_in_range(self) -> None:
        """Test 'any of ($x*) in (range)' syntax."""
        yara_code = """
        rule test {
            strings:
                $x1 = "test1"
                $x2 = "test2"
            condition:
                any of ($x*) in (0..1000)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)
        assert isinstance(ast.rules[0].condition.subject, OfExpression)

    def test_numeric_quantifier_in_range(self) -> None:
        """Test '2 of ($key*) in (range)' syntax."""
        yara_code = """
        rule test {
            strings:
                $key1 = "key1"
                $key2 = "key2"
                $key3 = "key3"
            condition:
                2 of ($key*) in (0..500)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)
        assert isinstance(ast.rules[0].condition.subject, OfExpression)

    def test_all_of_them_in_range(self) -> None:
        """Test 'all of them in (range)' syntax."""
        yara_code = """
        rule test {
            strings:
                $a = "test1"
                $b = "test2"
            condition:
                all of them in (0..filesize)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)
        assert isinstance(ast.rules[0].condition.subject, OfExpression)

    def test_all_of_them_at_offset(self) -> None:
        """Test 'all of them at offset' syntax."""
        yara_code = """
        rule test {
            strings:
                $a = "test1"
                $b = "test2"
            condition:
                all of them at 0
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, AtExpression)
        assert isinstance(ast.rules[0].condition.string_id, OfExpression)

    def test_numeric_of_wildcard_at_offset(self) -> None:
        """Test 'N of ($a*) at offset' syntax."""
        yara_code = """
        rule test {
            strings:
                $a1 = "test1"
                $a2 = "test2"
            condition:
                1 of ($a*) at 0
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, AtExpression)
        assert isinstance(ast.rules[0].condition.string_id, OfExpression)

    def test_percentage_of_expression_without_offset_restriction(self) -> None:
        """Test percentage 'of' syntax without offset or range restrictions."""
        yara_code = """
        rule test {
            strings:
                $a = "test1"
                $b = "test2"
            condition:
                50% of them
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, OfExpression)

    @pytest.mark.parametrize(
        "condition",
        [
            "50% of them in (0..100)",
            "50% of ($a*) in (0..100)",
            "50% of them at 0",
            "50% of ($a*) at 0",
        ],
    )
    def test_percentage_of_expression_rejects_offset_restrictions(
        self,
        condition: str,
    ) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "test1"
                $b = "test2"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError, match="Percentage of-expressions do not support"):
            Parser().parse(yara_code)

    def test_complex_range_expression(self) -> None:
        """Test 'of' expression with complex range using offsets."""
        yara_code = """
        rule test {
            strings:
                $code1 = { 01 02 03 }
                $code2 = { 04 05 06 }
            condition:
                all of ($code*) in (@code1 .. @code1 + 50)
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        assert isinstance(ast.rules[0].condition, InExpression)

    def test_real_world_pattern_from_master_yara(self) -> None:
        """Test real pattern from master_yara.yar."""
        yara_code = """
        rule test {
            strings:
                $code_part1 = { 68 8E 4E 0E EC }
                $code_part2 = { 68 AA FC 0D 7C }
                $code_part3 = { 68 7E D8 E2 73 }
                $code_part4 = { 50 8B 55 F4 E8 A6 00 00 00 50 FF D2 85 C0 75 06 }
            condition:
                uint16(0) == 0x5A4D and
                filesize < 5MB and
                all of ($code_part*) and
                (
                    $code_part2 in (@code_part1 .. @code_part1 + 20) and
                    $code_part3 in (@code_part2 .. @code_part2 + 20) and
                    $code_part4 in (@code_part3 .. @code_part3 + 20)
                )
        }
        """
        ast = Parser().parse(yara_code)
        assert len(ast.rules) == 1
        # The condition should parse without errors

    def test_backward_compatibility_with_string_id_property(self) -> None:
        """Test that the string_id property works for backward compatibility."""
        yara_code = """
        rule test {
            strings:
                $a = "test"
            condition:
                $a in (0..100)
        }
        """
        ast = Parser().parse(yara_code)
        in_expr = ast.rules[0].condition

        # Test backward compatibility property
        assert isinstance(in_expr, InExpression)
        assert in_expr.string_id == "$a"

    def test_of_expression_string_id_returns_none(self) -> None:
        """Test that string_id returns None for OfExpression subjects."""
        yara_code = """
        rule test {
            strings:
                $a1 = "test1"
                $a2 = "test2"
            condition:
                all of ($a*) in (0..100)
        }
        """
        ast = Parser().parse(yara_code)
        in_expr = ast.rules[0].condition

        # When subject is OfExpression, string_id should return None
        assert isinstance(in_expr, InExpression)
        assert in_expr.string_id is None


class TestExpressionQuantifierOf:
    """Parsing of of-expressions whose quantifier is a primary expression.

    libyara accepts any ``primary_expression`` (a numeric leaf or arithmetic
    thereof) as the of-expression quantifier, e.g. ``#a of them`` or
    ``#a + 1 of (...)``.  These previously failed to parse while the AST and
    code generator already supported such quantifiers.
    """

    @staticmethod
    def _parse(condition: str) -> OfExpression:
        yara_code = f"""
        rule test {{
            strings:
                $a = "a"
                $b = "b"
            condition:
                {condition}
        }}
        """
        ast = Parser().parse(yara_code)
        node = ast.rules[0].condition
        assert isinstance(node, OfExpression)
        return node

    def test_string_count_quantifier(self) -> None:
        node = self._parse("#a of ($a, $b)")
        assert isinstance(node.quantifier, StringCount)
        assert node.quantifier.string_id == "a"

    def test_arithmetic_count_quantifier(self) -> None:
        from yaraast.ast.expressions import BinaryExpression

        node = self._parse("#a + #b of ($a, $b)")
        assert isinstance(node.quantifier, BinaryExpression)
        assert node.quantifier.operator == "+"
        assert isinstance(node.quantifier.left, StringCount)
        assert isinstance(node.quantifier.right, StringCount)

    def test_integer_arithmetic_count_quantifier(self) -> None:
        from yaraast.ast.expressions import BinaryExpression, IntegerLiteral

        node = self._parse("1 + 1 of them")
        assert isinstance(node.quantifier, BinaryExpression)
        assert node.quantifier.operator == "+"
        assert isinstance(node.quantifier.left, IntegerLiteral)
        assert isinstance(node.quantifier.right, IntegerLiteral)

    def test_arithmetic_count_quantifier_with_in_restriction(self) -> None:
        from yaraast.ast.expressions import BinaryExpression

        yara_code = """
        rule test {
            strings:
                $a = "a"
                $b = "b"
            condition:
                25 - 1 of them in (!b..1)
        }
        """

        ast = Parser().parse(yara_code)
        condition = ast.rules[0].condition

        assert isinstance(condition, InExpression)
        assert isinstance(condition.subject, OfExpression)
        assert isinstance(condition.subject.quantifier, BinaryExpression)
        assert condition.subject.quantifier.operator == "-"
        yara.compile(source=CodeGenerator().generate(ast))

    def test_arithmetic_count_quantifier_with_at_restriction(self) -> None:
        from yaraast.ast.expressions import BinaryExpression

        yara_code = """
        rule test {
            strings:
                $a = "a"
                $b = "b"
            condition:
                25 - 1 of them at @a
        }
        """

        ast = Parser().parse(yara_code)
        condition = ast.rules[0].condition

        assert isinstance(condition, AtExpression)
        assert isinstance(condition.string_id, OfExpression)
        assert isinstance(condition.string_id.quantifier, BinaryExpression)
        assert condition.string_id.quantifier.operator == "-"
        yara.compile(source=CodeGenerator().generate(ast))

    def test_string_count_in_range_count_quantifier(self) -> None:
        from yaraast.ast.expressions import BinaryExpression, IntegerLiteral, ParenthesesExpression

        node = self._parse("(#a in (0..10)) % 1 of ($a, $b)")
        assert isinstance(node.quantifier, BinaryExpression)
        assert node.quantifier.operator == "%"
        assert isinstance(node.quantifier.left, ParenthesesExpression)
        assert isinstance(node.quantifier.right, IntegerLiteral)

    def test_dynamic_percentage_quantifier(self) -> None:
        node = self._parse("#a% of them")
        assert isinstance(node.quantifier, UnaryExpression)
        assert node.quantifier.operator == "%"
        assert isinstance(node.quantifier.operand, StringCount)

    def test_parenthesized_dynamic_percentage_quantifier(self) -> None:
        from yaraast.ast.expressions import BinaryExpression

        node = self._parse("(25 + 25)% of them")
        assert isinstance(node.quantifier, UnaryExpression)
        assert node.quantifier.operator == "%"
        assert isinstance(node.quantifier.operand, ParenthesesExpression)
        assert isinstance(node.quantifier.operand.expression, BinaryExpression)

    def test_multiplicative_dynamic_percentage_quantifier(self) -> None:
        from yaraast.ast.expressions import BinaryExpression

        node = self._parse("@a % 50% of them")
        assert isinstance(node.quantifier, UnaryExpression)
        assert node.quantifier.operator == "%"
        assert isinstance(node.quantifier.operand, BinaryExpression)
        assert node.quantifier.operand.operator == "%"

    def test_signed_remainder_dynamic_percentage_quantifier(self) -> None:
        from yaraast.ast.expressions import BinaryExpression

        node = self._parse("--25 % ~100% of them")
        assert isinstance(node.quantifier, UnaryExpression)
        assert node.quantifier.operator == "%"
        assert isinstance(node.quantifier.operand, BinaryExpression)
        assert node.quantifier.operand.operator == "%"

    def test_dynamic_percentage_quantifier_round_trips_to_libyara(self) -> None:
        source = 'rule t { strings: $a = "a" condition: #a% of them }'
        ast = Parser().parse(source)
        generated = CodeGenerator().generate(ast)
        reparsed = Parser().parse(generated)
        condition = reparsed.rules[0].condition

        assert isinstance(condition, OfExpression)
        assert isinstance(condition.quantifier, UnaryExpression)
        assert generated.count("% of them") == 1

    def test_double_unary_count_quantifier(self) -> None:
        from yaraast.ast.expressions import IntegerLiteral, UnaryExpression

        node = self._parse("- -1 of them")
        assert isinstance(node.quantifier, UnaryExpression)
        assert node.quantifier.operator == "-"
        assert isinstance(node.quantifier.operand, UnaryExpression)
        assert node.quantifier.operand.operator == "-"
        assert isinstance(node.quantifier.operand.operand, IntegerLiteral)

    def test_identifier_quantifier(self) -> None:
        from yaraast.ast.expressions import Identifier

        node = self._parse("filesize of ($a, $b)")
        assert isinstance(node.quantifier, Identifier)
        assert node.quantifier.name == "filesize"

    @pytest.mark.parametrize(
        "condition",
        [
            "#a of ($a, $b)",
            "filesize of ($a, $b)",
            "entrypoint of ($a, $b)",
            "uint8(0) of ($a, $b)",
        ],
    )
    def test_primary_expression_quantifier_round_trips(self, condition: str) -> None:
        node = self._parse(condition)
        generated = CodeGenerator().generate(
            Parser().parse(f'rule t {{ strings: $a = "a" $b = "b" condition: {condition} }}')
        )
        reparsed = Parser().parse(generated).rules[0].condition
        assert isinstance(reparsed, OfExpression)
        assert type(reparsed.quantifier) is type(node.quantifier)

    @pytest.mark.parametrize(
        "condition",
        [
            "$a of ($a, $b)",
            "1 of them of ($a, $b)",
            "(0..10) of ($a, $b)",
            "0 - 1 of them",
            "(0 - 1) of them",
            "~1 of them",
            "0% of them",
            "101% of them",
            "false% of them",
            "false of them",
            '"any" of them',
            "/a/ of them",
            "1.2 of them",
            "1.2% of them",
            "--1.2% of them",
            "(#a + --1.2)% of them",
            "(-#a >> 50 >> 101)% of them",
            "(1 << 63 >> 63)% of them",
            "25 + 25% of them",
            "25 - 1% of them",
            "25 << 1% of them",
            "~25 * 2% of them",
            "51 * 2% of them",
        ],
    )
    def test_invalid_quantifiers_rejected(self, condition: str) -> None:
        yara_code = f"""
        rule test {{
            strings:
                $a = "a"
                $b = "b"
            condition:
                {condition}
        }}
        """
        with pytest.raises(ParserError):
            Parser().parse(yara_code)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
