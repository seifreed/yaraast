"""Tests for 'of ... in (range)' and 'of ... at offset' syntax support."""

import pytest

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import (
    ParenthesesExpression,
    StringCount,
    StringWildcard,
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
        with pytest.raises(ParserError, match="Invalid operand for numeric unary operator"):
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
