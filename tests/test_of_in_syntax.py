"""Tests for 'of ... in (range)' and 'of ... at offset' syntax support."""

import pytest

from yaraast.ast.conditions import AtExpression, InExpression, OfExpression
from yaraast.ast.expressions import StringCount
from yaraast.parser import Parser
from yaraast.parser._shared import ParserError


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

    @pytest.mark.parametrize("condition", ["-#a in (-1..0)", "~#a < 0", "not 1 of them"])
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
