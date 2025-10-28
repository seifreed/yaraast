"""Tests for 'of ... in (range)' syntax support."""

import pytest

from yaraast.ast.conditions import InExpression, OfExpression
from yaraast.parser import Parser


class TestOfInSyntax:
    """Test parsing of 'of' expressions with 'in' range syntax."""

    def test_simple_string_in_range(self):
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

    def test_all_of_wildcard_in_range(self):
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

    def test_any_of_strings_in_range(self):
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

    def test_numeric_quantifier_in_range(self):
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

    def test_all_of_them_in_range(self):
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

    def test_complex_range_expression(self):
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

    def test_real_world_pattern_from_master_yara(self):
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

    def test_backward_compatibility_with_string_id_property(self):
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
        assert in_expr.string_id == "$a"

    def test_of_expression_string_id_returns_none(self):
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
        assert in_expr.string_id is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
