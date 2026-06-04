"""Test full YARA language coverage features."""

from __future__ import annotations

import pytest

from yaraast import CodeGenerator, Parser
from yaraast.ast.expressions import BinaryExpression, RegexLiteral, StringLiteral
from yaraast.types import TypeValidator


def test_import_without_alias() -> None:
    """Test import statements."""
    yara_code = """
    import "pe"
    import "elf"
    import "math"

    rule test_imports {
        condition:
            pe.machine == 0x14c and
            elf.type == 0x02 and
            math.entropy(0, filesize) > 7.0
    }
    """

    parser = Parser()
    ast = parser.parse(yara_code)

    # Check imports
    assert len(ast.imports) == 3
    assert ast.imports[0].module == "pe"
    assert ast.imports[0].alias is None
    assert ast.imports[1].module == "elf"
    assert ast.imports[1].alias is None
    assert ast.imports[2].module == "math"
    assert ast.imports[2].alias is None

    # Generate code and verify
    generator = CodeGenerator()
    output = generator.generate(ast)
    assert 'import "pe"' in output
    assert 'import "elf"' in output
    assert 'import "math"' in output
    assert "as pe" not in output
    assert "as elf" not in output
    assert "as math" not in output


def test_string_matches_regex_literal() -> None:
    """Test string matching a regex expression."""
    yara_code = """
    rule string_matches_regex_literal {
        condition:
            "foo123bar" matches /b[a-z]+r/
    }
    """

    parser = Parser()
    ast = parser.parse(yara_code)

    # Get the condition
    rule = ast.rules[0]
    condition = rule.condition

    # Verify it's a binary expression with matches operator
    assert isinstance(condition, BinaryExpression)
    assert condition.operator == "matches"

    # Check left side is string literal
    assert isinstance(condition.left, StringLiteral)
    assert condition.left.value == "foo123bar"

    # Check right side is regex literal
    assert isinstance(condition.right, RegexLiteral)
    assert condition.right.pattern == "b[a-z]+r"
    assert condition.right.modifiers == ""

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)
    assert '"foo123bar" matches /b[a-z]+r/' in output


def test_big_endian_little_endian_functions() -> None:
    """Test big-endian and little-endian integer functions."""
    yara_code = """
    rule endian_functions {
        condition:
            uint16be(0) == 0x4D5A and
            uint32be(4) == 0x50450000 and
            int16be(8) < 0 and
            int32be(12) > 1000 and
            uint16le(16) != 0x5A4D and
            uint32le(20) == 0x00004550 and
            int16le(24) >= -100 and
            int32le(28) <= 2000
    }
    """

    parser = Parser()
    ast = parser.parse(yara_code)

    # Type check should pass
    is_valid, errors = TypeValidator.validate(ast)
    assert is_valid, f"Type validation failed: {errors}"

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)

    # Check all functions are present
    for func in [
        "uint16be",
        "uint32be",
        "int16be",
        "int32be",
        "uint16le",
        "uint32le",
        "int16le",
        "int32le",
    ]:
        assert func in output


def test_complex_regex_in_expressions() -> None:
    """Test complex regex patterns in expressions."""
    yara_code = r"""
    rule complex_regex {
        strings:
            $a = /[a-z]{3,5}/ nocase
            $b = /\w+@\w+\.\w+/
            $c = /(https?|ftp):\/\/[^\s]+/i

        condition:
            $a and
            $b and
            $c and
            "user@gmail.com" matches /.*@(gmail|yahoo|hotmail)\.com/ and
            "test123" matches /test[0-9]+/
    }
    """

    parser = Parser()
    ast = parser.parse(yara_code)

    # Check the rule parsed correctly
    rule = ast.rules[0]
    assert len(rule.strings) == 3

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)

    # Verify regex patterns are preserved
    assert r"/[a-z]{3,5}/" in output
    assert r"/\w+@\w+\.\w+/" in output
    assert r'"user@gmail.com" matches /.*@(gmail|yahoo|hotmail)\.com/' in output
    assert r'"test123" matches /test[0-9]+/' in output


def test_string_matches_dynamic_regex() -> None:
    """Test literal string matching dynamic regex."""
    yara_code = r"""
    rule string_matches_regex {
        strings:
            $email = /[a-z]+@[a-z]+\.com/
            $pattern = "malware"

        condition:
            $email and
            $pattern and
            "malware" matches /mal[a-z]+/ and
            "static_string" matches /static.*/ and
            "user@evil.com" matches /.*@evil\.com/
    }
    """

    parser = Parser()
    ast = parser.parse(yara_code)

    # Type validation should pass
    is_valid, errors = TypeValidator.validate(ast)
    assert is_valid, f"Type validation failed: {errors}"

    # Generate and verify
    generator = CodeGenerator()
    output = generator.generate(ast)
    assert '"malware" matches /mal[a-z]+/' in output
    assert '"static_string" matches /static.*/' in output
    assert r'"user@evil.com" matches /.*@evil\.com/' in output


def test_mixed_features() -> None:
    """Test combination of all new features."""
    yara_code = r"""
    import "pe"
    import "math"

    rule advanced_detection {
        meta:
            description = "Advanced detection using new features"

        strings:
            $mz = { 4D 5A }
            $str = "malicious"
            $url = /https?:\/\/[a-z0-9\.\-]+\/[a-z0-9]+/i

        condition:
            $mz at 0 and
            uint16be(0) == 0x4D5A and
            uint32le(uint32(0x3c)) == 0x00004550 and
            pe.machine == 0x14c and
            math.entropy(0, 1024) > 6.5 and
            $str and
            $url and
            "malicious" matches /mal[a-z]+/ and
            "https://example.test/download/file" matches /.*\/download\//i and
            "ABCDE" matches /[A-Z]+/
    }
    """

    parser = Parser()
    ast = parser.parse(yara_code)

    # Should parse without errors
    assert len(ast.imports) == 2
    assert ast.imports[0].alias is None
    assert ast.imports[1].alias is None

    # Type check
    is_valid, errors = TypeValidator.validate(ast)
    assert is_valid, f"Type validation failed: {errors}"

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)

    # Verify all features are present
    assert 'import "pe"' in output
    assert 'import "math"' in output
    assert "uint16be(0) == 0x4D5A" in output
    assert "uint32le(uint32(0x3c))" in output
    assert "pe.machine" in output
    assert "math.entropy" in output
    assert '"malicious" matches /mal[a-z]+/' in output
    assert '"ABCDE" matches /[A-Z]+/' in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
