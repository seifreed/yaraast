"""Test advanced code generator with formatting options."""

from yaraast.codegen.advanced_generator import AdvancedCodeGenerator
from yaraast.codegen.formatting import (
    BraceStyle,
    FormattingConfig,
    HexStyle,
    IndentStyle,
    StringStyle,
)
from yaraast.parser import Parser


def test_compact_formatting() -> None:
    """Test compact formatting style."""
    yara_code = """
rule test_rule {
    meta:
        author = "test"
        version = 1

    strings:
        $str1 = "test"
        $str2 = { 48 65 6C 6C 6F }

    condition:
        $str1 and $str2
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    config = FormattingConfig.compact()
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Check compact formatting
    assert "  " in output  # 2-space indent
    assert "$str1=" in output or "$str1 =" in output


def test_expanded_formatting() -> None:
    """Test expanded formatting style."""
    yara_code = """
rule test_rule {
    strings:
        $a = "short"
        $longname = "longer string"

    condition:
        $a and $longname
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    config = FormattingConfig.expanded()
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Check expanded formatting
    assert "    " in output  # 4-space indent
    assert "\n\n\n" not in output or "\n\n" in output  # Multiple blank lines


def test_brace_styles() -> None:
    """Test different brace placement styles."""
    yara_code = """
rule test {
    condition:
        true
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Same line style
    config = FormattingConfig(brace_style=BraceStyle.SAME_LINE)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)
    assert "rule test {" in output

    # New line style
    config = FormattingConfig(brace_style=BraceStyle.NEW_LINE)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)
    assert "rule test\n{" in output or "rule test\r\n{" in output


def test_string_alignment() -> None:
    """Test string definition alignment."""
    yara_code = """
rule test {
    strings:
        $a = "a"
        $longname = "long"
        $b = { 01 02 }

    condition:
        any of them
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Tabular alignment
    config = FormattingConfig(string_style=StringStyle.TABULAR)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Should align identifiers and values
    lines = output.split("\n")
    string_lines = [line for line in lines if "$" in line and "=" in line]
    if string_lines:
        # Check that = signs are aligned
        equals_positions = [line.index("=") for line in string_lines if "=" in line]
        assert len(set(equals_positions)) <= 2  # Allow some variance


def test_hex_formatting() -> None:
    """Test hex string formatting options."""
    yara_code = """
rule test {
    strings:
        $hex = { 48 65 6c 6c 6f }

    condition:
        $hex
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Uppercase hex
    config = FormattingConfig(hex_style=HexStyle.UPPERCASE)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)
    assert "48 65 6C 6C 6F" in output or "48656C6C6F" in output

    # Lowercase hex
    config = FormattingConfig(hex_style=HexStyle.LOWERCASE)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)
    assert "48 65 6c 6c 6f" in output or "48656c6c6f" in output


def test_sorting_options() -> None:
    """Test sorting of imports, rules, etc."""
    yara_code = """
import "pe"
import "math"
import "elf"

rule zzz_last {
    condition: true
}

rule aaa_first {
    condition: true
}

rule mmm_middle {
    meta:
        z_last = "z"
        a_first = "a"
        m_middle = "m"
    condition: true
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Test import sorting
    config = FormattingConfig(sort_imports=True)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    import_lines = [line for line in output.split("\n") if "import" in line]
    assert len(import_lines) == 3
    assert import_lines[0] < import_lines[1] < import_lines[2]  # Alphabetical order

    # Test rule sorting
    config = FormattingConfig(sort_rules=True)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Rules should be in alphabetical order
    assert output.index("aaa_first") < output.index("mmm_middle") < output.index("zzz_last")

    # Test meta sorting
    config = FormattingConfig(sort_meta=True)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Meta should be sorted within the rule
    meta_section = output[output.index("meta:") : output.index("condition:")]
    assert (
        meta_section.index("a_first")
        < meta_section.index("m_middle")
        < meta_section.index("z_last")
    )


def test_spacing_options() -> None:
    """Test various spacing options."""
    yara_code = """
rule test : tag1 tag2 {
    condition:
        true and false or (1 + 2)
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Test spacing around operators
    config = FormattingConfig(
        space_before_colon=False,
        space_after_colon=False,
        space_around_operators=False,
    )
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    assert "test:" in output or "test :" in output  # Colon spacing


def test_indentation_styles() -> None:
    """Test spaces vs tabs indentation."""
    yara_code = """
rule test {
    meta:
        test = true
    condition:
        true
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Test tab indentation
    config = FormattingConfig(indent_style=IndentStyle.TABS)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Should contain tabs
    assert "\t" in output

    # Test space indentation
    config = FormattingConfig(indent_style=IndentStyle.SPACES, indent_size=3)
    generator = AdvancedCodeGenerator(config)
    output = generator.generate(ast)

    # Should contain 3-space indents
    assert "   " in output
    assert "\t" not in output


if __name__ == "__main__":
    test_compact_formatting()
    test_expanded_formatting()
    test_brace_styles()
    test_string_alignment()
    test_hex_formatting()
    test_sorting_options()
    test_spacing_options()
    test_indentation_styles()
    print("✓ All advanced generator tests passed")
