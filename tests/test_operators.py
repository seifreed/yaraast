"""Test missing operators implementation."""

from yaraast.ast.operators import DefinedExpression
from yaraast.codegen import CodeGenerator
from yaraast.parser import Parser


def test_defined_operator() -> None:
    """Test defined operator parsing and generation."""
    yara_code = """
rule test_defined {
    condition:
        defined $string1
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Check AST structure
    rule = ast.rules[0]
    condition = rule.condition
    assert isinstance(condition, DefinedExpression)

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)

    assert "defined $string1" in output


def test_iequals_operator() -> None:
    """Test iequals operator."""
    yara_code = """
rule test_iequals {
    strings:
        $test = "TEST"

    condition:
        $test iequals "test"
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)

    assert "iequals" in output


def test_icontains_operator() -> None:
    """Test icontains operator."""
    yara_code = """
rule test_icontains {
    condition:
        pe.version_info["CompanyName"] icontains "microsoft"
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    # Generate code
    generator = CodeGenerator()
    output = generator.generate(ast)

    assert "icontains" in output


def test_complex_defined() -> None:
    """Test complex defined expressions."""
    yara_code = """
rule test_complex_defined {
    condition:
        defined pe.sections[0].name and
        defined pe.version_info["CompanyName"]
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    generator = CodeGenerator()
    output = generator.generate(ast)

    assert "defined pe.sections[0].name" in output
    assert 'defined pe.version_info["CompanyName"]' in output


def test_string_operators_with_modules() -> None:
    """Test string operators with module attributes."""
    yara_code = """
rule test_module_string_ops {
    condition:
        pe.sections[0].name iequals ".text" and
        pe.version_info["ProductName"] istartswith "Windows" and
        pe.version_info["FileDescription"] iendswith "Application"
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    generator = CodeGenerator()
    output = generator.generate(ast)

    assert "iequals" in output
    assert "istartswith" in output
    assert "iendswith" in output


def test_arrays_in_expressions() -> None:
    """Test arrays in for expressions."""
    yara_code = """
rule test_arrays {
    condition:
        for any section in pe.sections : (
            section.name == ".text"
        )
}
"""

    parser = Parser()
    ast = parser.parse(yara_code)

    generator = CodeGenerator()
    output = generator.generate(ast)

    assert "for any section in pe.sections" in output


if __name__ == "__main__":
    test_defined_operator()
    test_iequals_operator()
    test_icontains_operator()
    test_complex_defined()
    test_string_operators_with_modules()
    test_arrays_in_expressions()
    print("✓ All operator tests passed")
